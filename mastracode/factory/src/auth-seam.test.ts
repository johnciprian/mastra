import type { IMastraAuthProvider } from '@mastra/core/server';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { buildAuthRoutes, mountFactoryAuth, factoryAuthTenant } from './auth.js';

/**
 * Provider-seam behavior: the auth module operates on an explicitly-passed
 * provider (DI — an explicit provider is authoritative regardless of env) and
 * falls back to a WorkOS provider implied by the `WORKOS_*` env vars only when
 * the caller passes none. Public `/auth/*` routes are derived from the
 * provider's capabilities (SSO-shaped vs HTTP-handler-shaped).
 * Provider-specific behavior lives in the provider packages' own tests.
 */

// Mock @mastra/auth-workos so no real WorkOS client is constructed.
vi.mock('@mastra/auth-workos', () => ({
  MastraAuthWorkos: class {
    name = 'workos';
    authenticateToken = vi.fn(async () => null);
    authorizeUser = async () => true;
    getLoginUrl = vi.fn(() => 'https://workos.example/login');
    handleCallback = vi.fn();
  },
}));

const ORIGINAL_ENV = { ...process.env };

/** Minimal custom provider standing in for a non-WorkOS `IMastraAuthProvider`. */
function fakeProvider(overrides: Record<string, unknown> = {}): IMastraAuthProvider {
  return {
    name: 'fake',
    authenticateToken: vi.fn(async () => ({ id: 'user_fake', email: 'fake@example.com', organizationId: 'org_fake' })),
    authorizeUser: async () => true,
    ...overrides,
  } as unknown as IMastraAuthProvider;
}

/** SSO capability mixin (makes `isSSOProvider` true). */
function ssoCapability(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    getLoginUrl: vi.fn(async () => 'https://fake.example/login'),
    handleCallback: vi.fn(async () => ({ user: {}, tokens: { accessToken: 't' }, cookies: ['fake_session=abc'] })),
    getLogoutUrl: vi.fn(async () => 'https://fake.example/logout'),
    getClearSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'fake_session=; Path=/; Max-Age=0' })),
    ...overrides,
  };
}

/** HTTP-handler capability mixin (makes `isAuthHttpHandler` true). */
function httpHandlerCapability(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    handleAuthRequest: vi.fn(async () => new Response('handled', { status: 200 })),
    getClearSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'fake_session=; Path=/; Max-Age=0' })),
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.WORKOS_API_KEY;
  delete process.env.WORKOS_CLIENT_ID;
  delete process.env.WORKOS_REDIRECT_URI;
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe('active provider resolution', () => {
  it('an explicit provider enables auth regardless of env', () => {
    const enabled = mountFactoryAuth(new Hono(), { provider: fakeProvider() });
    expect(enabled).toBe(true);
  });

  it('no provider and no WORKOS env vars disables auth', () => {
    const enabled = mountFactoryAuth(new Hono());
    expect(enabled).toBe(false);
  });

  it('falls back to env-implied WorkOS when no provider is passed (back-compat)', () => {
    process.env.WORKOS_API_KEY = 'sk_test';
    process.env.WORKOS_CLIENT_ID = 'client_test';
    const enabled = mountFactoryAuth(new Hono());
    expect(enabled).toBe(true);
  });
});

describe('mountFactoryAuth with an explicit custom provider', () => {
  function buildApp(provider: IMastraAuthProvider) {
    const app = new Hono();
    const enabled = mountFactoryAuth(app, { provider });
    app.get('*', c => c.text('ok'));
    return { app, enabled };
  }

  it('derives hosted-login routes for an SSO-shaped provider', async () => {
    const { app, enabled } = buildApp(fakeProvider(ssoCapability()));
    expect(enabled).toBe(true);

    const res = await app.request('/auth/login?returnTo=/dashboard');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://fake.example/login');
  });

  it('proxies /auth/api/* to an HTTP-handler-shaped provider', async () => {
    const provider = fakeProvider(httpHandlerCapability());
    const { app } = buildApp(provider);

    const res = await app.request('/auth/api/sign-in/email', { method: 'POST' });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('handled');
  });

  it('redirects /auth/login to the SPA form for a handler-shaped (non-SSO) provider', async () => {
    const { app } = buildApp(fakeProvider(httpHandlerCapability()));

    const res = await app.request('/auth/login?returnTo=/chat');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/signin?returnTo=%2Fchat');
  });

  it('gates protected routes through provider.authenticateToken and stashes the tenant', async () => {
    const provider = fakeProvider();
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    app.get('/web/whoami', c => c.json(factoryAuthTenant(c) ?? { tenant: null }));

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ orgId: 'org_fake', userId: 'user_fake' });
    expect(provider.authenticateToken).toHaveBeenCalledOnce();
  });

  it('bootstraps a no-org user through IOrganizationsProvider.ensureOrganization', async () => {
    const ensureOrganization = vi.fn(async () => 'org_boot');
    const provider = fakeProvider({
      authenticateToken: vi.fn(async () => ({ id: 'user_solo', email: 'solo@example.com' })),
      ensureOrganization,
      isOrganizationAdmin: vi.fn(async () => false),
    });
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    app.get('/web/whoami', c => c.json(factoryAuthTenant(c) ?? { tenant: null }));

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(await res.json()).toEqual({ orgId: 'org_boot', userId: 'user_solo' });
    expect(ensureOrganization).toHaveBeenCalledWith('user_solo');
  });

  it('returns 401 for unauthenticated API calls (provider returns null)', async () => {
    const { app } = buildApp(fakeProvider({ authenticateToken: vi.fn(async () => null) }));
    const res = await app.request('/web/projects', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });

  it('serves the provider-neutral /auth/me from the provider session', async () => {
    const { app } = buildApp(fakeProvider());
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      authenticated: true,
      user: { userId: 'user_fake', email: 'fake@example.com', organizationId: 'org_fake' },
      provider: 'fake',
      // A bare provider validates tokens but cannot sign anyone in from a
      // browser, which is `kind: 'none'` — not "auth is off".
      auth: {
        signIn: { kind: 'none', providerHint: 'generic' },
        features: { logout: false, organizations: false, refresh: false, sessionRevocation: false },
      },
    });
  });

  it('/auth/me surfaces signUpDisabled when a credentials provider disables sign-up', async () => {
    const { app } = buildApp(
      fakeProvider({
        authenticateToken: vi.fn(async () => null),
        signIn: vi.fn(),
        isSignUpEnabled: () => false,
      }),
    );
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      authenticated: false,
      user: null,
      provider: 'fake',
      signUpDisabled: true,
      auth: {
        signIn: {
          kind: 'credentials',
          providerHint: 'generic',
          signUpEnabled: false,
          credentialsBasePath: '/auth',
        },
        features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
      },
    });
  });

  it('logout for a handler-shaped provider revokes the session and clears the cookie', async () => {
    const handleAuthRequest = vi.fn(
      async () => new Response(null, { status: 200, headers: { 'Set-Cookie': 'fake_session=revoked; Max-Age=0' } }),
    );
    const { app } = buildApp(fakeProvider(httpHandlerCapability({ handleAuthRequest })));

    const res = await app.request('/auth/logout');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/');
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
    const revoked = handleAuthRequest.mock.calls[0]![0] as Request;
    expect(revoked.method).toBe('POST');
    expect(new URL(revoked.url).pathname).toBe('/auth/api/sign-out');
  });
});

describe('buildAuthRoutes', () => {
  it('derives SSO routes plus /auth/me as unauthenticated apiRoutes', () => {
    const routes = buildAuthRoutes(fakeProvider(ssoCapability()));
    const paths = routes.map(r => r.path);
    expect(paths).toEqual(['/auth/login', '/auth/callback', '/auth/logout', '/auth/me']);
    expect(routes.every(r => r.requiresAuth === false)).toBe(true);
  });

  it('derives handler routes plus /auth/me for an HTTP-handler-shaped provider', () => {
    const routes = buildAuthRoutes(fakeProvider(httpHandlerCapability()));
    const paths = routes.map(r => r.path);
    expect(paths).toEqual(['/auth/api/*', '/auth/login', '/auth/logout', '/auth/me']);
    expect(routes.every(r => r.requiresAuth === false)).toBe(true);
  });

  it('a bare provider still gets /auth/me', () => {
    const routes = buildAuthRoutes(fakeProvider());
    expect(routes.map(r => r.path)).toEqual(['/auth/me']);
  });
});

/** The `/auth/me` body, as far as these tests read it. */
interface AuthMeBody {
  authenticated: boolean;
  provider?: string;
  /** Legacy negative field, kept for one release. U9 removes it. */
  signUpDisabled?: boolean;
  auth: {
    signIn: {
      kind: 'hosted' | 'credentials' | 'both' | 'none';
      providerHint?: string;
      /** Positive field from the kit's descriptor. */
      signUpEnabled?: boolean;
      credentialsBasePath?: string;
    };
    features: { logout: boolean; organizations: boolean; refresh: boolean; sessionRevocation: boolean };
  };
}

/** Credentials capability mixin (makes `isCredentialsProvider` true). */
function credentialsCapability(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { signIn: vi.fn(), ...overrides };
}

/** Session capability mixin (makes `isSessionProvider` true). */
function sessionCapability(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    createSession: vi.fn(),
    validateSession: vi.fn(),
    refreshSession: vi.fn(),
    destroySession: vi.fn(),
    ...overrides,
  };
}

/**
 * U1: `/auth/me` carries the kit's capability descriptor, so `/signin` can
 * branch on what a provider can *do* rather than on its name.
 *
 * The sign-up block below is the part worth reading before changing any of
 * this. For one release the payload states the same fact twice with opposite
 * polarity — `auth.signIn.signUpEnabled` (positive, matching the provider's
 * `isSignUpEnabled`) and the legacy `signUpDisabled` (negative, which is what
 * `factory-ui`'s SignInPage reads today). A dropped `!` between them renders a
 * sign-up link on a deployment that switched sign-up off, and that failure is
 * invisible from the outside: no error, no log, just accounts that should not
 * exist. So the polarity of both fields is asserted explicitly, in the same
 * payload, rather than each being checked in a test of its own where they could
 * agree by accident.
 */
describe('/auth/me capability descriptor', () => {
  /** GET `/auth/me` against a provider and return the parsed body. */
  async function authMe(provider: IMastraAuthProvider): Promise<AuthMeBody> {
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    return (await res.json()) as AuthMeBody;
  }

  describe('a descriptor is present for every capability shape', () => {
    it.each([
      { shape: 'bare (token validator only)', overrides: {}, kind: 'none' },
      { shape: 'hosted login', overrides: ssoCapability(), kind: 'hosted' },
      { shape: 'credentials', overrides: credentialsCapability(), kind: 'credentials' },
      {
        shape: 'hosted login and credentials',
        overrides: { ...ssoCapability(), ...credentialsCapability() },
        kind: 'both',
      },
    ])('$shape reports kind "$kind"', async ({ overrides, kind }) => {
      const body = await authMe(fakeProvider(overrides));
      expect(body.auth.signIn.kind).toBe(kind);
      // Never a vendor name: the hint is a rendering token the SPA maps to copy.
      expect(body.auth.signIn.providerHint).toBe('generic');
    });
  });

  it('reports the descriptor to a signed-out browser too', async () => {
    // The payload that says "you are signed out" is the same one that has to
    // tell the browser how to sign in, so `/signin` renders from one request.
    const body = await authMe(fakeProvider({ authenticateToken: vi.fn(async () => null), ...ssoCapability() }));
    expect(body.authenticated).toBe(false);
    expect(body.auth.signIn.kind).toBe('hosted');
    expect(body.auth.features.logout).toBe(true);
  });

  it('keeps the bare provider name alongside the descriptor for one release', async () => {
    // U9 removes this; until then a browser on a cached bundle still branches
    // on the name, so the descriptor is added beside it and not instead of it.
    const body = await authMe(fakeProvider(ssoCapability()));
    expect(body.provider).toBe('fake');
    expect(body.auth).toBeDefined();
  });

  it('derives the account-menu features from the provider capabilities', async () => {
    const body = await authMe(
      fakeProvider({
        ...ssoCapability(),
        ...sessionCapability(),
        ensureOrganization: vi.fn(async () => 'org_fake'),
        isOrganizationAdmin: vi.fn(async () => false),
      }),
    );
    expect(body.auth.features).toEqual({
      logout: true,
      organizations: true,
      refresh: true,
      sessionRevocation: true,
    });
  });

  it('offers no session revocation when the provider only looks like a session provider', async () => {
    // isSessionProvider narrows on createSession/validateSession alone, so a
    // provider can pass the guard with no destroySession to call.
    const body = await authMe(
      fakeProvider({ ...sessionCapability({ refreshSession: undefined, destroySession: undefined }) }),
    );
    expect(body.auth.features.refresh).toBe(false);
    expect(body.auth.features.sessionRevocation).toBe(false);
    // Still worth a sign-out control: there is a server-side session to end.
    expect(body.auth.features.logout).toBe(true);
  });

  describe('the two sign-up fields, in one payload, with opposite polarity', () => {
    it.each([
      {
        label: 'a provider that allows sign-up',
        overrides: credentialsCapability({ isSignUpEnabled: () => true }),
        enabled: true,
      },
      {
        label: 'a provider that omits isSignUpEnabled (contract default is on)',
        overrides: credentialsCapability(),
        enabled: true,
      },
      {
        label: 'a provider that disables sign-up',
        overrides: credentialsCapability({ isSignUpEnabled: () => false }),
        enabled: false,
      },
    ])('$label', async ({ overrides, enabled }) => {
      const body = await authMe(fakeProvider(overrides));

      // Positive field: says what the provider's own method says.
      expect(body.auth.signIn.signUpEnabled).toBe(enabled);

      // Negative field: present only to say "off", absent otherwise. This is
      // the shape SignInPage reads as `signUpDisabled === true`.
      expect(body.signUpDisabled).toBe(enabled ? undefined : true);

      // And the two disagree as booleans in exactly the way they should. This
      // is the assertion that catches a dropped `!`: it fails if the fields are
      // ever made to agree, in either direction.
      expect(body.auth.signIn.signUpEnabled).toBe(!(body.signUpDisabled ?? false));
    });

    it('states neither field for a provider with no credentials sign-in', async () => {
      // There is no sign-up to describe, so nothing is claimed either way — an
      // absent positive field must not be read as "sign-up is off".
      const body = await authMe(fakeProvider(ssoCapability()));
      expect(body.auth.signIn.signUpEnabled).toBeUndefined();
      expect(body.signUpDisabled).toBeUndefined();
    });

    it.each([
      {
        label: 'throws',
        isSignUpEnabled: () => {
          throw new Error('provider is down');
        },
      },
      { label: 'is async, so returns a truthy Promise', isSignUpEnabled: async () => true },
      { label: 'returns a non-boolean', isSignUpEnabled: () => 'yes' },
    ])('fails closed when isSignUpEnabled $label', async ({ isSignUpEnabled }) => {
      // Stricter than the expression this replaced, deliberately: hiding a
      // sign-up link that should have shown is a support ticket, while showing
      // one that should have been hidden creates accounts nobody authorized.
      const body = await authMe(fakeProvider(credentialsCapability({ isSignUpEnabled })));
      expect(body.auth.signIn.signUpEnabled).toBe(false);
      expect(body.signUpDisabled).toBe(true);
    });
  });

  it('points a credentials form at the path this host actually mounts', async () => {
    // The kit's default happens to match where registerAuthRoutes mounts, so
    // no override is passed. The provider's own endpoints hang below it at
    // /auth/api/*, which is what the SPA posts to.
    const body = await authMe(fakeProvider({ ...credentialsCapability(), ...httpHandlerCapability() }));
    expect(body.auth.signIn.credentialsBasePath).toBe('/auth');

    const app = new Hono();
    mountFactoryAuth(app, { provider: fakeProvider({ ...credentialsCapability(), ...httpHandlerCapability() }) });
    const posted = await app.request(`${body.auth.signIn.credentialsBasePath}/api/sign-in/email`, { method: 'POST' });
    expect(posted.status).toBe(200);
  });
});

/**
 * The compat flag for the identity/session/logout migration. It is read once at
 * module load, so both paths are reached by reloading the module rather than by
 * assigning to `process.env` — the last test here is what pins that property,
 * and the rest would pass just as well against a per-request read.
 *
 * Placed last in the file, and it leaves the module registry reset behind it:
 * the statically imported bindings above are already resolved and keep working,
 * but a fresh registry is the tidier state to hand to whatever runs next.
 */
describe('MASTRACODE_AUTH_IDENTITY_V2 (compat flag)', () => {
  /**
   * Import a fresh copy of the auth module with the flag set to `value`
   * (`undefined` unsets it). Deleting the variable explicitly rather than
   * trusting the ambient environment keeps the default-off assertion honest on
   * a machine that happens to export it.
   */
  async function importAuthWith(value: string | undefined): Promise<typeof import('./auth.js')> {
    if (value === undefined) delete process.env.MASTRACODE_AUTH_IDENTITY_V2;
    else process.env.MASTRACODE_AUTH_IDENTITY_V2 = value;
    vi.resetModules();
    return import('./auth.js');
  }

  afterEach(() => {
    delete process.env.MASTRACODE_AUTH_IDENTITY_V2;
    vi.resetModules();
  });

  it('names the env var it reads', async () => {
    const auth = await importAuthWith(undefined);
    expect(auth.AUTH_IDENTITY_V2_ENV_VAR).toBe('MASTRACODE_AUTH_IDENTITY_V2');
  });

  it('defaults to off when the env var is unset', async () => {
    const auth = await importAuthWith(undefined);
    expect(auth.isAuthIdentityV2Enabled()).toBe(false);
  });

  it.each(['1', 'true', 'TRUE', '  true  '])('is on when the env var is %j at module load', async value => {
    const auth = await importAuthWith(value);
    expect(auth.isAuthIdentityV2Enabled()).toBe(true);
  });

  it.each(['', '0', 'false', 'FALSE', 'yes', 'on', 'v2', 'undefined'])(
    'stays off for %j, because an unrecognized value must not opt in',
    async value => {
      const auth = await importAuthWith(value);
      expect(auth.isAuthIdentityV2Enabled()).toBe(false);
    },
  );

  it('parses opt-in values without a module reload', async () => {
    const { readAuthIdentityV2Env } = await importAuthWith(undefined);
    expect(readAuthIdentityV2Env('1')).toBe(true);
    expect(readAuthIdentityV2Env('true')).toBe(true);
    expect(readAuthIdentityV2Env('True')).toBe(true);
    expect(readAuthIdentityV2Env('\tTRUE\n')).toBe(true);
    expect(readAuthIdentityV2Env('0')).toBe(false);
    expect(readAuthIdentityV2Env('false')).toBe(false);
    expect(readAuthIdentityV2Env('')).toBe(false);
    expect(readAuthIdentityV2Env(undefined)).toBe(false);
  });

  it('reads the env var once at module load, not per call', async () => {
    const auth = await importAuthWith(undefined);
    expect(auth.isAuthIdentityV2Enabled()).toBe(false);

    // Flipping the variable on a module that has already loaded must not move
    // the answer: a flag that changed underneath a running process could resolve
    // a session on one path and re-check it on the other.
    process.env.MASTRACODE_AUTH_IDENTITY_V2 = 'true';
    expect(auth.isAuthIdentityV2Enabled()).toBe(false);

    // Only a reload picks the new value up, which is the documented way to
    // reach the other path.
    const reloaded = await importAuthWith('true');
    expect(reloaded.isAuthIdentityV2Enabled()).toBe(true);
  });
});
