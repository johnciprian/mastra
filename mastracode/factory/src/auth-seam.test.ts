import type { IMastraAuthProvider } from '@mastra/core/server';
import {
  fakeProvider as kitFakeProvider,
  withCredentials,
  withHttpHandler,
  withOrganizations,
  withSSO,
  withSession,
} from '@mastra/factory-auth/testing';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { buildAuthRoutes, mountFactoryAuth, factoryAuthTenant } from './auth.js';

/**
 * Provider-seam behavior: the auth module operates on an explicitly-passed
 * provider, and on nothing else. There is no environment fallback — auth is on
 * when a provider was passed and off when one was not. Public `/auth/*` routes
 * are derived from the provider's capabilities (SSO-shaped vs
 * HTTP-handler-shaped). Provider-specific behavior lives in the provider
 * packages' own tests.
 */

const ORIGINAL_ENV = { ...process.env };

/** Minimal provider standing in for any `IMastraAuthProvider`. */
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

  it('no provider disables auth', () => {
    const enabled = mountFactoryAuth(new Hono());
    expect(enabled).toBe(false);
  });

  it('does not resurrect a provider from the WORKOS_* environment', () => {
    // These two variables used to switch auth on by themselves, which made
    // "is auth enabled here?" a question about the process environment rather
    // than about the call. Now only the argument decides.
    process.env.WORKOS_API_KEY = 'sk_test';
    process.env.WORKOS_CLIENT_ID = 'client_test';
    const enabled = mountFactoryAuth(new Hono());
    expect(enabled).toBe(false);
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
    // Logout is two entries: POST is the real route, GET the deprecated shim.
    expect(routes.map(r => `${String(r.method)} ${r.path}`)).toEqual([
      'GET /auth/login',
      'GET /auth/callback',
      'POST /auth/logout',
      'GET /auth/logout',
      'GET /auth/me',
    ]);
    expect(routes.every(r => r.requiresAuth === false)).toBe(true);
  });

  it('derives handler routes plus /auth/me for an HTTP-handler-shaped provider', () => {
    const routes = buildAuthRoutes(fakeProvider(httpHandlerCapability()));
    expect(routes.map(r => `${String(r.method)} ${r.path}`)).toEqual([
      'ALL /auth/api/*',
      'GET /auth/login',
      'POST /auth/logout',
      'GET /auth/logout',
      'GET /auth/me',
    ]);
    expect(routes.every(r => r.requiresAuth === false)).toBe(true);
  });

  it('a bare provider still gets /auth/me', () => {
    const routes = buildAuthRoutes(fakeProvider());
    expect(routes.map(r => r.path)).toEqual(['/auth/me']);
  });
});

/**
 * B8: the OAuth `state` round trip, through the kit's codec.
 *
 * `state` is the only channel that survives the bounce to an identity provider
 * and back, so its format is a contract between this host and every provider —
 * and the thing that makes it fragile is that the two hosts driving the same
 * providers hand `handleCallback` different spellings of it. This host passes
 * the raw value the IdP echoed; `packages/server` splits it and passes the id
 * half. A provider that keys anything on `state` sees one or the other.
 */
describe('OAuth state codec', () => {
  /** Mount the SSO routes and return the app plus the provider's spies. */
  function ssoApp(overrides: Record<string, unknown> = {}) {
    const getLoginUrl = vi.fn(async (_redirectUri: string, _state: string) => 'https://idp.example/login');
    const handleCallback = vi.fn(async (_code: string, _state: string) => ({
      user: { id: 'u1' },
      cookies: ['idp_session=abc'],
    }));
    const provider = fakeProvider({ ...ssoCapability({ getLoginUrl, handleCallback }), ...overrides });
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    return { app, getLoginUrl, handleCallback };
  }

  /** The `state` this host mints for a given destination. */
  async function mintState(returnTo: string): Promise<string> {
    const { app, getLoginUrl } = ssoApp();
    await app.request(`/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
    return getLoginUrl.mock.calls[0]![1];
  }

  it('mints state in the documented id|encodedReturnTo format', async () => {
    const state = await mintState('/agents/42');
    const delimiter = state.indexOf('|');
    expect(delimiter).toBeGreaterThan(0);
    expect(state.slice(delimiter + 1)).toBe(encodeURIComponent('/agents/42'));
  });

  it('round trips a returnTo that itself contains the delimiter', async () => {
    // The first `|` is the only significant one. Splitting on every pipe and
    // taking element 1 works right up until a destination contains one, and a
    // post-login redirect that quietly goes to `/` is a bug nobody files.
    const state = await mintState('/search?q=a|b');
    expect(state.slice(state.indexOf('|') + 1)).toBe(encodeURIComponent('/search?q=a|b'));

    const { app } = ssoApp();
    const res = await app.request(`/auth/callback?code=ok&state=${encodeURIComponent(state)}`);
    expect(res.headers.get('location')).toBe('/search?q=a|b');
  });

  it('hands handleCallback the raw state, exactly as the IdP echoed it', async () => {
    // This host's half of the disagreement, pinned: the contract documents the
    // raw value, so narrowing it here would break a provider that stored
    // something under the full `state` at login.
    const state = await mintState('/dashboard');
    const { app, handleCallback } = ssoApp();
    await app.request(`/auth/callback?code=ok&state=${encodeURIComponent(state)}`);
    expect(handleCallback).toHaveBeenCalledWith('ok', state);
  });

  it('lets a provider keyed through parseStateId complete a callback under both hosts', async () => {
    // The kit's `stateStoreKey(state) = parseStateId(state) ?? state` is what
    // reconciles the two spellings. A provider using it stores under one key at
    // login and finds it again whichever host drives the callback. Modelled
    // here rather than asserted about: the store is real, and a miss throws.
    const stateStoreKey = (state: string): string => {
      const delimiter = state.indexOf('|');
      if (state.length === 0) return state;
      if (delimiter === -1) return state;
      if (delimiter === 0) return state;
      return state.slice(0, delimiter);
    };
    const store = new Map<string, { redirectUri: string }>();

    const getLoginUrl = vi.fn(async (redirectUri: string, state: string) => {
      store.set(stateStoreKey(state), { redirectUri });
      return 'https://idp.example/login';
    });
    const handleCallback = vi.fn(async (_code: string, state: string) => {
      const entry = store.get(stateStoreKey(state));
      if (!entry) throw new Error('invalid or expired state');
      return { user: { id: 'u1' }, cookies: ['idp_session=abc'] };
    });

    const { app } = ssoApp({ ...ssoCapability({ getLoginUrl, handleCallback }) });
    await app.request('/auth/login?returnTo=%2Fdashboard');
    const state = getLoginUrl.mock.calls[0]![1];

    // This host: the raw value.
    const raw = await app.request(`/auth/callback?code=ok&state=${encodeURIComponent(state)}`);
    expect(raw.headers.get('location')).toBe('/dashboard');

    // packages/server: the id half only. Same provider, same store, same key.
    const idHalf = state.slice(0, state.indexOf('|'));
    expect(await handleCallback('ok', idHalf)).toMatchObject({ user: { id: 'u1' } });
  });

  it.each([
    { what: 'no state at all', state: undefined, expected: '/' },
    { what: 'a state with no delimiter', state: 'opaque-provider-state', expected: '/' },
    { what: 'a malformed percent escape', state: 'id|%zz', expected: '/' },
    { what: 'an absolute URL', state: `id|${encodeURIComponent('https://evil.com')}`, expected: '/' },
    { what: 'a protocol-relative URL', state: `id|${encodeURIComponent('//evil.com')}`, expected: '/' },
    { what: 'a backslash-smuggled host', state: `id|${encodeURIComponent('/\\evil.com')}`, expected: '/' },
    {
      what: 'an already-encoded protocol-relative URL, which must not be decoded twice',
      state: `id|${encodeURIComponent('/%2F%2Fevil.com')}`,
      expected: '/%2F%2Fevil.com',
    },
  ])('sends the user to $what safely', async ({ state, expected }) => {
    const { app } = ssoApp();
    const query = state === undefined ? '' : `&state=${encodeURIComponent(state)}`;
    const res = await app.request(`/auth/callback?code=ok${query}`);
    expect(res.headers.get('location')).toBe(expected);
  });

  it('survives a state the query parser turned into something other than a string', async () => {
    // `?state=a&state=b` is an array under some parsers, `?state[x]=y` an
    // object. Neither is a string, and the codec is documented as total.
    const { app } = ssoApp();
    const res = await app.request('/auth/callback?code=ok&state=a&state=b');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/');
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
   * trusting the ambient environment keeps the default-on assertion honest on
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

  it('defaults to ON when the env var is unset', async () => {
    const auth = await importAuthWith(undefined);
    expect(auth.isAuthIdentityV2Enabled()).toBe(true);
  });

  it.each(['0', 'false', 'FALSE', '  false  '])('is off when the env var is %j at module load', async value => {
    const auth = await importAuthWith(value);
    expect(auth.isAuthIdentityV2Enabled()).toBe(false);
  });

  it.each(['1', 'true', 'TRUE', '  true  '])('stays on for the explicit opt-in %j', async value => {
    const auth = await importAuthWith(value);
    expect(auth.isAuthIdentityV2Enabled()).toBe(true);
  });

  it.each(['', 'no', 'off', 'flase', 'FALSE!', 'v1', 'undefined', 'null', '00', 'false ish'])(
    'stays ON for %j, because an unrecognized value must not select the legacy path',
    async value => {
      // The same rule as before the default flipped, pointed the other way: a
      // typo must never land a deployment on the non-default path. That used to
      // mean "must not opt in"; now the non-default path is the legacy reader,
      // with the defects v2 exists to fix, so a typo must not opt *out*.
      const auth = await importAuthWith(value);
      expect(auth.isAuthIdentityV2Enabled()).toBe(true);
    },
  );

  it('parses opt-out values without a module reload', async () => {
    const { readAuthIdentityV2Env } = await importAuthWith(undefined);
    expect(readAuthIdentityV2Env('0')).toBe(false);
    expect(readAuthIdentityV2Env('false')).toBe(false);
    expect(readAuthIdentityV2Env('False')).toBe(false);
    expect(readAuthIdentityV2Env('\tFALSE\n')).toBe(false);
    expect(readAuthIdentityV2Env('1')).toBe(true);
    expect(readAuthIdentityV2Env('true')).toBe(true);
    expect(readAuthIdentityV2Env('')).toBe(true);
    expect(readAuthIdentityV2Env(undefined)).toBe(true);
    expect(readAuthIdentityV2Env('flase')).toBe(true);
  });

  it('reads the env var once at module load, not per call', async () => {
    const auth = await importAuthWith(undefined);
    expect(auth.isAuthIdentityV2Enabled()).toBe(true);

    // Flipping the variable on a module that has already loaded must not move
    // the answer: a flag that changed underneath a running process could resolve
    // a session on one path and re-check it on the other.
    process.env.MASTRACODE_AUTH_IDENTITY_V2 = 'false';
    expect(auth.isAuthIdentityV2Enabled()).toBe(true);

    // Only a reload picks the new value up, which is the documented way to
    // reach the other path.
    const reloaded = await importAuthWith('false');
    expect(reloaded.isAuthIdentityV2Enabled()).toBe(false);
  });
});

/**
 * B3: what the flag actually switches — which reader turns a provider's
 * `authenticateToken` result into an identity.
 *
 * Each case runs the SAME payload through BOTH readers via the reload recipe
 * above, so the table below is a behavioural diff rather than two independent
 * suites that could drift. `legacy` and `v2` are the user id each path resolves,
 * with `null` meaning "authenticated as nobody".
 *
 * The differences here were found by running both readers over a payload corpus
 * before the change, not by reading them side by side: the kit's own note says
 * its precedence matches what this module already did, and on the flat id key
 * set that turned out to be an overstatement worth pinning down in tests.
 *
 * Both legs select their path EXPLICITLY. The legacy leg used to get there by
 * unsetting the variable, which stopped meaning "legacy" the moment the default
 * flipped — and would have quietly turned this table into v2 compared against
 * itself, still green and testing nothing. Naming both values is what keeps the
 * diff a diff.
 */
describe('identity resolution under the compat flag', () => {
  /** The explicit opt-out that selects the pre-kit reader. */
  const LEGACY = 'false';

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

  /**
   * Sign in through the gate with `payload` as the provider's result, and report
   * the tenant the request resolved to. Goes through `mountFactoryAuth` rather
   * than calling the reader directly, so the assertion covers the path a real
   * request takes: authenticate, normalize, stash, read back.
   */
  async function tenantFor(
    auth: typeof import('./auth.js'),
    payload: unknown,
    providerOverrides: Record<string, unknown> = {},
  ): Promise<{ orgId?: string; userId?: string } | null> {
    const app = new Hono();
    auth.mountFactoryAuth(app, {
      provider: fakeProvider({ authenticateToken: vi.fn(async () => payload), ...providerOverrides }),
    });
    app.get('/web/whoami', c => c.json(auth.factoryAuthTenant(c) ?? { tenant: null }));
    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    if (res.status === 401) return null;
    return (await res.json()) as { orgId?: string; userId?: string };
  }

  it.each([
    {
      what: 'a flat provider id',
      payload: { id: 'u1', organizationId: 'org_a' },
      legacy: 'u1',
      v2: 'u1',
    },
    {
      what: 'the real WorkOS shape, id and workosId holding the same value',
      payload: { id: 'w1', workosId: 'w1', organizationId: 'org_a' },
      legacy: 'w1',
      v2: 'w1',
    },
    {
      what: 'a Firebase DecodedIdToken, which names its id `uid`',
      payload: { uid: 'fb1' },
      legacy: null,
      v2: 'fb1',
    },
    {
      what: 'raw OIDC claims, which name it `sub`',
      payload: { sub: 'oidc1' },
      legacy: null,
      v2: 'oidc1',
    },
    {
      what: 'a numeric id, as a serial primary key produces',
      payload: { id: 7 },
      legacy: null,
      v2: '7',
    },
    {
      // The one row where the tenant no longer matches the legacy *reader*.
      // That reader still hands back '   ' verbatim, but `factoryAuthTenant`
      // refuses to build a tenant from it on either path: since B12 the
      // organization is derived from the user id, and deriving one from
      // whitespace throws — a 500 on a gated route where a 401 belongs.
      // Treating blank as absent keeps the refusal and drops the crash.
      what: 'a blank id, which is a storage key every user would share',
      payload: { id: '   ' },
      legacy: null,
      v2: null,
    },
    {
      what: 'a workosId with no id, which the real provider never emits',
      payload: { workosId: 'w1' },
      legacy: 'w1',
      v2: null,
    },
    {
      what: 'a session wrapper, org taken from the session half',
      payload: { session: { activeOrganizationId: 'org_s' }, user: { id: 'u1' } },
      legacy: 'u1',
      v2: 'u1',
    },
    {
      what: 'a session wrapper whose user half names nobody (no fallthrough)',
      payload: { session: { activeOrganizationId: 'org_s' }, user: { email: 'e@x.com' }, id: 'top' },
      legacy: null,
      v2: null,
    },
    {
      what: 'a payload naming no user at all',
      payload: { email: 'e@x.com' },
      legacy: null,
      v2: null,
    },
  ])('$what', async ({ payload, legacy, v2 }) => {
    const off = await tenantFor(await importAuthWith(LEGACY), payload);
    expect(off?.userId ?? null).toBe(legacy);

    const on = await tenantFor(await importAuthWith('true'), payload);
    expect(on?.userId ?? null).toBe(v2);
  });

  it('ignores the org on the user half when the session names none, under both readers', async () => {
    // The payload P12 settled. The kit used to read `user.organizationId` here
    // and resolve into org_u, which widened org scope under the flag: a session
    // that resolved as personal reached an organization it had never activated.
    // Membership is not activation, so the fallback was removed and both
    // readers now resolve the private partition.
    const payload = { session: {}, user: { id: 'u1', organizationId: 'org_u' } };

    // This provider does no organization bootstrap, so neither reader has an
    // organization to use. Since B12 the tenant still resolves one for that
    // user — their own private one — rather than none.
    const off = await tenantFor(await importAuthWith(LEGACY), payload);
    expect(off).toEqual({ userId: 'u1', orgId: 'user:u1' });

    const on = await tenantFor(await importAuthWith('true'), payload);
    expect(on).toEqual({ userId: 'u1', orgId: 'user:u1' });
  });

  it('lets a provider map its own payload through the kit escape hatch, under v2', async () => {
    // The id lives under a custom claim the kit cannot know about. Legacy has no
    // such hook, so the same payload authenticates as nobody there.
    const payload = { 'https://claims.example/uid': 'custom1' };
    const toIdentity = vi.fn((raw: unknown) => ({
      id: (raw as Record<string, string>)['https://claims.example/uid']!,
    }));

    const off = await tenantFor(await importAuthWith(LEGACY), payload, { toIdentity });
    expect(off).toBeNull();

    const on = await tenantFor(await importAuthWith('true'), payload, { toIdentity });
    expect(on?.userId).toBe('custom1');
    expect(toIdentity).toHaveBeenCalled();
  });

  it('treats a throwing identity mapper as an unauthenticated request', async () => {
    // toAuthIdentity lets a mapper's throw propagate on purpose; the gate's own
    // catch turns it into a 401 rather than into a plausible-looking identity.
    const on = await tenantFor(
      await importAuthWith('true'),
      { id: 'u1' },
      {
        toIdentity: vi.fn(() => {
          throw new Error('mapper is broken');
        }),
      },
    );
    expect(on).toBeNull();
  });
});

/**
 * B9: the session cookie — who mints it, who reads it, who clears it.
 *
 * Two sources exist and both have to keep working. A provider that returns
 * `cookies` from `handleCallback` has already built its own session cookie
 * (WorkOS and Okta both do), and the host must not second-guess it. A provider
 * that returns only tokens leaves the cookie to the host, and that is the branch
 * the kit takes over: signed, `__Host-` prefixed where the deployment allows it,
 * and read back by the host rather than re-derived from a header by each
 * provider.
 *
 * The host path is behind the compat flag AND a configured secret, so these
 * reload the module the same way the identity tests do.
 */
describe('session cookie', () => {
  const SECRET = 'a'.repeat(32);
  /**
   * The explicit opt-out that selects the legacy path.
   *
   * These cases used to reach it by unsetting the variable. That stopped
   * meaning "legacy" when the default flipped, and each one would have kept
   * passing for a different reason — flag on with no secret also leaves the
   * host without a cookie — so the case name would have outlived the thing it
   * tested.
   */
  const LEGACY = 'false';

  async function importAuthWith(
    flag: string | undefined,
    secret: string | undefined,
  ): Promise<typeof import('./auth.js')> {
    if (flag === undefined) delete process.env.MASTRACODE_AUTH_IDENTITY_V2;
    else process.env.MASTRACODE_AUTH_IDENTITY_V2 = flag;
    if (secret === undefined) delete process.env.MASTRACODE_AUTH_SESSION_SECRET;
    else process.env.MASTRACODE_AUTH_SESSION_SECRET = secret;
    vi.resetModules();
    return import('./auth.js');
  }

  afterEach(() => {
    delete process.env.MASTRACODE_AUTH_IDENTITY_V2;
    delete process.env.MASTRACODE_AUTH_SESSION_SECRET;
    vi.resetModules();
  });

  /** An SSO provider whose handleCallback returns `cookies`, `tokens`, or both. */
  function callbackProvider(result: Record<string, unknown>, extra: Record<string, unknown> = {}): IMastraAuthProvider {
    return fakeProvider({
      ...ssoCapability({ handleCallback: vi.fn(async () => result) }),
      ...extra,
    });
  }

  /** Session capability, so the tokens-only branch is reachable. */
  function sessionCapabilityFor(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      createSession: vi.fn(async () => ({ id: 'sess-1' })),
      validateSession: vi.fn(),
      getSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'provider_session=built-by-provider; Path=/' })),
      ...overrides,
    };
  }

  async function callbackSetCookies(
    auth: typeof import('./auth.js'),
    provider: IMastraAuthProvider,
  ): Promise<string[]> {
    const app = new Hono();
    auth.mountFactoryAuth(app, { provider });
    const res = await app.request('/auth/callback?code=ok&state=id%7C%2Fdash');
    return res.headers.getSetCookie();
  }

  describe('source 1: the provider built its own cookie', () => {
    it('forwards provider cookies verbatim on the legacy path', async () => {
      const auth = await importAuthWith(LEGACY, undefined);
      const cookies = await callbackSetCookies(
        auth,
        callbackProvider({ user: { id: 'u1' }, cookies: ['wos_session=sealed; Path=/'] }),
      );
      expect(cookies).toContain('wos_session=sealed; Path=/');
    });

    it('still forwards them verbatim with the host cookie switched on', async () => {
      // The host does not second-guess a provider that already built a session.
      const auth = await importAuthWith('true', SECRET);
      const cookies = await callbackSetCookies(
        auth,
        callbackProvider({ user: { id: 'u1' }, cookies: ['wos_session=sealed; Path=/'] }),
      );
      expect(cookies).toContain('wos_session=sealed; Path=/');
      expect(cookies.some(cookie => cookie.includes('mastra_factory_session'))).toBe(false);
    });
  });

  describe('source 2: the provider returned tokens and left the cookie to the host', () => {
    const tokensResult = { user: { id: 'u1' }, tokens: { accessToken: 'access-1' } };

    it('uses the provider session headers on the legacy path', async () => {
      const auth = await importAuthWith(LEGACY, undefined);
      const cookies = await callbackSetCookies(auth, callbackProvider(tokensResult, sessionCapabilityFor()));
      expect(cookies).toContain('provider_session=built-by-provider; Path=/');
    });

    it('mints a signed __Host- cookie when the host owns the session', async () => {
      const auth = await importAuthWith('true', SECRET);
      const cookies = await callbackSetCookies(auth, callbackProvider(tokensResult, sessionCapabilityFor()));
      const session = cookies.find(cookie => cookie.startsWith('__Host-mastra_factory_session='));
      expect(session).toBeDefined();
      expect(session).toContain('HttpOnly');
      expect(session).toContain('Secure');
      expect(session).toContain('Path=/');
      // The provider's own header is not also written: one session, one cookie.
      expect(cookies.some(cookie => cookie.startsWith('provider_session='))).toBe(false);
      // Signed, so the access token is not sitting there in the clear.
      expect(session).not.toContain('access-1');
    });

    it('falls back to the provider when the flag is on but no secret is configured', async () => {
      // Minting refuses a weak secret, and there is no safe default to invent,
      // so a half-configured deployment keeps working rather than failing every
      // sign-in.
      const auth = await importAuthWith('true', undefined);
      const cookies = await callbackSetCookies(auth, callbackProvider(tokensResult, sessionCapabilityFor()));
      expect(cookies).toContain('provider_session=built-by-provider; Path=/');
      expect(cookies.some(cookie => cookie.includes('mastra_factory_session'))).toBe(false);
    });

    it('round trips: the minted cookie authenticates the next request', async () => {
      const auth = await importAuthWith('true', SECRET);
      const authenticateToken = vi.fn(async (token: string) =>
        token === 'access-1' ? { id: 'u1', organizationId: 'org_a' } : null,
      );
      const provider = callbackProvider(tokensResult, { ...sessionCapabilityFor(), authenticateToken });

      const app = new Hono();
      auth.mountFactoryAuth(app, { provider });
      app.get('/web/whoami', c => c.json(auth.factoryAuthTenant(c) ?? { tenant: null }));

      const setCookies = (await app.request('/auth/callback?code=ok&state=id%7C%2Fdash')).headers.getSetCookie();
      const session = setCookies.find(cookie => cookie.startsWith('__Host-mastra_factory_session='))!;
      const cookieHeader = session.split(';')[0]!;

      // No Authorization header — a browser navigation, exactly as it arrives.
      const res = await app.request('/web/whoami', { headers: { Accept: 'application/json', Cookie: cookieHeader } });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ orgId: 'org_a', userId: 'u1' });
      expect(authenticateToken).toHaveBeenCalledWith('access-1', expect.anything());
    });

    it('rejects a tampered cookie as if it were absent', async () => {
      const auth = await importAuthWith('true', SECRET);
      const app = new Hono();
      // Only the real token authenticates, so a cookie that fails its signature
      // check yields '' and the request is refused. A provider that accepted
      // anything would pass this test without the signature mattering at all.
      auth.mountFactoryAuth(app, {
        provider: fakeProvider({
          authenticateToken: vi.fn(async (token: string) => (token === 'access-1' ? { id: 'u1' } : null)),
        }),
      });
      app.get('/web/whoami', c => c.json(auth.factoryAuthTenant(c) ?? { tenant: null }));

      const res = await app.request('/web/whoami', {
        headers: { Accept: 'application/json', Cookie: '__Host-mastra_factory_session=v1.forged.999.nope' },
      });
      expect(res.status).toBe(401);
    });
  });

  describe('clearing on sign-out', () => {
    it('clears the host cookie alongside the provider cookies', async () => {
      const auth = await importAuthWith('true', SECRET);
      const app = new Hono();
      auth.mountFactoryAuth(app, { provider: fakeProvider(ssoCapability()) });

      const cookies = (await app.request('/auth/logout')).headers.getSetCookie();
      // Both, because a user upgraded across the switch still holds the old one.
      expect(cookies.some(cookie => cookie.startsWith('fake_session='))).toBe(true);
      const host = cookies.find(cookie => cookie.startsWith('__Host-mastra_factory_session='));
      expect(host).toBeDefined();
      expect(host).toContain('Max-Age=0');
    });

    it('clears only the provider cookies when the host owns none', async () => {
      const auth = await importAuthWith(LEGACY, undefined);
      const app = new Hono();
      auth.mountFactoryAuth(app, { provider: fakeProvider(ssoCapability()) });

      const cookies = (await app.request('/auth/logout')).headers.getSetCookie();
      expect(cookies.some(cookie => cookie.startsWith('fake_session='))).toBe(true);
      expect(cookies.some(cookie => cookie.includes('mastra_factory_session'))).toBe(false);
    });
  });

  /**
   * The un-join heuristic in `providerClearCookies`. `getClearSessionHeaders`
   * returns one string slot, so a provider clearing two cookies folds them with
   * a comma — the same folding `Headers.get('set-cookie')` performs. Appending
   * that joined value as one header clears neither cookie.
   */
  describe('splitting a provider header that folded several cookies together', () => {
    async function clearCookiesFor(setCookie: string): Promise<string[]> {
      const auth = await importAuthWith(LEGACY, undefined);
      const app = new Hono();
      auth.mountFactoryAuth(app, {
        provider: fakeProvider(ssoCapability({ getClearSessionHeaders: vi.fn(() => ({ 'Set-Cookie': setCookie })) })),
      });
      return (await app.request('/auth/logout')).headers.getSetCookie();
    }

    it('splits two folded cookies back into two headers', async () => {
      const cookies = await clearCookiesFor('a=; Path=/; Max-Age=0, b=; Path=/; Max-Age=0');
      expect(cookies).toContain('a=; Path=/; Max-Age=0');
      expect(cookies).toContain('b=; Path=/; Max-Age=0');
    });

    it('does NOT split on the comma inside an Expires date', async () => {
      // This is the malformed-header case the lookahead exists for. A plain
      // split(',') yields `a=; Path=/; Expires=Thu` and ` 01 Jan 1970 ...`,
      // neither of which clears anything, and the failure is invisible: sign-out
      // returns 302 and the user stays signed in.
      const folded =
        'a=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT, b=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
      const cookies = await clearCookiesFor(folded);
      expect(cookies).toContain('a=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(cookies).toContain('b=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(cookies.some(cookie => cookie.startsWith('01 Jan'))).toBe(false);
    });

    it('leaves a single unfolded cookie alone', async () => {
      const cookies = await clearCookiesFor('only=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
      expect(cookies).toContain('only=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
    });

    it('emits nothing when the provider offers no clearing header', async () => {
      const cookies = await clearCookiesFor('');
      expect(cookies.some(cookie => cookie.startsWith('fake_session='))).toBe(false);
    });
  });
});

/**
 * B10: signing out revokes the session server-side, and POST is the route that
 * does it.
 *
 * A GET that ends a session is CSRF-triggerable — `<img src="/auth/logout">` on
 * any page signs the visitor out. POST is the documented route and needs no
 * inference about who asked. GET survives one more release because the SPA's
 * sign-out is still a top-level navigation to it, and it is guarded by
 * `Sec-Fetch-Dest`, which a page cannot forge.
 */
describe('logout', () => {
  /** SSO provider with a full session capability, so revocation is reachable. */
  function revocableProvider(overrides: Record<string, unknown> = {}) {
    const destroySession = vi.fn(async () => {});
    const getSessionIdFromRequest = vi.fn(() => 'sess-1');
    const provider = fakeProvider({
      ...ssoCapability(),
      createSession: vi.fn(),
      validateSession: vi.fn(),
      getSessionIdFromRequest,
      destroySession,
      ...overrides,
    });
    return { provider, destroySession, getSessionIdFromRequest };
  }

  function appFor(provider: IMastraAuthProvider): Hono {
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    return app;
  }

  describe('POST is the route that signs you out', () => {
    it('revokes the provider session, clears cookies, and redirects', async () => {
      const { provider, destroySession, getSessionIdFromRequest } = revocableProvider();
      const res = await appFor(provider).request('/auth/logout', { method: 'POST' });

      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('https://fake.example/logout');
      expect(getSessionIdFromRequest).toHaveBeenCalled();
      expect(destroySession).toHaveBeenCalledWith('sess-1');
      expect(res.headers.getSetCookie().some(cookie => cookie.includes('Max-Age=0'))).toBe(true);
    });

    it('still clears cookies when the provider cannot revoke', async () => {
      // isSessionProvider narrows on createSession/validateSession alone, so a
      // provider can pass the guard with no destroySession to call. Signing out
      // of the browser must not depend on that.
      const provider = fakeProvider({ ...ssoCapability(), createSession: vi.fn(), validateSession: vi.fn() });
      const res = await appFor(provider).request('/auth/logout', { method: 'POST' });

      expect(res.status).toBe(302);
      expect(res.headers.getSetCookie().some(cookie => cookie.includes('Max-Age=0'))).toBe(true);
    });

    it('still clears cookies when revocation throws', async () => {
      const { provider } = revocableProvider({
        destroySession: vi.fn(async () => {
          throw new Error('session store unreachable');
        }),
      });
      const res = await appFor(provider).request('/auth/logout', { method: 'POST' });

      expect(res.status).toBe(302);
      expect(res.headers.getSetCookie().some(cookie => cookie.includes('Max-Age=0'))).toBe(true);
    });

    it('does not revoke when the request carries no session id', async () => {
      const { provider, destroySession } = revocableProvider({ getSessionIdFromRequest: vi.fn(() => undefined) });
      await appFor(provider).request('/auth/logout', { method: 'POST' });
      expect(destroySession).not.toHaveBeenCalled();
    });

    it('revokes on the handler-shaped provider too, alongside its own sign-out call', async () => {
      const handleAuthRequest = vi.fn(async () => new Response(null, { status: 200 }));
      const destroySession = vi.fn(async () => {});
      const provider = fakeProvider({
        ...httpHandlerCapability({ handleAuthRequest }),
        createSession: vi.fn(),
        validateSession: vi.fn(),
        getSessionIdFromRequest: vi.fn(() => 'sess-2'),
        destroySession,
      });

      const res = await appFor(provider).request('/auth/logout', { method: 'POST' });
      expect(res.status).toBe(302);
      expect(destroySession).toHaveBeenCalledWith('sess-2');
      expect(new URL((handleAuthRequest.mock.calls[0]![0] as Request).url).pathname).toBe('/auth/api/sign-out');
    });
  });

  describe('the deprecated GET shim', () => {
    it('still signs out a real browser navigation', async () => {
      // The SPA's sign-out is window.location.assign('/auth/logout'), and a
      // bookmarked link is the same request. Neither may quietly stop working
      // while they are the only sign-out the product has.
      const { provider, destroySession } = revocableProvider();
      const res = await appFor(provider).request('/auth/logout', {
        headers: { 'Sec-Fetch-Dest': 'document' },
      });

      expect(res.status).toBe(302);
      expect(destroySession).toHaveBeenCalledWith('sess-1');
      expect(res.headers.getSetCookie().some(cookie => cookie.includes('Max-Age=0'))).toBe(true);
    });

    it('signs out a browser too old to send Sec-Fetch-Dest', async () => {
      // The residual gap, and the reason this is a shim rather than the answer:
      // with no header there is nothing to distinguish a navigation from an
      // <img>, and refusing would break sign-out for those people instead.
      const { provider, destroySession } = revocableProvider();
      const res = await appFor(provider).request('/auth/logout');

      expect(res.status).toBe(302);
      expect(destroySession).toHaveBeenCalled();
    });

    it.each(['image', 'script', 'iframe', 'style', 'font', 'empty'])(
      'refuses to sign out a request whose Sec-Fetch-Dest is %j',
      async destination => {
        // `<img src="/auth/logout">` on any page. The response still redirects,
        // so nothing looks broken to the attacker's page — it simply does not
        // touch the session.
        const { provider, destroySession } = revocableProvider();
        const res = await appFor(provider).request('/auth/logout', {
          headers: { 'Sec-Fetch-Dest': destination },
        });

        expect(res.status).toBe(302);
        expect(res.headers.get('location')).toBe('/');
        expect(destroySession).not.toHaveBeenCalled();
        expect(res.headers.getSetCookie()).toEqual([]);
      },
    );

    it('guards the handler-shaped provider the same way', async () => {
      const handleAuthRequest = vi.fn(async () => new Response(null, { status: 200 }));
      const provider = fakeProvider(httpHandlerCapability({ handleAuthRequest }));
      const res = await appFor(provider).request('/auth/logout', {
        headers: { 'Sec-Fetch-Dest': 'image' },
      });

      expect(res.status).toBe(302);
      expect(handleAuthRequest).not.toHaveBeenCalled();
    });

    it('POST is never subject to the shim guard', async () => {
      // A cross-origin form POST cannot carry the SPA's cookies as SameSite=Lax,
      // and POST is the route we tell people to use, so it does not inspect
      // Sec-Fetch-Dest at all.
      const { provider, destroySession } = revocableProvider();
      await appFor(provider).request('/auth/logout', {
        method: 'POST',
        headers: { 'Sec-Fetch-Dest': 'empty' },
      });
      expect(destroySession).toHaveBeenCalled();
    });
  });
});

/**
 * B11: transparent session refresh on Factory routes.
 *
 * `packages/server` already refreshes an expired session on `/api/*`. The
 * Factory did not, so the same provider with a working `refreshSession` kept an
 * API client signed in indefinitely and signed a browser out of the Factory the
 * moment its access token expired. Same session, two lifetimes, decided only by
 * which host served the route.
 */
describe('session refresh', () => {
  /**
   * A provider whose access token expires after the first use. `authenticateToken`
   * accepts only the token currently in `state.valid`, and `refreshSession` mints
   * the next one — so a request presenting a stale cookie can only succeed by
   * actually going through the refresh path.
   */
  function expiringProvider(overrides: Record<string, unknown> = {}) {
    const state = { valid: 'token-2' };
    const refreshSession = vi.fn(async (sessionId: string) => (sessionId === 'sess-1' ? { id: sessionId } : null));
    const getSessionIdFromRequest = vi.fn(() => 'sess-1');
    const getSessionHeaders = vi.fn(() => ({ 'Set-Cookie': `refreshed=${state.valid}; Path=/; HttpOnly` }));
    const authenticateToken = vi.fn(async (token: string) =>
      token === state.valid ? { id: 'u1', organizationId: 'org_a' } : null,
    );
    const provider = fakeProvider({
      authenticateToken,
      createSession: vi.fn(),
      validateSession: vi.fn(),
      getSessionIdFromRequest,
      refreshSession,
      getSessionHeaders,
      ...overrides,
    });
    return { provider, refreshSession, getSessionIdFromRequest, authenticateToken };
  }

  function gatedApp(provider: IMastraAuthProvider): Hono {
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    app.get('/web/whoami', c => c.json(factoryAuthTenant(c) ?? { tenant: null }));
    return app;
  }

  it('refreshes an expired session and serves the request', async () => {
    const { provider, refreshSession } = expiringProvider();
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-1' },
    });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ orgId: 'org_a', userId: 'u1' });
    expect(refreshSession).toHaveBeenCalledWith('sess-1');
  });

  it('sends the refreshed cookie back on the request that triggered the refresh', async () => {
    // Without this the next request presents the same expired cookie and
    // refreshes again — working, but re-refreshing forever.
    const { provider } = expiringProvider();
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-1' },
    });

    expect(res.headers.getSetCookie()).toContain('refreshed=token-2; Path=/; HttpOnly');
  });

  it('does not refresh when the first authentication already succeeded', async () => {
    const { provider, refreshSession } = expiringProvider();
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-2' },
    });

    expect(res.status).toBe(200);
    expect(refreshSession).not.toHaveBeenCalled();
  });

  it('401s without refreshing when the provider cannot refresh', async () => {
    // isSessionProvider narrows on createSession/validateSession, so a provider
    // can pass that guard with none of the three refresh members.
    const provider = fakeProvider({
      authenticateToken: vi.fn(async () => null),
      createSession: vi.fn(),
      validateSession: vi.fn(),
    });
    const res = await gatedApp(provider).request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });

  it('401s when the request carries no session id to refresh', async () => {
    const { provider, refreshSession } = expiringProvider({ getSessionIdFromRequest: vi.fn(() => null) });
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-1' },
    });

    expect(res.status).toBe(401);
    expect(refreshSession).not.toHaveBeenCalled();
  });

  it('401s and sends no cookie when the refresh returns nothing', async () => {
    const { provider } = expiringProvider({ refreshSession: vi.fn(async () => null) });
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-1' },
    });

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it('401s and sends no cookie when the refresh throws', async () => {
    const { provider } = expiringProvider({
      refreshSession: vi.fn(async () => {
        throw new Error('session store unreachable');
      }),
    });
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-1' },
    });

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it('401s and drops the cookie when the refreshed session still does not authenticate', async () => {
    // Sending a Set-Cookie for a session that did not work would replace the
    // browser's cookie with one that is no better, and sign the person out
    // holding a fresh cookie.
    const { provider } = expiringProvider({
      getSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'refreshed=still-wrong; Path=/' })),
    });
    const res = await gatedApp(provider).request('/web/whoami', {
      headers: { Accept: 'application/json', Authorization: 'Bearer token-1' },
    });

    expect(res.status).toBe(401);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it('redirects an expired browser navigation to /signin when the refresh fails', async () => {
    const { provider } = expiringProvider({ refreshSession: vi.fn(async () => null) });
    const res = await gatedApp(provider).request('/web/whoami', { headers: { Accept: 'text/html' } });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toContain('/signin?returnTo=');
  });
});

/**
 * B12: a signed-in user always has an organization.
 *
 * Seven org-gated route groups each had the same decision to make when a user
 * resolved to no organization, and each made the safe-looking one: refuse. The
 * result was a user who had authenticated, held a valid session, and got a 403
 * that is indistinguishable from "you are not allowed" — with nothing anywhere
 * saying "your provider has no organizations".
 */
describe('tenant organization resolution', () => {
  function tenantApp(provider: IMastraAuthProvider): Hono {
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    app.get('/web/whoami', c => c.json(factoryAuthTenant(c) ?? { tenant: null }));
    return app;
  }

  async function tenantOf(provider: IMastraAuthProvider): Promise<Record<string, unknown>> {
    const res = await tenantApp(provider).request('/web/whoami', { headers: { Accept: 'application/json' } });
    return (await res.json()) as Record<string, unknown>;
  }

  it('resolves a private organization for a provider that has none', async () => {
    // The doneWhen: a no-org provider reaches the board rather than 403ing.
    const tenant = await tenantOf(
      fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'u1', email: 'u1@example.com' })) }),
    );
    expect(tenant).toEqual({ orgId: 'user:u1', userId: 'u1' });
  });

  it('keeps a declared organization rather than deriving one', async () => {
    // Preferring a derived id over the provider's answer would move a member of
    // a real organization into a private one, where their team's data is not.
    const tenant = await tenantOf(
      fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'u1', organizationId: 'org_real' })) }),
    );
    expect(tenant).toEqual({ orgId: 'org_real', userId: 'u1' });
  });

  it('gives two no-org users two different organizations', async () => {
    // The synthetic id is derived from the user's own id, so it is a private
    // organization of one rather than a shared bucket. If these collided, the
    // change would be a data leak instead of a fix.
    const first = await tenantOf(fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'u1' })) }));
    const second = await tenantOf(fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'u2' })) }));

    expect(first.orgId).not.toBe(second.orgId);
    expect(first).toEqual({ orgId: 'user:u1', userId: 'u1' });
    expect(second).toEqual({ orgId: 'user:u2', userId: 'u2' });
  });

  it('is stable across requests, because it is a storage key', async () => {
    const provider = fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'u1' })) });
    const app = tenantApp(provider);
    const first = await (await app.request('/web/whoami', { headers: { Accept: 'application/json' } })).json();
    const second = await (await app.request('/web/whoami', { headers: { Accept: 'application/json' } })).json();
    expect(first).toEqual(second);
  });

  it('still prefers a bootstrapped organization over a derived one', async () => {
    // ensureOrganization runs first; the derived id is the fallback for when it
    // yields nothing, not a replacement for it.
    const tenant = await tenantOf(
      fakeProvider({
        authenticateToken: vi.fn(async () => ({ id: 'u1' })),
        ensureOrganization: vi.fn(async () => 'org_boot'),
        isOrganizationAdmin: vi.fn(async () => false),
      }),
    );
    expect(tenant).toEqual({ orgId: 'org_boot', userId: 'u1' });
  });

  it('does not invent an organization for a request with no user', async () => {
    // The gate refuses before the route runs, so there is no identity to derive
    // one from. Resolving an organization is for signed-in users; it is not a
    // way in.
    const app = tenantApp(fakeProvider({ authenticateToken: vi.fn(async () => null) }));
    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });
});

/** A kit fake with no valid session, so `/auth/me` answers signed-out. */
function kitFake() {
  return kitFakeProvider({ tokens: [] });
}

/**
 * U2: the `/auth/me` descriptor, against the kit's own fakes.
 *
 * The seam tests above build their doubles by hand, which is right for testing
 * the gate. This block deliberately does not: it drives the four sign-in kinds
 * through `@mastra/factory-auth/testing`, so what the host emits is checked
 * against the same provider shapes the kit's conformance suite uses. A
 * hand-rolled double that happens to satisfy `isCredentialsProvider` proves the
 * host reads its own fixture; the kit's fake proves the host reads a provider.
 *
 * The sign-up half is the server side of a fact the SPA also has to get right.
 * `/auth/me` carries the same answer twice with opposite polarity for one
 * release — positive `auth.signIn.signUpEnabled`, negative legacy
 * `signUpDisabled` — and the UI stream covers what the browser does with them.
 * What is covered here is narrower and is the host's alone: `authMeta()`
 * derives the negative field *from* the descriptor rather than asking the
 * provider a second time, so the pair cannot drift no matter what the provider
 * does.
 */
describe('/auth/me descriptor, against the kit fakes', () => {
  async function authMeFor(provider: IMastraAuthProvider): Promise<AuthMeBody> {
    const app = new Hono();
    mountFactoryAuth(app, { provider });
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    return (await res.json()) as AuthMeBody;
  }

  describe('the four sign-in kinds', () => {
    it('hosted: a provider with an SSO login only', async () => {
      const body = await authMeFor(withSSO(kitFake()) as unknown as IMastraAuthProvider);
      expect(body.auth.signIn.kind).toBe('hosted');
      // No credentials, so nothing is claimed about sign-up in either polarity.
      expect(body.auth.signIn.signUpEnabled).toBeUndefined();
      expect(body.auth.signIn.credentialsBasePath).toBeUndefined();
      expect(body.signUpDisabled).toBeUndefined();
      expect(body.auth.features.logout).toBe(true);
    });

    it('credentials: a provider with an email/password sign-in only', async () => {
      const body = await authMeFor(withCredentials(kitFake()) as unknown as IMastraAuthProvider);
      expect(body.auth.signIn.kind).toBe('credentials');
      expect(body.auth.signIn.credentialsBasePath).toBe('/auth');
      expect(body.auth.signIn.signUpEnabled).toBe(true);
    });

    it('both: a provider offering hosted login and credentials', async () => {
      const body = await authMeFor(withCredentials(withSSO(kitFake())) as unknown as IMastraAuthProvider);
      expect(body.auth.signIn.kind).toBe('both');
      expect(body.auth.signIn.credentialsBasePath).toBe('/auth');
    });

    it('none: a provider that validates tokens but cannot sign anyone in', async () => {
      // Not "auth is off". This provider enforces; it simply has no browser
      // sign-in, which is what today's Supabase and Firebase providers are.
      const body = await authMeFor(kitFake() as unknown as IMastraAuthProvider);
      expect(body.auth.signIn.kind).toBe('none');
      expect(body.auth.features.logout).toBe(false);
      expect(body.authenticated).toBe(false);
    });
  });

  describe('features come from the capabilities the fake actually declares', () => {
    it('reports organizations and session revocation when the fake has them', async () => {
      const provider = withSession(withOrganizations(withSSO(kitFake())));
      const body = await authMeFor(provider as unknown as IMastraAuthProvider);
      expect(body.auth.features).toEqual({
        logout: true,
        organizations: true,
        refresh: true,
        sessionRevocation: true,
      });
    });

    it('reports logout for an http-handler provider that cannot sign anyone in', async () => {
      // kind is `none`, but the provider serves its own auth routes, so there
      // is a sign-out to offer.
      const body = await authMeFor(withHttpHandler(kitFake()) as unknown as IMastraAuthProvider);
      expect(body.auth.signIn.kind).toBe('none');
      expect(body.auth.features.logout).toBe(true);
    });
  });

  /**
   * The server-side half of the polarity contract. Every case asserts the two
   * fields *in the same payload*, and the last one asserts the invariant
   * directly rather than by example.
   */
  describe('both sign-up fields, derived from one answer', () => {
    it.each([
      { what: 'sign-up on', signUpEnabled: true, enabled: true },
      { what: 'sign-up off', signUpEnabled: false, enabled: false },
      { what: 'no isSignUpEnabled method at all', signUpEnabled: null, enabled: true },
      {
        what: 'a provider whose sign-up check throws',
        signUpEnabled: () => {
          throw new Error('sign-up check is down');
        },
        enabled: false,
      },
    ])('$what', async ({ signUpEnabled, enabled }) => {
      const provider = withCredentials(kitFake(), { signUpEnabled });
      const body = await authMeFor(provider as unknown as IMastraAuthProvider);

      expect(body.auth.signIn.signUpEnabled).toBe(enabled);
      expect(body.signUpDisabled).toBe(enabled ? undefined : true);
      // Opposite polarity, same payload, every time.
      expect(body.auth.signIn.signUpEnabled).toBe(!(body.signUpDisabled ?? false));
    });

    it('asks the provider once, so the two fields cannot answer differently', async () => {
      // The property the derivation exists for. If `signUpDisabled` were
      // computed by asking the provider a second time, an implementation that
      // is not idempotent — a flag read from config, a cache that expires
      // between the two calls — could answer differently, and the payload would
      // contradict itself. One call means that cannot happen.
      let asks = 0;
      const provider = withCredentials(kitFake(), {
        signUpEnabled: () => {
          asks += 1;
          // Answers differently every time it is asked.
          return asks % 2 === 1;
        },
      });

      const body = await authMeFor(provider as unknown as IMastraAuthProvider);

      expect(asks).toBe(1);
      expect(body.auth.signIn.signUpEnabled).toBe(!(body.signUpDisabled ?? false));
    });
  });

  it('keeps the provider name beside the descriptor for one release', async () => {
    const body = await authMeFor(withSSO(kitFake()) as unknown as IMastraAuthProvider);
    expect(typeof body.provider).toBe('string');
    expect(body.auth).toBeDefined();
  });
});

/**
 * B17 — BACKEND EXIT GATE.
 *
 * Everything here runs with `MASTRACODE_AUTH_IDENTITY_V2` ON, which is the
 * state the lane is trying to reach. The suites above mostly assert the shipped
 * default; this one asserts the destination, so the two together say what the
 * flag actually switches.
 *
 * It is a gate rather than a coverage pass, so every case drives a real
 * `app.request()` through `mountFactoryAuth` and asserts an HTTP outcome. A test
 * that calls an exported helper directly can keep passing while the wiring that
 * reaches it rots; the point of a gate is to fail when the seam regresses, not
 * when a function does.
 *
 * The five it exists for:
 *
 *   1. a cookie-only request authenticates through the gate — the browser path,
 *      which nothing covered before;
 *   2. a `{ uid }`-shaped provider authenticates end to end;
 *   3. a provider with no organizations reaches the board without a 403;
 *   4. each capability branch — SSO, http-handler, neither — drives real
 *      responses rather than a route-table assertion;
 *   5. the `{ session, tokens }` callback branch, which neither host asserted.
 */
describe('BACKEND EXIT GATE (flag ON)', () => {
  const SECRET = 'g'.repeat(32);

  /** The auth module, loaded with the flag and the cookie secret set. */
  async function gateAuth(): Promise<typeof import('./auth.js')> {
    process.env.MASTRACODE_AUTH_IDENTITY_V2 = 'true';
    process.env.MASTRACODE_AUTH_SESSION_SECRET = SECRET;
    vi.resetModules();
    return import('./auth.js');
  }

  afterEach(() => {
    delete process.env.MASTRACODE_AUTH_IDENTITY_V2;
    delete process.env.MASTRACODE_AUTH_SESSION_SECRET;
    vi.resetModules();
  });

  /** A gated app with a protected board route that reports the tenant. */
  function board(auth: typeof import('./auth.js'), provider: IMastraAuthProvider): Hono {
    const app = new Hono();
    auth.mountFactoryAuth(app, { provider });
    app.get('/web/board', c => c.json({ ok: true, tenant: auth.factoryAuthTenant(c) ?? null }));
    return app;
  }

  const json = { Accept: 'application/json' };

  it('1. authenticates a cookie-only request, with no Authorization header', async () => {
    // A browser navigation sends no Authorization header. The provider reads the
    // Cookie header itself, which the empty token is its documented signal to
    // do. Nothing exercised this path before: every gate test sent a bearer.
    const auth = await gateAuth();
    const authenticateToken = vi.fn(async (token: string, request: Request) => {
      if (token) return null;
      const cookie = request.headers.get('cookie') ?? '';
      return /(?:^|;\s*)provider_session=good\b/.test(cookie) ? { id: 'u-cookie', organizationId: 'org_a' } : null;
    });
    const app = board(auth, fakeProvider({ authenticateToken }));

    const ok = await app.request('/web/board', { headers: { ...json, Cookie: 'provider_session=good' } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ ok: true, tenant: { orgId: 'org_a', userId: 'u-cookie' } });

    // And the negative, so the assertion above is about the cookie and not
    // about a provider that says yes to everything.
    const denied = await app.request('/web/board', { headers: { ...json, Cookie: 'provider_session=stale' } });
    expect(denied.status).toBe(401);
  });

  it('1b. authenticates a cookie-only request against the host-minted session cookie', async () => {
    // The other cookie source: the host mints and reads its own signed cookie,
    // so the token reaches the provider as an argument.
    const auth = await gateAuth();
    const provider = fakeProvider({
      ...ssoCapability({
        handleCallback: vi.fn(async () => ({ user: { id: 'u-host' }, tokens: { accessToken: 'host-token' } })),
      }),
      createSession: vi.fn(async () => ({ id: 'sess' })),
      validateSession: vi.fn(),
      getSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'ignored=1' })),
      authenticateToken: vi.fn(async (token: string) => (token === 'host-token' ? { id: 'u-host' } : null)),
    });
    const app = board(auth, provider);

    const callback = await app.request('/auth/callback?code=ok&state=id%7C%2F');
    const session = callback.headers.getSetCookie().find(c => c.startsWith('__Host-mastra_factory_session='))!;
    expect(session).toBeDefined();

    const res = await app.request('/web/board', { headers: { ...json, Cookie: session.split(';')[0]! } });
    expect(res.status).toBe(200);
    expect((await res.json()).tenant.userId).toBe('u-host');
  });

  it('2. authenticates a { uid }-shaped provider end to end', async () => {
    // Firebase names its id `uid`. Before the kit this authenticated as nobody
    // and then failed somewhere unrelated with a message about state.
    const auth = await gateAuth();
    const app = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => ({ uid: 'fb-1' })) }));

    const res = await app.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } });
    expect(res.status).toBe(200);
    expect((await res.json()).tenant.userId).toBe('fb-1');
  });

  it('2b. authenticates a { sub }-shaped provider end to end', async () => {
    // Raw OIDC claims. Same story as `uid`.
    const auth = await gateAuth();
    const app = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => ({ sub: 'oidc-1' })) }));

    const res = await app.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } });
    expect(res.status).toBe(200);
    expect((await res.json()).tenant.userId).toBe('oidc-1');
  });

  it('3. lets a provider with no organizations reach the board', async () => {
    // Every org-gated route used to refuse this user with a 403 that reads as
    // "not allowed". They now act inside a private organization of their own.
    const auth = await gateAuth();
    const app = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'solo' })) }));

    const res = await app.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, tenant: { orgId: 'user:solo', userId: 'solo' } });
  });

  it('3b. keeps two organization-less users apart', async () => {
    // The property that makes case 3 a fix rather than a leak.
    const auth = await gateAuth();
    const first = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'a' })) }));
    const second = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => ({ id: 'b' })) }));

    const one = await (await first.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } })).json();
    const two = await (await second.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } })).json();
    expect(one.tenant.orgId).not.toBe(two.tenant.orgId);
  });

  describe('4. every capability branch drives real responses', () => {
    it('SSO: login redirects to the provider and the gate stays open on /auth/*', async () => {
      const auth = await gateAuth();
      const app = board(auth, fakeProvider(ssoCapability()));

      const login = await app.request('/auth/login?returnTo=%2Fdash');
      expect(login.status).toBe(302);
      expect(login.headers.get('location')).toBe('https://fake.example/login');

      const logout = await app.request('/auth/logout', { method: 'POST' });
      expect(logout.status).toBe(302);

      // An SSO provider serves no /auth/api/* surface.
      expect((await app.request('/auth/api/anything', { method: 'POST' })).status).toBe(404);
    });

    it('http-handler: /auth/api/* is proxied and login goes to the SPA form', async () => {
      const auth = await gateAuth();
      const handleAuthRequest = vi.fn(async () => new Response('handled', { status: 200 }));
      const app = board(auth, fakeProvider(httpHandlerCapability({ handleAuthRequest })));

      const proxied = await app.request('/auth/api/sign-in/email', { method: 'POST' });
      expect(proxied.status).toBe(200);
      expect(await proxied.text()).toBe('handled');

      const login = await app.request('/auth/login?returnTo=%2Fchat');
      expect(login.status).toBe(302);
      expect(login.headers.get('location')).toBe('/signin?returnTo=%2Fchat');
    });

    it('neither: only /auth/me is served, and the gate still protects the app', async () => {
      const auth = await gateAuth();
      const app = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => null) }));

      const me = await app.request('/auth/me');
      expect(me.status).toBe(200);
      expect((await me.json()).auth.signIn.kind).toBe('none');

      // No hosted login exists to redirect to, and the app is still gated.
      expect((await app.request('/auth/login')).status).toBe(404);
      expect((await app.request('/web/board', { headers: json })).status).toBe(401);
    });
  });

  it('5. completes the { session, tokens } callback branch', async () => {
    // The branch neither host asserted: a provider that returns tokens but no
    // cookies, leaving the session for the host to create and the cookie for
    // the host to mint.
    const auth = await gateAuth();
    const createSession = vi.fn(async () => ({ id: 'sess-1' }));
    const provider = fakeProvider({
      ...ssoCapability({
        handleCallback: vi.fn(async () => ({
          user: { id: 'u-1', organizationId: 'org_a' },
          tokens: { accessToken: 'access-1', refreshToken: 'refresh-1', expiresAt: 123 },
        })),
      }),
      createSession,
      validateSession: vi.fn(),
      getSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'provider=1' })),
    });
    const app = board(auth, provider);

    const res = await app.request('/auth/callback?code=ok&state=id%7C%2Fdash');

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/dash');
    // The provider's session record is created from the tokens it returned,
    // carrying the org so a later validate resolves the same tenant.
    expect(createSession).toHaveBeenCalledWith('u-1', {
      accessToken: 'access-1',
      refreshToken: 'refresh-1',
      expiresAt: 123,
      organizationId: 'org_a',
    });
    // And the host mints the cookie, rather than the provider's headers landing.
    const cookies = res.headers.getSetCookie();
    expect(cookies.some(c => c.startsWith('__Host-mastra_factory_session='))).toBe(true);
    expect(cookies.some(c => c.startsWith('provider='))).toBe(false);
  });

  /**
   * The B3 differential table, re-run with the flag ON against real HTTP.
   *
   * The table in `identity resolution under the compat flag` compares the two
   * readers; this asserts what the destination state actually serves, so a
   * regression in identity resolution fails the gate rather than only the
   * comparison.
   */
  describe('identity shapes, end to end', () => {
    it.each([
      { what: 'a flat id', payload: { id: 'u1' }, userId: 'u1' },
      { what: 'a Firebase uid', payload: { uid: 'fb1' }, userId: 'fb1' },
      { what: 'raw OIDC claims', payload: { sub: 'oidc1' }, userId: 'oidc1' },
      { what: 'uid winning over sub', payload: { uid: 'fb1', sub: 'oidc1' }, userId: 'fb1' },
      { what: 'id winning over both', payload: { id: 'i1', uid: 'fb1', sub: 'oidc1' }, userId: 'i1' },
      { what: 'a numeric id', payload: { id: 7 }, userId: '7' },
      {
        what: 'a session wrapper',
        payload: { session: { activeOrganizationId: 'o' }, user: { id: 'u1' } },
        userId: 'u1',
      },
    ])('authenticates $what', async ({ payload, userId }) => {
      const auth = await gateAuth();
      const app = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => payload) }));

      const res = await app.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } });
      expect(res.status).toBe(200);
      expect((await res.json()).tenant.userId).toBe(userId);
    });

    it.each([
      { what: 'a blank id', payload: { id: '   ' } },
      { what: 'a vendor-only id the kit does not read', payload: { workosId: 'w1' } },
      { what: 'a wrapper whose user half names nobody', payload: { session: {}, user: {}, id: 'top' } },
      { what: 'a payload naming no user', payload: { email: 'e@x.com' } },
      { what: 'no payload at all', payload: null },
    ])('refuses $what', async ({ payload }) => {
      const auth = await gateAuth();
      const app = board(auth, fakeProvider({ authenticateToken: vi.fn(async () => payload) }));

      const res = await app.request('/web/board', { headers: { ...json, Authorization: 'Bearer t' } });
      expect(res.status).toBe(401);
    });
  });
});

/**
 * B18: what flipping the default actually costs a signed-in person.
 *
 * The upgrade note for this release rests on these two answers, so they are
 * measured rather than asserted. The direction is the opposite of what the
 * changeset originally claimed, which is why it is pinned here.
 */
describe('sessions across the flag flip', () => {
  const SECRET = 'f'.repeat(32);

  async function importAuthWith(flag: string, secret: string | undefined): Promise<typeof import('./auth.js')> {
    process.env.MASTRACODE_AUTH_IDENTITY_V2 = flag;
    if (secret === undefined) delete process.env.MASTRACODE_AUTH_SESSION_SECRET;
    else process.env.MASTRACODE_AUTH_SESSION_SECRET = secret;
    vi.resetModules();
    return import('./auth.js');
  }

  afterEach(() => {
    delete process.env.MASTRACODE_AUTH_IDENTITY_V2;
    delete process.env.MASTRACODE_AUTH_SESSION_SECRET;
    vi.resetModules();
  });

  /** A provider that authenticates from its own cookie, as WorkOS and Okta do. */
  function providerCookieProvider() {
    return fakeProvider({
      authenticateToken: vi.fn(async (token: string, request: Request) => {
        if (token) return null;
        const cookie = request.headers.get('cookie') ?? '';
        return /(?:^|;\s*)wos_session=live\b/.test(cookie) ? { id: 'u1' } : null;
      }),
    });
  }

  function board(auth: typeof import('./auth.js'), provider: IMastraAuthProvider): Hono {
    const app = new Hono();
    auth.mountFactoryAuth(app, { provider });
    app.get('/web/board', c => c.json({ tenant: auth.factoryAuthTenant(c) ?? null }));
    return app;
  }

  it('keeps a provider-minted session alive when the default turns V2 on', async () => {
    // The upgrade most deployments actually perform. The host reads no cookie of
    // its own here, so `requestAuthToken` yields '' — which is the provider's
    // documented signal to read the Cookie header itself, exactly as before.
    // Nobody is signed out.
    const auth = await importAuthWith('true', SECRET);
    const res = await board(auth, providerCookieProvider()).request('/web/board', {
      headers: { Accept: 'application/json', Cookie: 'wos_session=live' },
    });

    expect(res.status).toBe(200);
    expect((await res.json()).tenant.userId).toBe('u1');
  });

  it('signs out a session minted by the host when the flag is set back to false', async () => {
    // The cost is on the ROLLBACK, not the upgrade, and only for deployments
    // whose provider hands back tokens instead of cookies. A session minted
    // under V2 lives in the host's own signed cookie, and the legacy path never
    // reads that cookie — so going back sends those people to sign-in once.
    const on = await importAuthWith('true', SECRET);
    const provider = fakeProvider({
      ...ssoCapability({
        handleCallback: vi.fn(async () => ({ user: { id: 'u1' }, tokens: { accessToken: 'access-1' } })),
      }),
      createSession: vi.fn(async () => ({ id: 's1' })),
      validateSession: vi.fn(),
      getSessionHeaders: vi.fn(() => ({ 'Set-Cookie': 'provider_session=legacy; Path=/' })),
      authenticateToken: vi.fn(async (token: string) => (token === 'access-1' ? { id: 'u1' } : null)),
    });

    const callback = await board(on, provider).request('/auth/callback?code=ok&state=id%7C%2F');
    const hostCookie = callback.headers.getSetCookie().find(c => c.startsWith('__Host-mastra_factory_session='))!;
    expect(hostCookie).toBeDefined();

    // Same cookie, same provider, legacy reader.
    const off = await importAuthWith('false', SECRET);
    const res = await board(off, provider).request('/web/board', {
      headers: { Accept: 'application/json', Cookie: hostCookie.split(';')[0]! },
    });

    expect(res.status).toBe(401);
  });
});
