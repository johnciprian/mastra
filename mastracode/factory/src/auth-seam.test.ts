import type { IMastraAuthProvider } from '@mastra/core/server';
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
 */
describe('identity resolution under the compat flag', () => {
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
      what: 'a blank id, which is a storage key every user would share',
      payload: { id: '   ' },
      legacy: '   ',
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
    const off = await tenantFor(await importAuthWith(undefined), payload);
    expect(off?.userId ?? null).toBe(legacy);

    const on = await tenantFor(await importAuthWith('true'), payload);
    expect(on?.userId ?? null).toBe(v2);
  });

  it('takes the org from the user half when the session names none, only under v2', async () => {
    // A widening rather than a fix: a session that resolved as personal can now
    // resolve into an organization the user does belong to. Worth stating on its
    // own because it changes which org-scoped data a request can reach.
    const payload = { session: {}, user: { id: 'u1', organizationId: 'org_u' } };

    // This provider does no organization bootstrap, so legacy leaves the user
    // personal: the org sitting on the user half is simply never read.
    const off = await tenantFor(await importAuthWith(undefined), payload);
    expect(off).toEqual({ userId: 'u1' });

    const on = await tenantFor(await importAuthWith('true'), payload);
    expect(on).toEqual({ userId: 'u1', orgId: 'org_u' });
  });

  it('lets a provider map its own payload through the kit escape hatch, under v2', async () => {
    // The id lives under a custom claim the kit cannot know about. Legacy has no
    // such hook, so the same payload authenticates as nobody there.
    const payload = { 'https://claims.example/uid': 'custom1' };
    const toIdentity = vi.fn((raw: unknown) => ({
      id: (raw as Record<string, string>)['https://claims.example/uid']!,
    }));

    const off = await tenantFor(await importAuthWith(undefined), payload, { toIdentity });
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
