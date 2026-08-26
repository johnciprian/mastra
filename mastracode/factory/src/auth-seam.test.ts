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
