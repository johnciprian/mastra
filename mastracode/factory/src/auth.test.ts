import type { IMastraAuthProvider } from '@mastra/core/server';
import { Hono } from 'hono';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  getFactoryAuthOrgId,
  getFactoryAuthUser,
  getFactoryAuthUserId,
  mountFactoryAuth,
  factoryAuthTenant,
} from './auth.js';

// A hosted-login provider, built here rather than mocked out of a vendor
// package. This suite is about the provider-neutral gate — which routes it
// derives, who it lets through, what it reports to the SPA — and none of that
// depends on which vendor is behind the provider. Building the double locally
// says so, and it is what lets the module under test have no vendor dependency
// at all. `authenticateToken`'s behavior is swapped per-test via
// `mockAuthenticate`.
//
// Every `mockAuthenticate` payload below names the user with `id`. These
// fixtures used to say `workosId` instead — a shape no provider actually
// emits on its own — and they passed only because the pre-kit reader accepted
// that vendor key as an identifier. The payloads that still exercise it
// deliberately live in `auth-seam.test.ts`, where the differential table
// asserts what each flag path makes of them.
const mockAuthenticate = vi.fn();
const mockGetLoginUrl = vi.fn((_redirectUri: string, _state: string) => 'https://idp.example/login');
const mockHandleCallback = vi.fn(async () => ({
  user: { email: 'a@b.com' },
  cookies: ['idp_session=sealed; Path=/'],
}));
const mockGetLogoutUrl = vi.fn(async () => 'https://idp.example/logout');
const mockGetClearSessionHeaders = vi.fn(() => ({ 'Set-Cookie': 'idp_session=; Path=/; HttpOnly; Max-Age=0' }));
// Personal-org bootstrap (IOrganizationsProvider). A provider's own bootstrap
// mechanics are covered in its package; here the double models "no org → org_new".
const mockEnsureOrganization = vi.fn(async (_userId: string) => 'org_new');
const mockIsOrganizationAdmin = vi.fn(async () => false);

const ORIGINAL_ENV = { ...process.env };

/**
 * The provider under test: hosted login (`ISSOProvider`) plus organizations,
 * constructed and passed explicitly by each caller.
 */
function hostedProvider(): IMastraAuthProvider {
  return {
    name: 'hosted',
    getLoginUrl: mockGetLoginUrl,
    handleCallback: mockHandleCallback,
    authenticateToken: mockAuthenticate,
    authorizeUser: async () => true,
    getLogoutUrl: mockGetLogoutUrl,
    getClearSessionHeaders: mockGetClearSessionHeaders,
    ensureOrganization: mockEnsureOrganization,
    isOrganizationAdmin: mockIsOrganizationAdmin,
  } as unknown as IMastraAuthProvider;
}

beforeEach(() => {
  vi.clearAllMocks();
  // Restore default mock behavior after clearAllMocks wipes it.
  mockGetLoginUrl.mockReturnValue('https://idp.example/login');
  mockHandleCallback.mockResolvedValue({ user: { email: 'a@b.com' }, cookies: ['idp_session=sealed; Path=/'] });
  mockGetLogoutUrl.mockResolvedValue('https://idp.example/logout');
  mockGetClearSessionHeaders.mockReturnValue({ 'Set-Cookie': 'idp_session=; Path=/; HttpOnly; Max-Age=0' });
  mockEnsureOrganization.mockResolvedValue('org_new');
});

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

/** Build a gated app where the protected catch-all returns 200 "ok". */
function buildApp() {
  const app = new Hono();
  const enabled = mountFactoryAuth(app, { provider: hostedProvider() });
  app.get('*', c => c.text('ok'));
  app.post('*', c => c.text('ok'));
  return { app, enabled };
}

describe('active provider resolution', () => {
  it('leaves auth disabled when no provider is passed', () => {
    expect(mountFactoryAuth(new Hono())).toBe(false);
  });

  it('enables auth when a provider is passed', () => {
    expect(mountFactoryAuth(new Hono(), { provider: hostedProvider() })).toBe(true);
  });

  it('ignores the WORKOS_* environment entirely', () => {
    // The env vars used to imply a provider all on their own, so a deployment
    // that merely had WorkOS credentials in its environment acquired an
    // identity provider nobody had configured. Setting all three must now do
    // nothing at all: auth is on when, and only when, a provider was passed.
    process.env.WORKOS_API_KEY = 'sk_test';
    process.env.WORKOS_CLIENT_ID = 'client_test';
    process.env.WORKOS_REDIRECT_URI = 'http://localhost:4111/auth/callback';

    expect(mountFactoryAuth(new Hono())).toBe(false);
  });
});

describe('mountFactoryAuth (disabled)', () => {
  it('is a no-op and leaves routes ungated', async () => {
    // No provider, so no gate — the same app shape as buildApp() otherwise.
    const app = new Hono();
    const enabled = mountFactoryAuth(app);
    app.get('*', c => c.text('ok'));
    app.post('*', c => c.text('ok'));
    expect(enabled).toBe(false);

    const res = await app.request('/api/anything', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
  });
});

describe('mountFactoryAuth gate (enabled)', () => {
  it('redirects unauthenticated HTML navigation to /signin with returnTo', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/some/page', { headers: { Accept: 'text/html' } });
    expect(res.status).toBe(302);
    const location = res.headers.get('location') ?? '';
    expect(location.startsWith('/signin?returnTo=')).toBe(true);
    expect(decodeURIComponent(location.split('returnTo=')[1]!)).toBe('/some/page');
  });

  it('lets unauthenticated HTML navigation reach /signin so the SPA can render the sign-in page', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/signin?returnTo=%2Fchat', { headers: { Accept: 'text/html' } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
  });

  it('forwards the platform deploy-auth /login landing to /signin with its query intact', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/login?error=access_denied&error_description=You%20do%20not%20have%20access', {
      headers: { Accept: 'text/html' },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(
      '/signin?error=access_denied&error_description=You%20do%20not%20have%20access',
    );
  });

  it('lets unauthenticated requests fetch static assets and metadata needed by the sign-in page', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    for (const path of [
      '/assets/app.js',
      '/manifest.webmanifest',
      '/mastra.svg',
      '/pwa-192.png',
      '/pwa-512.png',
      '/apple-touch-icon.png',
      '/favicon-session-initializing.svg',
      '/favicon-session-working.svg',
      '/favicon-session-awaiting.svg',
      '/favicon-session-error.svg',
    ]) {
      const res = await app.request(path, { headers: { Accept: '*/*' } });
      expect(res.status).toBe(200);
      expect(await res.text()).toBe('ok');
    }
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  it('keeps auth on other /favicon-session- paths and on non-GET favicon requests', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const unknownAsset = await app.request('/favicon-session-admin/config.json', { headers: { Accept: '*/*' } });
    expect(unknownAsset.status).toBe(401);

    const written = await app.request('/favicon-session-working.svg', {
      method: 'POST',
      headers: { Accept: '*/*' },
    });
    expect(written.status).toBe(401);
  });

  it('returns 401 JSON for unauthenticated /api requests', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/web/projects', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' });
  });

  it('lets unauthenticated GitHub webhook deliveries reach the route handler', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/web/github/webhook', { method: 'POST', headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  it('does not bypass auth for non-POST GitHub webhook requests', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/web/github/webhook', { method: 'GET', headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' });
  });

  it('lets unauthenticated channel webhook deliveries reach the route handler', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/api/agent-controllers/mastra-code/channels/slack/webhook', {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  it('passes channel webhooks through for any controller id', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/api/agent-controllers/some-other-controller/channels/slack/webhook', {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(200);
    expect(mockAuthenticate).not.toHaveBeenCalled();
  });

  it('does not extend the webhook pass to platforms that are not allowlisted', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    // The pass exists because the Slack adapter verifies request signatures. A
    // platform that has not been vetted for that must not inherit it.
    const res = await app.request('/api/agent-controllers/mastra-code/channels/discord/webhook', {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' });
  });

  it('does not bypass auth for non-POST channel webhook requests', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/api/agent-controllers/mastra-code/channels/slack/webhook', {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' });
  });

  it('does not bypass auth for other agent-controller API paths', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/api/agent-controllers/mastra-code/sessions', {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized' });
  });

  it('returns 401 for unauthenticated non-HTML navigation (XHR)', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();

    const res = await app.request('/some/page', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });

  it('passes through when the provider authenticates', async () => {
    mockAuthenticate.mockResolvedValue({ id: 'user_ok', email: 'user@example.com', name: 'User' });
    const { app } = buildApp();

    const res = await app.request('/web/projects', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('ok');
  });

  it('treats a provider result without a stable user id as unauthenticated', async () => {
    // Downstream tenancy scopes rows by user id; a session that cannot yield
    // one must not pass the gate.
    mockAuthenticate.mockResolvedValue({ email: 'user@example.com', name: 'User' });
    const { app } = buildApp();

    const res = await app.request('/web/projects', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });

  it('treats a thrown provider error as unauthenticated', async () => {
    mockAuthenticate.mockRejectedValue(new Error('boom'));
    const { app } = buildApp();

    const res = await app.request('/web/projects', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(401);
  });

  it('stashes flat-provider avatar URLs on the context for downstream routes', async () => {
    mockAuthenticate.mockResolvedValue({
      id: 'user_123',
      email: 'user@example.com',
      name: 'User',
      avatarUrl: 'https://avatars.example/user.png',
    });
    const app = new Hono();
    mountFactoryAuth(app, { provider: hostedProvider() });
    app.get('/web/whoami', c => {
      const user = getFactoryAuthUser(c);
      return c.json({ userId: getFactoryAuthUserId(user), avatarUrl: user?.avatarUrl });
    });

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ userId: 'user_123', avatarUrl: 'https://avatars.example/user.png' });
  });

  it('stashes session-provider avatar URLs on the context for downstream routes', async () => {
    mockAuthenticate.mockResolvedValue({
      session: { activeOrganizationId: 'org_123' },
      user: {
        id: 'user_123',
        email: 'user@example.com',
        name: 'User',
        avatarUrl: 'https://avatars.example/user.png',
      },
    });
    const app = new Hono();
    mountFactoryAuth(app, { provider: hostedProvider() });
    app.get('/web/whoami', c => {
      const user = getFactoryAuthUser(c);
      return c.json({
        userId: getFactoryAuthUserId(user),
        organizationId: getFactoryAuthOrgId(user),
        avatarUrl: user?.avatarUrl,
      });
    });

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      userId: 'user_123',
      organizationId: 'org_123',
      avatarUrl: 'https://avatars.example/user.png',
    });
  });
});

describe('mountFactoryAuth /auth routes (enabled)', () => {
  it('redirects /auth/login to the hosted login URL', async () => {
    const { app } = buildApp();
    const res = await app.request('/auth/login?returnTo=/dashboard');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://idp.example/login');
    expect(mockGetLoginUrl).toHaveBeenCalledOnce();
  });

  it('encodes returnTo into pipe-format state (MastraAuthStudio contract)', async () => {
    const { app } = buildApp();
    await app.request('/auth/login?returnTo=/dashboard');
    const state = mockGetLoginUrl.mock.calls[0]![1] as string;
    const pipeIndex = state.indexOf('|');
    expect(pipeIndex).toBeGreaterThan(0);
    expect(decodeURIComponent(state.slice(pipeIndex + 1))).toBe('/dashboard');
  });

  it('stashes returnTo in a short-lived cookie across the login round-trip', async () => {
    const { app } = buildApp();
    const res = await app.request('/auth/login?returnTo=/dashboard');
    expect(res.headers.get('set-cookie')).toContain('mastra_factory_return_to=%2Fdashboard');
  });

  it('rejects external returnTo in login (open-redirect protection)', async () => {
    const { app } = buildApp();
    await app.request('/auth/login?returnTo=https://evil.com');
    // The encoded state must carry the sanitized "/" path, not the external URL.
    const state = mockGetLoginUrl.mock.calls[0]![1] as string;
    expect(decodeURIComponent(state.split('|')[1]!)).toBe('/');
  });

  it('rejects protocol-relative returnTo', async () => {
    const { app } = buildApp();
    await app.request('/auth/login?returnTo=//evil.com');
    const state = mockGetLoginUrl.mock.calls[0]![1] as string;
    expect(decodeURIComponent(state.split('|')[1]!)).toBe('/');
  });

  it('handles the callback, applies cookies, and redirects to decoded returnTo', async () => {
    const { app } = buildApp();
    const state = `uuid-1|${encodeURIComponent('/dashboard')}`;
    const res = await app.request(`/auth/callback?code=abc&state=${state}`);
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/dashboard');
    expect(res.headers.get('set-cookie')).toContain('idp_session=sealed');
    // Hono percent-decodes query values, so the provider sees the raw pipe form.
    expect(mockHandleCallback).toHaveBeenCalledWith('abc', 'uuid-1|/dashboard');
  });

  it('falls back to the returnTo cookie when the callback has no state', async () => {
    const { app } = buildApp();
    const res = await app.request('/auth/callback?code=abc', {
      headers: { Cookie: 'mastra_factory_return_to=%2Fconnect%2Fslack%3Fstate%3Dsigned' },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/connect/slack?state=signed');
    // The stash cookie must be cleared once consumed.
    expect(res.headers.get('set-cookie')).toContain('mastra_factory_return_to=;');
  });

  it('rejects an external URL smuggled into the returnTo cookie', async () => {
    const { app } = buildApp();
    const res = await app.request('/auth/callback?code=abc', {
      headers: { Cookie: `mastra_factory_return_to=${encodeURIComponent('https://evil.com')}` },
    });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/');
  });

  it('redirects callback back to login when code is missing', async () => {
    const { app } = buildApp();
    const res = await app.request('/auth/callback');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/auth/login');
    expect(mockHandleCallback).not.toHaveBeenCalled();
  });

  it('surfaces an IdP denial on /signin, keeping the intended destination for a retry', async () => {
    const { app } = buildApp();
    const state = `uuid-1|${encodeURIComponent('/dashboard')}`;
    const res = await app.request(
      `/auth/callback?error=access_denied&error_description=You%20do%20not%20have%20access&state=${state}`,
    );
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(
      '/signin?error=access_denied&error_description=You+do+not+have+access&returnTo=%2Fdashboard',
    );
    expect(mockHandleCallback).not.toHaveBeenCalled();
  });

  it('redirects callback back to login when the code exchange fails', async () => {
    mockHandleCallback.mockRejectedValue(new Error('expired code'));
    const { app } = buildApp();
    const state = `uuid-1|${encodeURIComponent('/dashboard')}`;
    const res = await app.request(`/auth/callback?code=bad&state=${state}`);
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/auth/login');
  });

  it('logout clears the session cookie and redirects to the hosted logout URL', async () => {
    const { app } = buildApp();
    const res = await app.request('/auth/logout');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('https://idp.example/logout');
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  it('logout still clears the session cookie when the provider has no logout URL', async () => {
    mockGetLogoutUrl.mockRejectedValue(new Error('no session'));
    const { app } = buildApp();
    const res = await app.request('/auth/logout');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/');
    expect(res.headers.get('set-cookie')).toContain('Max-Age=0');
  });

  /**
   * The descriptor this provider derives to: a hosted login with organizations,
   * no credentials sign-in, and no server-side session (the double implements
   * neither createSession nor validateSession). Spelled out once and shared, so
   * a change in what the provider can do shows up as one diff rather than three.
   */
  const hostedDescriptor = {
    signIn: { kind: 'hosted', providerHint: 'generic' },
    features: { logout: true, organizations: true, refresh: false, sessionRevocation: false },
  };

  it('/auth/me reports authenticated:false when no session', async () => {
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      authenticated: false,
      user: null,
      provider: 'hosted',
      auth: hostedDescriptor,
    });
  });

  it('/auth/me reports the user when authenticated', async () => {
    mockAuthenticate.mockResolvedValue({ id: 'user_me', email: 'user@example.com', name: 'User' });
    const { app } = buildApp();
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      authenticated: true,
      // No-org accounts are bootstrapped into a personal org during /auth/me.
      user: { userId: 'user_me', email: 'user@example.com', name: 'User', organizationId: 'org_new' },
      provider: 'hosted',
      auth: hostedDescriptor,
    });
    expect(mockEnsureOrganization).toHaveBeenCalledWith('user_me');
  });

  it('/auth/me surfaces the organization id and stable user id to the SPA', async () => {
    mockAuthenticate.mockResolvedValue({
      id: 'user_1',
      email: 'user@example.com',
      name: 'User',
      organizationId: 'org_a',
    });
    const { app } = buildApp();
    const res = await app.request('/auth/me');
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      authenticated: true,
      user: { email: 'user@example.com', name: 'User', organizationId: 'org_a', userId: 'user_1' },
      provider: 'hosted',
      auth: hostedDescriptor,
    });
    expect(mockEnsureOrganization).not.toHaveBeenCalled();
  });

  it('/auth/me states no sign-up field for the hosted-login provider', async () => {
    // A hosted login has no credentials sign-in, so neither the descriptor's positive
    // signUpEnabled nor the legacy negative signUpDisabled is claimed.
    mockAuthenticate.mockResolvedValue(null);
    const { app } = buildApp();
    const body = (await (await app.request('/auth/me')).json()) as {
      signUpDisabled?: boolean;
      auth: { signIn: { signUpEnabled?: boolean } };
    };
    expect(body.auth.signIn.signUpEnabled).toBeUndefined();
    expect(body.signUpDisabled).toBeUndefined();
  });
});

describe('org-tenant identity', () => {
  it('getFactoryAuthOrgId reads the organization id from the user shape', () => {
    expect(getFactoryAuthOrgId({ id: 'user_1', organizationId: 'org_a' })).toBe('org_a');
    expect(getFactoryAuthOrgId({ id: 'user_1' })).toBeUndefined();
    expect(getFactoryAuthOrgId(undefined)).toBeUndefined();
  });

  it('gate stashes organizationId and factoryAuthTenant returns { orgId, userId }', async () => {
    mockAuthenticate.mockResolvedValue({ id: 'user_1', organizationId: 'org_a', email: 'u@e.com' });
    const app = new Hono();
    mountFactoryAuth(app, { provider: hostedProvider() });
    app.get('/web/whoami', c => c.json(factoryAuthTenant(c) ?? { tenant: null }));

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ orgId: 'org_a', userId: 'user_1' });
    // The user already has an org — no bootstrap round-trip.
    expect(mockEnsureOrganization).not.toHaveBeenCalled();
  });

  it('gate bootstraps a no-org user so factoryAuthTenant yields the new org', async () => {
    mockAuthenticate.mockResolvedValue({ id: 'user_boot', email: 'boot@example.com' });
    const app = new Hono();
    mountFactoryAuth(app, { provider: hostedProvider() });
    app.get('/web/whoami', c => c.json(factoryAuthTenant(c) ?? { tenant: null }));

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ orgId: 'org_new', userId: 'user_boot' });
    expect(mockEnsureOrganization).toHaveBeenCalledWith('user_boot');
  });

  it('factoryAuthTenant falls back to a private organization when bootstrap yields none', async () => {
    // Bootstrap is best-effort. When org creation yields nothing the user has
    // no provider organization, and the tenant resolves a deterministic private
    // one from their id rather than leaving orgId absent for every org-gated
    // route to refuse.
    mockEnsureOrganization.mockResolvedValue(undefined as unknown as string);
    mockAuthenticate.mockResolvedValue({ id: 'user_solo', email: 'solo@e.com' });
    const app = new Hono();
    mountFactoryAuth(app, { provider: hostedProvider() });
    app.get('/web/whoami', c => {
      const tenant = factoryAuthTenant(c);
      return c.json({ orgId: tenant?.orgId ?? null, userId: tenant?.userId ?? null });
    });

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ orgId: 'user:user_solo', userId: 'user_solo' });
  });

  it('a thrown bootstrap error still yields a usable tenant instead of failing the request', async () => {
    mockEnsureOrganization.mockRejectedValue(new Error('identity provider unavailable'));
    mockAuthenticate.mockResolvedValue({ id: 'user_err', email: 'err@e.com' });
    const app = new Hono();
    mountFactoryAuth(app, { provider: hostedProvider() });
    app.get('/web/whoami', c => {
      const tenant = factoryAuthTenant(c);
      return c.json({ orgId: tenant?.orgId ?? null, userId: tenant?.userId ?? null });
    });

    const res = await app.request('/web/whoami', { headers: { Accept: 'application/json' } });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ orgId: 'user:user_err', userId: 'user_err' });
  });
});

/**
 * The PKCE round trip: a verifier written as a login cookie has to be readable
 * again at the callback.
 *
 * `getLoginCookies` is the write half, and the Factory has always called it.
 * The read half is `setCallbackCookieHeader`, which was declared on no
 * interface at all, so the Factory had no way to reach it — a PKCE provider
 * could stash its verifier at login and then find `handleCallback` handed only
 * `code` and `state`, with the cookie jar out of reach. That is not a
 * documentation gap; it is a hosted login that cannot complete.
 */
describe('mountFactoryAuth PKCE round trip', () => {
  /** Pull one cookie's value out of a raw `Cookie` header. */
  function readCookieValue(header: string | null, name: string): string | undefined {
    for (const part of header?.split(';') ?? []) {
      const [key, ...rest] = part.trim().split('=');
      if (key === name) return rest.join('=');
    }
    return undefined;
  }

  /**
   * A PKCE-shaped hosted-login provider, built here rather than mocked, so the
   * seam is exercised rather than asserted. The verifier lives only in the
   * browser's cookie jar between the two requests: `handleCallback` takes no
   * argument that could carry it, so the sole channel is the callback
   * request's `Cookie` header arriving through `setCallbackCookieHeader`. A
   * provider that cannot see it refuses the exchange, which is what a real one
   * does — `auth/cloud` throws `PKCEError.missingVerifier()` at exactly this
   * point.
   */
  function pkceProvider(verifier: string) {
    const seenCookieHeaders: (string | null)[] = [];
    let callbackCookieHeader: string | null = null;
    const provider = {
      name: 'pkce',
      getLoginUrl: () => 'https://idp.example/authorize',
      getLoginCookies: () => [`pkce_verifier=${verifier}; Path=/; HttpOnly; Max-Age=600`],
      setCallbackCookieHeader(header: string | null) {
        seenCookieHeaders.push(header);
        callbackCookieHeader = header;
      },
      handleCallback: async (code: string) => {
        const sent = readCookieValue(callbackCookieHeader, 'pkce_verifier');
        if (!sent) throw new Error('missing PKCE code verifier');
        return {
          user: { id: 'u_pkce', email: 'pkce@example.com' },
          cookies: [`idp_session=${code}.${sent}; Path=/`],
        };
      },
      authenticateToken: async () => null,
      authorizeUser: async () => true,
    };
    return { provider: provider as unknown as IMastraAuthProvider, seenCookieHeaders };
  }

  it('carries the verifier from the login cookie through to handleCallback', async () => {
    const { provider } = pkceProvider('verifier-abc');
    const app = new Hono();
    mountFactoryAuth(app, { provider });

    // Login writes the verifier the way a browser would receive it.
    const login = await app.request('/auth/login');
    expect(login.status).toBe(302);
    expect(login.headers.get('set-cookie')).toContain('pkce_verifier=verifier-abc');

    // The browser sends it straight back on the callback. If the provider
    // cannot read it, handleCallback throws and the Factory bounces to
    // /auth/login with no session cookie at all.
    const callback = await app.request('/auth/callback?code=code-1&state=uuid-1', {
      headers: { Cookie: 'pkce_verifier=verifier-abc' },
    });

    expect(callback.status).toBe(302);
    expect(callback.headers.get('location')).toBe('/');
    expect(callback.headers.get('set-cookie')).toContain('idp_session=code-1.verifier-abc');
  });

  it("hands the provider the callback request's whole Cookie header, not just the verifier", async () => {
    const { provider, seenCookieHeaders } = pkceProvider('verifier-xyz');
    const app = new Hono();
    mountFactoryAuth(app, { provider });

    await app.request('/auth/callback?code=code-2&state=uuid-2', {
      headers: { Cookie: 'other=1; pkce_verifier=verifier-xyz; another=2' },
    });

    expect(seenCookieHeaders).toEqual(['other=1; pkce_verifier=verifier-xyz; another=2']);
  });

  it('passes null when the callback carries no cookies at all', async () => {
    const { provider, seenCookieHeaders } = pkceProvider('verifier-none');
    const app = new Hono();
    mountFactoryAuth(app, { provider });

    const res = await app.request('/auth/callback?code=code-3&state=uuid-3');

    // Nothing to read, so the provider refuses and the Factory bounces — but
    // it was still given the chance to look, which is the whole point.
    expect(seenCookieHeaders).toEqual([null]);
    expect(res.headers.get('location')).toBe('/auth/login');
  });

  it('leaves a provider that does not implement the read side untouched', async () => {
    // The shared hostedProvider() double has no setCallbackCookieHeader. The
    // member is optional, so its callback must behave exactly as before.
    const { app } = buildApp();
    const res = await app.request('/auth/callback?code=abc&state=uuid-1', {
      headers: { Cookie: 'some=cookie' },
    });

    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/');
    expect(res.headers.get('set-cookie')).toContain('idp_session=sealed');
    expect(mockHandleCallback).toHaveBeenCalledWith('abc', 'uuid-1');
  });
});
