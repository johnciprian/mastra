/**
 * P28(b): the `ISessionProvider` members that AuthKit can actually back.
 *
 * This provider declared all seven and implemented six of them as no-ops —
 * `validateSession` returned null for every session including live ones,
 * `destroySession` had an empty body, `getSessionIdFromRequest` never found a
 * session that was sitting in the request it was handed. `toAuthDescriptor`
 * read the declaration and told every host `features.sessionRevocation`, so the
 * one claim on this provider that matters for security was false in fact.
 *
 * Five are now real. The sixth, `createSession`, cannot be: a WorkOS session
 * comes from an authenticated token exchange and the SDK has no call that mints
 * one from a user id. It is asserted here as the documented hole rather than
 * left to be rediscovered.
 *
 * The session id is the sealed cookie throughout — see the section comment in
 * `./auth-provider`. These tests seal and unseal through a fake with the
 * properties that matter (opaque, password-bound, throws on anything it did not
 * produce) rather than real iron-webcrypto, so a failure here is a failure in
 * this provider and not in someone else's cipher.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { MastraAuthWorkos } from './auth-provider';

const COOKIE_PASSWORD = 'test-cookie-password-at-least-32-chars';
const API_KEY = 'sk_test';
const CLIENT_ID = 'client_test';

const mockAuthenticateWithCode = vi.fn();
const mockAuthenticateWithRefreshToken = vi.fn();
const mockRevokeSession = vi.fn();
const mockGetLogoutUrl = vi.fn();
const mockWithAuth = vi.fn();

vi.mock('@workos-inc/node', () => {
  class MockWorkOS {
    userManagement: Record<string, unknown>;
    organizations: Record<string, unknown>;

    constructor() {
      this.userManagement = {
        getJwksUrl: vi.fn().mockReturnValue('https://mock-jwks-url'),
        authenticateWithCode: mockAuthenticateWithCode,
        authenticateWithRefreshToken: mockAuthenticateWithRefreshToken,
        revokeSession: mockRevokeSession,
        getLogoutUrl: mockGetLogoutUrl,
        getUser: vi.fn(),
        listOrganizationMemberships: vi.fn(),
      };
      this.organizations = {};
    }
  }
  return { WorkOS: MockWorkOS, GeneratePortalLinkIntent: {} };
});

vi.mock('@mastra/auth', () => ({ verifyJwks: vi.fn() }));

/**
 * A seal with the properties this provider depends on and none it does not: the
 * output is not the input, only the same password opens it, and anything else
 * throws rather than yielding a half-session.
 */
vi.mock('@workos/authkit-session', () => {
  class MockAuthService {
    withAuth = mockWithAuth;
  }
  return {
    AuthService: MockAuthService,
    CookieSessionStorage: class {},
    sessionEncryption: {
      sealData: async (data: unknown, { password }: { password: string }) =>
        `sealed.${btoa(password)}.${btoa(JSON.stringify(data))}`,
      unsealData: async <T>(value: string, { password }: { password: string }): Promise<T> => {
        const [tag, sealedPassword, payload] = String(value).split('.');
        if (tag !== 'sealed' || sealedPassword !== btoa(password) || !payload) {
          throw new Error('bad seal');
        }
        return JSON.parse(atob(payload)) as T;
      },
    },
  };
});

/** An unsigned JWT: this provider decodes the payload and never verifies it. */
function jwt(claims: Record<string, unknown>): string {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return `header.${payload}.signature`;
}

function inAnHour(): number {
  return Math.floor(Date.now() / 1000) + 3600;
}

function provider(options: Record<string, unknown> = {}): MastraAuthWorkos {
  return new MastraAuthWorkos({
    apiKey: API_KEY,
    clientId: CLIENT_ID,
    redirectUri: 'https://app.test/auth/callback',
    session: { cookiePassword: COOKIE_PASSWORD },
    ...options,
  });
}

/** Sign in for real through `handleCallback`, and hand back what the browser would hold. */
async function signIn(
  auth: MastraAuthWorkos,
  claims: Record<string, unknown> = { sid: 'session_01H', sub: 'user_01H', exp: inAnHour() },
): Promise<{ setCookie: string; request: Request; accessToken: string }> {
  const accessToken = jwt(claims);
  mockAuthenticateWithCode.mockResolvedValueOnce({
    user: { id: 'user_01H', email: 'ada@example.com' },
    accessToken,
    refreshToken: 'refresh_01H',
    organizationId: 'org_01H',
  });

  const result = await auth.handleCallback('code_01H', 'state');
  const setCookie = result.cookies![0]!;
  const request = new Request('https://app.test/api/agents', {
    headers: { Cookie: setCookie.split(';')[0]! },
  });
  return { setCookie, request, accessToken };
}

beforeEach(() => {
  vi.clearAllMocks();
  delete process.env.WORKOS_COOKIE_PASSWORD;
  mockRevokeSession.mockResolvedValue(undefined);
});

describe('getSessionIdFromRequest', () => {
  it('finds the session the request is carrying', async () => {
    const auth = provider();
    const { request, setCookie } = await signIn(auth);
    const pair = setCookie.split(';')[0]!;

    const sessionId = auth.getSessionIdFromRequest(request);

    expect(sessionId).toBe(pair.slice(pair.indexOf('=') + 1));
    expect(sessionId).not.toBeNull();
  });

  it('keeps the whole value when the sealed cookie contains =', () => {
    // Base64 padding puts `=` inside the value. Splitting the pair on every `=`
    // instead of the first truncates the seal, and a truncated seal does not
    // open — a sign-in that works until the padding happens to land.
    const auth = provider();
    const request = new Request('https://app.test/', {
      headers: { Cookie: 'wos_session=sealed.cGFzcw==.cGF5bG9hZA==' },
    });

    expect(auth.getSessionIdFromRequest(request)).toBe('sealed.cGFzcw==.cGF5bG9hZA==');
  });

  it('picks its own cookie out of a header full of others', () => {
    const auth = provider();
    const request = new Request('https://app.test/', {
      headers: { Cookie: 'ph_id=abc; wos_session=sealed-value; theme=dark' },
    });

    expect(auth.getSessionIdFromRequest(request)).toBe('sealed-value');
  });

  it('honours a renamed cookie', () => {
    const auth = provider({ session: { cookiePassword: COOKIE_PASSWORD, cookieName: 'acme_session' } });
    const request = new Request('https://app.test/', {
      headers: { Cookie: 'wos_session=wrong; acme_session=right' },
    });

    expect(auth.getSessionIdFromRequest(request)).toBe('right');
  });

  it.each([
    ['no Cookie header at all', undefined],
    ['a header without our cookie', 'other=value'],
    ['our cookie present but empty', 'wos_session='],
    ['a cookie whose name only looks like ours', 'not_wos_session=value'],
  ])('returns null for %s', (_label, cookie) => {
    const auth = provider();
    const request = new Request('https://app.test/', { headers: cookie ? { Cookie: cookie } : {} });

    expect(auth.getSessionIdFromRequest(request)).toBeNull();
  });
});

describe('validateSession', () => {
  it('accepts the session handleCallback issued, round trip', async () => {
    const auth = provider();
    const { request } = await signIn(auth);

    const session = await auth.validateSession(auth.getSessionIdFromRequest(request)!);

    expect(session).not.toBeNull();
    expect(session!.userId).toBe('user_01H');
    expect(session!.metadata).toMatchObject({ workosSessionId: 'session_01H', organizationId: 'org_01H' });
  });

  it('reports the expiry the access token actually carries', async () => {
    const auth = provider();
    const exp = inAnHour();
    const { request } = await signIn(auth, { sid: 'session_01H', sub: 'user_01H', exp, iat: exp - 3600 });

    const session = await auth.validateSession(auth.getSessionIdFromRequest(request)!);

    expect(session!.expiresAt.getTime()).toBe(exp * 1000);
    expect(session!.createdAt.getTime()).toBe((exp - 3600) * 1000);
  });

  it('refuses an expired access token rather than passing it on as valid', async () => {
    // The host calls refreshSession on exactly this null, so answering "valid"
    // here would skip the refresh and authenticate on a dead token.
    const auth = provider();
    const { request } = await signIn(auth, {
      sid: 'session_01H',
      sub: 'user_01H',
      exp: Math.floor(Date.now() / 1000) - 60,
    });

    expect(await auth.validateSession(auth.getSessionIdFromRequest(request)!)).toBeNull();
  });

  it.each([
    ['a value that was never sealed', 'not-a-sealed-cookie'],
    ['an empty id', ''],
  ])('returns null for %s', async (_label, sessionId) => {
    expect(await provider().validateSession(sessionId)).toBeNull();
  });

  it('refuses a cookie sealed by a different deployment', async () => {
    // Unsealing IS the authentication here, so this is the forgery case: a
    // well-formed cookie from somewhere else must not open.
    const other = provider({ session: { cookiePassword: 'a-completely-different-password-32ch' } });
    const { request } = await signIn(other);
    const sessionId = other.getSessionIdFromRequest(request)!;

    expect(await provider().validateSession(sessionId)).toBeNull();
  });
});

describe('destroySession', () => {
  it('revokes the session at WorkOS, which is what sessionRevocation claims', async () => {
    const auth = provider();
    const { request } = await signIn(auth);

    await auth.destroySession(auth.getSessionIdFromRequest(request)!);

    expect(mockRevokeSession).toHaveBeenCalledExactlyOnceWith({ sessionId: 'session_01H' });
  });

  it('does not call WorkOS for a session it cannot open', async () => {
    await provider().destroySession('not-a-sealed-cookie');

    expect(mockRevokeSession).not.toHaveBeenCalled();
  });

  it('does not call WorkOS when the token carries no sid', async () => {
    const auth = provider();
    const { request } = await signIn(auth, { sub: 'user_01H', exp: inAnHour() });

    await auth.destroySession(auth.getSessionIdFromRequest(request)!);

    expect(mockRevokeSession).not.toHaveBeenCalled();
  });

  it('stays quiet when WorkOS refuses, because the browser is signed out either way', async () => {
    // Hosts clear cookies whether or not this succeeds. A session that had
    // already expired throwing here would turn a working sign-out into an error
    // page with the cookie already gone.
    mockRevokeSession.mockRejectedValueOnce(new Error('session already revoked'));
    const auth = provider();
    const { request } = await signIn(auth);

    await expect(auth.destroySession(auth.getSessionIdFromRequest(request)!)).resolves.toBeUndefined();
  });
});

describe('refreshSession', () => {
  const refreshed = {
    user: { id: 'user_01H', email: 'ada@example.com' },
    accessToken: '',
    refreshToken: 'refresh_02H',
    organizationId: 'org_01H',
  };

  it('exchanges the refresh token and returns a session whose id is the NEW cookie', async () => {
    const auth = provider();
    const { request } = await signIn(auth);
    const before = auth.getSessionIdFromRequest(request)!;
    mockAuthenticateWithRefreshToken.mockResolvedValueOnce({
      ...refreshed,
      accessToken: jwt({ sid: 'session_02H', sub: 'user_01H', exp: inAnHour() }),
    });

    const session = await auth.refreshSession(before);

    expect(mockAuthenticateWithRefreshToken).toHaveBeenCalledExactlyOnceWith({
      clientId: CLIENT_ID,
      refreshToken: 'refresh_01H',
      organizationId: 'org_01H',
    });
    expect(session!.id).not.toBe(before);
    expect(session!.userId).toBe('user_01H');
    expect(session!.metadata).toMatchObject({ workosSessionId: 'session_02H' });
  });

  it('carries the new cookie out through getSessionHeaders, or the refresh is a no-op', async () => {
    // This is the whole path: the host calls getSessionHeaders on what
    // refreshSession returns and sends that Set-Cookie to the browser. If the
    // two do not connect, the session refreshes server-side and the browser
    // keeps presenting the old token.
    const auth = provider();
    const { request } = await signIn(auth);
    mockAuthenticateWithRefreshToken.mockResolvedValueOnce({
      ...refreshed,
      accessToken: jwt({ sid: 'session_02H', sub: 'user_01H', exp: inAnHour() }),
    });

    const session = await auth.refreshSession(auth.getSessionIdFromRequest(request)!);
    const headers = auth.getSessionHeaders(session!);

    expect(headers['Set-Cookie']).toContain(`wos_session=${session!.id}`);
    expect(headers['Set-Cookie']).toContain('HttpOnly');
  });

  it('seals the refreshed session so it validates on the next request', async () => {
    const auth = provider();
    const { request } = await signIn(auth);
    mockAuthenticateWithRefreshToken.mockResolvedValueOnce({
      ...refreshed,
      accessToken: jwt({ sid: 'session_02H', sub: 'user_01H', exp: inAnHour() }),
    });

    const session = await auth.refreshSession(auth.getSessionIdFromRequest(request)!);

    expect(await auth.validateSession(session!.id)).not.toBeNull();
  });

  it('returns null when WorkOS rejects the refresh token', async () => {
    mockAuthenticateWithRefreshToken.mockRejectedValueOnce(new Error('refresh token expired'));
    const auth = provider();
    const { request } = await signIn(auth);

    expect(await auth.refreshSession(auth.getSessionIdFromRequest(request)!)).toBeNull();
  });

  it('returns null for a session it cannot open, without calling WorkOS', async () => {
    expect(await provider().refreshSession('not-a-sealed-cookie')).toBeNull();
    expect(mockAuthenticateWithRefreshToken).not.toHaveBeenCalled();
  });
});

describe('getSessionHeaders', () => {
  it('emits nothing for a session that carries no cookie', () => {
    // Only handleCallback and refreshSession attach one. Building a cookie from
    // a session that has none would put a value in the browser that
    // authenticates nobody.
    const auth = provider();
    const foreign = { id: 'not-from-here', userId: 'user_01H', createdAt: new Date(), expiresAt: new Date() };

    expect(auth.getSessionHeaders(foreign)).toEqual({});
  });
});

describe('createSession', () => {
  it('does not exist, which is what ISessionManager means', () => {
    // P33. This used to be a stub returning a record nothing would accept, and
    // its presence made isSessionProvider report a capability that was not
    // there. A WorkOS session comes from an authenticated token exchange, so
    // there is nothing to mint from a user id alone -- the member is gone
    // rather than lying, and the interface says so.
    const auth = provider();

    expect('createSession' in auth).toBe(false);
    expect((auth as unknown as Record<string, unknown>).createSession).toBeUndefined();
  });

  it('leaves the provider managing sessions without claiming to mint them', async () => {
    // The guards are the contract's own answer to the line above, so assert on
    // them rather than only on the missing member.
    const { canManageSessions, isSessionProvider } = await import('@mastra/factory-auth/contract');
    const auth = provider();

    expect(canManageSessions(auth)).toBe(true);
    expect(isSessionProvider(auth)).toBe(false);
  });
});

describe('reading the sid claim', () => {
  it('decodes a payload that Base64URL encodes with - or _', async () => {
    // Regression: this used to be `atob(payloadBase64)` on the raw segment.
    // `atob` rejects the `-` and `_` that Base64URL uses in place of `+` and
    // `/`, so it threw for any token whose payload happened to contain them —
    // caught, turned into a null, and the session was silently never revoked.
    const sid = 'sess_>>>';
    const encoded = Buffer.from(JSON.stringify({ sid })).toString('base64url');
    expect(encoded, 'the fixture must actually exercise the Base64URL alphabet').toMatch(/[-_]/);

    const auth = provider();
    const { request } = await signIn(auth, { sid, sub: 'user_01H', exp: inAnHour() });

    await auth.destroySession(auth.getSessionIdFromRequest(request)!);

    expect(mockRevokeSession).toHaveBeenCalledExactlyOnceWith({ sessionId: sid });
  });
});
