/**
 * `getLoginUrl` / `handleCallback`, the half of this provider that had no tests.
 *
 * That absence is the root cause of the state defect, not a symptom of it:
 * `getLoginUrl` keyed its state store on the id half of `state` while
 * `handleCallback` looked the value up verbatim, so every sign-in under the
 * Software Factory - which passes the raw query-string value through - failed
 * with "Invalid or expired state parameter". Nothing exercised the two halves
 * together, so nothing noticed.
 *
 * These run offline against real `jose`: a key pair generated here replaces the
 * provider's remote JWKS, and the token endpoint is stubbed per test. `jose` is
 * deliberately not mocked - the id token the provider verifies during a callback
 * is a genuine RS256 JWT.
 */
import { encodeState, parseStateId } from '@mastra/factory-auth/oauth-state';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { MastraAuthOkta } from './auth-provider';

const DOMAIN = 'callback-tests.okta.test';
const ISSUER = `https://${DOMAIN}/oauth2/default`;
const CLIENT_ID = 'callback-tests-client-id';
const CLIENT_SECRET = 'callback-tests-client-secret';

/** The redirect URI the constructor is configured with. */
const CONFIGURED_REDIRECT_URI = 'https://app.example.test/api/auth/callback';

/** A different one, handed to `getLoginUrl`, so the two can be told apart. */
const LOGIN_REDIRECT_URI = 'https://app.example.test/mastra/auth/sso/callback';

const COOKIE_PASSWORD = 'callback-tests-cookie-password-32-chars';

const USER_ID = 'okta_00u_callback_user';

const KEY_ID = 'callback-tests-signing-key';

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });

const KEY_SET: JSONWebKeySet = {
  keys: [{ ...(await exportJWK(publicKey)), kid: KEY_ID, alg: 'RS256', use: 'sig' }],
};

const localJwks = createLocalJWKSet(KEY_SET);

/** A real Okta ID token, signed for a `sub` the tests assert on. */
const ID_TOKEN = await new SignJWT({
  email: 'callback@example.test',
  email_verified: true,
  name: 'Callback User',
  groups: ['Engineering'],
})
  .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
  .setIssuer(ISSUER)
  .setAudience(CLIENT_ID)
  .setSubject(USER_ID)
  .setIssuedAt()
  .setExpirationTime('1h')
  .sign(privateKey);

function createProvider(): MastraAuthOkta {
  const provider = new MastraAuthOkta({
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    issuer: ISSUER,
    redirectUri: CONFIGURED_REDIRECT_URI,
    session: { cookiePassword: COOKIE_PASSWORD },
  });
  // The remote key set is the one thing here that would reach the network.
  (provider as unknown as { jwks: typeof localJwks }).jwks = localJwks;
  return provider;
}

/** The token endpoint answering a normal, successful exchange. */
function stubTokenEndpoint() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () =>
    Response.json({
      access_token: 'okta-access-token',
      refresh_token: 'okta-refresh-token',
      id_token: ID_TOKEN,
      expires_in: 3600,
      token_type: 'Bearer',
    }),
  );
}

/**
 * A distinct state per test. The provider's state store is module-global and
 * shared across instances, so reusing an id would let one test see another's.
 */
let stateCounter = 0;
function freshState(returnTo = '/agents/42'): string {
  stateCounter += 1;
  return encodeState(returnTo, `callback-test-state-${stateCounter}`);
}

describe('MastraAuthOkta hosted login', () => {
  let provider: MastraAuthOkta;

  beforeEach(() => {
    provider = createProvider();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  describe('getLoginUrl', () => {
    test('sends the state to Okta unchanged', () => {
      const state = freshState();

      const url = new URL(provider.getLoginUrl(LOGIN_REDIRECT_URI, state));

      expect(url.origin + url.pathname).toBe(`${ISSUER}/v1/authorize`);
      expect(url.searchParams.get('state')).toBe(state);
      expect(url.searchParams.get('client_id')).toBe(CLIENT_ID);
      expect(url.searchParams.get('response_type')).toBe('code');
      expect(url.searchParams.get('redirect_uri')).toBe(LOGIN_REDIRECT_URI);
    });

    test('sets no login cookies, and takes both arguments the interface passes', () => {
      // `ISSOProvider.getLoginCookies(redirectUri, state)`. This provider is a
      // confidential client with no PKCE verifier to stash, so the answer is
      // empty - but the arity has to match, or the one parameter it declares
      // silently binds `redirectUri` under the name `state`.
      expect(provider.getLoginCookies.length).toBe(2);
      expect(provider.getLoginCookies(LOGIN_REDIRECT_URI, freshState())).toEqual([]);
    });
  });

  describe('handleCallback', () => {
    test('accepts the raw state the Software Factory passes through', async () => {
      // The regression. `mastracode/factory/src/auth.ts` hands `handleCallback`
      // `c.req.query('state')` verbatim, so this is the exact value that used to
      // be rejected on every single sign-in.
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      stubTokenEndpoint();

      const result = await provider.handleCallback('okta-auth-code', state);

      expect(result.user.id).toBe(USER_ID);
      expect(result.user.oktaId).toBe(USER_ID);
      expect(result.user.email).toBe('callback@example.test');
      expect(result.tokens?.accessToken).toBe('okta-access-token');
    });

    test('accepts the bare state id packages/server splits out first', async () => {
      // `packages/server/src/server/handlers/auth.ts` splits on the first `|` and
      // passes only the id. Both hosts have to keep working off one store.
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      stubTokenEndpoint();

      const result = await provider.handleCallback('okta-auth-code', parseStateId(state)!);

      expect(result.user.id).toBe(USER_ID);
    });

    test('keys on the id half even when the returnTo carries its own delimiter', async () => {
      // Only the first `|` is significant. A state whose destination contains
      // one must still resolve to the same key on both sides.
      const state = `callback-test-piped-state|%2Fsearch%3Fq%3Da|b`;
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      stubTokenEndpoint();

      await expect(provider.handleCallback('okta-auth-code', state)).resolves.toMatchObject({
        user: { id: USER_ID },
      });
    });

    test('exchanges the code against the redirect_uri recorded at login', async () => {
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      const fetchSpy = stubTokenEndpoint();

      await provider.handleCallback('okta-auth-code', state);

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const [url, init] = fetchSpy.mock.calls[0]!;
      expect(url).toBe(`${ISSUER}/v1/token`);
      const body = new URLSearchParams(init?.body as string);
      expect(body.get('grant_type')).toBe('authorization_code');
      expect(body.get('code')).toBe('okta-auth-code');
      // Not CONFIGURED_REDIRECT_URI: Okta requires the value used at authorize.
      expect(body.get('redirect_uri')).toBe(LOGIN_REDIRECT_URI);
      const headers = init?.headers as Record<string, string>;
      expect(headers.Authorization).toBe(`Basic ${btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)}`);
    });

    test('returns a session cookie that authenticates the same user with no bearer token', async () => {
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      stubTokenEndpoint();

      const result = await provider.handleCallback('okta-auth-code', state);

      const cookie = result.cookies?.[0];
      expect(cookie).toBeDefined();
      expect(cookie).toContain('okta_session=');
      expect(cookie).toContain('HttpOnly');

      vi.restoreAllMocks();
      const request = new Request('https://app.example.test/api/agents', {
        headers: { cookie: cookie!.split(';')[0]! },
      });
      const user = await provider.authenticateToken('', request);
      expect(user?.id).toBe(USER_ID);
    });

    test('rejects a state it never minted', async () => {
      stubTokenEndpoint();

      await expect(provider.handleCallback('okta-auth-code', freshState())).rejects.toThrow(
        'Invalid or expired state parameter',
      );
      expect(globalThis.fetch).not.toHaveBeenCalled();
    });

    test('rejects a replayed state, whichever spelling the replay uses', async () => {
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      stubTokenEndpoint();

      await provider.handleCallback('okta-auth-code', state);

      await expect(provider.handleCallback('okta-auth-code', state)).rejects.toThrow(
        'Invalid or expired state parameter',
      );
      await expect(provider.handleCallback('okta-auth-code', parseStateId(state)!)).rejects.toThrow(
        'Invalid or expired state parameter',
      );
    });

    test('rejects a state older than its ten minute window', async () => {
      vi.useFakeTimers();
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      stubTokenEndpoint();

      vi.setSystemTime(Date.now() + 11 * 60 * 1000);

      await expect(provider.handleCallback('okta-auth-code', state)).rejects.toThrow('State parameter has expired');
    });

    test('surfaces a failed token exchange', async () => {
      const state = freshState();
      provider.getLoginUrl(LOGIN_REDIRECT_URI, state);
      vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('invalid_grant', { status: 400 }));

      await expect(provider.handleCallback('okta-auth-code', state)).rejects.toThrow(
        'Token exchange failed: invalid_grant',
      );
    });
  });

  describe('sessions', () => {
    test('a created session validates and names its user', async () => {
      const session = await provider.createSession(USER_ID, { source: 'test' });

      expect(session.userId).toBe(USER_ID);
      await expect(provider.validateSession(session.id)).resolves.toMatchObject({
        id: session.id,
        userId: USER_ID,
      });
    });

    test('a destroyed session stops validating', async () => {
      const session = await provider.createSession(USER_ID);

      await provider.destroySession(session.id);

      await expect(provider.validateSession(session.id)).resolves.toBeNull();
    });

    test('an expired session stops validating', async () => {
      vi.useFakeTimers();
      const session = await provider.createSession(USER_ID);

      vi.setSystemTime(session.expiresAt.getTime() + 1000);

      await expect(provider.validateSession(session.id)).resolves.toBeNull();
    });

    test('refreshSession extends a live session and declines an unknown one', async () => {
      const session = await provider.createSession(USER_ID);

      const refreshed = await provider.refreshSession(session.id);

      expect(refreshed?.id).toBe(session.id);
      expect(refreshed?.expiresAt.getTime()).toBeGreaterThanOrEqual(session.expiresAt.getTime());
      await expect(provider.refreshSession('never-created')).resolves.toBeNull();
    });
  });
});
