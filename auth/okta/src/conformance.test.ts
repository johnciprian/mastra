/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Okta tenant, no environment
 * variables. Two things make that possible, and both mirror what a real
 * deployment does rather than replacing it with a mock:
 *
 * - The provider's remote JWKS is swapped for a local one built from a key pair
 *   generated in this file, so `jwtVerify` runs its real verification path
 *   against keys we hold instead of fetching Okta's. `jose` is never mocked -
 *   the token this suite hands to `authenticateToken` is a genuine RS256 JWT
 *   that genuinely verifies.
 * - The session cookie fixture is minted by driving the provider's own
 *   `handleCallback` through a stubbed token endpoint, so obligation 2 is asked
 *   about the exact cookie a real sign-in issues. Reimplementing the provider's
 *   AES-GCM session format here would go stale silently the moment that format
 *   changed.
 *
 * A fresh provider per `createProvider()` call, which is what the suite expects.
 * Note that the OAuth state store this provider keeps is module-global rather
 * than per-instance, so it is genuinely shared between those instances; no check
 * here depends on it not being.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { encodeState, parseStateId } from '@mastra/factory-auth/oauth-state';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JSONWebKeySet } from 'jose';

import { MastraAuthOkta } from './auth-provider';

const DOMAIN = 'conformance.okta.test';
const ISSUER = `https://${DOMAIN}/oauth2/default`;
const CLIENT_ID = 'conformance-client-id';
const CLIENT_SECRET = 'conformance-client-secret';
const REDIRECT_URI = 'https://conformance.test/auth/callback';

/** Never leaves this file. Only ever encrypts the seeded session cookie. */
const COOKIE_PASSWORD = 'conformance-cookie-password-at-least-32-chars';

/** The `sub` claim of {@link TOKEN}, which is what `mapOktaClaimsToUser` keys on. */
const USER_ID = 'okta_conformance_user';

const KEY_ID = 'conformance-signing-key';

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });

const KEY_SET: JSONWebKeySet = {
  keys: [{ ...(await exportJWK(publicKey)), kid: KEY_ID, alg: 'RS256', use: 'sig' }],
};

/**
 * Stands in for `createRemoteJWKSet(new URL(...))`, which is the one thing in
 * this provider that would otherwise reach the network.
 */
const localJwks = createLocalJWKSet(KEY_SET);

/** An Okta ID token, signed for real, with the claims Okta actually sends. */
const TOKEN = await new SignJWT({
  email: 'conformance@example.test',
  email_verified: true,
  name: 'Conformance User',
  groups: ['Everyone'],
})
  .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
  .setIssuer(ISSUER)
  // The provider's `audience` defaults to the client id, which is the `aud` of
  // an Okta ID token, and `handleCallback` verifies against the client id
  // unconditionally. One token serves both paths.
  .setAudience(CLIENT_ID)
  .setSubject(USER_ID)
  .setIssuedAt()
  .setExpirationTime('1h')
  .sign(privateKey);

/**
 * The provider as a host deploys it.
 *
 * Okta has groups, not organizations, so `MastraAuthOkta` implements no
 * `IOrganizationsProvider` and never will. Obligation 4 does not ask it to: the
 * check is titled "on its own or through the wrapper", and
 * `withSyntheticOrganizations` is the sanctioned answer for a provider with no
 * organization concept. It derives `user:${userId}`, a pure function of the user
 * id that two processes agree on without talking to each other. The README
 * documents this as the recommended way to mount this provider under the
 * Factory, so what runs here is what a deployment runs.
 */
function createProvider() {
  const provider = new MastraAuthOkta({
    domain: DOMAIN,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    issuer: ISSUER,
    redirectUri: REDIRECT_URI,
    session: { cookiePassword: COOKIE_PASSWORD },
  });
  // The field is `private`, so this is a cast rather than a subclass override.
  // It is the whole offline seam: everything downstream of it is the provider's
  // own code running unmodified. Done before wrapping, so it lands on the real
  // instance rather than on the proxy.
  (provider as unknown as { jwks: typeof localJwks }).jwks = localJwks;
  return withSyntheticOrganizations(provider);
}

/**
 * What a signed-in browser sends: the encrypted `okta_session` cookie this
 * provider issues at the end of a successful callback.
 *
 * The token endpoint is stubbed for the length of one call, and the id token it
 * returns is the same real JWT the local key set verifies. The `state` is handed
 * back in the spelling `packages/server` uses - the id half - because that is
 * the spelling this provider accepts today. Obligation 3 below asks the other
 * question, with the raw value the Factory passes.
 */
async function mintSessionCookie(): Promise<string> {
  const provider = createProvider();
  const state = encodeState('/agents/42', 'conformance-seed-state');
  provider.getLoginUrl(REDIRECT_URI, state);

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    Response.json({
      access_token: 'conformance-access-token',
      id_token: TOKEN,
      expires_in: 3600,
      token_type: 'Bearer',
    })) as typeof fetch;

  try {
    const result = await provider.handleCallback('conformance-seed-code', parseStateId(state) ?? state);
    const cookie = result.cookies?.[0];
    if (cookie === undefined) {
      throw new Error('handleCallback returned no cookies, so obligation 2 has no browser session to send.');
    }
    // Drop the attributes; a `Cookie` request header carries name=value only.
    return cookie.split(';')[0]!;
  } finally {
    globalThis.fetch = originalFetch;
  }
}

const COOKIE_HEADER = await mintSessionCookie();

describeAuthProvider({
  name: '@mastra/auth-okta',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: COOKIE_HEADER,
  sso: { redirectUri: REDIRECT_URI },
});
