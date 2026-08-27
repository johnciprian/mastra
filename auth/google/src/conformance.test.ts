/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Google project, no environment
 * variables. One seam does all of it, and it is not a mock of anything inside
 * this package: {@link googleApi} is an in-memory Google standing in front of
 * `globalThis.fetch`, serving the two endpoints this provider reaches — the
 * OIDC key set at `www.googleapis.com` and the token endpoint at
 * `oauth2.googleapis.com`. Both URLs are hardcoded constants in
 * `./auth-provider`, so they are answered where they point rather than
 * redirected somewhere convenient. Anything addressed elsewhere throws, so a
 * request that escaped would fail the run instead of leaving the process.
 *
 * Nothing inside the package is replaced, and no module is mocked. `jose` is
 * real, `this.jwks` is the provider's own `createRemoteJWKSet`, and both tokens
 * below are genuine RS256 JWTs that genuinely verify against keys generated in
 * this file. The signed state codec, the nonce binding, the PBKDF2 key
 * derivation and the AES-GCM session cookie all run as they ship, which is what
 * makes the findings below findings about this provider rather than about its
 * test double.
 *
 * THE NONCE, AND WHY THE IN-MEMORY GOOGLE HAS TO PLAY ALONG
 *
 * This provider does OIDC nonce binding properly, which is more than the other
 * three in this batch do: `getLoginUrl` mints a nonce, puts it in the
 * authorization URL and seals a copy inside its signed `state`, and
 * `handleCallback` refuses an ID token whose `nonce` claim does not match the
 * one it sealed. So an ID token minted ahead of time cannot be made to verify.
 * {@link issuedNonce} is how the fixture bridges that: the cookie-minting
 * helper reads the nonce out of the authorization URL and the in-memory token
 * endpoint signs its ID token with it. That is precisely Google's own role in
 * the flow — echo back the nonce it was handed at the authorization request —
 * rather than a way around the check.
 *
 * THE CONFIGURATION UNDER TEST
 *
 * SSO enabled — a `clientSecret` and a session cookie password — which is the
 * deployment a Factory host runs, because it is the one that can sign somebody
 * in from a browser. It matters which is chosen: `ssoEnabled` is
 * `!!clientSecret` and gates whether `ISSOProvider` and `ISessionProvider` are
 * attached to the instance at all. Without them this provider is a bearer-token
 * validator, obligations 2 and 3 and every `sso/` and `sessions/` check skip as
 * not applying, and two of the three findings below would go unasked rather
 * than unfound.
 *
 * `allowedDomains` is deliberately left unset, which is the open configuration:
 * `isHostedDomainAllowed` returns `true` for everybody. A Workspace deployment
 * that restricts to one domain is a different provider to conformance — every
 * check would need the `hd` claim on both tokens — and restricting here would
 * be testing the restriction rather than the contract. `secureCookies` is
 * passed explicitly because it otherwise reads `process.env.NODE_ENV`, and this
 * suite is not allowed to depend on the environment it runs in.
 *
 * WHAT IS RED TODAY, AND WHY IT IS RECORDED RATHER THAN FIXED OR HIDDEN
 *
 * Three checks fail. All three are findings about the provider rather than
 * about this file, so each is recorded in `knownFailures` below: the suite goes
 * green and says on every run that it is not the green of a clean provider.
 * None is fixed here — each fix is a change to a published package, which is
 * not a test's to make. The `knownFailures` entries carry the codes; this is
 * the diagnosis behind them.
 *
 * 1. `obligation/stateCodec/login-url#state-not-round-tripped`
 *    This one is half right, and the half that works is worth stating because
 *    it is the only instance of it in this batch. `getLoginUrl` wraps the
 *    host's `state` in its own signed token — base64({ s, r, e, n }) plus an
 *    HMAC — and then appends the host state's suffix from the first `|`
 *    onwards, so the authorization URL carries
 *    `<signedToken>|<encodedReturnTo>`. The destination therefore does survive:
 *    `decodeState(echoed).returnTo` is `/agents/42`, and post-login redirects
 *    land where they should. What does not survive is the id half —
 *    `parseStateId` reads everything before the first `|`, which is now the
 *    signed blob rather than the host's id — so a host doing CSRF comparison on
 *    the callback compares against something it never minted. The check
 *    requires both halves, so it is red.
 *    Not fixed: the wrapper is this provider's CSRF and redirect-URI integrity
 *    mechanism and carries the nonce binding described above. Threading the
 *    host's id through it means changing what goes on the wire for a published
 *    provider, which is a deliberate change rather than a side effect of adding
 *    a test.
 *
 * 2. `obligation/stateCodec/callback#state-rejected`
 *    The same defect from the other end. `handleCallback(code, callbackState)`
 *    takes everything before the first `|` as its state token and hands it to
 *    `verifyStateToken`, which splits on `.` and requires exactly two parts. A
 *    host-minted `id|returnTo` state yields the bare id, so it is rejected as
 *    "Invalid state token format" before any network attempt — the suite
 *    replaced `globalThis.fetch` and counted zero calls.
 *
 * 3. `sessions/round-trip#validate-rejects-fresh-session`
 *    `validateSession` returns `null` unconditionally: the attached
 *    `ISessionProvider` is a set of no-ops around a session that lives entirely
 *    in an encrypted cookie. There is genuinely nothing server-side to look up.
 *    But `isSessionProvider` tests only that `createSession` and
 *    `validateSession` exist, so the guard reports a capability the provider
 *    does not have, and `toAuthDescriptor` reports
 *    `features.sessionRevocation: true` on the strength of `destroySession`
 *    existing — so a UI will offer "sign out everywhere" on a provider that
 *    cannot revoke anything. The defect is the declaration, not the design.
 *    `auth/workos`, `auth/cloud`, `auth/studio`, `auth/auth0`, `auth/clerk` and
 *    `auth/neon` all ship a version of this; it is the single most common
 *    finding in this repository.
 *
 * WHAT PASSES AND IS WORTH KNOWING: THE PKCE ROUND TRIP
 *
 * `sso/pkce-round-trip` applies to this provider rather than skipping, because
 * `getLoginCookies` is attached whenever SSO is on. It returns `[]`, so the
 * check finds no cookie to hold anybody to and passes — which is the truthful
 * answer for a confidential client that authenticates the token exchange with
 * `client_secret` and carries no code verifier. A green there says "nothing
 * crosses the round trip", not "PKCE works". This provider gets its replay
 * protection from the nonce instead, which travels in the signed `state` rather
 * than in a cookie.
 *
 * WHAT IS NOT A KNOWN FAILURE: THE ORGANIZATION OBLIGATION
 *
 * `MastraAuthGoogle` resolves no organization: a Workspace hosted domain is a
 * login restriction rather than a tenant, and `MastraRBACGoogle` maps groups to
 * permissions without introducing one. Obligation 4 is not gated on
 * `isOrganizationsProvider`, on purpose, so the provider is wrapped in
 * `withSyntheticOrganizations`, which the kit documents as the sanctioned
 * answer for exactly this shape and which `auth/okta` and `auth/cloud` mount
 * the same way. It derives `user:${userId}`, a pure function of the user id
 * that two processes agree on without talking to each other.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { isSSOProvider } from '@mastra/factory-auth/contract';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { afterEach, beforeEach } from 'vitest';

import { MastraAuthGoogle } from './index';

/** The three Google URLs `./auth-provider` hardcodes. Answered where they point. */
const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const ISSUER = 'https://accounts.google.com';

const CLIENT_ID = 'conformance-client-id.apps.googleusercontent.com';
const CLIENT_SECRET = 'conformance-client-secret';
const REDIRECT_URI = 'https://conformance.test/auth/callback';

/** Never leaves this file. Encrypts the session cookie and signs the state token. */
const COOKIE_PASSWORD = 'conformance-cookie-password-at-least-32-chars';

/** The `sub` of every token here, and what every path must resolve to. */
const USER_ID = '116081234567890123456';

const KEY_ID = 'conformance-signing-key';

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });

const KEY_SET: JSONWebKeySet = {
  keys: [{ ...(await exportJWK(publicKey)), kid: KEY_ID, alg: 'RS256', use: 'sig' }],
};

/**
 * A Google ID token, signed for real, with the claims Google actually sends.
 *
 * `nonce` is a parameter because `handleCallback` binds the ID token to the
 * nonce its own `getLoginUrl` minted. See the header.
 */
function signIdToken(nonce?: string): Promise<string> {
  return (
    new SignJWT({
      email: 'conformance@example.test',
      email_verified: true,
      name: 'Conformance User',
      given_name: 'Conformance',
      family_name: 'User',
      picture: 'https://conformance.test/avatar.png',
      ...(nonce === undefined ? {} : { nonce }),
    })
      .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
      .setIssuer(ISSUER)
      // Google's ID token `aud` is the OAuth client id, which is what both
      // `authenticateToken` and `handleCallback` verify against.
      .setAudience(CLIENT_ID)
      .setSubject(USER_ID)
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(privateKey)
  );
}

/** The bearer token a client sends. No nonce: nothing binds one on this path. */
const TOKEN = await signIdToken();

/**
 * The nonce the in-memory Google was handed at the authorization request, and
 * must echo in the ID token it issues. Set by {@link mintSessionCookie}.
 */
let issuedNonce: string | undefined;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/**
 * The in-memory Google.
 *
 * Only the two endpoints this provider reaches exist. Anything addressed
 * elsewhere throws, so the promise that this suite is offline does not depend
 * on the provider being well-behaved.
 */
async function googleApi(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);
  const route = `${request.method} ${url.origin}${url.pathname}`;

  if (route === `GET ${JWKS_URL}`) return json(KEY_SET);

  if (route === `POST ${TOKEN_URL}`) {
    const body = new URLSearchParams(await request.text());
    // A confidential client authenticates the exchange with its secret; a
    // token endpoint that did not check would accept a callback from anybody.
    if (body.get('client_id') !== CLIENT_ID || body.get('client_secret') !== CLIENT_SECRET) {
      return json({ error: 'invalid_client' }, 401);
    }
    return json({
      access_token: 'conformance-access-token',
      id_token: await signIdToken(issuedNonce),
      expires_in: 3600,
      token_type: 'Bearer',
    });
  }

  if (url.origin === new URL(JWKS_URL).origin || url.origin === new URL(TOKEN_URL).origin) {
    return json({ error: 'not_found' }, 404);
  }

  throw new Error(`[conformance] unexpected request to ${url.href} — this suite must stay offline.`);
}

let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  realFetch = globalThis.fetch;
  globalThis.fetch = googleApi as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

/**
 * The provider as a host deploys it for Studio login. See the header for why
 * SSO is on, why `allowedDomains` is unset, and why the wrapper is the answer
 * to obligation 4.
 */
function createProvider() {
  return withSyntheticOrganizations(
    new MastraAuthGoogle({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      session: { cookiePassword: COOKIE_PASSWORD, secureCookies: true },
    }),
  );
}

/**
 * What a signed-in browser sends: the encrypted `google_session` cookie this
 * provider issues at the end of a successful callback.
 *
 * Both the `state` and the `nonce` are read back out of the authorization URL
 * rather than invented. That is the same thing Google does — echo back what it
 * was sent — and it keeps this fixture working if either format changes.
 * Whether the state format is the *host's* is obligation 3's question, and it
 * is asked separately below.
 */
async function mintSessionCookie(): Promise<string> {
  const original = globalThis.fetch;
  globalThis.fetch = googleApi as typeof globalThis.fetch;
  try {
    const provider = createProvider();
    // Narrowed through the kit's own guard rather than cast. The SSO methods
    // are attached to the instance at construction rather than declared on the
    // class, so a cast would compile whether or not the attachment happened -
    // and the attachment is exactly what `ssoEnabled` gates. This fails loudly
    // and in the right words if that ever stops being true.
    if (!isSSOProvider(provider)) {
      throw new Error('SSO is not attached, so this suite cannot mint the cookie obligation 2 needs.');
    }
    const loginUrl = new URL(await provider.getLoginUrl(REDIRECT_URI, 'conformance-seed-state'));
    const signedState = loginUrl.searchParams.get('state')!;
    issuedNonce = loginUrl.searchParams.get('nonce') ?? undefined;

    const result = await provider.handleCallback('conformance-seed-code', signedState);
    const cookie = result.cookies?.[0];
    if (cookie === undefined) {
      throw new Error('handleCallback returned no cookies, so obligation 2 has no browser session to send.');
    }
    // Drop the attributes; a `Cookie` request header carries name=value only.
    return cookie.split(';')[0]!;
  } finally {
    globalThis.fetch = original;
  }
}

const COOKIE_HEADER = await mintSessionCookie();

/**
 * The three defects this provider ships with, recorded so the suite can be
 * green without being a lie. Each `reason` is a pointer plus a sentence; the
 * diagnosis lives in this file's header, which is where a reader of the failing
 * check already lands.
 *
 * Each code was read off the failure the check actually prints rather than
 * chosen by hand — `sessions/round-trip` alone has five, and the callback check
 * has two that a reader would pick between wrongly.
 *
 * These are checked in both directions on every run: fix one of these defects
 * and the suite fails until its entry is deleted in the same change.
 */
const knownFailures = [
  {
    check: 'obligation/stateCodec/login-url',
    code: 'obligation/stateCodec/login-url#state-not-round-tripped',
    reason:
      'getLoginUrl carries the host’s returnTo through — it appends the state’s suffix from the first ' +
      '"|" onwards — but replaces the id half with its own signed token, so parseStateId reads the ' +
      'signed blob and a host comparing it on the callback compares against something it never minted. ' +
      'Not fixed because the wrapper carries this provider’s CSRF, redirect-URI integrity and OIDC nonce ' +
      "binding. Diagnosis 1 in this file's header.",
  },
  {
    check: 'obligation/stateCodec/callback',
    code: 'obligation/stateCodec/callback#state-rejected',
    reason:
      'handleCallback takes everything before the first "|" as its state token and verifyStateToken then ' +
      'requires exactly two "."-separated parts, so a host-minted id|returnTo state is rejected as ' +
      '"Invalid state token format" before any network attempt. Same root cause as the login-url ' +
      "failure, from the other end. Diagnosis 2 in this file's header.",
  },
  {
    check: 'sessions/round-trip',
    code: 'sessions/round-trip#validate-rejects-fresh-session',
    reason:
      'validateSession returns null unconditionally; the attached ISessionProvider is no-ops around a ' +
      'cookie-only session, but isSessionProvider tests only that two methods exist, so the capability ' +
      "is reported and sessionRevocation is advertised. Diagnosis 3 in this file's header.",
  },
];

describeAuthProvider({
  name: '@mastra/auth-google',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: COOKIE_HEADER,
  sso: { redirectUri: REDIRECT_URI },
  knownFailures,
});
