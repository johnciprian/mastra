/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Clerk instance, no environment
 * variables. Two seams are replaced, and only two, both of them places this
 * provider would otherwise leave the process:
 *
 * 1. **The JWKS verifier.** `authenticateToken` verifies a bearer token with
 *    `verifyJwks` from `@mastra/auth`, and that function reaches the network
 *    through `jwks-rsa`, which uses `node:http`/`node:https` directly rather
 *    than `globalThis.fetch`. Standing an in-memory issuer in front of `fetch`
 *    therefore cannot reach it, and it is imported rather than injected, so
 *    replacing it means replacing the module — the same seam `auth/workos`
 *    takes for the same function and the same reason. Everything else
 *    `@mastra/auth` exports is passed through untouched.
 * 2. **The Clerk HTTP surface.** {@link clerkApi} is an in-memory Clerk in
 *    front of `globalThis.fetch`, serving the Frontend API token endpoint this
 *    provider exchanges codes against. The `@clerk/backend` SDK client is real
 *    and unmocked: it constructs offline and issues its requests through
 *    `globalThis.fetch`, so the in-memory Clerk catches those too.
 *
 * Nothing else inside the package is replaced. The signed state codec, the
 * PBKDF2 key derivation, the AES-GCM session cookie and the publishable-key
 * decoding that derives the Frontend API URL all run as they ship, which is
 * what makes the findings below findings about this provider rather than about
 * its test double.
 *
 * The Backend API declines, on purpose. `handleCallback` tries to enrich the
 * user it built from the ID token by calling `clerk.users.getUser`, and the
 * in-memory Clerk answers that with a 404. That is not a gap in the fixture: it
 * is the documented fallback path — `getUser` catches and returns `null`, and
 * `handleCallback` keeps the user it already had — and running the branch a
 * real deployment hits whenever the Backend API is unreachable is worth more
 * than reproducing Clerk's user serialization format, which no check reads.
 *
 * THE CONFIGURATION UNDER TEST
 *
 * SSO enabled — `oauthClientId`, `oauthClientSecret` and a session cookie
 * password — which is the second of the two deployments this package documents
 * ("With SSO for Studio login") and the one a Factory host runs, because it is
 * the one that can sign somebody in from a browser. It matters which is chosen:
 * `ssoEnabled` is `!!(oauthClientId && oauthClientSecret)` and gates whether
 * `ISSOProvider` and `ISessionProvider` are attached to the instance at all.
 * Without them this provider is a bearer-token validator, obligations 2 and 3
 * and every `sso/` and `sessions/` check skip as not applying, and two of the
 * three findings below would go unasked rather than unfound.
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
 *    `getLoginUrl(redirectUri, state)` does not echo the host's `state`. It
 *    wraps it: `createStateToken` builds `{ s: state, r: redirectUri, e: expiry }`,
 *    base64s that, appends an HMAC-SHA256 signature, and puts the result in the
 *    authorization URL. The host's value is in there — this provider loses
 *    nothing — but it is no longer readable by the codec that minted it, so
 *    `parseStateId` reads the whole base64 blob as the id and `decodeState`
 *    finds no destination. Every post-login redirect lands on `/`.
 *    Not fixed: the wrapper is this provider's CSRF and redirect-URI integrity
 *    mechanism, and it is stateless on purpose so it works across instances.
 *    Carrying the host's `id|returnTo` through it means changing what goes on
 *    the wire for a published provider, which is a deliberate change rather
 *    than a side effect of adding a test.
 *
 * 2. `obligation/stateCodec/callback#state-rejected`
 *    The same defect from the other end. `handleCallback(code, stateToken)`
 *    hands the raw value to `verifyStateToken`, which splits on `.` and
 *    requires exactly two parts, so a host-minted `id|returnTo` state is
 *    rejected as "Invalid state token format" before any network attempt — the
 *    suite replaced `globalThis.fetch` and counted zero calls. Both halves of
 *    obligation 3 fail for one root cause: this provider's `state` is its own
 *    format in both directions.
 *
 * 3. `sessions/round-trip#validate-rejects-fresh-session`
 *    `validateSession` returns `null` unconditionally: the attached
 *    `ISessionProvider` is a set of no-ops around a session that lives entirely
 *    in an encrypted cookie, as the "cookie-only sessions" comments in
 *    `./index` say. There is genuinely nothing server-side to look up. But
 *    `isSessionProvider` tests only that `createSession` and `validateSession`
 *    exist, so the guard reports a capability the provider does not have, and
 *    `toAuthDescriptor` reports `features.sessionRevocation: true` on the
 *    strength of `destroySession` existing — so a UI will offer "sign out
 *    everywhere" on a provider that cannot revoke anything. The defect is the
 *    declaration, not the design. `auth/workos`, `auth/cloud`, `auth/studio`,
 *    `auth/auth0`, `auth/google` and `auth/neon` all ship a version of this; it
 *    is the single most common finding in this repository.
 *
 * WHAT PASSES AND IS WORTH KNOWING: THE PKCE ROUND TRIP
 *
 * `sso/pkce-round-trip` applies to this provider rather than skipping, because
 * `getLoginCookies` is attached whenever SSO is on. It returns `[]`, so the
 * check finds no cookie to hold anybody to and passes — which is the truthful
 * answer for a confidential client that authenticates the token exchange with
 * HTTP Basic and carries no code verifier. A green there says "nothing crosses
 * the round trip", not "PKCE works".
 *
 * WHAT IS NOT A KNOWN FAILURE: THE ORGANIZATION OBLIGATION
 *
 * `MastraAuthClerk` resolves no organization of its own. Obligation 4 is not
 * gated on `isOrganizationsProvider`, on purpose, so the provider is wrapped in
 * `withSyntheticOrganizations`, which the kit documents as the sanctioned
 * answer for exactly this shape and which `auth/okta` and `auth/cloud` mount
 * the same way. It derives `user:${userId}`, a pure function of the user id
 * that two processes agree on without talking to each other.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { isSSOProvider } from '@mastra/factory-auth/contract';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
import { afterEach, beforeEach, vi } from 'vitest';

import { MastraAuthClerk } from './index';

/**
 * Hoisted so the `@mastra/auth` mock factory below — which vitest lifts above
 * every import in this file — can read them without a temporal dead zone.
 */
const fixtures = vi.hoisted(() => ({
  /** The bearer token the injected verifier accepts. Nothing else is signed. */
  TOKEN: 'conformance-clerk-session-jwt',
  /** The ID token the in-memory Clerk returns from the token endpoint. */
  ID_TOKEN: 'conformance-clerk-id-token',
  USER_ID: 'user_conformance',
  EMAIL: 'conformance@example.test',
}));

const { TOKEN, ID_TOKEN, USER_ID, EMAIL } = fixtures;

/**
 * The offline stand-in for Clerk's JWKS verification.
 *
 * See the header for why this one is a module mock rather than an in-memory
 * issuer: `jwks-rsa` does not go through `globalThis.fetch`, and `verifyJwks`
 * is imported rather than injected. It accepts the two tokens this suite mints
 * and throws for everything else, which is what a real `jwt.verify` does for a
 * token it cannot validate — the provider is expected to catch that and resolve
 * null.
 */
vi.mock('@mastra/auth', async importActual => {
  const actual = await importActual<typeof import('@mastra/auth')>();
  return {
    ...actual,
    verifyJwks: async (accessToken: string) => {
      if (accessToken !== fixtures.TOKEN && accessToken !== fixtures.ID_TOKEN) {
        throw new Error('invalid signature');
      }
      return {
        sub: fixtures.USER_ID,
        email: fixtures.EMAIL,
        name: 'Conformance User',
        picture: 'https://conformance.test/avatar.png',
      };
    },
  };
});

const FAPI_DOMAIN = 'conformance.clerk.test';
const FAPI_ORIGIN = `https://${FAPI_DOMAIN}`;
/** Clerk's publishable key is `pk_test_` + base64 of the FAPI domain plus `$`. */
const PUBLISHABLE_KEY = `pk_test_${btoa(`${FAPI_DOMAIN}$`)}`;
const SECRET_KEY = 'sk_test_conformance';
const JWKS_URI = `${FAPI_ORIGIN}/.well-known/jwks.json`;

/** Clerk's Backend API origin, which the `@clerk/backend` SDK addresses. */
const BACKEND_ORIGIN = 'https://api.clerk.com';

const OAUTH_CLIENT_ID = 'conformance-oauth-client-id';
const OAUTH_CLIENT_SECRET = 'conformance-oauth-client-secret';
const REDIRECT_URI = 'https://conformance.test/auth/callback';

/** Never leaves this file. Encrypts the session cookie and signs the state token. */
const COOKIE_PASSWORD = 'conformance-cookie-password-at-least-32-chars';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/**
 * The in-memory Clerk.
 *
 * Two origins, because this provider talks to two: the Frontend API for the
 * OAuth token exchange, and the Backend API through the SDK. Anything addressed
 * elsewhere throws, so the promise that this suite is offline does not depend
 * on the provider being well-behaved.
 */
async function clerkApi(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);

  if (url.origin === BACKEND_ORIGIN) {
    // See the header: the enrichment declining is the branch under test.
    return json({ errors: [{ code: 'resource_not_found', message: 'Not Found' }] }, 404);
  }

  if (url.origin !== FAPI_ORIGIN) {
    throw new Error(`[conformance] unexpected request to ${url.href} — this suite must stay offline.`);
  }

  if (request.method === 'POST' && url.pathname === '/oauth/token') {
    // A confidential client authenticates the exchange with HTTP Basic; an
    // instance that did not check would accept a callback from anybody.
    const expected = `Basic ${btoa(`${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`)}`;
    if (request.headers.get('Authorization') !== expected) {
      return json({ error: 'invalid_client' }, 401);
    }
    return json({
      access_token: 'conformance-access-token',
      id_token: ID_TOKEN,
      expires_in: 3600,
      token_type: 'Bearer',
    });
  }

  return json({ error: 'not_found' }, 404);
}

let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  realFetch = globalThis.fetch;
  globalThis.fetch = clerkApi as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

/**
 * The provider as a host deploys it for Studio login. See the header for why
 * SSO is on, and why the wrapper is the answer to obligation 4.
 */
function createProvider() {
  return withSyntheticOrganizations(
    new MastraAuthClerk({
      jwksUri: JWKS_URI,
      secretKey: SECRET_KEY,
      publishableKey: PUBLISHABLE_KEY,
      oauthClientId: OAUTH_CLIENT_ID,
      oauthClientSecret: OAUTH_CLIENT_SECRET,
      redirectUri: REDIRECT_URI,
      session: { cookiePassword: COOKIE_PASSWORD },
    }),
  );
}

/**
 * What a signed-in browser sends: the encrypted `clerk_session` cookie this
 * provider issues at the end of a successful callback.
 *
 * The `state` handed to `handleCallback` is read back out of the authorization
 * URL rather than invented, because this provider's `state` is its own signed
 * format and only `getLoginUrl` can mint one. That is the same thing an
 * identity provider does — echo back what it was sent — and it keeps this
 * fixture working if the format changes. Whether that format is the *host's*
 * is obligation 3's question, and it is asked separately below.
 */
async function mintSessionCookie(): Promise<string> {
  const original = globalThis.fetch;
  globalThis.fetch = clerkApi as typeof globalThis.fetch;
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
    const loginUrl = await provider.getLoginUrl(REDIRECT_URI, 'conformance-seed-state');
    const signedState = new URL(loginUrl).searchParams.get('state')!;

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
      'getLoginUrl wraps the host state in its own signed token — base64({ s, r, e }) plus an HMAC — so ' +
      'parseStateId reads the whole blob as the id and decodeState finds no destination, and every ' +
      'post-login redirect lands on /. Not fixed because the wrapper is this provider’s stateless CSRF ' +
      "and redirect-URI integrity mechanism. Diagnosis 1 in this file's header.",
  },
  {
    check: 'obligation/stateCodec/callback',
    code: 'obligation/stateCodec/callback#state-rejected',
    reason:
      'verifyStateToken splits the state on "." and requires exactly two parts, so a host-minted ' +
      'id|returnTo state is rejected as "Invalid state token format" before any network attempt. Same ' +
      "root cause as the login-url failure, from the other end. Diagnosis 2 in this file's header.",
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
  name: '@mastra/auth-clerk',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: COOKIE_HEADER,
  sso: { redirectUri: REDIRECT_URI },
  knownFailures,
});
