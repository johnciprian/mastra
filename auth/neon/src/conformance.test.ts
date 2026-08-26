/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Neon project, no environment
 * variables. This provider holds no local key material and owns no session
 * store — every question it answers, it answers by asking Neon Auth over
 * `globalThis.fetch` — so the whole of it can be exercised by standing an
 * in-memory Neon Auth in front of that one seam. {@link neonAuthApi} is that
 * API: a JWKS endpoint serving a key set generated in this file, and a
 * `get-session` endpoint that knows exactly one live session. It throws rather
 * than answering for any other host, so a request that escaped would fail the
 * run instead of leaving the process.
 *
 * Nothing inside the package is replaced, and no module is mocked. `jose` is
 * real, and the bearer token below is a genuine RS256 JWT that genuinely
 * verifies: the provider's own `createRemoteJWKSet(new URL(this.jwksUrl))`
 * fetches the key set from the in-memory API and `jwtVerify` runs its real
 * verification path against it. The cookie parser, the header assembly and the
 * session decoding all run as they ship, which is what makes the findings below
 * findings about this provider rather than about its test double.
 *
 * Only the two endpoints conformance drives exist. Neon Auth's
 * `sign-in/email` and `sign-up/email` are real endpoints this provider calls,
 * but no check in the suite reaches them — `credentials/sign-up-enabled` reads
 * `isSignUpEnabled()`, which is a field read — so serving them here would be
 * scaffolding for a call that never happens. Everything else under the Neon
 * origin answers 404, which is what a stale client would get from the real one.
 *
 * WHICH BEARER TOKEN THIS SUITE USES, AND WHY IT MATTERS
 *
 * `authenticateToken` has two paths and they do not agree. It tries JWT
 * verification first — "for bearer JWT tokens from API clients", in this
 * package's own words — and falls back to replaying the token as a Neon session
 * cookie. This suite hands it a JWT, because that is the path the provider
 * tries first and the one it documents for bearer tokens.
 *
 * The choice is load-bearing rather than incidental, so it is stated plainly:
 * the two paths return differently shaped payloads, and only one of them
 * resolves an identity. Diagnosis 1 below is what that costs.
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
 * 1. `obligation/flatId#no-id-in-payload`
 *    The JWT path returns `{ user, jwt }`. `toAuthIdentity` recognizes a
 *    `{ session, user }` pair — both halves present — and otherwise reads
 *    `id`/`uid`/`sub` off the top level. `{ user, jwt }` is neither: it carries
 *    no `session`, so the wrapper rule does not apply, and the top level has no
 *    id of its own. The identity resolves to `null`, so under the Factory a
 *    perfectly valid Neon JWT authenticates nobody.
 *    The session-cookie path is unaffected, and that is the useful half of this
 *    diagnosis rather than a footnote: it returns `{ session, user }`, the
 *    wrapper rule fires, and `user.id` resolves. So the defect is not "this
 *    provider has no id" — it is one branch of one method returning a shape the
 *    other branch does not. The `two branches, two payload shapes` block at the
 *    foot of this file pins both halves of that claim, so a fix to either one
 *    has something to fail against.
 *    Not fixed: the payload shape is `NeonAuthUser`, an exported type, and
 *    every consumer reading `result.jwt` reads it at the top level. Lifting
 *    `sub` to the top level or renaming the branch's wrapper is a change to a
 *    published surface.
 *
 * 2. `obligation/cookieAuth#cookie-not-read`
 *    `authenticateToken('', request)` returns `null` on its first statement —
 *    `if (!token || typeof token !== 'string') return null` — before it looks
 *    at the request at all. The cookie-reading code below that line is real and
 *    correct, and it is unreachable for the one call obligation 2 is about: the
 *    host sends an empty bearer precisely to say "this request carried no
 *    token, read the cookie". So a browser holding a valid Neon session cookie
 *    and no bearer token is not authenticated under the Factory.
 *    The cookie path runs only when a non-empty bearer token is present and JWT
 *    verification of it has already failed, which is the opposite of the
 *    condition it was written for.
 *    Not fixed: the fix is to move the empty-token guard below the cookie
 *    branch, which changes when a published provider authenticates a request.
 *    That is a behaviour change to ship deliberately, not a side effect of
 *    adding a test.
 *
 * 3. `sessions/round-trip#validate-rejects-fresh-session`
 *    `createSession(userId)` mints a random UUID locally and tells Neon
 *    nothing — it issues no request at all, so there is nothing the in-memory
 *    Neon could have recorded. `validateSession` then asks `get-session` about
 *    that UUID as if it were a session token, and is told no. The two halves of
 *    the loop never meet.
 *    `auth/cloud`, `auth/studio` and `auth/workos` all ship a version of this,
 *    and it is the same root cause each time: `isSessionProvider` tests only
 *    that `createSession` and `validateSession` exist, so a provider whose
 *    sessions live entirely in the identity provider still reports the
 *    capability.
 *
 * WHAT IS NOT A KNOWN FAILURE: THE ORGANIZATION OBLIGATION
 *
 * `MastraAuthNeon` has no organization concept — the word appears nowhere in
 * `src/`. Obligation 4 is not gated on `isOrganizationsProvider`, on purpose,
 * so the provider is wrapped in `withSyntheticOrganizations`, which the kit
 * documents as the sanctioned answer for exactly this shape and which
 * `auth/okta` and `auth/cloud` mount the same way. It derives `user:${userId}`,
 * a pure function of the user id that two processes agree on without talking to
 * each other.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { toAuthIdentity } from '@mastra/factory-auth/identity';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type { JSONWebKeySet } from 'jose';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MastraAuthNeon } from './index';

const BASE_URL = 'https://neon.conformance.test';

/** The cookie name the provider reads and writes. Its documented default. */
const SESSION_COOKIE_NAME = 'neonauth.session_token';

/** The session token the in-memory Neon has already issued to a signed-in browser. */
const SESSION_TOKEN = 'conformance-neon-session-token';

/** The `sub` of {@link TOKEN}, and the `user.id` `get-session` answers with. */
const USER_ID = 'conformance_neon_user';

const KEY_ID = 'conformance-signing-key';

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });

/** Served at `/auth/jwks`, which is where this provider's JWKS URL points. */
const KEY_SET: JSONWebKeySet = {
  keys: [{ ...(await exportJWK(publicKey)), kid: KEY_ID, alg: 'RS256', use: 'sig' }],
};

/**
 * A Neon Auth JWT, signed for real.
 *
 * `verifyJwt` passes no `issuer` or `audience` to `jwtVerify`, so a signature
 * the key set above validates is the whole of what this provider checks.
 */
const TOKEN = await new SignJWT({
  email: 'conformance@example.test',
  name: 'Conformance User',
  email_verified: true,
})
  .setProtectedHeader({ alg: 'RS256', kid: KEY_ID })
  .setSubject(USER_ID)
  .setIssuedAt()
  .setExpirationTime('1h')
  .sign(privateKey);

/** What `get-session` answers for the one live session. */
const SESSION_BODY = {
  session: {
    id: 'conformance_neon_session',
    token: SESSION_TOKEN,
    userId: USER_ID,
    expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
  user: {
    id: USER_ID,
    email: 'conformance@example.test',
    name: 'Conformance User',
    image: null,
    emailVerified: true,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  },
};

/**
 * The session tokens the in-memory Neon has issued and not yet revoked.
 *
 * Rebuilt per test, so a check cannot see another's writes. A token is in here
 * because Neon issued it; a UUID this provider invented locally is not, which
 * is the whole of diagnosis 3.
 */
let liveSessions: Set<string>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** The session token in a `Cookie` header, or `null`. The browser's half. */
function sessionTokenFrom(cookieHeader: string | null): string | null {
  if (cookieHeader === null) return null;
  for (const pair of cookieHeader.split(';')) {
    const [name, ...rest] = pair.trim().split('=');
    if (name?.trim() === SESSION_COOKIE_NAME) return rest.join('=') || null;
  }
  return null;
}

/**
 * The in-memory Neon Auth API.
 *
 * Anything addressed off the Neon origin throws, so the promise that this suite
 * is offline does not depend on the provider being well-behaved.
 */
async function neonAuthApi(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);
  if (url.origin !== BASE_URL) {
    throw new Error(`[conformance] unexpected request to ${url.href} — this suite must stay offline.`);
  }

  switch (`${request.method} ${url.pathname}`) {
    case 'GET /auth/jwks':
      return json(KEY_SET);

    case 'GET /auth/get-session': {
      const token = sessionTokenFrom(request.headers.get('Cookie'));
      if (token === null || !liveSessions.has(token)) return json({ error: 'unauthorized' }, 401);
      return json(SESSION_BODY);
    }

    default:
      return json({ error: 'not_found' }, 404);
  }
}

let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  liveSessions = new Set([SESSION_TOKEN]);
  realFetch = globalThis.fetch;
  globalThis.fetch = neonAuthApi as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

/**
 * The provider as a host deploys it: a base URL and nothing else, which is the
 * shape this package's own README and class documentation show. `jwksUrl`,
 * `sessionCookieName` and `signUpEnabled` are all left at their defaults, so
 * what runs here is the default deployment rather than a configuration chosen
 * to pass. See the header for why the wrapper is the answer to obligation 4.
 */
function createProvider() {
  return withSyntheticOrganizations(new MastraAuthNeon({ baseUrl: BASE_URL }));
}

/**
 * The three defects this provider ships with, recorded so the suite can be
 * green without being a lie. Each `reason` is a pointer plus a sentence; the
 * diagnosis lives in this file's header, which is where a reader of the failing
 * check already lands.
 *
 * Each code was read off the failure the check actually prints rather than
 * chosen by hand — `sessions/round-trip` alone has five.
 *
 * These are checked in both directions on every run: fix one of these defects
 * and the suite fails until its entry is deleted in the same change.
 */
const knownFailures = [
  {
    check: 'obligation/flatId',
    code: 'obligation/flatId#no-id-in-payload',
    reason:
      'The JWT branch of authenticateToken returns { user, jwt }, which is neither a { session, user } ' +
      'pair nor a payload with a top-level id, so toAuthIdentity resolves null and a valid Neon JWT ' +
      'authenticates nobody under the Factory. The session-cookie branch returns { session, user } and ' +
      'resolves correctly. Not fixed because NeonAuthUser is an exported type. Diagnosis 1 in this ' +
      "file's header.",
  },
  {
    check: 'obligation/cookieAuth',
    code: 'obligation/cookieAuth#cookie-not-read',
    reason:
      'authenticateToken returns null on its first statement when the bearer token is empty, before it ' +
      'reads the request, so the cookie branch below is unreachable for exactly the call obligation 2 ' +
      'is about. Not fixed because moving the guard changes when a published provider authenticates a ' +
      "request. Diagnosis 2 in this file's header.",
  },
  {
    check: 'sessions/round-trip',
    code: 'sessions/round-trip#validate-rejects-fresh-session',
    reason:
      'createSession mints a UUID locally and issues no request, so Neon never hears about the session ' +
      'and validateSession can never accept it. The same defect auth/cloud, auth/studio and auth/workos ' +
      "ship. Diagnosis 3 in this file's header.",
  },
];

describeAuthProvider({
  name: '@mastra/auth-neon',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: `${SESSION_COOKIE_NAME}=${SESSION_TOKEN}`,
  knownFailures,
});

/**
 * The evidence behind diagnoses 1 and 2, pinned.
 *
 * The conformance run reports both as one red each, and a red says a check
 * failed rather than why. These say why, in terms of the branch responsible, so
 * that a fix to either one is caught here as well as by the `knownFailures`
 * entry going stale — and so that the header's claim about the session-cookie
 * branch is a measurement rather than an assertion.
 */
describe('@mastra/auth-neon: two branches, two payload shapes', () => {
  it('resolves no identity from the JWT branch and the right one from the session branch', async () => {
    const provider = new MastraAuthNeon({ baseUrl: BASE_URL });

    // The JWT branch: a real, valid Neon JWT. The payload is `{ user, jwt }`,
    // which carries no top-level id and is not a `{ session, user }` pair, so
    // the host resolves nobody. This is diagnosis 1.
    const viaJwt = await provider.authenticateToken(TOKEN, new Request(`${BASE_URL}/api/agents`));
    expect(viaJwt).not.toBeNull();
    expect(Object.keys(viaJwt!)).toEqual(['user', 'jwt']);
    expect(toAuthIdentity(viaJwt, provider)).toBeNull();

    // The session branch, reached the only way it can be reached: a non-empty
    // bearer token that is not a verifiable JWT, which the provider then
    // replays as a session cookie. The payload is `{ session, user }`, the
    // wrapper rule fires, and the same person resolves.
    const viaSession = await provider.authenticateToken(SESSION_TOKEN, new Request(`${BASE_URL}/api/agents`));
    expect(toAuthIdentity(viaSession, provider)?.id).toBe(USER_ID);
  });

  it('never reaches the cookie branch for the empty bearer token obligation 2 sends', async () => {
    const provider = new MastraAuthNeon({ baseUrl: BASE_URL });
    const request = new Request(`${BASE_URL}/api/agents`, {
      headers: { Cookie: `${SESSION_COOKIE_NAME}=${SESSION_TOKEN}` },
    });

    // The cookie is live: the same value authenticates when it arrives as a
    // bearer token, so this is the guard rather than the credential. Diagnosis 2.
    expect(await provider.authenticateToken(SESSION_TOKEN, request)).not.toBeNull();
    expect(await provider.authenticateToken('', request)).toBeNull();
  });
});
