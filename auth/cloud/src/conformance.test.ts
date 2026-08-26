/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no Mastra Cloud tenant, no
 * environment variables. This provider owns no credentials and holds no local
 * key material — every question it answers, it answers by asking the Cloud API
 * over `fetch`, through the single `fetchWithRetry` wrapper in
 * `./oauth/network` — so the whole of it can be exercised by standing an
 * in-memory Cloud API in front of `globalThis.fetch`. {@link cloudApi} is that
 * API: one user, one live access token, and a session store that only knows
 * the tokens it minted. It throws rather than answering for any other host, so
 * a request that escaped would fail the run instead of leaving the process.
 *
 * Nothing inside the package is replaced. PKCE generation, the base64url state
 * codec, the CSRF comparison, the cookie parsers and the retry wrapper all run
 * as they ship, which is what makes the obligation 3 results below findings
 * about this provider rather than about its test double.
 *
 * `isProduction` is passed explicitly for the same reason the base URL is
 * fake: `setSessionCookie` and `getLoginUrl` otherwise read
 * `process.env.NODE_ENV`, and this suite is not allowed to depend on the
 * environment it runs in.
 *
 * The stub is installed per test rather than once, because the suite itself
 * replaces `globalThis.fetch` for the checks that must observe the absence of
 * a network, and restores whatever it found. Restoring ours in `afterEach`
 * keeps it out of every other file in the run. The session store is rebuilt in
 * the same hook, so a check that destroys a session cannot be seen by the
 * next one.
 *
 * WHAT IS RED TODAY, AND WHY IT IS RECORDED RATHER THAN FIXED OR HIDDEN
 *
 * Three checks fail. All three are findings about the provider rather than
 * about this file, so each is recorded in `knownFailures` below: the suite
 * goes green and says on every run that it is not the green of a clean
 * provider. None is fixed here — each fix is a change to a published package
 * or to `@internal/auth`, neither of which is a test's to make. The
 * `knownFailures` entries carry the codes; this is the diagnosis behind them.
 *
 * 1. `obligation/stateCodec/login-url#state-not-round-tripped`
 *    `getLoginUrl(redirectUri, state)` reads only the `returnTo` half out of
 *    the host's `state` — it splits on `|` and percent-decodes the second
 *    field — and then throws the value away. `./oauth/oauth` mints a fresh
 *    CSRF token and re-encodes its own state as base64url
 *    `{"csrf":…,"returnTo":…}`, and that is what reaches the authorization
 *    URL. The id half the host minted, which is the half it would compare on
 *    the callback, never comes back.
 *    Not fixed: the id would have to travel inside the provider's own state
 *    payload and be re-emitted on the callback, which changes the wire format
 *    `/auth/oss` and `/auth/callback` see. Whether Mastra Cloud round-trips a
 *    longer state is not verifiable from this repository, and a green that
 *    depends on an unverified assumption is worse than a recorded red.
 *
 * 2. `obligation/stateCodec/callback#state-rejected`
 *    `handleCallback(code, state)` cannot read the PKCE verifier it wrote at
 *    login, so it throws `PKCEError.missingVerifier()` before it looks at the
 *    `state` at all and before it makes any network attempt — the suite
 *    replaced `globalThis.fetch` and counted zero calls.
 *    This is the systemic PKCE gap the audit records, seen from the provider
 *    side. The write half, `getLoginCookies`, is declared on `ISSOProvider`
 *    and is called by the Factory. The read half is
 *    `setCallbackCookieHeader`, which is *not* on `ISSOProvider` at all: it is
 *    an undeclared duck-typed hook, called only from
 *    `packages/server/src/server/handlers/auth.ts:492` and forwarded by
 *    `CompositeAuth`. It appears zero times in `mastracode/factory/src/`. So a
 *    host that has only the declared interface — which is what conformance
 *    holds a provider to — has no way to hand this method the cookie, and
 *    every sign-in through the Factory fails here.
 *    Not fixed, and deliberately not worked around: pre-feeding the cookie
 *    from `createProvider` would invent a host behaviour the Factory does not
 *    have, and would turn a real gap green. The fix is to declare the read
 *    side on `ISSOProvider` and call it from the Factory callback, which is a
 *    change to `@internal/auth` and `mastracode/factory`.
 *    Second defect behind the same code, and it survives the first: this
 *    provider's `decodeState` is `JSON.parse(base64url)`, so a host-minted
 *    `id|returnTo` state is rejected as malformed even once the cookie is
 *    readable. Both halves of obligation 3 fail for one root cause — the
 *    provider does not use the kit's state codec in either direction.
 *
 * 3. `sessions/round-trip#validate-rejects-fresh-session`
 *    `createSession(userId)` with no metadata mints a random UUID and returns
 *    it without telling Cloud anything — it issues no request at all, so
 *    there is nothing the in-memory Cloud could have recorded. `validateSession`
 *    then asks `/auth/session/validate` about that UUID and is told no. The
 *    two halves of the loop never meet.
 *    In production the host always passes `metadata.accessToken`, which is why
 *    nothing has noticed; the declared contract makes `metadata` optional, and
 *    `isSessionProvider` tests only that `createSession` and `validateSession`
 *    exist. `auth/studio` ships the identical defect from the identical code.
 *
 * WHAT IS NOT A KNOWN FAILURE: THE ORGANIZATION OBLIGATION
 *
 * `MastraCloudAuthProvider` has no organization concept — `CloudUser` carries
 * an id, an email, a name, an avatar and a role, and the word does not appear
 * anywhere else in `src/`. Obligation 4 is not gated on
 * `isOrganizationsProvider`, on purpose, so the provider is wrapped in
 * `withSyntheticOrganizations`, which the kit documents as the sanctioned
 * answer for exactly this shape and which `auth/okta` mounts the same way. It
 * derives `user:${userId}`, a pure function of the user id that two processes
 * agree on without talking to each other.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
import { afterEach, beforeEach } from 'vitest';

import { MastraCloudAuthProvider } from './auth-provider';

const CLOUD_BASE_URL = 'https://cloud.conformance.test';
const PROJECT_ID = 'proj_conformance';
const REDIRECT_URI = 'https://conformance.test/auth/callback';

/** The cookie name the provider reads. Must match `SESSION_COOKIE_NAME` in `./session/cookie`. */
const SESSION_COOKIE_NAME = 'mastra_cloud_session';

/** The access token the in-memory Cloud has already issued to a signed-in browser. */
const TOKEN = 'conformance-cloud-access-token';

/** The `sub` the `/auth/verify` payload carries, and what `authenticateToken` must resolve to. */
const USER_ID = 'user_conformance';

/** A stable, obviously-fake code the in-memory Cloud exchanges. */
const AUTHORIZATION_CODE = 'conformance-authorization-code';

/**
 * What `/auth/verify` answers for a live token.
 *
 * One payload for both the bearer path and the cookie path on purpose:
 * obligation 2 compares the user the cookie resolves against the user the
 * bearer token resolves, and they have to be the same person.
 */
const VERIFY_BODY = {
  sub: USER_ID,
  email: 'conformance@example.test',
  name: 'Conformance User',
  avatar_url: 'https://conformance.test/avatar.png',
  role: 'member',
};

interface CloudSessionRecord {
  userId: string;
  createdAt: number;
  expiresAt: number;
}

/**
 * The tokens the in-memory Cloud has issued and not yet revoked.
 *
 * Rebuilt per test. A token is in here because Cloud minted it — at the token
 * exchange, or as the seeded browser session — which is the whole point: a
 * value this provider invented locally is not in here, and Cloud has no reason
 * to accept one.
 */
let sessions: Map<string, CloudSessionRecord>;

function freshSessions(): Map<string, CloudSessionRecord> {
  const now = Date.now();
  return new Map([[TOKEN, { userId: USER_ID, createdAt: now, expiresAt: now + 24 * 60 * 60 * 1000 }]]);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/**
 * The in-memory Mastra Cloud API.
 *
 * Only the four endpoints this provider calls exist. Everything else under the
 * Cloud origin answers 404, which is what a stale client would get from the
 * real one; anything addressed elsewhere throws, so the promise that this
 * suite is offline does not depend on the provider being well-behaved.
 */
async function cloudApi(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);
  if (url.origin !== CLOUD_BASE_URL) {
    throw new Error(`[conformance] unexpected request to ${url.href} — this suite must stay offline.`);
  }

  const bearer = request.headers.get('Authorization')?.replace(/^Bearer /, '') ?? null;
  const live = bearer !== null ? sessions.get(bearer) : undefined;
  const unauthorized = json({ error: 'unauthorized' }, 401);

  switch (`${request.method} ${url.pathname}`) {
    case 'POST /auth/verify':
      // Cloud scopes verification to the project the token was issued for.
      if (request.headers.get('X-Project-ID') !== PROJECT_ID) return unauthorized;
      return live !== undefined ? json(VERIFY_BODY) : unauthorized;

    case 'POST /auth/session/validate':
      if (request.headers.get('X-Project-ID') !== PROJECT_ID) return unauthorized;
      return live !== undefined
        ? json({ userId: live.userId, createdAt: live.createdAt, expiresAt: live.expiresAt })
        : unauthorized;

    case 'POST /auth/session/destroy':
      // No X-Project-ID on this endpoint — see the note in `./session/session`.
      if (bearer !== null) sessions.delete(bearer);
      return json({ ok: true });

    case 'POST /auth/callback': {
      if (request.headers.get('X-Project-ID') !== PROJECT_ID) return unauthorized;
      const body = (await request.json()) as { code?: string; redirect_uri?: string; code_verifier?: string };
      if (body.code !== AUTHORIZATION_CODE) {
        return json({ code: 'invalid_grant', message: 'The authorization code is invalid or has expired.' }, 400);
      }
      if (typeof body.code_verifier !== 'string' || body.code_verifier === '') {
        return json({ code: 'invalid_request', message: 'code_verifier is required.' }, 400);
      }
      const now = Date.now();
      const minted = `conformance-minted-${now}`;
      sessions.set(minted, { userId: USER_ID, createdAt: now, expiresAt: now + 3600 * 1000 });
      return json({ access_token: minted, token_type: 'Bearer', expires_in: 3600 });
    }

    default:
      return json({ error: 'not_found' }, 404);
  }
}

let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  sessions = freshSessions();
  realFetch = globalThis.fetch;
  globalThis.fetch = cloudApi as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

/**
 * The provider as a host deploys it, wrapped the way a provider with no
 * organization concept is meant to be. See the header for why the wrapper is
 * the answer here rather than a recorded failure.
 */
function createProvider() {
  return withSyntheticOrganizations(
    new MastraCloudAuthProvider({
      projectId: PROJECT_ID,
      cloudBaseUrl: CLOUD_BASE_URL,
      callbackUrl: REDIRECT_URI,
      isProduction: true,
    }),
  );
}

/**
 * The three defects this provider ships with, recorded so the suite can be
 * green without being a lie. Each `reason` is a pointer plus a sentence; the
 * diagnosis lives in this file's header, which is where a reader of the
 * failing check already lands.
 *
 * Each code was read off the failure the check actually prints rather than
 * chosen by hand — `sessions/round-trip` alone has five, and the callback
 * check has two that a reader would pick between wrongly.
 *
 * These are checked in both directions on every run: fix one of these defects
 * and the suite fails until its entry is deleted in the same change.
 */
const knownFailures = [
  {
    check: 'obligation/stateCodec/login-url',
    code: 'obligation/stateCodec/login-url#state-not-round-tripped',
    reason:
      'getLoginUrl reads only the returnTo half out of the host’s state and drops the value; ./oauth/oauth ' +
      'mints a fresh CSRF token and re-encodes its own base64url state, so the host’s id never comes back. ' +
      'Not fixed because whether Mastra Cloud round-trips a longer state cannot be verified from this ' +
      'repository. Diagnosis 1 in this file’s header.',
  },
  {
    check: 'obligation/stateCodec/callback',
    code: 'obligation/stateCodec/callback#state-rejected',
    reason:
      'handleCallback throws PKCEError.missingVerifier() before reading the state and before any network ' +
      'attempt. P5 has since declared the read half (setCallbackCookieHeader on ISSOProvider) and the ' +
      'Factory now calls it, so a host CAN hand this provider the cookie -- but the conformance harness ' +
      'does not, which is P6. Behind that, decodeState is JSON.parse(base64url) and rejects a host-minted ' +
      'id|returnTo state anyway, so this check would still fail on the state alone. Diagnosis 2 in this ' +
      'file’s header.',
  },
  {
    check: 'sessions/round-trip',
    code: 'sessions/round-trip#validate-rejects-fresh-session',
    reason:
      'createSession(userId) with no metadata mints a UUID and issues no request, so Cloud never hears about ' +
      'the session and validateSession can never accept it; the host always passes metadata.accessToken, but ' +
      'the contract makes it optional. Diagnosis 3 in this file’s header.',
  },
];

describeAuthProvider({
  name: '@mastra/auth-cloud',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: `${SESSION_COOKIE_NAME}=${TOKEN}`,
  sso: {
    redirectUri: REDIRECT_URI,
    code: AUTHORIZATION_CODE,
  },
  knownFailures,
});
