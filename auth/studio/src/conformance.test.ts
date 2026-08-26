/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no shared API, no environment
 * variables. This provider owns no credentials of its own — every question it
 * answers, it answers by asking the Mastra shared API over `fetch` — so the
 * whole of it can be exercised by standing an in-memory shared API in front of
 * `globalThis.fetch`. {@link sharedApi} is that API: one user, one
 * organization, one sealed session cookie and one CLI token, and it throws
 * rather than answering for any other host, so a request that escaped would
 * fail the run instead of leaving the process.
 *
 * The stub is installed per test rather than once, because the suite itself
 * replaces `globalThis.fetch` for the checks that must observe the absence of a
 * network, and restores whatever it found. Restoring ours in `afterEach` keeps
 * it out of every other file in the run.
 *
 * WHAT IS RED TODAY, AND WHY IT IS RECORDED RATHER THAN FIXED OR HIDDEN
 *
 * Four checks fail. All four are findings about the provider rather than about
 * this file, so each is recorded in `knownFailures` below: the suite goes
 * green and says on every run that it is not the green of a clean provider.
 * None is fixed here — every fix has a product or data consequence that is not
 * a test's to decide, and each is named with its defect. The `knownFailures`
 * entries carry the codes; this is the diagnosis behind them.
 *
 * 1. `obligation/stateCodec/login-url#no-state-parameter`
 *    `getLoginUrl` reads the `returnTo` half out of the host's `state` and
 *    forwards it as `post_login_redirect`, then drops the value itself: the
 *    authorization URL carries no `state` parameter, so the id half — the half
 *    a host would compare on the callback for CSRF — never comes back. The
 *    Factory already works around this: `mastracode/factory/src/auth.ts` keeps
 *    a `mastra_factory_return_to` cookie because "not every provider/platform
 *    echoes `state` back to the callback".
 *    Not fixed: adding `state` to the shared API's `/auth/login` query would
 *    turn the check green whether or not the shared API echoes it back, and
 *    that is not verifiable from this repository. A green that depends on an
 *    unverified assumption is worse than a recorded red.
 *
 * 2. `obligation/stateCodec/callback#threw-without-cause-after-token-exchange`
 *    `handleCallback` reaches the shared API — the suite counts the `fetch`
 *    and can see the `state` was accepted — and then throws
 *    `Error('Session validation failed')` with no `cause`, because
 *    `verifySessionCookie` catches the transport failure and answers `null`.
 *    The operator gets that one sentence for an expired session, a clock skew
 *    and an unreachable shared API alike.
 *    This one was previously silenced with `sso.reachedTokenExchange`, back
 *    when the suite misread it as a `state` rejection. The suite now diagnoses
 *    it correctly, so the hook is gone: a correct diagnosis of a real gap is
 *    worth seeing on every run, and the hook would have hidden it. Fixing it
 *    means propagating the cause out of `verifySessionCookie`, which is a
 *    provider change rather than a test one.
 *
 * 3. `obligation/organizationId/deterministic#not-a-string`
 *    `ensureOrganization(userId)` resolves `undefined` unless
 *    `verifySessionCookie` has previously seen a *cookie* for that user and
 *    cached it in `userSessionCookies`. The interface hands it only a user id,
 *    so a correct implementation has to work from one — and a user
 *    authenticated by bearer token (the CLI flow, `verifyBearerToken`, which
 *    never calls `rememberUserSession`) never gets an organization
 *    bootstrapped, on any request.
 *    Not fixed: `withSyntheticOrganizations` from
 *    `@mastra/factory-auth/organizations` is the kit's documented remedy, but
 *    applying it changes which partition bearer-token users' rows land in.
 *
 * 4. `sessions/round-trip#validate-rejects-fresh-session`
 *    `createSession(userId)` with no metadata mints a random UUID, and
 *    `validateSession` only accepts a sealed shared-API session, so the two
 *    halves of the loop never meet. In production the host always passes
 *    `metadata.accessToken` (`mastracode/factory/src/auth.ts`,
 *    `packages/server/src/server/handlers/auth.ts`), which is why nothing has
 *    noticed; the declared contract makes `metadata` optional.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { afterEach, beforeEach } from 'vitest';

import { MastraAuthStudio } from './index';

const SHARED_API = 'https://shared-api.conformance.test/v1';

/** The cookie name the provider reads. Must match `COOKIE_NAME` in `./index`. */
const COOKIE_NAME = 'wos-session';

/** The sealed session the shared API would have minted for a signed-in browser. */
const SESSION = 'conformance-sealed-session';

/** The CLI/API token the shared API accepts on `/auth/verify`. */
const TOKEN = 'conformance-cli-token';

const USER_ID = 'user_conformance';
const ORG_ID = 'org_conformance';

/**
 * What `/auth/me` and `/auth/verify` both answer.
 *
 * One payload for both endpoints on purpose: obligation 2 compares the user the
 * cookie resolves against the user the bearer token resolves, and they have to
 * be the same person.
 */
const IDENTITY = {
  user: {
    id: USER_ID,
    email: 'conformance@example.test',
    firstName: 'Conformance',
    lastName: 'User',
    profilePictureUrl: 'https://conformance.test/avatar.png',
  },
  organizationId: ORG_ID,
  role: 'admin',
  permissions: ['*'],
  memberOrgIds: [ORG_ID],
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** The `wos-session` value on a request, or null. Mirrors the provider's own parser. */
function sessionOf(headers: Headers): string | null {
  return headers.get('Cookie')?.match(new RegExp(`${COOKIE_NAME}=([^;]+)`))?.[1] ?? null;
}

/**
 * The in-memory Mastra shared API.
 *
 * Only the endpoints this provider calls exist. Everything else under the API's
 * own prefix answers 404, which is what a stale client would get from the real
 * one; anything addressed elsewhere throws, so the promise that this suite is
 * offline does not depend on the provider being well-behaved.
 */
async function sharedApi(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const request = new Request(input, init);
  const url = new URL(request.url);
  if (!`${url.origin}${url.pathname}`.startsWith(SHARED_API)) {
    throw new Error(`[conformance] unexpected request to ${url.href} — this suite must stay offline.`);
  }
  const route = `${request.method} ${url.pathname.slice(new URL(SHARED_API).pathname.length)}`;
  const session = sessionOf(request.headers);
  const bearer = request.headers.get('Authorization')?.replace(/^Bearer /, '') ?? null;
  const unauthorized = json({ error: 'unauthorized' }, 401);

  switch (route) {
    case 'GET /auth/me':
      return session === SESSION ? json(IDENTITY) : unauthorized;
    case 'GET /auth/verify':
      return bearer === TOKEN ? json(IDENTITY) : unauthorized;
    case 'GET /auth/orgs':
      return session === SESSION ? json({ organizations: [{ id: ORG_ID, role: 'admin' }] }) : unauthorized;
    case 'POST /auth/orgs':
      return session === SESSION ? json({ organization: { id: ORG_ID } }) : unauthorized;
    case 'POST /auth/logout':
      return session === SESSION
        ? json({ ok: true, logoutUrl: 'https://shared-api.conformance.test/logout' })
        : unauthorized;
    default:
      return json({ error: 'not_found' }, 404);
  }
}

let realFetch: typeof globalThis.fetch;

beforeEach(() => {
  realFetch = globalThis.fetch;
  globalThis.fetch = sharedApi as typeof globalThis.fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
});

function createProvider(): MastraAuthStudio {
  return new MastraAuthStudio({ sharedApiUrl: SHARED_API });
}

/**
 * The four defects this provider ships with, recorded so the suite can be
 * green without being a lie. Each `reason` is a pointer plus a sentence; the
 * diagnosis lives in this file's header, which is where a reader of the
 * failing check already lands.
 *
 * These are checked in both directions on every run: fix one of these defects
 * and the suite fails until its entry is deleted in the same change.
 */
const knownFailures = [
  {
    check: 'obligation/stateCodec/login-url',
    code: 'obligation/stateCodec/login-url#no-state-parameter',
    reason:
      'getLoginUrl forwards the state’s returnTo half as post_login_redirect and drops the value, so ' +
      'no `state` reaches the callback. Not fixed because whether the shared API echoes `state` back ' +
      'cannot be verified from this repository. Diagnosis 1 in this file’s header.',
  },
  {
    check: 'obligation/stateCodec/callback',
    code: 'obligation/stateCodec/callback#threw-without-cause-after-token-exchange',
    reason:
      'handleCallback reaches the shared API and then throws Error("Session validation failed") with ' +
      'no cause, because verifySessionCookie swallows the transport failure. Recorded rather than ' +
      'silenced with sso.reachedTokenExchange. Diagnosis 2 in this file’s header.',
  },
  {
    check: 'obligation/organizationId/deterministic',
    code: 'obligation/organizationId/deterministic#not-a-string',
    reason:
      'ensureOrganization resolves undefined for any user whose cookie verifySessionCookie has not ' +
      'cached, so bearer-token (CLI) users never get an organization. Not fixed because wrapping in ' +
      'withSyntheticOrganizations moves which partition their rows land in. Diagnosis 3 in this file’s header.',
  },
  {
    check: 'sessions/round-trip',
    code: 'sessions/round-trip#validate-rejects-fresh-session',
    reason:
      'createSession(userId) with no metadata mints a UUID validateSession can never accept; the host ' +
      'always passes metadata.accessToken, but the contract makes it optional. Diagnosis 4 in this ' +
      'file’s header.',
  },
];

describeAuthProvider({
  name: '@mastra/auth-studio',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: `${COOKIE_NAME}=${SESSION}`,
  knownFailures,
});
