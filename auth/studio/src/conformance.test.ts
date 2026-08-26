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
 * WHAT WAS RED, AND WHAT FIXED IT
 *
 * Four checks used to fail here, each recorded in a `knownFailures` entry. All
 * four are fixed in the provider and every entry is gone with them — the record
 * is checked in both directions on every run, so an entry that outlived its
 * defect fails the suite. `knownFailures` is deliberately absent below rather
 * than empty: there is nothing to record.
 *
 * What changed, for a reader who arrives from one of the old entries:
 *
 * 1. `obligation/stateCodec/login-url#no-state-parameter`
 *    `getLoginUrl` read the `returnTo` half out of the host's `state`,
 *    forwarded it as `post_login_redirect`, and dropped the value itself, so
 *    the id half — the half a host compares on the callback for CSRF — never
 *    came back. It now forwards the whole `state` as the OAuth `state`
 *    parameter, in addition to `post_login_redirect` rather than instead of
 *    it: a shared API that does not echo `state` back behaves exactly as it did
 *    before, and the Factory's `mastra_factory_return_to` cookie still carries
 *    the destination either way.
 *
 * 2. `obligation/stateCodec/callback#threw-without-cause-after-token-exchange`
 *    `handleCallback` reached the shared API and then threw
 *    `Error('Session validation failed')` with no `cause`, because
 *    `verifySessionCookie` caught the transport failure and answered `null`.
 *    The operator got that one sentence for an expired session, a clock skew
 *    and an unreachable shared API alike. `verifySessionCookie` now takes a
 *    `throwOnFailure` option — off for the request paths, where a rejection is
 *    an ordinary outcome — and `handleCallback` attaches what it gets as the
 *    `cause`.
 *
 * 3. `obligation/organizationId/deterministic#not-a-string`
 *    `ensureOrganization(userId)` resolved `undefined` unless
 *    `verifySessionCookie` had previously seen a *cookie* for that user, so a
 *    user authenticated by bearer token (the CLI flow) never got an
 *    organization at all. The cookie-backed bootstrap is unchanged; a user
 *    there is no cookie for now falls back to the derived `user:${userId}` —
 *    the same id `resolveOrganizationId` in `mastracode/factory/src/auth.ts`
 *    already applies to a user with no organization, so the partition is the
 *    one those rows land in today.
 *
 * 4. `sessions/round-trip#validate-rejects-fresh-session`
 *    `createSession(userId)` with no metadata minted a random UUID that
 *    `validateSession` — which only accepts a sealed shared-API session — could
 *    never accept. The host always passes `metadata.accessToken`
 *    (`mastracode/factory/src/auth.ts`,
 *    `packages/server/src/server/handlers/auth.ts`), which is why nothing had
 *    noticed, but the declared contract makes `metadata` optional. A session
 *    minted with no credential behind it is now recorded in-process, so
 *    create/validate/destroy are one loop; a sealed session is still verified
 *    against the shared API on every call and is never held in memory, which is
 *    what keeps revocation lag where it was.
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

describeAuthProvider({
  name: '@mastra/auth-studio',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: `${COOKIE_NAME}=${SESSION}`,
});
