/**
 * The provider conformance suite, for people *writing* a provider.
 *
 * ```ts
 * // auth/my-provider/src/conformance.test.ts
 * import { describeAuthProvider } from '@mastra/factory-auth/conformance';
 * import { MyAuthProvider } from './auth-provider.js';
 *
 * describeAuthProvider({
 *   name: '@mastra/auth-my-provider',
 *   createProvider: () => new MyAuthProvider({ issuer: 'https://idp.test', verify: fakeVerifier }),
 *   token: 'a-token-my-provider-accepts',
 *   userId: 'user_123',
 *   cookieHeader: 'my_provider_session=a-token-my-provider-accepts',
 * });
 * ```
 *
 * That is the whole integration. It registers one vitest suite that asserts the
 * contract your provider declares, plus the four obligations that no interface
 * states and no documentation stated before this package - see
 * {@link AUTH_OBLIGATION_GUIDANCE}.
 *
 * IT NEEDS NO NETWORK, NO IDENTITY PROVIDER, AND NO ENVIRONMENT VARIABLES
 *
 * Every check runs against whatever {@link AuthProviderConformanceOptions.createProvider}
 * hands back, offline. Making your provider verify a token without calling a
 * vendor is your job and it is the same job your unit tests already do: inject a
 * verifier, subclass, or stub the SDK inside the factory. One check goes
 * further and *removes* the network - it replaces `globalThis.fetch` for the
 * duration of a single call - because "did this provider reject my `state`, or
 * did it get as far as the token exchange" is not a question you can answer
 * while the exchange might succeed. See {@link authConformanceChecks} for that
 * one.
 *
 * VITEST IS AN OPTIONAL PEER DEPENDENCY
 *
 * This is the only module in `@mastra/factory-auth` that imports a test runner,
 * and `vitest` is declared as an *optional* peer for exactly that reason: a host
 * that only consumes a provider never loads this subpath and should not be asked
 * to install a runner. If you import it, install `vitest` (>=4) yourself. Every
 * other entry point in this package is runner-free, including
 * `@mastra/factory-auth/testing`.
 *
 * SKIP OR FAIL: ONE RULE
 *
 * A check is skipped only when a structural guard from `./contract` says the
 * provider does not *declare* the capability the check is about. It is never
 * skipped because the provider declared a capability and then did not deliver
 * it. So a bearer-token validator that implements no hosted login does not fail
 * for having no `state` codec - it has no login URL to put a `state` in - while
 * a provider that does implement `getLoginUrl` is held to the codec without
 * exception.
 *
 * Two consequences worth stating, because both are deliberate:
 *
 * - **Obligation 4 is not gated on `isOrganizationsProvider`.** Gating it there
 *   would make it self-fulfilling: every provider without organizations would
 *   skip the check that exists to notice exactly that. Failing that guard is the
 *   finding, and `withSyntheticOrganizations` is the one-line fix.
 * - **Obligation 2 is gated on whether a browser can hold a session at all**,
 *   which is `toAuthDescriptor(provider).features.logout` - true when the
 *   provider offers a hosted login, a credentials sign-in, server-side sessions,
 *   or its own auth routes. A pure bearer-token validator has no browser session
 *   to read a cookie for, and requiring one would be requiring it to invent a
 *   cookie nobody sets.
 * - **`sso/pkce-round-trip` is gated on the WRITE half only.** A provider with
 *   no `getLoginCookies` carries nothing across the round trip and skips. A
 *   provider that has it and has no `setCallbackCookieHeader` is the defect the
 *   check exists for, so gating on the read half would skip exactly the provider
 *   being looked for - the same self-fulfilling gate obligation 4 avoids.
 *   Between those two, a provider that declares `getLoginCookies` and hands back
 *   none passes rather than skipping: the check applied and ran, and found no
 *   cookie to hold anybody to. That is the truthful answer for a confidential
 *   client authenticating with `client_secret`, which is the shape four
 *   providers in this repository ship.
 * - **A guard passing is not the same as the method being there**, and
 *   `users/get-user` is the check that has to say so out loud. `isUserProvider`
 *   tests `getCurrentUser` alone, while `IUserProvider` requires `getUser` too -
 *   so the guard narrows a provider with one of two required members to a type
 *   that promises both, `provider.getUser(id)` typechecks in the host, and it is
 *   `undefined` at run time. The gate can only ask the guard, so the missing
 *   member is a FAIL inside the check body rather than a skip: the provider
 *   declared `IUserProvider` and did not deliver it, which is the second half of
 *   the rule above. `isOrganizationsProvider` reads both of its interface's
 *   members and has no such gap, which is why `organizations/is-admin` can gate
 *   on it and stop there.
 *
 * A PROVIDER THAT DOES NOT CONFORM, AND SHIPS ANYWAY
 *
 * There is a third outcome besides pass and skip, and it exists because the
 * first providers this suite was run against had real defects with no small fix
 * - a `validateSession` that returns `null` unconditionally, a `getLoginUrl`
 * that drops `state`. With conformance required in CI, the only moves available
 * were to weaken the suite, leave the build red until nobody reads it, or drop
 * the provider from the run. All three end with nobody knowing.
 *
 * {@link AuthProviderConformanceOptions.knownFailures} is the fourth: record the
 * failure, name which one it is, and say why. The suite stays green and says
 * loudly that it is only green because somebody wrote the defect down. What
 * stops that from decaying into a permanent exemption is that the record is
 * checked in both directions - see {@link runAuthConformanceCheck}.
 *
 * @module
 */
import { describe, expect, it } from 'vitest';
import { toAuthDescriptor } from '../capabilities.js';
import {
  hasAuthInit,
  isAuthHttpHandler,
  isCredentialsProvider,
  isOrganizationsProvider,
  isSessionProvider,
  isSSOProvider,
  isUserProvider,
} from '../contract.js';
import type { IMastraAuthProvider } from '../contract.js';
import { toAuthIdentity } from '../identity.js';
import type { AuthIdentity } from '../identity.js';
import { decodeState, encodeState, parseStateId } from '../oauth-state.js';
import { resolveOrganizationId } from '../organizations.js';
import type { AuthObligation } from '../testing/index.js';
import {
  attachFailureCode,
  AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX,
  AUTH_OBLIGATION_COUNT,
  AUTH_OBLIGATION_GUIDANCE,
  formatConformanceFailure,
  formatKnownFailure,
  formatStaleKnownFailure,
  isFixtureFailureCode,
  KIT_PACKAGE_NAME,
  kitImport,
  KNOWN_FAILURE_TITLE_PREFIX,
  readFailureCode,
} from './obligations.js';
import type { ConformanceFailure } from './obligations.js';

// `attachFailureCode` is deliberately NOT re-exported. It is how a `fail` site
// stamps its code onto the assertion, which is this module's own business;
// `readFailureCode` is the half a consumer needs. Adding an export later is a
// minor and removing one is a major, so the surface starts at what is used.
export {
  AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX,
  AUTH_OBLIGATION_COUNT,
  AUTH_OBLIGATION_GUIDANCE,
  CONFORMANCE_DOCS_URL,
  formatConformanceFailure,
  formatKnownFailure,
  formatStaleKnownFailure,
  isFixtureFailureCode,
  KNOWN_FAILURE_TITLE_PREFIX,
  readFailureCode,
} from './obligations.js';
export type {
  AuthConformanceFailureCode,
  AuthObligationGuidance,
  ConformanceFailure,
  KnownFailureReport,
  StaleKnownFailureKind,
  StaleKnownFailureReport,
} from './obligations.js';

// ============================================================================
// Options
// ============================================================================

/** Hosted-login fixtures. Read only when `isSSOProvider(provider)`. */
export interface AuthConformanceSSOOptions {
  /**
   * The OAuth `redirect_uri` handed to `getLoginUrl`. Defaults to
   * `'https://conformance.test/auth/callback'`.
   *
   * Override it when your provider validates the value against a configured
   * allowlist and would reject the default.
   */
  redirectUri?: string;

  /**
   * The authorization code handed to `handleCallback`. Defaults to
   * `'conformance-authorization-code'`.
   *
   * It is never expected to be valid. The check it appears in is about `state`,
   * and a code that fails is the normal outcome.
   */
  code?: string;

  /**
   * Recognize an error meaning "this provider got as far as the token exchange".
   *
   * The `stateCodec` obligation asks whether `handleCallback` accepts a `state`
   * the host minted, and the only offline evidence of "yes" is that the provider
   * stopped asking about the `state` and started talking to the network. The
   * suite arranges for that to be visible by replacing `globalThis.fetch` with
   * one that throws a recognizable error, then checks whether the failure came
   * from there.
   *
   * That works for a provider whose token exchange goes through global `fetch`,
   * which is every provider in this repository. Supply this when yours does not
   * - an SDK holding its own `undici` agent, or `node:https` - and answer `true`
   * for whatever your transport throws when it cannot reach the issuer.
   *
   * Widening, not disabling: the suite's own recognizer runs first, and this is
   * consulted only for errors it did not recognize. A hook that answers `true`
   * unconditionally turns the check off, which is a thing you can do and a thing
   * a reviewer can see you doing.
   */
  reachedTokenExchange?: (error: unknown) => boolean;
}

/**
 * One check this provider is known not to pass, recorded rather than hidden.
 *
 * The case this exists for is a provider that ships today and does not conform,
 * where the defect is real and the fix is not small. Three options existed
 * before it: change the suite so the provider passes, leave CI red until
 * somebody stops reading it, or exclude the provider from conformance
 * altogether. Every one of those ends with nobody knowing the provider is
 * broken. Recording it ends with everybody knowing.
 *
 * ```ts
 * knownFailures: [
 *   {
 *     check: 'sessions/round-trip',
 *     code: 'sessions/round-trip#validate-rejects-fresh-session',
 *     reason:
 *       'validateSession returns null unconditionally; every ISessionProvider member is a no-op. ' +
 *       'Full diagnosis in this file’s header, under WHAT IS RED TODAY.',
 *   },
 * ]
 * ```
 *
 * An entry is not an exclusion, and the difference is that it is checked in
 * both directions on every run. The suite fails when a recorded check passes,
 * when it stops applying, and when it fails for a reason other than the one
 * recorded - so the entry cannot outlive the defect, and cannot spread to cover
 * a second one.
 */
export interface AuthConformanceKnownFailure {
  /**
   * The check id, exactly as {@link AuthConformanceCheck.id} spells it -
   * `'sessions/round-trip'`.
   *
   * An id no check has fails at registration, loudly, listing the ids that do
   * exist. A typo must not become a permanent silent exemption, and a check
   * that was renamed must not leave a dead entry behind still granting cover.
   */
  readonly check: string;

  /**
   * Which *way* this check fails, as
   * {@link AuthConformanceCheck.failureCodes} spells it -
   * `'sessions/round-trip#validate-rejects-fresh-session'`.
   *
   * Required, and the reason it is required is that a check id alone records
   * only *that* a check fails. `sessions/round-trip` has five distinct ways to
   * go red, and two providers can fail it for genuinely different defects. An
   * entry keyed on the id alone would silently cover a second, unrelated
   * regression arriving later in the same check - which is the outcome this
   * whole mechanism exists to rule out.
   *
   * The code is a stable identifier this package owns, not a substring of the
   * failure text: message wording is patch-level here and asserting on it would
   * break your suite on a rewording. Run the check once and the red quotes the
   * code to paste in.
   *
   * It must belong to the check named above, which is checked at registration.
   */
  readonly code: string;

  /**
   * Why this is not fixed, in a sentence or two.
   *
   * Required, and non-empty. An exemption without a stated reason is how the
   * four undocumented obligations happened in the first place: everybody
   * involved knew why at the time, and the knowledge left with them.
   *
   * A pointer plus a sentence is the intended shape rather than an essay -
   * where the full diagnosis lives, and enough of it that a reader of the CI
   * output does not have to go and find it to know whether this matters to
   * them.
   */
  readonly reason: string;
}

/**
 * Everything {@link describeAuthProvider} needs, and nothing it can work out
 * for itself.
 *
 * The three required fields are the three facts no guard can derive: what to
 * call this provider, how to build one, and a token it accepts. Everything else
 * has a default or is required only for the providers it applies to.
 */
export interface AuthProviderConformanceOptions<TProvider extends IMastraAuthProvider = IMastraAuthProvider> {
  /**
   * What to call this provider in the suite title and in every failure message.
   *
   * Use the published package name - `'@mastra/auth-workos'` - rather than a
   * class name. A failure from a conformance suite is usually read by somebody
   * who did not write the provider, in CI output that names no file.
   */
  name: string;

  /**
   * Build a provider, offline.
   *
   * Called once per check, so no check can observe another's leftovers: a state
   * store filled by the hosted-login check is not visible to the next one, and a
   * provider that mutates itself on first use is exercised from a clean start
   * every time.
   *
   * Anything asynchronous - opening an in-memory database, running migrations -
   * can be awaited here.
   */
  createProvider: () => TProvider | Promise<TProvider>;

  /**
   * A bearer token this provider accepts.
   *
   * It has to work with no network and no real identity provider, which usually
   * means the provider `createProvider` returns has had its verifier injected or
   * its SDK stubbed. That is the same setup your unit tests need, so this option
   * rarely costs anything new.
   */
  token: string;

  /**
   * The id `authenticateToken` must resolve to for {@link token}.
   *
   * Optional but recommended, and not only as an extra assertion. Several checks
   * need a user id in hand - `ensureOrganization` takes one - and without this
   * they have to read it back out of `authenticateToken`. Supplying it keeps a
   * provider whose id is nested (obligation 1) reporting exactly one failure
   * instead of cascading into every check downstream of it.
   */
  userId?: string;

  /**
   * A token this provider must reject. Defaults to
   * `'conformance-rejected-token'`.
   *
   * Override it if that string is somehow meaningful to your provider. It is
   * never expected to authenticate anybody.
   */
  rejectedToken?: string;

  /**
   * The `Cookie` header a signed-in browser sends to this provider - for
   * example `` `better-auth.session_token=${token}` ``.
   *
   * Required for any provider that can put a session in a browser, which is
   * obligation 2's gate. There is no default and there deliberately is not one:
   * only you know which cookie your provider reads, and a suite that guessed the
   * name would report a guess that missed as an obligation failure, which is a
   * worse outcome than asking.
   *
   * Two spellings are both fine. Use your own cookie if the provider owns the
   * browser session, or the host's if you read
   * `@mastra/factory-auth/cookie`'s - `sessionCookieName(site)` gives you that
   * name.
   */
  cookieHeader?: string;

  /**
   * The URL the suite builds its request fixtures against. Defaults to
   * `'https://conformance.test/api/agents'`.
   *
   * Override it when your provider branches on the path - a `public` route list
   * that would let an unauthenticated request through, for instance.
   */
  requestUrl?: string;

  /** See {@link AuthConformanceSSOOptions}. Ignored unless `isSSOProvider(provider)`. */
  sso?: AuthConformanceSSOOptions;

  /**
   * Checks this provider is known not to pass, each with a reason.
   *
   * See {@link AuthConformanceKnownFailure}. Leave it off for a provider that
   * conforms; an empty array means the same thing.
   */
  knownFailures?: readonly AuthConformanceKnownFailure[];
}

// ============================================================================
// Checks
// ============================================================================

/**
 * One conformance check, separated from the runner that registers it.
 *
 * `describeAuthProvider` is a thin adapter over this list, and the split is not
 * decoration. A suite that can only be run by vitest can only be *proved* by
 * vitest, and there is no way to write a passing test that a nested suite failed
 * - so the kit's own tests call {@link run} directly and assert that each check
 * throws the message it promises. That is how
 * `src/__tests__/conformance-red.test.ts` demonstrates all four obligations
 * going red against a deliberately broken fake, which is the half of "does this
 * suite work" that a green run cannot answer.
 *
 * It is exported for the same reason it exists: a provider author who wants to
 * run conformance from a script, a different runner, or a CLI can iterate this
 * list without taking vitest as a dependency of the code that does the
 * iterating.
 */
export interface AuthConformanceCheck {
  /** Stable identifier, e.g. `'obligation/cookieAuth'`. Safe to filter on. */
  readonly id: string;

  /** The `describe` block this check is registered under. */
  readonly section: string;

  /** The `it` title. Reads as a claim about the provider, not as a procedure. */
  readonly title: string;

  /** Which of the four obligations this check belongs to, or `null`. */
  readonly obligation: AuthObligation | null;

  /**
   * Every way this check can go red, as stable codes.
   *
   * `['sessions/round-trip#create-threw', 'sessions/round-trip#validate-rejects-fresh-session', ...]`.
   * A check has several because a check asks several questions, and telling
   * those apart is what lets a {@link AuthConformanceKnownFailure} record one
   * named defect instead of "this check may fail". Each entry is this check's
   * `id`, a `#`, and a slug.
   *
   * Not exhaustive of everything that can *throw* out of {@link run}: a shared
   * fixture step fails under the `fixture/` namespace, which no check declares
   * and no entry may name. See {@link AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX}.
   */
  readonly failureCodes: readonly string[];

  /**
   * Why this check does not apply to `provider`, or `null` when it does.
   *
   * The only legitimate reason is that a structural guard says the provider does
   * not declare the capability the check is about. See the skip rule in this
   * module's header.
   */
  readonly skipReason: (provider: IMastraAuthProvider) => string | null;

  /** Run it. Resolves when the provider conforms, throws when it does not. */
  readonly run: (provider: IMastraAuthProvider) => Promise<void>;

  /**
   * The caller's `knownFailures` entry for this check, or `null`.
   *
   * Resolved here rather than left for the runner to look up, so that an
   * adapter walking this list - a script, a different runner, a CLI - gets the
   * declaration as data and enforces the same policy through
   * {@link runAuthConformanceCheck} without re-deriving any of it.
   */
  readonly knownFailure: AuthConformanceKnownFailure | null;
}

// ============================================================================
// Outcomes
// ============================================================================

/**
 * What one check did, once the known-failure policy has been applied to it.
 *
 * The half of {@link runAuthConformanceCheck} worth reading twice is that
 * `knownFailure` is the *only* non-failing outcome a recorded check can reach.
 * A recorded check that passes, that turns out not to apply, or that fails
 * under a different code all arrive here as `failed`, with a message about the
 * record rather than about the provider.
 */
export type AuthConformanceOutcome =
  /** It ran and the provider conformed. */
  | { readonly status: 'passed' }
  /** A structural guard says it does not apply. `reason` is that guard's. */
  | { readonly status: 'skipped'; readonly reason: string }
  /** It went red. `code` is `null` when the throw came from outside a `fail` site. */
  | { readonly status: 'failed'; readonly message: string; readonly code: string | null }
  /** It went red exactly as its `knownFailures` entry records. Not a suite failure. */
  | {
      readonly status: 'knownFailure';
      readonly entry: AuthConformanceKnownFailure;
      /** The full report, laid out like every other message in this package. */
      readonly message: string;
      /** The original failure, unedited. */
      readonly failure: string;
    };

// ============================================================================
// Internals: fixtures
// ============================================================================

/** The options, with every default filled in. */
interface Fixtures {
  readonly name: string;
  readonly token: string;
  readonly rejectedToken: string;
  readonly userId: string | undefined;
  readonly cookieHeader: string | undefined;
  readonly requestUrl: string;
  readonly redirectUri: string;
  readonly code: string;
  readonly reachedTokenExchange: ((error: unknown) => boolean) | undefined;
  readonly knownFailures: readonly AuthConformanceKnownFailure[];
}

const DEFAULT_REQUEST_URL = 'https://conformance.test/api/agents';
const DEFAULT_REDIRECT_URI = 'https://conformance.test/auth/callback';
const DEFAULT_CODE = 'conformance-authorization-code';
const DEFAULT_REJECTED_TOKEN = 'conformance-rejected-token';

/** The `state` id every hosted-login check mints under. Fixed, so a failure quotes a constant. */
const CONFORMANCE_STATE_ID = 'conformance-state-id';

/** The destination every hosted-login check round trips. Chosen to survive percent-encoding. */
const CONFORMANCE_RETURN_TO = '/agents/42';

/**
 * An organization id no provider bootstrapped, for the one question in this
 * suite whose wrong answer is a grant of rights over somebody else's data.
 *
 * A literal rather than something derived, so the failure quotes a constant and
 * a reader can see at a glance that the suite did not invent a plausible id and
 * catch a provider out on a near miss. It names itself, it is not in any
 * provider's id format, and no `ensureOrganization` in this repository or
 * outside it can return it.
 */
const CONFORMANCE_UNOWNED_ORGANIZATION = 'conformance-organization-nobody-created';

function readFixtures(options: AuthProviderConformanceOptions): Fixtures {
  if (typeof options.name !== 'string' || options.name.trim() === '') {
    throw new TypeError('describeAuthProvider: `name` must be a non-empty string naming the provider under test.');
  }
  if (typeof options.createProvider !== 'function') {
    throw new TypeError('describeAuthProvider: `createProvider` must be a function returning a provider.');
  }
  if (typeof options.token !== 'string' || options.token === '') {
    throw new TypeError(
      'describeAuthProvider: `token` must be a non-empty bearer token this provider accepts offline. ' +
        'An empty one cannot be told apart from the empty token obligation 2 is about.',
    );
  }
  return {
    name: options.name,
    token: options.token,
    rejectedToken: options.rejectedToken ?? DEFAULT_REJECTED_TOKEN,
    userId: options.userId,
    cookieHeader: options.cookieHeader,
    requestUrl: options.requestUrl ?? DEFAULT_REQUEST_URL,
    redirectUri: options.sso?.redirectUri ?? DEFAULT_REDIRECT_URI,
    code: options.sso?.code ?? DEFAULT_CODE,
    reachedTokenExchange: options.sso?.reachedTokenExchange,
    knownFailures: readKnownFailures(options.knownFailures),
  };
}

/**
 * Validate `knownFailures` for shape, before any check exists to run.
 *
 * Everything wrong with an entry is wrong in the calling test file, so it is
 * raised the way this module already raises a missing `token`: a `TypeError` at
 * registration, which fails the whole file rather than one test. That is the
 * loudest thing available and the only volume worth having here. An exemption
 * that is *quietly* ignored - a typo, a stale id after a rename - is
 * indistinguishable from an exemption that works, and it grants cover forever.
 *
 * Ids and codes are checked against the real list in
 * {@link resolveKnownFailures}, which needs the built checks. This pass is the
 * part that needs nothing.
 */
function readKnownFailures(entries: readonly AuthConformanceKnownFailure[] | undefined): AuthConformanceKnownFailure[] {
  if (entries === undefined) return [];
  if (!Array.isArray(entries)) {
    throw new TypeError('describeAuthProvider: `knownFailures` must be an array of { check, code, reason } entries.');
  }
  const seen = new Set<string>();
  return entries.map((entry, index) => {
    const at = `describeAuthProvider: knownFailures[${index}]`;
    if (typeof entry !== 'object' || entry === null) {
      throw new TypeError(`${at} is ${String(entry)}, not a { check, code, reason } entry.`);
    }
    if (typeof entry.check !== 'string' || entry.check.trim() === '') {
      throw new TypeError(`${at}.check must be a non-empty check id, e.g. 'sessions/round-trip'.`);
    }
    if (typeof entry.code !== 'string' || entry.code.trim() === '') {
      throw new TypeError(
        `${at}.code must be a non-empty failure code, e.g. ` +
          `'sessions/round-trip#validate-rejects-fresh-session'. It names WHICH way the check fails; ` +
          'the check id alone would let this entry cover a second, unrelated defect in the same check. ' +
          'Run the check once - the failure it prints quotes the code to record here.',
      );
    }
    if (typeof entry.reason !== 'string' || entry.reason.trim() === '') {
      throw new TypeError(
        `${at}.reason must be a non-empty explanation of why '${entry.check}' is not fixed. ` +
          'An exemption with no stated reason is how an undocumented obligation gets created: ' +
          'everybody knows why at the time, and the knowledge leaves with them.',
      );
    }
    if (isFixtureFailureCode(entry.code)) {
      throw new TypeError(
        `${at}.code is ${JSON.stringify(entry.code)}, which is a fixture fault rather than a provider ` +
          'defect. `knownFailures` grants a provider an exemption, and "the token this suite was told ' +
          'to use does not work" is not something to be exempt from - fix the fixture instead.',
      );
    }
    if (seen.has(entry.check)) {
      throw new TypeError(
        `${at} is a second entry for ${JSON.stringify(entry.check)}. A check stops at its first failure, ` +
          'so only one of them could ever match; the other would sit there unevaluated, never checked ' +
          'and never made to expire. Record the one that actually fires.',
      );
    }
    seen.add(entry.check);
    return { check: entry.check, code: entry.code, reason: entry.reason };
  });
}

/**
 * The five nearest ids to a mistyped one, for the message that reports it.
 *
 * Nothing clever: shared prefix, then shared characters. The point is only that
 * somebody who typed `sessions/roundtrip` sees `sessions/round-trip` at the top
 * of the list rather than eighteen ids in registration order.
 */
function nearest(target: string, candidates: readonly string[]): string[] {
  const score = (candidate: string): number => {
    const characters = new Set(target);
    let shared = 0;
    for (const character of candidate) if (characters.has(character)) shared += 1;
    let prefix = 0;
    while (prefix < target.length && prefix < candidate.length && target[prefix] === candidate[prefix]) prefix += 1;
    return prefix * 10 + shared;
  };
  return [...candidates].sort((left, right) => score(right) - score(left)).slice(0, 5);
}

/**
 * Bind every entry to the check it names, failing on any that names nothing.
 *
 * Two different mistakes, reported differently because they need different
 * fixes. An unknown check id is usually a typo or a rename, and the reader
 * needs the list of ids. A code that does not belong to a real check is usually
 * a defect that now surfaces somewhere else, and the reader needs that check's
 * own codes rather than all of them.
 */
function resolveKnownFailures(
  fixtures: Fixtures,
  checks: readonly Omit<AuthConformanceCheck, 'knownFailure'>[],
): Map<string, AuthConformanceKnownFailure> {
  const byId = new Map(checks.map(check => [check.id, check]));
  const resolved = new Map<string, AuthConformanceKnownFailure>();

  for (const entry of fixtures.knownFailures) {
    const check = byId.get(entry.check);
    if (check === undefined) {
      throw new TypeError(
        `describeAuthProvider: knownFailures names the check ${JSON.stringify(entry.check)}, which does ` +
          'not exist. An entry for a check that is not in the suite is never evaluated, so it would sit ' +
          'there granting cover that nothing ever re-examines - which is exactly what a recorded known ' +
          'failure is supposed not to be. If a check was renamed, the entry has to be renamed with it.\n' +
          `Closest ids: ${nearest(entry.check, [...byId.keys()]).join(', ')}\n` +
          `All ${byId.size} ids: ${[...byId.keys()].join(', ')}`,
      );
    }
    if (!check.failureCodes.includes(entry.code)) {
      throw new TypeError(
        `describeAuthProvider: knownFailures records the code ${JSON.stringify(entry.code)} for ` +
          `${JSON.stringify(entry.check)}, and that check cannot produce it. A code names one of the ways ` +
          'a check goes red; an unproduceable one can never match, so the entry would never cover the ' +
          'failure it was written for and the suite would stay red with nobody able to see why.\n' +
          `Codes ${JSON.stringify(entry.check)} can produce:\n` +
          check.failureCodes.map(code => `  ${code}`).join('\n'),
      );
    }
    resolved.set(entry.check, entry);
  }
  return resolved;
}

// ============================================================================
// Internals: reporting
// ============================================================================

/** Render a value for an OBSERVED line: short, unambiguous, never a stack trace. */
function show(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (value === null) return 'null';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'bigint') return `${value}n`;
  if (typeof value === 'function') return `[function ${value.name || 'anonymous'}]`;
  if (value instanceof Error) return `${value.name}: ${value.message}`;
  try {
    const json = JSON.stringify(value);
    if (typeof json !== 'string') return Object.prototype.toString.call(value);
    return json.length > 300 ? `${json.slice(0, 297)}...` : json;
  } catch {
    return Object.prototype.toString.call(value);
  }
}

/**
 * Fail a check with the package's standard message.
 *
 * Routed through `expect.fail` rather than `throw new Error` so vitest reports
 * it as an assertion rather than as a crash in the suite itself, which is the
 * difference between "your provider is wrong" and "the conformance suite is
 * broken" in a CI summary.
 *
 * `code` is required here and optional on the published
 * {@link ConformanceFailure}. Requiring it at the call site is the whole
 * enforcement: a new way for a check to go red does not compile until it has
 * been named, and a `knownFailures` entry can only ever be as specific as the
 * names that exist. The assertion carries the code as a property as well as in
 * its text, so the runner reads it structurally instead of parsing prose that
 * this package's semver policy allows to be reworded in a patch.
 */
function fail(fixtures: Fixtures, failure: Omit<ConformanceFailure, 'provider' | 'code'> & { code: string }): never {
  try {
    expect.fail(formatConformanceFailure({ provider: fixtures.name, ...failure }));
  } catch (error) {
    throw attachFailureCode(error, failure.code);
  }
}

// ============================================================================
// Internals: the network stub
// ============================================================================

/** Text that identifies the suite's own stubbed transport wherever it surfaces. */
const TOKEN_EXCHANGE_MARKER = '[factory-auth conformance] the token exchange left the process';

/** Thrown by the stubbed `fetch`. Its presence is the evidence the check reads. */
class TokenExchangeReached extends Error {
  constructor() {
    super(TOKEN_EXCHANGE_MARKER);
    this.name = 'TokenExchangeReached';
  }
}

/**
 * Run `body` with `globalThis.fetch` replaced by one that always throws
 * {@link TokenExchangeReached}, and restore it afterwards.
 *
 * Two jobs, and the second is the one that matters. It keeps the suite offline
 * even if a provider would otherwise dial out - the header promises no network,
 * and a promise that depends on the provider being well-behaved is not one. And
 * it turns "reached the token exchange" into an observable event, which is the
 * only offline way to tell a provider that accepted the host's `state` from one
 * that rejected it before doing anything.
 *
 * The swap is a global mutation, so it is deliberately as small as it can be:
 * one call, restored in `finally`, never spanning an `await` the caller does not
 * control. Do not run the suite with `describe.concurrent`.
 */
async function withoutNetwork<T>(body: (calls: { count: number }) => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  // Counted, not just thrown. Whether the stub was reached at all is the one
  // piece of first-hand evidence available about how far a provider got, and
  // the callback check needs it: an error is what the provider chose to throw,
  // while a call to this is something the suite watched happen.
  const calls = { count: 0 };
  globalThis.fetch = (() => {
    calls.count += 1;
    throw new TokenExchangeReached();
  }) as typeof fetch;
  try {
    return await body(calls);
  } finally {
    globalThis.fetch = original;
  }
}

/**
 * Did this error come from the stubbed transport?
 *
 * Walks the `cause` chain, because a provider that wraps the failure of its
 * token exchange in its own error is doing the right thing and must not be
 * punished for it. Bounded, because a cause chain can be cyclic.
 */
function isTokenExchangeError(error: unknown): boolean {
  let cursor: unknown = error;
  for (let depth = 0; cursor !== null && cursor !== undefined && depth < 8; depth += 1) {
    if (cursor instanceof TokenExchangeReached) return true;
    const message: unknown = (cursor as { message?: unknown }).message;
    if (typeof message === 'string' && message.includes(TOKEN_EXCHANGE_MARKER)) return true;
    cursor = (cursor as { cause?: unknown }).cause;
  }
  return false;
}

// ============================================================================
// Internals: shared steps
// ============================================================================

/**
 * A request with the given headers, against the configured URL.
 *
 * A plain `Request`, deliberately, rather than the minimal `{ headers }` a
 * provider might get away with in its own unit tests. `MastraAuthRequest` covers
 * both, and a provider that only handles the object shape would pass its own
 * suite and fail under a host.
 */
function requestWith(fixtures: Fixtures, headers: Record<string, string> = {}): Request {
  return new Request(fixtures.requestUrl, { headers });
}

/** What a call did: resolved with a value, or rejected with an error. */
type Outcome<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: unknown };

const NOOP = (): void => {};

/** Whether a value is Promise-like, without awaiting it. */
function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    (typeof value === 'object' && value !== null && typeof (value as PromiseLike<unknown>).then === 'function') ||
    (typeof value === 'function' && typeof (value as unknown as PromiseLike<unknown>).then === 'function')
  );
}

async function settle<T>(body: () => Promise<T> | T): Promise<Outcome<T>> {
  try {
    return { ok: true, value: await body() };
  } catch (error) {
    return { ok: false, error };
  }
}

/**
 * The `state` this provider's own authorization URL carries, or `null`.
 *
 * Used by `sso/pkce-round-trip` to play the identity provider rather than the
 * host. An identity provider echoes back the `state` it was *sent*, which is
 * whatever `getLoginUrl` put in the query string - not necessarily what the host
 * minted. For a provider that meets obligation 3 those are the same string, so
 * this changes nothing; for one that re-encodes `state` it is the difference
 * between asking about the cookie and re-asking obligation 3's question under a
 * second name.
 */
function echoedState(loginUrl: unknown): string | null {
  try {
    return new URL(loginUrl as string).searchParams.get('state');
  } catch {
    // A login URL that does not parse is `obligation/stateCodec/login-url`'s
    // finding, reported there. Here it just means there is no echo to read, and
    // the caller falls back to the state the host minted.
    return null;
  }
}

/**
 * The `Cookie` header a browser would send back, from the `Set-Cookie` values a
 * provider handed out at login. `null` when none of them names a cookie.
 *
 * A browser keeps the `name=value` pair and drops the attributes, so that is
 * what this keeps. What it deliberately does not model is a browser's storage
 * rules - `Domain`, `Path`, `Secure`, and an already-elapsed `Max-Age` are all
 * ignored, so a provider gets its own cookie back under the most favourable
 * conditions available. Being generous here is the right direction: this check
 * exists to catch a value that cannot survive the trip at all, and a red that
 * depended on the suite's cookie-jar emulation would be a red about the suite.
 */
function toCookieHeader(setCookieValues: readonly string[]): string | null {
  const pairs: string[] = [];
  for (const value of setCookieValues) {
    const pair = (value.split(';', 1)[0] ?? '').trim();
    // `>0` rather than `>=0`: a leading `=` is a cookie with no name, which is
    // not a pair a browser would send back.
    if (pair.indexOf('=') > 0) pairs.push(pair);
  }
  return pairs.length === 0 ? null : pairs.join('; ');
}

/**
 * Do what a browser does between login and callback: carry the cookies
 * `getLoginCookies` set back to the provider through `setCallbackCookieHeader`.
 *
 * Best-effort, and silent about everything. It exists so that a check whose
 * subject is NOT the cookie can still ask its own question of a provider that
 * needs one. Before this, a correct PKCE provider - one that stashes a code
 * verifier at login and requires it at the callback - failed
 * `obligation/stateCodec/callback` and was told it had "rejected a state its own
 * getLoginUrl was just handed", about a call that never reached the `state` at
 * all. A false red that reads exactly like a true one is the outcome this
 * package exists to prevent, and the suite was producing one the moment PKCE
 * became implementable.
 *
 * Nothing here fails: a throw from either half, a return value that is not a
 * list of cookies, a provider with no read side. All of those are
 * `sso/pkce-round-trip`'s findings, reported there once, with a diagnosis. Here
 * they are simply the absence of a cookie to hand back.
 *
 * @returns the `Cookie` header that was handed over, or `null` when there was
 * none to hand or nowhere to hand it.
 */
async function handBackLoginCookies(
  provider: IMastraAuthProvider,
  redirectUri: string,
  state: string,
): Promise<string | null> {
  const sso = provider as {
    getLoginCookies?: (redirectUri: string, state: string) => unknown;
    setCallbackCookieHeader?: (cookieHeader: string | null) => void;
  };
  if (typeof sso.getLoginCookies !== 'function' || typeof sso.setCallbackCookieHeader !== 'function') return null;

  const written = await settle(() => sso.getLoginCookies?.(redirectUri, state));
  if (!written.ok || !Array.isArray(written.value)) return null;
  const values = written.value.filter((entry): entry is string => typeof entry === 'string');
  const cookieHeader = toCookieHeader(values);
  if (cookieHeader === null) return null;

  const fed = await settle(() => sso.setCallbackCookieHeader?.(cookieHeader));
  return fed.ok ? cookieHeader : null;
}

/**
 * The OBSERVED line saying the browser's half of the trip was performed, when it
 * was.
 *
 * Present so that a reader of an obligation-3 failure can see the suite did hand
 * the login cookies back, and rule the cookie out before going looking for it.
 */
function loginCookiesNote(cookieHeader: string | null): string[] {
  if (cookieHeader === null) return [];
  return [
    'The cookies getLoginCookies set were handed back through setCallbackCookieHeader first,',
    `the way a browser would: Cookie: ${cookieHeader}`,
  ];
}

/**
 * Authenticate with the configured token, or fail with a message about the
 * fixture rather than about the provider.
 *
 * Most checks need an authenticated payload before they can ask their own
 * question, so a rejected `token` fixture would otherwise surface as four
 * unrelated failures none of which mentions the token. It surfaces as this
 * instead.
 */
async function authenticated(provider: IMastraAuthProvider, fixtures: Fixtures): Promise<unknown> {
  const outcome = await settle(() => provider.authenticateToken(fixtures.token, requestWith(fixtures)));
  if (!outcome.ok) {
    fail(fixtures, {
      code: `${AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX}token-threw`,
      headline: 'authenticateToken threw for the token this suite was told the provider accepts.',
      observed: [
        `authenticateToken(${show(fixtures.token)}, request) threw.`,
        `  ${show(outcome.error)}`,
        `  request: GET ${fixtures.requestUrl}, no headers`,
      ],
      why:
        'The suite hands this token to almost every check, so a provider that cannot accept it here\n' +
        'cannot be asked anything else. A throw in particular is not the contract: `authenticateToken`\n' +
        'is declared to resolve to a user or to null, and a host that has to catch it will catch it\n' +
        'once, log it, and answer 401 with no further detail.',
      how:
        'Two possibilities, and they need different fixes.\n' +
        '\n' +
        'If the throw is a network call, the provider `createProvider` returned is not offline.\n' +
        'Conformance runs with no identity provider: inject your verifier, subclass, or stub the SDK\n' +
        'inside the factory.\n' +
        '\n' +
        'If the throw is deliberate - a malformed token, an unknown key id - return null instead.\n' +
        'Rejection is a normal outcome on a public endpoint and should not be exceptional.',
    });
  }
  if (outcome.value === null || outcome.value === undefined) {
    fail(fixtures, {
      code: `${AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX}token-rejected`,
      headline: 'authenticateToken rejected the token this suite was told the provider accepts.',
      observed: [
        `authenticateToken(${show(fixtures.token)}, request) resolved to ${show(outcome.value)}.`,
        `  request: GET ${fixtures.requestUrl}, no headers`,
      ],
      why:
        'The `token` option is the fixture every other check is built on: it is how the suite gets an\n' +
        'authenticated payload to ask questions about. Nothing downstream of it can be trusted while\n' +
        'it is rejected.',
      how:
        'Check that `token` names a value the provider `createProvider` returns actually accepts, with\n' +
        'no network available. If your provider only accepts tokens it can verify against a live\n' +
        'issuer, give the factory a stubbed verifier and hand this option a token that verifier\n' +
        'accepts.',
    });
  }
  return outcome.value;
}

/** The identity behind the configured token, or `null` when none resolves. */
async function identityOf(provider: IMastraAuthProvider, fixtures: Fixtures): Promise<AuthIdentity | null> {
  return toAuthIdentity(await authenticated(provider, fixtures), provider);
}

/**
 * The user id later checks need, from the caller's fixture or from the provider.
 *
 * Prefers {@link AuthProviderConformanceOptions.userId} so that a provider
 * failing obligation 1 still gets a straight answer on obligation 4 instead of a
 * cascade.
 */
async function userIdOf(provider: IMastraAuthProvider, fixtures: Fixtures): Promise<string> {
  if (fixtures.userId !== undefined && fixtures.userId !== '') return fixtures.userId;
  const identity = await identityOf(provider, fixtures);
  if (identity !== null) return identity.id;
  fail(fixtures, {
    code: `${AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX}user-id-unavailable`,
    headline: 'This check needs a user id, and neither the options nor authenticateToken supplied one.',
    observed: [
      'The `userId` option was not set.',
      `toAuthIdentity(authenticateToken(${show(fixtures.token)}, request)) resolved to null.`,
    ],
    why:
      'Some checks - resolving an organization, in particular - take a user id as an argument. With no\n' +
      '`userId` option the suite has to read one back out of `authenticateToken`, and a provider that\n' +
      'fails obligation 1 has none to give.',
    how:
      'Fix obligation 1, or set the `userId` option to the id this token belongs to. Setting it is\n' +
      'worth doing either way: it keeps one broken obligation reporting one failure.',
  });
}

// ============================================================================
// Internals: the gates
// ============================================================================

/** Always applies. The base contract, and the obligations everybody owes. */
const ALWAYS = (): null => null;

function requiresSSO(provider: IMastraAuthProvider): string | null {
  return isSSOProvider(provider)
    ? null
    : 'This provider declares no hosted login (isSSOProvider is false), so it has no authorization ' +
        'URL and no OAuth `state` to agree about. Implement ISSOProvider and this check applies.';
}

/**
 * The reason a gate gives up, when reading the provider is what broke.
 *
 * A gate runs before the check body, with nothing around it, so a provider whose
 * property read throws - a getter with side effects is the realistic case - used
 * to surface a raw `Error` from the gate instead of a diagnosis. Two checks did
 * that, and neither of them is the check whose job it is to report it:
 * `contract/descriptor` exists for exactly this and says what to do about it.
 *
 * So a gate that cannot decide skips and points there. Skipping is honest -
 * whether the check applies is genuinely unknown - and it leaves one clear
 * failure in the run rather than three, two of which name the wrong thing.
 */
function unreadable(what: string, error: unknown): string {
  return (
    `This check could not tell whether it applies: reading ${what} on the provider threw ` +
    `(${show(error)}). A property read is not supposed to have side effects. See the ` +
    '`contract/descriptor` check in this same run, which reports this properly and says how to fix it.'
  );
}

function requiresBrowserSession(provider: IMastraAuthProvider): string | null {
  let logout: boolean;
  try {
    logout = toAuthDescriptor(provider).features.logout;
  } catch (error) {
    return unreadable('the capability methods that make up the descriptor', error);
  }
  return logout
    ? null
    : 'This provider cannot put a session in a browser: no hosted login, no credentials sign-in, no ' +
        'server-side sessions, and no auth routes of its own. A browser never holds a cookie for it, ' +
        'so there is no cookie for authenticateToken to read. It is a bearer-token validator, which ' +
        'is a supported shape.';
}

function requiresCredentials(provider: IMastraAuthProvider): string | null {
  let credentials: boolean;
  try {
    credentials = isCredentialsProvider(provider);
  } catch (error) {
    return unreadable('`signIn`', error);
  }
  return credentials ? null : 'This provider declares no credentials sign-in (isCredentialsProvider is false).';
}

function requiresSessions(provider: IMastraAuthProvider): string | null {
  return isSessionProvider(provider)
    ? null
    : 'This provider declares no server-side sessions (isSessionProvider is false).';
}

function requiresUsers(provider: IMastraAuthProvider): string | null {
  return isUserProvider(provider)
    ? null
    : 'This provider offers no user directory (isUserProvider is false), so nothing asks it who is ' +
        'signed in and nothing looks a user up by id. Implement IUserProvider - `getCurrentUser` and ' +
        '`getUser` - and these checks apply.';
}

function requiresOrganizations(provider: IMastraAuthProvider): string | null {
  return isOrganizationsProvider(provider)
    ? null
    : 'This provider resolves no organizations (isOrganizationsProvider is false), so it has no ' +
        'administrator question to answer. `obligation/organizationId/declared` in this same run is ' +
        'where that absence is reported; it is deliberately not skipped, and this check is not the ' +
        'place to report it a second time.';
}

function requiresHttpHandler(provider: IMastraAuthProvider): string | null {
  return isAuthHttpHandler(provider)
    ? null
    : 'This provider serves no auth routes of its own (isAuthHttpHandler is false).';
}

function requiresInit(provider: IMastraAuthProvider): string | null {
  return hasAuthInit(provider) ? null : 'This provider has no one-time init hook (hasAuthInit is false).';
}

// ============================================================================
// The checks
// ============================================================================

const SECTION_CONTRACT = 'the base contract';
const SECTION_SSO = 'hosted login (ISSOProvider)';
const SECTION_CREDENTIALS = 'credentials (ICredentialsProvider)';
const SECTION_USERS = 'users (IUserProvider)';
const SECTION_ORGANIZATIONS = 'organizations (IOrganizationsProvider)';
const SECTION_SESSIONS = 'server-side sessions (ISessionProvider)';
const SECTION_ROUTES = 'auth routes (IAuthHttpHandler)';
const SECTION_INIT = 'initialization (IAuthInit)';

/** `obligation 2 of 4 - cookieAuth`, from the one source that numbers them. */
function obligationSection(obligation: AuthObligation): string {
  const { ordinal } = AUTH_OBLIGATION_GUIDANCE[obligation];
  return `obligation ${ordinal} of ${AUTH_OBLIGATION_COUNT} - ${obligation}`;
}

/**
 * Every check, in the order they are registered.
 *
 * Built per call rather than declared once, because each one closes over the
 * caller's fixtures - the token, the cookie header, the redirect URI - and a
 * shared list would have to take them as a second argument everywhere.
 *
 * @param options See {@link AuthProviderConformanceOptions}.
 * @throws TypeError when a required option is missing or empty. That is a
 * mistake in the calling test file rather than in the provider, so it fails at
 * registration time, before any suite exists to report it as a provider defect.
 */
export function authConformanceChecks(options: AuthProviderConformanceOptions): readonly AuthConformanceCheck[] {
  const fixtures = readFixtures(options);
  const built = buildChecks(fixtures);
  const knownFailures = resolveKnownFailures(fixtures, built);

  return built.map(check => ({
    ...check,
    knownFailure: knownFailures.get(check.id) ?? null,
    // Every gate gets the backstop, not just the runner.
    //
    // A gate runs before the check body with nothing around it, so a provider
    // whose property read throws - a getter with side effects is the realistic
    // case - would surface a raw error from whichever gate happened to touch it
    // first. `requiresBrowserSession` and `requiresCredentials` catch that
    // themselves and name the read that broke; this covers the gates that
    // inspect an optional method inline. Either way the run ends with one honest
    // failure from `contract/descriptor` rather than several naming the wrong
    // thing. Wrapping here rather than in `describeAuthProvider` means an
    // adapter that walks these checks itself behaves the same way.
    skipReason(provider) {
      try {
        return check.skipReason(provider);
      } catch (error) {
        return unreadable('a capability method', error);
      }
    },
  }));
}

function buildChecks(fixtures: Fixtures): readonly Omit<AuthConformanceCheck, 'knownFailure'>[] {
  return [
    // ------------------------------------------------------------------
    // The base contract
    // ------------------------------------------------------------------
    {
      id: 'contract/shape',
      section: SECTION_CONTRACT,
      title: 'implements IMastraAuthProvider',
      obligation: null,
      failureCodes: ['contract/shape#missing-required-member'],
      skipReason: ALWAYS,
      async run(provider) {
        const problems: string[] = [];
        if (typeof provider.authenticateToken !== 'function') {
          problems.push(`provider.authenticateToken is ${show(provider.authenticateToken)}, not a function.`);
        }
        if (typeof provider.authorizeUser !== 'function') {
          problems.push(`provider.authorizeUser is ${show(provider.authorizeUser)}, not a function.`);
        }
        if (provider.name !== undefined && typeof provider.name !== 'string') {
          problems.push(`provider.name is ${show(provider.name)}, which is neither a string nor absent.`);
        }
        if (problems.length === 0) return;
        fail(fixtures, {
          code: 'contract/shape#missing-required-member',
          headline: 'This is not a provider: the two required members of IMastraAuthProvider are not both present.',
          observed: problems,
          why:
            'Everything else in this suite, and everything the host does, is built on these two methods.\n' +
            'The seven capability guards are structural and would happily report capabilities on an\n' +
            'object that cannot authenticate anybody.',
          how:
            `Extend \`MastraAuthProvider\`, which ${KIT_PACKAGE_NAME}/contract re-exports, and implement\n` +
            '`authenticateToken(token, request)` and `authorizeUser(user, request)`. A plain object with\n' +
            'those two methods is also a provider - the contract is structural - but the base class\n' +
            'carries the option plumbing hosts expect.',
        });
      },
    },
    {
      id: 'contract/descriptor',
      section: SECTION_CONTRACT,
      title: 'derives a capability descriptor a UI can render',
      obligation: null,
      failureCodes: ['contract/descriptor#threw'],
      skipReason: ALWAYS,
      async run(provider) {
        const outcome = await settle(() => toAuthDescriptor(provider));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'contract/descriptor#threw',
            headline: 'toAuthDescriptor threw while inspecting this provider.',
            observed: [`toAuthDescriptor(provider) threw.`, `  ${show(outcome.error)}`],
            why:
              'The descriptor is what the sign-in screen renders from, and it is documented as pure and\n' +
              'never-throwing. It only ever calls one provider method - `isSignUpEnabled` - and swallows a\n' +
              'throw from it, so reaching this message means something else on the provider threw while\n' +
              'merely being read: a getter with side effects, or a Proxy.',
            how: 'Make property reads on your provider inert. Move work into the methods that do it.',
          });
        }
        // Bare `expect`, and deliberately still bare. Every field below is
        // derived by `toAuthDescriptor` from boolean guards rather than read off
        // the provider, so none of these can fire for any provider that can be
        // built - they are a tripwire on this package, not a claim about the one
        // under test. That is also why they carry no failure code and are not in
        // `failureCodes`: a `knownFailures` entry can only name a code, so
        // leaving these uncoded is what stops a provider from ever recording
        // "the descriptor reader is broken" as an exemption it is owed.
        const descriptor = outcome.value;
        expect(['hosted', 'credentials', 'both', 'none']).toContain(descriptor.signIn.kind);
        expect(typeof descriptor.features.logout).toBe('boolean');
        expect(typeof descriptor.features.organizations).toBe('boolean');
      },
    },
    {
      id: 'contract/rejects-unknown-token',
      section: SECTION_CONTRACT,
      title: 'resolves null for a token it does not know',
      obligation: null,
      failureCodes: ['contract/rejects-unknown-token#threw', 'contract/rejects-unknown-token#accepted-unknown-token'],
      skipReason: ALWAYS,
      async run(provider) {
        const outcome = await settle(() => provider.authenticateToken(fixtures.rejectedToken, requestWith(fixtures)));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'contract/rejects-unknown-token#threw',
            headline: 'authenticateToken threw for an unknown token instead of resolving null.',
            observed: [
              `authenticateToken(${show(fixtures.rejectedToken)}, request) threw.`,
              `  ${show(outcome.error)}`,
            ],
            why:
              'An unknown token is the ordinary state of a public endpoint - a stale tab, a bookmark, a\n' +
              'scanner. The contract declares `Promise<TUser | null>`, so a host treats a throw as a bug\n' +
              'rather than as a rejection: it logs a stack trace per unauthenticated request and answers\n' +
              '401 with nothing useful in it.',
            how: 'Catch verification failures in `authenticateToken` and `return null`.',
          });
        }
        if (outcome.value !== null && outcome.value !== undefined) {
          fail(fixtures, {
            code: 'contract/rejects-unknown-token#accepted-unknown-token',
            headline: 'authenticateToken accepted a token it should not recognize.',
            observed: [
              `authenticateToken(${show(fixtures.rejectedToken)}, request) resolved to ${show(outcome.value)}.`,
              `  request: GET ${fixtures.requestUrl}, no headers`,
            ],
            why:
              'A provider that authenticates an arbitrary string authenticates everybody. This is the one\n' +
              'check in the suite whose failure is a security finding rather than an integration defect.',
            how:
              'Verify the token before returning a payload. If `conformance-rejected-token` is somehow\n' +
              'meaningful to your provider, set the `rejectedToken` option to a string that is not.',
          });
        }
      },
    },
    {
      id: 'contract/rejects-anonymous-request',
      section: SECTION_CONTRACT,
      title: 'authenticates nobody when there is no token and no cookie',
      obligation: null,
      failureCodes: ['contract/rejects-anonymous-request#authenticated-anonymous'],
      skipReason: ALWAYS,
      async run(provider) {
        // A throw is not an authentication, and `contract/rejects-unknown-token`
        // already owns the "reject without throwing" claim. This check is only
        // about the one outcome that is a security finding.
        const outcome = await settle(() => provider.authenticateToken('', requestWith(fixtures)));
        if (outcome.ok && outcome.value !== null && outcome.value !== undefined) {
          fail(fixtures, {
            code: 'contract/rejects-anonymous-request#authenticated-anonymous',
            headline: 'authenticateToken authenticated a request carrying no credentials at all.',
            observed: [
              `authenticateToken("", request) resolved to ${show(outcome.value)}.`,
              `  request: GET ${fixtures.requestUrl}, no Authorization header, no Cookie header`,
            ],
            why:
              'The empty token is how the host says "this request carried no bearer token". Obligation 2\n' +
              'asks you to look at the Cookie header when you see it - not to treat it as a pass. A\n' +
              'provider that returns a user here authenticates every anonymous request in the deployment.',
            how:
              'When `token` is empty and the request carries no session cookie you recognize, `return null`.\n' +
              'The two rules compose: read the cookie, and if there is nothing to read, reject.',
          });
        }
      },
    },
    {
      id: 'contract/authorize-user',
      section: SECTION_CONTRACT,
      title: 'authorizeUser answers a boolean for an authenticated payload',
      obligation: null,
      failureCodes: ['contract/authorize-user#threw', 'contract/authorize-user#not-a-boolean'],
      skipReason: ALWAYS,
      async run(provider) {
        const payload = await authenticated(provider, fixtures);
        const outcome = await settle(() => provider.authorizeUser(payload, requestWith(fixtures)));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'contract/authorize-user#threw',
            headline: 'authorizeUser threw for a payload its own authenticateToken produced.',
            observed: [`authorizeUser(payload, request) threw.`, `  ${show(outcome.error)}`],
            why:
              'Authorization runs on every request to a protected path. A throw there is an unhandled\n' +
              'error rather than a denial, so the host cannot tell a refusal apart from a crash.',
            how: 'Return `false` to deny. Keep `authorizeUser` free of anything that can fail.',
          });
        }
        if (typeof outcome.value !== 'boolean') {
          fail(fixtures, {
            code: 'contract/authorize-user#not-a-boolean',
            headline: 'authorizeUser answered with something other than a boolean.',
            observed: [`authorizeUser(payload, request) resolved to ${show(outcome.value)}.`],
            why:
              'The contract declares `Promise<boolean> | boolean`. Anything else is read for truthiness by\n' +
              'whoever consumes it, and the values that go wrong there go wrong in the permissive\n' +
              'direction: an un-awaited Promise is truthy, so a provider that meant to deny allows.',
            how: 'Return `true` or `false`. If the answer needs a lookup, make the method `async`.',
          });
        }
        // Either answer is conforming. The suite asserts the shape of the answer,
        // never the policy: a provider that denies core routes by default is
        // making a deployment decision, not breaking a contract.
      },
    },
    {
      id: 'contract/map-user-to-resource-id',
      section: SECTION_CONTRACT,
      title: 'mapUserToResourceId agrees with the resolved identity',
      obligation: null,
      failureCodes: ['contract/map-user-to-resource-id#disagrees-with-identity'],
      skipReason: provider =>
        typeof provider.mapUserToResourceId === 'function'
          ? null
          : 'This provider does not implement the optional mapUserToResourceId.',
      async run(provider) {
        const payload = await authenticated(provider, fixtures);
        const identity = toAuthIdentity(payload, provider);
        const mapped = provider.mapUserToResourceId?.(payload);
        const expected = identity?.id;
        // `null` and `undefined` both mean "no resource id" on this method.
        const normalized = mapped === null ? undefined : mapped;
        if (normalized !== expected) {
          fail(fixtures, {
            code: 'contract/map-user-to-resource-id#disagrees-with-identity',
            headline: 'mapUserToResourceId and toAuthIdentity disagree about who this payload is.',
            observed: [
              `mapUserToResourceId(payload) returned ${show(mapped)}.`,
              `toAuthIdentity(payload, provider) resolved id ${show(expected)}.`,
            ],
            why:
              'These two answers key different halves of the same deployment. Memory resources are stored\n' +
              "under `mapUserToResourceId`'s answer, and everything else under the identity's `id`. When\n" +
              'they differ, one user has two identities and each half of the app can only see one of them\n' +
              '- with no error anywhere, because both halves are internally consistent.',
            how:
              'Return the same value the identity resolves to:\n' +
              '\n' +
              `  ${kitImport('{ toAuthIdentity }', '/identity')}\n` +
              '\n' +
              '  mapUserToResourceId(user) {\n' +
              '    return toAuthIdentity(user, this)?.id;\n' +
              '  }\n' +
              '\n' +
              'Or leave the method off entirely - it is optional, and the host falls back to the identity.',
          });
        }
      },
    },

    // ------------------------------------------------------------------
    // Obligation 1: a flat, resolvable id
    // ------------------------------------------------------------------
    {
      id: 'obligation/flatId',
      section: obligationSection('flatId'),
      title: 'authenticateToken resolves to an identity with a non-empty id',
      obligation: 'flatId',
      failureCodes: ['obligation/flatId#no-id-in-payload', 'obligation/flatId#wrong-user'],
      skipReason: ALWAYS,
      async run(provider) {
        const payload = await authenticated(provider, fixtures);
        const identity = toAuthIdentity(payload, provider);
        if (identity === null) {
          fail(fixtures, {
            code: 'obligation/flatId#no-id-in-payload',
            obligation: 'flatId',
            observed: [
              `authenticateToken(${show(fixtures.token)}, request) resolved to:`,
              `  ${show(payload)}`,
              'toAuthIdentity found no id in it, so this payload names nobody.',
              'It looks for `id`, then `uid`, then `sub`, at the top level - and inside `user` for a',
              '`{ session, user }` pair. A blank or whitespace-only value counts as absent.',
            ],
          });
        }
        if (fixtures.userId !== undefined && identity.id !== fixtures.userId) {
          fail(fixtures, {
            code: 'obligation/flatId#wrong-user',
            obligation: 'flatId',
            headline: 'authenticateToken resolved to a different user than the one this token belongs to.',
            observed: [
              `The \`userId\` option says this token belongs to ${show(fixtures.userId)}.`,
              `toAuthIdentity resolved ${show(identity.id)}.`,
              `The payload was: ${show(payload)}`,
            ],
            why:
              'The id is a storage key. Resolving the wrong field - a session id, a tenant id, an email -\n' +
              'is worse than resolving none: the request succeeds, and the data lands under a key that is\n' +
              "not that user's. `{ session, user }` payloads are where this happens, because the top level\n" +
              'carries a `session.id` that is not a user id.',
            how:
              'Check which field your payload puts the user id in. Precedence is `id`, then `uid`, then\n' +
              '`sub`, so a payload carrying both `id` and `sub` with different values resolves to `id`. If\n' +
              'the right value is somewhere else, implement `toIdentity` and say so explicitly.',
          });
        }
      },
    },

    // ------------------------------------------------------------------
    // Obligation 2: cookie-readable authenticateToken
    // ------------------------------------------------------------------
    {
      id: 'obligation/cookieAuth',
      section: obligationSection('cookieAuth'),
      title: 'authenticateToken reads the Cookie header when the bearer token is empty',
      obligation: 'cookieAuth',
      failureCodes: ['obligation/cookieAuth#cookie-not-read', 'obligation/cookieAuth#different-user'],
      skipReason: requiresBrowserSession,
      async run(provider) {
        if (fixtures.cookieHeader === undefined) {
          fail(fixtures, {
            code: 'fixture/cookie-header-missing',
            headline: 'This provider can put a session in a browser, so the suite needs its `cookieHeader` fixture.',
            observed: [
              `toAuthDescriptor(provider).features.logout is true, so obligation ` +
                `${AUTH_OBLIGATION_GUIDANCE.cookieAuth.ordinal} applies.`,
              'The `cookieHeader` option was not set, so there is no browser request to send.',
            ],
            why:
              'Obligation 2 is checked by sending a request that carries a session cookie and an empty\n' +
              'bearer token. Only you know which cookie your provider reads, and a suite that guessed a\n' +
              'name would report the guess missing as an obligation failure - a false red that looks\n' +
              'exactly like a true one.',
            how:
              'Pass the `Cookie` header a signed-in browser would send:\n' +
              '\n' +
              '  describeAuthProvider({\n' +
              '    // ...\n' +
              '    token: MY_TOKEN,\n' +
              '    cookieHeader: `my_provider_session=${MY_TOKEN}`,\n' +
              '  });\n' +
              '\n' +
              'If the host owns the cookie rather than your provider, `sessionCookieName(site)` from\n' +
              "'@mastra/factory-auth/cookie' gives you that name.",
          });
        }
        // The bearer path runs FIRST, and the order is the check.
        //
        // The failure below tells the reader "the credential is good and the
        // Cookie header is not being read". That is a claim about the bearer
        // path, and until it was made in front of a real provider nothing
        // established it: a provider that authenticates *nobody* - one that
        // failed to initialize is exactly that - reached the message and was
        // told its cookie parsing was at fault, which sends somebody to write
        // cookie parsing for a provider that never started. Going through
        // `authenticated` first reports that as the fixture problem it is, which
        // is the same job `authenticated` already does for every other check.
        const viaBearer = toAuthIdentity(await authenticated(provider, fixtures), provider)?.id;

        const request = requestWith(fixtures, { cookie: fixtures.cookieHeader });
        const outcome = await settle(() => provider.authenticateToken('', request));
        const value = outcome.ok ? outcome.value : null;
        if (!outcome.ok || value === null || value === undefined) {
          fail(fixtures, {
            code: 'obligation/cookieAuth#cookie-not-read',
            obligation: 'cookieAuth',
            observed: [
              `authenticateToken("", request) ${outcome.ok ? `resolved to ${show(value)}` : 'threw'}.`,
              outcome.ok ? `  request: GET ${fixtures.requestUrl}` : `  ${show(outcome.error)}`,
              `  Cookie: ${fixtures.cookieHeader}`,
              '',
              `The same credential authenticates as a bearer token: authenticateToken(${show(fixtures.token)},`,
              'request) resolves to a user. So the credential is good and the Cookie header is not being',
              'read.',
            ],
          });
        }
        // Compared against what the BEARER path resolves, never against the
        // `userId` fixture. A provider that fails obligation 1 resolves no
        // identity on either path, and this check must not report that as a
        // second, different defect - obligation 1 owns it.
        const viaCookie = toAuthIdentity(outcome.value, provider)?.id;
        if (viaBearer !== undefined && viaCookie !== viaBearer) {
          fail(fixtures, {
            code: 'obligation/cookieAuth#different-user',
            obligation: 'cookieAuth',
            headline: 'The cookie authenticated a different user than the bearer token did.',
            observed: [
              `Via the Cookie header, authenticateToken resolved id ${show(viaCookie)}.`,
              `Via the bearer token, it resolves id ${show(viaBearer)}.`,
              `  Cookie: ${fixtures.cookieHeader}`,
            ],
            why:
              'The two paths carry the same credential and must name the same person. When they diverge, a\n' +
              'browser session and an API token behave as two different accounts, and data written under\n' +
              'one is invisible to the other.',
            how:
              'Resolve the cookie to the same token you would have received as a bearer, then run the one\n' +
              'verification path over it. Two verification paths is how they drift.',
          });
        }
      },
    },

    // ------------------------------------------------------------------
    // Obligation 3: agreement with the kit's OAuth state codec
    // ------------------------------------------------------------------
    {
      id: 'obligation/stateCodec/login-url',
      section: obligationSection('stateCodec'),
      title: 'getLoginUrl echoes a state the kit codec can still read',
      obligation: 'stateCodec',
      failureCodes: [
        'obligation/stateCodec/login-url#threw',
        'obligation/stateCodec/login-url#not-an-absolute-url',
        'obligation/stateCodec/login-url#no-state-parameter',
        'obligation/stateCodec/login-url#state-not-round-tripped',
      ],
      skipReason: requiresSSO,
      async run(provider) {
        if (!isSSOProvider(provider)) return;
        const state = encodeState(CONFORMANCE_RETURN_TO, CONFORMANCE_STATE_ID);
        const outcome = await settle(() => provider.getLoginUrl(fixtures.redirectUri, state));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'obligation/stateCodec/login-url#threw',
            obligation: 'stateCodec',
            headline: 'getLoginUrl threw for a state in this package’s format.',
            observed: [`getLoginUrl(${show(fixtures.redirectUri)}, ${show(state)}) threw.`, `  ${show(outcome.error)}`],
          });
        }
        const loginUrl = outcome.value;
        let echoed: string | null;
        try {
          echoed = new URL(loginUrl).searchParams.get('state');
        } catch {
          fail(fixtures, {
            code: 'obligation/stateCodec/login-url#not-an-absolute-url',
            obligation: 'stateCodec',
            headline: 'getLoginUrl did not return an absolute URL.',
            observed: [`getLoginUrl(...) returned ${show(loginUrl)}, which does not parse as a URL.`],
            how:
              'Return an absolute URL. The host redirects the browser to this value verbatim, so a relative\n' +
              'path sends the person to a route on your own app rather than to the identity provider.',
          });
        }
        if (echoed === null) {
          fail(fixtures, {
            code: 'obligation/stateCodec/login-url#no-state-parameter',
            obligation: 'stateCodec',
            headline: 'getLoginUrl produced an authorization URL with no `state` parameter.',
            observed: [
              `getLoginUrl(${show(fixtures.redirectUri)}, ${show(state)}) returned:`,
              `  ${loginUrl}`,
              'It carries no `state` query parameter, so nothing comes back on the callback.',
            ],
          });
        }
        const id = parseStateId(echoed);
        const { returnTo } = decodeState(echoed);
        if (id !== CONFORMANCE_STATE_ID || returnTo !== CONFORMANCE_RETURN_TO) {
          fail(fixtures, {
            code: 'obligation/stateCodec/login-url#state-not-round-tripped',
            obligation: 'stateCodec',
            observed: [
              `The state handed to getLoginUrl was ${show(state)}.`,
              `The authorization URL carries       ${show(echoed)}.`,
              '',
              `parseStateId(echoed)         is ${show(id)}, expected ${show(CONFORMANCE_STATE_ID)}.`,
              `decodeState(echoed).returnTo is ${show(returnTo)}, expected ${show(CONFORMANCE_RETURN_TO)}.`,
              '',
              'The value was re-encoded on the way out, so the destination the host put in it does not',
              'survive the round trip.',
            ],
          });
        }
      },
    },
    {
      id: 'obligation/stateCodec/callback',
      section: obligationSection('stateCodec'),
      title: 'handleCallback accepts a state the host minted',
      obligation: 'stateCodec',
      failureCodes: [
        'obligation/stateCodec/callback#state-rejected',
        'obligation/stateCodec/callback#threw-without-cause-after-token-exchange',
      ],
      skipReason: requiresSSO,
      async run(provider) {
        if (!isSSOProvider(provider)) return;
        const state = encodeState(CONFORMANCE_RETURN_TO, CONFORMANCE_STATE_ID);

        // Counted across `handleCallback` alone. `getLoginUrl` runs inside the
        // same stub and a provider is entitled to dial out there - fetching a
        // discovery document is the ordinary case - so counting from zero at the
        // callback is what keeps "it reached the token exchange" a claim about
        // the call this check is actually asking about.
        let callsDuringCallback = 0;
        let handedBack: string | null = null;
        const outcome = await withoutNetwork(async calls => {
          // The login half runs first and inside the same stub, because a
          // provider that keeps a state store fills it here. Skipping it would
          // ask the callback about a state that was never minted, which every
          // correct provider is entitled to reject.
          await settle(() => provider.getLoginUrl(fixtures.redirectUri, state));
          // And the browser's half of the same trip, for the same reason. A
          // provider that stashed a PKCE verifier in a login cookie needs it
          // back before it can get as far as looking at the `state`; without
          // this it throws for the missing verifier and is told, wrongly, that
          // it rejected the host's state. Whether the cookie loop itself works
          // is `sso/pkce-round-trip`'s question, not this one's.
          handedBack = await handBackLoginCookies(provider, fixtures.redirectUri, state);
          const before = calls.count;
          const settled = await settle(() => provider.handleCallback(fixtures.code, state));
          callsDuringCallback = calls.count - before;
          return settled;
        });

        // Resolving is conforming: the provider completed a callback with no
        // network at all, which a provider holding a local key set can do.
        if (outcome.ok) return;
        if (isTokenExchangeError(outcome.error)) return;
        if (fixtures.reachedTokenExchange?.(outcome.error) === true) return;

        // Two different failures, told apart by evidence rather than by
        // inference, and separating them is a fix for a real misdiagnosis.
        //
        // The recognizer above walks the `cause` chain, which is the strongest
        // signal there is and the one a provider earns by wrapping the transport
        // failure properly. A provider that catches the transport failure and
        // rethrows a flat error of its own - `Error('Session validation failed')`
        // with no `cause` - defeats it, and this check used to answer that with
        // "handleCallback rejected a state its own getLoginUrl was just handed".
        // That is a sentence about `state`, and it was said about a method whose
        // `state` parameter is named `_state` and never read. A false red that
        // reads exactly like a true one is the specific outcome this package
        // exists to prevent, so it is not left standing.
        //
        // What is NOT done here is to treat "fetch was called" as conforming.
        // Widening the pass condition would let a provider that dials out before
        // validating `state` - discovery first, then reject - go green on a check
        // it fails, and a silent false green is worse than a loud wrong reason.
        // So the check keeps its teeth: still red, with the diagnosis the
        // evidence supports and the two fixes that actually apply. Going green
        // stays behind `sso.reachedTokenExchange`, where a reviewer can see it.
        if (callsDuringCallback > 0) {
          fail(fixtures, {
            code: 'obligation/stateCodec/callback#threw-without-cause-after-token-exchange',
            obligation: 'stateCodec',
            headline: 'handleCallback reached the token exchange and then threw an error that hides why.',
            observed: [
              `getLoginUrl(${show(fixtures.redirectUri)}, state) ran first, with state = ${show(state)}.`,
              ...loginCookiesNote(handedBack),
              `handleCallback(${show(fixtures.code)}, state) called globalThis.fetch ${callsDuringCallback} time(s),`,
              'so it accepted the state and got as far as the token exchange. It then threw:',
              `  ${show(outcome.error)}`,
              '',
              'The suite replaced globalThis.fetch with one that throws a recognizable error, and that',
              'error is not in this one’s `cause` chain - so the provider caught the transport failure',
              'and rethrew something of its own that does not carry it.',
              '',
              'This is a diagnosis problem, not necessarily a `state` problem. The suite can see that the',
              'state was accepted; it cannot see whether what followed was a real defect.',
            ],
            why:
              'Swallowing the cause is what makes this unanswerable, in production as much as here. The\n' +
              'operator gets "Session validation failed" for an expired code, a clock skew, a wrong client\n' +
              'secret and an unreachable issuer alike, and every one of those needs a different fix. This\n' +
              'check is simply the first reader to be unable to tell them apart.',
            how:
              'Attach the original failure as the `cause`, which is one argument:\n' +
              '\n' +
              '  } catch (error) {\n' +
              "    throw new Error('Session validation failed', { cause: error });\n" +
              '  }\n' +
              '\n' +
              'That is worth doing on its own merits, and it makes this check pass: the recognizer walks\n' +
              'the `cause` chain and will find the transport failure at the end of it.\n' +
              '\n' +
              'If the error genuinely cannot carry a cause, pass `sso.reachedTokenExchange` and answer\n' +
              '`true` for what your transport throws. That is the same escape hatch a provider whose token\n' +
              'exchange does not go through global `fetch` uses, and it is visible in your options rather\n' +
              'than silent.',
          });
        }

        fail(fixtures, {
          code: 'obligation/stateCodec/callback#state-rejected',
          obligation: 'stateCodec',
          headline: 'handleCallback rejected a state its own getLoginUrl was just handed.',
          observed: [
            `getLoginUrl(${show(fixtures.redirectUri)}, state) ran first, with state = ${show(state)}.`,
            ...loginCookiesNote(handedBack),
            `handleCallback(${show(fixtures.code)}, state) then threw, before reaching the token exchange:`,
            `  ${show(outcome.error)}`,
            '',
            'The suite replaced globalThis.fetch for this call, and it was never called: handleCallback',
            'made no network attempt at all before throwing. So the provider stopped at the state rather',
            'than getting as far as the token exchange.',
            ...(handedBack === null
              ? []
              : [
                  '',
                  'This provider also carries a cookie across the login round trip, and one that cannot read',
                  'its own cookie back stops here too - before the state, with a message about the state.',
                  '`sso/pkce-round-trip` in this same run reports that loop on its own terms. Read it first.',
                ]),
          ],
          why:
            `${AUTH_OBLIGATION_GUIDANCE.stateCodec.why}\n` +
            '\n' +
            'The usual cause is a state store keyed on one substring and read with another: getLoginUrl\n' +
            'stores under `parseStateId(state)` while handleCallback looks up the whole value it was\n' +
            'handed, or the other way round. Every sign-in then fails with "invalid or expired state",\n' +
            'and nothing about that message points at the keying.',
          how:
            `${AUTH_OBLIGATION_GUIDANCE.stateCodec.how}\n` +
            '\n' +
            'If your token exchange does not go through global `fetch` - an SDK holding its own agent, or\n' +
            '`node:https` - this check cannot see it reach the network and will report that as a state\n' +
            'rejection. Pass `sso.reachedTokenExchange` to teach it what your transport throws when it\n' +
            'cannot reach the issuer.',
        });
      },
    },

    // ------------------------------------------------------------------
    // Obligation 4: an organization id
    // ------------------------------------------------------------------
    {
      id: 'obligation/organizationId/declared',
      section: obligationSection('organizationId'),
      title: 'satisfies isOrganizationsProvider, on its own or through the wrapper',
      obligation: 'organizationId',
      failureCodes: ['obligation/organizationId/declared#not-declared'],
      skipReason: ALWAYS,
      async run(provider) {
        if (isOrganizationsProvider(provider)) return;
        fail(fixtures, {
          code: 'obligation/organizationId/declared#not-declared',
          obligation: 'organizationId',
          headline: 'This provider resolves no organization: isOrganizationsProvider(provider) is false.',
          observed: [
            'isOrganizationsProvider(provider) is false.',
            `  provider.ensureOrganization  is ${show((provider as { ensureOrganization?: unknown }).ensureOrganization)}`,
            `  provider.isOrganizationAdmin is ${show((provider as { isOrganizationAdmin?: unknown }).isOrganizationAdmin)}`,
            '',
            'This check is deliberately not skipped for a provider without organizations. Skipping it',
            'there would skip the only check that notices, which is how this obligation went unwritten',
            'for as long as it did.',
          ],
        });
      },
    },
    {
      id: 'obligation/organizationId/deterministic',
      section: obligationSection('organizationId'),
      title: 'ensureOrganization returns the same non-empty id on every call',
      obligation: 'organizationId',
      failureCodes: [
        'obligation/organizationId/deterministic#threw',
        'obligation/organizationId/deterministic#not-a-string',
        'obligation/organizationId/deterministic#not-deterministic',
      ],
      skipReason: ALWAYS,
      async run(provider) {
        if (!isOrganizationsProvider(provider)) {
          // The check above owns that failure; reporting it twice would make one
          // defect look like two.
          return;
        }
        const userId = await userIdOf(provider, fixtures);

        const first = await settle(() => provider.ensureOrganization(userId));
        if (!first.ok) {
          fail(fixtures, {
            code: 'obligation/organizationId/deterministic#threw',
            obligation: 'organizationId',
            headline: 'ensureOrganization threw instead of resolving an organization id.',
            observed: [`ensureOrganization(${show(userId)}) threw.`, `  ${show(first.error)}`],
            how:
              `${AUTH_OBLIGATION_GUIDANCE.organizationId.how}\n` +
              '\n' +
              'Wrapping also covers this case specifically: `withSyntheticOrganizations` treats a delegate\n' +
              'that throws as one that declined, and supplies the synthetic id, so a transient failure in\n' +
              'your organization lookup degrades to a private organization instead of failing the request.',
          });
        }
        const second = await settle(() => provider.ensureOrganization(userId));
        const one = first.value;
        const two = second.ok ? second.value : undefined;

        if (typeof one !== 'string' || one === '') {
          fail(fixtures, {
            code: 'obligation/organizationId/deterministic#not-a-string',
            obligation: 'organizationId',
            observed: [
              `ensureOrganization(${show(userId)}) resolved to ${show(one)}.`,
              'It has to resolve to a non-empty string. `undefined` is what the interface documents for a',
              'user who stays no-org, and it is exactly the answer a host cannot store.',
            ],
          });
        }
        if (one !== two) {
          fail(fixtures, {
            code: 'obligation/organizationId/deterministic#not-deterministic',
            obligation: 'organizationId',
            headline: 'ensureOrganization is not deterministic: two calls for one user gave two organizations.',
            observed: [
              `ensureOrganization(${show(userId)}) resolved to ${show(one)}.`,
              `ensureOrganization(${show(userId)}) resolved to ${show(two)} on the second call.`,
            ],
            why:
              'The interface requires idempotence under concurrent and retried first logins, and the host\n' +
              'relies on it harder than that: it calls this on sign-in, and every organization-scoped row\n' +
              'is written under whatever came back. An id that changes per call partitions one user\n' +
              "against themselves - yesterday's work is still there and they cannot see it, with no error\n" +
              'anywhere.',
            how:
              'Derive the id, or look it up and create only when it is missing. Do not generate one per\n' +
              'call. `withSyntheticOrganizations` derives `user:${userId}`, which is a pure function of\n' +
              'the user id and needs no store.',
          });
        }

        // The host-side resolver has to agree, because that is the path most
        // surfaces actually take: they hold an identity, not a provider.
        const identity = await identityOf(provider, fixtures);
        if (identity !== null) {
          const resolved = resolveOrganizationId(identity);
          expect(typeof resolved, 'resolveOrganizationId(identity) must answer a string').toBe('string');
          expect(resolved.length, 'resolveOrganizationId(identity) must not answer an empty string').toBeGreaterThan(0);
        }
      },
    },

    // ------------------------------------------------------------------
    // Declared capabilities
    // ------------------------------------------------------------------
    {
      id: 'sso/login-button',
      section: SECTION_SSO,
      title: 'getLoginButtonConfig describes a control a UI can draw',
      obligation: null,
      failureCodes: ['sso/login-button#threw', 'sso/login-button#not-renderable'],
      skipReason: requiresSSO,
      async run(provider) {
        if (!isSSOProvider(provider)) return;
        const outcome = await settle(() => provider.getLoginButtonConfig());
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'sso/login-button#threw',
            headline: 'getLoginButtonConfig threw.',
            observed: [`getLoginButtonConfig() threw.`, `  ${show(outcome.error)}`],
            why: 'The sign-in screen calls this to draw its one button. A throw there is a blank page.',
            how: 'Return a literal. This method should not do work.',
          });
        }
        const config = outcome.value;
        const problems: string[] = [];
        if (typeof config?.provider !== 'string' || config.provider === '') {
          problems.push(`config.provider is ${show(config?.provider)}, expected a non-empty string.`);
        }
        if (typeof config?.text !== 'string' || config.text === '') {
          problems.push(`config.text is ${show(config?.text)}, expected a non-empty string.`);
        }
        if (problems.length === 0) return;
        fail(fixtures, {
          code: 'sso/login-button#not-renderable',
          headline: 'getLoginButtonConfig returned a config a UI cannot render.',
          observed: [`getLoginButtonConfig() returned ${show(config)}.`, ...problems],
          why:
            '`text` is the label on the only control an unauthenticated person can reach. A blank one\n' +
            'renders an empty button, which is indistinguishable from a broken deployment.',
          how: "Return `{ provider: 'my-provider', text: 'Sign in with My Provider' }` at minimum.",
        });
      },
    },
    {
      id: 'sso/logout-url',
      section: SECTION_SSO,
      title: 'getLogoutUrl, when implemented, answers a URL or null',
      obligation: null,
      failureCodes: ['sso/logout-url#threw', 'sso/logout-url#not-an-absolute-url'],
      skipReason: provider =>
        isSSOProvider(provider) && typeof provider.getLogoutUrl === 'function'
          ? null
          : 'This provider does not implement the optional getLogoutUrl.',
      async run(provider) {
        if (!isSSOProvider(provider) || provider.getLogoutUrl === undefined) return;
        const outcome = await settle(() => provider.getLogoutUrl?.(fixtures.redirectUri, requestWith(fixtures)));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'sso/logout-url#threw',
            headline: 'getLogoutUrl threw.',
            observed: [`getLogoutUrl(${show(fixtures.redirectUri)}, request) threw.`, `  ${show(outcome.error)}`],
            why:
              'Sign-out runs this. A throw leaves the person signed in at the identity provider with the\n' +
              'host believing they signed out, so the next sign-in silently restores the old session.',
            how: 'Return `null` when there is no session to end, rather than throwing.',
          });
        }
        const url = outcome.value;
        if (url === null || url === undefined) return;
        if (typeof url !== 'string' || !URL.canParse(url)) {
          fail(fixtures, {
            code: 'sso/logout-url#not-an-absolute-url',
            headline: 'getLogoutUrl answered something that is not an absolute URL.',
            observed: [`getLogoutUrl(...) returned ${show(url)}.`],
            why: 'The host redirects the browser to this value verbatim.',
            how: 'Return an absolute URL, or `null` when the provider has no hosted logout for this session.',
          });
        }
      },
    },
    {
      id: 'sso/pkce-round-trip',
      section: SECTION_SSO,
      title: 'a cookie set at login comes back readable at the callback',
      obligation: null,
      failureCodes: [
        'sso/pkce-round-trip#login-cookies-threw',
        'sso/pkce-round-trip#not-cookie-headers',
        'sso/pkce-round-trip#no-read-side',
        'sso/pkce-round-trip#read-side-threw',
        'sso/pkce-round-trip#cookie-not-read-back',
      ],
      skipReason: provider => {
        const gate = requiresSSO(provider);
        if (gate !== null) return gate;
        return isSSOProvider(provider) && typeof provider.getLoginCookies === 'function'
          ? null
          : 'This provider sets no cookies at login (getLoginCookies is not implemented), so it carries ' +
              'nothing across the hosted-login round trip and has nothing to read back. A confidential ' +
              'client authenticating with `client_secret` is exactly that shape. Implement ' +
              '`getLoginCookies` - which is what a PKCE provider does with its code verifier - and this ' +
              'check applies.';
      },
      async run(provider) {
        if (!isSSOProvider(provider) || provider.getLoginCookies === undefined) return;
        const state = encodeState(CONFORMANCE_RETURN_TO, CONFORMANCE_STATE_ID);

        // The whole round trip runs inside the stub. Two reasons, and the second
        // is why the counter is read rather than only the error: a provider is
        // entitled to dial out during `getLoginUrl` - fetching a discovery
        // document is the ordinary case - and the header promises no network
        // either way; and "did `handleCallback` get as far as the token
        // exchange" is the one piece of first-hand evidence available about
        // whether the cookie arrived.
        await withoutNetwork(async calls => {
          const login = await settle(() => provider.getLoginUrl(fixtures.redirectUri, state));
          if (!login.ok) {
            // `obligation/stateCodec/login-url#threw` owns that failure, and
            // reporting it twice would make one defect look like two.
            return;
          }

          const written = await settle(() => provider.getLoginCookies?.(fixtures.redirectUri, state));
          if (!written.ok) {
            fail(fixtures, {
              code: 'sso/pkce-round-trip#login-cookies-threw',
              headline: 'getLoginCookies threw.',
              observed: [
                `getLoginUrl(${show(fixtures.redirectUri)}, state) ran first, with state = ${show(state)}.`,
                `getLoginCookies(${show(fixtures.redirectUri)}, state) then threw.`,
                `  ${show(written.error)}`,
              ],
              why:
                'The host calls this on the login redirect, immediately after `getLoginUrl`, and puts what\n' +
                'comes back on the response as `Set-Cookie`. A throw there is a 500 on the route the sign-in\n' +
                'button points at, so nobody can start a login at all.',
              how:
                'Return `undefined` when there is nothing to set, rather than throwing. Nothing that can fail\n' +
                'belongs here: mint the verifier inside `getLoginUrl` and hand the finished cookie back from\n' +
                'this method.',
            });
          }

          // Read as `unknown` on purpose. The declared return type is
          // `string[] | undefined`, and the point of the next few lines is the
          // provider that does not honour it.
          const returned: unknown = written.value;

          // Nothing was written, so there is nothing to read back and the check
          // is satisfied. This is a PASS rather than a skip, and the difference
          // is the skip rule in this module's header: the provider declared the
          // capability, so the check applies to it and did run. It simply found
          // no cookie to hold anybody to - which is the truthful answer for a
          // confidential client, and the shape four providers in this repository
          // ship today.
          if (returned === undefined || returned === null) return;

          if (!Array.isArray(returned) || returned.some(entry => typeof entry !== 'string')) {
            fail(fixtures, {
              code: 'sso/pkce-round-trip#not-cookie-headers',
              headline: 'getLoginCookies returned something that is not a list of Set-Cookie header values.',
              observed: [`getLoginCookies(${show(fixtures.redirectUri)}, state) returned ${show(returned)}.`],
              why:
                'The host appends each entry to the login redirect as one `Set-Cookie` header, verbatim.\n' +
                'Anything that is not a `name=value; attributes` string is either dropped by the browser or\n' +
                'sets a cookie under a name nothing reads - and either way the value never comes back, which\n' +
                'is a sign-in that fails at the callback for a reason the callback cannot see.',
              how:
                'Return an array of complete `Set-Cookie` header values:\n' +
                '\n' +
                '  return [`my_pkce_verifier=${verifier}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`];\n' +
                '\n' +
                'Return `undefined` when this login sets no cookie.',
            });
          }
          const setCookies = returned as readonly string[];
          if (setCookies.length === 0) return;

          const cookieHeader = toCookieHeader(setCookies);
          if (cookieHeader === null) {
            fail(fixtures, {
              code: 'sso/pkce-round-trip#not-cookie-headers',
              headline: 'getLoginCookies returned values that name no cookie.',
              observed: [
                `getLoginCookies(${show(fixtures.redirectUri)}, state) returned ${setCookies.length} value(s):`,
                ...setCookies.map(value => `  ${show(value)}`),
                'None of them starts with a `name=value` pair, so a browser would store nothing and send',
                'nothing back on the callback.',
              ],
              why:
                'A `Set-Cookie` header value is a `name=value` pair followed by attributes. A value made only\n' +
                'of attributes sets no cookie, so whatever the provider meant to carry across the round trip\n' +
                'is discarded by the browser before the callback happens.',
              how:
                'Put the pair first:\n' +
                '\n' +
                '  return [`my_pkce_verifier=${verifier}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`];',
            });
          }

          // The structural half of this check, and the one the doneWhen names.
          //
          // It is asked HERE rather than in the gate, and that placement is the
          // whole design. Gating on `setCallbackCookieHeader` would skip this
          // check for exactly the provider it exists to catch - the one that
          // writes a verifier and declares no way to read it - which is the
          // self-fulfilling gate obligation 4 avoids for the same reason. And it
          // is asked only once a cookie has actually been written, so a
          // confidential client that declares `getLoginCookies` and returns none
          // is not asked for a read side it has nothing to read.
          if (typeof provider.setCallbackCookieHeader !== 'function') {
            fail(fixtures, {
              code: 'sso/pkce-round-trip#no-read-side',
              headline: 'This provider writes a cookie at login and declares no way to read one back.',
              observed: [
                `getLoginCookies(${show(fixtures.redirectUri)}, state) returned ${setCookies.length} value(s):`,
                ...setCookies.map(value => `  ${show(value)}`),
                `A browser would send them back as: Cookie: ${cookieHeader}`,
                '',
                `provider.setCallbackCookieHeader is ${show(provider.setCallbackCookieHeader)}.`,
                '`handleCallback(code, state)` takes no request and no headers, so there is no other',
                'channel by which the callback request’s cookies could reach this provider.',
              ],
              why:
                '`getLoginCookies` and `setCallbackCookieHeader` are the two halves of one loop. A PKCE\n' +
                'provider stashes its code verifier in a cookie at login and has to read it back to complete\n' +
                'the token exchange, and `handleCallback` is handed only `code` and `state` - so the callback\n' +
                'request’s `Cookie` header reaches the provider through the read half or not at all.\n' +
                '\n' +
                'With the write half alone, every sign-in gets as far as the callback and fails there for a\n' +
                'missing verifier. The host bounces the browser back to the login route, which re-enters the\n' +
                'identity provider: a redirect loop, and nothing in it says the cookie was written and never\n' +
                'read.',
              how:
                'Declare the read half. It is one field and one method:\n' +
                '\n' +
                '  private callbackCookieHeader: string | null = null;\n' +
                '\n' +
                '  setCallbackCookieHeader(cookieHeader: string | null): void {\n' +
                '    this.callbackCookieHeader = cookieHeader;\n' +
                '  }\n' +
                '\n' +
                '  async handleCallback(code: string, state: string) {\n' +
                '    const verifier = readMyVerifierCookie(this.callbackCookieHeader);\n' +
                '    // ... exchange `code` with `verifier`\n' +
                '  }\n' +
                '\n' +
                '`setCallbackCookieHeader` is optional on `ISSOProvider`, and hosts call it on every SSO\n' +
                'callback before `handleCallback` when a provider implements it. The argument is `null` when\n' +
                'the request carried no cookies at all.\n' +
                '\n' +
                'If this provider sets no cookie at login - a confidential client authenticating with\n' +
                '`client_secret` has no verifier to stash - then `getLoginCookies` should not be returning\n' +
                'one. `undefined` is what the method documents for that, and this check asks nothing further\n' +
                'of a provider that answers it.',
            });
          }

          const fed = await settle(() => provider.setCallbackCookieHeader?.(cookieHeader));
          if (!fed.ok) {
            fail(fixtures, {
              code: 'sso/pkce-round-trip#read-side-threw',
              headline: 'setCallbackCookieHeader threw for the callback request’s Cookie header.',
              observed: [
                `setCallbackCookieHeader(${show(cookieHeader)}) threw.`,
                `  ${show(fed.error)}`,
                'That header is what a browser would send back after the cookies getLoginCookies just set.',
              ],
              why:
                'Hosts call this on every SSO callback, before `handleCallback`, and it is declared to return\n' +
                '`void`. A throw ends the callback before the token exchange is attempted, so the sign-in\n' +
                'fails at its last step and the error names cookie parsing rather than anything the person\n' +
                'did.',
              how:
                'Store the header and return. Parse it in `handleCallback`, where a failure can be reported\n' +
                'as a failed exchange:\n' +
                '\n' +
                '  setCallbackCookieHeader(cookieHeader: string | null): void {\n' +
                '    this.callbackCookieHeader = cookieHeader;\n' +
                '  }\n' +
                '\n' +
                'The argument is `null` when the request carried no cookies, so do not assume a string.',
            });
          }

          // The identity provider echoes back the `state` it was SENT, which is
          // whatever this provider put in its own authorization URL - not
          // necessarily what the host minted. Playing the identity provider
          // faithfully is what keeps this check about the cookie: a provider
          // that re-encodes `state` already fails
          // `obligation/stateCodec/login-url`, and handing it a state it never
          // minted here would report that one defect a second time under a name
          // that points at cookies. Obligation 3 owns the state; this owns the
          // cookie. For a provider that meets obligation 3 the two values are
          // the same string and the distinction costs nothing.
          const callbackState = echoedState(login.value) ?? state;

          const before = calls.count;
          const settled = await settle(() => provider.handleCallback(fixtures.code, callbackState));
          const callsDuringCallback = calls.count - before;

          // Resolving is conforming: the provider completed a callback with no
          // network at all, which a provider holding a local key set can do.
          if (settled.ok) return;
          // Reaching the token exchange is conforming too, and here - unlike in
          // `obligation/stateCodec/callback` - it is conclusive rather than
          // merely suggestive. That check has to keep asking whether the failure
          // after the exchange was about `state`; this one does not care what
          // happened after, because a provider that got as far as the network
          // got past its own cookie parsing, which is the entire question.
          if (callsDuringCallback > 0) return;
          if (isTokenExchangeError(settled.error)) return;
          if (fixtures.reachedTokenExchange?.(settled.error) === true) return;

          fail(fixtures, {
            code: 'sso/pkce-round-trip#cookie-not-read-back',
            headline: 'handleCallback could not use the cookie this provider set at login.',
            observed: [
              `getLoginUrl(${show(fixtures.redirectUri)}, state) ran first, with state = ${show(state)}.`,
              `getLoginCookies(${show(fixtures.redirectUri)}, state) returned ${setCookies.length} value(s).`,
              `setCallbackCookieHeader was then called with what a browser would send back:`,
              `  Cookie: ${cookieHeader}`,
              `handleCallback(${show(fixtures.code)}, state) then threw, before reaching the token exchange:`,
              `  ${show(settled.error)}`,
              '',
              'The suite replaced globalThis.fetch for this call and it was never called: handleCallback',
              'made no network attempt at all before throwing.',
              '',
              `The state it was handed is ${show(callbackState)}, which is the value this provider’s own`,
              'authorization URL carries - the suite echoed it back the way an identity provider does. So a',
              'state this provider does not recognize is not what stopped it.',
            ],
            why:
              '`getLoginCookies` and `setCallbackCookieHeader` are the two halves of one loop, and the value\n' +
              'that travels between them is a PKCE code verifier. If it does not survive the trip, every\n' +
              'sign-in reaches the callback and fails there; the host bounces the browser back to the login\n' +
              'route, which re-enters the identity provider. The person sees a redirect loop and the logs\n' +
              'say a verifier was missing, which points at the callback - where nothing is wrong.',
            how:
              'Read the cookie out of the header `setCallbackCookieHeader` was handed, under the same name\n' +
              '`getLoginCookies` wrote it:\n' +
              '\n' +
              '  setCallbackCookieHeader(cookieHeader: string | null): void {\n' +
              '    this.callbackCookieHeader = cookieHeader;\n' +
              '  }\n' +
              '\n' +
              '  async handleCallback(code: string, state: string) {\n' +
              "    const verifier = readCookie(this.callbackCookieHeader, 'my_pkce_verifier');\n" +
              '    // ... exchange `code` with `verifier`\n' +
              '  }\n' +
              '\n' +
              'Three causes account for most of these. The read half is declared and stores nothing, which\n' +
              'is a no-op that satisfies every structural guard. The name written and the name read are not\n' +
              'the same. Or the verifier is looked for on a `Request` object, which `handleCallback` never\n' +
              'receives.\n' +
              '\n' +
              'If your token exchange does not go through global `fetch` - an SDK holding its own agent, or\n' +
              '`node:https` - this check cannot see it reach the network and will report that as the cookie\n' +
              'not arriving. Pass `sso.reachedTokenExchange` and answer `true` for what your transport\n' +
              'throws when it cannot reach the issuer.',
          });
        });
      },
    },
    {
      id: 'credentials/sign-up-enabled',
      section: SECTION_CREDENTIALS,
      title: 'isSignUpEnabled, when implemented, answers a literal boolean',
      obligation: null,
      failureCodes: ['credentials/sign-up-enabled#not-a-literal-boolean'],
      skipReason: provider => {
        const gate = requiresCredentials(provider);
        if (gate !== null) return gate;
        return isCredentialsProvider(provider) && typeof provider.isSignUpEnabled === 'function'
          ? null
          : 'This provider does not implement the optional isSignUpEnabled, which the contract reads as ' +
              '"sign-up is on".';
      },
      async run(provider) {
        if (!isCredentialsProvider(provider) || provider.isSignUpEnabled === undefined) return;
        // Wrapped in an object on purpose, and this is the whole check.
        //
        // `settle` awaits what the body returns. Handing it the call directly
        // meant an `async isSignUpEnabled()` resolving to `true` arrived here as
        // the boolean `true` and passed - the one shape the failure text below
        // is written about, and the shape `toAuthDescriptor` independently
        // treats as sign-up-disabled. The two halves of this package disagreed
        // about the same provider, and the half whose job is to notice was the
        // half that could not. The wrapper keeps `await` away from the returned
        // value so the check can see what the method actually returned.
        //
        // `capabilities.ts` `readSignUpEnabled` makes the matching judgement:
        // `true` only for a literal `true`, everything else `false`. The two
        // must stay in step, because a provider that passes this check is
        // exactly a provider the descriptor reads correctly.
        const outcome = await settle(() => ({ returned: provider.isSignUpEnabled?.() as unknown }));
        if (outcome.ok) {
          // A returned Promise is about to be reported as a failure, not
          // awaited. Attach a sink so a later rejection is not an unhandled one
          // that fails an unrelated test.
          const returned = outcome.value.returned;
          if (isThenable(returned)) returned.then(NOOP, NOOP);
          if (typeof returned === 'boolean') return;
        }
        fail(fixtures, {
          code: 'credentials/sign-up-enabled#not-a-literal-boolean',
          headline: 'isSignUpEnabled did not answer a literal boolean.',
          observed: [
            outcome.ok
              ? `isSignUpEnabled() returned ${show(outcome.value.returned)}.`
              : `isSignUpEnabled() threw: ${show(outcome.error)}`,
          ],
          why:
            'The contract declares this method synchronous, and `toAuthDescriptor` treats anything that is\n' +
            'not literally `true` as `false` for exactly this reason: an `async isSignUpEnabled()` returns\n' +
            'a Promise, a Promise is truthy, and a loose reader would show a sign-up link on a deployment\n' +
            'that switched sign-up off. Failing here is better than that, but the honest fix is upstream.',
          how:
            'Make the method synchronous and return `true` or `false`. If the answer needs a lookup, cache\n' +
            'it at construction time. Leave the method off entirely to mean "sign-up is on".',
        });
      },
    },
    {
      id: 'users/current-user',
      section: SECTION_USERS,
      title: 'getCurrentUser answers for the same person authenticateToken does, and for nobody else',
      obligation: null,
      failureCodes: [
        'users/current-user#threw',
        'users/current-user#no-id-in-user',
        'users/current-user#different-user',
        'users/current-user#authenticated-anonymous-request',
      ],
      skipReason: requiresUsers,
      async run(provider) {
        if (!isUserProvider(provider)) return;

        // Every credential the suite holds, on one request. `getCurrentUser`
        // takes a `Request` and nothing else, and providers differ about which
        // header they read: some parse the bearer, some read only a session
        // cookie. Sending both means a `null` answer below is a fact about the
        // provider rather than about which header this suite guessed.
        const headers: Record<string, string> = { authorization: `Bearer ${fixtures.token}` };
        if (fixtures.cookieHeader !== undefined) headers.cookie = fixtures.cookieHeader;

        const outcome = await settle(() => provider.getCurrentUser(requestWith(fixtures, headers)));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'users/current-user#threw',
            headline: 'getCurrentUser threw instead of answering a user or null.',
            observed: [
              'getCurrentUser(request) threw.',
              `  ${show(outcome.error)}`,
              `  request: GET ${fixtures.requestUrl}`,
              `    authorization: Bearer ${fixtures.token}`,
              ...(fixtures.cookieHeader === undefined ? [] : [`    cookie: ${fixtures.cookieHeader}`]),
            ],
            why:
              '`IUserProvider.getCurrentUser` is declared to resolve to a user or to `null`, and hosts call\n' +
              'it on the "who am I" route every signed-in page loads. A throw there is a 500 on a route that\n' +
              'has no failure state of its own, so a signed-out browser and an identity provider that is\n' +
              'down look identical, and the page breaks rather than showing a sign-in button.',
            how:
              'Return `null` for a request you cannot resolve, rather than throwing. Rejection is the\n' +
              'ordinary outcome here: this method runs on requests that legitimately carry no session.',
          });
        }

        const current = outcome.value;

        // Nothing resolved, and this check asks nothing further. A provider
        // whose user lookup needs a live vendor cannot answer offline, and
        // `okta`'s session store, `clerk`'s Users API and `studio`'s cached
        // cookie are all in that shape. What this check is for is the provider
        // that answers, and answers about somebody else.
        if (current === null || current === undefined) return;

        const identity = toAuthIdentity(current, provider);
        if (identity === null) {
          fail(fixtures, {
            code: 'users/current-user#no-id-in-user',
            headline: 'getCurrentUser answered with something that names nobody.',
            observed: [
              'getCurrentUser(request) resolved to:',
              `  ${show(current)}`,
              'toAuthIdentity found no id in it. It looks for `id`, then `uid`, then `sub`, at the top',
              'level - and inside `user` for a `{ session, user }` pair. A blank or whitespace-only value',
              'counts as absent.',
            ],
            why:
              'This is the same rule obligation 1 holds `authenticateToken` to, applied to the other path\n' +
              'that produces a user. A host reads an id off whichever of the two answered it, and a user\n' +
              'object with no resolvable id is one the host has to either drop or key under `undefined`.\n' +
              'Dropping it signs the person out on a page that just told them they were signed in.',
            how:
              'Return the id at the top level, under `id`, `uid` or `sub`. If it genuinely lives elsewhere,\n' +
              'implement `toIdentity` on the provider and say so explicitly - the same escape hatch\n' +
              'obligation 1 documents, and the same one this check reads through.',
          });
        }

        // Through `userIdOf`, so the `userId` option is preferred over reading
        // an id back out of `authenticateToken`. A provider whose
        // `authenticateToken` is broken has one defect and should report it
        // once: without this, every check that needs an id to compare against
        // reports the same root cause under its own name.
        const expected = await userIdOf(provider, fixtures);
        if (identity.id !== expected) {
          fail(fixtures, {
            code: 'users/current-user#different-user',
            headline: 'getCurrentUser and authenticateToken name two different people for one credential.',
            observed: [
              `getCurrentUser(request) resolved the id ${show(identity.id)}.`,
              fixtures.userId === undefined
                ? `authenticateToken(${show(fixtures.token)}, request) resolved the id ${show(expected)}.`
                : `The \`userId\` option says this credential belongs to ${show(expected)}.`,
              'The request carried:',
              `  authorization: Bearer ${fixtures.token}`,
              ...(fixtures.cookieHeader === undefined ? [] : [`  cookie: ${fixtures.cookieHeader}`]),
              'getCurrentUser resolved to:',
              `  ${show(current)}`,
            ],
            why:
              'These are two views of one signed-in person, and hosts use both: the enforcement path goes\n' +
              'through `authenticateToken`, and `getCurrentUser` supplies the profile shown on screen.\n' +
              'When they disagree, the person is shown one identity and their work is stored under\n' +
              'another - a request that succeeds, and data that lands under a key that is not theirs. It\n' +
              'is the same defect obligation 1 exists for, arriving through the second door.',
            how:
              'Resolve both paths from the same field of the same token. The usual cause is a\n' +
              '`{ session, user }` payload read at the top level on one path and inside `user` on the\n' +
              'other, so one of them answers a session id. If your provider genuinely has two id spaces,\n' +
              'map to the one `authenticateToken` returns; that is the one the host keys storage on.',
          });
        }

        // The security half, and the mirror of `contract/rejects-anonymous-
        // request`. `getCurrentUser` is not the enforcement path, but a host
        // that trusts it - and the "who am I" route does - hands out a session
        // to a request that presented nothing.
        const anonymous = await settle(() => provider.getCurrentUser(requestWith(fixtures)));
        if (anonymous.ok && anonymous.value !== null && anonymous.value !== undefined) {
          fail(fixtures, {
            code: 'users/current-user#authenticated-anonymous-request',
            headline: 'getCurrentUser answered with a user for a request carrying no credentials at all.',
            observed: [
              `getCurrentUser(request) resolved to ${show(anonymous.value)}.`,
              `  request: GET ${fixtures.requestUrl}, no headers at all`,
              'No Authorization header, no Cookie header, no session of any kind.',
            ],
            why:
              'A host asks this to draw the signed-in state of a page, and answering it for an anonymous\n' +
              'request tells the browser somebody is signed in when nobody is. Whoever that user is, they\n' +
              'are the same user for every visitor, so a shared deployment shows one person’s name, email\n' +
              'and organization to everybody who loads the page.',
            how:
              'Read the credential off the request rather than off the provider. A `currentUser` field\n' +
              'cached on the instance is the usual cause: the provider is long-lived and shared across\n' +
              'requests, so the last person to sign in becomes everybody. Resolve per request, and return\n' +
              '`null` when the request carries nothing.',
          });
        }
      },
    },
    {
      id: 'users/get-user',
      section: SECTION_USERS,
      title: 'getUser is there, and looks up this provider’s own user by id',
      obligation: null,
      failureCodes: ['users/get-user#not-declared', 'users/get-user#threw', 'users/get-user#different-user'],
      skipReason: requiresUsers,
      async run(provider) {
        if (!isUserProvider(provider)) return;

        // The structural half, asked HERE rather than in the gate, for the
        // reason the module header gives: `isUserProvider` reads one of the two
        // members `IUserProvider` requires, so the gate cannot tell a provider
        // that has `getUser` from one that does not. Gating on it would skip
        // exactly the provider this half exists to find.
        if (typeof provider.getUser !== 'function') {
          fail(fixtures, {
            code: 'users/get-user#not-declared',
            headline: 'This provider satisfies isUserProvider and has no getUser.',
            observed: [
              'isUserProvider(provider) is true, which is the guard hosts branch on.',
              `  provider.getCurrentUser is ${show(provider.getCurrentUser)}`,
              `  provider.getUser        is ${show((provider as { getUser?: unknown }).getUser)}`,
              '',
              '`IUserProvider` requires both. The guard reads only `getCurrentUser`, so it narrows this',
              'provider to a type that promises a `getUser` it does not have.',
            ],
            why:
              '`isUserProvider` is a structural guard and it is optimistic: it tests `getCurrentUser` and\n' +
              'stops. A host that writes `if (isUserProvider(auth)) auth.getUser(id)` therefore compiles,\n' +
              'because the guard narrowed to an interface that declares the method, and throws\n' +
              '`auth.getUser is not a function` at run time - inside the host, on a request, with a stack\n' +
              'that points at the host rather than at the provider that is missing the member.\n' +
              '\n' +
              'This is the reason a passing guard is not evidence that a capability is complete, and it is\n' +
              'why this suite asks about members the guard never reads.',
            how:
              'Implement it. It is declared to resolve to a user or to `null`, and `null` is a legitimate\n' +
              'answer for the whole method:\n' +
              '\n' +
              '  async getUser(userId: string): Promise<MyUser | null> {\n' +
              '    // Look the id up, or return null when this provider cannot.\n' +
              '    return null;\n' +
              '  }\n' +
              '\n' +
              'A provider that has no directory to search should say so by resolving `null`, not by\n' +
              'leaving the method off - the absence is what the host cannot see coming.',
          });
        }

        const userId = await userIdOf(provider, fixtures);
        const outcome = await settle(() => provider.getUser(userId));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'users/get-user#threw',
            headline: 'getUser threw for this provider’s own user id.',
            observed: [
              `getUser(${show(userId)}) threw.`,
              `  ${show(outcome.error)}`,
              'That is the id this suite was told the token belongs to, so it is not an id the provider',
              'has never seen.',
            ],
            why:
              'Hosts call this to put a name and an avatar next to work somebody else did - a run, a\n' +
              'thread, an audit row. It is declared to resolve to a user or to `null`, and a throw turns\n' +
              'every one of those surfaces into an error for a piece of decoration, rather than rendering\n' +
              'the id and moving on.',
            how:
              'Resolve `null` for an id you cannot find or cannot look up, rather than throwing. If the\n' +
              'lookup needs a vendor call that can fail, catch it and answer `null`: the caller has an id\n' +
              'to fall back on and no way to handle your exception.',
          });
        }

        const found = outcome.value;
        // `null` is what the interface documents for a user who is not found,
        // and it is the honest answer for a provider with no directory to
        // search - four in this repository return it unconditionally. This
        // check does not demand a user; it demands that a user it does hand
        // back is the one that was asked for.
        if (found === null || found === undefined) return;

        const identity = toAuthIdentity(found, provider);
        if (identity !== null && identity.id === userId) return;

        fail(fixtures, {
          code: 'users/get-user#different-user',
          headline: 'getUser answered with a different user than the id it was asked about.',
          observed: [
            `getUser(${show(userId)}) resolved to:`,
            `  ${show(found)}`,
            identity === null
              ? 'toAuthIdentity found no id in it, so there is nothing to match against the id requested.'
              : `toAuthIdentity resolved the id ${show(identity.id)}, and ${show(userId)} was asked for.`,
          ],
          why:
            'This is a lookup by primary key, and the caller already holds the id - it is calling to turn\n' +
            'that id into a name. Answering with somebody else labels one person’s work with another\n' +
            "person's name and email, on every surface that renders it, with nothing anywhere reporting\n" +
            'an error. An answer that names nobody is the same defect one step earlier: the host has no\n' +
            'way to tell it apart from the user it asked for.',
          how:
            'Return the record for the id you were handed, or `null` when there is none. Two causes\n' +
            'account for most of these: the method ignores its argument and returns whoever is currently\n' +
            'signed in, or it resolves a user whose id lives somewhere `toAuthIdentity` does not look -\n' +
            'it reads `id`, then `uid`, then `sub`, at the top level.',
        });
      },
    },
    {
      id: 'organizations/is-admin',
      section: SECTION_ORGANIZATIONS,
      title: 'isOrganizationAdmin answers a boolean, and never yes for an organization it never created',
      obligation: null,
      failureCodes: [
        'organizations/is-admin#threw',
        'organizations/is-admin#not-a-boolean',
        'organizations/is-admin#threw-for-an-unknown-organization',
        'organizations/is-admin#admin-of-an-unknown-organization',
      ],
      skipReason: requiresOrganizations,
      async run(provider) {
        if (!isOrganizationsProvider(provider)) return;
        const userId = await userIdOf(provider, fixtures);

        // The organization this provider itself bootstrapped, so the question is
        // about a real one. `obligation/organizationId/deterministic` owns every
        // way `ensureOrganization` can be wrong, so a failure there is not
        // repeated here: this check takes whatever it got and asks the admin
        // question about it, or skips that half when there was nothing to ask
        // about.
        const bootstrapped = await settle(() => provider.ensureOrganization(userId));
        const organizationId = bootstrapped.ok && typeof bootstrapped.value === 'string' ? bootstrapped.value : null;

        if (organizationId !== null) {
          const own = await settle(() => provider.isOrganizationAdmin(organizationId, userId));
          if (!own.ok) {
            fail(fixtures, {
              code: 'organizations/is-admin#threw',
              headline: 'isOrganizationAdmin threw for this provider’s own organization.',
              observed: [
                `ensureOrganization(${show(userId)}) resolved ${show(organizationId)}.`,
                `isOrganizationAdmin(${show(organizationId)}, ${show(userId)}) then threw.`,
                `  ${show(own.error)}`,
              ],
              why:
                '`IOrganizationsProvider` says in as many words that provider errors here should resolve to\n' +
                '`false` rather than throw, and the reason is what the answer is used for. Every host that\n' +
                'gates an administrative action calls this, so a throw either takes down the route or is\n' +
                'caught by a caller that has to guess - and a caller guessing about an authorization answer\n' +
                'guesses wrong in one of two directions, one of which is fail-open.',
              how:
                'Catch and answer `false`. Deciding it here is the point: this method is the only place that\n' +
                'knows a lookup failed, and `false` is the safe reading of "cannot tell".\n' +
                '\n' +
                '  async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {\n' +
                '    try {\n' +
                '      return (await this.roleOf(organizationId, userId)) === "admin";\n' +
                '    } catch {\n' +
                '      return false;\n' +
                '    }\n' +
                '  }',
            });
          }
          if (typeof own.value !== 'boolean') {
            fail(fixtures, {
              code: 'organizations/is-admin#not-a-boolean',
              headline: 'isOrganizationAdmin answered with something that is not a boolean.',
              observed: [
                `isOrganizationAdmin(${show(organizationId)}, ${show(userId)}) resolved to ${show(own.value)}.`,
                'The contract declares `Promise<boolean>`, and this value was read after awaiting it.',
              ],
              why:
                'Callers write `if (await auth.isOrganizationAdmin(org, user))`, so the answer is read for\n' +
                'truthiness. A role string - `"member"`, `"viewer"` - is truthy, and so is an object, and so\n' +
                'is a Promise that was never awaited. Every one of those reads as "yes, an administrator" at\n' +
                'the call site, which is a fail-open answer to the one question in this interface where\n' +
                'fail-open means one user acting on another user’s data.\n' +
                '\n' +
                'This check does not ask for `true`. Answering `false` for your own organization is fine -\n' +
                'a provider that cannot reach its role store yet is right to say no. What is not fine is an\n' +
                'answer a caller cannot read as no.',
              how:
                'Compare, and return the comparison:\n' +
                '\n' +
                '  return role === "admin" || role === "owner";\n' +
                '\n' +
                'Not the role itself, and not the result of a bare `await`-less call to something else.',
            });
          }
        }

        // The half that is a security answer.
        //
        // A provider is asked about an organization nothing bootstrapped, under
        // a user id it does know. `false` is the only correct answer, and it has
        // to be reached without a throw: a host gating on this catches nothing.
        const stranger = await settle(() => provider.isOrganizationAdmin(CONFORMANCE_UNOWNED_ORGANIZATION, userId));
        if (!stranger.ok) {
          fail(fixtures, {
            code: 'organizations/is-admin#threw-for-an-unknown-organization',
            headline: 'isOrganizationAdmin threw for an organization id it does not recognize.',
            observed: [
              `isOrganizationAdmin(${show(CONFORMANCE_UNOWNED_ORGANIZATION)}, ${show(userId)}) threw.`,
              `  ${show(stranger.error)}`,
              'That id belongs to no organization. A provider is asked about ids it has never seen',
              'whenever one arrives from a URL, a stale bookmark, or another tenant.',
            ],
            why:
              'An unknown organization id is not an exceptional condition, it is the ordinary shape of a\n' +
              'request that should be refused. Throwing for it leaves a host unable to tell two answers\n' +
              'apart - "not an administrator" and "this provider broke" - and they want opposite handling:\n' +
              'one is a 403 and the other is a retry.',
            how:
              'Answer `false` for an id you do not recognize. The lookup that finds nothing and the lookup\n' +
              'that fails have the same safe answer here, so both can end at `return false`.',
          });
        }
        if (stranger.value !== true) return;

        fail(fixtures, {
          code: 'organizations/is-admin#admin-of-an-unknown-organization',
          headline: 'isOrganizationAdmin answered true for an organization this provider never created.',
          observed: [
            `isOrganizationAdmin(${show(CONFORMANCE_UNOWNED_ORGANIZATION)}, ${show(userId)}) resolved true.`,
            `ensureOrganization(${show(userId)}) resolved ${show(organizationId)}, which is a different id.`,
            'No organization has that id. The suite made it up, and it is not in any provider’s format.',
          ],
          why:
            'This is the one answer in the interface whose wrong value hands somebody rights over another\n' +
            'user’s data. A host gates administrative actions on it - renaming an organization, removing a\n' +
            'member, reading everything scoped to it - and the id comes from the request, which means it\n' +
            'comes from whoever made the request. A provider that answers `true` for ids it does not\n' +
            'recognize turns "guess an organization id" into an administrator role in it.\n' +
            '\n' +
            'The usual shape is not a decision to fail open. It is a lookup that finds no membership row\n' +
            'and falls through to a default of `true`, or a check that asks "is this user an admin\n' +
            'anywhere" and ignores the organization it was handed.',
          how:
            'Refuse by default and grant on evidence:\n' +
            '\n' +
            '  async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {\n' +
            '    const membership = await this.membership(organizationId, userId);\n' +
            '    if (membership === undefined) return false;\n' +
            '    return membership.role === "admin" || membership.role === "owner";\n' +
            '  }\n' +
            '\n' +
            'The organization id has to appear in the lookup. If this provider has no organizations of\n' +
            'its own and the members came from a wrapper, use `withSyntheticOrganizations` from\n' +
            `'${KIT_PACKAGE_NAME}/organizations' - it answers this question itself for ids in its own\n` +
            'namespace, in both directions, and never delegates them.',
        });
      },
    },
    {
      id: 'sessions/round-trip',
      section: SECTION_SESSIONS,
      title: 'a created session validates, and names the user it was created for',
      obligation: null,
      failureCodes: [
        'sessions/round-trip#create-threw',
        'sessions/round-trip#create-returned-no-id',
        'sessions/round-trip#create-wrong-user',
        'sessions/round-trip#validate-rejects-fresh-session',
        'sessions/round-trip#destroyed-session-still-validates',
      ],
      skipReason: requiresSessions,
      async run(provider) {
        if (!isSessionProvider(provider)) return;
        const userId = await userIdOf(provider, fixtures);

        const created = await settle(() => provider.createSession(userId));
        if (!created.ok) {
          fail(fixtures, {
            code: 'sessions/round-trip#create-threw',
            headline: 'createSession threw.',
            observed: [`createSession(${show(userId)}) threw.`, `  ${show(created.error)}`],
            why:
              'This provider declares ISessionProvider, so the host will call this after a successful\n' +
              'sign-in and hand the browser whatever comes back.',
            how:
              'If your session store needs infrastructure, give `createProvider` an in-memory one for the\n' +
              'conformance run. If this provider is not really a session provider, remove `createSession`\n' +
              'and `validateSession` - the guard is structural, and it is reporting what it finds.',
          });
        }
        const session = created.value as { id?: unknown; userId?: unknown } | null;
        if (session === null || typeof session !== 'object' || typeof session.id !== 'string' || session.id === '') {
          fail(fixtures, {
            code: 'sessions/round-trip#create-returned-no-id',
            headline: 'createSession returned something with no session id.',
            observed: [`createSession(${show(userId)}) returned ${show(session)}.`],
            why: 'The id is the value the host puts in a cookie and hands back to `validateSession`.',
            how: 'Return a `Session`: `{ id, userId, createdAt, expiresAt }` at minimum.',
          });
        }
        if (session.userId !== userId) {
          fail(fixtures, {
            code: 'sessions/round-trip#create-wrong-user',
            headline: 'createSession returned a session belonging to a different user.',
            observed: [`createSession(${show(userId)}) returned a session with userId ${show(session.userId)}.`],
            why: 'The host reads the user back off the session on every subsequent request.',
            how: 'Store the `userId` argument on the session unchanged.',
          });
        }

        const validated = await settle(() => provider.validateSession(session.id as string));
        if (!validated.ok || validated.value === null || validated.value === undefined) {
          fail(fixtures, {
            code: 'sessions/round-trip#validate-rejects-fresh-session',
            headline: 'validateSession rejected a session this provider had just created.',
            observed: [
              `createSession(${show(userId)}) returned session ${show(session.id)}.`,
              validated.ok
                ? `validateSession(${show(session.id)}) resolved to ${show(validated.value)}.`
                : `validateSession(${show(session.id)}) threw: ${show(validated.error)}`,
            ],
            why:
              'Create and validate are the two methods `isSessionProvider` tests for, and they are the two\n' +
              'halves of one loop: the host creates a session on sign-in and validates it on every request\n' +
              'after. A session that does not validate is a sign-in that does not stick.',
            how:
              'Make sure `createSession` commits before it resolves, and that `validateSession` reads the\n' +
              'same store under the same key.',
          });
        }

        if (typeof provider.destroySession !== 'function') return;
        await settle(() => provider.destroySession(session.id as string));
        const afterDestroy = await settle(() => provider.validateSession(session.id as string));
        if (afterDestroy.ok && afterDestroy.value !== null && afterDestroy.value !== undefined) {
          fail(fixtures, {
            code: 'sessions/round-trip#destroyed-session-still-validates',
            headline: 'A destroyed session still validates.',
            observed: [
              `destroySession(${show(session.id)}) resolved.`,
              `validateSession(${show(session.id)}) then returned ${show(afterDestroy.value)}.`,
            ],
            why:
              'This provider advertises session revocation - `toAuthDescriptor` reports\n' +
              '`features.sessionRevocation: true` on the strength of `destroySession` existing - so a UI\n' +
              'will offer "sign out everywhere" and a person will believe it worked.',
            how: 'Remove the session from the store in `destroySession`, or drop the method.',
          });
        }
      },
    },
    {
      id: 'routes/answers-a-response',
      section: SECTION_ROUTES,
      title: 'handleAuthRequest answers a Response, including for a path it does not serve',
      obligation: null,
      failureCodes: ['routes/answers-a-response#threw', 'routes/answers-a-response#not-a-response'],
      skipReason: requiresHttpHandler,
      async run(provider) {
        if (!isAuthHttpHandler(provider)) return;
        const request = new Request(`${new URL(fixtures.requestUrl).origin}/auth/api/conformance-unknown-route`);
        const outcome = await withoutNetwork(() => settle(() => provider.handleAuthRequest(request)));
        if (!outcome.ok) {
          fail(fixtures, {
            code: 'routes/answers-a-response#threw',
            headline: 'handleAuthRequest threw for a route it does not serve.',
            observed: [`handleAuthRequest(GET ${request.url}) threw.`, `  ${show(outcome.error)}`],
            why:
              'The host mounts this handler as a catch-all under its auth prefix, so it receives every\n' +
              'path under it, including ones from stale clients and scanners. A throw becomes a 500 on a\n' +
              'public route.',
            how: 'Answer `new Response(null, { status: 404 })` for a path you do not serve.',
          });
        }
        if (!(outcome.value instanceof Response)) {
          fail(fixtures, {
            code: 'routes/answers-a-response#not-a-response',
            headline: 'handleAuthRequest resolved to something that is not a Response.',
            observed: [`handleAuthRequest(GET ${request.url}) resolved to ${show(outcome.value)}.`],
            why: 'The host returns this value to the browser as-is.',
            how: 'Return a `Response`.',
          });
        }
      },
    },
    {
      id: 'init/accepts-host-context',
      section: SECTION_INIT,
      title: 'init accepts the host context',
      obligation: null,
      failureCodes: ['init/accepts-host-context#threw'],
      skipReason: requiresInit,
      async run(provider) {
        if (!hasAuthInit(provider)) return;
        const outcome = await withoutNetwork(() =>
          settle(() =>
            provider.init({
              publicUrl: new URL(fixtures.requestUrl).origin,
              allowedOrigins: [new URL(fixtures.requestUrl).origin],
            }),
          ),
        );
        if (outcome.ok) return;
        fail(fixtures, {
          code: 'init/accepts-host-context#threw',
          headline: 'init threw for a host context carrying only a public URL and allowed origins.',
          observed: [`init({ publicUrl, allowedOrigins }) threw.`, `  ${show(outcome.error)}`],
          why:
            'The host calls `init` once during preparation, before it serves anything. The hook is\n' +
            'documented for failing fast on requirements only satisfiable at prepare time, so a throw here\n' +
            'is a refusal to start - which is right for a genuine misconfiguration and wrong for a field\n' +
            'the host did not happen to pass.',
          how:
            'Treat every field of `AuthInitContext` as optional; all three are. If your provider needs a\n' +
            '`database` handle, take it in the constructor and use `init` only to consume what the host\n' +
            'can add.',
        });
      },
    },
  ];
}

// ============================================================================
// Running one check
// ============================================================================

/** The message of a thrown value, however unhelpfully it was thrown. */
function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

/**
 * Run one check against one provider and say what happened, with the
 * known-failure policy applied.
 *
 * This is where that policy lives, once. `describeAuthProvider` is a `describe`
 * and an `it` around it, and an adapter for another runner is the same shape -
 * so the two halves cannot drift, which is the thing that would quietly break
 * the guarantee. The split C1 established is what makes the policy testable at
 * all: there is no way to write a passing vitest test asserting that a nested
 * vitest suite went red, so the kit's own tests call this and assert on the
 * outcome as data.
 *
 * The four rules, all of them enforced here:
 *
 * 1. A check with no entry behaves exactly as before - pass, skip with the
 *    gate's reason, or fail.
 * 2. A recorded check that fails with the recorded code is a `knownFailure`.
 *    Reported, not silent; not a suite failure.
 * 3. A recorded check that passes, or that turns out not to apply, is a
 *    `failed` - the record has outlived the defect and has to be deleted.
 * 4. A recorded check that fails under a different code is a `failed` too. An
 *    entry names one defect; letting any failure of that check count would let
 *    it absorb the next, unrelated regression in the same check.
 *
 * @param check one of {@link authConformanceChecks}
 * @param provider a freshly built provider, not shared with another check
 * @param providerName how to name it in a message. Defaults to `check.id`'s
 * suite name being unavailable here, so pass the caller's `name`.
 */
export async function runAuthConformanceCheck(
  check: AuthConformanceCheck,
  provider: IMastraAuthProvider,
  providerName: string,
): Promise<AuthConformanceOutcome> {
  const entry = check.knownFailure;

  // Safe to call unguarded: `authConformanceChecks` wraps every gate.
  const skip = check.skipReason(provider);
  if (skip !== null) {
    if (entry === null) return { status: 'skipped', reason: skip };
    return {
      status: 'failed',
      code: null,
      message: formatStaleKnownFailure({
        provider: providerName,
        check: check.id,
        code: entry.code,
        reason: entry.reason,
        kind: 'skipped',
        detail: skip,
      }),
    };
  }

  let thrown: unknown;
  let failed = false;
  try {
    await check.run(provider);
  } catch (error) {
    thrown = error;
    failed = true;
  }

  if (entry === null) {
    if (!failed) return { status: 'passed' };
    return { status: 'failed', message: messageOf(thrown), code: readFailureCode(thrown) };
  }

  if (!failed) {
    return {
      status: 'failed',
      code: null,
      message: formatStaleKnownFailure({
        provider: providerName,
        check: check.id,
        code: entry.code,
        reason: entry.reason,
        kind: 'passed',
      }),
    };
  }

  const actual = readFailureCode(thrown);
  if (actual !== entry.code) {
    return {
      status: 'failed',
      code: actual,
      message: formatStaleKnownFailure({
        provider: providerName,
        check: check.id,
        code: entry.code,
        reason: entry.reason,
        kind: 'different-code',
        actualCode: actual,
        detail: messageOf(thrown),
      }),
    };
  }

  return {
    status: 'knownFailure',
    entry,
    failure: messageOf(thrown),
    message: formatKnownFailure({
      provider: providerName,
      check: check.id,
      code: entry.code,
      reason: entry.reason,
      message: messageOf(thrown),
    }),
  };
}

// ============================================================================
// The suite
// ============================================================================

/**
 * Register the conformance suite for one provider.
 *
 * ```ts
 * describeAuthProvider({
 *   name: '@mastra/auth-my-provider',
 *   createProvider: () => new MyAuthProvider({ verify: fakeVerifier }),
 *   token: 'a-token-my-provider-accepts',
 *   userId: 'user_123',
 *   cookieHeader: 'my_provider_session=a-token-my-provider-accepts',
 * });
 * ```
 *
 * Call it at the top level of a `*.test.ts` in your own package. It registers
 * one `describe` per section and one `it` per check, so a failure names the
 * obligation in the test path - `obligation 2 of 4 - cookieAuth >
 * authenticateToken reads the Cookie header ...` - before anybody reads the
 * message.
 *
 * A check that does not apply is reported as **skipped, with the reason**,
 * never as passed. That distinction is the whole point of the skip rule in this
 * module's header: a suite where "not applicable" and "correct" look the same
 * is a suite that goes green for a provider nobody checked.
 *
 * Nothing about the suite is conditional on the environment. It reads no
 * variables, opens no sockets, and removes `globalThis.fetch` for the one check
 * that needs the absence of a network to be observable.
 *
 * @param options See {@link AuthProviderConformanceOptions}.
 * @throws TypeError at registration time when `name`, `createProvider` or
 * `token` is missing. Those are mistakes in the calling file, and failing before
 * any suite exists keeps them from being reported as provider defects.
 */
export function describeAuthProvider(options: AuthProviderConformanceOptions): void {
  const checks = authConformanceChecks(options);
  const sections = [...new Set(checks.map(check => check.section))];

  describe(`auth provider conformance: ${options.name}`, () => {
    for (const section of sections) {
      describe(section, () => {
        for (const check of checks.filter(candidate => candidate.section === section)) {
          const title = check.knownFailure === null ? check.title : `${KNOWN_FAILURE_TITLE_PREFIX}${check.title}`;
          it(title, async ctx => {
            // A fresh provider per check: no check can see another's state, and
            // a provider that mutates itself on first use is exercised from a
            // clean start every time.
            const provider = await options.createProvider();
            const outcome = await runAuthConformanceCheck(check, provider, options.name);

            if (outcome.status === 'passed') return;
            if (outcome.status === 'failed') expect.fail(outcome.message);
            if (outcome.status === 'skipped') {
              ctx.skip(outcome.reason);
              return;
            }

            // A known failure, and the two lines below are the whole reporting
            // decision. It must not fail the run - that is the point of
            // recording it - and it must not be invisible either, because an
            // invisible exemption is an exclusion with extra steps.
            //
            // So it is announced on stderr, which the default reporter prints
            // with the file and test name attached and which therefore survives
            // a run nobody opens in verbose mode, and it is then skipped with
            // the full report as the note. Together with the title prefix, a
            // provider carrying known failures cannot be mistaken for a clean
            // one at any level of detail somebody chooses to read.
            //
            // eslint-disable-next-line no-console -- the visibility is the feature; see above.
            console.warn(
              `[factory-auth conformance] KNOWN FAILURE  ${options.name}  ${outcome.entry.code}\n` +
                `  ${outcome.entry.reason}`,
            );
            ctx.skip(outcome.message);
          });
        }
      });
    }
  });
}
