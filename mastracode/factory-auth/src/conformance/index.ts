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
} from '../contract.js';
import type { IMastraAuthProvider } from '../contract.js';
import { toAuthIdentity } from '../identity.js';
import type { AuthIdentity } from '../identity.js';
import { decodeState, encodeState, parseStateId } from '../oauth-state.js';
import { resolveOrganizationId } from '../organizations.js';
import type { AuthObligation } from '../testing/index.js';
import {
  AUTH_OBLIGATION_COUNT,
  AUTH_OBLIGATION_GUIDANCE,
  formatConformanceFailure,
  KIT_PACKAGE_NAME,
  kitImport,
} from './obligations.js';

export {
  AUTH_OBLIGATION_COUNT,
  AUTH_OBLIGATION_GUIDANCE,
  CONFORMANCE_DOCS_URL,
  formatConformanceFailure,
} from './obligations.js';
export type { AuthObligationGuidance, ConformanceFailure } from './obligations.js';

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
   * Why this check does not apply to `provider`, or `null` when it does.
   *
   * The only legitimate reason is that a structural guard says the provider does
   * not declare the capability the check is about. See the skip rule in this
   * module's header.
   */
  readonly skipReason: (provider: IMastraAuthProvider) => string | null;

  /** Run it. Resolves when the provider conforms, throws when it does not. */
  readonly run: (provider: IMastraAuthProvider) => Promise<void>;
}

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
}

const DEFAULT_REQUEST_URL = 'https://conformance.test/api/agents';
const DEFAULT_REDIRECT_URI = 'https://conformance.test/auth/callback';
const DEFAULT_CODE = 'conformance-authorization-code';
const DEFAULT_REJECTED_TOKEN = 'conformance-rejected-token';

/** The `state` id every hosted-login check mints under. Fixed, so a failure quotes a constant. */
const CONFORMANCE_STATE_ID = 'conformance-state-id';

/** The destination every hosted-login check round trips. Chosen to survive percent-encoding. */
const CONFORMANCE_RETURN_TO = '/agents/42';

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
  };
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
 */
function fail(
  fixtures: Fixtures,
  failure: {
    obligation?: AuthObligation;
    headline?: string;
    observed: readonly string[];
    why?: string;
    how?: string;
  },
): never {
  expect.fail(formatConformanceFailure({ provider: fixtures.name, ...failure }));
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
async function withoutNetwork<T>(body: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = (() => {
    throw new TokenExchangeReached();
  }) as typeof fetch;
  try {
    return await body();
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

  return buildChecks(fixtures).map(check => ({
    ...check,
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

function buildChecks(fixtures: Fixtures): readonly AuthConformanceCheck[] {
  return [
    // ------------------------------------------------------------------
    // The base contract
    // ------------------------------------------------------------------
    {
      id: 'contract/shape',
      section: SECTION_CONTRACT,
      title: 'implements IMastraAuthProvider',
      obligation: null,
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
      skipReason: ALWAYS,
      async run(provider) {
        const outcome = await settle(() => toAuthDescriptor(provider));
        if (!outcome.ok) {
          fail(fixtures, {
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
      skipReason: ALWAYS,
      async run(provider) {
        const outcome = await settle(() => provider.authenticateToken(fixtures.rejectedToken, requestWith(fixtures)));
        if (!outcome.ok) {
          fail(fixtures, {
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
      skipReason: ALWAYS,
      async run(provider) {
        // A throw is not an authentication, and `contract/rejects-unknown-token`
        // already owns the "reject without throwing" claim. This check is only
        // about the one outcome that is a security finding.
        const outcome = await settle(() => provider.authenticateToken('', requestWith(fixtures)));
        if (outcome.ok && outcome.value !== null && outcome.value !== undefined) {
          fail(fixtures, {
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
      skipReason: ALWAYS,
      async run(provider) {
        const payload = await authenticated(provider, fixtures);
        const outcome = await settle(() => provider.authorizeUser(payload, requestWith(fixtures)));
        if (!outcome.ok) {
          fail(fixtures, {
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
      skipReason: ALWAYS,
      async run(provider) {
        const payload = await authenticated(provider, fixtures);
        const identity = toAuthIdentity(payload, provider);
        if (identity === null) {
          fail(fixtures, {
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
      skipReason: requiresBrowserSession,
      async run(provider) {
        if (fixtures.cookieHeader === undefined) {
          fail(fixtures, {
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
      skipReason: requiresSSO,
      async run(provider) {
        if (!isSSOProvider(provider)) return;
        const state = encodeState(CONFORMANCE_RETURN_TO, CONFORMANCE_STATE_ID);
        const outcome = await settle(() => provider.getLoginUrl(fixtures.redirectUri, state));
        if (!outcome.ok) {
          fail(fixtures, {
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
      skipReason: requiresSSO,
      async run(provider) {
        if (!isSSOProvider(provider)) return;
        const state = encodeState(CONFORMANCE_RETURN_TO, CONFORMANCE_STATE_ID);

        const outcome = await withoutNetwork(async () => {
          // The login half runs first and inside the same stub, because a
          // provider that keeps a state store fills it here. Skipping it would
          // ask the callback about a state that was never minted, which every
          // correct provider is entitled to reject.
          await settle(() => provider.getLoginUrl(fixtures.redirectUri, state));
          return settle(() => provider.handleCallback(fixtures.code, state));
        });

        // Resolving is conforming: the provider completed a callback with no
        // network at all, which a provider holding a local key set can do.
        if (outcome.ok) return;
        if (isTokenExchangeError(outcome.error)) return;
        if (fixtures.reachedTokenExchange?.(outcome.error) === true) return;

        fail(fixtures, {
          obligation: 'stateCodec',
          headline: 'handleCallback rejected a state its own getLoginUrl was just handed.',
          observed: [
            `getLoginUrl(${show(fixtures.redirectUri)}, state) ran first, with state = ${show(state)}.`,
            `handleCallback(${show(fixtures.code)}, state) then threw, before reaching the token exchange:`,
            `  ${show(outcome.error)}`,
            '',
            'The suite replaced globalThis.fetch for this call, so a provider that got as far as the',
            'token exchange fails with a recognizable error instead. This failure is not that one, which',
            'means the provider stopped at the state.',
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
      skipReason: ALWAYS,
      async run(provider) {
        if (isOrganizationsProvider(provider)) return;
        fail(fixtures, {
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
      skipReason: requiresSSO,
      async run(provider) {
        if (!isSSOProvider(provider)) return;
        const outcome = await settle(() => provider.getLoginButtonConfig());
        if (!outcome.ok) {
          fail(fixtures, {
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
      skipReason: provider =>
        isSSOProvider(provider) && typeof provider.getLogoutUrl === 'function'
          ? null
          : 'This provider does not implement the optional getLogoutUrl.',
      async run(provider) {
        if (!isSSOProvider(provider) || provider.getLogoutUrl === undefined) return;
        const outcome = await settle(() => provider.getLogoutUrl?.(fixtures.redirectUri, requestWith(fixtures)));
        if (!outcome.ok) {
          fail(fixtures, {
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
            headline: 'getLogoutUrl answered something that is not an absolute URL.',
            observed: [`getLogoutUrl(...) returned ${show(url)}.`],
            why: 'The host redirects the browser to this value verbatim.',
            how: 'Return an absolute URL, or `null` when the provider has no hosted logout for this session.',
          });
        }
      },
    },
    {
      id: 'credentials/sign-up-enabled',
      section: SECTION_CREDENTIALS,
      title: 'isSignUpEnabled, when implemented, answers a literal boolean',
      obligation: null,
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
      id: 'sessions/round-trip',
      section: SECTION_SESSIONS,
      title: 'a created session validates, and names the user it was created for',
      obligation: null,
      skipReason: requiresSessions,
      async run(provider) {
        if (!isSessionProvider(provider)) return;
        const userId = await userIdOf(provider, fixtures);

        const created = await settle(() => provider.createSession(userId));
        if (!created.ok) {
          fail(fixtures, {
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
            headline: 'createSession returned something with no session id.',
            observed: [`createSession(${show(userId)}) returned ${show(session)}.`],
            why: 'The id is the value the host puts in a cookie and hands back to `validateSession`.',
            how: 'Return a `Session`: `{ id, userId, createdAt, expiresAt }` at minimum.',
          });
        }
        if (session.userId !== userId) {
          fail(fixtures, {
            headline: 'createSession returned a session belonging to a different user.',
            observed: [`createSession(${show(userId)}) returned a session with userId ${show(session.userId)}.`],
            why: 'The host reads the user back off the session on every subsequent request.',
            how: 'Store the `userId` argument on the session unchanged.',
          });
        }

        const validated = await settle(() => provider.validateSession(session.id as string));
        if (!validated.ok || validated.value === null || validated.value === undefined) {
          fail(fixtures, {
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
      skipReason: requiresHttpHandler,
      async run(provider) {
        if (!isAuthHttpHandler(provider)) return;
        const request = new Request(`${new URL(fixtures.requestUrl).origin}/auth/api/conformance-unknown-route`);
        const outcome = await withoutNetwork(() => settle(() => provider.handleAuthRequest(request)));
        if (!outcome.ok) {
          fail(fixtures, {
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
          it(check.title, async ctx => {
            // A fresh provider per check: no check can see another's state, and
            // a provider that mutates itself on first use is exercised from a
            // clean start every time.
            const provider = await options.createProvider();
            // Safe to call unguarded: `authConformanceChecks` wraps every gate.
            const skip = check.skipReason(provider);
            if (skip !== null) {
              ctx.skip(skip);
              return;
            }
            await check.run(provider);
          });
        }
      });
    }
  });
}
