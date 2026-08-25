/**
 * The conformance suite, tested the only way a conformance suite can be.
 *
 * A suite that passes is weak evidence. This whole lane exists because an
 * undocumented contract let broken providers look fine, and a check that cannot
 * fail is indistinguishable from a provider that is correct - so the load-bearing
 * half of this file is the red half: four fakes, each correct except for one
 * obligation, each of which must turn that obligation's checks red and nothing
 * else's.
 *
 * THE PROBLEM THIS FILE HAS TO SOLVE FIRST
 *
 * You cannot write a passing vitest test that asserts a nested vitest suite
 * failed. That is why `src/conformance/` separates {@link authConformanceChecks}
 * - plain async functions that throw - from `describeAuthProvider`, which is a
 * thin `describe`/`it` adapter over them. {@link runChecks} below drives the
 * check list directly and records what each one did, so "this check went red,
 * with this message" becomes an ordinary assertion.
 *
 * The adapter is not left unproved by that split: the bottom of this file calls
 * `describeAuthProvider` for real, against the fully-capable fake, so the
 * registered suite is a suite that actually runs in CI.
 *
 * WHAT IS ASSERTED, AND WHY EACH ONE IS HERE
 *
 * 1. **Green, with nothing skipped.** Against `fullyCapableFake()` every check
 *    passes AND none is skipped. The second half is the guard against the
 *    failure mode this lane is about: a check that is silently inapplicable
 *    everywhere is a check nobody has ever run, and it would sit here green
 *    forever.
 * 2. **Red, one obligation at a time.** For each of {@link AUTH_OBLIGATIONS},
 *    `fakeViolating(obligation)` must fail at least one check tagged with that
 *    obligation and must fail no check tagged with a different one. Isolation is
 *    the claim that makes a red result evidence about one rule.
 * 3. **The skip rule.** A bearer-token validator - `kind: 'none'`, the shape
 *    Supabase and Firebase ship today - must skip the capability checks rather
 *    than fail them, and must still be held to the obligations that do not
 *    depend on a capability.
 * 4. **The messages.** Every failure this suite can produce is read by somebody
 *    who has never seen this repository, so every message is asserted to carry
 *    all four sections and a documentation URL.
 */
import { describe, expect, it } from 'vitest';
import {
  authConformanceChecks,
  describeAuthProvider,
  formatConformanceFailure,
  AUTH_OBLIGATION_COUNT,
  AUTH_OBLIGATION_GUIDANCE,
  CONFORMANCE_DOCS_URL,
} from '../conformance/index.js';
import type { AuthConformanceCheck, AuthProviderConformanceOptions } from '../conformance/index.js';
import type { IMastraAuthProvider } from '../contract.js';
import { parseStateId } from '../oauth-state.js';
import { withSyntheticOrganizations } from '../organizations.js';
import {
  AUTH_OBLIGATIONS,
  AUTH_OBLIGATION_SUMMARY,
  FAKE_COOKIE_NAME,
  FAKE_TOKEN,
  fakeProvider,
  fakeViolating,
  fullyCapableFake,
} from '../testing/index.js';
import type { AuthObligation } from '../testing/index.js';

// ============================================================================
// The harness
// ============================================================================

/** What one check did when it was run. */
type CheckOutcome =
  | { readonly status: 'passed'; readonly check: AuthConformanceCheck }
  | { readonly status: 'skipped'; readonly check: AuthConformanceCheck; readonly reason: string }
  | { readonly status: 'failed'; readonly check: AuthConformanceCheck; readonly message: string };

/**
 * Run every check the way `describeAuthProvider` runs it, and record the result
 * instead of reporting it.
 *
 * A fresh provider per check, exactly as the adapter does - otherwise a check
 * that mutated the provider would change the answer for the next one and this
 * harness would stop modelling the thing it is supposed to prove.
 */
async function runChecks(options: AuthProviderConformanceOptions): Promise<readonly CheckOutcome[]> {
  const outcomes: CheckOutcome[] = [];
  for (const check of authConformanceChecks(options)) {
    const provider = await options.createProvider();
    let reason: string | null;
    try {
      reason = check.skipReason(provider);
    } catch (error) {
      // A gate that throws is a red `it` in the adapter, because
      // `describeAuthProvider` calls `skipReason` inside the test body with
      // nothing around it. Recording it as a failure is what the reader sees.
      // `requiresBrowserSession` is the gate that can do this: it calls
      // `toAuthDescriptor`, which is documented as never throwing but is only as
      // inert as the provider's property reads are.
      outcomes.push({ status: 'failed', check, message: error instanceof Error ? error.message : String(error) });
      continue;
    }
    if (reason !== null) {
      outcomes.push({ status: 'skipped', check, reason });
      continue;
    }
    try {
      await check.run(provider);
      outcomes.push({ status: 'passed', check });
    } catch (error) {
      outcomes.push({ status: 'failed', check, message: error instanceof Error ? error.message : String(error) });
    }
  }
  return outcomes;
}

/** The options a fake is run under. The cookie and the bearer carry one token. */
function optionsFor(
  createProvider: () => IMastraAuthProvider,
  overrides: Partial<AuthProviderConformanceOptions> = {},
): AuthProviderConformanceOptions {
  return {
    name: '@mastra/auth-fake',
    createProvider,
    token: FAKE_TOKEN,
    userId: 'fake-user',
    cookieHeader: `${FAKE_COOKIE_NAME}=${FAKE_TOKEN}`,
    ...overrides,
  };
}

function ids(outcomes: readonly CheckOutcome[], status: CheckOutcome['status']): string[] {
  return outcomes.filter(outcome => outcome.status === status).map(outcome => outcome.check.id);
}

function failures(outcomes: readonly CheckOutcome[]): Extract<CheckOutcome, { status: 'failed' }>[] {
  return outcomes.filter(
    (outcome): outcome is Extract<CheckOutcome, { status: 'failed' }> => outcome.status === 'failed',
  );
}

/** Every failure, rendered the way a reader would see it. Used in failure output only. */
function report(outcomes: readonly CheckOutcome[]): string {
  return failures(outcomes)
    .map(outcome => `--- ${outcome.check.id} ---\n${outcome.message}`)
    .join('\n\n');
}

// ============================================================================
// The check list itself
// ============================================================================

describe('the check list', () => {
  const checks = authConformanceChecks(optionsFor(() => fullyCapableFake()));

  it('gives every check a unique id', () => {
    expect(new Set(checks.map(check => check.id)).size).toBe(checks.length);
  });

  it('covers every obligation named in AUTH_OBLIGATIONS', () => {
    const covered = new Set(checks.map(check => check.obligation).filter(obligation => obligation !== null));
    expect([...covered].sort()).toEqual([...AUTH_OBLIGATIONS].sort());
  });

  it('numbers every obligation section from the same source as the fakes', () => {
    for (const obligation of AUTH_OBLIGATIONS) {
      const { ordinal } = AUTH_OBLIGATION_GUIDANCE[obligation];
      const section = `obligation ${ordinal} of ${AUTH_OBLIGATIONS.length} - ${obligation}`;
      expect(checks.some(check => check.section === section)).toBe(true);
    }
  });

  it('rejects options the caller cannot have meant', () => {
    const valid = optionsFor(() => fullyCapableFake());
    expect(() => authConformanceChecks({ ...valid, name: '' })).toThrow(TypeError);
    expect(() => authConformanceChecks({ ...valid, token: '' })).toThrow(/non-empty bearer token/);
    expect(() =>
      authConformanceChecks({ ...valid, createProvider: undefined as unknown as () => IMastraAuthProvider }),
    ).toThrow(/createProvider/);
  });
});

// ============================================================================
// Green, and nothing skipped
// ============================================================================

describe('a fully-capable provider', () => {
  it('passes every check', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake()));
    expect(report(outcomes)).toBe('');
    expect(ids(outcomes, 'passed')).toHaveLength(outcomes.length);
  });

  /**
   * The anti-false-green guard, and the reason this assertion is separate from
   * the one above.
   *
   * "Every check passed" is satisfied vacuously by a suite that skipped
   * everything. The fully-capable fake declares all six optional capabilities and
   * meets all four obligations, so there is no honest reason for any check to be
   * inapplicable to it - and if one is, that check has never run anywhere and
   * nobody would find out from a green suite.
   */
  it('skips nothing, so every check in the list has actually run', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake()));
    expect(ids(outcomes, 'skipped')).toEqual([]);
  });
});

// ============================================================================
// Red, one obligation at a time
// ============================================================================

/**
 * Four demonstrations, run as a matrix rather than written out.
 *
 * Two assertions per obligation, and the second is the one that makes the first
 * mean anything. That the suite goes red for a broken provider is necessary;
 * that it goes red *only* where the break is, is what lets a reader treat the
 * failing test name as a diagnosis.
 */
describe.each(AUTH_OBLIGATIONS.map(obligation => [obligation] as const))(
  'a provider that violates only %s',
  (obligation: AuthObligation) => {
    it('fails that obligation', async () => {
      const outcomes = await runChecks(optionsFor(() => fakeViolating(obligation)));
      const failed = failures(outcomes).filter(outcome => outcome.check.obligation === obligation);
      expect(
        failed.map(outcome => outcome.check.id),
        `no check for '${obligation}' went red, so nothing proves that obligation is enforced`,
      ).not.toEqual([]);
    });

    it('fails nothing else', async () => {
      const outcomes = await runChecks(optionsFor(() => fakeViolating(obligation)));
      const collateral = failures(outcomes).filter(outcome => outcome.check.obligation !== obligation);
      expect(collateral.map(outcome => `${outcome.check.id}\n${outcome.message}`)).toEqual([]);
    });

    it('names the obligation, and explains it, in every message it produces', async () => {
      const outcomes = await runChecks(optionsFor(() => fakeViolating(obligation)));
      const { ordinal } = AUTH_OBLIGATION_GUIDANCE[obligation];
      for (const outcome of failures(outcomes)) {
        expect(outcome.message).toContain(`obligation ${ordinal} of ${AUTH_OBLIGATIONS.length}, '${obligation}'`);
        expect(outcome.message).toContain('@mastra/auth-fake');
        expect(outcome.message).toContain('OBSERVED');
        expect(outcome.message).toContain('WHY THIS EXISTS');
        expect(outcome.message).toContain('HOW TO FIX IT');
        expect(outcome.message).toContain(CONFORMANCE_DOCS_URL);
      }
    });
  },
);

describe('what each broken fake actually reports', () => {
  it('flatId: the payload is quoted, and the id keys that were looked for are named', async () => {
    const outcomes = await runChecks(optionsFor(() => fakeViolating('flatId')));
    const failed = failures(outcomes);
    expect(failed.map(outcome => outcome.check.id)).toEqual(['obligation/flatId']);
    expect(failed[0]?.message).toContain('toAuthIdentity found no id in it');
    expect(failed[0]?.message).toContain('`id`, then `uid`, then `sub`');
    expect(failed[0]?.message).toContain('profile');
  });

  it('cookieAuth: the Cookie header that was sent is quoted back', async () => {
    const outcomes = await runChecks(optionsFor(() => fakeViolating('cookieAuth')));
    const failed = failures(outcomes);
    expect(failed.map(outcome => outcome.check.id)).toEqual(['obligation/cookieAuth']);
    expect(failed[0]?.message).toContain(`Cookie: ${FAKE_COOKIE_NAME}=${FAKE_TOKEN}`);
    expect(failed[0]?.message).toContain('the Cookie header is not being');
    expect(failed[0]?.message).toContain('getRequestHeader');
  });

  it('stateCodec: both halves of the round trip go red, and each says which half', async () => {
    const outcomes = await runChecks(optionsFor(() => fakeViolating('stateCodec')));
    const failed = failures(outcomes);
    expect(failed.map(outcome => outcome.check.id)).toEqual([
      'obligation/stateCodec/login-url',
      'obligation/stateCodec/callback',
    ]);
    expect(failed[0]?.message).toContain('The value was re-encoded on the way out');
    expect(failed[0]?.message).toContain('parseStateId(echoed)');
    expect(failed[1]?.message).toContain('rejected a state its own getLoginUrl was just handed');
    expect(failed[1]?.message).toContain('before reaching the token exchange');
  });

  it('organizationId: the undefined answer is quoted, and the wrapper is named', async () => {
    const outcomes = await runChecks(optionsFor(() => fakeViolating('organizationId')));
    const failed = failures(outcomes);
    expect(failed.map(outcome => outcome.check.id)).toEqual(['obligation/organizationId/deterministic']);
    expect(failed[0]?.message).toContain('resolved to undefined');
    expect(failed[0]?.message).toContain('withSyntheticOrganizations');
  });
});

// ============================================================================
// The defect that actually shipped
// ============================================================================

/**
 * A hosted-login provider that keeps a state store, keyed one way and read
 * another.
 *
 * `fakeViolating('stateCodec')` breaks the obligation by re-encoding `state`,
 * which is one of the two ways to break it. The other is the one that shipped:
 * `auth/okta` echoes `state` through the authorization URL perfectly - so the
 * round-trip check is green on it - and then stores its state entry under
 * `parseStateId(state)` while `handleCallback` looks the value up verbatim. Every
 * sign-in fails at the callback with "invalid or expired state", and the package
 * has no `handleCallback` coverage at all, which is why it shipped.
 *
 * Reproducing that shape here is what turns "the suite goes red for our own
 * fake" into "the suite goes red for the bug this lane exists because of". It
 * also pins the division of labour between the two `stateCodec` checks: this
 * provider fails exactly one of them, and the re-encoding fake fails the other.
 *
 * @param storeKey how `getLoginUrl` keys its entry
 * @param lookupKey how `handleCallback` looks it up
 */
function ssoWithStateStore(storeKey: (state: string) => string, lookupKey: (state: string) => string) {
  const base = fullyCapableFake();
  const states = new Map<string, { redirectUri: string }>();
  return {
    ...base,
    getLoginUrl(redirectUri: string, state: string): string {
      states.set(storeKey(state), { redirectUri });
      const url = new URL('https://idp.test/v1/authorize');
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('state', state);
      return url.toString();
    },
    async handleCallback(code: string, state: string) {
      if (!states.has(lookupKey(state))) throw new Error('Invalid or expired state parameter');
      // A correct provider gets this far and exchanges the code. There is no
      // network under conformance, which is precisely how the check can tell
      // "accepted the state" from "rejected it".
      await fetch('https://idp.test/v1/token', { method: 'POST' });
      return base.handleCallback(code, state);
    },
  };
}

const wholeState = (state: string) => state;
const idHalfOfState = (state: string) => parseStateId(state) ?? state;

describe('a provider whose state store is keyed one way and read another', () => {
  it('passes the round-trip check, because it echoes state perfectly', async () => {
    const outcomes = await runChecks(optionsFor(() => ssoWithStateStore(idHalfOfState, wholeState)));
    expect(ids(outcomes, 'passed')).toContain('obligation/stateCodec/login-url');
  });

  it('fails the callback check, and nothing else', async () => {
    const outcomes = await runChecks(optionsFor(() => ssoWithStateStore(idHalfOfState, wholeState)));
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['obligation/stateCodec/callback']);
    expect(failures(outcomes)[0]?.message).toContain('Invalid or expired state parameter');
    expect(failures(outcomes)[0]?.message).toContain('before reaching the token exchange');
  });

  /**
   * The positive control, and the reason the check above is not just "any error
   * fails".
   *
   * Keyed and read the same way, this provider accepts the state and goes on to
   * the token exchange - which throws, because the suite removed the network.
   * That failure must be recognized as success. Without this assertion the
   * callback check would pass every provider that throws for any reason, which
   * is every provider.
   */
  it('passes once both halves use the same key, even though the exchange cannot complete', async () => {
    const outcomes = await runChecks(optionsFor(() => ssoWithStateStore(wholeState, wholeState)));
    expect(report(outcomes)).toBe('');
    expect(ids(outcomes, 'passed')).toContain('obligation/stateCodec/callback');
  });

  it('leaves globalThis.fetch exactly as it found it', async () => {
    const before = globalThis.fetch;
    await runChecks(optionsFor(() => ssoWithStateStore(wholeState, wholeState)));
    expect(globalThis.fetch).toBe(before);
  });
});

// ============================================================================
// The skip rule
// ============================================================================

describe('a bearer-token validator', () => {
  /** `kind: 'none'`: no hosted login, no credentials, no sessions, no routes. */
  const bearerOnly = () => fakeProvider({ user: { organizationId: undefined } });

  it('skips every capability check rather than failing it', async () => {
    const outcomes = await runChecks(optionsFor(bearerOnly));
    expect(ids(outcomes, 'skipped').sort()).toEqual(
      [
        'credentials/sign-up-enabled',
        'init/accepts-host-context',
        'obligation/cookieAuth',
        'obligation/stateCodec/callback',
        'obligation/stateCodec/login-url',
        'routes/answers-a-response',
        'sessions/round-trip',
        'sso/login-button',
        'sso/logout-url',
      ].sort(),
    );
  });

  it('explains every skip in terms of a guard the provider does not satisfy', async () => {
    const outcomes = await runChecks(optionsFor(bearerOnly));
    for (const outcome of outcomes) {
      if (outcome.status !== 'skipped') continue;
      expect(outcome.reason.length, `${outcome.check.id} skipped with an empty reason`).toBeGreaterThan(0);
      expect(outcome.reason).toMatch(/is false|does not implement|cannot put a session in a browser/);
    }
  });

  /**
   * The obligation that is deliberately NOT gated on its own guard.
   *
   * Gating obligation 4 on `isOrganizationsProvider` would skip it for exactly
   * the providers it exists to catch. This is the assertion that pins that
   * decision: a provider with no organizations fails, and it fails here rather
   * than passing quietly.
   */
  it('still fails obligation 4, because that obligation is not gated on its own guard', async () => {
    const outcomes = await runChecks(optionsFor(bearerOnly));
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['obligation/organizationId/declared']);
    expect(failures(outcomes)[0]?.message).toContain('isOrganizationsProvider(provider) is false');
    expect(failures(outcomes)[0]?.message).toContain('deliberately not skipped');
  });

  it('passes in full once it is wrapped with withSyntheticOrganizations', async () => {
    const outcomes = await runChecks(optionsFor(() => withSyntheticOrganizations(bearerOnly())));
    expect(report(outcomes)).toBe('');
    expect(ids(outcomes, 'failed')).toEqual([]);
    // The capability checks are still skipped; wrapping adds organizations, not a browser sign-in.
    expect(ids(outcomes, 'skipped')).toContain('obligation/stateCodec/login-url');
    expect(ids(outcomes, 'passed')).toContain('obligation/organizationId/deterministic');
  });
});

// ============================================================================
// Fixtures the caller has to supply, and what happens when they do not
// ============================================================================

describe('missing fixtures are reported as missing fixtures', () => {
  it('asks for cookieHeader rather than failing obligation 2 for its absence', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake(), { cookieHeader: undefined }));
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'obligation/cookieAuth');
    expect(failed?.message).toContain('needs its `cookieHeader` fixture');
    // Not reported as an obligation failure: a suite that cannot tell a missing
    // fixture from a broken provider produces false reds that read as true ones.
    expect(failed?.message).not.toContain("does not meet obligation 2 of 4, 'cookieAuth'");
  });

  it('reports a rejected token fixture as a token problem, not as four unrelated defects', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake(), { token: 'a-token-nothing-accepts' }));
    for (const outcome of failures(outcomes)) {
      expect(outcome.message).toContain('rejected the token this suite was told the provider accepts');
    }
    expect(failures(outcomes).length).toBeGreaterThan(0);
  });

  it('asks for userId when obligation 1 is broken and no id can be read back', async () => {
    const outcomes = await runChecks(optionsFor(() => fakeViolating('flatId'), { userId: undefined }));
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'obligation/organizationId/deterministic');
    expect(failed?.message).toContain('This check needs a user id');
    expect(failed?.message).toContain('Setting it is');
  });
});

// ============================================================================
// The red half for every check that is not an obligation
// ============================================================================

/**
 * The other twelve checks, each shown going red.
 *
 * The four obligations have had a demonstrably-failing fake since this suite
 * shipped, and the twelve contract and capability checks have not. A green run
 * against `fullyCapableFake()` says nothing about them: a check whose condition
 * can never be true passes every provider, and it passes them *silently*, which
 * is the exact failure this whole lane exists because of. `contract/rejects-
 * unknown-token` is the sharpest case - its own message calls it "the one check
 * in the suite whose failure is a security finding" - and until now no test had
 * ever seen it fail.
 *
 * One row per way a check can go red. Each builds the fully-capable fake and
 * breaks exactly one thing, so the failure set is the claim: `fails` is what must
 * go red and nothing else may.
 */
type Broken = Partial<Record<string, unknown>>;

/** The fully-capable fake with one member replaced. Everything else is intact. */
function brokenFake(overrides: Broken): IMastraAuthProvider {
  return { ...(fullyCapableFake() as unknown as Broken), ...overrides } as unknown as IMastraAuthProvider;
}

/** A payload that `JSON.stringify` cannot render, for the reporter's last resort. */
function circularPayload(): Record<string, unknown> {
  const payload: Record<string, unknown> = { id: 'fake-user' };
  payload.self = payload;
  return payload;
}

interface RedCase {
  /** What was broken, as the `it` title reads it. */
  readonly label: string;
  /** The provider under test. */
  readonly provider: () => IMastraAuthProvider;
  /** Every check id that must go red, and no other may. */
  readonly fails: readonly string[];
  /** Which of them {@link says} is about. Defaults to the first. */
  readonly about?: string;
  /** Text the reader has to find in that check's message. */
  readonly says: RegExp;
  /** Options the case needs beyond the defaults. */
  readonly options?: Partial<AuthProviderConformanceOptions>;
}

const RED_CASES: readonly RedCase[] = [
  {
    label: 'authorizeUser is missing entirely, so this is not a provider',
    provider: () => brokenFake({ authorizeUser: undefined }),
    fails: ['contract/shape', 'contract/authorize-user'],
    says: /provider\.authorizeUser is undefined, not a function/,
  },
  {
    label: 'name is set to something that is not a string',
    provider: () => brokenFake({ name: 42 }),
    fails: ['contract/shape'],
    says: /provider\.name is 42, which is neither a string nor absent/,
  },
  {
    label: 'authenticateToken is missing, so nothing downstream can be asked anything',
    provider: () => brokenFake({ authenticateToken: undefined }),
    fails: [
      'contract/shape',
      'contract/rejects-unknown-token',
      'contract/authorize-user',
      'contract/map-user-to-resource-id',
      'obligation/flatId',
      'obligation/cookieAuth',
      // The organization checks read an identity back before they compare the
      // host-side resolver against it, so this one reports the same root cause
      // rather than an organization defect.
      'obligation/organizationId/deterministic',
    ],
    says: /provider\.authenticateToken is undefined, not a function/,
  },
  {
    label: 'authenticateToken resolves a different user than the token belongs to',
    provider: () =>
      brokenFake({
        async authenticateToken(token: string, request: Request) {
          // A session id where a user id belongs - the `{ session, user }`
          // mistake, in the shape that succeeds rather than the shape that
          // returns null. The request authenticates and the data lands under a
          // key that is not that person's. Both paths agree, so obligation 2 is
          // untouched and this is a claim about obligation 1 alone.
          const cookie = request.headers.get('cookie') ?? '';
          const presented = token === FAKE_TOKEN || cookie.includes(FAKE_TOKEN);
          return presented ? { id: 'sess_abc', organizationId: 'fake-org' } : null;
        },
      }),
    fails: ['obligation/flatId'],
    says: /resolved to a different user than the one this token belongs to/,
  },
  {
    label: 'the cookie and the bearer token authenticate two different people',
    provider: () =>
      brokenFake({
        async authenticateToken(token: string, request: Request) {
          if (token === FAKE_TOKEN) return { id: 'fake-user', organizationId: 'fake-org' };
          if (token !== '') return null;
          const cookie = request.headers.get('cookie') ?? '';
          // Two verification paths that have drifted, which is how they always
          // drift: one of them was written later, for the browser.
          return cookie.includes(FAKE_TOKEN) ? { id: 'somebody-else', organizationId: 'fake-org' } : null;
        },
      }),
    fails: ['obligation/cookieAuth'],
    says: /The cookie authenticated a different user than the bearer token did/,
  },
  {
    label: 'a property read on the provider throws, so the descriptor cannot be derived',
    provider: () => {
      const provider = brokenFake({});
      Object.defineProperty(provider, 'signIn', {
        get() {
          throw new Error('this getter has side effects');
        },
        configurable: true,
      });
      return provider;
    },
    // Only `contract/descriptor` reports this properly. The other two are gates
    // that read `signIn` while deciding whether to skip - `requiresBrowserSession`
    // through `toAuthDescriptor`, and `requiresCredentials` directly - and a gate
    // throws outside any check body, so it surfaces as a raw error rather than as
    // this suite's own diagnosis. See the note on the gate in `runChecks`.
    fails: ['contract/descriptor', 'credentials/sign-up-enabled', 'obligation/cookieAuth'],
    says: /toAuthDescriptor threw while inspecting this provider/,
  },
  {
    label: 'every token authenticates, including one the provider should not know',
    provider: () => fullyCapableFake({ token: [FAKE_TOKEN, 'conformance-rejected-token'] }),
    fails: ['contract/rejects-unknown-token'],
    says: /accepted a token it should not recognize/,
  },
  {
    label: 'an unknown token throws instead of resolving null',
    provider: () =>
      brokenFake({
        async authenticateToken(token: string) {
          if (token !== FAKE_TOKEN) throw new Error('jwt malformed');
          return { id: 'fake-user', organizationId: 'fake-org' };
        },
      }),
    // The cookie path goes through the same method, so obligation 2 sees the
    // throw as well. That is honest rather than collateral: this provider really
    // does reject a browser navigation.
    fails: ['contract/rejects-unknown-token', 'obligation/cookieAuth'],
    says: /threw for an unknown token instead of resolving null/,
  },
  {
    label: 'an empty token authenticates, so every anonymous request is somebody',
    provider: () =>
      brokenFake({
        async authenticateToken() {
          return { id: 'fake-user', organizationId: 'fake-org' };
        },
      }),
    fails: ['contract/rejects-unknown-token', 'contract/rejects-anonymous-request'],
    about: 'contract/rejects-anonymous-request',
    says: /authenticated a request carrying no credentials at all/,
  },
  {
    label: 'authorizeUser answers with an un-awaited Promise',
    provider: () => brokenFake({ authorizeUser: () => Promise.resolve as unknown as boolean }),
    fails: ['contract/authorize-user'],
    says: /answered with something other than a boolean/,
  },
  {
    label: 'authorizeUser throws for a payload its own authenticateToken produced',
    provider: () =>
      brokenFake({
        authorizeUser: () => {
          throw new Error('policy engine unreachable');
        },
      }),
    fails: ['contract/authorize-user'],
    says: /threw for a payload its own authenticateToken produced/,
  },
  {
    label: 'mapUserToResourceId names a different user than the identity does',
    provider: () => brokenFake({ mapUserToResourceId: () => 'some-other-key' }),
    fails: ['contract/map-user-to-resource-id'],
    says: /disagree about who this payload is/,
  },
  {
    label: 'getLoginUrl throws for a state in this package’s format',
    provider: () =>
      brokenFake({
        getLoginUrl: () => {
          throw new Error('state must be a UUID');
        },
      }),
    fails: ['obligation/stateCodec/login-url'],
    says: /getLoginUrl threw for a state in this package/,
  },
  {
    label: 'getLoginUrl returns a path rather than an absolute URL',
    provider: () => brokenFake({ getLoginUrl: () => '/authorize?state=x' }),
    fails: ['obligation/stateCodec/login-url'],
    says: /did not return an absolute URL/,
  },
  {
    label: 'the authorization URL carries no state at all',
    provider: () => brokenFake({ getLoginUrl: () => 'https://fake-idp.test/authorize?redirect_uri=x' }),
    fails: ['obligation/stateCodec/login-url'],
    says: /no `state` query parameter, so nothing comes back on the callback/,
  },
  {
    label: 'ensureOrganization throws instead of resolving an organization',
    provider: () =>
      brokenFake({
        async ensureOrganization() {
          throw new Error('organization directory unavailable');
        },
      }),
    fails: ['obligation/organizationId/deterministic'],
    says: /ensureOrganization threw instead of resolving an organization id/,
  },
  {
    label: 'ensureOrganization mints a fresh organization on every call',
    provider: () => {
      let issued = 0;
      return brokenFake({
        async ensureOrganization() {
          issued += 1;
          return `org_${issued}`;
        },
      });
    },
    fails: ['obligation/organizationId/deterministic'],
    says: /not deterministic: two calls for one user gave two organizations/,
  },
  {
    label: 'getLoginButtonConfig returns a control with no label on it',
    provider: () => brokenFake({ getLoginButtonConfig: () => ({ provider: 'fake', text: '' }) }),
    fails: ['sso/login-button'],
    says: /config\.text is "", expected a non-empty string/,
  },
  {
    label: 'getLoginButtonConfig names no provider',
    provider: () => brokenFake({ getLoginButtonConfig: () => ({ text: 'Sign in' }) }),
    fails: ['sso/login-button'],
    says: /config\.provider is undefined, expected a non-empty string/,
  },
  {
    label: 'createSession throws, so a successful sign-in has nowhere to go',
    provider: () =>
      brokenFake({
        async createSession() {
          throw new Error('session store not configured');
        },
      }),
    fails: ['sessions/round-trip'],
    says: /createSession threw/,
  },
  {
    label: 'getLoginButtonConfig throws, so the sign-in screen is blank',
    provider: () =>
      brokenFake({
        getLoginButtonConfig: () => {
          throw new Error('no branding configured');
        },
      }),
    fails: ['sso/login-button'],
    says: /getLoginButtonConfig threw/,
  },
  {
    label: 'getLogoutUrl answers a relative path rather than an absolute URL',
    provider: () => brokenFake({ getLogoutUrl: () => '/logout' }),
    fails: ['sso/logout-url'],
    says: /answered something that is not an absolute URL/,
  },
  {
    label: 'getLogoutUrl throws instead of answering null',
    provider: () =>
      brokenFake({
        getLogoutUrl: () => {
          throw new Error('no session to end');
        },
      }),
    fails: ['sso/logout-url'],
    says: /getLogoutUrl threw/,
  },
  {
    // Not the async case, which this check cannot currently see: `settle` awaits
    // the return value, so an `async isSignUpEnabled()` arrives as the boolean it
    // resolves to and the check passes. That is the one shape the check's own
    // message says it exists for, and it is a defect in `src/conformance/index.ts`
    // rather than a gap in this file - see the standing note below this table.
    label: 'isSignUpEnabled answers a truthy string rather than a boolean',
    provider: () => brokenFake({ isSignUpEnabled: () => 'yes' }),
    fails: ['credentials/sign-up-enabled'],
    says: /did not answer a literal boolean/,
  },
  {
    label: 'createSession returns a session with no id',
    provider: () => brokenFake({ createSession: async () => ({ userId: 'fake-user' }) }),
    fails: ['sessions/round-trip'],
    says: /createSession returned something with no session id/,
  },
  {
    label: 'createSession files the session under a different user',
    provider: () =>
      brokenFake({ createSession: async () => ({ id: 'sess-1', userId: 'somebody-else', metadata: undefined }) }),
    fails: ['sessions/round-trip'],
    says: /returned a session belonging to a different user/,
  },
  {
    label: 'a session that was just created does not validate',
    provider: () => brokenFake({ validateSession: async () => null }),
    fails: ['sessions/round-trip'],
    says: /rejected a session this provider had just created/,
  },
  {
    label: 'destroySession does nothing, so "sign out everywhere" is a lie',
    provider: () => brokenFake({ destroySession: async () => {} }),
    fails: ['sessions/round-trip'],
    says: /A destroyed session still validates/,
  },
  {
    label: 'handleAuthRequest answers something that is not a Response',
    provider: () => brokenFake({ handleAuthRequest: async () => ({ status: 404 }) }),
    fails: ['routes/answers-a-response'],
    says: /resolved to something that is not a Response/,
  },
  {
    label: 'handleAuthRequest throws for a route it does not serve',
    provider: () =>
      brokenFake({
        handleAuthRequest: async () => {
          throw new Error('unknown route');
        },
      }),
    fails: ['routes/answers-a-response'],
    says: /threw for a route it does not serve/,
  },
  {
    label: 'init refuses to start over a field the host did not pass',
    provider: () =>
      brokenFake({
        init: async () => {
          throw new Error('AuthInitContext.database is required');
        },
      }),
    fails: ['init/accepts-host-context'],
    says: /init threw for a host context carrying only a public URL and allowed origins/,
  },
];

describe.each(RED_CASES.map(redCase => [redCase.label, redCase] as const))(
  'a provider where %s',
  (_label: string, redCase: RedCase) => {
    it('fails exactly the checks that are about it', async () => {
      const outcomes = await runChecks(optionsFor(redCase.provider, redCase.options));
      expect(
        failures(outcomes)
          .map(outcome => outcome.check.id)
          .sort(),
      ).toEqual([...redCase.fails].sort());
    });

    it('says what went wrong in terms the provider author can act on', async () => {
      const outcomes = await runChecks(optionsFor(redCase.provider, redCase.options));
      const about = redCase.about ?? redCase.fails[0]!;
      const failed = failures(outcomes).find(outcome => outcome.check.id === about);
      expect(failed, `${about} did not fail`).toBeDefined();
      expect(failed!.message).toMatch(redCase.says);
      // Every failure this suite emits is read by somebody who has never seen
      // this repository, contract failures included.
      expect(failed!.message).toContain('OBSERVED');
      expect(failed!.message).toContain('WHY THIS EXISTS');
      expect(failed!.message).toContain('HOW TO FIX IT');
      expect(failed!.message).toContain(CONFORMANCE_DOCS_URL);
    });
  },
);

/**
 * A standing note, because a reader of the table above will look for it.
 *
 * `credentials/sign-up-enabled` cannot fail for an `async isSignUpEnabled()`,
 * which is the exact shape its own failure text is written about. `settle`
 * awaits what the method returns, so a Promise resolving to `true` reaches the
 * check as the boolean `true` and passes. `toAuthDescriptor` meanwhile treats
 * that provider as sign-up-disabled, because it reads the Promise without
 * awaiting and anything that is not literally `true` answers `false`. So the two
 * halves of this package disagree about the same provider, and the half whose job
 * is to notice is the half that cannot.
 *
 * Left as a finding rather than fixed here: the change is one line in
 * `src/conformance/index.ts`, but it turns a green suite red for any published
 * provider that has an async check, which is a decision for whoever owns that
 * file rather than for a test sweep.
 */
describe('a provider that cannot be asked anything', () => {
  /**
   * `authenticateToken` throws for the token the suite was told it accepts.
   *
   * Distinct from the existing "rejected token fixture" case, which resolves
   * null. A throw takes a different branch and produces different guidance -
   * "your provider is not offline" rather than "your token is wrong" - and the
   * checks that need an authenticated payload before they can ask their own
   * question have to report that one fact rather than their own downstream
   * confusion.
   */
  const throwsOnEverything = () =>
    brokenFake({
      async authenticateToken() {
        throw new Error('getaddrinfo ENOTFOUND idp.test');
      },
    });

  it('reports the throw as a fixture problem in every check that needs a payload', async () => {
    const outcomes = await runChecks(optionsFor(throwsOnEverything));
    const needAPayload = ['contract/authorize-user', 'contract/map-user-to-resource-id', 'obligation/flatId'];
    for (const id of needAPayload) {
      const failed = failures(outcomes).find(outcome => outcome.check.id === id);
      expect(failed, `${id} did not fail`).toBeDefined();
      expect(failed!.message).toContain('threw for the token this suite was told the provider accepts');
    }
  });

  it('tells the reader the provider is not offline, which is the usual cause', async () => {
    const outcomes = await runChecks(optionsFor(throwsOnEverything));
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'contract/authorize-user');
    expect(failed?.message).toContain('is not offline');
    expect(failed?.message).toContain('ENOTFOUND');
  });
});

describe('a payload the reporter cannot serialize', () => {
  /**
   * `show()` renders every OBSERVED line, and its last resort is the branch
   * nothing reached: a value `JSON.stringify` throws on. A circular payload is
   * not exotic - an ORM row with a back-reference is one - and a reporter that
   * threw while rendering a failure would replace "your provider is wrong" with
   * "the conformance suite crashed".
   */
  it('renders a circular payload instead of throwing while reporting', async () => {
    const outcomes = await runChecks(
      optionsFor(() =>
        brokenFake({
          async authenticateToken() {
            return circularPayload();
          },
        }),
      ),
    );
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'contract/rejects-unknown-token');
    expect(failed?.message).toContain('[object Object]');
  });
});

// ============================================================================
// The obligations, numbered from one source
// ============================================================================

describe('the obligation roster', () => {
  it('counts the obligations rather than restating how many there are', () => {
    expect(AUTH_OBLIGATION_COUNT).toBe(AUTH_OBLIGATIONS.length);
    // The number a provider author reads in "obligation 2 of 4". A literal here
    // would agree with a stale count; this pins that the two come from the same
    // array, which is the property that matters when a fifth is added.
    expect(AUTH_OBLIGATION_COUNT).toBeGreaterThan(0);
  });

  it('gives each obligation guidance that is about that obligation', () => {
    // The copy-paste this catches: guidance for `stateCodec` carrying
    // `obligation: 'cookieAuth'`. Nothing else compares the key with the field,
    // and the failure it produces - a message that names the wrong obligation and
    // explains the wrong problem - looks like a correct message to every
    // assertion that only checks the sections are present.
    for (const obligation of AUTH_OBLIGATIONS) {
      const guidance = AUTH_OBLIGATION_GUIDANCE[obligation];
      expect(guidance.obligation, `guidance under '${obligation}' names a different obligation`).toBe(obligation);
      expect(guidance.summary).toBe(AUTH_OBLIGATION_SUMMARY[obligation]);
      expect(guidance.why.length).toBeGreaterThan(0);
      expect(guidance.how.length).toBeGreaterThan(0);
    }
  });

  it('numbers them 1..n in the order the roster lists them', () => {
    const ordinals = AUTH_OBLIGATIONS.map(obligation => AUTH_OBLIGATION_GUIDANCE[obligation].ordinal);
    expect(ordinals).toEqual(AUTH_OBLIGATIONS.map((_obligation, index) => index + 1));
  });

  it('explains every obligation the roster names, and no more', () => {
    expect(Object.keys(AUTH_OBLIGATION_GUIDANCE).sort()).toEqual([...AUTH_OBLIGATIONS].sort());
  });
});

// ============================================================================
// The message format
// ============================================================================

describe('failure messages', () => {
  it('carry a headline, an observation, a reason, a fix and a URL', () => {
    const message = formatConformanceFailure({
      provider: '@mastra/auth-example',
      obligation: 'cookieAuth',
      observed: ['authenticateToken("", request) resolved to null.'],
    });

    expect(message.split('\n')[0]).toBe(
      "Auth conformance violation: @mastra/auth-example does not meet obligation 2 of 4, 'cookieAuth'.",
    );
    expect(message).toContain(AUTH_OBLIGATION_GUIDANCE.cookieAuth.summary);
    expect(message).toContain('OBSERVED');
    expect(message).toContain('WHY THIS EXISTS');
    expect(message).toContain('HOW TO FIX IT');
    expect(message.trimEnd().endsWith(CONFORMANCE_DOCS_URL)).toBe(true);
  });

  it('drops the obligation ordinal for a plain contract failure', () => {
    const message = formatConformanceFailure({
      provider: '@mastra/auth-example',
      headline: 'getLoginButtonConfig returned a config a UI cannot render.',
      observed: ['config.text is undefined.'],
      why: 'Because.',
      how: 'Return one.',
    });
    expect(message.split('\n')[0]).toBe(
      'Auth conformance violation: @mastra/auth-example does not meet the provider contract.',
    );
    expect(message).not.toContain('obligation');
  });

  it('refuses to render a failure that explains nothing', () => {
    expect(() =>
      formatConformanceFailure({ provider: '@mastra/auth-example', observed: ['something went wrong'] }),
    ).toThrow(/has to explain itself/);
  });

  it('points at a URL rather than at a path inside this repository', () => {
    expect(CONFORMANCE_DOCS_URL.startsWith('https://')).toBe(true);
  });
});

// ============================================================================
// The vitest adapter, running for real
// ============================================================================

/**
 * The drop-in integration, exercised as a consumer writes it.
 *
 * Everything above drives the check list directly, which proves the checks and
 * says nothing about the twelve lines that register them. This is those twelve
 * lines: if `describeAuthProvider` stopped registering a suite, stopped awaiting
 * `createProvider`, or reported a skip as a pass, the tests it contributes here
 * would vanish or go red.
 */
describeAuthProvider({
  name: '@mastra/auth-fake (the kit’s own fully-capable fake)',
  createProvider: () => fullyCapableFake(),
  token: FAKE_TOKEN,
  userId: 'fake-user',
  cookieHeader: `${FAKE_COOKIE_NAME}=${FAKE_TOKEN}`,
});

/**
 * The same adapter, on the shape that actually skips.
 *
 * The registration above proves the adapter registers and runs, and it can prove
 * nothing about the branch that reports a check as skipped - the fully-capable
 * fake declares every capability, so that branch never executes. This one does:
 * a bearer-token validator wrapped for organizations passes every check that
 * applies to it and skips nine that do not.
 *
 * The distinction is the whole reason `describeAuthProvider` calls `ctx.skip`
 * with a reason rather than quietly passing. A suite where "not applicable" and
 * "correct" look identical goes green for a provider nobody checked, and this is
 * the run where a reader can see the difference in the output.
 */
describeAuthProvider({
  name: '@mastra/auth-fake (a bearer-token validator, wrapped for organizations)',
  createProvider: () => withSyntheticOrganizations(fakeProvider({ user: { organizationId: undefined } })),
  token: FAKE_TOKEN,
  userId: 'fake-user',
});
