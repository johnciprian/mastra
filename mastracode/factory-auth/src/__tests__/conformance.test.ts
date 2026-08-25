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
  AUTH_OBLIGATION_GUIDANCE,
  CONFORMANCE_DOCS_URL,
} from '../conformance/index.js';
import type { AuthConformanceCheck, AuthProviderConformanceOptions } from '../conformance/index.js';
import type { IMastraAuthProvider } from '../contract.js';
import { parseStateId } from '../oauth-state.js';
import { withSyntheticOrganizations } from '../organizations.js';
import {
  AUTH_OBLIGATIONS,
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
    const reason = check.skipReason(provider);
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
