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
import { toAuthDescriptor } from '../capabilities.js';
import {
  authConformanceChecks,
  describeAuthProvider,
  formatConformanceFailure,
  runAuthConformanceCheck,
  AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX,
  AUTH_OBLIGATION_COUNT,
  AUTH_OBLIGATION_GUIDANCE,
  CONFORMANCE_DOCS_URL,
  isFixtureFailureCode,
  KNOWN_FAILURE_TITLE_PREFIX,
} from '../conformance/index.js';
import type {
  AuthConformanceCheck,
  AuthConformanceKnownFailure,
  AuthConformanceOutcome,
  AuthProviderConformanceOptions,
} from '../conformance/index.js';
import {
  canClearSession,
  canManageSessions,
  hasAuthInit,
  isAuthHttpHandler,
  isCredentialsProvider,
  isOrganizationsProvider,
  isSessionProvider,
  isSSOProvider,
  isUserProvider,
} from '../contract.js';
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
import type { AuthObligation, FullyCapableFake } from '../testing/index.js';

// ============================================================================
// The harness
// ============================================================================

/** What one check did when it was run, with the check it did it for attached. */
type CheckOutcome = AuthConformanceOutcome & { readonly check: AuthConformanceCheck };

/**
 * Run every check the way `describeAuthProvider` runs it, and record the result
 * instead of reporting it.
 *
 * It runs it that way in the strongest available sense: the loop below calls
 * the same {@link runAuthConformanceCheck} the vitest adapter calls, so the
 * skip rule, the failure reporting and the whole known-failure policy are
 * proved here in the one implementation that also ships. A harness with its own
 * copy of the rules would go on passing after the two drifted, and the thing it
 * would stop proving is exactly the thing it exists to prove.
 *
 * A fresh provider per check, exactly as the adapter does - otherwise a check
 * that mutated the provider would change the answer for the next one and this
 * harness would stop modelling the thing it is supposed to prove.
 */
async function runChecks(options: AuthProviderConformanceOptions): Promise<readonly CheckOutcome[]> {
  const outcomes: CheckOutcome[] = [];
  for (const check of authConformanceChecks(options)) {
    const provider = await options.createProvider();
    try {
      outcomes.push({ ...(await runAuthConformanceCheck(check, provider, options.name)), check });
    } catch (error) {
      // `runAuthConformanceCheck` is not supposed to throw: a gate that reads a
      // broken provider is wrapped by `authConformanceChecks`, and a check body
      // that throws is caught and reported. Reaching here means one of those
      // stopped being true, so it is recorded as a failure that names itself
      // rather than aborting the run with a bare stack.
      outcomes.push({
        status: 'failed',
        check,
        code: null,
        message: `runAuthConformanceCheck threw instead of reporting: ${
          error instanceof Error ? error.message : String(error)
        }`,
      });
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
  /**
   * Every capability the kit knows about, PKCE included.
   *
   * `fullyCapableFake()` alone is one short of that: `withSSO` installs
   * `getLoginCookies` only when asked - a fake that always had it could not
   * model the provider that does not - and it does not install
   * `setCallbackCookieHeader` at all. So `sso/pkce-round-trip` would be skipped
   * here, and a check skipped against the one provider that declares everything
   * is a check nobody has ever run.
   *
   * {@link withPkceLoginCookie} adds both halves and makes the second one
   * load-bearing: its `handleCallback` refuses without the verifier in the
   * header it was handed, so this fake passes by completing the round trip
   * rather than by owning two method names. Folding the pair into `withSSO`
   * itself, behind a `loginCookies` option that also installs a read side, is
   * the tidier home for it and is a change to the published testing surface.
   */
  const fullyCapable = () => withPkceLoginCookie('stores');

  it('passes every check', async () => {
    const outcomes = await runChecks(optionsFor(fullyCapable));
    expect(report(outcomes)).toBe('');
    expect(ids(outcomes, 'passed')).toHaveLength(outcomes.length);
  });

  /**
   * The anti-false-green guard, and the reason this assertion is separate from
   * the one above.
   *
   * "Every check passed" is satisfied vacuously by a suite that skipped
   * everything. The fully-capable fake declares every optional capability and
   * meets all four obligations, so there is no honest reason for any check to be
   * inapplicable to it - and if one is, that check has never run anywhere and
   * nobody would find out from a green suite.
   */
  it('skips nothing, so every check in the list has actually run', async () => {
    const outcomes = await runChecks(optionsFor(fullyCapable));
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
// The provider that reaches the network and hides that it did
// ============================================================================

/**
 * A hosted-login provider that swallows the transport failure, which is the
 * shape that produced this suite's one known misdiagnosis.
 *
 * `@mastra/auth-studio`'s `handleCallback` reaches the token exchange, catches
 * whatever the network did, and rethrows a flat `Error('Session validation
 * failed')` with no `cause`. The `cause`-chain recognizer therefore finds
 * nothing, and the check used to report "handleCallback rejected a state its own
 * getLoginUrl was just handed" - a sentence about `state`, said about a method
 * whose `state` parameter is named `_state` and is never read. That is a false
 * red that reads exactly like a true one, which is the specific outcome this
 * package exists to prevent.
 *
 * The fix is not to pass it. The suite now separates two questions it was
 * previously answering as one - did the provider reach the network, and did it
 * explain what happened there - by counting calls to the stubbed `fetch` during
 * `handleCallback`. It stays red, because something here is genuinely wrong and
 * the suite cannot see what; it just stops naming the wrong thing.
 *
 * @param attachCause whether the rethrown error carries the original, which is
 * the one-argument fix the failure recommends
 */
function ssoThatSwallowsTheTransportError(attachCause: boolean) {
  const base = fullyCapableFake();
  return {
    ...base,
    getLoginUrl(redirectUri: string, state: string): string {
      const url = new URL('https://idp.test/v1/authorize');
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('state', state);
      return url.toString();
    },
    async handleCallback(code: string, _state: string) {
      try {
        await fetch('https://idp.test/v1/token', { method: 'POST' });
      } catch (error) {
        throw new Error('Session validation failed', attachCause ? { cause: error } : undefined);
      }
      return base.handleCallback(code, _state);
    },
  };
}

/** The one outcome for the callback check. */
function callbackOutcome(outcomes: readonly CheckOutcome[]): CheckOutcome {
  const outcome = outcomes.find(candidate => candidate.check.id === 'obligation/stateCodec/callback');
  expect(outcome, 'the callback check did not run').toBeDefined();
  return outcome!;
}

describe('a provider that reaches the token exchange and rethrows without a cause', () => {
  const swallowing = () => ssoThatSwallowsTheTransportError(false);

  it('is still red, because the suite genuinely cannot tell whether it conforms', async () => {
    const outcomes = await runChecks(optionsFor(swallowing));
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['obligation/stateCodec/callback']);
  });

  /**
   * The misdiagnosis, asserted as absent. This is the load-bearing half: the
   * check was already red for this provider before the change, and being red
   * for the wrong stated reason is what sent somebody to debug `state` keying in
   * a method that never reads `state`.
   */
  it('no longer claims the state was rejected', async () => {
    const outcomes = await runChecks(optionsFor(swallowing));
    const failed = failures(outcomes)[0]!;
    expect(failed.message).not.toContain('rejected a state its own getLoginUrl was just handed');
    expect(failed.message).not.toContain('the provider stopped at the state');
  });

  it('says what it actually observed: fetch was called, so the state was accepted', async () => {
    const outcomes = await runChecks(optionsFor(swallowing));
    const failed = failures(outcomes)[0]!;
    expect(failed.code).toBe('obligation/stateCodec/callback#threw-without-cause-after-token-exchange');
    expect(failed.message).toContain('called globalThis.fetch 1 time(s)');
    expect(failed.message).toContain('accepted the state and got as far as the token exchange');
    expect(failed.message).toContain('a diagnosis problem, not necessarily a `state` problem');
  });

  it('names the one-argument fix, and the escape hatch as the fallback', async () => {
    const outcomes = await runChecks(optionsFor(swallowing));
    const failed = failures(outcomes)[0]!;
    expect(failed.message).toContain('cause: error');
    expect(failed.message).toContain('sso.reachedTokenExchange');
  });

  it('passes once the cause is attached, with no other change', async () => {
    const outcomes = await runChecks(optionsFor(() => ssoThatSwallowsTheTransportError(true)));
    expect(report(outcomes)).toBe('');
    expect(ids(outcomes, 'passed')).toContain('obligation/stateCodec/callback');
  });

  /**
   * The pre-existing escape hatch keeps working and keeps taking precedence.
   * A provider whose transport is not global `fetch` had no other option, and
   * this change must not take it away from them.
   */
  it('still honours sso.reachedTokenExchange, which runs before any of this', async () => {
    const outcomes = await runChecks(
      optionsFor(swallowing, {
        sso: { reachedTokenExchange: error => error instanceof Error && error.message.includes('Session validation') },
      }),
    );
    expect(report(outcomes)).toBe('');
  });

  /**
   * The other half of the claim, and the reason the pass condition was NOT
   * widened to "fetch was called".
   *
   * A provider that stops at the state makes no network attempt, and that is now
   * asserted rather than inferred: the message says fetch was never called. Had
   * "fetch was called" been made to mean "conforming", a provider that fetched a
   * discovery document and then rejected the state would go green on a check it
   * fails - a silent false green, which is worse than a loud wrong reason.
   */
  it('keeps the state-rejection diagnosis for a provider that never reaches the network', async () => {
    const outcomes = await runChecks(optionsFor(() => ssoWithStateStore(idHalfOfState, wholeState)));
    const failed = failures(outcomes)[0]!;
    expect(failed.code).toBe('obligation/stateCodec/callback#state-rejected');
    expect(failed.message).toContain('rejected a state its own getLoginUrl was just handed');
    expect(failed.message).toContain('it was never called');
  });

  it('records as a known failure like any other red, under its own code', async () => {
    const outcomes = await runChecks(
      optionsFor(swallowing, {
        knownFailures: [
          {
            check: 'obligation/stateCodec/callback',
            code: 'obligation/stateCodec/callback#threw-without-cause-after-token-exchange',
            reason: 'handleCallback swallows the transport error. Tracked separately.',
          },
        ],
      }),
    );
    expect(report(outcomes)).toBe('');
    expect(callbackOutcome(outcomes).status).toBe('knownFailure');
  });

  it('leaves globalThis.fetch exactly as it found it', async () => {
    const before = globalThis.fetch;
    await runChecks(optionsFor(swallowing));
    expect(globalThis.fetch).toBe(before);
  });
});

// ============================================================================
// The PKCE cookie round trip
// ============================================================================

/** The cookie the fakes below stash a code verifier in. */
const PKCE_COOKIE_NAME = 'fake_pkce_verifier';

/** What is in it. A real provider mints one per login; a constant is enough here. */
const PKCE_VERIFIER = 'fake-code-verifier';

/** Which halves of the login-cookie loop a fake implements. */
type PkceReadSide =
  /** `getLoginCookies` and nothing else. The defect `sso/pkce-round-trip` exists for. */
  | 'none'
  /** Both halves declared, and the read half stores nothing. `auth/studio` ships exactly this. */
  | 'noop'
  /** Both halves, and the verifier survives the trip. */
  | 'stores';

/**
 * A fully-capable provider that carries a PKCE verifier in a login cookie.
 *
 * The point of the fake is that its `handleCallback` genuinely *needs* the
 * cookie: it refuses unless the verifier is in the header it was handed, the
 * way a real PKCE provider refuses without a code verifier to send to the token
 * endpoint. So `'stores'` passes `sso/pkce-round-trip` by completing the round
 * trip, and `'noop'` fails it despite declaring both method names - which is the
 * difference between the strong version of this check and the weak one.
 *
 * @param readSide which halves to install; see {@link PkceReadSide}
 */
function withPkceLoginCookie(readSide: PkceReadSide): FullyCapableFake {
  const base = fullyCapableFake();
  let received: string | null = null;

  const provider: FullyCapableFake = {
    ...base,
    getLoginCookies(): string[] {
      return [`${PKCE_COOKIE_NAME}=${PKCE_VERIFIER}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`];
    },
    async handleCallback(code: string, state: string) {
      if (received === null || !received.includes(`${PKCE_COOKIE_NAME}=${PKCE_VERIFIER}`)) {
        throw new Error('missing code verifier: no PKCE cookie reached handleCallback');
      }
      return base.handleCallback(code, state);
    },
  };

  if (readSide !== 'none') {
    provider.setCallbackCookieHeader = (cookieHeader: string | null): void => {
      if (readSide === 'stores') received = cookieHeader;
    };
  }
  return provider;
}

function pkceOutcome(outcomes: readonly CheckOutcome[]): CheckOutcome {
  return outcomes.find(outcome => outcome.check.id === 'sso/pkce-round-trip')!;
}

describe('a provider that carries a PKCE verifier in a login cookie', () => {
  /**
   * The direction the whole check exists for.
   *
   * `getLoginCookies` is declared and hands back a real cookie; nothing declares
   * a way to read one. Before this check a provider in that shape passed all
   * eighteen and was told it was done, and every sign-in through it failed at the
   * callback for a verifier that was written and never read.
   */
  it('fails when the write half is declared and the read half is not', async () => {
    const outcomes = await runChecks(optionsFor(() => withPkceLoginCookie('none')));
    const outcome = pkceOutcome(outcomes);
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe('sso/pkce-round-trip#no-read-side');
    expect(outcome.status === 'failed' && outcome.message).toContain('provider.setCallbackCookieHeader is undefined');
    expect(outcome.status === 'failed' && outcome.message).toContain(PKCE_COOKIE_NAME);
  });

  /**
   * The other direction, and the reason the check is not "do both methods
   * exist".
   *
   * This fake declares both halves. The read half is a no-op, which satisfies
   * every structural guard there is and delivers nothing - the shape
   * `auth/studio` ships today. A check that stopped at the method names would
   * pass it.
   */
  it('fails when both halves are declared and the value does not survive the trip', async () => {
    const outcomes = await runChecks(optionsFor(() => withPkceLoginCookie('noop')));
    const outcome = pkceOutcome(outcomes);
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe('sso/pkce-round-trip#cookie-not-read-back');
    expect(outcome.status === 'failed' && outcome.message).toContain('missing code verifier');
    expect(outcome.status === 'failed' && outcome.message).toContain('The read half is declared and stores nothing');
  });

  /** The green direction, which is what makes the two reds above mean anything. */
  it('passes once the verifier written at login is readable at the callback', async () => {
    const outcomes = await runChecks(optionsFor(() => withPkceLoginCookie('stores')));
    expect(report(outcomes)).toBe('');
    expect(pkceOutcome(outcomes).status).toBe('passed');
  });

  /**
   * The skip, and why it is a skip rather than a red.
   *
   * A provider with no `getLoginCookies` carries nothing across the round trip.
   * `auth/okta` is that provider on purpose - a confidential client
   * authenticating with `client_secret` has no verifier to stash - and failing it
   * for the absence of a read side it has nothing to read would be a false red.
   */
  it('skips for a hosted-login provider that sets no cookies at all', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake()));
    const outcome = pkceOutcome(outcomes);
    expect(outcome.status).toBe('skipped');
    expect(outcome.status === 'skipped' && outcome.reason).toContain('getLoginCookies is not implemented');
  });

  /**
   * The middle case, which is a pass and not a skip, and the distinction is the
   * skip rule.
   *
   * `getLoginCookies` is declared, so the check applies and runs. It hands back
   * nothing, so there is no cookie to hold anybody to - which is the honest
   * answer for the four providers in this repository that declare the method and
   * return `[]`. Skipping here would say the check did not apply to a provider it
   * did apply to.
   */
  it.each([
    ['an empty list', (): string[] => []],
    ['undefined', (): undefined => undefined],
  ])('passes, rather than skipping, for a provider that declares the method and returns %s', async (_label, answer) => {
    const noCookies = (): FullyCapableFake => ({ ...fullyCapableFake(), getLoginCookies: answer });
    const outcomes = await runChecks(optionsFor(noCookies));
    expect(pkceOutcome(outcomes).status).toBe('passed');
    expect(report(outcomes)).toBe('');
  });

  /**
   * The interaction that made this check worth landing with the obligation-3
   * change beside it.
   *
   * A correct PKCE provider throws for a missing verifier before it ever looks
   * at `state`, so `obligation/stateCodec/callback` used to report it as having
   * "rejected a state its own getLoginUrl was just handed" - a sentence about a
   * value that call never read. That check now performs the browser's half of the
   * trip too, so its finding is about `state` again.
   */
  it('leaves the state-codec callback check able to ask its own question', async () => {
    const outcomes = await runChecks(optionsFor(() => withPkceLoginCookie('stores')));
    const stateCodec = outcomes.find(outcome => outcome.check.id === 'obligation/stateCodec/callback')!;
    expect(stateCodec.status).toBe('passed');
  });

  /**
   * And when the cookie loop is the thing that is broken, obligation 3 says so
   * rather than sending the reader after a `state` nobody rejected.
   */
  it('points at the PKCE check from the state-codec failure when a cookie was handed back', async () => {
    const outcomes = await runChecks(optionsFor(() => withPkceLoginCookie('noop')));
    const stateCodec = outcomes.find(outcome => outcome.check.id === 'obligation/stateCodec/callback')!;
    expect(stateCodec.status).toBe('failed');
    expect(stateCodec.status === 'failed' && stateCodec.message).toContain(
      'handed back through setCallbackCookieHeader',
    );
    expect(stateCodec.status === 'failed' && stateCodec.message).toContain('sso/pkce-round-trip');
  });

  it('leaves globalThis.fetch exactly as it found it', async () => {
    const before = globalThis.fetch;
    await runChecks(optionsFor(() => withPkceLoginCookie('none')));
    expect(globalThis.fetch).toBe(before);
  });
});

// ============================================================================
// Half an interface
// ============================================================================

function usersOutcome(outcomes: readonly CheckOutcome[], id: string): CheckOutcome {
  return outcomes.find(outcome => outcome.check.id === id)!;
}

describe('a provider that implements half of IUserProvider', () => {
  /**
   * `getCurrentUser` and no `getUser`.
   *
   * `isUserProvider` tests both members `IUserProvider` requires, so this
   * provider fails the guard - and a host branching on the guard therefore
   * treats it as having no user directory at all, silently losing the half it
   * did implement. That is the defect, and it is why the gate for this section
   * asks whether EITHER member is present rather than asking the guard. Gating
   * on the guard would skip exactly the provider these checks exist to find.
   */
  const halfAUserProvider = () => brokenFake({ getUser: undefined });

  it('does not satisfy the guard, because the guard requires both members', () => {
    expect(isUserProvider(halfAUserProvider())).toBe(false);
  });

  it('fails rather than skipping, because half an interface is a defect and not a smaller capability', async () => {
    const outcomes = await runChecks(optionsFor(halfAUserProvider));
    const outcome = usersOutcome(outcomes, 'users/get-user');
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe('users/get-user#not-declared');
  });

  it('names both members and what the guard makes of them', async () => {
    const outcomes = await runChecks(optionsFor(halfAUserProvider));
    const outcome = usersOutcome(outcomes, 'users/get-user');
    expect(outcome.status === 'failed' && outcome.message).toContain('isUserProvider(provider) is false');
    expect(outcome.status === 'failed' && outcome.message).toContain('provider.getUser        is undefined');
  });

  /** One defect, one failure: the other half of the section still runs. */
  it('leaves getCurrentUser’s own check able to pass', async () => {
    const outcomes = await runChecks(optionsFor(halfAUserProvider));
    expect(usersOutcome(outcomes, 'users/current-user').status).toBe('passed');
  });

  /** The mirror: `getUser` and no `getCurrentUser` is the same defect, reported by the other check. */
  it('fails the other way round too', async () => {
    const outcomes = await runChecks(optionsFor(() => brokenFake({ getCurrentUser: undefined })));
    const outcome = usersOutcome(outcomes, 'users/current-user');
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe('users/current-user#not-declared');
    expect(usersOutcome(outcomes, 'users/get-user').status).toBe('passed');
  });

  /**
   * The skip, and why it is a skip rather than a red.
   *
   * A provider with neither member declares no user directory at all, and
   * nothing in a host asks it who is signed in. `supabase` and `firebase` are
   * that shape today. Failing them for a capability they never claimed is the
   * false red the skip rule exists to prevent. Neither member is a decision;
   * one of the two is a half-finished job, which is why that fails instead.
   */
  it('skips both checks for a provider that declares no user directory', async () => {
    const outcomes = await runChecks(optionsFor(() => withSyntheticOrganizations(fakeProvider())));
    for (const id of ['users/current-user', 'users/get-user']) {
      const outcome = usersOutcome(outcomes, id);
      expect(outcome.status, id).toBe('skipped');
      expect(outcome.status === 'skipped' && outcome.reason).toContain('neither getCurrentUser nor getUser');
    }
  });

  /**
   * And the answer that is a pass rather than a red, for the same reason
   * `sso/pkce-round-trip` passes a provider that hands back no cookies.
   *
   * `null` is what `IUserProvider` documents for a user who is not found, and
   * for `getCurrentUser` it is the ordinary answer on a request with no
   * session. Four providers in this repository return it from `getUser`
   * unconditionally because they have no directory to search. The check applied
   * and ran; there was no user to hold anybody to.
   */
  it('passes a provider whose lookups resolve null, rather than demanding a user', async () => {
    const outcomes = await runChecks(
      optionsFor(() => brokenFake({ getCurrentUser: async () => null, getUser: async () => null })),
    );
    expect(report(outcomes)).toBe('');
    expect(usersOutcome(outcomes, 'users/current-user').status).toBe('passed');
    expect(usersOutcome(outcomes, 'users/get-user').status).toBe('passed');
  });

  /**
   * The security half of the user section, kept separate because it is the one
   * failure here that is not about a wrong name on a screen.
   *
   * A provider that answers `getCurrentUser` off a field cached on the instance
   * rather than off the request answers it for everybody. The credentialled
   * probe cannot see that - it gets the right user - so the check asks a second
   * time with a request carrying nothing at all.
   */
  it('fails a getCurrentUser that answers for a request carrying no credentials', async () => {
    const outcomes = await runChecks(
      optionsFor(() => brokenFake({ getCurrentUser: async () => ({ id: 'fake-user' }) })),
    );
    const outcome = usersOutcome(outcomes, 'users/current-user');
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe('users/current-user#authenticated-anonymous-request');
    expect(outcome.status === 'failed' && outcome.message).toContain('no headers at all');
    expect(outcome.status === 'failed' && outcome.message).toContain('cached on the instance');
  });
});

// ============================================================================
// Half an interface, for every interface
// ============================================================================

/** The check that reports a capability interface carried in part. */
const WHOLE_CAPABILITIES = 'contract/whole-capabilities';

/**
 * The eight capability interfaces, their guards, and every member each
 * requires - written out here rather than imported from the roster the check
 * reads.
 *
 * That duplication is the point. Importing `src/conformance/index.ts`'s roster
 * would make this file agree with whatever that file says, which is not a
 * property worth asserting. Written out, the two are independent, and the
 * assertions below hold *three* lists in step: this table, that roster, and the
 * structural guards `@mastra/core/server` actually ships. A member that core
 * adds to a guard and nobody adds here shows up as a guard that does not flip.
 */
interface CapabilityCase {
  /** The interface, as `@mastra/core/server` spells it. */
  readonly name: string;

  /** Its guard, as `./contract` re-exports it. */
  readonly guard: (provider: unknown) => boolean;

  /** Every member it requires. Optional members are not listed and not tested. */
  readonly members: readonly string[];

  /**
   * The code `contract/whole-capabilities` fails under for this interface, or
   * `null` when it never reports this one.
   *
   * `null` for the three one-member interfaces, which cannot be carried in
   * part, and for `IUserProvider`, whose halves are reported member by member
   * by {@link reportedFor}.
   */
  readonly code: string | null;

  /**
   * Which check reports the absence of each member, when it is not the general
   * one. Only `IUserProvider` has these.
   */
  readonly reportedFor?: Readonly<Record<string, string>>;

  /**
   * Member sets that are a whole declared interface of their own, and therefore
   * a supported shape rather than half of this one.
   */
  readonly wholeSubsets?: readonly (readonly string[])[];

  /** Checks that go red alongside, when one member of this interface is taken away. */
  readonly alsoFails?: readonly string[];

  /**
   * The code a partial carry of this interface is reported under, when that is
   * not {@link code}.
   *
   * `code` answers "what slug does this interface contribute to the check's own
   * roster", and `ISessionManager` contributes none - half of it is half an
   * `ISessionProvider` too, so a slug of its own would name one defect twice.
   * But it is still reported, under the wider interface's slug, and the subset
   * test below needs to know which. Two questions that used to have one field.
   */
  readonly reportsAs?: string;
}

const CAPABILITY_CASES: readonly CapabilityCase[] = [
  {
    name: 'ISSOProvider',
    guard: isSSOProvider,
    members: ['getLoginUrl', 'handleCallback', 'getLoginButtonConfig'],
    code: `${WHOLE_CAPABILITIES}#partial-sso`,
  },
  {
    name: 'ISessionProvider',
    guard: isSessionProvider,
    members: [
      'createSession',
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ],
    code: `${WHOLE_CAPABILITIES}#partial-sessions`,
    // The two legitimate proper subsets in the contract, and the reason this
    // whole check could not be written before P11. The session interfaces are a
    // chain - `ISessionProvider extends ISessionManager extends ISessionClearer`
    // - so each rung is the whole of a declared interface rather than a fraction
    // of a bigger one. `@mastra/auth-better-auth` sits on the first,
    // `@mastra/auth-workos` on the second.
    wholeSubsets: [
      ['getClearSessionHeaders'],
      [
        'validateSession',
        'destroySession',
        'refreshSession',
        'getSessionIdFromRequest',
        'getSessionHeaders',
        'getClearSessionHeaders',
      ],
    ],
  },
  {
    name: 'ISessionManager',
    guard: canManageSessions,
    members: [
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ],
    // Reported as `#partial-sessions`, because half an `ISessionManager` is
    // necessarily half an `ISessionProvider` too. A slug here would name one
    // defect twice.
    code: null,
    reportsAs: `${WHOLE_CAPABILITIES}#partial-sessions`,
    // No whole subsets FROM THIS FRAME, even though `ISessionManager extends
    // ISessionClearer` at the type level. `carrying` strips members of the case's
    // own list and leaves the rest of the fully-capable fake alone, so every
    // subset here still carries `createSession` - which makes it a partial
    // `ISessionProvider` whatever else it has. The clearer-alone exemption is
    // real and is exercised from the `ISessionProvider` frame above, where all
    // seven come off.
    // Every member of this one is a member of `ISessionProvider`, so taking any
    // away leaves a partial of that. Same finding from the other end, as with
    // `ISessionClearer` below.
    alsoFails: [WHOLE_CAPABILITIES],
  },
  {
    name: 'ISessionClearer',
    guard: canClearSession,
    members: ['getClearSessionHeaders'],
    code: null,
    // Its only member is also a member of `ISessionProvider`, so taking it away
    // from the fully-capable fake leaves six sevenths of that one behind. The
    // general check reports it under `#partial-sessions`; that is the same
    // finding seen from the other end, not a second defect.
    alsoFails: [WHOLE_CAPABILITIES],
  },
  {
    name: 'IUserProvider',
    guard: isUserProvider,
    members: ['getCurrentUser', 'getUser'],
    code: null,
    reportedFor: { getCurrentUser: 'users/current-user', getUser: 'users/get-user' },
  },
  {
    name: 'ICredentialsProvider',
    guard: isCredentialsProvider,
    members: ['signIn', 'signUp'],
    code: `${WHOLE_CAPABILITIES}#partial-credentials`,
  },
  {
    name: 'IOrganizationsProvider',
    guard: isOrganizationsProvider,
    members: ['ensureOrganization', 'isOrganizationAdmin'],
    code: `${WHOLE_CAPABILITIES}#partial-organizations`,
    // Obligation 4 is deliberately not gated on the guard, so a provider that
    // loses either organization member fails it as well. Two findings about one
    // provider, and both are true: it half-implements the interface, and it
    // resolves no organization.
    alsoFails: ['obligation/organizationId/declared'],
  },
  {
    name: 'IAuthHttpHandler',
    guard: isAuthHttpHandler,
    members: ['handleAuthRequest'],
    code: null,
  },
  {
    name: 'IAuthInit',
    guard: hasAuthInit,
    members: ['init'],
    code: null,
  },
];

/** `contract/whole-capabilities`, run on its own against one provider. */
async function wholeCapabilitiesOutcome(provider: IMastraAuthProvider): Promise<AuthConformanceOutcome> {
  const check = authConformanceChecks(optionsFor(() => provider)).find(
    candidate => candidate.id === WHOLE_CAPABILITIES,
  );
  expect(check, `${WHOLE_CAPABILITIES} is not in the check list`).toBeDefined();
  return runAuthConformanceCheck(check!, provider, '@mastra/auth-fake');
}

/** The fully-capable fake with these members taken off. Everything else is intact. */
function lacking(members: readonly string[]): IMastraAuthProvider {
  return brokenFake(Object.fromEntries(members.map(member => [member, undefined])));
}

/** The fully-capable fake carrying exactly `keep` of `capability`'s members. */
function carrying(capability: CapabilityCase, keep: readonly string[]): IMastraAuthProvider {
  return lacking(capability.members.filter(member => !keep.includes(member)));
}

/** Every non-empty proper subset of `members`. 126 of them for `ISessionProvider`. */
function properSubsets(members: readonly string[]): string[][] {
  const subsets: string[][] = [];
  for (let mask = 1; mask < (1 << members.length) - 1; mask += 1) {
    subsets.push(members.filter((_member, index) => (mask & (1 << index)) !== 0));
  }
  return subsets;
}

function isWholeSubset(capability: CapabilityCase, subset: readonly string[]): boolean {
  return (capability.wholeSubsets ?? []).some(
    whole => whole.length === subset.length && whole.every(member => subset.includes(member)),
  );
}

describe('the capability roster the general check reads', () => {
  /**
   * Every guard, so the roster is the contract's roster rather than a list of
   * the interesting cases.
   *
   * `./contract` re-exports exactly eight, and `public-surface.test.ts` fails if
   * that set changes without its inventory changing - so a ninth guard arriving
   * from core is caught there, and this is where it has to be given a member
   * list before the general check can see it.
   */
  it('covers every capability guard the contract re-exports', () => {
    expect(new Set(CAPABILITY_CASES.map(capability => capability.guard))).toEqual(
      new Set([
        isSSOProvider,
        isSessionProvider,
        canClearSession,
        canManageSessions,
        isUserProvider,
        isCredentialsProvider,
        isOrganizationsProvider,
        isAuthHttpHandler,
        hasAuthInit,
      ]),
    );
  });

  /**
   * The seam between this table and the roster inside the check.
   *
   * A code is a value downstream suites hold in a `knownFailures` entry, so the
   * set of them is a published surface. An interface added to the roster with a
   * slug and no case here, or a case here naming a code the check cannot
   * produce, both land on this assertion.
   */
  it('declares one failure code for each interface it reports, and no others', () => {
    const check = authConformanceChecks(optionsFor(() => fullyCapableFake())).find(
      candidate => candidate.id === WHOLE_CAPABILITIES,
    );
    expect([...check!.failureCodes].sort()).toEqual(
      CAPABILITY_CASES.flatMap(capability => (capability.code === null ? [] : [capability.code])).sort(),
    );
  });
});

describe.each(CAPABILITY_CASES.map(capability => [capability.name, capability] as const))(
  '%s, carried whole and carried in part',
  (_name: string, capability: CapabilityCase) => {
    /** The green half. A check that cannot pass is as useless as one that cannot fail. */
    it('passes for a provider that carries all of it', async () => {
      expect(capability.guard(fullyCapableFake())).toBe(true);
      const outcome = await wholeCapabilitiesOutcome(fullyCapableFake());
      expect(outcome.status, JSON.stringify(outcome)).toBe('passed');
    });

    /**
     * The member list above, held against the guard core actually ships.
     *
     * Both directions, because one alone proves half of it. Removing any member
     * has to flip the guard, which shows the guard tests at least these; an
     * object carrying exactly these has to satisfy it, which shows it tests no
     * more. Together they pin the list, and a member core adds or drops shows up
     * here rather than as a partial shape the check silently cannot see.
     */
    it('has a guard that tests exactly the members this table lists', () => {
      const exactly = Object.fromEntries(capability.members.map(member => [member, () => {}]));
      expect(capability.guard(exactly), `${capability.name} rejects an object carrying exactly its members`).toBe(true);
      for (const member of capability.members) {
        expect(capability.guard(lacking([member])), `removing ${member} did not flip the guard`).toBe(false);
      }
    });

    const subsets = properSubsets(capability.members);
    if (subsets.length > 0) {
      it(`answers for every one of the ${subsets.length} ways to carry part of it`, async () => {
        // What a partial carry reports under, which is this interface's own slug
        // where it has one and the wider interface's where it does not.
        const reportedAs = capability.code ?? capability.reportsAs ?? null;
        for (const subset of subsets) {
          const outcome = await wholeCapabilitiesOutcome(carrying(capability, subset));
          const passes = reportedAs === null || isWholeSubset(capability, subset);
          expect(outcome.status, `carrying [${subset.join(', ')}]: ${JSON.stringify(outcome)}`).toBe(
            passes ? 'passed' : 'failed',
          );
          if (!passes) {
            expect(outcome.status === 'failed' && outcome.code, `carrying [${subset.join(', ')}]`).toBe(reportedAs);
          }
        }
      });
    }

    /**
     * One defect, one failure - and where a second failure is legitimate, it is
     * named rather than tolerated.
     */
    it.each(capability.members.map(member => [member] as const))(
      'goes red exactly where the defect is when %s is missing',
      async (member: string) => {
        const outcomes = await runChecks(optionsFor(() => lacking([member])));
        // Taking one member off can land on a smaller declared interface rather
        // than on a fraction of this one - dropping `createSession` from
        // `ISessionProvider` leaves a whole `ISessionManager`. That is the
        // supported shape, so nothing is red. Asked as a rule rather than
        // spelled out per member, so a subset declared later is covered the day
        // it lands.
        const remainder = capability.members.filter(other => other !== member);
        const stillWhole = isWholeSubset(capability, remainder);
        const expected = [
          ...(capability.code === null || stillWhole ? [] : [WHOLE_CAPABILITIES]),
          ...(capability.reportedFor?.[member] === undefined ? [] : [capability.reportedFor[member]]),
          ...(stillWhole ? [] : (capability.alsoFails ?? [])),
        ];
        expect(
          failures(outcomes)
            .map(outcome => outcome.check.id)
            .sort(),
          report(outcomes),
        ).toEqual([...expected].sort());
      },
    );
  },
);

/**
 * The shape that made this check unwritable until P11, passing.
 *
 * `@mastra/auth-better-auth` implements `getClearSessionHeaders` and none of the
 * other six `ISessionProvider` members: it owns the cookie it set during
 * sign-in and has to clear it on sign-out, and it creates no session a host can
 * address by id. Before `ISessionClearer` was declared, that was a convention
 * hosts read structurally and no interface described - indistinguishable, from
 * the outside, from a session provider somebody stopped writing. It is now a
 * declared one-member interface with its own guard, which is what lets the
 * general check exempt it by rule rather than by name.
 */
describe('a provider that owns a session cookie and nothing else', () => {
  const sessions = CAPABILITY_CASES.find(capability => capability.name === 'ISessionProvider')!;
  const cookieOwner = () => carrying(sessions, ['getClearSessionHeaders']);

  it('is a whole ISessionClearer and not a partial ISessionProvider', () => {
    expect(canClearSession(cookieOwner())).toBe(true);
    expect(isSessionProvider(cookieOwner())).toBe(false);
  });

  it('passes the general check, because a declared smaller interface is not half a bigger one', async () => {
    const outcome = await wholeCapabilitiesOutcome(cookieOwner());
    expect(outcome.status, JSON.stringify(outcome)).toBe('passed');
  });

  it('fails nothing else either', async () => {
    const outcomes = await runChecks(optionsFor(cookieOwner));
    expect(report(outcomes)).toBe('');
  });

  /** And the moment it grows a second session member, it is half an interface again. */
  it('goes red as soon as it carries one more session member', async () => {
    const outcome = await wholeCapabilitiesOutcome(carrying(sessions, ['getClearSessionHeaders', 'createSession']));
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe(`${WHOLE_CAPABILITIES}#partial-sessions`);
  });
});

describe('what a half-implemented interface actually reports', () => {
  it('names the interface, the guard, the missing member and the section that went silent', async () => {
    const outcome = await wholeCapabilitiesOutcome(lacking(['getLoginButtonConfig']));
    expect(outcome.status).toBe('failed');
    const message = outcome.status === 'failed' ? outcome.message : '';
    expect(message).toContain('This provider implements part of ISSOProvider');
    expect(message).toContain('ISSOProvider requires 3 members, and this provider carries 2 of them');
    expect(message).toContain('provider.getLoginButtonConfig is undefined   <- missing');
    expect(message).toContain('isSSOProvider(provider) is false');
    expect(message).toContain('Every check in this section of the run was skipped');
    expect(message).toContain('hosted login (ISSOProvider)');
    expect(message).toContain('no authorization URL is ever built');
    expect(message).toContain('ISSOProvider still needs:');
    // The four sections and the URL, like every other message this suite emits.
    expect(message).toContain('OBSERVED');
    expect(message).toContain('WHY THIS EXISTS');
    expect(message).toContain('HOW TO FIX IT');
    expect(message).toContain(CONFORMANCE_DOCS_URL);
    // And the offer, so a provider that cannot finish the interface today can
    // record it rather than excluding itself from the run.
    expect(message).toContain('knownFailures');
    expect(message).toContain(`${WHOLE_CAPABILITIES}#partial-sso`);
  });

  /**
   * The sessions message carries the one piece of advice no other interface
   * needs: there is a declared smaller interface, and implementing that is a
   * real answer rather than a workaround.
   */
  it('points a would-be session provider at ISessionClearer', async () => {
    const outcome = await wholeCapabilitiesOutcome(lacking(['refreshSession']));
    const message = outcome.status === 'failed' ? outcome.message : '';
    expect(message).toContain('`ISessionClearer` requires `getClearSessionHeaders` and');
    expect(message).toContain('canClearSession');
  });

  /**
   * Two half-implemented interfaces, one check, and a reader who is told about
   * both. A check stops at its first failure, so the second would otherwise be
   * invisible until the first was fixed.
   */
  it('names the other interfaces it found, having stopped at the first', async () => {
    const outcome = await wholeCapabilitiesOutcome(lacking(['getLoginButtonConfig', 'signUp']));
    const message = outcome.status === 'failed' ? outcome.message : '';
    expect(outcome.status === 'failed' && outcome.code).toBe(`${WHOLE_CAPABILITIES}#partial-sso`);
    expect(message).toContain('One other interface is half-implemented too');
    expect(message).toContain('fixing this one surfaces: ICredentialsProvider');
  });

  /**
   * And the interface that is reported somewhere better: the reader is told
   * where, rather than told nothing.
   */
  it('points at the user checks for a half-implemented IUserProvider', async () => {
    const outcome = await wholeCapabilitiesOutcome(lacking(['getLoginButtonConfig', 'getUser']));
    const message = outcome.status === 'failed' ? outcome.message : '';
    expect(message).toContain('IUserProvider is also half-implemented');
    expect(message).toContain('users/current-user and users/get-user');
  });

  /**
   * A property read with side effects is `contract/descriptor`'s finding, and
   * this check has to stay quiet about it. Reporting it here as well would turn
   * one defect into two, and the second would name capabilities rather than the
   * getter that broke.
   */
  it('says nothing for a provider whose property read throws', async () => {
    const provider = brokenFake({});
    Object.defineProperty(provider, 'signUp', {
      get() {
        throw new Error('this getter has side effects');
      },
      configurable: true,
    });
    const outcome = await wholeCapabilitiesOutcome(provider);
    expect(outcome.status, JSON.stringify(outcome)).toBe('passed');
  });

  /**
   * A provider with no optional capability at all declares nothing, so there is
   * nothing to be half of. The empty set is not a finding.
   */
  it('passes a bearer-token validator that declares no capability at all', async () => {
    const outcome = await wholeCapabilitiesOutcome(withSyntheticOrganizations(fakeProvider()));
    expect(outcome.status, JSON.stringify(outcome)).toBe('passed');
  });
});

// ============================================================================
// The one answer whose wrong value is a grant of rights
// ============================================================================

function adminOutcome(outcomes: readonly CheckOutcome[]): CheckOutcome {
  return outcomes.find(outcome => outcome.check.id === 'organizations/is-admin')!;
}

describe('a provider that answers isOrganizationAdmin for an organization it never created', () => {
  /**
   * The direction the whole check exists for, and the only one in this suite
   * where a green would hand somebody rights over another user's data.
   *
   * `admin: true` is a provider whose membership lookup finds nothing and falls
   * through to a default of yes. Every structural guard passes it, obligation 4
   * passes it - `ensureOrganization` is perfectly correct - and it makes the
   * organization id in a URL into an administrator role in that organization.
   */
  const alwaysAdmin = () => fullyCapableFake({ organizations: { admin: true } });

  it('fails, with the invented id quoted so the reader can see it was invented', async () => {
    const outcomes = await runChecks(optionsFor(alwaysAdmin));
    const outcome = adminOutcome(outcomes);
    expect(outcome.status).toBe('failed');
    expect(outcome.status === 'failed' && outcome.code).toBe('organizations/is-admin#admin-of-an-unknown-organization');
    expect(outcome.status === 'failed' && outcome.message).toContain('conformance-organization-nobody-created');
    expect(outcome.status === 'failed' && outcome.message).toContain('The suite made it up');
  });

  it('fails nothing else, so the red is evidence about the admin answer alone', async () => {
    const outcomes = await runChecks(optionsFor(alwaysAdmin));
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['organizations/is-admin']);
  });

  /**
   * The direction that must stay green, and the reason this check does not
   * simply assert `true` for the provider's own organization.
   *
   * `@mastra/auth-studio` answers `false` on a cold cache: it has no session
   * cookie for the user yet, so it cannot know their role, and it says no. That
   * is the correct answer to "cannot tell" and it must not be a conformance
   * failure - a check that demanded `true` would turn every fail-closed
   * provider red and teach the fix "return true when you are not sure".
   */
  it('passes a provider that answers false for its own organization', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake({ organizations: { admin: false } })));
    expect(report(outcomes)).toBe('');
    expect(adminOutcome(outcomes).status).toBe('passed');
  });

  /**
   * The wrapper is the recommended fix, so it has to survive the check that
   * recommends it. `withSyntheticOrganizations` decides both directions itself
   * for ids in its own namespace and never delegates them, which is exactly the
   * behaviour asked for here.
   */
  it('passes a bearer-token validator wrapped with withSyntheticOrganizations', async () => {
    const outcomes = await runChecks(optionsFor(() => withSyntheticOrganizations(fakeProvider())));
    expect(adminOutcome(outcomes).status).toBe('passed');
  });

  /**
   * And the wrapper still refuses when the provider underneath it is the
   * fail-open one, because it never asks about an id it minted. This is the
   * assertion that says the recommended fix is a fix rather than a way to get
   * the check to stop asking.
   */
  it('passes once a fail-open provider is wrapped, because synthetic ids are never delegated', async () => {
    const outcomes = await runChecks(
      optionsFor(() => withSyntheticOrganizations(fakeProvider({ user: { organizationId: undefined } }))),
    );
    expect(adminOutcome(outcomes).status).toBe('passed');
  });

  /** The obligation-4 fake still reports one defect, and it is obligation 4's. */
  it('does not add a second red to a provider that resolves no organization at all', async () => {
    const outcomes = await runChecks(optionsFor(() => fakeViolating('organizationId')));
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['obligation/organizationId/deterministic']);
    expect(adminOutcome(outcomes).status).toBe('passed');
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
        // Not `obligation/organizationId/declared`, which is the check that
        // reports the absence of organizations and is deliberately ungated.
        // This one is about the answer a provider with organizations gives.
        'organizations/is-admin',
        'routes/answers-a-response',
        'sessions/round-trip',
        'sso/login-button',
        'sso/logout-url',
        'sso/pkce-round-trip',
        'users/current-user',
        'users/get-user',
      ].sort(),
    );
  });

  /**
   * Most gates ask a guard and say which one is false. The user section asks
   * instead whether either required member is present, so that half an
   * interface fails rather than skipping - so its reason names the members.
   * Either way a skip has to say what the provider does not have.
   */
  it('explains every skip in terms of something the provider does not have', async () => {
    const outcomes = await runChecks(optionsFor(bearerOnly));
    for (const outcome of outcomes) {
      if (outcome.status !== 'skipped') continue;
      expect(outcome.reason.length, `${outcome.check.id} skipped with an empty reason`).toBeGreaterThan(0);
      expect(outcome.reason).toMatch(/is false|has neither|does not implement|cannot put a session in a browser/);
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

  /**
   * The same claim, for the provider that authenticates *nobody*.
   *
   * The case above leaves the cookie fixture working, so obligation 2 passes and
   * never reports anything - which is why obligation 2 was the one check that
   * still made an unverified claim. Found by the first real-provider run:
   * `@mastra/auth-better-auth` built in deferred-instance mode has no
   * better-auth instance until `init()` supplies a database, so every path
   * resolves null, and obligation 2 told the reader "the credential is good and
   * the Cookie header is not being read" about a provider that could not read
   * anything. That sends somebody to write cookie parsing for a provider whose
   * actual problem is that it never started.
   */
  it('reports a rejected token fixture as a token problem when the cookie is rejected too', async () => {
    const outcomes = await runChecks(
      optionsFor(() => fullyCapableFake(), {
        token: 'a-token-nothing-accepts',
        cookieHeader: `${FAKE_COOKIE_NAME}=also-nothing-accepted`,
      }),
    );
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'obligation/cookieAuth');
    expect(failed?.message).toContain('rejected the token this suite was told the provider accepts');
    // The claim obligation 2's message makes about the bearer path has to be one
    // the check established, not one it assumed.
    expect(failed?.message).not.toContain('So the credential is good');
    expect(failed?.message).not.toContain("does not meet obligation 2 of 4, 'cookieAuth'");
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
    // `contract/descriptor` is the only check that reports this, and that is now
    // by design. The two gates that read `signIn` while deciding whether to skip
    // - `requiresBrowserSession` through `toAuthDescriptor`, and
    // `requiresCredentials` directly - used to throw outside any check body and
    // surface a raw error, so one broken getter produced three failures, two of
    // which named the wrong thing. They skip and point here instead.
    fails: ['contract/descriptor'],
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
  // ------------------------------------------------------------------
  // The login-cookie loop, one broken step at a time
  // ------------------------------------------------------------------
  //
  // Every row here declares BOTH halves, so the failure is about the step named
  // in the label rather than about a read side that was never there - which the
  // `sso/pkce-round-trip` describe block covers on its own. Declaring both also
  // puts `obligation/stateCodec/callback` through the browser's half of the trip,
  // and none of these rows may make that check red: a cookie loop that cannot
  // start is not a `state` this provider rejected.
  {
    label: 'getLoginCookies throws, so the login redirect is a 500',
    provider: () =>
      brokenFake({
        getLoginCookies: () => {
          throw new Error('PKCE verifier could not be generated');
        },
        setCallbackCookieHeader: () => {},
      }),
    fails: ['sso/pkce-round-trip'],
    says: /getLoginCookies threw/,
  },
  {
    label: 'getLoginCookies returns one Set-Cookie value rather than a list of them',
    provider: () =>
      brokenFake({
        getLoginCookies: () => 'fake_pkce=abc; Path=/',
        setCallbackCookieHeader: () => {},
      }),
    fails: ['sso/pkce-round-trip'],
    says: /not a list of Set-Cookie header values/,
  },
  {
    label: 'getLoginCookies returns a list with something other than a string in it',
    provider: () =>
      brokenFake({
        getLoginCookies: () => ['fake_pkce=abc; Path=/', 42],
        setCallbackCookieHeader: () => {},
      }),
    fails: ['sso/pkce-round-trip'],
    says: /not a list of Set-Cookie header values/,
  },
  {
    label: 'getLoginCookies returns attributes with no name=value pair in front of them',
    provider: () =>
      brokenFake({
        getLoginCookies: () => ['; Path=/; HttpOnly; Max-Age=600', '=no-name-at-all'],
        setCallbackCookieHeader: () => {},
      }),
    fails: ['sso/pkce-round-trip'],
    says: /returned values that name no cookie/,
  },
  {
    label: 'setCallbackCookieHeader throws for the header a browser would send back',
    provider: () =>
      brokenFake({
        getLoginCookies: () => ['fake_pkce=abc; Path=/; HttpOnly'],
        setCallbackCookieHeader: () => {
          throw new Error('cookie header could not be parsed');
        },
      }),
    fails: ['sso/pkce-round-trip'],
    says: /setCallbackCookieHeader threw/,
  },
  {
    // The login half is what broke, and obligation 3 owns that. This check has
    // no authorization URL to read a state out of and no login to carry a cookie
    // from, so it must not report the same defect a second time.
    label: 'getLoginUrl throws, which the PKCE check defers to obligation 3 about',
    provider: () =>
      brokenFake({
        getLoginUrl: () => {
          throw new Error('no issuer configured');
        },
        getLoginCookies: () => ['fake_pkce=abc; Path=/'],
        setCallbackCookieHeader: () => {},
      }),
    fails: ['obligation/stateCodec/login-url'],
    says: /getLoginUrl threw for a state in this package’s format/,
  },
  {
    // Same division of labour, for the URL that parses as nothing. The PKCE
    // check finds no `state` to echo, falls back to the host's, and carries on.
    label: 'getLoginUrl answers a relative path, so there is no state to echo back',
    provider: () =>
      brokenFake({
        getLoginUrl: () => '/authorize?state=ignored',
        getLoginCookies: () => ['fake_pkce=abc; Path=/'],
        setCallbackCookieHeader: () => {},
      }),
    fails: ['obligation/stateCodec/login-url'],
    says: /did not return an absolute URL/,
  },
  // ------------------------------------------------------------------
  // The user directory, one broken member at a time
  // ------------------------------------------------------------------
  {
    label: 'getCurrentUser throws instead of answering a user or null',
    provider: () =>
      brokenFake({
        getCurrentUser: () => {
          throw new Error('session store unreachable');
        },
      }),
    fails: ['users/current-user'],
    says: /getCurrentUser threw instead of answering a user or null/,
  },
  {
    // Obligation 1's payload shape, arriving through the other door. The id is
    // present and readable by anything that knows this provider, and
    // `toAuthIdentity` does not look there - so a host has a user object it
    // cannot key anything on.
    label: 'getCurrentUser answers a user whose id is nested where nothing looks for it',
    provider: () => brokenFake({ getCurrentUser: async () => ({ profile: { id: 'fake-user' } }) }),
    fails: ['users/current-user'],
    says: /answered with something that names nobody/,
  },
  {
    label: 'getCurrentUser names a different person than authenticateToken does',
    provider: () => brokenFake({ getCurrentUser: async () => ({ id: 'somebody-else' }) }),
    fails: ['users/current-user'],
    says: /name two different people for one credential/,
  },
  {
    label: 'getUser throws for the provider’s own user id',
    provider: () =>
      brokenFake({
        getUser: () => {
          throw new Error('directory lookup failed');
        },
      }),
    fails: ['users/get-user'],
    says: /getUser threw for this provider’s own user id/,
  },
  {
    // The method that ignores its argument. It looks right against a fixture
    // with one user in it, which is why the fake's directory has two.
    label: 'getUser ignores the id it was handed and answers whoever is signed in',
    provider: () => brokenFake({ getUser: async () => ({ id: 'somebody-else' }) }),
    fails: ['users/get-user'],
    says: /answered with a different user than the id it was asked about/,
  },
  {
    label: 'getUser answers a record with no id anywhere in it',
    provider: () => brokenFake({ getUser: async () => ({ email: 'nobody@example.test' }) }),
    fails: ['users/get-user'],
    says: /toAuthIdentity found no id in it/,
  },
  // ------------------------------------------------------------------
  // The organization administrator answer
  // ------------------------------------------------------------------
  {
    label: 'isOrganizationAdmin throws rather than resolving false',
    provider: () =>
      brokenFake({
        async isOrganizationAdmin() {
          throw new Error('role service unavailable');
        },
      }),
    fails: ['organizations/is-admin'],
    says: /threw for this provider’s own organization/,
  },
  {
    // Truthy at the call site, which is the whole defect: `if (await
    // isOrganizationAdmin(...))` reads "member" as yes.
    label: 'isOrganizationAdmin answers the role string rather than a boolean',
    provider: () => brokenFake({ isOrganizationAdmin: async () => 'member' }),
    fails: ['organizations/is-admin'],
    says: /answered with something that is not a boolean/,
  },
  {
    label: 'isOrganizationAdmin throws for an organization id it does not recognize',
    provider: () =>
      brokenFake({
        async isOrganizationAdmin(organizationId: string) {
          if (organizationId === 'fake-org') return true;
          throw new Error(`unknown organization: ${organizationId}`);
        },
      }),
    fails: ['organizations/is-admin'],
    says: /threw for an organization id it does not recognize/,
  },
  {
    label: 'isSignUpEnabled answers a truthy string rather than a boolean',
    provider: () => brokenFake({ isSignUpEnabled: () => 'yes' }),
    fails: ['credentials/sign-up-enabled'],
    says: /did not answer a literal boolean/,
  },
  {
    // The shape the check's own failure text is written about, and the one it
    // used to be blind to: `settle` awaited the return value, so a Promise
    // resolving to `true` arrived as the boolean `true` and passed.
    label: 'isSignUpEnabled is async, so it answers a Promise rather than a boolean',
    provider: () => brokenFake({ isSignUpEnabled: async () => true }),
    fails: ['credentials/sign-up-enabled'],
    says: /did not answer a literal boolean/,
  },
  {
    label: 'isSignUpEnabled answers a Promise that resolves false',
    provider: () => brokenFake({ isSignUpEnabled: async () => false }),
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

    /**
     * Every red carries a code, and the code is one the check admits to.
     *
     * This is the assertion that keeps `knownFailures` honest at the source. An
     * entry can only name a code, so a failure that reaches a provider author
     * with no code is a failure nobody can ever record - and a code missing from
     * `failureCodes` is one `describeAuthProvider` would reject at registration,
     * leaving the author with a red they are told to record and cannot.
     *
     * Running it over the whole red table rather than as one test is the point:
     * these thirty-odd cases are the closest thing the package has to full
     * coverage of the ways a check can go red, so this holds the declaration and
     * the call sites in step without a second list to maintain.
     */
    it('fails with a declared code, so the failure is one that could be recorded', async () => {
      const outcomes = await runChecks(optionsFor(redCase.provider, redCase.options));
      for (const outcome of failures(outcomes)) {
        const { code } = outcome;
        expect(code, `${outcome.check.id} failed with no code:\n${outcome.message}`).not.toBeNull();
        if (isFixtureFailureCode(code!)) continue;
        expect(
          outcome.check.failureCodes,
          `${outcome.check.id} produced ${code}, which it does not declare in failureCodes`,
        ).toContain(code);
      }
    });
  },
);

// ============================================================================
// Failure codes
// ============================================================================

/**
 * The codes are a published surface, so they are held to the shape the docs
 * promise rather than to whatever was typed.
 *
 * A code is the only thing a `knownFailures` entry can key on. Message wording
 * is patch-level in this package and is explicitly not to be asserted on, which
 * is the whole reason these exist - so the properties that make them usable are
 * pinned here rather than left to convention.
 */
describe('the failure code registry', () => {
  const checks = authConformanceChecks(optionsFor(() => fullyCapableFake()));

  it('gives every check at least one way to go red', () => {
    for (const check of checks) {
      expect(check.failureCodes.length, `${check.id} declares no failure codes`).toBeGreaterThan(0);
    }
  });

  it('namespaces every code under the check that can produce it', () => {
    for (const check of checks) {
      for (const code of check.failureCodes) {
        expect(code, `${check.id} declares ${code}, which is not namespaced under it`).toMatch(
          new RegExp(`^${check.id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}#[a-z0-9-]+$`),
        );
      }
    }
  });

  it('never reuses a code across two checks', () => {
    const all = checks.flatMap(check => check.failureCodes);
    expect(new Set(all).size, 'two checks declare the same failure code').toBe(all.length);
  });

  /**
   * Fixture faults live outside the per-check namespace on purpose, and the
   * reason is that they are not defects of the provider at all.
   *
   * The same fault - a `token` the provider will not accept - surfaces from
   * whichever check needed an authenticated payload first, so it has no natural
   * check to be namespaced under. Keeping it out of every `failureCodes` list is
   * what makes it unrecordable, and `readKnownFailures` refuses one outright.
   */
  it('keeps fixture faults out of every check’s declared codes', () => {
    for (const check of checks) {
      for (const code of check.failureCodes) {
        expect(isFixtureFailureCode(code), `${check.id} declares the fixture code ${code}`).toBe(false);
      }
    }
  });

  it('reports a rejected token fixture under the fixture namespace, not as a provider defect', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake(), { token: 'a-token-nothing-accepts' }));
    const failed = failures(outcomes);
    expect(failed.length).toBeGreaterThan(0);
    for (const outcome of failed) {
      expect(outcome.code).toBe(`${AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX}token-rejected`);
    }
  });

  it('quotes the code, and how to record it, in the failure a provider author reads', async () => {
    const outcomes = await runChecks(optionsFor(() => brokenFake({ validateSession: async () => null })));
    const failed = failures(outcomes)[0]!;
    expect(failed.message).toContain('sessions/round-trip#validate-rejects-fresh-session');
    // The offer has to be in the message: somebody reading a red they cannot fix
    // today should not have to already know this option exists to find it.
    expect(failed.message).toContain('knownFailures');
  });

  // No `from` immediately before a quote anywhere in this file: the EE boundary
  // scanner reads that shape as an import specifier and is fail-closed about it.
  it('makes no such offer for a fixture fault, which is not a thing anybody is owed an exemption for', async () => {
    const outcomes = await runChecks(optionsFor(() => fullyCapableFake(), { token: 'a-token-nothing-accepts' }));
    expect(failures(outcomes)[0]!.message).not.toContain('knownFailures');
  });
});

// ============================================================================
// knownFailures: the four semantics
// ============================================================================

/**
 * A provider that ships, does not conform, and says so.
 *
 * The four entries this mechanism was built for are two real providers with
 * four real defects, and the shape below is the first of them: `@mastra/auth-
 * workos` declares `ISessionProvider` and its `validateSession` returns `null`
 * unconditionally, so a session it just minted does not validate. The guard is
 * structural and tests two members for existence, so it reports a capability the
 * provider does not have - and the check catches exactly that.
 *
 * Nothing about the fake matters except that it fails one check, for one named
 * reason, and passes everything else.
 */
const providerWithARealDefect = () => brokenFake({ validateSession: async () => null });

const SESSION_DEFECT = 'sessions/round-trip#validate-rejects-fresh-session';

const RECORDED: AuthConformanceKnownFailure = {
  check: 'sessions/round-trip',
  code: SESSION_DEFECT,
  reason: 'validateSession returns null unconditionally. Full diagnosis in this file’s header.',
};

/** The one outcome for `sessions/round-trip`, whatever it turned out to be. */
function sessionOutcome(outcomes: readonly CheckOutcome[]): CheckOutcome {
  const outcome = outcomes.find(candidate => candidate.check.id === 'sessions/round-trip');
  expect(outcome, 'sessions/round-trip did not run at all').toBeDefined();
  return outcome!;
}

describe('knownFailures: a recorded check that fails', () => {
  const options = optionsFor(providerWithARealDefect, { knownFailures: [RECORDED] });

  it('is reported as a known failure rather than as a suite failure', async () => {
    const outcomes = await runChecks(options);
    expect(sessionOutcome(outcomes).status).toBe('knownFailure');
  });

  it('leaves the run with nothing red, which is the whole point of recording it', async () => {
    const outcomes = await runChecks(options);
    expect(report(outcomes)).toBe('');
  });

  /**
   * Without the record, the same provider is red. Stated directly rather than
   * implied, because "the suite is green" is only evidence about `knownFailures`
   * if the same provider is red without it.
   */
  it('is a genuine failure: the identical provider goes red with no entry', async () => {
    const outcomes = await runChecks(optionsFor(providerWithARealDefect));
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['sessions/round-trip']);
    expect(failures(outcomes)[0]!.code).toBe(SESSION_DEFECT);
  });

  /**
   * Visible, not silent. A recorded failure that reads like a pass would be an
   * exclusion with extra steps, and the point of recording rather than excluding
   * is that somebody scanning CI can see the provider does not conform.
   */
  it('says the provider does not conform, and quotes the reason somebody wrote', async () => {
    const outcomes = await runChecks(options);
    const outcome = sessionOutcome(outcomes);
    expect(outcome.status === 'knownFailure' && outcome.message).toContain('KNOWN FAILURE');
    expect(outcome.status === 'knownFailure' && outcome.message).toContain('does not conform');
    expect(outcome.status === 'knownFailure' && outcome.message).toContain(RECORDED.reason);
    expect(outcome.status === 'knownFailure' && outcome.message).toContain(SESSION_DEFECT);
  });

  it('reproduces the original failure underneath, so nothing is paraphrased away', async () => {
    const outcomes = await runChecks(options);
    const outcome = sessionOutcome(outcomes);
    expect(outcome.status === 'knownFailure' && outcome.failure).toContain(
      'rejected a session this provider had just created',
    );
    expect(outcome.status === 'knownFailure' && outcome.message).toContain(
      'rejected a session this provider had just created',
    );
  });

  it('marks the test title, so a run that prints names shows it without expanding anything', () => {
    const [check] = authConformanceChecks(options).filter(candidate => candidate.id === 'sessions/round-trip');
    expect(check!.knownFailure).toEqual(RECORDED);
    // `describeAuthProvider` builds its `it` title from this; the registration at
    // the bottom of this file is where that title actually reaches a reporter.
    expect(KNOWN_FAILURE_TITLE_PREFIX.length).toBeGreaterThan(0);
  });

  it('touches no other check', async () => {
    const outcomes = await runChecks(options);
    for (const outcome of outcomes) {
      if (outcome.check.id === 'sessions/round-trip') continue;
      expect(outcome.status, `${outcome.check.id} changed because of an unrelated entry`).not.toBe('knownFailure');
    }
  });
});

describe('knownFailures: a recorded check that passes', () => {
  /**
   * The property that stops the list rotting.
   *
   * A recorded entry is an admission with an expiry date. If fixing the defect
   * left the entry in place, the list would go on granting cover for a provider
   * that no longer needs it, and nothing would ever report that - which is the
   * failure mode of every exclusion list anybody has ever kept. So the suite
   * fails, and deleting the entry is part of the fix rather than a follow-up
   * nobody files.
   */
  const options = optionsFor(() => fullyCapableFake(), { knownFailures: [RECORDED] });

  it('fails the suite', async () => {
    const outcomes = await runChecks(options);
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['sessions/round-trip']);
  });

  it('says the check passed, and that the entry is what has to go', async () => {
    const outcomes = await runChecks(options);
    const failed = failures(outcomes)[0]!;
    expect(failed.message).toContain('knownFailures entry is stale');
    expect(failed.message).toContain('and it passed');
    expect(failed.message).toContain('Delete the knownFailures entry');
  });

  it('quotes the reason back, so the reader can see what is no longer true', async () => {
    const outcomes = await runChecks(options);
    expect(failures(outcomes)[0]!.message).toContain(RECORDED.reason);
  });

  it('does not blame the provider, which is conforming', async () => {
    const outcomes = await runChecks(options);
    expect(failures(outcomes)[0]!.message).not.toContain('Auth conformance violation');
  });
});

describe('knownFailures: a recorded check that stops applying', () => {
  /**
   * The other way an entry outlives its defect, and it is not hypothetical.
   *
   * `sessions/round-trip` is gated on `isSessionProvider`, which tests two
   * members for existence. A provider whose session support is a set of no-ops
   * "kept for interface compatibility" is exactly the shape this whole mechanism
   * was built for - and the honest fix for it may well be to delete those
   * members rather than implement them. The day somebody does, the check stops
   * applying, and an entry left behind covers nothing while still reading as an
   * admission of a live defect.
   */
  const bearerOnly = () => fakeProvider({ user: { organizationId: undefined } });
  const options = optionsFor(() => withSyntheticOrganizations(bearerOnly()), { knownFailures: [RECORDED] });

  it('fails the suite rather than skipping quietly', async () => {
    const outcomes = await runChecks(options);
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['sessions/round-trip']);
  });

  it('says the check did not run, and repeats the gate’s own reason', async () => {
    const outcomes = await runChecks(options);
    const failed = failures(outcomes)[0]!;
    expect(failed.message).toContain('did not run at all');
    expect(failed.message).toContain('isSessionProvider is false');
    expect(failed.message).toContain('Delete the knownFailures entry');
  });

  it('still skips that check for the same provider with no entry', async () => {
    const outcomes = await runChecks(optionsFor(() => withSyntheticOrganizations(bearerOnly())));
    expect(sessionOutcome(outcomes).status).toBe('skipped');
  });
});

describe('knownFailures: a recorded check that fails for a different reason', () => {
  /**
   * The reason an entry names a code and not just a check id.
   *
   * `sessions/round-trip` has five ways to go red, and the two real providers
   * that need entries for it fail it for genuinely different defects - one has a
   * `validateSession` that always answers null, the other mints an id that
   * `validateSession` can never accept. An entry keyed on the check id alone
   * would cover both, and would go on covering a third, unrelated regression
   * that arrived in the same check later. Matching on which failure is what
   * keeps the record worth having.
   */
  const alsoBrokenElsewhere = () =>
    brokenFake({
      async createSession() {
        throw new Error('session store not configured');
      },
    });
  const options = optionsFor(alsoBrokenElsewhere, { knownFailures: [RECORDED] });

  it('fails the suite instead of absorbing the new defect', async () => {
    const outcomes = await runChecks(options);
    expect(failures(outcomes).map(outcome => outcome.check.id)).toEqual(['sessions/round-trip']);
  });

  it('names both codes, so the reader can see which one moved', async () => {
    const outcomes = await runChecks(options);
    const failed = failures(outcomes)[0]!;
    expect(failed.message).toContain('failed for a different reason');
    expect(failed.message).toContain(SESSION_DEFECT);
    expect(failed.message).toContain('sessions/round-trip#create-threw');
  });

  it('reproduces what it actually said, because that may be the new regression', async () => {
    const outcomes = await runChecks(options);
    expect(failures(outcomes)[0]!.message).toContain('createSession threw');
  });

  it('offers both readings: the same defect moved, or a new one arrived', async () => {
    const outcomes = await runChecks(options);
    const failed = failures(outcomes)[0]!;
    expect(failed.message).toContain('surfacing at a different point');
    expect(failed.message).toContain('a regression this');
  });

  /**
   * A fixture fault must not be covered either, and it takes this path to get
   * there: `fixture/...` is never a check's declared code, so it can never equal
   * a recorded one.
   */
  it('does not let an entry cover a broken fixture', async () => {
    // No `userId` option and a token nothing accepts, so `sessions/round-trip`
    // cannot get as far as its own question: it fails under `fixture/...`
    // instead. That is the fault of the calling file, and an entry recorded
    // against the provider must not absorb it.
    const outcomes = await runChecks(
      optionsFor(providerWithARealDefect, {
        knownFailures: [RECORDED],
        token: 'a-token-nothing-accepts',
        userId: undefined,
      }),
    );
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'sessions/round-trip');
    expect(failed, 'the entry swallowed a fixture fault').toBeDefined();
    expect(failed!.message).toContain('failed for a different reason');
    expect(failed!.message).toContain(`failed with ${AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX}`);
    expect(isFixtureFailureCode(failed!.code ?? '')).toBe(true);
  });
});

// ============================================================================
// knownFailures: entries the caller cannot have meant
// ============================================================================

/**
 * Every one of these is a mistake in the calling test file rather than a defect
 * in the provider, so every one of them is a `TypeError` at registration - which
 * fails the whole file before any suite exists to report it as something else.
 *
 * That is the loudest volume available, and loud is the requirement. An
 * exemption that is quietly ignored is indistinguishable from one that works,
 * and it goes on being indistinguishable for as long as nobody re-derives it by
 * hand.
 */
describe('knownFailures: an entry that names nothing', () => {
  const build = (knownFailures: readonly AuthConformanceKnownFailure[]) =>
    authConformanceChecks(optionsFor(providerWithARealDefect, { knownFailures }));

  it('refuses a check id no check has', () => {
    expect(() => build([{ ...RECORDED, check: 'sessions/roundtrip' }])).toThrow(TypeError);
    expect(() => build([{ ...RECORDED, check: 'sessions/roundtrip' }])).toThrow(/which does not exist/);
  });

  it('suggests the id the author probably meant', () => {
    expect(() => build([{ ...RECORDED, check: 'sessions/roundtrip' }])).toThrow(/Closest ids: sessions\/round-trip/);
  });

  it('lists every real id, because a rename is the other way to get here', () => {
    expect(() => build([{ ...RECORDED, check: 'sessions/roundtrip' }])).toThrow(/All \d+ ids:/);
  });

  it('says why a dead entry is not harmless', () => {
    expect(() => build([{ ...RECORDED, check: 'sessions/roundtrip' }])).toThrow(/nothing ever re-examines/);
  });

  it('refuses a code the named check cannot produce', () => {
    expect(() => build([{ ...RECORDED, code: 'sessions/round-trip#validate-rejects-frsh-session' }])).toThrow(
      /cannot produce it/,
    );
  });

  it('lists the codes that check can produce', () => {
    expect(() => build([{ ...RECORDED, code: 'sessions/round-trip#nope' }])).toThrow(
      /sessions\/round-trip#destroyed-session-still-validates/,
    );
  });

  it('refuses a code that belongs to a different check than the entry names', () => {
    expect(() => build([{ ...RECORDED, code: 'sso/login-button#threw' }])).toThrow(/cannot produce it/);
  });
});

describe('knownFailures: an entry with no stated reason', () => {
  const build = (knownFailures: readonly AuthConformanceKnownFailure[]) =>
    authConformanceChecks(optionsFor(providerWithARealDefect, { knownFailures }));

  it.each([
    ['missing', undefined],
    ['empty', ''],
    ['whitespace', '   \n  '],
  ])('refuses a reason that is %s', (_label, reason) => {
    expect(() => build([{ ...RECORDED, reason: reason as unknown as string }])).toThrow(TypeError);
    expect(() => build([{ ...RECORDED, reason: reason as unknown as string }])).toThrow(/must be a non-empty/);
  });

  /**
   * The reason the reason is required, said in the message rather than only in
   * the docs. This package exists because four obligations went unwritten while
   * everybody involved knew what they were.
   */
  it('says why, in the message', () => {
    expect(() => build([{ ...RECORDED, reason: '' }])).toThrow(/knowledge leaves with them/);
  });

  it.each([
    ['a missing code', { code: undefined }],
    ['an empty code', { code: '' }],
    ['a missing check id', { check: undefined }],
    ['an empty check id', { check: '  ' }],
  ])('refuses %s', (_label, override) => {
    expect(() => build([{ ...RECORDED, ...override } as unknown as AuthConformanceKnownFailure])).toThrow(TypeError);
  });

  it('explains that a code is what keeps the entry from spreading', () => {
    expect(() => build([{ ...RECORDED, code: '' }])).toThrow(/second, unrelated defect/);
  });

  it('refuses a fixture code, which is not a provider defect anybody is owed an exemption for', () => {
    expect(() =>
      build([{ check: 'obligation/cookieAuth', code: 'fixture/cookie-header-missing', reason: 'later' }]),
    ).toThrow(/fix the fixture instead/);
  });

  it('refuses two entries for one check, because only one of them could ever fire', () => {
    expect(() =>
      build([RECORDED, { ...RECORDED, code: 'sessions/round-trip#create-threw', reason: 'also this' }]),
    ).toThrow(/second entry/);
  });

  it('refuses something that is not an array, and something that is not an entry', () => {
    expect(() => build('sessions/round-trip' as unknown as AuthConformanceKnownFailure[])).toThrow(/must be an array/);
    expect(() => build([null as unknown as AuthConformanceKnownFailure])).toThrow(/not a \{ check, code, reason \}/);
  });

  it('accepts no knownFailures at all, and an empty list, as meaning the same thing', () => {
    expect(() => authConformanceChecks(optionsFor(() => fullyCapableFake()))).not.toThrow();
    expect(() => build([])).not.toThrow();
    for (const check of build([])) expect(check.knownFailure).toBeNull();
  });
});

/**
 * The two halves of this package have to agree about the same provider, and
 * these are the tests that say so.
 *
 * `credentials/sign-up-enabled` and `toAuthDescriptor` both read
 * `isSignUpEnabled`, and for a while they disagreed: the check awaited what the
 * method returned, so an `async isSignUpEnabled()` reached it as the boolean it
 * resolved to and passed, while the descriptor read the un-awaited Promise and
 * reported the same provider as sign-up-disabled. The half whose job it is to
 * notice was the half that could not.
 *
 * Both now judge the returned value without awaiting it, so a provider the suite
 * passes is exactly a provider the descriptor reads correctly. That is the
 * property worth protecting, so it is asserted directly rather than left to the
 * two tables to imply.
 */
describe('the suite and the descriptor agree about isSignUpEnabled', () => {
  it.each([
    ['a literal true', () => true, true],
    ['a literal false', () => false, false],
    ['an absent method', undefined, true],
  ])('%s: both halves agree, and the check passes', async (_label, isSignUpEnabled, expected) => {
    const make = () => brokenFake(isSignUpEnabled === undefined ? {} : { isSignUpEnabled });
    expect(toAuthDescriptor(make()).signIn.signUpEnabled).toBe(expected);
    const outcomes = await runChecks(optionsFor(make));
    const outcome = outcomes.find(candidate => candidate.check.id === 'credentials/sign-up-enabled');
    expect(outcome?.status, JSON.stringify(outcome)).not.toBe('failed');
  });

  it.each([
    ['an async method', async () => true],
    ['a truthy string', () => 'yes'],
    ['a truthy number', () => 1],
  ])('%s: the descriptor says false, and the check says so out loud', async (_label, isSignUpEnabled) => {
    // The descriptor's answer is the safe one, but on its own it is silent: the
    // provider author sees a sign-up link quietly missing and nothing else. The
    // check is what turns that into a sentence they can act on.
    const make = () => brokenFake({ isSignUpEnabled } as never);
    expect(toAuthDescriptor(make()).signIn.signUpEnabled).toBe(false);
    const outcomes = await runChecks(optionsFor(make));
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'credentials/sign-up-enabled');
    expect(failed, 'the check did not fail').toBeDefined();
    expect(failed!.message).toMatch(/did not answer a literal boolean/);
  });

  it('does not leave a rejected Promise unhandled while reporting one', async () => {
    // The check reports the Promise rather than awaiting it, so a Promise that
    // rejects later would otherwise be an unhandled rejection that fails an
    // unrelated test in the same run.
    const make = () => brokenFake({ isSignUpEnabled: () => Promise.reject(new Error('lookup failed')) } as never);
    const outcomes = await runChecks(optionsFor(make));
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'credentials/sign-up-enabled');
    expect(failed).toBeDefined();
    await new Promise(resolve => setTimeout(resolve, 10));
  });
});

/**
 * A gate that cannot read the provider skips and points at the check whose job
 * it is to report that, rather than throwing a raw error of its own.
 */
describe('a provider whose property read throws', () => {
  const withThrowingGetter = (property: string) => () => {
    const provider = brokenFake({});
    Object.defineProperty(provider, property, {
      get() {
        throw new Error('this getter has side effects');
      },
      configurable: true,
    });
    return provider;
  };

  it('reports it once, from contract/descriptor', async () => {
    const outcomes = await runChecks(optionsFor(withThrowingGetter('signIn')));
    const failed = failures(outcomes);
    expect(failed.map(outcome => outcome.check.id)).toEqual(['contract/descriptor']);
    expect(failed[0]!.message).toMatch(/toAuthDescriptor threw while inspecting this provider/);
  });

  it.each([
    ['obligation/cookieAuth', 'signIn'],
    ['credentials/sign-up-enabled', 'signIn'],
  ])('skips %s with a pointer rather than throwing from its gate', async (id, property) => {
    const outcomes = await runChecks(optionsFor(withThrowingGetter(property)));
    const outcome = outcomes.find(candidate => candidate.check.id === id);
    expect(outcome?.status, JSON.stringify(outcome)).toBe('skipped');
    expect(outcome!.status === 'skipped' && outcome.reason).toMatch(/could not tell whether it applies/);
    expect(outcome!.status === 'skipped' && outcome.reason).toMatch(/contract\/descriptor/);
  });

  it('covers a gate that inspects an optional method inline, not just the two named ones', async () => {
    // `mapUserToResourceId`, `getLogoutUrl` and `isSignUpEnabled` are read by
    // inline gates rather than by a named function, which is why the backstop
    // lives in the runner as well as in those two gates.
    const outcomes = await runChecks(optionsFor(withThrowingGetter('mapUserToResourceId')));
    const outcome = outcomes.find(candidate => candidate.check.id === 'contract/map-user-to-resource-id');
    expect(outcome?.status, JSON.stringify(outcome)).toBe('skipped');
    expect(outcome!.status === 'skipped' && outcome.reason).toMatch(/could not tell whether it applies/);
  });
});
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

/**
 * A provider that throws something that is not an `Error`.
 *
 * `throw 'unauthorized'` is legal JavaScript and does happen. The runner reads a
 * message off whatever came out, so a bare string has to survive that with the
 * string intact - and it must arrive with no failure code, because it did not
 * come from a `fail` site. That second half is what stops a `knownFailures`
 * entry from ever covering it: an uncoded failure can equal no recorded code.
 */
describe('a provider that throws a value that is not an Error', () => {
  const throwsAString = () => {
    const provider = brokenFake({});
    Object.defineProperty(provider, 'authenticateToken', {
      get() {
        // eslint-disable-next-line no-throw-literal -- the point of the test
        throw 'authenticateToken is not available on this instance';
      },
      configurable: true,
    });
    return provider;
  };

  it('reports the thrown value as its own message', async () => {
    const outcomes = await runChecks(optionsFor(throwsAString));
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'contract/shape');
    expect(failed, 'contract/shape did not fail').toBeDefined();
    expect(failed!.message).toBe('authenticateToken is not available on this instance');
  });

  it('carries no failure code, so no entry can ever cover it', async () => {
    const outcomes = await runChecks(optionsFor(throwsAString));
    expect(failures(outcomes).find(outcome => outcome.check.id === 'contract/shape')!.code).toBeNull();
  });

  it('fails a recorded entry rather than being absorbed by it', async () => {
    const outcomes = await runChecks(
      optionsFor(throwsAString, {
        knownFailures: [{ check: 'contract/shape', code: 'contract/shape#missing-required-member', reason: 'not yet' }],
      }),
    );
    const failed = failures(outcomes).find(outcome => outcome.check.id === 'contract/shape');
    expect(failed, 'the entry swallowed an uncoded throw').toBeDefined();
    expect(failed!.message).toContain('the failure did not come from a check assertion');
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

/**
 * The same adapter again, on a provider that does not conform and says so.
 *
 * Everything above drives the outcomes as data, which proves the policy and
 * proves nothing about how a known failure actually *reads* in a run. This
 * registration is the run: it goes green, and it is visibly not the green of a
 * clean provider.
 *
 * **The `stderr` line this prints during `pnpm test` is the feature working, not
 * noise to tidy away.** A recorded failure that produced no output would be an
 * exclusion with extra steps - the thing this mechanism exists to be an
 * alternative to. It is printed by the default reporter with the file and test
 * name attached, so it survives a CI run nobody opens in verbose mode; the test
 * title carries `known failure:`; and the skip note carries the full report. A
 * reader gets the same answer at every level of detail they choose to read.
 *
 * If the fake below is ever fixed so `sessions/round-trip` passes, this
 * registration goes red and the entry has to be deleted with it. That is the
 * anti-rot property, running against the real adapter rather than the harness.
 */
describeAuthProvider({
  name: '@mastra/auth-fake (a provider with one recorded known failure)',
  createProvider: () => brokenFake({ validateSession: async () => null }),
  token: FAKE_TOKEN,
  userId: 'fake-user',
  cookieHeader: `${FAKE_COOKIE_NAME}=${FAKE_TOKEN}`,
  knownFailures: [
    {
      check: 'sessions/round-trip',
      code: 'sessions/round-trip#validate-rejects-fresh-session',
      reason:
        'validateSession answers null for a session it just minted. Stands in here for the real case: ' +
        'a provider whose ISessionProvider members are no-ops kept for interface compatibility.',
    },
  ],
});
