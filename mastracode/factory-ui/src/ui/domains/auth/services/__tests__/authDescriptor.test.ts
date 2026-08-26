/**
 * The sign-up polarity table.
 *
 * `/auth/me` carries two fields of opposite polarity describing one fact for a
 * single release — the positive `auth.signIn.signUpEnabled` and the legacy
 * negative `signUpDisabled` — so the resolution between them gets an exhaustive
 * table rather than a spot check. A missing `!` here shows a sign-up link on a
 * deployment that deliberately disabled sign-up, and that failure is invisible
 * from the outside: no error, no blank screen, just an affordance that should
 * not be there. Every combination is pinned, including the two the wire is not
 * supposed to produce (a self-contradicting server, and a legacy-only server).
 */
import { describe, expect, it } from 'vitest';

import { isSignUpEnabled } from '../auth';
import type { AuthDescriptor, AuthSignInKind, FactoryAuthState } from '../auth';

function descriptor(signIn: Partial<AuthDescriptor['signIn']> & { kind: AuthSignInKind }): AuthDescriptor {
  return {
    signIn: { providerHint: 'generic', ...signIn },
    features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
  };
}

function state(overrides: Partial<FactoryAuthState> = {}): FactoryAuthState {
  return { authEnabled: true, authenticated: false, ...overrides };
}

describe('isSignUpEnabled', () => {
  describe('given a descriptor that states the fact', () => {
    it.each([
      ['enabled', true, true],
      ['disabled', false, false],
    ])('takes the descriptor at its word when sign-up is %s', (_label, signUpEnabled, expected) => {
      expect(isSignUpEnabled(state({ auth: descriptor({ kind: 'credentials', signUpEnabled }) }))).toBe(expected);
    });

    it('still disables sign-up when the legacy field agrees, which is what the wire actually sends', () => {
      const auth = descriptor({ kind: 'credentials', signUpEnabled: false });
      expect(isSignUpEnabled(state({ auth, signUpDisabled: true }))).toBe(false);
    });

    it('prefers the descriptor over a legacy field that contradicts it', () => {
      // Not a shape the Factory emits, but a proxy or a mixed-version deploy can
      // produce it. The descriptor is authoritative by design, so `true` here is
      // the specified answer rather than an accident of ordering.
      const auth = descriptor({ kind: 'credentials', signUpEnabled: true });
      expect(isSignUpEnabled(state({ auth, signUpDisabled: true }))).toBe(true);
    });
  });

  describe('given a descriptor that is silent on sign-up', () => {
    // The descriptor omits `signUpEnabled` for every kind without a credentials
    // sign-in, so "absent" must read as "not stated" — never as "disabled".
    it('falls through to the legacy field when one is present', () => {
      const auth = descriptor({ kind: 'hosted' });
      expect(isSignUpEnabled(state({ auth, signUpDisabled: true }))).toBe(false);
    });

    it('defaults to enabled when nothing states otherwise', () => {
      expect(isSignUpEnabled(state({ auth: descriptor({ kind: 'hosted' }) }))).toBe(true);
    });
  });

  describe('given no descriptor at all (a server predating it)', () => {
    it.each([
      ['the legacy field disables sign-up', true, false],
      ['the legacy field is explicitly false', false, true],
      ['the legacy field is absent', undefined, true],
    ])('%s', (_label, signUpDisabled, expected) => {
      expect(isSignUpEnabled(state({ provider: 'anything', signUpDisabled }))).toBe(expected);
    });
  });

  it('defaults to enabled before the auth state has loaded', () => {
    expect(isSignUpEnabled(undefined)).toBe(true);
  });
});
