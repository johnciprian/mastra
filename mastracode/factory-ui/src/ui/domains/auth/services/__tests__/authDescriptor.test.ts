/**
 * The sign-up decision, which now has exactly one input.
 *
 * `/auth/me` used to carry two fields of opposite polarity describing one fact
 * — the positive `auth.signIn.signUpEnabled` and a legacy negative
 * `signUpDisabled` — and the resolution between them was the risk this table
 * covered: a missing `!` shows a sign-up link on a deployment that deliberately
 * disabled sign-up, and that failure is invisible from the outside, no error
 * and no blank screen, just an affordance that should not be there.
 *
 * The negative field is gone. What is left to get wrong is narrower and still
 * worth pinning exhaustively: `false` must not be read as "not stated", and
 * "not stated" must not be read as "off".
 */
import { describe, expect, it } from 'vitest';

import { credentialsBasePath, isSignUpEnabled } from '../auth';
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
  });

  describe('given a descriptor that is silent on sign-up', () => {
    // The descriptor omits `signUpEnabled` for every kind without a credentials
    // sign-in, so "absent" must read as "not stated" — never as "disabled".
    it('defaults to enabled', () => {
      expect(isSignUpEnabled(state({ auth: descriptor({ kind: 'hosted' }) }))).toBe(true);
    });
  });

  it('defaults to enabled given no descriptor at all', () => {
    expect(isSignUpEnabled(state({ provider: 'anything' }))).toBe(true);
  });

  it('defaults to enabled before the auth state has loaded', () => {
    expect(isSignUpEnabled(undefined)).toBe(true);
  });
});

describe('credentialsBasePath', () => {
  it.each([
    ['a single segment', '/identity', '/identity'],
    ['nested segments', '/api/auth', '/api/auth'],
    ['the kit default', '/auth', '/auth'],
    // Trailing slashes would double up against the `/api/` segment.
    ['a trailing slash', '/identity/', '/identity'],
    ['several trailing slashes', '/identity///', '/identity'],
  ])('takes %s from the descriptor', (_label, declared, expected) => {
    expect(
      credentialsBasePath(state({ auth: descriptor({ kind: 'credentials', credentialsBasePath: declared }) })),
    ).toBe(expected);
  });

  describe('given nothing to go on', () => {
    it.each([
      ['no descriptor at all', state({ provider: 'anything' })],
      ['a descriptor with no credentials sign-in', state({ auth: descriptor({ kind: 'hosted' }) })],
      ['no auth state yet', undefined],
    ])('falls back to the kit default for %s', (_label, input) => {
      expect(credentialsBasePath(input)).toBe('/auth');
    });
  });

  describe('given a path that could send the password off-origin', () => {
    // This URL receives the user's password, and the SPA is normally served
    // same-origin where `baseUrl` is the empty string — so any of these would
    // resolve to another origin rather than to a path under this one.
    it.each([
      ['protocol-relative', '//evil.example'],
      // A backslash normalizes to a forward slash in http(s) URLs, so this
      // *becomes* `//evil.example`. A prefix check alone would let it through.
      ['backslash, which normalizes to protocol-relative', '/\\evil.example'],
      // The URL parser strips tab, newline and carriage return outright.
      ['tab-smuggled protocol-relative', '/\t/evil.example'],
      ['newline-smuggled protocol-relative', '/\n/evil.example'],
      ['an absolute URL', 'https://evil.example'],
      ['a scheme with no slashes', 'javascript:alert(1)'],
      ['a bare host', 'evil.example'],
      ['empty', ''],
      ['a lone slash', '/'],
    ])('rejects %s and falls back to the default', (_label, declared) => {
      expect(
        credentialsBasePath(state({ auth: descriptor({ kind: 'credentials', credentialsBasePath: declared }) })),
      ).toBe('/auth');
    });
  });
});
