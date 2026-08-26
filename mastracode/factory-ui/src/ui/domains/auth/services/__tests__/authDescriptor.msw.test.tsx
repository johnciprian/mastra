/**
 * What `fetchAuthState` makes of the two `/auth/me` payload shapes that are on
 * the wire at the same time: one carrying the capability descriptor, and one
 * from a server that predates it.
 *
 * Real `fetchAuthState`, real `fetch`, MSW at the network boundary only — so
 * these assert the actual wire contract rather than a re-description of the
 * parser.
 */
import { http, HttpResponse } from 'msw';
import type { JsonBodyType } from 'msw';
import { describe, expect, it } from 'vitest';

import { server } from '../../../../../../e2e/ui/msw-server';
import { TEST_BASE_URL } from '../../../../../../e2e/ui/render';
import { fetchAuthState, isSignUpEnabled } from '../auth';

const AUTH_ME_URL = `${TEST_BASE_URL}/auth/me`;

function stubAuthMe(body: JsonBodyType) {
  server.use(http.get(AUTH_ME_URL, () => HttpResponse.json(body)));
}

describe('fetchAuthState descriptor parsing', () => {
  describe('given a server that sends the descriptor', () => {
    it('carries the whole descriptor through onto the auth state', async () => {
      stubAuthMe({
        authenticated: false,
        user: null,
        provider: 'some-provider',
        auth: {
          signIn: {
            kind: 'both',
            label: 'Continue with your work account',
            providerHint: 'sso',
            signUpEnabled: false,
            credentialsBasePath: '/identity',
          },
          features: { logout: true, organizations: true, refresh: true, sessionRevocation: false },
        },
        signUpDisabled: true,
      });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth).toEqual({
        signIn: {
          kind: 'both',
          label: 'Continue with your work account',
          providerHint: 'sso',
          signUpEnabled: false,
          credentialsBasePath: '/identity',
        },
        features: { logout: true, organizations: true, refresh: true, sessionRevocation: false },
      });
      expect(isSignUpEnabled(state)).toBe(false);
    });

    it.each(['hosted', 'credentials', 'both', 'none'] as const)('accepts the %s sign-in kind', async kind => {
      stubAuthMe({
        authenticated: false,
        user: null,
        auth: {
          signIn: { kind },
          features: { logout: false, organizations: false, refresh: false, sessionRevocation: false },
        },
      });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth?.signIn.kind).toBe(kind);
      // Absent on the wire, defaulted on parse, so the UI's icon map never has
      // to handle `undefined`.
      expect(state.auth?.signIn.providerHint).toBe('generic');
    });

    it('defaults an unrecognized provider hint to the neutral treatment', async () => {
      // A hint this build does not know only picks an icon, so the descriptor is
      // still worth rendering — it must not be thrown away over it.
      stubAuthMe({
        authenticated: false,
        user: null,
        auth: {
          signIn: { kind: 'hosted', providerHint: 'holographic-badge' },
          features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
        },
      });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth?.signIn.kind).toBe('hosted');
      expect(state.auth?.signIn.providerHint).toBe('generic');
    });
  });

  describe('given a server that predates the descriptor', () => {
    it('reports no descriptor and keeps the provider name for the legacy fallback', async () => {
      stubAuthMe({ authenticated: false, user: null, provider: 'better-auth', signUpDisabled: true });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth).toBeUndefined();
      expect(state.provider).toBe('better-auth');
      expect(isSignUpEnabled(state)).toBe(false);
    });

    it('leaves sign-up enabled when the legacy field is absent', async () => {
      stubAuthMe({ authenticated: false, user: null, provider: 'better-auth' });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth).toBeUndefined();
      expect(isSignUpEnabled(state)).toBe(true);
    });
  });

  describe('given a descriptor this build cannot act on', () => {
    // Rejecting routes the page to its legacy provider-name fallback, which
    // still renders something a user can act on. Accepting a kind we cannot
    // branch on would drop the payload into whichever branch happens to be last.
    it.each([
      ['a kind from a newer server', { signIn: { kind: 'passkey' }, features: {} }],
      ['no kind at all', { signIn: {}, features: {} }],
      ['no signIn block', { features: {} }],
      ['a null descriptor', null],
      ['a non-object descriptor', 'hosted'],
    ])('rejects %s and falls back to the provider name', async (_label, auth) => {
      stubAuthMe({ authenticated: false, user: null, provider: 'better-auth', auth });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth).toBeUndefined();
      expect(state.provider).toBe('better-auth');
    });

    it('still yields a complete feature record when features are missing', async () => {
      stubAuthMe({ authenticated: false, user: null, auth: { signIn: { kind: 'hosted' } } });

      const state = await fetchAuthState(TEST_BASE_URL);

      expect(state.auth?.features).toEqual({
        logout: false,
        organizations: false,
        refresh: false,
        sessionRevocation: false,
      });
    });
  });
});
