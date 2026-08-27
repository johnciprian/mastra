import { screen } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { describe, expect, it } from 'vitest';

import { server } from '../../../../../../e2e/ui/msw-server';
import { renderWithProviders, TEST_BASE_URL } from '../../../../../../e2e/ui/render';
import { AccountSettingsSection } from '../AccountSettingsSection';

function stubAuthenticatedAccount(extra: Record<string, unknown> = {}) {
  server.use(
    http.get(`${TEST_BASE_URL}/auth/me`, () =>
      HttpResponse.json({
        authenticated: true,
        user: {
          userId: 'user-1',
          email: 'dev@mastra.ai',
          name: 'Dev',
          organizationId: 'org-1',
        },
        provider: 'workos',
        ...extra,
      }),
    ),
  );
}

/** A descriptor with `features` set as given; the sign-in half is irrelevant here. */
function descriptorWithFeatures(features: Record<string, boolean>) {
  return {
    auth: {
      signIn: { kind: 'hosted', providerHint: 'generic' },
      features: { logout: true, organizations: false, refresh: false, sessionRevocation: false, ...features },
    },
  };
}

describe('AccountSettingsSection', () => {
  describe('when the user is signed in', () => {
    it('shows the profile returned by the auth endpoint', async () => {
      stubAuthenticatedAccount();

      renderWithProviders(<AccountSettingsSection />);

      expect(await screen.findByText('Dev')).toBeInTheDocument();
      expect(screen.getByText('dev@mastra.ai')).toBeInTheDocument();
      // Humanized from the provider name, with no hand-written override table:
      // "Workos" rather than "WorkOS". The row names the identity system, which
      // the descriptor deliberately does not carry — see `authProviderLabel`.
      expect(screen.getByText('Workos')).toBeInTheDocument();
      expect(screen.getByText('user-1')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Copy account ID' })).toBeInTheDocument();
      expect(screen.getByText('org-1')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Copy organization ID' })).toBeInTheDocument();
    });

    it('offers logout as an explicit session action', async () => {
      stubAuthenticatedAccount();

      renderWithProviders(<AccountSettingsSection />);

      expect(await screen.findByRole('button', { name: 'Log out of MastraCode' })).toBeInTheDocument();
    });

    it('humanizes an auth provider it has never seen', async () => {
      stubAuthenticatedAccount({ provider: 'acme-identity-cloud' });

      renderWithProviders(<AccountSettingsSection />);

      expect(await screen.findByText('Acme Identity Cloud')).toBeInTheDocument();
    });

    describe('and the descriptor reports whether there is a session to end', () => {
      it('keeps the logout control when the provider offers one', async () => {
        stubAuthenticatedAccount(descriptorWithFeatures({ logout: true }));

        renderWithProviders(<AccountSettingsSection />);

        expect(await screen.findByRole('button', { name: 'Log out of MastraCode' })).toBeInTheDocument();
      });

      it('hides it for a provider with nothing to sign out of', async () => {
        // `features.logout: false` means a pure bearer-token validator: no
        // hosted login, no session, no auth routes of its own. The host mounts
        // `/auth/logout` for neither, so the button would have posted to a
        // route that was never registered.
        stubAuthenticatedAccount(descriptorWithFeatures({ logout: false }));

        renderWithProviders(<AccountSettingsSection />);

        expect(await screen.findByText('dev@mastra.ai')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Log out of MastraCode' })).not.toBeInTheDocument();
      });

      it('still shows it for a server that sends no descriptor', async () => {
        stubAuthenticatedAccount();

        renderWithProviders(<AccountSettingsSection />);

        expect(await screen.findByRole('button', { name: 'Log out of MastraCode' })).toBeInTheDocument();
      });
    });
  });

  describe('when authentication is disabled', () => {
    it('explains why account actions are unavailable', async () => {
      server.use(
        http.get(`${TEST_BASE_URL}/auth/me`, () => HttpResponse.json({ error: 'not_found' }, { status: 404 })),
      );

      renderWithProviders(<AccountSettingsSection />);

      expect(await screen.findByText('Authentication is not enabled for this deployment.')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Log out of MastraCode' })).not.toBeInTheDocument();
    });
  });
});
