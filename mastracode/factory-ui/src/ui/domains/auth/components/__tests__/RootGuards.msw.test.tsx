/**
 * BDD coverage for what the auth guard PUTS ON SCREEN in its non-app states.
 *
 * The three states are easy to confuse and two of them used to render
 * identically: "still checking", "the check failed", and "this server has no
 * auth provider" all reached `AuthPendingSkeleton`, whose only text is a
 * `BrandLoader` `aria-label`. A sighted visitor saw a bare spinner with no
 * words, retrying every two seconds, and could not tell a broken deployment
 * from a slow one.
 *
 * These tests assert on VISIBLE text (`getByText`, not `getByLabelText`),
 * because the defect was precisely that the text existed only for assistive
 * technology.
 */
import { screen, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { MemoryRouter } from 'react-router';
import { describe, expect, it, vi } from 'vitest';

import { server } from '../../../../../../e2e/ui/msw-server';
import { renderWithProviders, TEST_BASE_URL } from '../../../../../../e2e/ui/render';
import { RootGuards } from '../RootGuards';

const AUTH_ME_URL = `${TEST_BASE_URL}/auth/me`;

const renderGuard = () =>
  renderWithProviders(
    <MemoryRouter initialEntries={['/']}>
      <RootGuards />
    </MemoryRouter>,
  );

describe('RootGuards', () => {
  describe('given /auth/me cannot be reached', () => {
    it('says so in visible text rather than spinning silently', async () => {
      server.use(http.get(AUTH_ME_URL, () => new Response(null, { status: 500 })));

      renderGuard();

      await waitFor(() => expect(screen.getByText(/can't check whether you're signed in/i)).toBeInTheDocument());
      // The distinguishing detail: a reader must be told this is the server's
      // problem and that the page is still retrying, or the only available
      // action is to reload forever.
      expect(screen.getByText(/keeps retrying/i)).toBeInTheDocument();
    });
  });

  describe('given the server reports auth is disabled', () => {
    /**
     * Auth off is a supported way to run this locally, so the guard must not
     * stop. The server substitutes a single local tenant, so every
     * tenant-scoped route still serves and there is nobody to sign in as.
     *
     * What proves the fall-through is that `OnboardingGuard` ran — it is the
     * next guard, and the only thing that asks for the factory list.
     */
    it('falls through to the app instead of stopping at a screen', async () => {
      const factoriesRequested = vi.fn();
      server.use(http.get(AUTH_ME_URL, () => HttpResponse.json(null, { status: 404 })));
      server.use(
        http.get(`${TEST_BASE_URL}/web/factory/projects`, () => {
          factoriesRequested();
          return HttpResponse.json({ projects: [] });
        }),
      );

      renderGuard();

      await waitFor(() => expect(factoriesRequested).toHaveBeenCalled());
      expect(screen.queryByText(/no authentication provider configured/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/can't check whether you're signed in/i)).not.toBeInTheDocument();
    });

    /**
     * The production shape of "auth is disabled": the route is not mounted, so
     * the SPA fallback answers with 200 index.html instead of a 404. It has to
     * reach the same place as the 404 above — it is the same fact about the
     * deployment, only reported differently by the host.
     */
    it('reaches the same place when the unmounted route serves the SPA fallback', async () => {
      const factoriesRequested = vi.fn();
      server.use(
        http.get(
          AUTH_ME_URL,
          () =>
            new HttpResponse('<!doctype html><html><head><title>Mastra Factory</title></head></html>', {
              status: 200,
              headers: { 'Content-Type': 'text/html' },
            }),
        ),
      );
      server.use(
        http.get(`${TEST_BASE_URL}/web/factory/projects`, () => {
          factoriesRequested();
          return HttpResponse.json({ projects: [] });
        }),
      );

      renderGuard();

      await waitFor(() => expect(factoriesRequested).toHaveBeenCalled());
      expect(screen.queryByText(/can't check whether you're signed in/i)).not.toBeInTheDocument();
    });
  });
});
