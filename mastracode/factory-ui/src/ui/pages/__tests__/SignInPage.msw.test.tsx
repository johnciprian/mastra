/**
 * BDD coverage for the capability-driven /signin page.
 *
 * Drives the real route table (SignInGate → SignInPage) through a memory router
 * with MSW stubbing `/auth/me` and the credential endpoints. The page renders
 * from the capability descriptor and from nothing else: `signIn.kind` decides
 * which controls exist and `providerHint` decides how the hosted one looks. A
 * separate block covers what a response with no usable descriptor falls back to.
 *
 * Colocated with the page under `src/ui/pages/__tests__/`, alongside the other
 * page suites. It previously sat under `domains/auth/components/__tests__/`,
 * which was the odd one out — it tests a route, not a domain component.
 */
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { createMemoryRouter, RouterProvider } from 'react-router';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { server } from '../../../../e2e/ui/msw-server';
import { renderWithProviders, TEST_BASE_URL } from '../../../../e2e/ui/render';
import { navigateAfterSignIn, redirectToLogin } from '../../domains/auth/services/auth';
import type * as AuthService from '../../domains/auth/services/auth';
import { createAppRoutes } from '../../router';
import { safeReturnTo } from '../SignInPage';

// jsdom's `window.location.assign` is unforgeable (cannot be spied on), so the
// service-level navigation helpers are stubbed instead; `fetchAuthState` and
// the credential POST helpers stay real so MSW sees the actual requests.
vi.mock('../../domains/auth/services/auth', async importOriginal => {
  const actual = await importOriginal<typeof AuthService>();
  return { ...actual, redirectToLogin: vi.fn(), navigateAfterSignIn: vi.fn() };
});

const AUTH_ME_URL = `${TEST_BASE_URL}/auth/me`;

afterEach(() => {
  vi.mocked(redirectToLogin).mockClear();
  vi.mocked(navigateAfterSignIn).mockClear();
});

function stubAuthMe(body: Record<string, unknown>) {
  server.use(http.get(AUTH_ME_URL, () => HttpResponse.json({ authenticated: false, user: null, ...body })));
}

function renderSignIn(initialEntry = '/signin') {
  const router = createMemoryRouter(createAppRoutes(), { initialEntries: [initialEntry] });
  renderWithProviders(<RouterProvider router={router} />);
  return router;
}

describe('SignInPage', () => {
  it('renders the agent factory welcome message without a separate page header', async () => {
    stubAuthMe({});
    renderSignIn();

    expect(await screen.findByRole('heading', { name: 'Build with an agent factory' })).toBeInTheDocument();
    expect(screen.getByText(/Turn a repository into a working factory/)).toBeInTheDocument();
    expect(screen.queryByRole('banner')).not.toBeInTheDocument();
  });

  /**
   * No usable descriptor: an older server that sends none, or a newer one
   * sending a `signIn.kind` this build has no branch for.
   *
   * The page used to look the provider's *name* up here — one name got the
   * credential form, one got a Mastra Platform button, and every other name
   * fell through to a GitHub branch, so a deployment on an unrecognized
   * identity provider was told to "Continue with GitHub". That lookup is gone,
   * and these cases pin what stands in its place: one neutral hosted-login
   * button that names nobody, whatever the response calls its provider.
   */
  describe('given a response with no usable descriptor', () => {
    it('offers a neutral hosted-login button and redirects through it', async () => {
      stubAuthMe({ provider: 'some-provider-we-have-never-heard-of' });
      renderSignIn('/signin?returnTo=%2Ffactory%2Fboard');

      const button = await screen.findByRole('button', { name: 'Continue to sign in' });
      expect(screen.queryByLabelText('Email')).not.toBeInTheDocument();

      await userEvent.click(button);
      expect(button).toBeDisabled();
      expect(button).toHaveTextContent('Opening sign-in…');
      expect(redirectToLogin).toHaveBeenCalledWith(TEST_BASE_URL, '/factory/board');
    });

    it.each(['better-auth', 'mastra-studio', 'workos'])(
      'renders the same neutral button for the once-special-cased name %j',
      async provider => {
        // The three names the old lookup branched on. None of them may change
        // what this page renders any more.
        stubAuthMe({ provider });
        renderSignIn();

        expect(await screen.findByRole('button', { name: 'Continue to sign in' })).toBeInTheDocument();
        expect(screen.queryByLabelText('Email')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /GitHub|Mastra Platform/ })).not.toBeInTheDocument();
      },
    );

    it('falls back to it for a descriptor kind this build cannot act on', async () => {
      // A newer server sending a fifth kind. `parseAuthDescriptor` rejects it
      // rather than dropping the payload into whichever branch is last, and the
      // fallback is what the visitor gets.
      stubAuthMe({ provider: 'some-provider', auth: { signIn: { kind: 'passkey' }, features: {} } });
      renderSignIn();

      expect(await screen.findByRole('button', { name: 'Continue to sign in' })).toBeInTheDocument();
    });
  });

  /**
   * The capability-driven page: `signIn.kind` decides which controls exist and
   * `providerHint` decides how the hosted one looks, so a provider this SPA has
   * never heard of still gets a correct screen. Every kind is covered here, plus
   * the hint treatments, the credentials mount, and the sign-up affordance.
   */
  describe('given a server that sends the capability descriptor', () => {
    function stubDescriptor(signIn: Record<string, unknown>, rest: Record<string, unknown> = {}) {
      stubAuthMe({
        // A provider name the SPA has never seen. Every assertion below is
        // therefore also evidence that the descriptor drove the render: nothing
        // about this name could have produced a credential form or a labelled
        // hosted button on its own.
        provider: 'some-provider-we-have-never-heard-of',
        auth: {
          signIn,
          features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
        },
        ...rest,
      });
    }

    describe('kind: hosted', () => {
      it('renders a neutral hosted button for an unrecognised provider instead of a vendor one', async () => {
        stubDescriptor({ kind: 'hosted', providerHint: 'generic' });
        renderSignIn('/signin?returnTo=%2Ffactory%2Fboard');

        const button = await screen.findByRole('button', { name: 'Continue to sign in' });
        expect(screen.queryByRole('button', { name: 'Continue with GitHub' })).not.toBeInTheDocument();
        expect(screen.queryByLabelText('Email')).not.toBeInTheDocument();

        await userEvent.click(button);
        expect(button).toHaveTextContent('Opening sign-in…');
        expect(redirectToLogin).toHaveBeenCalledWith(TEST_BASE_URL, '/factory/board');
      });

      it.each([
        ['sso', 'Continue with single sign-on'],
        ['oauth', 'Continue with your identity provider'],
        ['email', 'Continue with email'],
      ])('renders the %s treatment from the rendering token alone', async (providerHint, label) => {
        stubDescriptor({ kind: 'hosted', providerHint });
        renderSignIn();

        expect(await screen.findByRole('button', { name: label })).toBeInTheDocument();
      });

      it('prefers host-supplied copy over the token default', async () => {
        stubDescriptor({ kind: 'hosted', providerHint: 'sso', label: 'Continue with your work account' });
        renderSignIn();

        expect(await screen.findByRole('button', { name: 'Continue with your work account' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'Continue with single sign-on' })).not.toBeInTheDocument();
      });
    });

    describe('kind: credentials', () => {
      it('renders the form and no hosted button', async () => {
        stubDescriptor({ kind: 'credentials', signUpEnabled: true });
        renderSignIn();

        expect(await screen.findByLabelText('Email')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'New here? Sign up' })).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^Continue/ })).not.toBeInTheDocument();
      });

      it('hides the sign-up affordance when the descriptor disables it', async () => {
        stubDescriptor({ kind: 'credentials', signUpEnabled: false });
        renderSignIn();

        expect(await screen.findByLabelText('Email')).toBeInTheDocument();
        expect(screen.queryByRole('button', { name: 'New here? Sign up' })).not.toBeInTheDocument();
        expect(screen.getByText('Account creation is managed by your administrator.')).toBeInTheDocument();
      });

      it('surfaces the server error message on failed sign-in', async () => {
        stubDescriptor({ kind: 'credentials', signUpEnabled: true });
        server.use(
          http.post(`${TEST_BASE_URL}/auth/api/sign-in/email`, () =>
            HttpResponse.json({ message: 'Invalid email or password' }, { status: 401 }),
          ),
        );
        renderSignIn();

        await userEvent.type(await screen.findByLabelText('Email'), 'ada@example.com');
        await userEvent.type(screen.getByLabelText('Password'), 'wrong');
        await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

        expect(await screen.findByRole('alert')).toHaveTextContent('Invalid email or password');
        expect(navigateAfterSignIn).not.toHaveBeenCalled();
      });

      it('posts to the auth mount the descriptor reports, not a hardcoded one', async () => {
        // The whole point of `credentialsBasePath`: a provider serving its own
        // auth routes somewhere else works without the SPA knowing which
        // provider it is. No handler is registered on `/auth/api/*`, so a
        // regression to the hardcoded path trips MSW's unhandled-request error.
        stubDescriptor({ kind: 'credentials', signUpEnabled: true, credentialsBasePath: '/identity' });
        const posted = vi.fn();
        server.use(
          http.post(`${TEST_BASE_URL}/identity/api/sign-in/email`, async ({ request }) => {
            posted(await request.json());
            return HttpResponse.json({ user: { id: 'user_9' } });
          }),
        );
        renderSignIn('/signin?returnTo=%2Ffactory%2Fboard');

        await userEvent.type(await screen.findByLabelText('Email'), 'ada@example.com');
        await userEvent.type(screen.getByLabelText('Password'), 'hunter22!');
        await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

        await waitFor(() => expect(navigateAfterSignIn).toHaveBeenCalledWith('/factory/board'));
        expect(posted).toHaveBeenCalledWith({ email: 'ada@example.com', password: 'hunter22!' });
      });

      it('signs up against the reported mount too', async () => {
        stubDescriptor({ kind: 'credentials', signUpEnabled: true, credentialsBasePath: '/identity' });
        const posted = vi.fn();
        server.use(
          http.post(`${TEST_BASE_URL}/identity/api/sign-up/email`, async ({ request }) => {
            posted(await request.json());
            return HttpResponse.json({ user: { id: 'user_10' } });
          }),
        );
        renderSignIn();

        await userEvent.click(await screen.findByRole('button', { name: 'New here? Sign up' }));
        await userEvent.type(screen.getByLabelText('Name'), 'Ada Lovelace');
        await userEvent.type(screen.getByLabelText('Email'), 'ada@example.com');
        await userEvent.type(screen.getByLabelText('Password'), 'hunter22!');
        await userEvent.click(screen.getByRole('button', { name: 'Create account' }));

        await waitFor(() => expect(navigateAfterSignIn).toHaveBeenCalledWith('/'));
        expect(posted).toHaveBeenCalledWith({
          name: 'Ada Lovelace',
          email: 'ada@example.com',
          password: 'hunter22!',
        });
      });

      it('ignores a mount that would post the password off-origin', async () => {
        // Served same-origin the SPA has an empty `baseUrl`, so `//evil.example`
        // would become a protocol-relative URL and send the password there. The
        // guard falls back to `/auth`, which is where the handler below sits.
        stubDescriptor({ kind: 'credentials', signUpEnabled: true, credentialsBasePath: '//evil.example' });
        const posted = vi.fn();
        server.use(
          http.post(`${TEST_BASE_URL}/auth/api/sign-in/email`, async ({ request }) => {
            posted(await request.json());
            return HttpResponse.json({ user: { id: 'user_11' } });
          }),
        );
        renderSignIn();

        await userEvent.type(await screen.findByLabelText('Email'), 'ada@example.com');
        await userEvent.type(screen.getByLabelText('Password'), 'hunter22!');
        await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

        await waitFor(() => expect(posted).toHaveBeenCalled());
      });
    });

    describe('kind: both', () => {
      it('renders the credential form and the hosted button together', async () => {
        stubDescriptor({ kind: 'both', providerHint: 'sso', signUpEnabled: true });
        renderSignIn();

        expect(await screen.findByLabelText('Email')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Sign in' })).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'Continue with single sign-on' })).toBeInTheDocument();
      });

      it('drives each route independently — the hosted button still redirects', async () => {
        stubDescriptor({ kind: 'both', providerHint: 'sso', signUpEnabled: true });
        renderSignIn('/signin?returnTo=%2Ffactory%2Fboard');

        await userEvent.click(await screen.findByRole('button', { name: 'Continue with single sign-on' }));

        expect(redirectToLogin).toHaveBeenCalledWith(TEST_BASE_URL, '/factory/board');
      });

      it('and the credential form still posts', async () => {
        stubDescriptor({ kind: 'both', providerHint: 'sso', signUpEnabled: true });
        const posted = vi.fn();
        server.use(
          http.post(`${TEST_BASE_URL}/auth/api/sign-in/email`, async ({ request }) => {
            posted(await request.json());
            return HttpResponse.json({ user: { id: 'user_12' } });
          }),
        );
        renderSignIn();

        await userEvent.type(await screen.findByLabelText('Email'), 'ada@example.com');
        await userEvent.type(screen.getByLabelText('Password'), 'hunter22!');
        await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));

        await waitFor(() => expect(navigateAfterSignIn).toHaveBeenCalledWith('/'));
        expect(posted).toHaveBeenCalledWith({ email: 'ada@example.com', password: 'hunter22!' });
      });
    });

    describe('kind: none', () => {
      it('explains that this provider cannot sign you in from a browser', async () => {
        stubDescriptor({ kind: 'none' });
        renderSignIn();

        expect(
          await screen.findByRole('heading', { name: /Sign-in isn.t available for this provider/ }),
        ).toBeInTheDocument();
        expect(screen.getByText(/validates API tokens but can.t sign you in from a browser/)).toBeInTheDocument();
        expect(screen.getByText(/Ask your\s+administrator for a token/)).toBeInTheDocument();
      });

      it('offers no sign-in control at all, rather than an empty box', async () => {
        stubDescriptor({ kind: 'none' });
        renderSignIn();

        await screen.findByRole('heading', { name: /Sign-in isn.t available for this provider/ });
        expect(screen.queryByLabelText('Email')).not.toBeInTheDocument();
        expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^Continue/ })).not.toBeInTheDocument();
        expect(screen.queryByRole('button', { name: /^Sign in/ })).not.toBeInTheDocument();
        expect(redirectToLogin).not.toHaveBeenCalled();
      });
    });

    /**
     * The sign-up affordance, driven end to end through the page.
     *
     * A response used to describe sign-up twice, in opposite directions, and
     * the failure that made that dangerous is silent: a sign-up link on a
     * deployment that disabled sign-up looks like a working page, not a bug.
     * The second field is gone, so what these pin is that the descriptor's own
     * field decides — including when a stray negative field is still on the
     * wire from a proxy or a mixed-version deployment.
     */
    describe('given a legacy negative field still on the payload', () => {
      it.each([
        // label, signUpEnabled (the descriptor's own field), sign-up offered?
        ['descriptor on, stray field says off', true, true],
        ['descriptor off, stray field says off', false, false],
      ])('resolves %s from the descriptor', async (_label, signUpEnabled, offered) => {
        stubDescriptor({ kind: 'credentials', signUpEnabled }, { signUpDisabled: true });
        renderSignIn();

        // The form itself is unaffected either way; only the affordance moves.
        expect(await screen.findByLabelText('Email')).toBeInTheDocument();
        const signUp = screen.queryByRole('button', { name: 'New here? Sign up' });
        if (offered) {
          expect(signUp).toBeInTheDocument();
        } else {
          expect(signUp).not.toBeInTheDocument();
          expect(screen.getByText('Account creation is managed by your administrator.')).toBeInTheDocument();
        }
      });

      it('defaults to enabled when the descriptor omits the field, stray or not', async () => {
        // Not what the Factory emits for a credentials provider, but a
        // hand-rolled server can omit it. Absent reads as "not stated", whose
        // documented default is enabled — and the stray negative field does not
        // get to overturn that, because nothing reads it.
        stubDescriptor({ kind: 'credentials' }, { signUpDisabled: true });
        renderSignIn();

        expect(await screen.findByLabelText('Email')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: 'New here? Sign up' })).toBeInTheDocument();
      });
    });

    it('renders from the descriptor even when the provider name suggests otherwise', async () => {
      // U9's doneWhen, stated directly: the descriptor is the only input to the
      // sign-in decision. This name once mapped to the credential form; the
      // descriptor says hosted, and hosted is what renders.
      stubAuthMe({
        provider: 'better-auth',
        auth: {
          signIn: { kind: 'hosted', providerHint: 'generic' },
          features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
        },
      });
      renderSignIn();

      expect(await screen.findByRole('button', { name: 'Continue to sign in' })).toBeInTheDocument();
      expect(screen.queryByLabelText('Email')).not.toBeInTheDocument();
    });
  });

  describe('given an IdP access_denied redirect', () => {
    function stubHostedDescriptor() {
      stubAuthMe({
        provider: 'some-provider',
        auth: {
          signIn: { kind: 'hosted', providerHint: 'sso' },
          features: { logout: true, organizations: false, refresh: false, sessionRevocation: false },
        },
      });
    }

    it('shows the denial with the IdP description and still allows a retry', async () => {
      stubHostedDescriptor();
      const description = encodeURIComponent('You do not have access to this application.');
      renderSignIn(`/signin?error=access_denied&error_description=${description}`);

      const alert = await screen.findByRole('alert');
      expect(alert).toHaveTextContent('Access denied');
      expect(alert).toHaveTextContent('You do not have access to this application.');
      expect(alert).toHaveTextContent('Ask an organization admin to add your account');

      await userEvent.click(await screen.findByRole('button', { name: 'Continue with single sign-on' }));
      expect(redirectToLogin).toHaveBeenCalledWith(TEST_BASE_URL, '/');
    });

    it('falls back to the admin hint when the IdP sends no description', async () => {
      stubHostedDescriptor();
      renderSignIn('/signin?error=access_denied');

      const alert = await screen.findByRole('alert');
      expect(alert).toHaveTextContent('Access denied');
      expect(alert).toHaveTextContent('Ask an organization admin to add your account');
    });
  });

  describe('returnTo sanitization', () => {
    it.each([
      ['/factory/board?x=1#frag', '/factory/board?x=1#frag'],
      ['//attacker.example', '/'],
      // Browsers normalize `/\` to `//` — an encoded backslash must not
      // become a protocol-relative cross-origin redirect.
      ['/\\attacker.example', '/'],
      ['/\\/attacker.example', '/'],
      ['https://attacker.example/x', '/'],
      ['javascript:alert(1)', '/'],
      [undefined, '/'],
    ])('resolves %s to %s against the page origin', (raw, expected) => {
      expect(safeReturnTo(raw)).toBe(expected);
    });
  });
});
