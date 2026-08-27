import { Button } from '@mastra/playground-ui/components/Button';
import { Input } from '@mastra/playground-ui/components/Input';
import { Txt } from '@mastra/playground-ui/components/Txt';
import { Building2, KeyRound, LogIn, Mail, ShieldCheck } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { Navigate, useSearchParams } from 'react-router';
import '@fontsource-variable/mona-sans/standard.css';

import { useApiConfig } from '../../api/config';
import { useFactoryAuth } from '../../hooks/useFactoryAuth';
import {
  credentialsBasePath,
  DEFAULT_PROVIDER_HINT,
  isSignUpEnabled,
  navigateAfterSignIn,
  redirectToLogin,
  signInWithPassword,
  signUpWithPassword,
} from '../domains/auth/services/auth';
import type { AuthProviderHint, AuthSignInDescriptor, AuthSignInKind } from '../domains/auth/services/auth';
import { FactoryHalftoneField } from '../domains/auth/components/FactoryHalftoneField';
import '../domains/auth/components/sign-in-page.css';

/**
 * Only accept same-origin paths so a crafted `?returnTo=` can't bounce the
 * user to an external site after login. Prefix checks alone are not enough —
 * browsers normalize `/\host` to the protocol-relative `//host` — so the value
 * is resolved against the page origin and rejected when it leaves it.
 */
export function safeReturnTo(raw?: string): string {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//')) return '/';
  try {
    const resolved = new URL(raw, window.location.origin);
    if (resolved.origin !== window.location.origin) return '/';
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return '/';
  }
}

/**
 * Email/password credential form, rendered for any provider whose descriptor
 * reports a credentials sign-in. Posts to the provider's credential endpoints
 * (which set the session cookie), then does a full navigation to `returnTo` so
 * the app boots with the fresh session.
 *
 * `signUpEnabled` is **positive**, matching the descriptor and the provider
 * method behind it, and it is the only polarity on the wire — the response used
 * to carry a negative legacy field beside it, which is where a dropped `!`
 * could render this form's sign-up control on a deployment that had switched
 * sign-up off. `isSignUpEnabled` still owns the read, so the default for an
 * unstated field lives in one place rather than at every call site.
 */
function CredentialSignInForm({
  returnTo,
  signUpEnabled,
  basePath,
}: {
  returnTo: string;
  signUpEnabled: boolean;
  basePath: string;
}) {
  const { baseUrl } = useApiConfig();
  const [mode, setMode] = useState<'sign-in' | 'sign-up'>('sign-in');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      if (mode === 'sign-up') {
        await signUpWithPassword({ baseUrl, basePath }, { name, email, password });
      } else {
        await signInWithPassword({ baseUrl, basePath }, { email, password });
      }
      navigateAfterSignIn(returnTo);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
      setPending(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex w-full flex-col gap-5">
      {mode === 'sign-up' ? (
        <label className="text-neutral5 flex flex-col gap-2 text-sm font-medium">
          Name
          <Input
            type="text"
            size="lg"
            placeholder="Ada Lovelace"
            autoComplete="name"
            required
            value={name}
            onChange={e => setName(e.target.value)}
          />
        </label>
      ) : null}
      <label className="text-neutral5 flex flex-col gap-2 text-sm font-medium">
        Email
        <Input
          type="email"
          size="lg"
          placeholder="you@company.com"
          autoComplete="email"
          required
          value={email}
          onChange={e => setEmail(e.target.value)}
        />
      </label>
      <label className="text-neutral5 flex flex-col gap-2 text-sm font-medium">
        Password
        <Input
          type="password"
          size="lg"
          placeholder="Enter your password"
          autoComplete={mode === 'sign-up' ? 'new-password' : 'current-password'}
          required
          value={password}
          onChange={e => setPassword(e.target.value)}
        />
      </label>
      {error ? (
        <Txt as="p" variant="ui-sm" role="alert" className="text-accent2">
          {error}
        </Txt>
      ) : null}
      <Button type="submit" variant="primary" size="lg" className="w-full" disabled={pending}>
        {pending ? 'Please wait…' : mode === 'sign-up' ? 'Create account' : 'Sign in'}
      </Button>
      {signUpEnabled ? (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="self-center"
          onClick={() => {
            setError(null);
            setMode(mode === 'sign-up' ? 'sign-in' : 'sign-up');
          }}
        >
          {mode === 'sign-up' ? 'Have an account? Sign in' : 'New here? Sign up'}
        </Button>
      ) : (
        <Txt as="p" variant="ui-sm" className="text-neutral3 text-center">
          Account creation is managed by your administrator.
        </Txt>
      )}
    </form>
  );
}

/** Icon and copy for the hosted-login button. */
interface HostedPresentation {
  icon: ReactNode;
  label: string;
  pendingLabel: string;
}

/**
 * `AuthProviderHint` → visual treatment. **One map, no vendors.**
 *
 * The tokens are rendering instructions, not provider names, and that is the
 * whole point: adding an identity provider server-side must never mean editing
 * this file. So nothing here may become a vendor logo — a token that resolved to
 * the GitHub mark would reintroduce exactly the coupling the descriptor removes,
 * which is the bug described at {@link NO_DESCRIPTOR_SIGN_IN_KIND}.
 *
 * Every icon is therefore neutral and describes the *shape of the flow*: a
 * building for an organization's IdP, a shield for a redirect to a consumer
 * identity provider, an envelope for an email-addressed flow.
 */
const HOSTED_PRESENTATION: Record<AuthProviderHint, HostedPresentation> = {
  generic: {
    icon: <LogIn aria-hidden="true" />,
    label: 'Continue to sign in',
    pendingLabel: 'Opening sign-in…',
  },
  sso: {
    icon: <Building2 aria-hidden="true" />,
    label: 'Continue with single sign-on',
    pendingLabel: 'Opening single sign-on…',
  },
  oauth: {
    icon: <ShieldCheck aria-hidden="true" />,
    label: 'Continue with your identity provider',
    pendingLabel: 'Opening your identity provider…',
  },
  email: {
    icon: <Mail aria-hidden="true" />,
    label: 'Continue with email',
    pendingLabel: 'Opening email sign-in…',
  },
};

/**
 * Resolve the hosted button's look from the descriptor.
 *
 * A host-supplied `label` overrides the copy but never the icon: copy is the
 * host's to write, whereas an icon chosen by anything other than the token would
 * be a vendor mark arriving through the back door.
 */
function hostedPresentation(signIn: AuthSignInDescriptor): HostedPresentation {
  const base = HOSTED_PRESENTATION[signIn.providerHint ?? 'generic'];
  return signIn.label ? { ...base, label: signIn.label } : base;
}

/**
 * What the page offers when there is no descriptor to read: while `/auth/me` is
 * still in flight, and on a response this build cannot act on (an older server,
 * or a newer one sending a `signIn.kind` this build has no branch for).
 *
 * A hosted-login button in its neutral treatment, which is the control that
 * works for the widest range of providers and names none of them.
 *
 * WHAT THIS REPLACED, BECAUSE IT IS THE REASON THE DESCRIPTOR EXISTS
 *
 * The fallback used to be a provider-name lookup: one name got the credential
 * form, one got a Mastra Platform button, and *every other name fell through to
 * a GitHub branch* — so a deployment on an identity provider this SPA had never
 * heard of told its users to "Continue with GitHub", under a GitHub logo. It
 * worked on whichever deployment the author had tested and was wrong
 * everywhere else. Nothing here may name a provider again; the gate in
 * `ui/__tests__/no-provider-literals.test.ts` fails the build if it does.
 */
const NO_DESCRIPTOR_SIGN_IN_KIND: AuthSignInKind = 'hosted';

/**
 * `signIn.kind === 'none'`: the provider works, enforces, and validates API
 * tokens, but implements neither a hosted login nor a credentials sign-in, so it
 * cannot take anyone from a blank browser to a session. Today that is Supabase
 * and Firebase.
 *
 * **This is not auth being switched off.** That deployment has no provider and
 * therefore no descriptor at all; it reports `authEnabled: false` and this page
 * redirects away before rendering. The two states look similar and mean opposite
 * things, so `none` may neither draw an empty box nor wave the visitor through —
 * it has to say what the deployment can actually do and who to ask.
 */
function SignInUnavailable() {
  return (
    <div className="border-border1 bg-surface3 flex items-start gap-3 rounded-lg border px-5 py-4">
      <KeyRound aria-hidden="true" className="text-neutral4 mt-0.5 size-5 shrink-0" />
      <div>
        <Txt as="h2" variant="header-xs" className="text-neutral6 font-medium">
          Sign-in isn’t available for this provider
        </Txt>
        <Txt as="p" variant="ui-sm" className="text-neutral3 mt-2 leading-5">
          This deployment uses a provider that validates API tokens but can’t sign you in from a browser. Ask your
          administrator for a token, or configure a provider that supports browser sign-in.
        </Txt>
      </div>
    </div>
  );
}

/**
 * Dedicated `/signin` route rendered when web auth is enabled and the session is
 * unauthenticated.
 *
 * The page branches on the provider's declared **capability**, and on nothing
 * else: `signIn.kind` decides which controls exist, and `providerHint` decides
 * how the hosted one looks. A provider the SPA has never heard of therefore
 * gets a correct screen without this file changing, and the provider's *name*
 * is not read here at all — see {@link NO_DESCRIPTOR_SIGN_IN_KIND} for what
 * happens when there is no descriptor to read.
 *
 * Every kind preserves where the user was headed via `?returnTo=`.
 */
export function SignInPage() {
  const { baseUrl } = useApiConfig();
  const auth = useFactoryAuth();
  const [searchParams] = useSearchParams();
  const [redirecting, setRedirecting] = useState(false);
  const returnTo = safeReturnTo(searchParams.get('returnTo') ?? undefined);
  const authError = searchParams.get('error');
  const authErrorDescription = searchParams.get('error_description');
  const accessDenied = authError === 'access_denied';

  // The descriptor decides what this page offers, and it is the only thing
  // that does. While the query is still pending there is no descriptor, which
  // resolves to the hosted button in its disabled state — the same thing this
  // page shows while loading, and never the `none` panel.
  const descriptor = auth.data?.auth;
  const signInKind: AuthSignInKind = descriptor?.signIn.kind ?? NO_DESCRIPTOR_SIGN_IN_KIND;
  const hosted = descriptor ? hostedPresentation(descriptor.signIn) : HOSTED_PRESENTATION[DEFAULT_PROVIDER_HINT];
  const showCredentials = signInKind === 'credentials' || signInKind === 'both';
  const showHostedLogin = signInKind === 'hosted' || signInKind === 'both';

  // Mirror of the root auth guard: signed-in (or auth-disabled) visitors have
  // nothing to do here, so send them to their destination (or the root landing
  // when returnTo is absent/unsafe).
  if (!auth.isPending && (!auth.data?.authEnabled || auth.data.authenticated)) {
    return <Navigate to={returnTo} replace />;
  }

  return (
    <main className="factory-signin-theme bg-surface1 font-mona-sans text-neutral6 min-h-dvh">
      <div className="mx-auto grid min-h-dvh w-full max-w-7xl grid-cols-1 px-6 sm:px-10 lg:grid-cols-[minmax(380px,0.82fr)_minmax(540px,1.18fr)]">
        <section className="relative z-3 flex max-w-xl flex-col justify-center py-11 lg:py-17">
          <h1 className="max-w-xl text-[clamp(2.625rem,5.3vw,4.25rem)] leading-[1.1] font-[520] tracking-[0.015em] text-balance [font-stretch:112%]">
            Build with an agent factory
          </h1>
          <Txt
            as="p"
            variant="ui-lg"
            className="text-neutral3 mt-6 max-w-lg text-[clamp(1.0625rem,1.65vw,1.375rem)] leading-[1.36] tracking-[0.015em]"
          >
            Turn a repository into a working factory. Agents pick up scoped work, collaborate, and ship changes you can
            review.
          </Txt>

          <section aria-label="Authentication" className="mt-10 w-full max-w-md lg:mt-12">
            {authError ? (
              <div role="alert" className="border-accent2/30 bg-surface3 mb-6 rounded-lg border px-4 py-3">
                <Txt as="p" variant="ui-md" className="text-accent2 font-medium">
                  {accessDenied ? 'Access denied' : 'Sign-in failed'}
                </Txt>
                {authErrorDescription ? (
                  <Txt as="p" variant="ui-sm" className="text-neutral4 mt-1 leading-5">
                    {authErrorDescription}
                  </Txt>
                ) : null}
                {accessDenied ? (
                  <Txt as="p" variant="ui-sm" className="text-neutral3 mt-1 leading-5">
                    Ask an organization admin to add your account, then sign in again.
                  </Txt>
                ) : null}
              </div>
            ) : null}
            {signInKind === 'none' ? <SignInUnavailable /> : null}
            {showCredentials ? (
              <>
                <div className="mb-6">
                  <h2 className="font-display text-2xl font-medium">Welcome back</h2>
                  <Txt as="p" variant="ui-md" className="text-neutral3 mt-2 leading-6">
                    Sign in to continue building with your team.
                  </Txt>
                </div>
                <CredentialSignInForm
                  returnTo={returnTo}
                  signUpEnabled={isSignUpEnabled(auth.data)}
                  basePath={credentialsBasePath(auth.data)}
                />
              </>
            ) : null}
            {showCredentials && showHostedLogin ? (
              <div className="my-6 flex items-center gap-4" aria-hidden="true">
                <span className="bg-border1 h-px flex-1" />
                <Txt as="span" variant="ui-sm" className="text-neutral3">
                  or
                </Txt>
                <span className="bg-border1 h-px flex-1" />
              </div>
            ) : null}
            {showHostedLogin ? (
              <Button
                variant="default"
                size="lg"
                className="w-80 max-w-full"
                disabled={redirecting || auth.isPending}
                onClick={() => {
                  setRedirecting(true);
                  redirectToLogin(baseUrl, returnTo);
                }}
              >
                {hosted.icon}
                {redirecting ? hosted.pendingLabel : hosted.label}
              </Button>
            ) : null}
          </section>
        </section>

        <FactoryHalftoneField />
      </div>
    </main>
  );
}
