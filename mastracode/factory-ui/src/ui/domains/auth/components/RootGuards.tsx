import { BrandLoader } from '@mastra/playground-ui/components/BrandLoader';
import { useFactoryAuth } from '../../../../hooks/useFactoryAuth';
import { useFactoriesQuery } from '../../../../hooks/useFactories';
import { hasResumableFactoryOnboarding } from '../../workspaces/services/onboardingFlow';
import { Navigate, Outlet, useLocation } from 'react-router';

export const RootGuards = () => {
  return <AuthGuard />;
};

const AuthGuard = () => {
  const { isPending, isError, data } = useFactoryAuth();
  const location = useLocation();

  if (isPending) return <AuthPendingSkeleton />;
  // Not a skeleton: a failed check is a state, not a slower version of loading.
  // `AuthPendingSkeleton` carries its label only in `BrandLoader`'s aria-label,
  // so routing an outage there showed a sighted visitor a bare spinner that
  // retried forever and looked exactly like "still loading".
  if (isError) return <AuthUnreachableScreen />;

  const state = data;
  // Auth off is a supported way to run this app locally, not a broken install:
  // the server substitutes a single local tenant (`LOCAL_TENANT_ID`) so every
  // tenant-scoped route still serves, and there is nobody to sign in as. Fall
  // through to the app rather than stopping at a screen that asks the operator
  // to configure the thing they deliberately switched off.
  //
  // Nothing is granted here that the server does not already grant: it decides
  // what an unauthenticated request may do. If the server were in fact gated
  // and this branch were reached by mistake, its routes would answer 401 and
  // the app would render its own errors.
  if (!state?.authEnabled) return <OnboardingGuard />;

  if (!state.authenticated) {
    // Router location (not window.location) so memory routers and in-app
    // navigations produce the correct returnTo.
    const returnTo = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to={`/signin?returnTo=${encodeURIComponent(returnTo)}`} replace />;
  }

  return <OnboardingGuard />;
};

const OnboardingGuard = () => {
  const pathname = useLocation().pathname;
  const { data: factories, isPending: factoriesPending } = useFactoriesQuery();

  if (factoriesPending) return <AuthPendingSkeleton label="Loading factories" />;
  if ((factories?.length ?? 0) === 0 && pathname !== '/onboarding') return <Navigate to="/onboarding" replace />;
  if (factories && factories.length > 0 && pathname === '/onboarding' && !hasResumableFactoryOnboarding(factories)) {
    return <Navigate to={`/factories/${factories[0].id}`} replace />;
  }

  return <Outlet />;
};

/**
 * The sign-in check itself failed — the server did not answer, or answered in a
 * way this app could not read.
 *
 * The only stopping state left. A deployment that turned auth off renders the
 * app instead, so reaching a screen at all now means the check genuinely could
 * not complete. The query keeps polling behind it, so
 * it clears on its own once the server recovers — which is why the copy says so
 * rather than offering a reload button that would do the same thing manually.
 */
function AuthUnreachableScreen() {
  return (
    <div className="bg-surface1 grid h-dvh w-full place-items-center px-6 text-center">
      <div className="max-w-md space-y-3">
        <h1 className="text-icon6 text-xl font-semibold">Can&apos;t check whether you&apos;re signed in</h1>
        <p className="text-icon3 text-sm leading-6">
          The server didn&apos;t answer the sign-in check. That usually means the server or its identity provider is
          unreachable, not that anything is wrong on your side. This page keeps retrying — if it doesn&apos;t clear, ask
          whoever runs this deployment to check the server logs.
        </p>
      </div>
    </div>
  );
}

export function AuthPendingSkeleton({ label = 'Checking sign-in' }: { label?: string }) {
  return (
    <div className="bg-surface1 flex h-dvh w-full items-center justify-center">
      <BrandLoader size="lg" aria-label={label} />
    </div>
  );
}
