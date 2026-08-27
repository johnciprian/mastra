import { Button } from '@mastra/playground-ui/components/Button';
import { CopyButton } from '@mastra/playground-ui/components/CopyButton';
import { Notice } from '@mastra/playground-ui/components/Notice';
import { Skeleton } from '@mastra/playground-ui/components/Skeleton';
import { Txt } from '@mastra/playground-ui/components/Txt';
import { LogOut } from 'lucide-react';

import { useApiConfig } from '../../../../api/config';
import { useFactoryAuth } from '../../../../hooks/useFactoryAuth';
import { clearMastraCodeStorage, submitLogout } from '../../auth/services/auth';
import { SettingsRow } from '@mastra/playground-ui/components/SettingsRow';
import { SettingsCard } from './SettingsCard';
import { SettingsSubsection } from './SettingsSubsection';

/**
 * Humanize the auth provider's name for the "Authentication" row.
 *
 * WHY THIS ROW KEEPS READING THE NAME WHEN THE SIGN-IN PAGE STOPPED
 *
 * The two screens ask different questions. The sign-in page asks "how do I get
 * in?", which is a capability question, and the descriptor answers it — that is
 * why branching on the name there was wrong. This row asks "which system holds
 * my identity?", which is an identity question, and the descriptor deliberately
 * cannot answer it: `providerHint` is documented as explicitly *not* a provider
 * name, and the kit refuses to derive `signIn.label` from `provider.name`
 * because a machine name is not display copy. There is no field to switch to.
 *
 * Rendering the capability here instead would also make the row worse at its
 * job. It sits beside "Account ID — useful when contacting support", and
 * "WorkOS" is what lets someone tell support which identity system they are on;
 * "Single sign-on" does not.
 *
 * So the name stays, and the hand-written override table that used to sit here
 * went instead. It mapped three names, and two of them earned nothing: the
 * humanizer already turns `mastra-studio` into exactly "Mastra Studio", and
 * `workos` differed only in capitalization. The third, `better-auth` →
 * "Email and password", substituted a sign-in *method* for a provider identity —
 * the precise conflation this lane exists to undo, and now genuinely answered
 * elsewhere by `signIn.kind`. Dropping the table costs the "WorkOS" casing,
 * which renders as "Workos", and buys a settings screen with no auth provider
 * name literals in it at all.
 */
function authProviderLabel(provider: string | undefined): string {
  if (!provider) return 'Unknown';
  return provider
    .split('-')
    .map(part => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function AccountValue({ children, mono = false }: { children: string; mono?: boolean }) {
  return (
    <Txt as="span" variant="ui-sm" font={mono ? 'mono' : undefined} className="text-icon4 truncate">
      {children}
    </Txt>
  );
}

function CopyableAccountValue({ value, label }: { value: string; label: string }) {
  return (
    <div className="flex min-w-0 items-center gap-1">
      <AccountValue mono>{value}</AccountValue>
      <CopyButton content={value} size="icon-xs" variant="ghost" tooltip={`Copy ${label}`} />
    </div>
  );
}

function AccountSettingsSkeleton() {
  return (
    <SettingsCard>
      <SettingsRow variant="factory" label="Name">
        <Skeleton className="h-4 w-28" />
      </SettingsRow>
      <SettingsRow variant="factory" label="Email">
        <Skeleton className="h-4 w-40" />
      </SettingsRow>
      <SettingsRow variant="factory" label="Authentication">
        <Skeleton className="h-4 w-24" />
      </SettingsRow>
    </SettingsCard>
  );
}

export function AccountSettingsSection() {
  const auth = useFactoryAuth();
  const { baseUrl } = useApiConfig();

  if (auth.isPending) {
    return (
      <SettingsSubsection title="Profile">
        <AccountSettingsSkeleton />
      </SettingsSubsection>
    );
  }

  if (auth.isError) {
    return <Notice variant="destructive">Could not load your account details. Reload the page to try again.</Notice>;
  }

  const state = auth.data;
  if (!state?.authEnabled) {
    return <Notice variant="info">Authentication is not enabled for this deployment.</Notice>;
  }

  if (!state.authenticated) {
    return <Notice variant="info">Sign in to view your account details.</Notice>;
  }

  const user = state.user;

  const logOut = () => {
    clearMastraCodeStorage();
    submitLogout(baseUrl);
  };

  // Hide the control only on an explicit `false`, which is the one answer that
  // is provably safe to act on. The host mounts `/auth/logout` for a hosted-login
  // provider or one serving its own auth routes, and `features.logout` is false
  // exactly when the provider is neither of those and has no session either — a
  // pure bearer-token validator, where the button would post to a route that
  // was never mounted. Absent descriptor (an older server) keeps today's
  // behaviour and shows it.
  const offersLogout = state.auth?.features.logout !== false;

  return (
    <div className="flex flex-col gap-8">
      <SettingsSubsection title="Profile" description="Your signed-in identity for this MastraCode deployment.">
        <SettingsCard>
          <SettingsRow variant="factory" label="Name">
            <AccountValue>{user?.name ?? 'Not provided'}</AccountValue>
          </SettingsRow>
          <SettingsRow variant="factory" label="Email">
            <AccountValue>{user?.email ?? 'Not provided'}</AccountValue>
          </SettingsRow>
          <SettingsRow variant="factory" label="Authentication">
            <AccountValue>{authProviderLabel(state.provider)}</AccountValue>
          </SettingsRow>
          {user?.userId && (
            <SettingsRow variant="factory" label="Account ID" description="Useful when contacting support.">
              <CopyableAccountValue value={user.userId} label="account ID" />
            </SettingsRow>
          )}
          {user?.organizationId && (
            <SettingsRow
              variant="factory"
              label="Organization ID"
              description="The organization that owns this Factory."
            >
              <CopyableAccountValue value={user.organizationId} label="organization ID" />
            </SettingsRow>
          )}
        </SettingsCard>
      </SettingsSubsection>
      {offersLogout && (
        <SettingsSubsection title="Session">
          <SettingsCard>
            <SettingsRow variant="factory" label="Log out" description="End your MastraCode session on this device.">
              <Button type="button" variant="outline" size="sm" aria-label="Log out of MastraCode" onClick={logOut}>
                <LogOut aria-hidden="true" />
                Log out
              </Button>
            </SettingsRow>
          </SettingsCard>
        </SettingsSubsection>
      )}
    </div>
  );
}
