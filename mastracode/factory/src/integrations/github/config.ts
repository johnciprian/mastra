/**
 * Composite feature gate + diagnostics for the GitHub App project feature.
 *
 * The GitHub feature is enabled only when *all three* hold:
 *  - a `GithubIntegration` instance is registered with the factory
 *    (constructed by the deploy entry from the `GITHUB_APP_*` env vars),
 *  - web auth is enabled (a per-user installation requires a logged-in user),
 *  - the application database is configured.
 *
 * OAuth/install `state` signing lives in `../../state-signing.ts` — the factory
 * creates one shared signer at boot and hands it to every integration.
 *
 * Everything here is pure: callers pass the handles they already own (the
 * integration, auth seam, state signer, sandbox fleet) — there is no global
 * registry lookup.
 */

import type { RouteAuth } from '../../routes/route.js';
import type { SandboxFleet } from '../../sandbox/fleet.js';
import type { StateSigner } from '../../state-signing.js';
import type { GithubIntegration } from './integration.js';

/**
 * Env vars the deploy entry reads to construct a `GithubIntegration`. Names
 * only — used by diagnostics to tell an operator what to set when the
 * integration is absent. The entry enforces all-or-nothing: partial config
 * fails the boot, so at runtime the integration is either fully configured or
 * not configured at all.
 */
const GITHUB_APP_ENV_VARS = [
  'GITHUB_APP_ID',
  'GITHUB_APP_PRIVATE_KEY',
  'GITHUB_APP_CLIENT_ID',
  'GITHUB_APP_CLIENT_SECRET',
  'GITHUB_APP_SLUG',
] as const;

/** Handles the GitHub feature gate + diagnostics are computed from. */
export interface GithubFeatureGateOptions {
  /** The registered GitHub integration, when configured. */
  github: GithubIntegration | undefined;
  /** Web auth seam — the feature requires a logged-in user. */
  auth: RouteAuth;
  /** True when the application database is configured. */
  appDbConfigured: boolean;
  /** Shared OAuth/install `state` signer, when configured. */
  stateSigner?: StateSigner;
  /** Sandbox fleet, when sandboxes are configured. */
  fleet?: SandboxFleet;
}

/**
 * True when the GitHub App project feature should be active.
 *
 * Configuration only. This used to also require `auth.enabled()`, which was
 * right while an auth-off deployment had no identity at all: installations are
 * stored per organization, and there was no organization to key them under, so
 * a connect flow had nowhere to put its result. `createFactoryRouteAuth` now
 * substitutes the local single-user tenant when no provider is configured, so
 * an auth-off Factory has a stable `local` org that owns its installations
 * across restarts, and every `if (!tenant)` on the GitHub routes is satisfied.
 *
 * Factory auth and GitHub identity answer different questions, which is why
 * dropping one does not weaken the other: this decides who is using the
 * Factory, while the connect flow still completes GitHub's own OAuth and
 * refuses to trust a raw `installation_id` without a verified user token
 * (see the identify bounce in `routes.ts`).
 *
 * The exposure this adds is the one auth-off already has: on a server with no
 * auth every route is open, so anyone who can reach it can use the connected
 * installation. That is why auth-off is documented for single-user local
 * development and warned about at boot.
 */
export function isGithubFeatureEnabled(options: Pick<GithubFeatureGateOptions, 'github' | 'auth'>): boolean {
  return options.github !== undefined;
}

/**
 * Non-secret diagnostic snapshot of every GitHub feature gate. Used by startup
 * logs, `/web/github/status`, and the SPA so all three explain the same state.
 *
 * Only env var *names* and booleans are exposed — never secret values.
 */
export interface GithubFeatureDiagnostics {
  githubAppConfigured: boolean;
  factoryAuthEnabled: boolean;
  appDbConfigured: boolean;
  stateSecretConfigured: boolean;
  sandboxEnabled: boolean;
  sandboxProvider: string;
  /** Names of the GitHub App env vars still needed (empty when configured). */
  missingGithubAppEnvVars: string[];
}

/**
 * Collect a non-secret diagnostic snapshot of every GitHub feature gate. Centralizes
 * the feature-gate reasoning so startup logs, the status API, and the SPA explain
 * the same state. Does not change `isGithubFeatureEnabled()` behavior.
 */
export function getGithubFeatureDiagnostics(options: GithubFeatureGateOptions): GithubFeatureDiagnostics {
  const { github, auth, appDbConfigured, stateSigner, fleet } = options;
  return {
    githubAppConfigured: github !== undefined,
    factoryAuthEnabled: auth.enabled(),
    appDbConfigured,
    stateSecretConfigured: stateSigner?.stable ?? false,
    sandboxEnabled: fleet?.enabled ?? false,
    sandboxProvider: fleet?.provider ?? 'none',
    missingGithubAppEnvVars: github ? [] : [...GITHUB_APP_ENV_VARS],
  };
}
