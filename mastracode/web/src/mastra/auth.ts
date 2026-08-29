/**
 * Which auth provider this deployment runs, resolved from environment.
 *
 * `MastraFactory`'s `auth` slot is required and closed — a provider instance,
 * or `AUTH_DISABLED` — so the entry has to name one. This module is where that
 * name is decided, and it is deliberately the only place: the entry reads one
 * function, and every "which provider?" question has one answer with one
 * reason.
 *
 * ## Two ways in
 *
 * `MASTRACODE_AUTH_PROVIDER` names the provider outright. When it is set it is
 * the ENTIRE decision — the inference ladder below is not consulted for
 * identity, and any variable that would have produced a different answer gets
 * a warning rather than silently losing. An unrecognized value is a boot
 * error, never a fallback: a typo (`worksos`) quietly landing on the platform
 * default is exactly the failure the required `auth` slot was introduced to
 * remove, and re-introducing it here would undo that.
 *
 * When it is UNSET the legacy ladder runs, with behavior identical to what it
 * had before this module existed — ordered by how explicit the operator's
 * intent is:
 *
 *   1. `MASTRACODE_AUTH_DISABLED=1` — explicit opt-out, auth off entirely.
 *   2. `MASTRA_SHARED_API_URL` — explicit platform deferral; identity rides the
 *      shared platform API (`.env.schema` names this the highest-precedence
 *      auth config), so it wins even over a configured `WORKOS_*` pair — but
 *      loudly, because silently ignoring sign-in config is how self-hosted
 *      logins end up 302-ing somewhere that rejects their redirect_uri.
 *   3. `WORKOS_API_KEY` + `WORKOS_CLIENT_ID` — self-managed WorkOS sign-in. The
 *      constructor reads the rest of the `WORKOS_*` group from env, and
 *      `init()` derives the /auth/callback redirect from the deployment's
 *      publicUrl when `WORKOS_REDIRECT_URI` is unset. `fetchMemberships` lets
 *      token auth resolve the user's organization so the bootstrapped
 *      personal org works without re-auth. Note `MASTRA_PLATFORM_ACCESS_TOKEN` /
 *      `MASTRA_PLATFORM_SECRET_KEY` do NOT defer to the platform here: they are
 *      compute/integration credentials (sandboxes, GitHub/Linear slots), not
 *      identity signals — platform compute plus self-managed sign-in is a
 *      supported combination.
 *   4. Nothing configured — platform-proxied identity, which is what the
 *      factory used to install when the entry left `auth` unset.
 *
 * The one change to that ladder is that every branch now NAMES its provider,
 * instead of the last one reaching a default by leaving a variable unassigned.
 * Net effect for existing deployments: unchanged.
 *
 * ## Why the imports are static
 *
 * `mastra build` bundles this entry, so `await import(envValue)` would not be
 * statically analyzable, would be dropped from the deploy manifest, and would
 * surface as ERR_MODULE_NOT_FOUND on the deployed server rather than here.
 * Every selectable provider is imported by name, and the unused ones are dead
 * weight in the bundle — which is the price of a selector that cannot fail at
 * runtime on a machine you are not looking at.
 */

import { MastraAuthBetterAuth } from '@mastra/auth-better-auth';
import { MastraAuthFirebase } from '@mastra/auth-firebase';
import { MastraAuthOkta } from '@mastra/auth-okta';
import { MastraAuthSupabase } from '@mastra/auth-supabase';
import { MastraAuthWorkos } from '@mastra/auth-workos';
import { isCredentialsProvider, isSSOProvider } from '@mastra/core/server';
import type { IMastraAuthProvider } from '@mastra/core/server';
import { AUTH_DISABLED, createMastraPlatformAuth, resolveFactoryPublicUrl } from '@mastra/factory';
import type { FactoryAuthConfig } from '@mastra/factory';

/** Every value `MASTRACODE_AUTH_PROVIDER` accepts. */
export const AUTH_PROVIDER_IDS = ['studio', 'workos', 'okta', 'better-auth', 'supabase', 'firebase', 'none'] as const;

export type AuthProviderId = (typeof AUTH_PROVIDER_IDS)[number];

/**
 * Providers that exist in the monorepo but are refused by name, so selecting
 * one fails with the reason instead of with a confusing "unknown value".
 *
 * Each records conformance failures against the Factory auth contract, which
 * means the sign-in, session, or identity surface the Factory UI drives is not
 * reliably there. They are refused rather than omitted because "unknown value"
 * would read as a typo and send the operator looking for a spelling mistake.
 */
const REFUSED_PROVIDER_IDS: Readonly<Record<string, string>> = {
  auth0: 'it records conformance failures against the Factory auth contract',
  clerk: 'it records conformance failures against the Factory auth contract',
  cloud: 'it records conformance failures against the Factory auth contract',
  google: 'it records conformance failures against the Factory auth contract',
  neon: 'it fails obligation/flatId and obligation/cookieAuth on top of its other conformance failures, which makes it unusable under Factory',
};

/**
 * Longest value echoed back into a boot log. Boot logs go to shared streams,
 * and an operator who pastes a secret into the wrong variable must not have it
 * land there at full length. Matches the clamp the factory's auth routes use on
 * IdP-supplied error text.
 */
const MAX_ECHOED_VALUE_LENGTH = 64;

export interface AuthSelectionContext {
  /** The deployment's browser-facing origin — Okta's callback is derived from it. */
  publicUrl: string | undefined;
  /** Environment to read. Injected rather than reached for, so this is unit-testable. */
  env: NodeJS.ProcessEnv;
  /** Where boot warnings go. Defaults to `console.warn`. */
  warn?: (message: string) => void;
}

/**
 * Resolve the `auth` value for `MastraFactory`. Throws — never falls back —
 * when the operator asked for something this deployment cannot give them.
 */
export function resolveFactoryAuth(context: AuthSelectionContext): FactoryAuthConfig {
  const { env } = context;
  const warn = context.warn ?? ((message: string) => console.warn(message));

  const selector = env.MASTRACODE_AUTH_PROVIDER?.trim();
  const id = selector ? parseSelector(selector) : inferProviderId(env, warn);
  if (selector) warnAboutOverriddenSignals(id, env, warn);

  if (id === 'none') {
    warn(
      '[Auth] Authentication is DISABLED — every route on this server is open, and any request reaches it ' +
        'unauthenticated. The web UI is a dead end in this mode too: it renders the "auth not configured" screen ' +
        'instead of a sign-in page, because there is nothing to sign in to. Intended for local development only.',
    );
    return AUTH_DISABLED;
  }

  const provider = construct(id, context, warn);
  warnIfCannotSignInFromBrowser(id, provider, warn);
  return provider;
}

/** Map the raw selector onto an id, or explain why it is not one. */
function parseSelector(selector: string): AuthProviderId {
  if ((AUTH_PROVIDER_IDS as readonly string[]).includes(selector)) return selector as AuthProviderId;

  const echoed = selector.slice(0, MAX_ECHOED_VALUE_LENGTH);
  const refusal = REFUSED_PROVIDER_IDS[selector];
  if (refusal) {
    throw new Error(
      `MASTRACODE_AUTH_PROVIDER='${echoed}' names a provider this deployment refuses to select, because ${refusal}. ` +
        `Accepted values: ${AUTH_PROVIDER_IDS.join(', ')}. ` +
        `The selector is a convenience over MastraFactory's 'auth' slot, not a gate on it — if you have verified ` +
        `'${echoed}' against your own deployment, construct it in src/mastra/index.ts and pass the instance to that slot directly.`,
    );
  }

  throw new Error(
    `MASTRACODE_AUTH_PROVIDER='${echoed}' is not a provider this deployment can select, so the server will not start. ` +
      `Accepted values: ${AUTH_PROVIDER_IDS.join(', ')}. ` +
      `Unset it to fall back to inference (MASTRA_SHARED_API_URL selects studio, a WORKOS_API_KEY + WORKOS_CLIENT_ID ` +
      `pair selects workos, and neither selects studio).`,
  );
}

/** The legacy ladder, unchanged in behavior — see the module docstring. */
function inferProviderId(env: NodeJS.ProcessEnv, warn: (message: string) => void): AuthProviderId {
  if (env.MASTRACODE_AUTH_DISABLED === '1') {
    warn(
      '[Auth] MASTRACODE_AUTH_DISABLED is deprecated — set MASTRACODE_AUTH_PROVIDER=none instead. ' +
        'The old flag is honored as an alias for now, but new deploys should use the selector.',
    );
    return 'none';
  }
  if (env.MASTRA_SHARED_API_URL?.trim()) {
    if (isWorkosConfigured(env)) {
      warn(
        '[Auth] WORKOS_API_KEY/WORKOS_CLIENT_ID are set but ignored: MASTRA_SHARED_API_URL takes precedence, so ' +
          'sign-in defers to the platform. Unset MASTRA_SHARED_API_URL to use self-managed WorkOS auth, or set ' +
          'MASTRACODE_AUTH_PROVIDER=workos to say so outright.',
      );
    }
    return 'studio';
  }
  if (isWorkosConfigured(env)) return 'workos';
  return 'studio';
}

/**
 * Report every variable the selector overrode that would otherwise have chosen
 * a different provider. Silence here is how an operator ends up debugging a
 * sign-in that is configured correctly and simply not in use.
 *
 * `MASTRACODE_AUTH_DISABLED` losing to the selector is deliberate and the
 * direction matters: the selector winning leaves the server GATED and the
 * operator reads this warning, while the flag winning would leave a production
 * server OPEN. Fail toward the safe state.
 */
function warnAboutOverriddenSignals(id: AuthProviderId, env: NodeJS.ProcessEnv, warn: (message: string) => void): void {
  if (env.MASTRACODE_AUTH_DISABLED === '1' && id !== 'none') {
    warn(
      `[Auth] MASTRACODE_AUTH_DISABLED is set but ignored: MASTRACODE_AUTH_PROVIDER='${id}' takes precedence, so ` +
        'authentication stays ON. Set MASTRACODE_AUTH_PROVIDER=none if you meant to run an open server. ' +
        '(MASTRACODE_AUTH_DISABLED is deprecated; the selector replaces it.)',
    );
  }
  if (env.MASTRA_SHARED_API_URL?.trim() && id !== 'studio') {
    warn(
      `[Auth] MASTRA_SHARED_API_URL is set but no longer decides identity: MASTRACODE_AUTH_PROVIDER='${id}' takes ` +
        'precedence. Set MASTRACODE_AUTH_PROVIDER=studio to defer sign-in to the shared platform API. ' +
        '(The variable still feeds the Platform GitHub/Linear integrations, which are unaffected.)',
    );
  }
  if (isWorkosConfigured(env) && id !== 'workos') {
    warn(
      `[Auth] WORKOS_API_KEY/WORKOS_CLIENT_ID are set but ignored: MASTRACODE_AUTH_PROVIDER='${id}' takes precedence. ` +
        'Set MASTRACODE_AUTH_PROVIDER=workos to use self-managed WorkOS sign-in.',
    );
  }
}

function isWorkosConfigured(env: NodeJS.ProcessEnv): boolean {
  return Boolean(env.WORKOS_API_KEY?.trim() && env.WORKOS_CLIENT_ID?.trim());
}

/**
 * Build the named provider, or fail naming the selector that caused the attempt.
 *
 * Note the deliberate asymmetry with {@link inferProviderId}: the ladder fails
 * SOFT on a half-set `WORKOS_*` pair, because nobody asked for WorkOS and the
 * right answer is to fall through. Once a selector names a provider, the same
 * missing environment must fail HARD — the operator asked for exactly this and
 * booting into something else would be the silent substitution this whole
 * change removes.
 */
function construct(
  id: Exclude<AuthProviderId, 'none'>,
  context: AuthSelectionContext,
  warn: (message: string) => void,
): IMastraAuthProvider {
  const { env, publicUrl } = context;
  try {
    switch (id) {
      case 'studio':
        return createMastraPlatformAuth({ publicUrl });
      case 'workos':
        return new MastraAuthWorkos({ fetchMemberships: true });
      case 'okta':
        // Okta validates `redirectUri` in its CONSTRUCTOR and has no `init()`
        // hook, so unlike WorkOS it cannot derive the callback from the host
        // later. Derive it here from the same public origin `buildAuthRoutes`
        // uses to build the callback URL at request time, so the two agree.
        // Everything else Okta reads from the `OKTA_*` group itself.
        return new MastraAuthOkta({
          redirectUri:
            env.OKTA_REDIRECT_URI?.trim() || new URL('/auth/callback', resolveFactoryPublicUrl(publicUrl)).toString(),
        });
      case 'better-auth': {
        // Deferred instance mode: passing `secret` instead of an `auth`
        // instance makes the provider build its own `betterAuth()` in `init()`
        // on the host's auth database and own its schema migrations. The
        // provider's own error for a missing secret talks about passing an
        // `auth` option, which is not the shape this entry uses — so name the
        // variable the operator actually has to set.
        const secret = env.BETTER_AUTH_SECRET?.trim();
        if (!secret) {
          throw new Error(
            'BETTER_AUTH_SECRET is required and empty. It signs Better Auth sessions, so without it the provider ' +
              'has no instance to build. Generate one with `openssl rand -base64 32` and keep it stable across ' +
              'deploys — changing it invalidates every live session.',
          );
        }
        return new MastraAuthBetterAuth({ secret });
      }
      case 'supabase':
        return new MastraAuthSupabase();
      case 'firebase':
        // Firebase is the one provider whose constructor validates nothing:
        // with no service account it falls back to Application Default
        // Credentials, which resolve lazily, so a deployment with no credential
        // at all boots clean and then fails every request with a 401 and
        // nothing naming the cause. This warning is the only place that cause
        // gets stated. It is not validation — ADC can also come from the
        // metadata server on Google infrastructure, where both variables are
        // legitimately unset and everything works.
        if (!env.FIREBASE_SERVICE_ACCOUNT?.trim() && !env.GOOGLE_APPLICATION_CREDENTIALS?.trim()) {
          warn(
            '[Auth] firebase is selected but neither FIREBASE_SERVICE_ACCOUNT nor GOOGLE_APPLICATION_CREDENTIALS ' +
              'is set. The Admin SDK will fall back to Application Default Credentials, which is correct on Google ' +
              'infrastructure and nowhere else — off it, the server starts normally and then rejects every request ' +
              'as unauthenticated. Set one of the two if this deployment is not running on Google infrastructure.',
          );
        }
        return new MastraAuthFirebase();
    }
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new Error(`MASTRACODE_AUTH_PROVIDER selected '${id}', but constructing that provider failed: ${detail}`, {
      cause,
    });
  }
}

/**
 * Warn when the selected provider cannot start a sign-in from a browser.
 *
 * Keyed on the CAPABILITY, never on vendor identity, so a provider that grows
 * a hosted login stops warning on its own and a future token-only provider
 * starts warning without anyone remembering to add it here. `isSSOProvider` and
 * `isCredentialsProvider` are the same two guards `toAuthDescriptor` composes
 * into `signIn.kind`, so "neither" is exactly its `kind: 'none'` — and
 * `auth.test.ts` pins that equivalence against `toAuthDescriptor` itself. They
 * are taken from `@mastra/core/server` rather than `@mastra/factory-auth`
 * because this file is copied verbatim into the `create-factory` scaffold,
 * whose dependencies must all be published packages.
 */
function warnIfCannotSignInFromBrowser(
  id: AuthProviderId,
  provider: IMastraAuthProvider,
  warn: (message: string) => void,
): void {
  if (isSSOProvider(provider) || isCredentialsProvider(provider)) return;
  warn(
    `[Auth] '${id}' validates bearer tokens but cannot sign anyone in from a browser, so this server is fully ` +
      'gated and no browser user can enter it. Every visitor sees "Sign-in isn\'t available for this provider"; ' +
      'the app is reachable only by sending an `Authorization: Bearer <token>` your own client obtained elsewhere. ' +
      'Choose a provider with a hosted login (studio, workos, okta) if you need people to sign in here.',
  );
}
