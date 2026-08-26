/**
 * Client-side glue for the optional web auth gate (see src/web/auth.ts).
 *
 * The server protects the whole surface; this module makes the SPA cooperate:
 * - `fetchAuthState()` reads `/auth/me` to decide whether to show the splash
 *   (unauthenticated) or the app, and to render identity / sign-out. Degrades
 *   gracefully to "auth disabled" when the route is absent.
 * - `loginUrl()` / `redirectToLogin()` build/navigate to the hosted
 *   login URL (used by the /signin page).
 * - `redirectToLogout()` / `logoutUrl()` send the user through the server logout route.
 *
 * Every helper takes the API base URL injected by `ApiConfigProvider` (empty
 * string when the app is served same-origin) so the frontend dev server on a
 * different port still reaches the Mastra server — same pattern as the shared
 * API client and `use-fs`.
 */

/**
 * How a browser can start a session with this deployment's provider.
 *
 * `none` is the value most likely to be misread: it is a working, enforcing
 * provider that validates API tokens but implements neither a hosted login nor
 * a credentials sign-in, so it cannot take anyone from a blank browser to a
 * session. **It does not mean auth is off.** A deployment with auth switched
 * off has no provider and therefore no descriptor at all — that state is
 * `authEnabled: false`, and the two must not render the same way.
 */
export type AuthSignInKind = 'hosted' | 'credentials' | 'both' | 'none';

/** Every {@link AuthSignInKind}, for exhaustiveness checks and the wire guard. */
const AUTH_SIGN_IN_KINDS: readonly AuthSignInKind[] = ['hosted', 'credentials', 'both', 'none'];

/**
 * A rendering token for the sign-in control. **Not a provider name**, and the
 * closedness is the feature: a vendor-carrying string would put vendor names
 * back into this SPA as branch conditions, which is the coupling the descriptor
 * exists to remove. Each token names a *visual treatment*, so adding a vendor
 * server-side never touches the UI's icon/label map.
 */
export type AuthProviderHint = 'generic' | 'sso' | 'oauth' | 'email';

/** Every {@link AuthProviderHint}, for the wire guard. */
const AUTH_PROVIDER_HINTS: readonly AuthProviderHint[] = ['generic', 'sso', 'oauth', 'email'];

/** Neutral treatment; the right answer whenever there is any doubt. */
export const DEFAULT_PROVIDER_HINT: AuthProviderHint = 'generic';

/** Where the host mounts its auth routes, and so where a credentials form posts. */
export const DEFAULT_CREDENTIALS_BASE_PATH = '/auth';

/** How a browser can start a session. */
export interface AuthSignInDescriptor {
  kind: AuthSignInKind;
  /** Host-supplied display copy. Absent by default — never derived from a provider name. */
  label?: string;
  /** Visual treatment. Optional so a payload from an older server still parses. */
  providerHint?: AuthProviderHint;
  /** **Positive polarity.** Present only when `kind` includes credentials. See {@link isSignUpEnabled}. */
  signUpEnabled?: boolean;
  /** Base path a credentials form posts to. Present only when `kind` includes credentials. */
  credentialsBasePath?: string;
}

/** What the account UI can offer once somebody is signed in. */
export interface AuthFeatureDescriptor {
  logout: boolean;
  organizations: boolean;
  refresh: boolean;
  sessionRevocation: boolean;
}

/**
 * What the deployment's provider can do, as a record this SPA can render.
 *
 * Structural mirror of `AuthDescriptor` from `@mastra/factory-auth/capabilities`,
 * which is the source of truth and produces every payload this parses. It is
 * restated here rather than imported because this package does not depend on
 * the auth kit (a server-side package); the kit's conformance suite and the
 * server-side descriptor tests pin the producing end of the same shape.
 */
export interface AuthDescriptor {
  signIn: AuthSignInDescriptor;
  features: AuthFeatureDescriptor;
}

export interface FactoryAuthState {
  /** Whether the server has web auth configured (any provider). */
  authEnabled: boolean;
  authenticated: boolean;
  user?: { userId?: string; email?: string; name?: string; organizationId?: string };
  /**
   * Active identity provider name. Retained only for the labelled legacy
   * fallback in `SignInPage`, for servers that predate the descriptor. Nothing
   * else may branch on it — see {@link AuthProviderHint}.
   */
  provider?: string;
  /**
   * The capability descriptor. Absent when the server predates it, which is the
   * only case where the provider name is still consulted.
   */
  auth?: AuthDescriptor;
  /**
   * @deprecated Legacy **negative** wire field, superseded by
   * `auth.signIn.signUpEnabled` and removed once every server emits the
   * descriptor. Never read it directly — call {@link isSignUpEnabled}, which
   * owns the precedence between the two polarities.
   */
  signUpDisabled?: boolean;
}

/**
 * Whether the sign-up affordance should be offered.
 *
 * THE PRECEDENCE, AND THE MISSING `!` THIS FUNCTION EXISTS TO CONTAIN
 *
 * For one release a single `/auth/me` response carries two fields of *opposite
 * polarity* describing this one fact:
 *
 * - `auth.signIn.signUpEnabled` — new, POSITIVE, authoritative.
 * - `signUpDisabled` — legacy, NEGATIVE, dropped once the descriptor is
 *   everywhere.
 *
 * Getting the negation wrong shows a sign-up link on a deployment that
 * deliberately disabled sign-up, and nothing about that failure looks like a bug
 * from the outside — no error, no blank screen, just an affordance that should
 * not be there. So the two polarities are reconciled in exactly this one place
 * and every call site reads the positive answer.
 *
 * 1. **Descriptor wins whenever it states the fact.** Tested with `typeof ===
 *    'boolean'`, not for truthiness: `false` is a deliberate "sign-up is off"
 *    and must not be confused with an absent field, which is "not stated" (the
 *    descriptor omits it entirely for kinds that have no credentials sign-in).
 *    A server that contradicts itself — descriptor says enabled, legacy field
 *    says disabled — resolves to the descriptor by design.
 * 2. **Otherwise the legacy field, negated.** Only reached on a server that
 *    predates the descriptor.
 * 3. **Otherwise enabled**, which is both the contract's documented default and
 *    the behaviour that shipped before the descriptor existed.
 */
export function isSignUpEnabled(state: FactoryAuthState | undefined): boolean {
  const declared = state?.auth?.signIn.signUpEnabled;
  if (typeof declared === 'boolean') return declared;
  return state?.signUpDisabled !== true;
}

/** The resourceId under which a user's personal (non-factory) sessions live. */
export function userSessionResourceId(state: FactoryAuthState | undefined): string {
  const userId = state?.user?.userId;
  if (!userId) throw new Error('Authenticated user is missing a user id');
  return userId;
}

/**
 * Build the hosted-login URL. `returnTo` is where the server sends the user
 * after authenticating; it defaults to the current location so contexts that
 * are not `/signin` (which would loop back to itself) round-trip in place.
 */
export function loginUrl(
  baseUrl: string,
  returnTo: string = window.location.pathname + window.location.search,
): string {
  return `${baseUrl}/auth/login?returnTo=${encodeURIComponent(returnTo)}`;
}

/** Full-page navigation to the hosted login (see `loginUrl` for `returnTo`). */
export function redirectToLogin(baseUrl: string, returnTo?: string): void {
  window.location.assign(loginUrl(baseUrl, returnTo));
}

export function logoutUrl(baseUrl: string): string {
  return `${baseUrl}/auth/logout`;
}

export function clearMastraCodeStorage(): void {
  for (let index = localStorage.length - 1; index >= 0; index -= 1) {
    const key = localStorage.key(index);
    if (key?.startsWith('mastracode')) localStorage.removeItem(key);
  }
}

export function redirectToLogout(baseUrl: string): void {
  window.location.assign(logoutUrl(baseUrl));
}

/**
 * POST credentials to a better-auth endpoint (`basePath: /auth/api`). The
 * session cookie is set by the response; the caller navigates afterwards.
 * Throws with the server's message so the sign-in form can display it.
 */
async function postBetterAuthCredentials(baseUrl: string, path: string, body: Record<string, string>): Promise<void> {
  const res = await fetch(`${baseUrl}/auth/api/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    credentials: 'include',
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let message = 'Authentication failed';
    try {
      const data = (await res.json()) as { message?: string };
      if (data?.message) message = data.message;
    } catch {
      // Non-JSON error body — keep the generic message.
    }
    throw new Error(message);
  }
}

/**
 * Full-page navigation after a successful credential sign-in, so the app boots
 * with the fresh session cookie. Service-level (like `redirectToLogin`) because
 * jsdom's `window.location.assign` is unforgeable in tests.
 */
export function navigateAfterSignIn(returnTo: string): void {
  window.location.assign(returnTo);
}

/** Email/password sign-in against the self-hosted better-auth provider. */
export function signInWithPassword(baseUrl: string, input: { email: string; password: string }): Promise<void> {
  return postBetterAuthCredentials(baseUrl, 'sign-in/email', input);
}

/** Email/password sign-up against the self-hosted better-auth provider. */
export function signUpWithPassword(
  baseUrl: string,
  input: { name: string; email: string; password: string },
): Promise<void> {
  return postBetterAuthCredentials(baseUrl, 'sign-up/email', input);
}

/**
 * Fetch the current auth state from `/auth/me`. When the route is missing (auth
 * disabled), reports `authEnabled: false` so the UI hides all auth affordances.
 */
export async function fetchAuthState(baseUrl: string): Promise<FactoryAuthState> {
  const res = await fetch(`${baseUrl}/auth/me`, { headers: { Accept: 'application/json' }, credentials: 'include' });
  if (res.status === 404) {
    return { authEnabled: false, authenticated: false };
  }
  if (res.status === 401 || res.status === 403) {
    return { authEnabled: true, authenticated: false };
  }
  if (!res.ok) {
    throw new Error(`Auth check failed (${res.status})`);
  }
  const data = (await res.json()) as {
    authenticated?: boolean;
    user?: { userId?: string; email?: string; name?: string; organizationId?: string } | null;
    provider?: string;
    auth?: unknown;
    signUpDisabled?: boolean;
  };
  return {
    authEnabled: true,
    authenticated: Boolean(data.authenticated),
    user: data.user ?? undefined,
    provider: data.provider,
    auth: parseAuthDescriptor(data.auth),
    signUpDisabled: data.signUpDisabled,
  };
}

/**
 * Narrow the wire `auth` field to an {@link AuthDescriptor}, or `undefined` when
 * the server did not send one this SPA can act on.
 *
 * `undefined` is a meaningful answer rather than a failure: it routes
 * `SignInPage` to its labelled legacy fallback, which is exactly right for a
 * server that predates the descriptor.
 *
 * `signIn.kind` is checked against the closed union rather than cast, because
 * an unrecognized kind is what a *newer* server sending a fifth kind looks like
 * to this build. Casting it would drop that payload into whichever branch
 * happens to be last; rejecting it degrades to the legacy provider-name
 * behaviour, which still renders something a user can act on.
 */
function parseAuthDescriptor(value: unknown): AuthDescriptor | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const { signIn, features } = value as { signIn?: unknown; features?: unknown };
  if (typeof signIn !== 'object' || signIn === null) return undefined;

  const raw = signIn as Partial<AuthSignInDescriptor>;
  if (!isAuthSignInKind(raw.kind)) return undefined;

  const parsed: AuthSignInDescriptor = { kind: raw.kind };
  if (typeof raw.label === 'string') parsed.label = raw.label;
  // An unrecognized hint falls back to the neutral treatment instead of
  // rejecting the descriptor: the hint only picks an icon, so a kind this build
  // understands is still worth rendering.
  parsed.providerHint = isAuthProviderHint(raw.providerHint) ? raw.providerHint : DEFAULT_PROVIDER_HINT;
  if (typeof raw.signUpEnabled === 'boolean') parsed.signUpEnabled = raw.signUpEnabled;
  if (typeof raw.credentialsBasePath === 'string') parsed.credentialsBasePath = raw.credentialsBasePath;

  return { signIn: parsed, features: parseAuthFeatures(features) };
}

/** Features are advisory booleans; anything non-boolean reads as "not offered". */
function parseAuthFeatures(value: unknown): AuthFeatureDescriptor {
  const raw = (typeof value === 'object' && value !== null ? value : {}) as Partial<AuthFeatureDescriptor>;
  return {
    logout: raw.logout === true,
    organizations: raw.organizations === true,
    refresh: raw.refresh === true,
    sessionRevocation: raw.sessionRevocation === true,
  };
}

function isAuthSignInKind(value: unknown): value is AuthSignInKind {
  return AUTH_SIGN_IN_KINDS.includes(value as AuthSignInKind);
}

function isAuthProviderHint(value: unknown): value is AuthProviderHint {
  return AUTH_PROVIDER_HINTS.includes(value as AuthProviderHint);
}
