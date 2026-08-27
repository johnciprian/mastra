/**
 * Client-side glue for the optional web auth gate (see src/web/auth.ts).
 *
 * The server protects the whole surface; this module makes the SPA cooperate:
 * - `fetchAuthState()` reads `/auth/me` to decide whether to show the splash
 *   (unauthenticated) or the app, and to render identity / sign-out. Degrades
 *   gracefully to "auth disabled" when the route is absent.
 * - `loginUrl()` / `redirectToLogin()` build/navigate to the hosted
 *   login URL (used by the /signin page).
 * - `submitLogout()` / `logoutUrl()` post the user through the server logout route.
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
  user?: { userId?: string; email?: string; name?: string; avatarUrl?: string; organizationId?: string };
  /**
   * Active identity provider name.
   *
   * It has one reader, and it is not the sign-in page: the "Authentication" row
   * in account settings, which answers "which system holds my identity?". The
   * descriptor deliberately cannot answer that — {@link AuthProviderHint} is
   * documented as explicitly *not* a provider name and the host refuses to
   * derive `signIn.label` from one — so there is no capability field to render
   * there instead.
   *
   * Displayed, never branched on. Which controls `/signin` offers comes from
   * {@link auth} alone, and a `provider === '<name>'` comparison anywhere in
   * this SPA fails the gate in `ui/__tests__/no-provider-literals.test.ts`.
   */
  provider?: string;
  /**
   * The capability descriptor: the only input to the sign-in decision.
   *
   * Absent when the server sent none, or sent one this build cannot act on —
   * see {@link parseAuthDescriptor}. `SignInPage` then falls back to a neutral
   * hosted-login button, which is the control that works for the widest range
   * of providers and names none of them.
   */
  auth?: AuthDescriptor;
}

/**
 * Whether the sign-up affordance should be offered.
 *
 * One input — the descriptor — and one place that reads it, so every call site
 * gets the positive answer without restating the test.
 *
 * The `typeof === 'boolean'` test is the load-bearing part and is not a
 * truthiness check by accident. `false` is a deliberate "sign-up is off"; an
 * absent field is "not stated", which is what the descriptor sends for every
 * kind that has no credentials sign-in at all. Collapsing the two would read
 * "not stated" as "off" and hide a sign-up form that should be there.
 *
 * Not stated resolves to **enabled**, which is the contract's documented
 * default. The failure that matters points the other way — a sign-up link
 * rendered on a deployment that deliberately disabled sign-up looks like a
 * working page from every angle, no error and no blank screen — and it is
 * `signUpEnabled: false` that prevents it. A response used to carry a second
 * field of the opposite polarity (`signUpDisabled`) that had to be reconciled
 * with this one; it is gone, and with it the chance of a dropped `!`.
 */
export function isSignUpEnabled(state: FactoryAuthState | undefined): boolean {
  const declared = state?.auth?.signIn.signUpEnabled;
  return typeof declared === 'boolean' ? declared : true;
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

/** Where sign-out posts. POST only — no route ends a session on a GET. */
export function logoutUrl(baseUrl: string): string {
  return `${baseUrl}/auth/logout`;
}

export function clearMastraCodeStorage(): void {
  for (let index = localStorage.length - 1; index >= 0; index -= 1) {
    const key = localStorage.key(index);
    if (key?.startsWith('mastracode')) localStorage.removeItem(key);
  }
}

/**
 * Sign out by submitting a form, which is the only way a page can POST and
 * still hand the browser on to wherever the server redirects.
 *
 * `location.assign` would be simpler and is what this used to do, but it can
 * only issue a GET, and no route ends a session on a GET any more: a URL that
 * signs you out by being fetched is one any other site can put in an `<img>`.
 * The form is same-origin-or-declared-origin by construction, so it carries the
 * `Origin` header the server checks.
 *
 * The form is removed again on the way out. `submit()` starts a navigation
 * rather than completing one, so a caller that is torn down before the browser
 * leaves — a test, or a route change that beats the network — does not strand a
 * node in the document.
 */
export function submitLogout(baseUrl: string): void {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = logoutUrl(baseUrl);
  form.hidden = true;
  document.body.appendChild(form);
  try {
    form.submit();
  } finally {
    form.remove();
  }
}

/**
 * Where a credentials form posts, taken from the descriptor.
 *
 * The host mounts a credentials provider's own HTTP surface at
 * `<basePath>/api/*` and reports `<basePath>` as `credentialsBasePath`, so
 * reading it here is what lets any provider that serves its own auth routes
 * work without the SPA knowing which one it is. The kit's default is `/auth`,
 * which is also the fallback for a server that sends no descriptor.
 *
 * THE VALUE IS CHECKED BEFORE IT IS USED, AND NOT AS A FORMALITY
 *
 * This path receives the user's password. The SPA is normally served
 * same-origin, where `baseUrl` is the empty string — so a descriptor carrying
 * `//evil.example` would produce the *protocol-relative* URL
 * `//evil.example/api/sign-in/email` and POST the password to another origin.
 * The sign-in page already guards its `returnTo` for this reason; getting it
 * wrong here leaks a credential rather than a destination.
 */
export function credentialsBasePath(state: FactoryAuthState | undefined): string {
  const declared = state?.auth?.signIn.credentialsBasePath;
  if (!declared || !SAFE_CREDENTIALS_BASE_PATH.test(declared)) return DEFAULT_CREDENTIALS_BASE_PATH;
  // Trailing slashes would double up against the `/api/` segment below.
  return declared.replace(/\/+$/, '');
}

/**
 * What a credentials mount path may look like: one or more `/segment` pieces of
 * ordinary path characters.
 *
 * This is an allowlist rather than a screen for known-bad prefixes, because the
 * bad list is open-ended and each entry is individually easy to miss. `//` is
 * protocol-relative; a backslash normalizes to a forward slash in http(s) URLs,
 * so `/\evil.example` *becomes* `//evil.example`; and the URL parser strips tab,
 * newline and carriage return outright, so `/<tab>/evil.example` becomes it too.
 * A mount path, meanwhile, is a small boring thing — `/auth`, `/identity`,
 * `/api/auth` — so describing what it may contain is both shorter and safe by
 * construction.
 */
const SAFE_CREDENTIALS_BASE_PATH = /^(?:\/[A-Za-z0-9._~-]+)+\/*$/;

/** Where a credentials form posts: the injected API origin plus the descriptor's auth mount. */
export interface CredentialsEndpoint {
  /** API base URL from `ApiConfigProvider` — empty string when served same-origin. */
  baseUrl: string;
  /** The descriptor's auth mount. See {@link credentialsBasePath}. */
  basePath: string;
}

/**
 * POST credentials to the provider's own HTTP surface, below the auth mount the
 * descriptor reported. The session cookie is set by the response; the caller
 * navigates afterwards. Throws with the server's message so the sign-in form can
 * display it.
 *
 * The `sign-in/email` and `sign-up/email` sub-paths remain fixed: they are the
 * endpoint shape the host's credentials providers serve, and the descriptor
 * describes where that surface is mounted, not what it is called.
 */
async function postCredentials(
  { baseUrl, basePath }: CredentialsEndpoint,
  path: string,
  body: Record<string, string>,
): Promise<void> {
  const res = await fetch(`${baseUrl}${basePath}/api/${path}`, {
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

/** Email/password sign-in against whichever provider serves this deployment's credentials. */
export function signInWithPassword(
  endpoint: CredentialsEndpoint,
  input: { email: string; password: string },
): Promise<void> {
  return postCredentials(endpoint, 'sign-in/email', input);
}

/** Email/password sign-up against whichever provider serves this deployment's credentials. */
export function signUpWithPassword(
  endpoint: CredentialsEndpoint,
  input: { name: string; email: string; password: string },
): Promise<void> {
  return postCredentials(endpoint, 'sign-up/email', input);
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
  };
  return {
    authEnabled: true,
    authenticated: Boolean(data.authenticated),
    user: data.user ?? undefined,
    provider: data.provider,
    auth: parseAuthDescriptor(data.auth),
  };
}

/**
 * Narrow the wire `auth` field to an {@link AuthDescriptor}, or `undefined` when
 * the server did not send one this SPA can act on.
 *
 * `undefined` is a meaningful answer rather than a failure: `SignInPage` falls
 * back to a neutral hosted-login button, which is something a user can act on
 * for the widest range of providers.
 *
 * `signIn.kind` is checked against the closed union rather than cast, because
 * an unrecognized kind is what a *newer* server sending a fifth kind looks like
 * to this build. Casting it would drop that payload into whichever branch
 * happens to be last; rejecting it degrades to that hosted-login fallback
 * instead.
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
