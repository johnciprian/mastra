import { MastraAuthWorkos } from '@mastra/auth-workos';
import {
  registerApiRoute,
  isAuthHttpHandler,
  isOrganizationsProvider,
  isSessionProvider,
  isSSOProvider,
} from '@mastra/core/server';
import type { ApiRoute, IMastraAuthProvider, ISessionProvider } from '@mastra/core/server';
import { toAuthDescriptor } from '@mastra/factory-auth/capabilities';
import type { AuthDescriptor } from '@mastra/factory-auth/capabilities';
import { toAuthIdentity } from '@mastra/factory-auth/identity';
import type { AuthIdentity } from '@mastra/factory-auth/identity';
import type { Context, Hono } from 'hono';

import type { RouteAuth } from './routes/route.js';
import { timedAboveThreshold } from './timing.js';

/**
 * Provider-neutral factory auth gating for the MastraCode web server.
 *
 * When an auth provider is active (a `MastraAuthProvider` instance passed to
 * `MastraFactory`'s `auth` slot, or — back-compat for suites/paths that never
 * boot the factory — implied by the WorkOS env vars), every route on the web
 * server is placed behind it: unauthenticated browser navigations are
 * redirected to the SPA's `/signin` page, API/XHR calls receive a 401, and a
 * small set of public routes stay reachable while signed out — the provider's
 * `/auth/*` routes plus `/auth/me`, the `/signin` page, its `/assets/*` bundle,
 * and the SPA manifest metadata. When no provider is active, `mountFactoryAuth` is a no-op and the server
 * behaves exactly as it does without auth.
 *
 * Provider specifics stay in the providers (`@mastra/auth-workos`,
 * `@mastra/auth-better-auth`, or any custom `IMastraAuthProvider`); this
 * module composes them capability-first via the core type guards:
 * - `authenticateToken` — session/bearer validation (all providers)
 * - `ISSOProvider` — hosted-login `/auth/login`, `/auth/callback`, `/auth/logout`
 * - `IAuthHttpHandler` — provider-owned `/auth/api/*` endpoints (better-auth)
 * - `IOrganizationsProvider` — personal-org bootstrap + admin checks
 * - `ICredentialsProvider.isSignUpEnabled` — SPA sign-up affordance, read
 *   through the kit's capability descriptor (see {@link authMeta})
 * - `getClearSessionHeaders` — session cookie clearing on logout
 *
 * One behavioural switch lives here: {@link isAuthIdentityV2Enabled}, the
 * rollback for the identity/session/logout migration. See its doc comment.
 */

/**
 * Name of the compat flag for the v2 identity path. Off unless explicitly
 * enabled — see {@link isAuthIdentityV2Enabled}.
 */
export const AUTH_IDENTITY_V2_ENV_VAR = 'MASTRACODE_AUTH_IDENTITY_V2';

/**
 * Parse the compat flag's value. Opt-in only: `1` and `true` (any case, any
 * surrounding whitespace) turn it on, and every other value leaves it off —
 * `0`, `false`, the empty string, and anything unrecognized alike.
 *
 * An unrecognized value resolves to off rather than on because this flag's
 * default *is* the safe answer. An operator who mistypes the value gets the
 * behaviour that already shipped, not an accidental opt-in to a path they had
 * not chosen. Exported so the parsing rules are testable without reloading the
 * module.
 */
export function readAuthIdentityV2Env(raw: string | undefined): boolean {
  const normalized = raw?.trim().toLowerCase();
  return normalized === '1' || normalized === 'true';
}

/**
 * The flag's value for this process, captured once at module load. See
 * {@link isAuthIdentityV2Enabled} for why it is read here and not per request.
 */
const AUTH_IDENTITY_V2 = readAuthIdentityV2Env(process.env[AUTH_IDENTITY_V2_ENV_VAR]);

/**
 * Whether the v2 identity path is enabled for this process
 * (`MASTRACODE_AUTH_IDENTITY_V2`), defaulting to **off**.
 *
 * The identity, session and logout changes land together, and together they are
 * the only part of this module that can break a live sign-in: they change how a
 * provider's `authenticateToken` result becomes a {@link FactoryAuthUser}, which
 * is the value every ownership check in the app compares against. A wrong answer
 * there does not throw — it reads as "this session belongs to somebody else" at
 * each check, and looks like data loss rather than an auth bug. So the release
 * carries a one-command rollback: unset the variable, restart, and the process
 * is back on the path that shipped before it.
 *
 * This is the single read site for the flag. Later work branches on this
 * function rather than reaching for `process.env` again, so that "what is this
 * process running?" has exactly one answer.
 *
 * READ ONCE, AT MODULE LOAD, AND THAT IS DELIBERATE
 *
 * A flag re-read per request can change value inside a running process, and a
 * session resolved on the v2 path but re-checked on the v1 path is precisely the
 * half-migrated state the flag exists to prevent. The gate also runs this on
 * every protected request, so one read is the cheaper shape besides.
 *
 * The cost is paid by tests: assigning to `process.env` after this module has
 * been imported does nothing. Reach the other path by reloading the module —
 * `vi.resetModules()` then `await import('./auth.js')` — as the compat-flag
 * suite in `auth-seam.test.ts` does. {@link readAuthIdentityV2Env} is exported
 * separately so the parsing rules need no reload at all.
 */
export function isAuthIdentityV2Enabled(): boolean {
  return AUTH_IDENTITY_V2;
}

/**
 * Minimal shape of the signed-in user surfaced to the SPA (no tokens).
 *
 * There is no vendor field. The type used to carry `workosId` beside `id`, which
 * meant every consumer had to decide which of the two was the real key — and a
 * vendor name in the neutral type is the tell that identity was never really
 * abstracted. Whatever the provider called its identifier, it arrives here as
 * {@link id}; see {@link legacyFactoryAuthUser} for how the pre-kit reader folds
 * `workosId` into it without changing which value wins.
 */
export interface FactoryAuthUser {
  /** Stable provider user id, used to scope per-user data (GitHub installs etc.). */
  id?: string;
  email?: string;
  name?: string;
  /** Provider-supplied profile picture URL, when the auth provider exposes one. */
  avatarUrl?: string;
  /**
   * Organization id. The org is the top-level tenant: it owns the GitHub
   * App installation and connected projects, while each user inside the org gets
   * isolated building instances. Absent for personal (no-org) accounts.
   */
  organizationId?: string;
}

/**
 * Tenant identity: the org is the top-level tenant, and each user inside it is
 * an isolated builder. Agent state, worktrees and sandboxes are scoped per
 * `(orgId, userId)`. Personal (no-org) users have `orgId === undefined`.
 */
export interface FactoryAuthTenant {
  /** Organization id, or `undefined` for personal (no-org) accounts. */
  orgId?: string;
  /** Stable provider user id. */
  userId: string;
}

/**
 * Validate that a `returnTo` value is a safe same-site path, to prevent
 * open-redirect attacks. Only absolute local paths (`/foo`) are allowed;
 * protocol-relative (`//evil.com`) and absolute URLs are rejected.
 */
export function sanitizeReturnTo(raw: string | undefined): string {
  if (!raw) return '/';
  if (!raw.startsWith('/')) return '/';
  // Reject protocol-relative URLs like "//evil.com" and "/\evil.com".
  if (raw.startsWith('//') || raw.startsWith('/\\')) return '/';
  return raw;
}

/** Extract a bearer token from the Authorization header, if present. */
export function getBearerToken(authorization: string | undefined): string {
  if (!authorization) return '';
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  return match?.[1] ?? '';
}

/**
 * Whether the SPA is served cross-origin from this API (platform deploy). When
 * `MASTRACODE_ALLOWED_ORIGINS` is set the browser talks to us cross-site, so
 * session cookies must be `SameSite=None; Secure` for the browser to send them.
 * Same-origin local dev leaves this unset and keeps the stricter `SameSite=Lax`.
 */
export function isCrossSiteAuth(): boolean {
  return Boolean(process.env.MASTRACODE_ALLOWED_ORIGINS?.trim());
}

/** Hono context variables set by the auth gate. */
export interface FactoryAuthVariables {
  factoryAuthUser: FactoryAuthUser;
}

/** Context key under which the gate stashes the authenticated user. */
const FACTORY_AUTH_USER_KEY = 'factoryAuthUser';

/**
 * Read the authenticated user the gate stashed on the context, or
 * `undefined` when unauthenticated / auth disabled. Used by downstream routes
 * (e.g. GitHub) to scope rows per user.
 */
export function getFactoryAuthUser(c: Context): FactoryAuthUser | undefined {
  return c.get(FACTORY_AUTH_USER_KEY) as FactoryAuthUser | undefined;
}

/**
 * Read the authenticated user off a request context, normalizing whatever the
 * active auth provider put there.
 *
 * The server's auth layer writes the provider's `authenticateToken` result into
 * the request context's `user` slot verbatim, so the value's shape follows the
 * provider: WorkOS writes a flat user, better-auth writes a `{ session, user }`
 * wrapper whose org lives on the session. Reading that slot as a
 * {@link FactoryAuthUser} therefore yields `undefined` for both the id and the
 * org under better-auth, which reads as "this session belongs to somebody else"
 * at every ownership check. Normalize on the way in instead.
 */
export function getFactoryAuthUserFromContext(
  requestContext: { get: (key: string) => unknown } | undefined,
): FactoryAuthUser | undefined {
  if (!requestContext || typeof requestContext.get !== 'function') return undefined;
  return toFactoryAuthUser(requestContext.get('user')) ?? undefined;
}

/**
 * Resolve the stable user id from an authenticated user shape.
 *
 * One field now, because {@link FactoryAuthUser} has one. This used to read
 * `workosId ?? id`, and that precedence is preserved where it mattered: the
 * legacy reader folds `workosId` into `id` with the same precedence, so the
 * value this returns is unchanged on both flag paths.
 */
export function getFactoryAuthUserId(user: FactoryAuthUser | undefined): string | undefined {
  return user?.id;
}

/** Resolve the organization id from a user shape, if present. */
export function getFactoryAuthOrgId(user: FactoryAuthUser | undefined): string | undefined {
  return user?.organizationId;
}

/**
 * Resolve the tenant identity `(orgId, userId)` from the authenticated user on
 * the context. Returns `undefined` when there is no signed-in user (auth
 * disabled or unauthenticated). `orgId` is `undefined` for personal accounts;
 * callers gate org-scoped GitHub features on its presence while agent state
 * falls back to a user-only tenant.
 */
export function factoryAuthTenant(c: Context): FactoryAuthTenant | undefined {
  const user = getFactoryAuthUser(c);
  const userId = getFactoryAuthUserId(user);
  if (!userId) return undefined;
  return { orgId: getFactoryAuthOrgId(user), userId };
}

/** True when both WorkOS credential env vars are present (legacy env gate). */
function envWorkosConfigured(): boolean {
  return Boolean(process.env.WORKOS_API_KEY && process.env.WORKOS_CLIENT_ID);
}

/**
 * WorkOS provider implied by the `WORKOS_*` env vars — back-compat for test
 * suites exercised without booting the factory (route suites set `WORKOS_*`
 * directly and call {@link mountFactoryAuth} without an explicit provider).
 * `fetchMemberships: true` lets `authenticateToken` resolve `organizationId`
 * from a single membership when the JWT has no org claim — required so a
 * bootstrapped personal org resolves without re-auth.
 */
function envFallbackAuthProvider(redirectUri: string | undefined): MastraAuthWorkos | undefined {
  if (!envWorkosConfigured()) return undefined;
  return new MastraAuthWorkos({
    redirectUri: redirectUri ?? process.env.WORKOS_REDIRECT_URI,
    fetchMemberships: true,
  });
}

/**
 * Map a provider `authenticateToken` result onto the neutral SPA user shape.
 *
 * Two implementations, chosen by {@link isAuthIdentityV2Enabled}: the kit's
 * {@link toAuthIdentity} when the flag is on, and {@link legacyFactoryAuthUser}
 * — the code that shipped — when it is off.
 *
 * WHAT THE KIT CHANGES, MEASURED RATHER THAN ASSUMED
 *
 * The two agree on structure: a `{ session, user }` wrapper is recognized
 * first, it never falls through to the flat reader, and the flat reader
 * otherwise takes the top level. They disagree on which keys count, and the
 * differences were enumerated by running both over a payload corpus rather than
 * by reading the two functions side by side.
 *
 * Mostly the kit resolves users the old reader turned into `null`, which is the
 * point of the change — a provider returning `{ uid }` (Firebase) or `{ sub }`
 * (raw OIDC claims) authenticated as nobody, then failed somewhere unrelated
 * with a message about state:
 *
 * - ids are read as `id` → `uid` → `sub`, not `id` alone;
 * - the same three keys are read inside a `{ session, user }` wrapper, where
 *   the old reader accepted only `user.id`;
 * - a numeric or bigint id is coerced to its decimal string, rather than
 *   rejected — a serial primary key behind a self-hosted provider is ordinary;
 * - in a wrapper, an absent `session.activeOrganizationId` now falls back to the
 *   `user` half's own `organizationId` instead of resolving to no org. This one
 *   *widens* org scope: a session that resolved as personal may now resolve into
 *   an organization the user does in fact belong to.
 *
 * Two narrow it, both fail-closed and both fixes:
 *
 * - a blank or whitespace-only `id` is treated as absent. The old reader
 *   returned it verbatim, so every user with a blank id shared one storage key;
 * - `workosId` is not an id key. See below, because this is the one with a
 *   production edge.
 *
 * THE `workosId` EDGE, AND WHY IT IS NARROW
 *
 * The old flat reader accepted `workosId` as an id, and {@link getFactoryAuthUserId}
 * preferred it over `id`. `AuthIdentity` has no vendor field, so under the flag
 * the key is simply `id`.
 *
 * That is a no-op against the real provider, which always emits both and sets
 * `workosId` to the same value as `id`. It is observable only where a
 * deployment has mapped `workosId` to a *different* JWT claim than the user id,
 * and there the storage key moves from the one to the other. That is exactly
 * the class of change the flag exists to make reversible.
 */
function toFactoryAuthUser(result: unknown, provider?: unknown): FactoryAuthUser | null {
  if (isAuthIdentityV2Enabled()) return fromAuthIdentity(toAuthIdentity(result, provider));
  return legacyFactoryAuthUser(result);
}

/**
 * Widen an {@link AuthIdentity} to the shape the rest of this module still
 * passes around. Field-for-field, minus `workosId`, which the kit's identity
 * does not carry — so under the flag {@link getFactoryAuthUserId} resolves `id`,
 * its only remaining source. B4 removes the field and this gap with it.
 */
function fromAuthIdentity(identity: AuthIdentity | null): FactoryAuthUser | null {
  if (!identity) return null;
  return {
    id: identity.id,
    email: identity.email,
    name: identity.name,
    avatarUrl: identity.avatarUrl,
    organizationId: identity.organizationId,
  };
}

/**
 * The identity reader that shipped, kept reachable while the flag defaults off.
 * Deleted once `MASTRACODE_AUTH_IDENTITY_V2` stops being a switch.
 *
 * Two result families:
 * - flat provider users (WorkOS `WorkOSUser` et al.): `id`/`workosId`/`email`/
 *   `name`/`organizationId` directly on the object;
 * - session-shaped results (better-auth `BetterAuthUser`): `{ session, user }`
 *   with the active org on the session.
 */
function legacyFactoryAuthUser(result: unknown): FactoryAuthUser | null {
  if (!result || typeof result !== 'object') return null;
  const record = result as Record<string, unknown>;

  // Session-shaped results: { session, user }. A result carrying both halves and
  // top-level identity fields is read as session-shaped: the session half is the
  // authenticated one, and preferring it keeps the org and the id from coming
  // from two different places.
  if (record.user && typeof record.user === 'object' && record.session && typeof record.session === 'object') {
    const user = record.user as { id?: unknown; email?: unknown; name?: unknown; avatarUrl?: unknown };
    const session = record.session as { activeOrganizationId?: unknown };
    if (typeof user.id !== 'string') return null;
    return {
      id: user.id,
      email: typeof user.email === 'string' ? user.email : undefined,
      name: typeof user.name === 'string' ? user.name : undefined,
      avatarUrl: typeof user.avatarUrl === 'string' ? user.avatarUrl : undefined,
      organizationId: typeof session.activeOrganizationId === 'string' ? session.activeOrganizationId : undefined,
    };
  }

  // Flat provider users.
  const flat = record as {
    id?: unknown;
    workosId?: unknown;
    email?: unknown;
    name?: unknown;
    avatarUrl?: unknown;
    organizationId?: unknown;
  };
  const id = typeof flat.id === 'string' ? flat.id : undefined;
  const workosId = typeof flat.workosId === 'string' ? flat.workosId : undefined;
  if (!id && !workosId) return null;
  return {
    // `workosId` first, then `id`. The neutral shape no longer has a vendor
    // field, so the vendor key is folded into `id` here instead — in the order
    // `getFactoryAuthUserId` used to apply itself, which is what keeps the
    // resolved user id identical for every payload this reader accepts.
    id: workosId ?? id,
    email: typeof flat.email === 'string' ? flat.email : undefined,
    name: typeof flat.name === 'string' ? flat.name : undefined,
    avatarUrl: typeof flat.avatarUrl === 'string' ? flat.avatarUrl : undefined,
    organizationId: typeof flat.organizationId === 'string' ? flat.organizationId : undefined,
  };
}

/**
 * Resolve the authenticated user for a request via the provider. Never throws:
 * ordinary invalid/expired sessions resolve to `null`.
 *
 * The provider is handed to {@link toFactoryAuthUser} as well as called. Under
 * the v2 path that lets a provider implementing the kit's `toIdentity` map its
 * own payload — the escape hatch for a token shape the kit does not recognize,
 * such as an id under a custom claim namespace. A mapper that throws is caught
 * here like any other provider failure and resolves to `null`, which is the
 * fail-closed direction: an unreadable payload authenticates nobody.
 */
async function authenticateRequest(
  provider: IMastraAuthProvider,
  token: string,
  raw: Request,
): Promise<FactoryAuthUser | null> {
  try {
    const result = await provider.authenticateToken(token, raw);
    return toFactoryAuthUser(result, provider);
  } catch {
    return null;
  }
}

/**
 * Bootstrap a personal org for no-org accounts so org-scoped features (GitHub
 * connect) work without leaving the app. Mutates the resolved user so the
 * current request sees the org immediately; subsequent requests resolve it via
 * the provider's own session/membership lookup (providers cache internally).
 * Best-effort: providers swallow their own bootstrap failures, and any
 * unexpected throw leaves the user no-org.
 */
async function ensureUserOrg(provider: IMastraAuthProvider, user: FactoryAuthUser): Promise<void> {
  if (getFactoryAuthOrgId(user)) return;
  if (!isOrganizationsProvider(provider)) return;
  const userId = getFactoryAuthUserId(user);
  if (!userId) return;
  try {
    const orgId = await provider.ensureOrganization(userId);
    if (orgId) user.organizationId = orgId;
  } catch {
    // Best-effort: the user stays no-org until a later request succeeds.
  }
}

/**
 * `Set-Cookie` values that clear the provider's session cookie(s), from the
 * provider's (possibly partial) `ISessionProvider.getClearSessionHeaders`.
 */
function providerClearCookies(provider: IMastraAuthProvider): string[] {
  const getClearSessionHeaders = (provider as Partial<ISessionProvider>).getClearSessionHeaders;
  if (typeof getClearSessionHeaders !== 'function') return [];
  const headers = getClearSessionHeaders.call(provider) ?? {};
  const setCookie = headers['Set-Cookie'];
  if (!setCookie) return [];
  // A provider may join several clearing cookies into one header value.
  return setCookie.split(/,(?=\s*[^;=,\s]+=)/).map(cookie => cookie.trim());
}

/**
 * Fail-closed authorization for organization-level administrative mutations.
 * The caller must belong to the same active organization and the provider must
 * explicitly confirm an admin/owner role.
 */
export async function isOrganizationAdmin(
  provider: IMastraAuthProvider | undefined,
  c: Context,
  organizationId: string,
): Promise<boolean> {
  const user = await ensureFactoryAuthUser(provider, c);
  if (!user || user.organizationId !== organizationId || !provider || !isOrganizationsProvider(provider)) {
    return false;
  }
  const userId = getFactoryAuthUserId(user);
  if (!userId) return false;
  try {
    return await provider.isOrganizationAdmin(organizationId, userId);
  } catch {
    return false;
  }
}

/**
 * Build the factory's implementation of the `RouteAuth` seam over the
 * resolved provider (`undefined` = auth disabled). Constructed once per boot
 * by `MastraFactory.prepare()` and handed to factory route modules at
 * construction — they never import the factory auth module directly.
 */
export function createFactoryRouteAuth(provider: IMastraAuthProvider | undefined): RouteAuth {
  return {
    enabled: () => provider !== undefined,
    ensureUser: (c: Context) => ensureFactoryAuthUser(provider, c),
    tenant: (c: Context) => factoryAuthTenant(c),
    isOrganizationAdmin: (c: Context, organizationId: string) => isOrganizationAdmin(provider, c, organizationId),
  };
}

/**
 * Resolve the authenticated user for a request, stashing it on the context.
 *
 * The gate only authenticates non-`/auth/*` requests via the `Authorization`
 * header, so cookie-based browser navigations to public `/auth/*` routes (the
 * GitHub connect/callback flow) arrive without a gate-stashed user. This reads
 * the session cookie from the raw request the same way `/auth/me` does,
 * caches the result on the context, and returns it so downstream helpers like
 * {@link factoryAuthTenant} work uniformly on both gated and public routes.
 *
 * Returns `undefined` when there is no valid session (or auth is disabled).
 */
export async function ensureFactoryAuthUser(
  provider: IMastraAuthProvider | undefined,
  c: Context,
): Promise<FactoryAuthUser | undefined> {
  const existing = getFactoryAuthUser(c);
  if (existing) return existing;
  if (!provider) return undefined;

  const token = getBearerToken(c.req.header('Authorization'));
  const user = await authenticateRequest(provider, token, c.req.raw);
  if (!user) return undefined;

  await ensureUserOrg(provider, user);

  c.set(FACTORY_AUTH_USER_KEY, user);
  return user;
}

export interface MountFactoryAuthOptions {
  /**
   * Explicit auth provider to mount. When omitted, falls back to a WorkOS
   * provider implied by the `WORKOS_*` env vars (back-compat for suites that
   * never boot the factory).
   */
  provider?: IMastraAuthProvider;
  /**
   * Absolute URL the identity provider redirects back to after login (WorkOS
   * env-fallback path only). Defaults to the `WORKOS_REDIRECT_URI` env var.
   */
  redirectUri?: string;
  /** Browser-facing origin used to derive the SSO callback URL. */
  publicUrl?: string;
}

/**
 * Decide whether a request is a top-level browser navigation (which should be
 * redirected to `/signin`) versus an API/XHR call (which should get a 401 JSON
 * response the SPA can react to).
 */
function isNavigationRequest(path: string, accept: string | undefined): boolean {
  if (path.startsWith('/api/')) return false;
  return (accept ?? '').includes('text/html');
}

/**
 * Provider description for the SPA, identical whether or not the caller has a
 * session, and the same object on every `/auth/me` response.
 *
 * `auth` is the capability descriptor: what this provider can do, in the shape
 * `@mastra/factory-auth` declares, so `/signin` can branch on capabilities
 * instead of on a vendor name. `provider` is the old answer — a bare name the
 * SPA still switches on — and it stays for one release so a browser holding a
 * cached bundle keeps working across the deploy. U9 removes it.
 *
 * THE TWO SIGN-UP FIELDS, AND WHY THEY ARE DERIVED RATHER THAN COMPUTED TWICE
 *
 * This response carries the same fact under two names of opposite polarity for
 * one release: `auth.signIn.signUpEnabled` is positive (it matches the provider
 * method, `isSignUpEnabled`), and the legacy `signUpDisabled` is negative. That
 * is the shape `factory-ui` reads today, so it cannot simply be dropped, and
 * U9 is where it goes.
 *
 * The hazard is a missing `!`. A sign-up link rendered on a deployment that
 * deliberately disabled sign-up looks like a working page from every angle —
 * nothing errors, nothing logs, and the only symptom is accounts that should
 * not exist. So `signUpDisabled` is *derived from* the descriptor here rather
 * than computed a second time from the provider: there is exactly one call to
 * `isSignUpEnabled` behind both fields, one negation between them, and no way
 * for the pair to drift apart as the code around them changes.
 *
 * That negation is also stricter than the expression it replaces, deliberately.
 * `toAuthDescriptor` answers `false` for a provider whose `isSignUpEnabled`
 * throws or returns a non-boolean (an `async` implementation returns a Promise,
 * which is truthy), where the old inline `=== false` let both cases through as
 * "sign-up is on". Both fields now fail closed on a misbehaving provider.
 *
 * `credentialsBasePath` is left at the kit's default, `/auth`, because that is
 * where {@link registerAuthRoutes} and {@link buildAuthRoutes} mount this
 * host's auth routes. A credentials provider's own endpoints hang below it at
 * `/auth/api/*`, which is what the SPA posts to.
 */
function authMeta(provider: IMastraAuthProvider): {
  /**
   * Optional because `IMastraAuthProvider.name` is. An unnamed provider drops
   * the key from the JSON rather than sending `null`, which is what this
   * response has always done and what the SPA's optional `provider?: string`
   * already expects.
   */
  provider: string | undefined;
  auth: AuthDescriptor;
  signUpDisabled?: true;
} {
  const auth = toAuthDescriptor(provider);
  const signUpDisabled = auth.signIn.signUpEnabled === false;
  return { provider: provider.name, auth, ...(signUpDisabled ? { signUpDisabled: true } : {}) };
}

/**
 * Handle the provider-neutral `/auth/me` route: validate the session with the
 * active provider and report the signed-in user (no tokens) to the SPA.
 * `/auth/me` is public (the gate skips `/auth/*`), so it validates the session
 * itself rather than reading a value the gate would have stashed.
 *
 * Both responses carry {@link authMeta}, so a signed-out browser learns how to
 * sign in from the same payload that tells it that it is signed out.
 */
async function handleAuthMe(provider: IMastraAuthProvider, c: Context): Promise<Response> {
  const token = getBearerToken(c.req.header('Authorization'));
  const user = await authenticateRequest(provider, token, c.req.raw);
  const meta = authMeta(provider);
  if (!user) {
    return c.json({ authenticated: false, user: null, ...meta });
  }
  // Resolve the org the same way gated requests do (providers cache, so this
  // is a lookup — not a create — after first bootstrap).
  await ensureUserOrg(provider, user);
  return c.json({
    authenticated: true,
    user: {
      userId: getFactoryAuthUserId(user),
      email: user.email,
      name: user.name,
      avatarUrl: user.avatarUrl,
      organizationId: user.organizationId,
    },
    ...meta,
  });
}

/**
 * Encode a validated returnTo path into the OAuth `state` parameter.
 *
 * Pipe format (`uuid|encodedPath`) is the contract `MastraAuthStudio` parses
 * to forward the path as the platform's `post_login_redirect`; a JSON blob
 * here silently degrades every post-login redirect to `/`.
 */
function encodeState(returnTo: string): string {
  return `${crypto.randomUUID()}|${encodeURIComponent(returnTo)}`;
}

/** Decode the OAuth `state` parameter back into a sanitized returnTo path. */
function decodeState(state: string | undefined): string {
  if (!state) return '/';
  const pipeIndex = state.indexOf('|');
  if (pipeIndex !== -1) {
    try {
      return sanitizeReturnTo(decodeURIComponent(state.slice(pipeIndex + 1)));
    } catch {
      return '/';
    }
  }
  return '/';
}

/**
 * Short-lived cookie stashing the post-login destination across the hosted
 * OAuth round-trip. Providers/platforms differ in whether they echo `state`
 * back to the callback, so the cookie is the reliable channel; `state` (when
 * echoed) takes precedence only if the cookie is missing.
 */
const RETURN_TO_COOKIE = 'mastra_factory_return_to';

function returnToCookieHeader(returnTo: string): string {
  const crossSite = isCrossSiteAuth() ? '; SameSite=None; Secure' : '; SameSite=Lax';
  return `${RETURN_TO_COOKIE}=${encodeURIComponent(returnTo)}; Path=/; Max-Age=600; HttpOnly${crossSite}`;
}

function clearReturnToCookieHeader(): string {
  const crossSite = isCrossSiteAuth() ? '; SameSite=None; Secure' : '; SameSite=Lax';
  return `${RETURN_TO_COOKIE}=; Path=/; Max-Age=0; HttpOnly${crossSite}`;
}

function readReturnToCookie(c: Context): string | undefined {
  const header = c.req.header('Cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const [name, ...rest] = part.trim().split('=');
    if (name === RETURN_TO_COOKIE) {
      try {
        return decodeURIComponent(rest.join('='));
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

/** HTTP methods supported for public auth routes. */
type AuthRouteMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'ALL';

/** A public `/auth/*` route derived from the provider's capabilities. */
interface AuthRouteSpec {
  path: string;
  method: AuthRouteMethod;
  handler: (c: Context) => Response | Promise<Response>;
}

/**
 * Derive the public `/auth/*` routes from the provider's capabilities:
 *
 * - `IAuthHttpHandler` → `ALL /auth/api/*` proxy to the provider's own HTTP
 *   surface (better-auth sign-in/up/out/session — what the SPA's
 *   email/password form posts to).
 * - `ISSOProvider` → hosted-login `GET /auth/login` / `GET /auth/callback` /
 *   `GET /auth/logout` (returnTo preserved through the OAuth `state` param).
 * - handler-shaped, non-SSO providers → `GET /auth/login` redirects to the
 *   SPA's `/signin` form, `GET /auth/logout` revokes via the provider's
 *   sign-out endpoint and clears the session cookie.
 */
function providerAuthRoutes(provider: IMastraAuthProvider, publicUrl?: string): AuthRouteSpec[] {
  const routes: AuthRouteSpec[] = [];

  if (isAuthHttpHandler(provider)) {
    routes.push({
      path: '/auth/api/*',
      method: 'ALL',
      handler: c => provider.handleAuthRequest(c.req.raw),
    });
  }

  if (isSSOProvider(provider)) {
    routes.push(
      {
        path: '/auth/login',
        method: 'GET',
        handler: async c => {
          const returnTo = sanitizeReturnTo(c.req.query('returnTo'));
          const state = encodeState(returnTo);
          // Build the callback URL from the browser-facing public origin so
          // the OAuth round-trip lands back on the SPA's origin (in dev the
          // SPA is on :5173 and Vite proxies /auth/* to the API on :4111 —
          // deriving from c.req.url would use :4111 and the post-callback
          // redirect to `/` would miss the SPA). Providers that ignore the
          // caller's URI in favor of their own config (e.g. MastraAuthWorkos
          // with an explicit `redirectUri` option) still take precedence.
          const redirectUri = publicUrl ? new URL('/auth/callback', publicUrl).toString() : '';
          const loginUrl = await provider.getLoginUrl(redirectUri, state);
          for (const cookie of (await provider.getLoginCookies?.(redirectUri, state)) ?? []) {
            c.header('Set-Cookie', cookie, { append: true });
          }
          // Stash the destination in a cookie too: not every provider/platform
          // echoes `state` back to the callback.
          if (returnTo !== '/') {
            c.header('Set-Cookie', returnToCookieHeader(returnTo), { append: true });
          }
          return c.redirect(loginUrl);
        },
      },
      {
        path: '/auth/callback',
        method: 'GET',
        handler: async c => {
          const code = c.req.query('code');
          const stateReturnTo = decodeState(c.req.query('state'));
          const cookieReturnTo = sanitizeReturnTo(readReturnToCookie(c));
          const returnTo = cookieReturnTo !== '/' ? cookieReturnTo : stateReturnTo;
          c.header('Set-Cookie', clearReturnToCookieHeader(), { append: true });
          const idpError = c.req.query('error');
          if (idpError) {
            // IdP denial (e.g. access_denied for a non-org-member): bouncing to
            // /auth/login would re-enter the IdP in a redirect loop.
            const query = new URLSearchParams({ error: idpError.slice(0, 64) });
            const description = c.req.query('error_description');
            if (description) query.set('error_description', description.slice(0, 256));
            if (returnTo !== '/') query.set('returnTo', returnTo);
            return c.redirect(`/signin?${query.toString()}`);
          }
          if (!code) {
            return c.redirect('/auth/login');
          }
          try {
            const result = await provider.handleCallback(code, c.req.query('state') ?? '');
            if (result.cookies?.length) {
              // Provider populated cookies directly (e.g. WorkOS AuthKit builds
              // its own sealed session cookie inside handleCallback).
              for (const cookie of result.cookies) {
                c.header('Set-Cookie', cookie, { append: true });
              }
            } else if (isSessionProvider(provider) && result.tokens) {
              // Fallback for providers that expose ISessionProvider but leave
              // cookie construction to the server (e.g. MastraAuthStudio, which
              // returns just the sealed session as accessToken so
              // getSessionHeaders can scope the cookie to this deployment's
              // domain via MASTRA_COOKIE_DOMAIN / sharedApiUrl auto-detection).
              // Mirrors packages/server/src/server/handlers/auth.ts:492-503.
              const resultUser = result.user as { id: string; organizationId?: string };
              const session = await provider.createSession(resultUser.id, {
                accessToken: result.tokens.accessToken,
                refreshToken: result.tokens.refreshToken,
                expiresAt: result.tokens.expiresAt,
                organizationId: resultUser.organizationId,
              });
              for (const [key, value] of Object.entries(provider.getSessionHeaders(session))) {
                c.header(key, value, { append: true });
              }
            }
            return c.redirect(returnTo);
          } catch {
            // Code exchange failed (expired/replayed code, misconfig). Send the
            // user back to login rather than surfacing a raw error.
            return c.redirect('/auth/login');
          }
        },
      },
      {
        path: '/auth/logout',
        method: 'GET',
        handler: async c => {
          let logoutUrl: string | null = null;
          try {
            logoutUrl = (await provider.getLogoutUrl?.('/', c.req.raw)) ?? null;
          } catch {
            logoutUrl = null;
          }
          // Clear the session cookie regardless of whether the provider
          // returned a logout URL.
          for (const cookie of providerClearCookies(provider)) {
            c.header('Set-Cookie', cookie, { append: true });
          }
          return c.redirect(logoutUrl ?? '/');
        },
      },
    );
  } else if (isAuthHttpHandler(provider)) {
    routes.push(
      {
        // Hosted-login equivalent: no hosted page, so send the browser to the
        // SPA's /signin form, preserving returnTo.
        path: '/auth/login',
        method: 'GET',
        handler: c => {
          const returnTo = sanitizeReturnTo(c.req.query('returnTo'));
          return c.redirect(`/signin?returnTo=${encodeURIComponent(returnTo)}`);
        },
      },
      {
        path: '/auth/logout',
        method: 'GET',
        handler: async c => {
          // Revoke the session server-side through the provider's own sign-out
          // endpoint and forward its clearing cookies; fall back to our clear
          // cookies regardless.
          try {
            const origin = new URL(c.req.url).origin;
            const response = await provider.handleAuthRequest(
              new Request(`${origin}/auth/api/sign-out`, { method: 'POST', headers: c.req.raw.headers }),
            );
            for (const cookie of response.headers.getSetCookie()) {
              c.header('Set-Cookie', cookie, { append: true });
            }
          } catch {
            // No/invalid session: nothing to revoke.
          }
          for (const cookie of providerClearCookies(provider)) {
            c.header('Set-Cookie', cookie, { append: true });
          }
          return c.redirect('/');
        },
      },
    );
  }

  return routes;
}

/**
 * Register the public `/auth/*` routes on a Hono app: the capability-derived
 * provider routes (login/callback/logout/provider APIs) plus the
 * provider-neutral `/auth/me`. Split out from `mountFactoryAuth` so both the local
 * Hono server and the platform Mastra entry can reuse the exact same handlers.
 */
export function registerAuthRoutes(
  app: Hono<any>,
  provider: IMastraAuthProvider,
  options: { publicUrl?: string } = {},
): void {
  for (const route of providerAuthRoutes(provider, options.publicUrl)) {
    const methods = route.method === 'ALL' ? ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] : [route.method];
    app.on(methods, route.path, c => route.handler(c));
  }
  app.get('/auth/me', c => handleAuthMe(provider, c));
}

/**
 * Build the public `/auth/*` routes (provider routes + `/auth/me`) as Mastra
 * `server.apiRoutes`. Used by the platform Mastra entry (`src/mastra/index.ts`),
 * which can't register plain Hono routes on the deployer-generated app the way
 * the local server does via {@link registerAuthRoutes}.
 *
 * Handlers are identical to {@link registerAuthRoutes}. All are `requiresAuth: false`
 * (they must be reachable while unauthenticated), and the gate middleware skips
 * `/auth/*` so it never blocks them. `/auth/*` is not under `/api`, so it is a
 * valid custom-route path.
 */
export function buildAuthRoutes(provider: IMastraAuthProvider, options: { publicUrl?: string } = {}): ApiRoute[] {
  return [
    // `registerApiRoute` handlers see @mastra/core's bundled hono Context type,
    // which is structurally identical to (but nominally distinct from) the
    // local hono version the route handlers are typed against — cast across
    // the seam.
    ...providerAuthRoutes(provider, options.publicUrl).map(route =>
      registerApiRoute(route.path, {
        method: route.method,
        requiresAuth: false,
        handler: c => route.handler(c as unknown as Context),
      }),
    ),
    registerApiRoute('/auth/me', {
      method: 'GET',
      requiresAuth: false,
      handler: c => handleAuthMe(provider, c as unknown as Context),
    }),
  ];
}

/**
 * Channel webhook paths whose adapter verifies the platform's request signature,
 * making the delivery self-authenticating. Add a platform here only once its
 * adapter rejects unsigned or mis-signed requests.
 */
const SIGNATURE_VERIFYING_CHANNEL_WEBHOOK = /^\/api\/agent-controllers\/[^/]+\/channels\/slack\/webhook$/;

// Fetched by tabs that may already be signed out. Enumerated, not prefix-matched,
// so a future route under the same prefix does not inherit the pass.
const SESSION_FAVICON_PATHS = new Set([
  '/favicon-session-initializing.svg',
  '/favicon-session-working.svg',
  '/favicon-session-awaiting.svg',
  '/favicon-session-error.svg',
]);

/**
 * Build the auth gate as a plain Hono middleware handler `(c, next)`. Protects
 * everything that is not a public `/auth/*` route: authenticated requests stash
 * the user on the context and continue; unauthenticated navigations redirect to
 * login and XHR/API calls get a 401 JSON. Shared by the local Hono server
 * (`mountFactoryAuth`) and the platform Mastra entry (`server.middleware`).
 */
export function createFactoryAuthGate(provider: IMastraAuthProvider) {
  return async (c: Context, next: () => Promise<void>): Promise<Response | void> => {
    const path = c.req.path;
    if (path.startsWith('/auth/')) {
      return next();
    }
    if (c.req.method === 'POST' && path === '/web/github/webhook') {
      return next();
    }
    // Inbound chat-channel webhooks (Slack events) carry no user session: they
    // authenticate by platform signature, the adapter verifying the request
    // against its signing secret. The routes declare `requiresAuth: false`, but
    // this gate is `use()` middleware — it runs before route matching, so that
    // metadata is not readable here and the path needs an explicit pass.
    //
    // The platform is allowlisted rather than matched as a wildcard: a pass
    // keyed on path shape alone would silently extend to any future adapter,
    // including one that does not verify signatures. Controller id stays a
    // wildcard because it is whatever the host registered.
    if (c.req.method === 'POST' && SIGNATURE_VERIFYING_CHANNEL_WEBHOOK.test(path)) {
      return next();
    }
    // The Slack account-linking deep link and the Sign-in-with-Slack OIDC
    // start/callback do their own auth (friendly login-redirect for signed-out
    // visitors; the OIDC callback authenticates via its signed `state`) — see
    // connect-route.ts.
    if (c.req.method === 'GET' && (path === '/connect/slack' || path.startsWith('/connect/slack/'))) {
      return next();
    }
    // The platform's deploy-auth flow lands IdP denials on `/login`
    // (`error=access_denied&error_description=...`); the SPA serves sign-in at
    // `/signin`, so forward the query there instead of burying it in returnTo.
    if (c.req.method === 'GET' && path === '/login') {
      return c.redirect(`/signin${new URL(c.req.url).search}`);
    }
    // The SPA sign-in page, its static bundle, and browser-fetched metadata
    // must be reachable while signed out; no user is stashed, so `/api/*`
    // stays protected.
    if (
      path === '/signin' ||
      path.startsWith('/assets/') ||
      path === '/manifest.webmanifest' ||
      path === '/mastra.svg' ||
      path === '/pwa-192.png' ||
      path === '/pwa-512.png' ||
      path === '/apple-touch-icon.png' ||
      (c.req.method === 'GET' && SESSION_FAVICON_PATHS.has(path))
    ) {
      return next();
    }

    const token = getBearerToken(c.req.header('Authorization'));
    // A slow verification here delays EVERY protected request — surface
    // outliers so auth-backend latency is attributable from server logs.
    const user = await timedAboveThreshold('auth.gate.authenticate', 1_000, () =>
      authenticateRequest(provider, token, c.req.raw),
    );

    if (user) {
      // Bootstrap a personal org for no-org accounts so the org id resolves on
      // this request (see ensureFactoryAuthUser for the rationale).
      await ensureUserOrg(provider, user);
      c.set(FACTORY_AUTH_USER_KEY, user);
      c.get('requestContext')?.set('user', user);
      return next();
    }

    if (isNavigationRequest(path, c.req.header('Accept'))) {
      const url = new URL(c.req.url);
      const returnTo = sanitizeReturnTo(url.pathname + url.search);
      return c.redirect(`/signin?returnTo=${encodeURIComponent(returnTo)}`);
    }

    return c.json({ error: 'unauthorized' }, 401);
  };
}

/**
 * Mount factory auth gating onto the host app. No-op when auth is disabled
 * (no provider active).
 *
 * Must be called before the Mastra adapter routes, the `/web/*` routes, and
 * the static UI handlers so the gate covers every request. Composes the shared
 * `registerAuthRoutes` + `createFactoryAuthGate` factories so the local Hono server
 * and the platform Mastra entry stay behavior-identical.
 */
export function mountFactoryAuth(app: Hono<any>, options: MountFactoryAuthOptions = {}): boolean {
  const provider = options.provider ?? envFallbackAuthProvider(options.redirectUri);
  if (!provider) return false;

  registerAuthRoutes(app, provider, { publicUrl: options.publicUrl });
  app.use('*', createFactoryAuthGate(provider));
  return true;
}
