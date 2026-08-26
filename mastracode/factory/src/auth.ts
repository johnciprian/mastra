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
import { getRequestHeader } from '@mastra/factory-auth/contract';
import { clearSessionCookie, mintSessionCookie, readSessionCookie } from '@mastra/factory-auth/cookie';
import type { SessionCookieSite } from '@mastra/factory-auth/cookie';
import { toAuthIdentity } from '@mastra/factory-auth/identity';
import type { AuthIdentity } from '@mastra/factory-auth/identity';
import { decodeState, encodeState } from '@mastra/factory-auth/oauth-state';
import { resolveOrganizationId } from '@mastra/factory-auth/organizations';
import type { Context, Hono } from 'hono';

import type { RouteAuth, RouteAuthProfile } from './routes/route.js';
import { timedAboveThreshold } from './timing.js';

/**
 * Provider-neutral factory auth gating for the MastraCode web server.
 *
 * When an auth provider is active — a `MastraAuthProvider` instance passed to
 * `MastraFactory`'s `auth` slot, which is the only way to activate one — every
 * route on the web
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
 * One behavioural switch lives here: {@link isAuthIdentityV2Enabled}, now on by
 * default and kept for one release as the rollback for the identity, session
 * and logout migration. See its doc comment.
 */

/**
 * Name of the compat flag for the v2 identity path. On unless explicitly
 * disabled — see {@link isAuthIdentityV2Enabled}.
 */
export const AUTH_IDENTITY_V2_ENV_VAR = 'MASTRACODE_AUTH_IDENTITY_V2';

/**
 * Parse the compat flag's value. Opt-**out** only: `0` and `false` (any case,
 * any surrounding whitespace) turn it off, and every other value leaves it on —
 * `1`, `true`, an unset variable, the empty string, and anything unrecognized
 * alike.
 *
 * WHY THE SAFE DIRECTION FLIPPED
 *
 * This started opt-in, and rejected unrecognized values for a reason worth
 * restating rather than deleting: the default was the shipped path, so a
 * mistyped value had to land there instead of opting a deployment into a
 * migration nobody had chosen.
 *
 * Both halves of that have now moved. The v2 path is the shipped path — it is
 * what the suite runs, what the conformance suite checks providers against, and
 * the only path where a `{ uid }` or `{ sub }` provider authenticates at all.
 * The legacy reader is the exception, kept reachable for one release so an
 * operator who hits a surprise has a way back. So the value that must never be
 * reached by accident is now the *old* one: a typo like `MASTRACODE_AUTH_IDENTITY_V2=flase`
 * must leave the process on v2, not silently drop it onto a path with known
 * defects. The rule is unchanged in spirit — an unrecognized value never
 * selects the non-default path — and the non-default path is the other one now.
 *
 * Exported so the parsing rules are testable without reloading the module.
 */
export function readAuthIdentityV2Env(raw: string | undefined): boolean {
  const normalized = raw?.trim().toLowerCase();
  return !(normalized === '0' || normalized === 'false');
}

/**
 * The flag's value for this process, captured once at module load. See
 * {@link isAuthIdentityV2Enabled} for why it is read here and not per request.
 */
const AUTH_IDENTITY_V2 = readAuthIdentityV2Env(process.env[AUTH_IDENTITY_V2_ENV_VAR]);

/**
 * Whether the v2 identity path is enabled for this process
 * (`MASTRACODE_AUTH_IDENTITY_V2`), defaulting to **on**.
 *
 * The identity, session and logout changes land together, and together they are
 * the only part of this module that can break a live sign-in: they change how a
 * provider's `authenticateToken` result becomes a {@link FactoryAuthUser}, which
 * is the value every ownership check in the app compares against. A wrong answer
 * there does not throw — it reads as "this session belongs to somebody else" at
 * each check, and looks like data loss rather than an auth bug.
 *
 * That is why this is still a switch after the default flipped. The release is
 * a soak, not a finished migration: set the variable to `false`, restart, and
 * the process is back on the reader that shipped before. {@link legacyFactoryAuthUser}
 * stays for exactly that, and the dual-path tests stay with it — deleting either
 * is a separate decision, taken after the soak rather than as part of it.
 *
 * This is the single read site for the flag. Everything else branches on this
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
 * `(orgId, userId)`.
 *
 * `orgId` is always a string. It used to be optional, and every org-gated route
 * had to decide what to do when it was missing — they all decided to 403, so a
 * signed-in user whose provider has no organization concept could not reach the
 * board at all. The kit resolves a deterministic `user:<userId>` organization
 * for exactly that case, which is a private organization of one rather than an
 * absent one, so the branch that produced the 403 no longer exists to be
 * written.
 */
export interface FactoryAuthTenant {
  /**
   * Organization id. A real one when the provider declares it, otherwise a
   * synthetic id derived from the user id — see {@link factoryAuthTenant}.
   */
  orgId: string;
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
 * The token to hand a provider's `authenticateToken` for this request.
 *
 * The `Authorization` header first, because an API client that sent one means
 * it. A browser navigation sends no such header, and the empty string it yields
 * is the provider's documented signal to go read the `Cookie` header itself —
 * which is what every provider-minted session still relies on.
 *
 * When this host owns the session cookie, its signed value is read here and
 * passed in explicitly instead. That is the difference the kit makes: the token
 * reaches the provider as an argument rather than each provider re-deriving it
 * from a header, and a cookie that fails its signature check or has expired
 * yields `''` — indistinguishable from no cookie at all, which is exactly how
 * a forged one should read.
 */
function requestAuthToken(c: Context): string {
  const bearer = getBearerToken(c.req.header('Authorization'));
  if (bearer) return bearer;
  const secret = authSessionSecret();
  if (!isAuthIdentityV2Enabled() || secret === undefined) return '';
  try {
    return readSessionCookie(c.req.raw, { secret }) ?? '';
  } catch {
    // A malformed cookie is not a reason to 500 a request that is merely
    // unauthenticated.
    return '';
  }
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

/**
 * Name of the env var holding the HMAC secret for the host's own session cookie.
 *
 * Must be at least 32 bytes and identical on every instance a request might
 * land on — two replicas with different secrets sign a user out every time the
 * load balancer moves them.
 */
export const AUTH_SESSION_SECRET_ENV_VAR = 'MASTRACODE_AUTH_SESSION_SECRET';

/**
 * The host session-cookie secret, or `undefined` when none is configured.
 *
 * Read per call rather than captured at module load, unlike the compat flag:
 * this one is a credential, and a process that rotates it (or a test that sets
 * it) should not have to be restarted to be believed. It is read on the
 * callback and on each gated request, which is a `process.env` lookup — cheaper
 * than the HMAC it guards.
 */
function authSessionSecret(): string | undefined {
  const secret = process.env[AUTH_SESSION_SECRET_ENV_VAR];
  return secret && secret.length > 0 ? secret : undefined;
}

/**
 * Whether this process mints, reads and clears its own session cookie through
 * the kit, rather than leaving all three to the provider.
 *
 * Two conditions, and both are deliberate:
 *
 * - the identity compat flag, because a change to the session cookie is a
 *   change to who is signed in, and it ships with the rest of that migration;
 * - a configured secret, because {@link mintSessionCookie} refuses to sign with
 *   a weak one and there is no safe default to invent. A deployment that turns
 *   the flag on without setting the secret keeps the behaviour it had rather
 *   than failing every sign-in, which is the direction that degrades safely.
 *
 * NOTE ON UPGRADING: the cookie the kit mints is not the cookie a provider
 * minted, so sessions do not survive switching this on. Everyone signs in once
 * more. That is a one-time cost of the host owning its own session, and it is
 * why this is behind a flag rather than simply shipped.
 */
function hostOwnsSessionCookie(): boolean {
  return isAuthIdentityV2Enabled() && authSessionSecret() !== undefined;
}

/**
 * Where the browser sits relative to this API, in the shape the kit's cookie
 * module takes. Drives `SameSite` and `Secure`, and with them whether the
 * cookie can carry the `__Host-` prefix — see {@link sessionCookieName}.
 */
function sessionCookieSite(): SessionCookieSite {
  return { crossSite: isCrossSiteAuth() };
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
 * the context. Returns `undefined` when there is no signed-in user — auth
 * disabled, or unauthenticated — and that is now the only reason it does.
 *
 * WHAT CHANGED, AND WHY IT IS NOT A WIDENING OF ACCESS
 *
 * `orgId` used to be optional, and a signed-in user whose provider has no
 * organization concept resolved to no organization. Every org-gated route group
 * then had the same decision to make with no good answer available, and each
 * one made the safe-looking choice: refuse. The result was a user who had
 * authenticated successfully, held a valid session, and could not open the
 * board — with nothing in the logs saying "no organization", because 403 is
 * what an unauthorized user gets too.
 *
 * `resolveOrganizationId` gives that case a real answer: a deterministic
 * `user:<userId>` organization. It is derived from the user's own id, so it is
 * unique to them and stable across processes and deploys — a private
 * organization of one, not a shared bucket. Nobody gains access to anybody
 * else's data; a user who previously had access to nothing gains access to
 * their own.
 *
 * A declared organization always wins. The provider — or the session inside it
 * — has said which organization this request is acting in, and preferring a
 * derived id over that would move a member of a real organization into a
 * private one, where their team's data is not.
 */
export function factoryAuthTenant(c: Context): FactoryAuthTenant | undefined {
  const user = getFactoryAuthUser(c);
  const userId = getFactoryAuthUserId(user);
  // Blank counts as absent. The pre-kit reader accepts a whitespace-only id and
  // hands it back verbatim, so this is reachable with the compat flag off — and
  // an id that is all spaces is a storage key every such user would share.
  // `resolveOrganizationId` refuses to derive an organization from one and
  // throws, which on a gated route is a 500 rather than the 401 the request
  // deserves. Answering "no tenant" here keeps the refusal and drops the crash.
  if (!userId || userId.trim() === '') return undefined;
  return { orgId: resolveOrganizationId({ id: userId, organizationId: getFactoryAuthOrgId(user) }), userId };
}

/**
 * Display fields for the signed-in user: the `RouteAuth.profile` answer.
 *
 * The tenant tuple deliberately carries no name, and for authorization that is
 * right. But the audit trail has to render a person, not an opaque id, and it
 * cannot get one from an `IUserProvider.getUser(id)` lookup either — the Studio
 * provider proxies through the shared API and always returns `null` for an
 * arbitrary id. So the acting user's own profile has to be captured from the
 * request that did the acting, which is exactly what this module already has
 * and no route module does. Exposing it here is what lets the audit domain stop
 * reading the gate's context variable itself.
 *
 * Gated on the same blank-id rule as {@link factoryAuthTenant}, so the two
 * cannot disagree about whether there is a signed-in user at all. Blank display
 * fields are dropped rather than passed through: a name of `"  "` renders as a
 * missing name in a UI but is truthy in code, which is the kind of value that
 * makes an actor look present and nameless.
 */
export function factoryAuthProfile(c: Context): RouteAuthProfile | undefined {
  const user = getFactoryAuthUser(c);
  const userId = getFactoryAuthUserId(user);
  if (!userId || userId.trim() === '') return undefined;
  const name = user?.name?.trim();
  const email = user?.email?.trim();
  const avatarUrl = user?.avatarUrl?.trim();
  return {
    id: userId,
    ...(name ? { name } : {}),
    ...(email ? { email } : {}),
    ...(avatarUrl ? { avatarUrl } : {}),
  };
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
 *   rejected — a serial primary key behind a self-hosted provider is ordinary.
 *
 * None of them widens organization scope. The kit briefly did, by falling back
 * to a wrapper's `user` half for an organization the session had not activated;
 * P12 settled that closed, so both readers now take a wrapper's organization
 * from `session.activeOrganizationId` and from nowhere else. A session that has
 * activated none resolves to the user's private partition under either reader,
 * which is why no assertion in this package's suite changes when the flag does.
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

/** The three `ISessionProvider` members transparent refresh needs. */
type SessionRefreshProvider = Pick<
  ISessionProvider,
  'refreshSession' | 'getSessionIdFromRequest' | 'getSessionHeaders'
>;

/**
 * Whether a provider can refresh a session without sending the user back
 * through a login.
 *
 * The three members are checked rather than `isSessionProvider`, and that is
 * still right now the guard tests all seven. This function asks a narrower
 * question than the guard: it needs exactly these three, and a provider that
 * has them can refresh whether or not it implements the rest of the interface.
 * Asking the guard would turn a smaller capability into no capability.
 */
function supportsSessionRefresh(
  provider: IMastraAuthProvider,
): provider is IMastraAuthProvider & SessionRefreshProvider {
  const candidate = provider as Partial<ISessionProvider>;
  return (
    typeof candidate.getSessionIdFromRequest === 'function' &&
    typeof candidate.refreshSession === 'function' &&
    typeof candidate.getSessionHeaders === 'function'
  );
}

/** What the gate learned about this request, plus any cookies it must send back. */
interface AuthenticatedRequest {
  user: FactoryAuthUser | null;
  /** Response headers carrying a refreshed session, when one was minted. */
  headers?: Record<string, string>;
}

/**
 * Authenticate a request, transparently refreshing an expired session once
 * before giving up.
 *
 * WHY THIS EXISTS
 *
 * `packages/server` already does this on `/api/*`, and the Factory did not. The
 * same provider, with a working `refreshSession`, therefore kept an API client
 * signed in indefinitely while signing a browser out of the Factory the moment
 * its access token expired — the same session, two different lifetimes,
 * depending only on which host served the route. That is the divergence this
 * closes; it is not a new capability.
 *
 * HOW A REFRESH IS FED BACK IN
 *
 * A provider reads its session from the request's `Cookie` header, so handing
 * it a refreshed session means handing it a request that carries one. The new
 * cookie is built from `getSessionHeaders`, spliced into a copy of the original
 * request, and the cookie's value is passed as the token as well — providers
 * differ on which of the two they read, and the two agree here.
 *
 * FAILURE IS ALWAYS THE ORIGINAL 401
 *
 * A refresh that returns nothing, throws, or produces a session that still does
 * not authenticate leaves `user` null and drops the headers. Sending a
 * `Set-Cookie` for a session that did not work would replace a cookie the
 * browser has with one that is no better, and the person would be signed out
 * with a fresh cookie in hand.
 */
async function authenticateWithRefresh(
  provider: IMastraAuthProvider,
  token: string,
  c: Context,
): Promise<AuthenticatedRequest> {
  const user = await authenticateRequest(provider, token, c.req.raw);
  if (user) return { user };
  if (!supportsSessionRefresh(provider)) return { user: null };

  try {
    const sessionId = provider.getSessionIdFromRequest(c.req.raw);
    if (!sessionId) return { user: null };

    const session = await provider.refreshSession(sessionId);
    if (!session) return { user: null };

    const headers = provider.getSessionHeaders(session);
    const cookiePair = Object.entries(headers)
      .filter(([key]) => key.toLowerCase() === 'set-cookie')
      .map(([, value]) => value.split(';')[0]?.trim() ?? '')
      .filter(pair => pair.length > 0)
      .join('; ');
    if (!cookiePair) return { user: null };

    const refreshedRequest = new Request(c.req.raw.url, {
      method: c.req.raw.method,
      headers: new Headers(c.req.raw.headers),
    });
    refreshedRequest.headers.set('Cookie', cookiePair);
    const refreshedValue = cookiePair.includes('=') ? cookiePair.slice(cookiePair.indexOf('=') + 1) : cookiePair;

    const refreshedUser = await authenticateRequest(provider, refreshedValue, refreshedRequest);
    if (!refreshedUser) return { user: null };

    // When this host owns the session cookie, the browser is holding ours
    // rather than the provider's, so the refreshed token has to be re-minted
    // under our name too — otherwise the next request presents the old one.
    const secret = authSessionSecret();
    if (hostOwnsSessionCookie() && secret !== undefined) {
      return {
        user: refreshedUser,
        headers: { ...headers, 'Set-Cookie': mintSessionCookie(refreshedValue, { ...sessionCookieSite(), secret }) },
      };
    }
    return { user: refreshedUser, headers };
  } catch {
    // A provider that throws mid-refresh is a provider that cannot refresh.
    return { user: null };
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
 *
 * THE UN-JOIN, AND WHAT IT IS DEFENDING AGAINST
 *
 * `getClearSessionHeaders` returns a `Record<string, string>`, so a provider
 * clearing two cookies has one slot to put them in and joins them with a comma
 * — which is how `Set-Cookie` is folded in HTTP/1.1, and is exactly what
 * `Headers.get('set-cookie')` hands back for multiple values. Appending that
 * joined string as a single header writes one malformed cookie and clears
 * neither, so it has to be split again.
 *
 * A plain `split(',')` cannot do it: a cookie's own `Expires` attribute
 * contains a comma (`Expires=Thu, 01 Jan 1970 00:00:00 GMT`), and splitting
 * there produces two fragments that are each nonsense. The lookahead requires
 * the comma to be followed by something shaped like `name=`, which an
 * `Expires` date is not — the day name is followed by a space and digits.
 *
 * It is a heuristic over a format that was never meant to be re-parsed, so the
 * malformed-header case it defends against is pinned by tests rather than left
 * to be rediscovered.
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
 * Revoke the caller's session server-side, where the provider can.
 *
 * Both halves are checked as methods rather than through `isSessionProvider`.
 * The guard now tests all seven members, so asking it here would decline to
 * revoke for a provider that has `getSessionIdFromRequest` and
 * `destroySession` but not the rest — the two this needs and the only two it
 * calls. Mirrors what `packages/server` does at its own logout — read the
 * session id off the request, then destroy it.
 *
 * Best-effort by design. A provider that throws here has still had its cookies
 * cleared by the caller, so the browser is signed out either way; failing the
 * whole request would leave the person looking at an error while their cookie
 * was already gone.
 */
async function revokeProviderSession(provider: IMastraAuthProvider, c: Context): Promise<void> {
  const session = provider as Partial<ISessionProvider>;
  if (typeof session.getSessionIdFromRequest !== 'function' || typeof session.destroySession !== 'function') return;
  try {
    const sessionId = session.getSessionIdFromRequest(c.req.raw);
    if (!sessionId) return;
    await session.destroySession(sessionId);
  } catch {
    // Already-expired or unknown session: nothing left to revoke.
  }
}

/**
 * Whether a GET `/auth/logout` came from a real browser navigation rather than
 * a sub-resource load on somebody else's page.
 *
 * A GET that signs the caller out is CSRF-triggerable: `<img src="/auth/logout">`
 * on any page silently ends the visitor's session. `Sec-Fetch-Dest` is what
 * separates the two — a top-level navigation sends `document`, an `<img>` sends
 * `image`, a `<script>` sends `script`. It is a forbidden header name, so a
 * page cannot set it, which is what makes it usable as a defence rather than a
 * hint.
 *
 * A request with no `Sec-Fetch-Dest` is allowed through: browsers that predate
 * the header exist, and refusing them would break sign-out for those people
 * rather than protecting them. That is the residual gap, and it is why this is
 * a shim on a deprecated route rather than the answer — `POST /auth/logout`
 * needs no such inference.
 */
function isLogoutNavigation(c: Context): boolean {
  const destination = c.req.header('Sec-Fetch-Dest');
  if (!destination) return true;
  return destination === 'document';
}

/**
 * Every `Set-Cookie` a sign-out should emit: the provider's own clearing
 * cookies, plus this host's when it owns one.
 *
 * Both, not either. A deployment that switched the host cookie on still has
 * users holding provider-minted cookies from before the switch, and a sign-out
 * that cleared only one of the two would leave the other behind — which reads
 * as "sign out did nothing" to the one person it happens to.
 */
function sessionClearCookies(provider: IMastraAuthProvider): string[] {
  const cookies = providerClearCookies(provider);
  if (hostOwnsSessionCookie()) cookies.push(clearSessionCookie(sessionCookieSite()));
  return cookies;
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
    runTenant: (requestContext: RequestContextLike | undefined) => factoryRunTenant(requestContext),
    profile: (c: Context) => factoryAuthProfile(c),
    isOrganizationAdmin: (c: Context, organizationId: string) => isOrganizationAdmin(provider, c, organizationId),
  };
}

/** The only shape {@link factoryRunTenant} needs from a request context. */
export interface RequestContextLike {
  get: (key: string) => unknown;
}

/**
 * Tenant identity for an agent-run request context, rather than an HTTP one.
 *
 * The same answer {@link factoryAuthTenant} gives, reached from the other
 * direction. Agent runs — dynamic workspace resolution, rule tools, session
 * subscriptions — execute under a `RequestContext` and never see the Hono
 * `Context` the rest of the seam takes, which is why those three modules
 * historically read identity out of the raw context themselves and were the
 * only callers left bypassing this port.
 *
 * The org resolution and the blank-id guard are identical on purpose: two
 * entry points that disagreed about who a caller is would be worse than the
 * bypass they replace.
 */
export function factoryRunTenant(requestContext: RequestContextLike | undefined): FactoryAuthTenant | undefined {
  const user = getFactoryAuthUserFromContext(requestContext);
  const userId = getFactoryAuthUserId(user);
  if (!userId || userId.trim() === '') return undefined;
  return { orgId: resolveOrganizationId({ id: userId, organizationId: user?.organizationId }), userId };
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

  const token = requestAuthToken(c);
  const user = await authenticateRequest(provider, token, c.req.raw);
  if (!user) return undefined;

  await ensureUserOrg(provider, user);

  c.set(FACTORY_AUTH_USER_KEY, user);
  return user;
}

export interface MountFactoryAuthOptions {
  /**
   * The auth provider to mount. Omitting it leaves auth disabled.
   *
   * There is no environment fallback. Which provider is active used to depend
   * on whether two `WORKOS_*` variables happened to be set in the process, so a
   * deployment could acquire an identity provider it never configured — and the
   * host had to name a vendor to offer that. The provider is now passed in, by
   * whoever decided on it.
   */
  provider?: IMastraAuthProvider;
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
  const token = requestAuthToken(c);
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
          const { returnTo: stateReturnTo } = decodeState(c.req.query('state'));
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
            // The read half of the `getLoginCookies` call in /auth/login above.
            // A PKCE provider wrote its code verifier there and needs it back
            // to finish the exchange, but `handleCallback` takes only `code`
            // and `state` — so the callback request's `Cookie` header has to
            // arrive separately, and this is the only channel for it. Without
            // this call such a provider throws for a missing verifier and the
            // catch below bounces the browser to /auth/login, which re-enters
            // the identity provider: a hosted login that cannot complete.
            //
            // Read through the contract's `getRequestHeader` rather than
            // `c.req.header('Cookie')` so header access here is the same
            // header access the rest of the kit performs.
            provider.setCallbackCookieHeader?.(getRequestHeader(c.req.raw, 'cookie'));

            // The RAW `state`, exactly as the identity provider echoed it, which
            // is what the codec documents a host hands to `handleCallback`.
            //
            // The other host disagrees: `packages/server` splits the value and
            // passes only the id half. A provider that stores something under
            // the `state` it was given at login and looks it up again here sees
            // two different spellings depending on who is driving it, and gets
            // "invalid or expired state" under one of them. The kit's answer is
            // `parseStateId(state) ?? state`, which normalizes both spellings to
            // the same key; `auth/okta` uses exactly that and works under both.
            //
            // So this deliberately keeps sending the raw value rather than
            // matching the other host: raw is what the contract documents, and a
            // provider written against that contract already handles it. Narrow
            // the value here and a provider that stored under the full `state`
            // would break instead.
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
              const secret = authSessionSecret();
              if (hostOwnsSessionCookie() && secret !== undefined) {
                // The host mints its own cookie: signed, `__Host-` prefixed
                // where the deployment allows it, and read back by
                // `requestAuthToken` rather than by each provider re-deriving
                // it from a header. `createSession` above is still the
                // provider's own record of the session — only the cookie moves.
                c.header(
                  'Set-Cookie',
                  mintSessionCookie(result.tokens.accessToken, { ...sessionCookieSite(), secret }),
                  {
                    append: true,
                  },
                );
              } else {
                for (const [key, value] of Object.entries(provider.getSessionHeaders(session))) {
                  c.header(key, value, { append: true });
                }
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
        method: 'POST',
        handler: c => ssoLogout(provider, c),
      },
      {
        // Deprecated for one release: the SPA and any bookmarked link still
        // navigate here with GET. See `isLogoutNavigation` for what this
        // refuses, and `ssoLogout` for what it does otherwise.
        path: '/auth/logout',
        method: 'GET',
        handler: c => {
          if (!isLogoutNavigation(c)) return c.redirect('/');
          return ssoLogout(provider, c);
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
        method: 'POST',
        handler: c => handlerLogout(provider, c),
      },
      {
        // Deprecated for one release; see the SSO branch above.
        path: '/auth/logout',
        method: 'GET',
        handler: c => {
          if (!isLogoutNavigation(c)) return c.redirect('/');
          return handlerLogout(provider, c);
        },
      },
    );
  }

  return routes;
}

/**
 * Sign out of a hosted-login provider: revoke server-side where the provider
 * supports it, clear every session cookie, then hand the browser on to the
 * provider's logout page when it has one.
 *
 * The order matters. Revocation reads the session id off the request, so it has
 * to happen before anything about the request is invalidated, and the cookies
 * are cleared whether or not the provider gave us a logout URL — a sign-out
 * that depends on a remote call succeeding is a sign-out that sometimes does
 * not happen.
 */
async function ssoLogout(provider: IMastraAuthProvider & Partial<ISSOLogout>, c: Context): Promise<Response> {
  await revokeProviderSession(provider, c);
  let logoutUrl: string | null = null;
  try {
    logoutUrl = (await provider.getLogoutUrl?.('/', c.req.raw)) ?? null;
  } catch {
    logoutUrl = null;
  }
  for (const cookie of sessionClearCookies(provider)) {
    c.header('Set-Cookie', cookie, { append: true });
  }
  return c.redirect(logoutUrl ?? '/');
}

/** The slice of `ISSOProvider` {@link ssoLogout} needs. */
interface ISSOLogout {
  getLogoutUrl?: (returnTo: string, request: Request) => Promise<string | null> | string | null;
}

/**
 * Sign out of a provider that serves its own auth routes: post to its sign-out
 * endpoint, forward whatever clearing cookies it answers with, and clear ours
 * regardless.
 */
async function handlerLogout(
  provider: IMastraAuthProvider & { handleAuthRequest: (request: Request) => Promise<Response> },
  c: Context,
): Promise<Response> {
  await revokeProviderSession(provider, c);
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
  for (const cookie of sessionClearCookies(provider)) {
    c.header('Set-Cookie', cookie, { append: true });
  }
  return c.redirect('/');
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

    const token = requestAuthToken(c);
    // A slow verification here delays EVERY protected request — surface
    // outliers so auth-backend latency is attributable from server logs.
    const { user, headers } = await timedAboveThreshold('auth.gate.authenticate', 1_000, () =>
      authenticateWithRefresh(provider, token, c),
    );

    // A refreshed session has to reach the browser even on the request that
    // triggered the refresh, or the next one presents the same expired cookie
    // and refreshes again — working, but re-refreshing forever.
    for (const [key, value] of Object.entries(headers ?? {})) {
      c.header(key, value, { append: true });
    }

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
 * (no provider passed).
 *
 * Must be called before the Mastra adapter routes, the `/web/*` routes, and
 * the static UI handlers so the gate covers every request. Composes the shared
 * `registerAuthRoutes` + `createFactoryAuthGate` factories so the local Hono server
 * and the platform Mastra entry stay behavior-identical.
 *
 * Reads no environment variables. Whether auth is on is now exactly "was a
 * provider passed", which is a question the caller can answer by looking at its
 * own code rather than at the process environment.
 */
export function mountFactoryAuth(app: Hono<any>, options: MountFactoryAuthOptions = {}): boolean {
  const provider = options.provider;
  if (!provider) return false;

  registerAuthRoutes(app, provider, { publicUrl: options.publicUrl });
  app.use('*', createFactoryAuthGate(provider));
  return true;
}
