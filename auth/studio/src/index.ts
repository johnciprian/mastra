import { createHash } from 'node:crypto';

import type {
  IOrganizationsProvider,
  ISSOProvider,
  ISessionProvider,
  IUserProvider,
  MastraAuthRequest,
  Session,
  SSOCallbackResult,
  SSOLoginConfig,
} from '@internal/auth';
import { getRequestHeader } from '@internal/auth';
import type { EEUser, IRBACProvider, RoleMapping } from '@internal/auth/ee';
import { resolvePermissionsFromMapping, matchesPermission } from '@internal/auth/ee';
import { MastraAuthProvider } from '@internal/auth/provider';
import type { MastraAuthProviderOptions } from '@internal/auth/provider';

export interface StudioUser extends EEUser {
  id: string;
  email?: string;
  name?: string;
  avatarUrl?: string;
  organizationId?: string;
  role?: string;
  permissions?: string[];
  /** All organization IDs the user is a member of (for cross-org access checks) */
  memberOrgIds?: string[];
}

export interface MastraAuthStudioOptions extends MastraAuthProviderOptions<StudioUser> {
  /** Base URL of the Mastra shared API (e.g., https://api.mastra.ai/v1) */
  sharedApiUrl?: string;
  /** Organization ID that owns this deployed instance. Users not in this org are rejected. */
  organizationId?: string;
  /**
   * Cookie domain for session cookies (e.g., '.example.com').
   * When set, cookies will include Secure and Domain attributes.
   * Defaults to auto-detecting from sharedApiUrl (uses '.mastra.ai' when sharedApiUrl contains '.mastra.ai').
   * Can also be set via MASTRA_COOKIE_DOMAIN environment variable.
   */
  cookieDomain?: string;
}

const COOKIE_NAME = 'wos-session';

/**
 * How long a session minted here is good for. The shared API's sealed cookie
 * carries its own lifetime; this is the window this provider reports for it,
 * and the lifetime of a locally minted session record.
 */
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * The organization id namespace for a user this provider cannot resolve a real
 * organization for, matching `@mastra/factory-auth`'s synthetic one.
 *
 * The literal is duplicated rather than imported because `@mastra/factory-auth`
 * is a devDependency here — this package must not grow a runtime dependency on
 * it — and because the value is a compatibility constant rather than a free
 * choice: `resolveOrganizationId` in the Factory
 * (`mastracode/factory/src/auth.ts`) already resolves a no-organization user to
 * `user:${userId}`, so rows for these users are in deployed databases under it.
 * `auth/firebase` and `auth/supabase` duplicate it for the same reason.
 */
const SYNTHETIC_ORGANIZATION_PREFIX = 'user:';

/**
 * Upper bound for shared-API verification fetches. Matches the platform API
 * client's request budget: a slow shared API must fail a single request in
 * bounded time instead of hanging every authenticated endpoint behind it.
 */
const VERIFY_FETCH_TIMEOUT_MS = 15_000;

/**
 * How long a successful credential verification may be reused without
 * re-contacting the shared API. Bounds revocation lag: a signed-out or
 * revoked session can be honored for at most this long.
 */
const VERIFY_CACHE_TTL_MS = 30_000;

/**
 * Auth provider for Mastra Studio deployed instances.
 *
 * Proxies all authentication through the shared API, keeping the
 * WorkOS API key safely in the shared API. Deployed instances only
 * need the shared API URL — no secrets required.
 *
 * The shared API's sealed session cookie (`wos-session`) is set with
 * `Domain=.mastra.ai` in production, so it's included in requests
 * to deployed instances and can be forwarded for validation.
 */
export class MastraAuthStudio
  extends MastraAuthProvider<StudioUser>
  implements ISSOProvider<StudioUser>, ISessionProvider<Session>, IUserProvider<StudioUser>, IOrganizationsProvider
{
  readonly isMastraCloudAuth = true;

  private sharedApiUrl: string;
  private organizationId: string | undefined;
  private useProductionCookies: boolean;
  private cookieDomain: string | undefined;
  /**
   * `userId → sealed session cookie` cache. The `IOrganizationsProvider`
   * interface only hands us a `userId`, but the shared API's org endpoints are
   * cookie-authenticated — so we remember the cookie last seen for a user
   * inside `verifySessionCookie` and reuse it here. Kept small: bounded to
   * the last 1000 users, LRU-evicted on insert.
   */
  private userSessionCookies = new Map<string, string>();
  private readonly maxCachedSessions = 1000;

  /**
   * Short-TTL cache of SUCCESSFUL credential verifications, keyed by a
   * sha256 of the credential (never the raw cookie/token). Every protected
   * request re-verifies against the shared API otherwise — one network
   * round trip per request. Failures are never cached, so a rejected
   * credential is always re-checked. Bounded + insert-order evicted.
   */
  private verifiedCredentials = new Map<string, { user: StudioUser; expiresAt: number }>();
  private readonly maxCachedVerifications = 1000;

  /**
   * Sessions this provider minted with no shared-API credential behind them —
   * `createSession(userId)` with no `metadata.accessToken`. Sealed sessions are
   * never stored here; see {@link createSession}. Bounded and insert-order
   * evicted like the caches above.
   */
  private localSessions = new Map<string, Session>();
  private readonly maxLocalSessions = 1000;

  /**
   * In-flight `ensureOrganization` promises keyed by userId. Concurrent calls
   * for the same brand-new user (multiple tabs, parallel requests) would
   * otherwise all see "no org" from `GET /auth/me` and each fire
   * `POST /auth/orgs`, creating duplicate personal organizations. The first
   * caller's promise is reused by every follower until it settles.
   */
  private organizationBootstrapInFlight = new Map<string, Promise<string | undefined>>();

  constructor(options?: MastraAuthStudioOptions) {
    super({ name: 'mastra-studio', ...options });
    const explicitSharedApiUrl = options?.sharedApiUrl || process.env.MASTRA_SHARED_API_URL;
    this.sharedApiUrl = explicitSharedApiUrl || 'https://platform.mastra.ai/v1';
    this.organizationId = options?.organizationId || process.env.MASTRA_ORGANIZATION_ID;

    // Strip trailing slash
    if (this.sharedApiUrl.endsWith('/')) {
      this.sharedApiUrl = this.sharedApiUrl.slice(0, -1);
    }

    // Cookie domain can be explicitly configured, read from env, or auto-detected from sharedApiUrl
    this.cookieDomain = options?.cookieDomain || process.env.MASTRA_COOKIE_DOMAIN;

    // Use production cookie settings (Secure + Domain) when:
    // 1. An explicit cookieDomain is configured, OR
    // 2. The shared API is *explicitly* configured on .mastra.ai (auto-detect
    //    default domain). The built-in platform.mastra.ai fallback doesn't
    //    count — a localhost studio using the default would otherwise mint
    //    Domain=.mastra.ai cookies the browser rejects.
    // Use hostname-based detection to avoid false positives (e.g., api.mastra.ai.evil.com)
    let autoDetectMastraAi = false;
    if (explicitSharedApiUrl) {
      try {
        const hostname = new URL(this.sharedApiUrl).hostname.toLowerCase();
        autoDetectMastraAi = hostname === 'mastra.ai' || hostname.endsWith('.mastra.ai');
      } catch {
        autoDetectMastraAi = false;
      }
    }
    this.useProductionCookies = !!this.cookieDomain || autoDetectMastraAi;

    // If no explicit domain but we're on .mastra.ai, use the default domain
    if (!this.cookieDomain && autoDetectMastraAi) {
      this.cookieDomain = '.mastra.ai';
    }

    if (options) {
      this.registerOptions(options);
    }
  }

  // ---------------------------------------------------------------------------
  // MastraAuthProvider abstract methods
  // ---------------------------------------------------------------------------

  /**
   * Authenticate an incoming request by forwarding the sealed session cookie
   * to the shared API's /auth/me endpoint, or a Bearer token to /auth/verify.
   */
  async authenticateToken(token: string, request: MastraAuthRequest): Promise<StudioUser | null> {
    let user: StudioUser | null = null;

    // Try sealed session cookie first (browser flow)
    const cookieHeader = getRequestHeader(request, 'Cookie');
    const sessionCookie = parseCookie(cookieHeader, COOKIE_NAME);

    if (sessionCookie) {
      user = await this.verifySessionCookie(sessionCookie);
    }

    // Fall back to Bearer token (CLI / API token flow)
    if (!user && token) {
      user = await this.verifyBearerToken(token);
    }

    if (!user) return null;

    // Org-scoping: if this instance belongs to a specific org, reject users not a member of that org
    // Check memberOrgIds (all orgs user belongs to) rather than organizationId (current org)
    if (this.organizationId && !user.memberOrgIds?.includes(this.organizationId)) {
      return null;
    }

    return user;
  }

  authorizeUser(user: StudioUser): boolean {
    return !!user?.id;
  }

  // ---------------------------------------------------------------------------
  // ISSOProvider
  // ---------------------------------------------------------------------------

  getLoginUrl(redirectUri: string, state: string): string {
    // Extract the post-login redirect from state (format: uuid|encodedPostLoginRedirect)
    let postLoginRedirect = '/';
    if (state) {
      const pipeIndex = state.indexOf('|');
      if (pipeIndex !== -1) {
        try {
          postLoginRedirect = decodeURIComponent(state.slice(pipeIndex + 1));
        } catch {
          // ignore decode errors
        }
      }
    }

    const params = new URLSearchParams({
      product: 'deploy',
      redirect_uri: redirectUri,
      post_login_redirect: postLoginRedirect,
      // The host's `state`, forwarded whole and unmodified.
      //
      // `post_login_redirect` above carries only the destination half of it. The
      // other half is the id a host mints per sign-in and compares on the
      // callback to tell its own redirect apart from one somebody else started
      // — the CSRF check — and dropping the value meant that half never came
      // back, on any request. Forwarding it under the OAuth parameter name is
      // the only spelling a host can read back, since the callback receives
      // whatever the authorization server echoes as `state`.
      //
      // Carried in addition to `post_login_redirect`, never instead of it: a
      // shared API that does not echo `state` back keeps behaving exactly as it
      // does today, and the destination still arrives by the parameter it
      // arrives by now.
      ...(state ? { state } : {}),
      // Force re-authentication so AuthKit always shows the account picker
      prompt: 'login',
      ...(this.organizationId ? { organization_id: this.organizationId } : {}),
    });

    return `${this.sharedApiUrl}/auth/login?${params.toString()}`;
  }

  async handleCallback(code: string, _state: string): Promise<SSOCallbackResult<StudioUser>> {
    // The shared API already consumed the OAuth code and passes the sealed
    // session directly as the `code` parameter in the redirect to this callback.
    // Validate it to get user info.
    this.logger.debug('SSO callback: validating sealed session via shared API', {
      sharedApiUrl: this.sharedApiUrl,
      codeLength: code?.length,
    });
    // `throwOnFailure` so the reason survives. Without it every way this can go
    // wrong — an expired session, a clock skew, an unreachable shared API —
    // reaches the operator as the same one sentence, and the one that matters
    // (the shared API is down) is the one that looks like all the others.
    let user: StudioUser | null;
    try {
      user = await this.verifySessionCookie(code, { throwOnFailure: true });
    } catch (error) {
      this.logger.error('SSO callback: session validation failed', {
        sharedApiUrl: this.sharedApiUrl,
        codeLength: code?.length,
        error: error instanceof Error ? { message: error.message, stack: error.stack } : String(error),
      });
      throw new Error('Session validation failed', { cause: error });
    }
    if (!user) {
      this.logger.error('SSO callback: session validation failed — verifySessionCookie returned null', {
        sharedApiUrl: this.sharedApiUrl,
        codeLength: code?.length,
      });
      throw new Error('Session validation failed');
    }

    // Omit `cookies` so the Mastra server fallback path calls
    // createSession() + getSessionHeaders() to build a cookie scoped to
    // the deployed instance's domain.
    return {
      user,
      tokens: {
        accessToken: code,
      },
    };
  }

  setCallbackCookieHeader(_cookieHeader: string | null): void {
    // No-op: we don't use PKCE cookies — the shared API handles the full OAuth flow
  }

  getLoginCookies(): string[] | undefined {
    // No PKCE cookies needed — shared API manages the OAuth state
    return undefined;
  }

  getLoginButtonConfig(): SSOLoginConfig {
    return {
      provider: 'mastra-studio',
      text: 'Sign in with Mastra',
      description:
        'Your deployed Studio is secured by your Mastra account. Sign in with the same email you used to sign up on mastra.ai.',
    };
  }

  async getLogoutUrl(_redirectUri: string, request?: Request): Promise<string | null> {
    const cookieHeader = request?.headers.get('Cookie');
    const sessionCookie = parseCookie(cookieHeader, COOKIE_NAME);

    if (!sessionCookie) return null;

    try {
      const res = await fetch(`${this.sharedApiUrl}/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `${COOKIE_NAME}=${sessionCookie}`,
        },
      });

      if (res.ok) {
        const data = (await res.json()) as { ok: boolean; logoutUrl?: string };
        return data.logoutUrl ?? null;
      }
    } catch {
      // Failed to get logout URL — return null
    }

    return null;
  }

  // ---------------------------------------------------------------------------
  // ISessionProvider
  // ---------------------------------------------------------------------------

  /**
   * Mint a session for a signed-in user.
   *
   * Two shapes, decided by whether the caller supplies the credential the
   * shared API issued. The host does, on every path that exists today
   * (`mastracode/factory/src/auth.ts`, `packages/server/src/server/handlers/auth.ts`):
   * `metadata.accessToken` is the sealed session, it becomes the session id,
   * and {@link validateSession} verifies it against the shared API on every
   * call — no local state, no revocation lag.
   *
   * Without it there is no shared-API session to name, and this used to mint a
   * random UUID that {@link validateSession} could never accept: a session the
   * provider created and then denied, which is a sign-in that does not stick.
   * `metadata` is optional in `ISessionProvider`, so that path is reachable by
   * any host that does not happen to pass one. Such a session is now recorded
   * here, so create/validate/destroy are one loop rather than two halves that
   * never meet.
   *
   * What a locally recorded session is NOT is a credential the shared API
   * knows: it authenticates nobody with `authenticateToken`, which reads the
   * `wos-session` cookie and asks the shared API about it. It is a record of a
   * sign-in this process performed, held in this process — so it does not
   * survive a restart and is not visible to another replica.
   */
  async createSession(userId: string, metadata?: Record<string, unknown>): Promise<Session> {
    const now = new Date();
    const accessToken = metadata?.accessToken;
    const session: Session = {
      id: (accessToken as string) || crypto.randomUUID(),
      userId,
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
      createdAt: now,
      metadata,
    };
    // Only the sessions with no shared-API credential behind them. Recording a
    // sealed session here would let this provider answer for it from memory for
    // a whole day, which is exactly the revocation lag `validateSession` avoids
    // by asking the shared API every time.
    if (!accessToken) this.rememberLocalSession(session);
    return session;
  }

  async validateSession(sessionId: string): Promise<Session | null> {
    // Locally minted sessions only — the map never holds a sealed session, so
    // this cannot shadow one, and a sealed session still costs a shared-API
    // round trip on every call.
    const local = this.readLocalSession(sessionId);
    if (local) return local;

    const user = await this.verifySessionCookie(sessionId);
    if (!user) return null;

    const now = new Date();
    return {
      id: sessionId,
      userId: user.id,
      expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
      createdAt: now,
    };
  }

  async destroySession(sessionId: string): Promise<void> {
    // A locally minted session is destroyed by forgetting it. Sending its id to
    // the shared API would ask it to sign out a cookie it never issued.
    if (this.localSessions.delete(sessionId)) return;

    try {
      await fetch(`${this.sharedApiUrl}/auth/logout`, {
        method: 'POST',
        headers: {
          Cookie: `${COOKIE_NAME}=${sessionId}`,
        },
      });
    } catch {
      // Best effort
    }
  }

  async refreshSession(sessionId: string): Promise<Session | null> {
    try {
      // Call the shared API's /auth/refresh endpoint to get a fresh access token
      const res = await fetch(`${this.sharedApiUrl}/auth/refresh`, {
        method: 'GET',
        headers: {
          Cookie: `${COOKIE_NAME}=${sessionId}`,
        },
      });

      if (!res.ok) {
        this.logger.warn('refreshSession: shared API refresh returned non-OK status', {
          status: res.status,
          url: `${this.sharedApiUrl}/auth/refresh`,
        });
        // Refresh failed, fall back to validation (will likely also fail)
        return this.validateSession(sessionId);
      }

      // Parse the new sealed session from Set-Cookie header
      const setCookie = res.headers.get('Set-Cookie');
      const newSessionId = setCookie ? parseCookieFromHeader(setCookie, COOKIE_NAME) : null;

      if (!newSessionId) {
        this.logger.warn('refreshSession: no Set-Cookie header in refresh response');
        // No new cookie returned, fall back to validation with original
        return this.validateSession(sessionId);
      }

      // Verify the new session works and return it
      const user = await this.verifySessionCookie(newSessionId);
      if (!user) return null;

      const now = new Date();
      return {
        id: newSessionId,
        userId: user.id,
        expiresAt: new Date(now.getTime() + SESSION_TTL_MS),
        createdAt: now,
      };
    } catch (error) {
      this.logger.error('refreshSession: fetch to shared API failed', {
        url: `${this.sharedApiUrl}/auth/refresh`,
        error: error instanceof Error ? { message: error.message, stack: error.stack } : String(error),
      });
      // On error, fall back to validation
      return this.validateSession(sessionId);
    }
  }

  getSessionIdFromRequest(request: Request): string | null {
    const cookieHeader = request.headers.get('Cookie');
    return parseCookie(cookieHeader, COOKIE_NAME);
  }

  getSessionHeaders(session: Session): Record<string, string> {
    const parts = [`${COOKIE_NAME}=${session.id}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=86400'];
    if (this.useProductionCookies && this.cookieDomain) {
      parts.push('Secure');
      parts.push(`Domain=${this.cookieDomain}`);
    }
    return { 'Set-Cookie': parts.join('; ') };
  }

  getClearSessionHeaders(): Record<string, string> {
    const parts = [`${COOKIE_NAME}=`, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
    if (this.useProductionCookies && this.cookieDomain) {
      parts.push('Secure');
      parts.push(`Domain=${this.cookieDomain}`);
    }
    return { 'Set-Cookie': parts.join('; ') };
  }

  // ---------------------------------------------------------------------------
  // IUserProvider
  // ---------------------------------------------------------------------------

  async getCurrentUser(request: Request): Promise<StudioUser | null> {
    const cookieHeader = request.headers.get('Cookie');
    const sessionCookie = parseCookie(cookieHeader, COOKIE_NAME);

    if (sessionCookie) {
      return this.verifySessionCookie(sessionCookie);
    }

    // Try bearer token
    const authHeader = request.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      return this.verifyBearerToken(authHeader.slice(7));
    }

    return null;
  }

  async getUser(_userId: string): Promise<StudioUser | null> {
    // Cannot look up users by ID — only validate sessions
    return null;
  }

  // ---------------------------------------------------------------------------
  // IOrganizationsProvider
  // ---------------------------------------------------------------------------

  /**
   * The organization this user's data is stored under, bootstrapping a real
   * personal organization on the shared API when there is a session to do it
   * with, and deriving one when there is not.
   *
   * WHY THERE ARE TWO ANSWERS
   *
   * The shared API's org endpoints are cookie-authenticated and this method
   * receives only a userId, so the real bootstrap runs against the sealed
   * session cookie last seen for that user in {@link userSessionCookies}
   * (populated by {@link verifySessionCookie}). That is the browser flow, and
   * it is unchanged: an existing org wins, a membership wins, and a user with
   * neither gets a personal organization created on the shared API.
   *
   * A user this provider holds no cookie for used to get `undefined` on every
   * request forever — the CLI/API-token flow, which authenticates through
   * `verifyBearerToken` and never records a cookie, never got an organization
   * bootstrapped at all. `undefined` is a value a host cannot store, so this
   * now falls back to the same derived `user:${userId}` the Factory's own
   * `resolveOrganizationId` already applies to a user with no organization
   * (`mastracode/factory/src/auth.ts`): the partition those rows land in is the
   * one they land in today, decided one layer earlier and reported honestly.
   *
   * The fallback covers a failed bootstrap for the same reason, which is the
   * rule `withSyntheticOrganizations` states: a delegate that declines and one
   * that fails are the same thing to a caller that needs a column value, and
   * the derived id is the narrowest partition there is — one containing a
   * single user.
   *
   * Never throws: a shared-API failure degrades to the derived id.
   */
  async ensureOrganization(userId: string): Promise<string | undefined> {
    // Dedupe concurrent bootstraps for the same user — otherwise parallel tabs
    // for a brand-new user each POST /auth/orgs and create duplicate personal
    // organizations.
    const inFlight = this.organizationBootstrapInFlight.get(userId);
    if (inFlight) return inFlight;

    const bootstrap = this.doEnsureOrganization(userId).finally(() => {
      this.organizationBootstrapInFlight.delete(userId);
    });
    this.organizationBootstrapInFlight.set(userId, bootstrap);
    return bootstrap;
  }

  private async doEnsureOrganization(userId: string): Promise<string | undefined> {
    const sessionCookie = this.userSessionCookies.get(userId);
    if (!sessionCookie) {
      this.logger.debug('ensureOrganization: no cached session cookie for user; deriving a personal org', { userId });
      return this.syntheticOrganizationId(userId);
    }

    try {
      // Check /auth/me first — the session may already carry an organizationId
      // (existing user) or memberOrgIds we can pick from (multi-org user with
      // no active selection).
      const me = await this.fetchMe(sessionCookie);
      if (me?.organizationId) return me.organizationId;
      if (me?.memberOrgIds && me.memberOrgIds.length > 0) return me.memberOrgIds[0];

      // No org anywhere → create a personal org. The shared API auto-switches
      // the session cookie to the new org, but the browser holds the sealed
      // cookie, not us, so we can't update it in-place. Next validated request
      // will observe the new org via /auth/me.
      const orgName = me?.user?.email ? `${me.user.email}'s org` : `Personal (${userId})`;
      const res = await fetch(`${this.sharedApiUrl}/auth/orgs`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: `${COOKIE_NAME}=${sessionCookie}`,
        },
        body: JSON.stringify({ name: orgName }),
      });

      if (!res.ok) {
        this.logger.warn('ensureOrganization: shared API POST /auth/orgs returned non-OK', {
          status: res.status,
          userId,
        });
        return this.syntheticOrganizationId(userId);
      }

      const data = (await res.json()) as { organization?: { id?: string } };
      return data.organization?.id ?? this.syntheticOrganizationId(userId);
    } catch (error) {
      this.logger.error('ensureOrganization: fetch to shared API failed', {
        userId,
        error: error instanceof Error ? { message: error.message, stack: error.stack } : String(error),
      });
      return this.syntheticOrganizationId(userId);
    }
  }

  /**
   * The derived personal organization for a user, or `undefined` when the id
   * names no user.
   *
   * Blank is the case worth stating: `user:` on its own is not one person's
   * organization, it is an organization every user with a broken id would
   * share. `undefined` is the honest answer there, and it is the one
   * `IOrganizationsProvider` already documents for a user who stays no-org.
   */
  private syntheticOrganizationId(userId: string): string | undefined {
    if (typeof userId !== 'string' || userId.trim() === '') return undefined;
    return `${SYNTHETIC_ORGANIZATION_PREFIX}${userId}`;
  }

  /**
   * Whether the user holds an admin-equivalent role in the organization.
   *
   * Derived organizations are decided here and never asked of the shared API,
   * in either direction: a user administers their own personal organization
   * and nobody administers somebody else's. Asking the shared API about an id
   * it has never issued could only produce a wrong answer, and one of the two
   * wrong answers hands a user administrative rights over another user's data.
   *
   * Otherwise: if the org matches the user's currently-active session org, we
   * read the role directly from `/auth/me`. Cross-org path: we call
   * `/auth/orgs` (which returns per-membership roles) and look up the target
   * org. Any shared-API failure resolves to `false`.
   */
  async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {
    if (typeof organizationId === 'string' && organizationId.startsWith(SYNTHETIC_ORGANIZATION_PREFIX)) {
      // `syntheticOrganizationId` answers `undefined` for a blank user id, and
      // `undefined === 'user:...'` is false, so a broken id administers nothing.
      return organizationId === this.syntheticOrganizationId(userId);
    }

    const sessionCookie = this.userSessionCookies.get(userId);
    if (!sessionCookie) return false;

    try {
      const me = await this.fetchMe(sessionCookie);
      if (me?.organizationId === organizationId) {
        return isAdminRole(me.role);
      }

      // Not the active org — fall back to /auth/orgs for the per-org role.
      const res = await fetch(`${this.sharedApiUrl}/auth/orgs`, {
        headers: { Cookie: `${COOKIE_NAME}=${sessionCookie}` },
      });
      if (!res.ok) return false;

      const data = (await res.json()) as {
        organizations?: Array<{ id: string; role?: string | null }>;
      };
      const membership = data.organizations?.find(o => o.id === organizationId);
      return isAdminRole(membership?.role ?? undefined);
    } catch {
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  /**
   * Record the sealed session cookie last seen for a user so
   * {@link ensureOrganization} / {@link isOrganizationAdmin} can act on their
   * behalf. LRU-evicted at {@link maxCachedSessions} entries.
   */
  private rememberUserSession(userId: string, sessionCookie: string): void {
    // Refresh recency by re-inserting.
    this.userSessionCookies.delete(userId);
    this.userSessionCookies.set(userId, sessionCookie);
    if (this.userSessionCookies.size > this.maxCachedSessions) {
      const oldest = this.userSessionCookies.keys().next().value;
      if (oldest !== undefined) this.userSessionCookies.delete(oldest);
    }
  }

  /** Record a locally minted session, evicting the oldest past the bound. */
  private rememberLocalSession(session: Session): void {
    this.localSessions.set(session.id, session);
    if (this.localSessions.size > this.maxLocalSessions) {
      const oldest = this.localSessions.keys().next().value;
      if (oldest !== undefined) this.localSessions.delete(oldest);
    }
  }

  /** A locally minted session, or `null` when there is none or it has expired. */
  private readLocalSession(sessionId: string): Session | null {
    const session = this.localSessions.get(sessionId);
    if (!session) return null;
    if (session.expiresAt.getTime() <= Date.now()) {
      this.localSessions.delete(sessionId);
      return null;
    }
    return session;
  }

  /** Cache key for a verified credential — hash, never the raw secret. */
  private verificationKey(kind: 'cookie' | 'bearer', credential: string): string {
    return createHash('sha256').update(`${kind}:${credential}`).digest('hex');
  }

  private getCachedVerification(key: string): StudioUser | null {
    const entry = this.verifiedCredentials.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= Date.now()) {
      this.verifiedCredentials.delete(key);
      return null;
    }
    return entry.user;
  }

  private cacheVerification(key: string, user: StudioUser): void {
    this.verifiedCredentials.delete(key);
    this.verifiedCredentials.set(key, { user, expiresAt: Date.now() + VERIFY_CACHE_TTL_MS });
    if (this.verifiedCredentials.size > this.maxCachedVerifications) {
      const oldest = this.verifiedCredentials.keys().next().value;
      if (oldest !== undefined) this.verifiedCredentials.delete(oldest);
    }
  }

  /**
   * Fetch the shared API's `/auth/me` and return the raw response body, or
   * `null` on any non-OK / network error. Split out so `ensureOrganization`
   * and `isOrganizationAdmin` can reuse it without duplicating the shape.
   */
  private async fetchMe(sessionCookie: string): Promise<{
    user?: { id?: string; email?: string };
    organizationId?: string;
    role?: string;
    memberOrgIds?: string[];
  } | null> {
    try {
      const res = await fetch(`${this.sharedApiUrl}/auth/me`, {
        headers: { Cookie: `${COOKIE_NAME}=${sessionCookie}` },
        signal: AbortSignal.timeout(VERIFY_FETCH_TIMEOUT_MS),
      });
      if (!res.ok) return null;
      return (await res.json()) as {
        user?: { id?: string; email?: string };
        organizationId?: string;
        role?: string;
        memberOrgIds?: string[];
      };
    } catch {
      return null;
    }
  }

  /**
   * Forward a sealed session cookie to the shared API's /auth/me endpoint
   * to validate it and get user info.
   *
   * @param options.throwOnFailure Surface *why* verification failed instead of
   * answering `null`. Off by default, because the request paths that call this
   * — `authenticateToken`, `getCurrentUser` — are asking a yes/no question on a
   * public endpoint, where a rejection is an ordinary outcome and not an
   * exception. {@link handleCallback} is the caller that needs the reason: it
   * has to throw either way, and a throw with no cause tells its operator
   * nothing.
   */
  private async verifySessionCookie(
    sessionCookie: string,
    options?: { throwOnFailure?: boolean },
  ): Promise<StudioUser | null> {
    const cacheKey = this.verificationKey('cookie', sessionCookie);
    const cached = this.getCachedVerification(cacheKey);
    if (cached) {
      // Keep the userId → cookie mapping warm for IOrganizationsProvider.
      this.rememberUserSession(cached.id, sessionCookie);
      return cached;
    }

    try {
      const res = await fetch(`${this.sharedApiUrl}/auth/me`, {
        headers: {
          Cookie: `${COOKIE_NAME}=${sessionCookie}`,
        },
        signal: AbortSignal.timeout(VERIFY_FETCH_TIMEOUT_MS),
      });

      if (!res.ok) {
        this.logger.warn('verifySessionCookie: shared API returned non-OK status', {
          status: res.status,
          statusText: res.statusText,
          url: `${this.sharedApiUrl}/auth/me`,
        });
        if (options?.throwOnFailure) {
          throw new Error(`Shared API GET /auth/me responded ${res.status} ${res.statusText}`.trim());
        }
        return null;
      }

      const data = (await res.json()) as {
        user: {
          id: string;
          email: string;
          firstName: string;
          lastName: string;
          profilePictureUrl?: string;
        };
        organizationId: string;
        role?: string;
        permissions?: string[];
        memberOrgIds?: string[];
      };

      // Remember the sealed cookie for this user so IOrganizationsProvider
      // methods (invoked with only a userId) can act on the user's behalf.
      this.rememberUserSession(data.user.id, sessionCookie);

      const user: StudioUser = {
        id: data.user.id,
        email: data.user.email,
        name: [data.user.firstName, data.user.lastName].filter(Boolean).join(' ') || undefined,
        avatarUrl: data.user.profilePictureUrl,
        organizationId: data.organizationId,
        role: data.role,
        permissions: data.permissions,
        memberOrgIds: data.memberOrgIds,
      };
      // Don't pin brand-new users in the no-org state: org bootstrap runs on
      // the next request, which must re-read /auth/me to see the new org.
      if (user.organizationId) this.cacheVerification(cacheKey, user);
      return user;
    } catch (error) {
      this.logger.error('verifySessionCookie: fetch to shared API failed', {
        url: `${this.sharedApiUrl}/auth/me`,
        error: error instanceof Error ? { message: error.message, stack: error.stack } : String(error),
      });
      // Rethrown unchanged rather than wrapped, so the caller that asked for
      // the reason gets the transport failure itself and can wrap it as its own
      // `cause`.
      if (options?.throwOnFailure) throw error;
      return null;
    }
  }

  /**
   * Forward a Bearer token to the shared API's /auth/verify endpoint
   * to validate it and get user info (used for CLI tokens).
   */
  private async verifyBearerToken(token: string): Promise<StudioUser | null> {
    const cacheKey = this.verificationKey('bearer', token);
    const cached = this.getCachedVerification(cacheKey);
    if (cached) return cached;

    try {
      const res = await fetch(`${this.sharedApiUrl}/auth/verify`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        signal: AbortSignal.timeout(VERIFY_FETCH_TIMEOUT_MS),
      });

      if (!res.ok) {
        this.logger.warn('verifyBearerToken: shared API returned non-OK status', {
          status: res.status,
          url: `${this.sharedApiUrl}/auth/verify`,
        });
        return null;
      }

      const data = (await res.json()) as {
        user: {
          id: string;
          email: string;
          firstName: string;
          lastName: string;
        };
        organizationId: string;
        role?: string;
        memberOrgIds?: string[];
      };

      const user: StudioUser = {
        id: data.user.id,
        email: data.user.email,
        name: [data.user.firstName, data.user.lastName].filter(Boolean).join(' ') || undefined,
        organizationId: data.organizationId,
        role: data.role,
        memberOrgIds: data.memberOrgIds,
      };
      // Same no-org guard as verifySessionCookie: cache only after the user's
      // organization bootstrap has completed.
      if (user.organizationId) this.cacheVerification(cacheKey, user);
      return user;
    } catch (error) {
      this.logger.error('verifyBearerToken: fetch to shared API failed', {
        url: `${this.sharedApiUrl}/auth/verify`,
        error: error instanceof Error ? { message: error.message, stack: error.stack } : String(error),
      });
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

function parseCookie(cookieHeader: string | null | undefined, name: string): string | null {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`${name}=([^;]+)`));
  return match?.[1] ?? null;
}

/**
 * WorkOS AuthKit conventionally uses `admin` / `owner` for admin-equivalent
 * roles; the shared API surfaces the WorkOS role slug directly on
 * `/auth/me` and `/auth/orgs`.
 */
function isAdminRole(role: string | undefined): boolean {
  return role === 'admin' || role === 'owner';
}

/**
 * Parse a cookie value from a Set-Cookie header.
 * Set-Cookie format: "name=value; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400"
 */
function parseCookieFromHeader(setCookieHeader: string, name: string): string | null {
  // Set-Cookie header starts with "name=value" followed by optional attributes
  const parts = setCookieHeader.split(';');
  if (parts.length === 0) return null;

  const [cookieName, ...valueParts] = parts[0]!.split('=');
  if (cookieName?.trim() !== name) return null;

  // Value could contain = characters, so rejoin
  return valueParts.join('=') || null;
}

// ---------------------------------------------------------------------------
// MastraRBACStudio — role-based permission provider for Studio auth
// ---------------------------------------------------------------------------

export interface MastraRBACStudioOptions {
  /**
   * Mapping from role names to permission arrays.
   *
   * @example
   * ```typescript
   * {
   *   admin: ['*'],
   *   member: ['agents:read', 'workflows:*'],
   *   viewer: ['agents:read', 'workflows:read'],
   *   _default: [],
   * }
   * ```
   */
  roleMapping: RoleMapping;
}

/**
 * RBAC provider for Mastra Studio authentication.
 *
 * Maps user roles (from the shared API's /auth/me endpoint) to Mastra permissions
 * using a configurable role mapping.
 */
export class MastraRBACStudio implements IRBACProvider<StudioUser> {
  private options: MastraRBACStudioOptions;

  get roleMapping(): RoleMapping {
    return this.options.roleMapping;
  }

  constructor(options: MastraRBACStudioOptions) {
    this.options = options;
  }

  async getRoles(user: StudioUser): Promise<string[]> {
    return user.role ? [user.role] : [];
  }

  async hasRole(user: StudioUser, role: string): Promise<boolean> {
    const roles = await this.getRoles(user);
    return roles.includes(role);
  }

  async getPermissions(user: StudioUser): Promise<string[]> {
    const roles = await this.getRoles(user);
    if (roles.length === 0) {
      return this.options.roleMapping['_default'] ?? [];
    }
    return resolvePermissionsFromMapping(roles, this.options.roleMapping);
  }

  async hasPermission(user: StudioUser, permission: string): Promise<boolean> {
    const permissions = await this.getPermissions(user);
    return permissions.some(p => matchesPermission(p, permission));
  }

  async hasAllPermissions(user: StudioUser, permissions: string[]): Promise<boolean> {
    const userPermissions = await this.getPermissions(user);
    return permissions.every(required => userPermissions.some(p => matchesPermission(p, required)));
  }

  async hasAnyPermission(user: StudioUser, permissions: string[]): Promise<boolean> {
    const userPermissions = await this.getPermissions(user);
    return permissions.some(required => userPermissions.some(p => matchesPermission(p, required)));
  }
}
