/**
 * MastraAuthWorkos - WorkOS authentication provider for Mastra.
 *
 * Uses @workos/authkit-session for session management with encrypted
 * cookie-based sessions that persist across server restarts.
 */

import type {
  AuthInitContext,
  IAuthInit,
  IOrganizationsProvider,
  IUserProvider,
  ISSOProvider,
  ISessionProvider,
  Session,
  SSOCallbackResult,
  SSOLoginConfig,
} from '@internal/auth';
import type { EEUser } from '@internal/auth/ee';
import type { MastraAuthProviderOptions } from '@internal/auth/provider';
import { MastraAuthProvider } from '@internal/auth/provider';
import { verifyJwks } from '@mastra/auth';
import type { JwtPayload } from '@mastra/auth';
import { AuthService, sessionEncryption } from '@workos/authkit-session';
import type { AuthKitConfig } from '@workos/authkit-session';
import { WorkOS } from '@workos-inc/node';
import type { OrganizationMembership } from '@workos-inc/node';
import { LRUCache } from 'lru-cache';

type HonoRequestLike = {
  raw?: Request;
  headers?: Headers;
  header(name: string): string | undefined;
};

type MastraAuthRequest = Request | HonoRequestLike;

function getWebRequest(request: MastraAuthRequest): Request | undefined {
  if (request instanceof Request) {
    return request;
  }

  return request.raw instanceof Request ? request.raw : undefined;
}

import { WebSessionStorage } from './session-storage.js';
import type { WorkOSUser, MastraAuthWorkosOptions } from './types.js';
import { mapWorkOSUserToEEUser } from './types.js';

/**
 * What this provider seals into its cookie. AuthKit reads the same shape, so
 * the fields are AuthKit's rather than ours.
 */
interface SealedSession {
  accessToken: string;
  refreshToken: string;
  user?: { id?: string };
  organizationId?: string;
  impersonator?: unknown;
}

/**
 * A session carrying the `Set-Cookie` that puts it in the browser.
 *
 * `getSessionHeaders` takes a bare `Session` by interface and has no way to
 * rebuild a sealed cookie from one, so the members that produce a session
 * attach the cookie they already sealed. The underscore marks it as this
 * provider's own channel between those members, not part of the contract.
 */
type SessionWithCookie = Session & { _sessionCookie?: string | string[] };

/**
 * The access-token claims this provider reads. `sid` is the WorkOS session
 * identifier — the handle `revokeSession` and `getLogoutUrl` both take.
 */
interface AccessTokenClaims {
  sid?: string;
  sub?: string;
  exp?: number;
  iat?: number;
}

/**
 * Decode a JWT's payload without verifying it.
 *
 * Verification is deliberately absent and is not a gap here: every caller
 * reaches this only with a token that came out of a cookie this provider
 * sealed, and unsealing is itself authenticated — a tampered cookie fails to
 * unseal rather than yielding claims to be checked.
 *
 * Base64URL, not Base64. `atob` rejects the `-` and `_` that JWT payloads use
 * in place of `+` and `/`, so decoding one directly throws on any token whose
 * payload happens to contain them — intermittently, depending on the bytes.
 */
function decodeJwtPayload(token: string): AccessTokenClaims | null {
  const payload = token.split('.')[1];
  if (!payload) return null;
  try {
    const base64 = payload.replaceAll('-', '+').replaceAll('_', '/');
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
    const decoded: unknown = JSON.parse(atob(padded));
    return typeof decoded === 'object' && decoded !== null ? (decoded as AccessTokenClaims) : null;
  } catch {
    return null;
  }
}

/** {@link decodeJwtPayload}, named for the one thing every caller wants from it. */
function accessTokenClaims(token: string | undefined): AccessTokenClaims | null {
  return token ? decodeJwtPayload(token) : null;
}

/**
 * Default cookie password for development (MUST be overridden in production).
 * Generated once per process to ensure consistency during dev.
 */
const DEV_COOKIE_PASSWORD = crypto.randomUUID() + crypto.randomUUID(); // 72 chars
const MEMBERSHIP_CACHE_TTL_MS = 60 * 1000;
const MEMBERSHIP_CACHE_MAX_SIZE = 1000;

/** Pull a stable error code out of a WorkOS SDK error, if present. */
function workosErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const e = error as { code?: unknown; rawData?: { code?: unknown } };
  if (typeof e.code === 'string') return e.code;
  if (e.rawData && typeof e.rawData.code === 'string') return e.rawData.code;
  return undefined;
}

/**
 * True when `createOrganization` rejected because an org is already bound to
 * this `externalId` — i.e. a prior bootstrap created the org but never attached
 * the membership. The org can be recovered via `getOrganizationByExternalId`.
 */
function isExternalIdAlreadyUsed(error: unknown): boolean {
  return workosErrorCode(error) === 'external_id_already_used';
}

/**
 * True when `createOrganizationMembership` rejected because the user is already
 * a member of the org. Safe to ignore: the desired end state already holds.
 */
function isMembershipAlreadyExists(error: unknown): boolean {
  const code = workosErrorCode(error);
  return code === 'organization_membership_already_exists' || code === 'entity_already_exists';
}

/**
 * Mastra authentication provider for WorkOS.
 *
 * Uses WorkOS AuthKit with encrypted cookie-based sessions.
 * Sessions are stored in cookies, so they persist across server restarts.
 *
 * @example Basic usage with SSO
 * ```typescript
 * import { MastraAuthWorkos } from '@mastra/auth-workos';
 *
 * const auth = new MastraAuthWorkos({
 *   apiKey: process.env.WORKOS_API_KEY,
 *   clientId: process.env.WORKOS_CLIENT_ID,
 *   redirectUri: 'https://myapp.com/auth/callback',
 *   cookiePassword: process.env.WORKOS_COOKIE_PASSWORD, // min 32 chars
 * });
 * ```
 */
export class MastraAuthWorkos
  extends MastraAuthProvider<WorkOSUser>
  implements IUserProvider<EEUser>, ISSOProvider<EEUser>, ISessionProvider<Session>, IOrganizationsProvider, IAuthInit
{
  protected workos: WorkOS;
  protected clientId: string;
  protected redirectUri: string;
  protected ssoConfig: MastraAuthWorkosOptions['sso'];
  protected authService: AuthService<Request, Response>;
  protected config: AuthKitConfig;
  protected fetchMemberships: boolean;
  protected trustJwtClaims: boolean;
  protected jwtClaimOptions?: MastraAuthWorkosOptions['jwtClaims'];
  protected mapJwtPayloadToUser?: MastraAuthWorkosOptions['mapJwtPayloadToUser'];
  protected membershipCache: LRUCache<string, OrganizationMembership[]>;

  constructor(options?: MastraAuthWorkosOptions) {
    super({ name: options?.name ?? 'workos' });

    const apiKey = options?.apiKey ?? process.env.WORKOS_API_KEY;
    const clientId = options?.clientId ?? process.env.WORKOS_CLIENT_ID;
    // The redirect URI may be resolved later: `init()` derives it from the
    // host's `publicUrl` when neither the option nor the env var is set.
    // `getLoginUrl()` fails with a clear error if it never resolves.
    const redirectUri = options?.redirectUri ?? process.env.WORKOS_REDIRECT_URI ?? '';
    const cookiePassword =
      options?.session?.cookiePassword ?? process.env.WORKOS_COOKIE_PASSWORD ?? DEV_COOKIE_PASSWORD;

    if (!apiKey || !clientId) {
      throw new Error(
        'WorkOS API key and client ID are required. ' +
          'Provide them in the options or set WORKOS_API_KEY and WORKOS_CLIENT_ID environment variables.',
      );
    }

    if (cookiePassword.length < 32) {
      throw new Error(
        'Cookie password must be at least 32 characters. ' +
          'Set WORKOS_COOKIE_PASSWORD environment variable or provide session.cookiePassword option.',
      );
    }

    this.clientId = clientId;
    this.redirectUri = redirectUri;
    this.ssoConfig = options?.sso;
    this.fetchMemberships = options?.fetchMemberships ?? false;
    this.trustJwtClaims = options?.trustJwtClaims ?? false;
    this.jwtClaimOptions = options?.jwtClaims;
    this.mapJwtPayloadToUser = options?.mapJwtPayloadToUser;
    this.membershipCache = new LRUCache<string, OrganizationMembership[]>({
      max: MEMBERSHIP_CACHE_MAX_SIZE,
      ttl: MEMBERSHIP_CACHE_TTL_MS,
    });

    // Create WorkOS client
    this.workos = new WorkOS(apiKey, { clientId });

    // Create AuthKit config
    this.config = {
      clientId,
      apiKey,
      redirectUri,
      cookiePassword,
      cookieName: options?.session?.cookieName ?? 'wos_session',
      cookieMaxAge: options?.session?.maxAge ?? 60 * 60 * 24 * 400, // 400 days
      cookieSameSite: options?.session?.sameSite?.toLowerCase() as 'lax' | 'strict' | 'none' | undefined,
      cookieDomain: undefined,
      apiHttps: true,
    };

    // Create session storage and auth service
    const storage = new WebSessionStorage(this.config);
    // Cast needed: @workos/authkit-session pins @workos-inc/node@8.0.0 but we use 8.8.0.
    // The runtime API is compatible; only private HttpClient types differ.
    this.authService = new AuthService(this.config, storage, this.workos as any, sessionEncryption);

    this.registerOptions(options as MastraAuthProviderOptions<WorkOSUser>);

    if (cookiePassword === DEV_COOKIE_PASSWORD) {
      console.warn(
        '[WorkOS] Using auto-generated cookie password for development. ' +
          'Sessions will not persist across server restarts. ' +
          'Set WORKOS_COOKIE_PASSWORD for persistent sessions.',
      );
    }
  }

  // ============================================================================
  // MastraAuthProvider Implementation
  // ============================================================================

  /**
   * Authenticate a bearer token or session cookie.
   *
   * Uses AuthKit's withAuth() for cookie-based sessions, falls back to
   * JWT verification for bearer tokens.
   */
  async authenticateToken(token: string, request: MastraAuthRequest): Promise<WorkOSUser | null> {
    try {
      // First try session-based auth via AuthKit
      const webRequest = getWebRequest(request);
      const { auth } = webRequest ? await this.authService.withAuth(webRequest) : { auth: { user: null } };

      if (auth.user) {
        // Fetch memberships only when FGA is configured (fetchMemberships: true).
        // Skipping this call avoids an extra network round-trip on every
        // authenticated request when FGA is not in use.
        let memberships: OrganizationMembership[] | undefined;
        if (this.fetchMemberships) {
          try {
            memberships = await this.getMemberships(auth.user.id);
          } catch {
            // Ignore membership fetch errors — FGA will gracefully degrade
          }
        }

        return {
          ...mapWorkOSUserToEEUser(auth.user),
          workosId: auth.user.id,
          organizationId: auth.organizationId,
          memberships,
        };
      }

      // Fall back to JWT verification for bearer tokens
      if (token) {
        const jwksUri = this.workos.userManagement.getJwksUrl(this.clientId);
        const payload = await verifyJwks(token, jwksUri);
        const jwtUser = this.resolveJwtPayloadUser(payload);

        if (this.trustJwtClaims && jwtUser?.id && jwtUser?.workosId) {
          return await this.attachMembershipsIfNeeded(jwtUser);
        }

        if (payload?.sub) {
          try {
            const user = await this.workos.userManagement.getUser(payload.sub);
            let memberships: OrganizationMembership[] | undefined;

            // Fetch memberships only when FGA is configured (fetchMemberships: true).
            if (this.fetchMemberships) {
              try {
                memberships = await this.getMemberships(user.id);
              } catch {
                memberships = undefined;
              }
            }

            return this.mergeJwtPayloadUser(
              {
                ...mapWorkOSUserToEEUser(user),
                workosId: user.id,
                organizationId: this.getSingleMembershipOrganizationId(memberships),
                memberships,
              },
              jwtUser,
              { trustOrganizationClaims: this.trustJwtClaims },
            );
          } catch {
            if (this.trustJwtClaims && jwtUser?.id && jwtUser?.workosId) {
              return await this.attachMembershipsIfNeeded(jwtUser);
            }
            return null;
          }
        }

        if (this.trustJwtClaims && jwtUser?.id && jwtUser?.workosId) {
          return await this.attachMembershipsIfNeeded(jwtUser);
        }
      }

      return null;
    } catch {
      return null;
    }
  }

  /**
   * Authorize a user for access.
   */
  async authorizeUser(user: WorkOSUser): Promise<boolean> {
    return !!user?.id && !!user?.workosId;
  }

  // ============================================================================
  // IUserProvider Implementation
  // ============================================================================

  /**
   * Get the current user from the request using AuthKit session.
   */
  /**
   * Declared as `WorkOSUser`, matching what the body builds and what the
   * sibling `getUser` has always declared. It used to say `EEUser`, which hid
   * `workosId`, `organizationId` and `memberships` from every caller - the
   * fields this provider exists to supply. Widening a return type is safe for
   * callers: `WorkOSUser extends EEUser`, so the class still satisfies
   * `IUserProvider<EEUser>`.
   */
  async getCurrentUser(request: Request): Promise<WorkOSUser | null> {
    try {
      const { auth, refreshedSessionData } = await this.authService.withAuth(request);

      if (!auth.user) {
        return null;
      }

      // Get organizationId from JWT claims, or fall back to fetching from memberships.
      // The fallback fetch is skipped when fetchMemberships is false (FGA not configured)
      // to avoid an extra network call on every authenticated request.
      let organizationId = auth.organizationId;
      let memberships: OrganizationMembership[] | undefined;
      if (this.fetchMemberships) {
        try {
          memberships = await this.getMemberships(auth.user.id);
          organizationId ??= this.getSingleMembershipOrganizationId(memberships);
        } catch {
          // Ignore membership fetch errors
        }
      }

      // Build user with session data
      const user: WorkOSUser = {
        ...mapWorkOSUserToEEUser(auth.user),
        workosId: auth.user.id,
        organizationId,
        memberships,
      };

      // If session was refreshed, attach to user object for caller to save
      if (refreshedSessionData) {
        (user as any)._refreshedSessionData = refreshedSessionData;
      }

      return user;
    } catch {
      return null;
    }
  }

  /**
   * Get a user by their ID.
   */
  async getUser(userId: string): Promise<WorkOSUser | null> {
    try {
      const user = await this.workos.userManagement.getUser(userId);
      return {
        ...mapWorkOSUserToEEUser(user),
        workosId: user.id,
      };
    } catch {
      return null;
    }
  }

  /**
   * Get the URL to the user's profile page.
   */
  getUserProfileUrl(user: EEUser): string {
    return `/profile/${user.id}`;
  }

  private async getMemberships(userId: string): Promise<OrganizationMembership[]> {
    const cached = this.membershipCache.get(userId);
    if (cached) {
      return cached;
    }

    try {
      const response = await this.workos.userManagement.listOrganizationMemberships({
        userId,
      });

      const memberships = await response.autoPagination();
      this.membershipCache.set(userId, memberships);
      return memberships;
    } catch (error) {
      this.membershipCache.delete(userId);
      throw error;
    }
  }

  private async attachMembershipsIfNeeded(user: WorkOSUser): Promise<WorkOSUser> {
    if (!this.fetchMemberships || user.organizationMembershipId) {
      return user;
    }

    try {
      const memberships = await this.getMemberships(user.workosId);
      return {
        ...user,
        organizationId: user.organizationId ?? this.getSingleMembershipOrganizationId(memberships),
        memberships,
      };
    } catch {
      return user;
    }
  }

  private getSingleMembershipOrganizationId(memberships?: OrganizationMembership[]): string | undefined {
    return memberships?.length === 1 ? memberships[0]?.organizationId : undefined;
  }

  private resolveJwtPayloadUser(payload: JwtPayload | null): WorkOSUser | null {
    if (!payload) {
      return null;
    }

    const mappedClaims = this.buildUserFromJwtClaims(payload);
    const customMappedClaims = this.mapJwtPayloadToUser?.(payload) ?? undefined;
    const combined = {
      ...(payload as Record<string, unknown>),
      ...(mappedClaims ?? {}),
      ...(customMappedClaims ?? {}),
    } as Partial<WorkOSUser> & Record<string, unknown>;

    const id = typeof combined.id === 'string' ? combined.id : undefined;
    const workosId = typeof combined.workosId === 'string' ? combined.workosId : id;
    if (!id || !workosId) {
      return null;
    }

    const metadata =
      combined.metadata && typeof combined.metadata === 'object' && !Array.isArray(combined.metadata)
        ? combined.metadata
        : undefined;

    return {
      ...combined,
      id,
      workosId,
      email: typeof combined.email === 'string' ? combined.email : undefined,
      name:
        typeof combined.name === 'string' ? combined.name : typeof combined.email === 'string' ? combined.email : id,
      organizationId: typeof combined.organizationId === 'string' ? combined.organizationId : undefined,
      organizationMembershipId:
        typeof combined.organizationMembershipId === 'string' ? combined.organizationMembershipId : undefined,
      metadata: {
        ...(metadata ?? {}),
        workosId,
        ...(typeof combined.organizationId === 'string' ? { organizationId: combined.organizationId } : {}),
        ...(typeof combined.organizationMembershipId === 'string'
          ? { organizationMembershipId: combined.organizationMembershipId }
          : {}),
      },
    };
  }

  private buildUserFromJwtClaims(payload: JwtPayload): Partial<WorkOSUser> | null {
    const userId = this.readJwtClaim(payload, this.jwtClaimOptions?.userId) ?? this.readJwtClaim(payload, 'sub');
    const workosId = this.readJwtClaim(payload, this.jwtClaimOptions?.workosId) ?? userId;

    if (!userId || !workosId) {
      return null;
    }

    return {
      id: userId,
      workosId,
      email: this.readJwtClaim(payload, this.jwtClaimOptions?.email) ?? this.readJwtClaim(payload, 'email'),
      name: this.readJwtClaim(payload, this.jwtClaimOptions?.name) ?? this.readJwtClaim(payload, 'name'),
      organizationId:
        this.readJwtClaim(payload, this.jwtClaimOptions?.organizationId) ?? this.readJwtClaim(payload, 'org_id'),
      organizationMembershipId: this.readJwtClaim(payload, this.jwtClaimOptions?.organizationMembershipId),
    };
  }

  private mergeJwtPayloadUser(
    user: WorkOSUser,
    jwtUser: WorkOSUser | null,
    options?: { trustOrganizationClaims?: boolean },
  ): WorkOSUser {
    if (!jwtUser) {
      return user;
    }

    const trustOrganizationClaims = options?.trustOrganizationClaims ?? true;
    const jwtMetadata = { ...(jwtUser.metadata ?? {}) };
    if (!trustOrganizationClaims) {
      delete jwtMetadata.organizationId;
      delete jwtMetadata.organizationMembershipId;
    }

    return {
      ...jwtUser,
      ...user,
      organizationId: trustOrganizationClaims ? (jwtUser.organizationId ?? user.organizationId) : user.organizationId,
      organizationMembershipId: trustOrganizationClaims
        ? (jwtUser.organizationMembershipId ?? user.organizationMembershipId)
        : user.organizationMembershipId,
      memberships: trustOrganizationClaims ? (user.memberships ?? jwtUser.memberships) : user.memberships,
      metadata: {
        ...jwtMetadata,
        ...(user.metadata ?? {}),
      },
    };
  }

  private readJwtClaim(payload: JwtPayload, claimPath?: string): string | undefined {
    if (!claimPath) {
      return undefined;
    }

    let current: unknown = payload;
    for (const segment of claimPath.split('.')) {
      if (!current || typeof current !== 'object' || !(segment in current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[segment];
    }

    return typeof current === 'string' ? current : undefined;
  }

  // ============================================================================
  // ISSOProvider Implementation
  // ============================================================================

  /**
   * Get the URL to redirect users to for SSO login.
   */
  getLoginUrl(redirectUri: string, state: string): string {
    const resolvedRedirectUri = redirectUri || this.redirectUri;
    if (!resolvedRedirectUri) {
      throw new Error(
        'WorkOS redirect URI is required. ' +
          'Provide it in the options, set the WORKOS_REDIRECT_URI environment variable, or call init() with a publicUrl.',
      );
    }

    const baseOptions = {
      clientId: this.clientId,
      redirectUri: resolvedRedirectUri,
      state,
    };

    if (this.ssoConfig?.connection) {
      return this.workos.userManagement.getAuthorizationUrl({
        ...baseOptions,
        connectionId: this.ssoConfig.connection,
      });
    } else if (this.ssoConfig?.provider) {
      return this.workos.userManagement.getAuthorizationUrl({
        ...baseOptions,
        provider: this.ssoConfig.provider,
      });
    } else if (this.ssoConfig?.defaultOrganization) {
      return this.workos.userManagement.getAuthorizationUrl({
        ...baseOptions,
        organizationId: this.ssoConfig.defaultOrganization,
      });
    }

    return this.workos.userManagement.getAuthorizationUrl({
      ...baseOptions,
      provider: 'authkit',
    });
  }

  /**
   * Handle the OAuth callback from WorkOS.
   *
   * Uses WorkOS SDK's authenticateWithCode directly instead of AuthKit's handleCallback.
   * AuthKit's handleCallback requires PKCE cookies that must be set during getLoginUrl()
   * and read during handleCallback(), but our ISSOProvider interface separates these
   * calls across different requests without cookie propagation.
   *
   * This approach was the original implementation before commit 6e4d4f5cf3 introduced
   * a regression by switching to AuthKit's handleCallback with dummy Request/Response
   * objects that couldn't provide the required PKCE cookies.
   */
  async handleCallback(code: string, _state: string): Promise<SSOCallbackResult<EEUser>> {
    // Use WorkOS SDK directly to exchange code for tokens (server-side, no PKCE required)
    const authResponse = await this.workos.userManagement.authenticateWithCode({
      clientId: this.clientId,
      code,
    });

    const user: WorkOSUser = {
      ...mapWorkOSUserToEEUser(authResponse.user),
      workosId: authResponse.user.id,
      organizationId: authResponse.organizationId,
    };

    // Create encrypted session cookie using AuthKit's encryption
    const sessionData = {
      accessToken: authResponse.accessToken,
      refreshToken: authResponse.refreshToken,
      user: authResponse.user,
      organizationId: authResponse.organizationId,
      impersonator: authResponse.impersonator,
    };

    const sealed = await this.sealSessionCookie(sessionData);
    const cookies = sealed ? [sealed.setCookie] : undefined;

    return {
      user,
      tokens: {
        accessToken: authResponse.accessToken,
        refreshToken: authResponse.refreshToken,
      },
      cookies,
    };
  }

  /**
   * Get the URL to redirect users to for logout.
   * Extracts session ID from the request's JWT to build a valid WorkOS logout URL.
   *
   * @param redirectUri - URL to redirect to after logout
   * @param request - Request containing session cookie (needed to extract sid)
   * @returns Logout URL or null if no active session
   */
  async getLogoutUrl(redirectUri: string, request?: Request): Promise<string | null> {
    // WorkOS logout requires session_id from the JWT's sid claim
    if (!request) {
      return null;
    }

    try {
      const { auth } = await this.authService.withAuth(request);

      // No active session
      if (!auth.user) {
        return null;
      }

      const sessionId = accessTokenClaims(auth.accessToken)?.sid;
      if (!sessionId) {
        return null;
      }

      return this.workos.userManagement.getLogoutUrl({ sessionId, returnTo: redirectUri });
    } catch {
      return null;
    }
  }

  /**
   * Get the configuration for rendering the login button.
   */
  getLoginButtonConfig(): SSOLoginConfig {
    let text = 'Sign in';
    if (this.ssoConfig?.provider) {
      const providerNames: Record<string, string> = {
        GoogleOAuth: 'Google',
        MicrosoftOAuth: 'Microsoft',
        GitHubOAuth: 'GitHub',
        AppleOAuth: 'Apple',
      };
      const providerName = providerNames[this.ssoConfig.provider];
      if (providerName) {
        text = `Sign in with ${providerName}`;
      }
    }

    return {
      provider: 'workos',
      text,
    };
  }

  // ============================================================================
  // ISessionProvider Implementation
  // ============================================================================
  //
  // THE SESSION ID IS THE SEALED COOKIE.
  //
  // A WorkOS session lives in an encrypted cookie, not in a table this provider
  // can query, so there is no server-side row to address by id. The sealed
  // cookie value is the only handle that identifies a session to this provider
  // and is opaque to the host holding it — the same choice `@mastra/auth-studio`
  // makes for the same reason.
  //
  // It follows that the id is a credential, not an identifier. Do not log it,
  // put it in a URL, or store it anywhere the cookie itself would not go.
  //
  // Five of the six members below are backed by AuthKit. `createSession` is the
  // one that cannot be: see its comment.

  /**
   * Seal a session into the `Set-Cookie` this provider sets, and hand back the
   * sealed value alongside it.
   *
   * One place, because `handleCallback` and `refreshSession` must produce
   * byte-identical cookie attributes — a refresh that widened `SameSite` or
   * dropped `Secure` would quietly downgrade a session mid-flight.
   */
  private async sealSessionCookie(session: SealedSession): Promise<{ sealed: string; setCookie: string } | undefined> {
    const cookiePassword = this.config.cookiePassword;
    if (!cookiePassword) return undefined;

    const sealed = await sessionEncryption.sealData(session, { password: cookiePassword });
    const setCookie = [
      `${this.config.cookieName ?? 'wos_session'}=${sealed}`,
      'Path=/',
      'HttpOnly',
      `SameSite=${this.config.cookieSameSite ?? 'Lax'}`,
      process.env['NODE_ENV'] === 'production' ? 'Secure' : '',
    ]
      .filter(Boolean)
      .join('; ');

    return { sealed, setCookie };
  }

  /** Open a sealed cookie, or `null` if it was tampered with, stale, or not ours. */
  private async unsealSession(sealed: string): Promise<SealedSession | null> {
    const cookiePassword = this.config.cookiePassword;
    if (!cookiePassword || !sealed) return null;
    try {
      const session = await sessionEncryption.unsealData<SealedSession>(sealed, { password: cookiePassword });
      return typeof session?.accessToken === 'string' ? session : null;
    } catch {
      // Wrong password, a cookie from another deployment, or a forgery.
      return null;
    }
  }

  /** Build the host-facing session record for an already-unsealed cookie. */
  private toSession(sealed: string, session: SealedSession): Session | null {
    const claims = accessTokenClaims(session.accessToken);
    const userId = session.user?.id ?? claims?.sub;
    if (!userId) return null;

    const issuedAt = claims?.iat ? new Date(claims.iat * 1000) : new Date();
    const expiresAt = claims?.exp
      ? new Date(claims.exp * 1000)
      : new Date(Date.now() + this.config.cookieMaxAge * 1000);

    return {
      id: sealed,
      userId,
      createdAt: issuedAt,
      expiresAt,
      metadata: { workosSessionId: claims?.sid, organizationId: session.organizationId },
    };
  }

  /**
   * Create a new session for a user.
   *
   * THIS CANNOT BE IMPLEMENTED, and returns a record nothing will accept.
   *
   * A WorkOS session is produced by an authenticated token exchange — a real
   * credential presented by a real person — and `@workos-inc/node` offers no
   * call that mints one from a user id alone. Backing this with an in-memory map
   * would satisfy a round-trip test while revoking nothing and leaving the
   * browser's sealed cookie working, which is worse than saying so.
   *
   * No host path reaches it: both this repository's hosts branch on the cookies
   * `handleCallback` returns before they consider `createSession`. It is kept so
   * that removing it is a deliberate major bump rather than a side effect, and
   * it is why `sessions/round-trip` is still a recorded conformance failure.
   */
  async createSession(userId: string, metadata?: Record<string, unknown>): Promise<Session> {
    const now = new Date();
    return {
      id: crypto.randomUUID(),
      userId,
      createdAt: now,
      expiresAt: new Date(now.getTime() + this.config.cookieMaxAge * 1000),
      metadata,
    };
  }

  /**
   * Validate a session.
   *
   * Unsealing is the authentication: the cookie is sealed with a password only
   * this deployment holds, so a value that opens is a value this provider
   * issued. What is left to check is time, and an expired access token is
   * refused here rather than passed on as valid — `refreshSession` is the way
   * back from that, and the host calls it on exactly this answer.
   */
  async validateSession(sessionId: string): Promise<Session | null> {
    const sealed = await this.unsealSession(sessionId);
    if (!sealed) return null;

    const claims = accessTokenClaims(sealed.accessToken);
    if (claims?.exp && claims.exp * 1000 <= Date.now()) return null;

    return this.toSession(sessionId, sealed);
  }

  /**
   * Destroy a session — really, at WorkOS, not just in this browser.
   *
   * This is what makes `features.sessionRevocation` true in fact. The access
   * token carries the WorkOS session id as its `sid` claim, which is the handle
   * `revokeSession` takes; `getLogoutUrl` reads the same claim for the same
   * reason.
   *
   * Best-effort by design, matching what the hosts expect: they clear the
   * browser's cookies whether or not this succeeds, and a sign-out that fails
   * because a session had already expired is a sign-out that worked.
   */
  async destroySession(sessionId: string): Promise<void> {
    const sealed = await this.unsealSession(sessionId);
    const workosSessionId = accessTokenClaims(sealed?.accessToken)?.sid;
    if (!workosSessionId) return;

    try {
      await this.workos.userManagement.revokeSession({ sessionId: workosSessionId });
    } catch {
      // Already revoked, expired, or unreachable. The cookie still gets cleared.
    }
  }

  /**
   * Refresh a session, returning one whose id is the NEW sealed cookie.
   *
   * The new value has to travel back to the browser or the refresh is a no-op
   * with extra steps, and the route it travels is `getSessionHeaders(session)`,
   * which the host calls on whatever this returns. So the returned record
   * carries the sealed cookie for that member to emit.
   */
  async refreshSession(sessionId: string): Promise<Session | null> {
    const current = await this.unsealSession(sessionId);
    if (!current?.refreshToken) return null;

    try {
      const refreshed = await this.workos.userManagement.authenticateWithRefreshToken({
        clientId: this.clientId,
        refreshToken: current.refreshToken,
        organizationId: current.organizationId,
      });

      const next: SealedSession = {
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken,
        user: refreshed.user,
        organizationId: refreshed.organizationId,
        impersonator: refreshed.impersonator,
      };

      const cookie = await this.sealSessionCookie(next);
      if (!cookie) return null;

      const session = this.toSession(cookie.sealed, next);
      if (!session) return null;

      const refreshedSession: SessionWithCookie = { ...session, _sessionCookie: cookie.setCookie };
      return refreshedSession;
    } catch {
      // An expired or already-used refresh token. The caller treats a null as
      // the original 401, which is the right answer.
      return null;
    }
  }

  /**
   * Extract session ID from a request — the sealed cookie value, per the note
   * at the top of this section.
   *
   * Synchronous by interface, which is the other reason the sealed cookie is
   * the id: deriving anything finer means unsealing, and unsealing is async.
   */
  getSessionIdFromRequest(request: Request): string | null {
    const header = request.headers?.get('Cookie');
    if (!header) return null;

    const name = this.config.cookieName ?? 'wos_session';
    for (const part of header.split(';')) {
      const separator = part.indexOf('=');
      if (separator === -1) continue;
      if (part.slice(0, separator).trim() !== name) continue;
      const value = part.slice(separator + 1).trim();
      return value.length > 0 ? value : null;
    }
    return null;
  }

  /**
   * Get response headers to set the session cookie.
   *
   * Only a session this provider built carries a cookie to set —
   * `handleCallback` and `refreshSession` both attach one. A session from
   * anywhere else (including `createSession`) has none, and gets no headers
   * rather than a cookie that would not authenticate.
   */
  getSessionHeaders(session: Session): Record<string, string> {
    const sessionCookie = (session as SessionWithCookie)._sessionCookie;
    if (!sessionCookie) return {};
    const value = Array.isArray(sessionCookie) ? sessionCookie[0] : sessionCookie;
    return value ? { 'Set-Cookie': value } : {};
  }

  /**
   * Get response headers to clear the session cookie.
   */
  getClearSessionHeaders(): Record<string, string> {
    const cookieParts = [`${this.config.cookieName}=`, 'Path=/', 'Max-Age=0', 'HttpOnly'];
    return { 'Set-Cookie': cookieParts.join('; ') };
  }

  // ============================================================================
  // IAuthInit Implementation
  // ============================================================================

  /**
   * One-time host initialization. Resolves the redirect URI from the host's
   * `publicUrl` (`<publicUrl>/auth/callback`) when it was not provided in the
   * options or via `WORKOS_REDIRECT_URI`.
   *
   * Fails at prepare time rather than handing WorkOS an empty redirect URI on
   * the first login (which breaks hosted login with an opaque provider error).
   */
  async init(ctx: AuthInitContext): Promise<void> {
    if (!this.redirectUri && ctx.publicUrl) {
      this.redirectUri = `${ctx.publicUrl}/auth/callback`;
      this.config.redirectUri = this.redirectUri;
      // Rebuild the session storage/auth service so they observe the resolved
      // redirect URI rather than the empty placeholder from construction.
      const storage = new WebSessionStorage(this.config);
      this.authService = new AuthService(this.config, storage, this.workos as any, sessionEncryption);
    }
    if (!this.redirectUri) {
      throw new Error(
        'MastraAuthWorkos could not resolve a callback URL: pass `redirectUri` (WORKOS_REDIRECT_URI) or configure the host `publicUrl`.',
      );
    }
  }

  // ============================================================================
  // IOrganizationsProvider Implementation
  // ============================================================================

  /**
   * Ensure the user belongs to a WorkOS organization, creating a personal org
   * on first use when they have none.
   *
   * - ≥1 membership → return the first org id (they already belong somewhere;
   *   we never auto-create when a membership exists).
   * - 0 memberships → create a personal org + membership and return its id.
   *
   * Idempotency: the create call carries `externalId = userId` and a stable
   * `idempotencyKey`, so concurrent/retried first logins never create duplicate
   * personal orgs. If a prior run created the org but never attached the
   * membership, the create rejects with `external_id_already_used`; we recover
   * the existing org by `externalId` and (re)attach the membership instead of
   * failing.
   *
   * Best-effort: any WorkOS error (e.g. API key lacking org-create permission)
   * is swallowed and returns `undefined`, leaving the user in their no-org
   * state rather than failing the request.
   */
  async ensureOrganization(userId: string): Promise<string | undefined> {
    try {
      const memberships = await this.workos.userManagement
        .listOrganizationMemberships({ userId })
        .then(page => page.autoPagination());

      const firstExisting = memberships.find(m => m.organizationId)?.organizationId;
      if (firstExisting) return firstExisting;

      // Build a predictable personal-org name from the user's profile.
      const profile = await this.workos.userManagement.getUser(userId).catch(() => null);
      const label = profile?.email ?? userId;

      // Create the personal org. A prior partial bootstrap (org created, but
      // the membership step never landed) leaves an org already bound to this
      // externalId, so the create 400s with `external_id_already_used`.
      // Recover by looking the existing org up by externalId instead of
      // dead-ending forever.
      let organizationId: string;
      try {
        const organization = await this.workos.organizations.createOrganization(
          {
            name: `${label}'s org`,
            externalId: userId,
            metadata: { mastraPersonalOrg: 'true', workosUserId: userId },
          },
          { idempotencyKey: `mastra-personal-org:${userId}` },
        );
        organizationId = organization.id;
      } catch (error) {
        if (!isExternalIdAlreadyUsed(error)) throw error;
        const existing = await this.workos.organizations.getOrganizationByExternalId(userId);
        organizationId = existing.id;
      }

      // Idempotently attach the user. If they are already a member (e.g. the
      // org existed from a prior run), tolerate the conflict and keep the org id.
      try {
        await this.workos.userManagement.createOrganizationMembership({ organizationId, userId });
      } catch (error) {
        if (!isMembershipAlreadyExists(error)) throw error;
      }

      // Drop any cached (empty) membership list so the next authenticated
      // request observes the new membership immediately.
      this.membershipCache.delete(userId);

      return organizationId;
    } catch (error) {
      console.warn(
        `[WorkOS] Failed to bootstrap personal organization for user ${userId}. ` +
          'The user will see organization_required until this succeeds. ' +
          'Ensure the WorkOS API key can create organizations/memberships.',
        error,
      );
      return undefined;
    }
  }

  /**
   * Whether the user holds an admin-equivalent role (`admin` or `owner`) in
   * the organization. Provider errors resolve to `false`.
   */
  async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {
    try {
      const memberships = await this.workos.userManagement
        .listOrganizationMemberships({ userId })
        .then(page => page.autoPagination());
      const membership = memberships.find(item => item.organizationId === organizationId);
      if (!membership) return false;
      // Multi-role environments report assigned roles in `roles`; single-role
      // environments only populate the legacy `role` field.
      const slugs = membership.roles?.length ? membership.roles.map(role => role.slug) : [membership.role.slug];
      return slugs.some(slug => slug === 'admin' || slug === 'owner');
    } catch {
      return false;
    }
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  /**
   * Get the underlying WorkOS client.
   */
  getWorkOS(): WorkOS {
    return this.workos;
  }

  /**
   * Get the AuthKit AuthService.
   */
  getAuthService(): AuthService<Request, Response> {
    return this.authService;
  }

  /**
   * Get the configured client ID.
   */
  getClientId(): string {
    return this.clientId;
  }

  /**
   * Get the configured redirect URI.
   */
  getRedirectUri(): string {
    return this.redirectUri;
  }
}
