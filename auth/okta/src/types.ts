/**
 * Shared types for Okta integration.
 */

import type { EEUser, RoleMapping } from '@internal/auth/ee';
import type { MastraAuthProviderOptions } from '@internal/auth/provider';
import type { JWTPayload } from 'jose';

// ============================================================================
// User Types
// ============================================================================

/**
 * Extended EEUser with Okta-specific fields.
 */
export interface OktaUser extends EEUser {
  /** Okta user ID */
  oktaId: string;
  /** User's Okta groups (if fetched) */
  groups?: string[];
}

/**
 * Maps Okta JWT claims to OktaUser format.
 *
 * @param payload - JWT payload from Okta token
 * @returns OktaUser object
 */
export function mapOktaClaimsToUser(payload: JWTPayload): OktaUser {
  return {
    id: (payload.sub as string) || (payload.uid as string) || '',
    oktaId: (payload.sub as string) || (payload.uid as string) || '',
    email: payload.email as string | undefined,
    name:
      (payload.name as string) ||
      [payload.given_name, payload.family_name].filter(Boolean).join(' ') ||
      (payload.email as string) ||
      undefined,
    avatarUrl: payload.picture as string | undefined,
    groups: payload.groups as string[] | undefined,
    metadata: {
      oktaId: payload.sub,
      emailVerified: payload.email_verified,
      updatedAt: payload.updated_at,
    },
  };
}

// ============================================================================
// Auth Provider Options
// ============================================================================

/**
 * Session configuration options for MastraAuthOkta.
 */
export interface OktaSessionOptions {
  /** Cookie name (default: 'okta_session') */
  cookieName?: string;
  /** Cookie max age in seconds (default: 86400 = 24 hours) */
  cookieMaxAge?: number;
  /**
   * Password for encrypting session cookies.
   * Must be at least 32 characters.
   * Defaults to OKTA_COOKIE_PASSWORD env var.
   */
  cookiePassword?: string;
  /**
   * Set the Secure flag on session cookies.
   * Defaults to true when NODE_ENV=production, false otherwise.
   */
  secureCookies?: boolean;
}

/**
 * Options for MastraAuthOkta.
 *
 * Extends `MastraAuthProviderOptions` for the same reason `MastraAuthWorkos`
 * does: the constructor hands this object to `registerOptions`, which binds
 * `authorizeUser`, `mapUserToResourceId`, `protected` and `public`. No test
 * exercised those here, so unlike WorkOS the gap produced no error and was
 * found only by comparison.
 */
export interface MastraAuthOktaOptions extends MastraAuthProviderOptions<OktaUser> {
  /** Okta domain (e.g., 'dev-123456.okta.com'). Defaults to OKTA_DOMAIN env var. */
  domain?: string;
  /** Okta OAuth client ID. Defaults to OKTA_CLIENT_ID env var. */
  clientId?: string;
  /** Okta OAuth client secret. Defaults to OKTA_CLIENT_SECRET env var. Required for SSO. */
  clientSecret?: string;
  /**
   * Token issuer URL.
   * Defaults to OKTA_ISSUER env var or `https://{domain}/oauth2/default`.
   */
  issuer?: string;
  /**
   * OAuth redirect URI for SSO callback.
   * Defaults to OKTA_REDIRECT_URI env var.
   */
  redirectUri?: string;
  /**
   * Expected `aud` claim when verifying bearer tokens.
   * Defaults to OKTA_AUDIENCE env var, then to the client ID (the ID-token audience).
   *
   * Set this to accept Okta access tokens:
   * - org authorization server: `https://{domain}`
   * - custom authorization server: the configured audience, e.g. `api://default`
   *
   * Pass an array to accept more than one, e.g. ID tokens from the browser and
   * access tokens from service callers against the same provider.
   */
  audience?: string | string[];
  /**
   * OAuth scopes to request.
   * Default: ['openid', 'profile', 'email', 'groups']
   */
  scopes?: string[];
  /**
   * Okta API token for user lookups via the Users API.
   * Required for getUser() to return user data by ID.
   * Defaults to OKTA_API_TOKEN env var.
   */
  apiToken?: string;
  /** Session configuration */
  session?: OktaSessionOptions;
  /** Custom provider name (default: 'okta') */
  name?: string;
}

// ============================================================================
// RBAC Provider Options
// ============================================================================

/**
 * Cache configuration options for RBAC permission caching.
 */
export interface PermissionCacheOptions {
  /** Maximum number of users to cache (default: 1000) */
  maxSize?: number;
  /** Time-to-live in milliseconds (default: 60000) */
  ttlMs?: number;
}

/**
 * Options for MastraRBACOkta.
 *
 * `TUser` is the user shape the surrounding host authenticates. It defaults to
 * {@link OktaUser}, so `new MastraRBACOkta({ ... })` needs no type argument.
 * Name it when Okta supplies only the groups and a different provider supplies
 * the user, which is the cross-provider case {@link MastraRBACOktaOptions.getUserId}
 * exists for.
 */
export interface MastraRBACOktaOptions<TUser extends EEUser = OktaUser> {
  /** Okta domain (e.g., 'dev-123456.okta.com'). Defaults to OKTA_DOMAIN env var. */
  domain?: string;

  /** Okta API token for management SDK. Defaults to OKTA_API_TOKEN env var. */
  apiToken?: string;

  /**
   * Map Okta groups to Mastra permissions.
   *
   * @example
   * ```typescript
   * roleMapping: {
   *   'Engineering': ['agents:*', 'workflows:*'],
   *   'Admin': ['*'],
   *   'Viewer': ['agents:read', 'workflows:read'],
   *   '_default': [],
   * }
   * ```
   */
  roleMapping: RoleMapping;

  /**
   * Extract the Okta user ID from the authenticated user.
   * Use this when a different auth provider (e.g. Auth0) supplies the user and
   * Okta supplies only the groups.
   *
   * The parameter is `TUser`, not `unknown`. Typing it `unknown` meant every
   * caller — including this package's own JSDoc example and its own test — had
   * to cast before reading a field, which is the opposite of what a typed
   * option is for.
   *
   * @example
   * ```typescript
   * // Default TUser, so the parameter is an OktaUser.
   * getUserId: user => user.oktaId
   * ```
   *
   * @example
   * ```typescript
   * // Cross-provider: name the shape the other provider produces.
   * interface Auth0User extends EEUser {
   *   metadata?: { oktaUserId?: string };
   * }
   *
   * new MastraRBACOkta<Auth0User>({
   *   getUserId: user => user.metadata?.oktaUserId ?? user.email,
   *   roleMapping: { Admin: ['*'] },
   * });
   * ```
   */
  getUserId?: (user: TUser) => string | undefined;

  /** Permission cache configuration */
  cache?: PermissionCacheOptions;
}
