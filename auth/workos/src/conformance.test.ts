/**
 * The Factory auth conformance suite, run against this provider.
 *
 * Everything here is offline: no network, no WorkOS tenant, no environment
 * variables. Two seams are replaced, and only two, both of them the places this
 * provider would otherwise leave the process:
 *
 * 1. **The JWKS verifier.** `authenticateToken` verifies a bearer token with
 *    `verifyJwks` from `@mastra/auth`, which fetches the issuer's key set. The
 *    module is mocked so that one function resolves a payload for
 *    {@link TOKEN} and throws for anything else — the same "inject your
 *    verifier" step `src/index.test.ts` already takes.
 * 2. **The WorkOS REST calls.** The SDK client is real; the handful of methods
 *    that would issue HTTP requests are backed by {@link createWorkOSStore}, an
 *    in-memory WorkOS with one user, no memberships, and no organizations. The
 *    two methods conformance actually reads for correctness —
 *    `getAuthorizationUrl` and `getJwksUrl` — are pure and are left alone, so
 *    the `state` obligation is checked against the real SDK's URL building.
 *
 * `AuthService.withAuth` is likewise replaced with a stand-in that keeps the
 * real cookie reading (`WebSessionStorage`) and the real iron-webcrypto
 * unsealing, and drops only the remote-JWKS validate-and-refresh step in the
 * middle. So obligation 2 exercises this package's own cookie path end to end.
 *
 * A fresh provider and a fresh store per `createProvider()` call, because the
 * suite builds one provider per check and `ensureOrganization` writes.
 *
 * WHAT IS RED TODAY, AND WHY IT IS RECORDED RATHER THAN FIXED OR HIDDEN
 *
 * One check fails — `sessions/round-trip`, under
 * `sessions/round-trip#validate-rejects-fresh-session`. It is a finding about
 * the provider rather than about this file, so it is recorded in
 * `knownFailures` below: the suite goes green and says on every run that it is
 * not the green of a clean provider.
 *
 * `MastraAuthWorkos` declares `ISessionProvider` and implements all seven of
 * its members as no-ops: `validateSession` returns `null` unconditionally,
 * `refreshSession` returns `null`, `getSessionIdFromRequest` returns `null`,
 * and `destroySession` does nothing (see the "kept for interface
 * compatibility" comments in `./auth-provider`). AuthKit really does keep the
 * session in an encrypted cookie, so there is nothing server-side to look up —
 * but `isSessionProvider` tests only `createSession` and `validateSession` for
 * existence, so the guard reports a capability the provider does not have.
 * Everything downstream believes it: `toAuthDescriptor` reports
 * `features.sessionRevocation: true` on the strength of `destroySession`
 * existing, and a UI will offer "sign out everywhere" on a provider that
 * cannot revoke anything. The defect is the declaration, not the design.
 *
 * Both ways out are provider decisions rather than test ones — give the
 * provider a real session store, or stop declaring `ISessionProvider`, which
 * is a breaking change to a published package — so neither is taken here.
 */
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import type { AuthService } from '@workos/authkit-session';
import { sessionEncryption } from '@workos/authkit-session';
import type { Organization, OrganizationMembership, User } from '@workos-inc/node';
import { vi } from 'vitest';

import { MastraAuthWorkos, WebSessionStorage } from './index';

/**
 * Hoisted so the `@mastra/auth` mock factory below — which vitest lifts above
 * every import in this file — can read them without a temporal dead zone.
 */
const fixtures = vi.hoisted(() => ({
  /** The bearer token the injected verifier accepts. Nothing else is signed. */
  TOKEN: 'conformance-workos-access-token',
  USER_ID: 'user_01CONFORMANCE',
  EMAIL: 'conformance@example.test',
}));

const { TOKEN, USER_ID, EMAIL } = fixtures;

/**
 * The offline stand-in for the WorkOS JWKS verification.
 *
 * `verifyJwks` is the one network call on the bearer path, and it is reached
 * through a module import rather than through an injectable seam, so replacing
 * it means replacing the module. Everything else `@mastra/auth` exports is
 * passed through untouched.
 */
vi.mock('@mastra/auth', async importActual => {
  const actual = await importActual<typeof import('@mastra/auth')>();
  return {
    ...actual,
    verifyJwks: async (accessToken: string) => {
      if (accessToken !== fixtures.TOKEN) {
        // What a real `jwt.verify` does for a token it cannot validate. The
        // provider is expected to catch this and resolve null.
        throw new Error('invalid signature');
      }
      return { sub: fixtures.USER_ID, email: fixtures.EMAIL, iss: 'https://api.workos.com' };
    },
  };
});

const CLIENT_ID = 'client_01CONFORMANCE';
const API_KEY = 'sk_test_conformance';
const REDIRECT_URI = 'https://conformance.test/auth/callback';
const COOKIE_NAME = 'wos_session';
/** Never leaves this file. AuthKit rejects anything shorter than 32 characters. */
const COOKIE_PASSWORD = 'conformance-cookie-password-at-least-32-chars';

const NOW = '2024-01-01T00:00:00.000Z';

function conformanceUser(): User {
  return {
    object: 'user',
    id: USER_ID,
    email: EMAIL,
    emailVerified: true,
    profilePictureUrl: null,
    firstName: 'Conformance',
    lastName: 'User',
    lastSignInAt: null,
    locale: null,
    createdAt: NOW,
    updatedAt: NOW,
    externalId: null,
    metadata: {},
  };
}

// ============================================================================
// The in-memory WorkOS
// ============================================================================

/** A stable, obviously-fake code that {@link createWorkOSStore} exchanges. */
const AUTHORIZATION_CODE = 'conformance-authorization-code';

interface WorkOSStore {
  readonly users: Map<string, User>;
  readonly organizations: Map<string, Organization>;
  readonly memberships: OrganizationMembership[];
  nextId: number;
}

/** A WorkOS account with one user, no organization, and no membership. */
function createWorkOSStore(): WorkOSStore {
  return {
    users: new Map([[USER_ID, conformanceUser()]]),
    organizations: new Map(),
    memberships: [],
    nextId: 1,
  };
}

/** The shape the WorkOS SDK's list endpoints return before `autoPagination()`. */
function page<T>(items: readonly T[]): { autoPagination: () => Promise<T[]> } {
  return { autoPagination: async () => [...items] };
}

/** A WorkOS SDK error carrying the `code` this provider branches on. */
function workosError(code: string, message: string): Error & { code: string } {
  return Object.assign(new Error(message), { code });
}

/**
 * Point the SDK's network-backed methods at `store`.
 *
 * Only the methods this provider calls over HTTP are replaced. `userManagement`
 * and `organizations` are plain instance properties on the SDK client, so the
 * client itself, its URL builders and its serializers stay real.
 */
function installOfflineWorkOS(provider: MastraAuthWorkos, store: WorkOSStore): void {
  const workos = provider.getWorkOS();
  const userManagement = workos.userManagement as unknown as Record<string, unknown>;
  const organizations = workos.organizations as unknown as Record<string, unknown>;

  userManagement.getUser = async (userId: string): Promise<User> => {
    const user = store.users.get(userId);
    if (!user) throw workosError('entity_not_found', `No user with id ${userId}.`);
    return user;
  };

  userManagement.listOrganizationMemberships = async ({ userId }: { userId?: string }) =>
    page(store.memberships.filter(membership => membership.userId === userId));

  userManagement.createOrganizationMembership = async ({
    organizationId,
    userId,
  }: {
    organizationId: string;
    userId: string;
  }): Promise<OrganizationMembership> => {
    const existing = store.memberships.find(m => m.organizationId === organizationId && m.userId === userId);
    if (existing) {
      throw workosError('organization_membership_already_exists', 'The user already belongs to this organization.');
    }
    const membership: OrganizationMembership = {
      object: 'organization_membership',
      id: `om_${store.nextId++}`,
      organizationId,
      organizationName: store.organizations.get(organizationId)?.name ?? organizationId,
      status: 'active',
      userId,
      directoryManaged: false,
      createdAt: NOW,
      updatedAt: NOW,
      customAttributes: {},
      role: { slug: 'admin' },
      roles: [{ slug: 'admin' }],
    };
    store.memberships.push(membership);
    return membership;
  };

  userManagement.authenticateWithCode = async ({ code }: { code: string }) => {
    if (code !== AUTHORIZATION_CODE) {
      throw workosError('invalid_grant', 'The authorization code is invalid or has expired.');
    }
    const user = store.users.get(USER_ID)!;
    return {
      user,
      organizationId: store.memberships[0]?.organizationId,
      accessToken: TOKEN,
      refreshToken: 'conformance-refresh-token',
    };
  };

  organizations.createOrganization = async ({
    name,
    externalId,
    metadata,
  }: {
    name: string;
    externalId?: string;
    metadata?: Record<string, string>;
  }): Promise<Organization> => {
    if (externalId !== undefined && [...store.organizations.values()].some(o => o.externalId === externalId)) {
      throw workosError('external_id_already_used', `An organization already uses externalId ${externalId}.`);
    }
    const organization: Organization = {
      object: 'organization',
      id: `org_${store.nextId++}`,
      name,
      allowProfilesOutsideOrganization: false,
      domains: [],
      createdAt: NOW,
      updatedAt: NOW,
      externalId: externalId ?? null,
      metadata: metadata ?? {},
    };
    store.organizations.set(organization.id, organization);
    return organization;
  };

  organizations.getOrganizationByExternalId = async (externalId: string): Promise<Organization> => {
    const organization = [...store.organizations.values()].find(o => o.externalId === externalId);
    if (!organization) throw workosError('entity_not_found', `No organization with externalId ${externalId}.`);
    return organization;
  };
}

// ============================================================================
// The offline AuthKit session service
// ============================================================================

/** What the provider reads off `withAuth`. AuthKit returns more; this is the part used. */
interface SealedSession {
  accessToken: string;
  refreshToken: string;
  user: User;
  organizationId?: string;
}

/**
 * `AuthService.withAuth`, minus the remote-JWKS step.
 *
 * The real implementation reads the cookie, unseals it, then calls
 * `jwtVerify` against `createRemoteJWKSet(...)` and refreshes through the
 * WorkOS API when that fails — the two things that need a network. Cookie
 * reading and unsealing are kept exactly as they are in production so that
 * obligation 2 is a real round trip through `WebSessionStorage` and
 * iron-webcrypto, not a stub answering yes.
 *
 * Like the real one, it never throws: an absent or undecryptable cookie is
 * `{ auth: { user: null } }`.
 */
function offlineAuthService(): AuthService<Request, Response> {
  const storage = new WebSessionStorage({
    clientId: CLIENT_ID,
    apiKey: API_KEY,
    redirectUri: REDIRECT_URI,
    cookiePassword: COOKIE_PASSWORD,
    cookieName: COOKIE_NAME,
    cookieMaxAge: 60 * 60 * 24,
    apiHttps: true,
  });

  const withAuth = async (request: Request) => {
    try {
      const encrypted = await storage.getSession(request);
      if (!encrypted) return { auth: { user: null } };
      const session = await sessionEncryption.unsealData<SealedSession>(encrypted, { password: COOKIE_PASSWORD });
      if (!session?.user) return { auth: { user: null } };
      return {
        auth: {
          user: session.user,
          accessToken: session.accessToken,
          organizationId: session.organizationId,
        },
      };
    } catch {
      return { auth: { user: null } };
    }
  };

  return { withAuth } as unknown as AuthService<Request, Response>;
}

// ============================================================================
// Fixtures
// ============================================================================

/**
 * What a signed-in browser sends: the AuthKit session cookie, sealed with the
 * same password the provider is configured with, holding the same user the
 * bearer token resolves to. Built once — sealing is deterministic input,
 * non-deterministic output, and every check reads the same value.
 */
const COOKIE_HEADER = `${COOKIE_NAME}=${encodeURIComponent(
  await sessionEncryption.sealData(
    {
      accessToken: TOKEN,
      refreshToken: 'conformance-refresh-token',
      user: conformanceUser(),
    } satisfies SealedSession,
    { password: COOKIE_PASSWORD },
  ),
)}`;

async function createProvider(): Promise<MastraAuthWorkos> {
  const provider = new MastraAuthWorkos({
    apiKey: API_KEY,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    // FGA-style configuration: memberships are fetched on every authenticated
    // request, so the organization id travels with the user and the
    // organization obligation is checked against a provider that actually
    // looks memberships up.
    fetchMemberships: true,
    session: { cookiePassword: COOKIE_PASSWORD, cookieName: COOKIE_NAME },
  });

  installOfflineWorkOS(provider, createWorkOSStore());
  // `authService` is protected; the cast is the whole reason this is a test.
  (provider as unknown as { authService: AuthService<Request, Response> }).authService = offlineAuthService();

  return provider;
}

/**
 * The one defect this provider ships with, recorded so the suite can be green
 * without being a lie. The `reason` is a pointer plus a sentence; the
 * diagnosis lives in this file's header, which is where a reader of the
 * failing check already lands.
 *
 * Checked in both directions on every run: give this provider real sessions,
 * or stop declaring `ISessionProvider`, and the suite fails until this entry
 * is deleted in the same change.
 */
const knownFailures = [
  {
    check: 'sessions/round-trip',
    code: 'sessions/round-trip#validate-rejects-fresh-session',
    reason:
      'validateSession returns null unconditionally; all seven ISessionProvider members are no-ops ' +
      'kept for interface compatibility, so isSessionProvider reports a capability this provider does ' +
      'not have and toAuthDescriptor then advertises features.sessionRevocation. Full diagnosis in ' +
      'this file’s header.',
  },
];

describeAuthProvider({
  name: '@mastra/auth-workos',
  createProvider,
  token: TOKEN,
  userId: USER_ID,
  cookieHeader: COOKIE_HEADER,
  sso: {
    redirectUri: REDIRECT_URI,
    code: AUTHORIZATION_CODE,
  },
  knownFailures,
});
