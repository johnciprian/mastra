/**
 * Base class for factory route modules.
 *
 * Route modules build Mastra `apiRoutes` from injected dependencies instead of
 * reaching into host globals. The host server (e.g. `mastracode/web`) supplies
 * the auth seam and storage domain handles at construction time, so the routes
 * stay portable and testable with fakes.
 */

import type { ApiRoute } from '@mastra/core/server';
import type { Context } from 'hono';

/**
 * The signed-in user's display fields, for surfaces that show *who* acted
 * rather than merely scoping data to them.
 *
 * Separate from the tenant tuple on purpose. `{ orgId, userId }` is an
 * authorization answer and every route needs it; a name and a face are a
 * presentation answer and only the audit trail needs it. Keeping them apart
 * means a route cannot accidentally authorize on a display name, and the
 * fields stay optional because no provider is obliged to supply them: a
 * bearer-token provider legitimately knows an id and nothing else.
 *
 * `id` is the same id {@link RouteAuth.tenant} reports, so a caller that
 * carries a profile alongside a tenant cannot end up describing two people.
 */
export interface RouteAuthProfile {
  /** Stable provider user id — identical to `tenant().userId`. */
  id: string;
  /** Human-readable display name, when the provider exposes one. */
  name?: string;
  /** Email address, when the provider exposes one. */
  email?: string;
  /** Profile picture URL, when the provider exposes one. */
  avatarUrl?: string;
}

/**
 * The auth surface factory routes need, implemented by the host server.
 *
 * Local (no-auth) deployments implement this with a stub where `enabled()`
 * returns `false` and `tenant()` returns `undefined` — routes then take their
 * single-user local paths.
 */
export interface RouteAuth {
  /** Whether an auth provider is active (tenant mode). */
  enabled(): boolean;
  /**
   * Resolve (and cache) the signed-in user for the request, if any. Must be
   * called before `tenant()` so the request context is populated.
   */
  ensureUser(c: Context): Promise<unknown>;
  /**
   * Tenant identity for the request, when signed in.
   *
   * `orgId` is always present. A provider with no organization concept resolves
   * to a deterministic private organization derived from the user id, so a
   * route never has to decide what an org-scoped operation means for a user who
   * has no organization — the answer used to be 403, which is indistinguishable
   * from "you are not allowed" for a user who simply was not in a team.
   */
  tenant(c: Context): { orgId: string; userId: string } | undefined;
  /**
   * Tenant identity for an agent-run request context, for callers that never
   * see a Hono `Context`.
   *
   * Dynamic workspace resolution, rule tools and session subscriptions all run
   * inside an agent turn, under a `RequestContext`. They used to read identity
   * out of that context themselves, importing the auth module directly — the
   * three places where this port was the preferred identity path rather than
   * the only one. Same answer as {@link tenant}, same organization resolution,
   * same treatment of a blank id.
   */
  runTenant(
    requestContext: { get: (key: string) => unknown } | undefined,
  ): { orgId: string; userId: string } | undefined;
  /**
   * Display profile for the signed-in user, when signed in.
   *
   * The audit trail is the reason this exists. Recording *that* a user moved a
   * work item is a tenant question and {@link tenant} answers it; rendering
   * "Ada Lovelace moved it" is not, and the audit domain used to answer it by
   * reading the gate's `factoryAuthUser` variable straight off the Hono
   * context — the last identity read in this package that went around this
   * port rather than through it. That read was not an oversight: nothing here
   * could answer the question, so there was nowhere else to go.
   *
   * Same lifecycle as {@link tenant}: call `ensureUser()` first, and expect
   * `undefined` when nobody is signed in. Every field but `id` is optional,
   * because a provider that knows only an id is a legitimate provider — a
   * caller that needs a label should fall back to the id rather than assume.
   */
  profile(c: Context): RouteAuthProfile | undefined;
  /** Fail-closed check that the caller administers the given organization. */
  isOrganizationAdmin(c: Context, organizationId: string): Promise<boolean>;
}

/** Dependencies shared by every factory route module. */
export interface RouteDependencies {
  auth: RouteAuth;
}

/**
 * A route module: constructed once at boot with its dependencies, then asked
 * for the `ApiRoute[]` it serves.
 */
export abstract class Route<TDeps extends RouteDependencies = RouteDependencies> {
  protected readonly deps: TDeps;

  constructor(deps: TDeps) {
    this.deps = deps;
  }

  /** Build the Mastra `apiRoutes` served by this module. */
  abstract routes(): ApiRoute[];
}
