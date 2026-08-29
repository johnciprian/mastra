/**
 * The `auth` slot of `MastraFactoryConfig` — its two inhabitants, the guard
 * that separates them, and the constructor for the platform-proxied provider.
 *
 * The slot used to have three states: a provider instance, `null` (off), and
 * omitted (silently construct `MastraAuthStudio`). Omission is the dangerous
 * one — a deploy that forgot to wire auth booted anyway, pointed at the shared
 * platform API, and looked healthy. So the slot is now required and closed:
 * a provider, or {@link AUTH_DISABLED}. Whatever the old omission bought you
 * is now spelled {@link createMastraPlatformAuth}, in the caller's own code,
 * where it is visible in review.
 *
 * This lives in `@mastra/factory` and not `@mastra/factory-auth` on purpose.
 * `factory-auth/src/capabilities.ts` says it in prose: "A deployment with auth
 * switched off is a different state entirely, and it is not represented here."
 * `AUTH_DISABLED` is a fact about how one host is configured, not a capability
 * a provider advertises — so it belongs to the host's config surface.
 */

import { MastraAuthStudio } from '@mastra/auth-studio';
import type { IMastraAuthProvider } from '@mastra/core/server';

/** The `auth` slot asked for no authentication at all. */
export interface FactoryAuthDisabled {
  readonly disabled: true;
}

/** The singleton. Frozen so it cannot be mutated into something that reads as enabled. */
export const AUTH_DISABLED: FactoryAuthDisabled = Object.freeze({ disabled: true });

/** Every value the `auth` slot accepts. There is no third state. */
export type FactoryAuthConfig = IMastraAuthProvider | FactoryAuthDisabled;

/**
 * Module-private on purpose. `resolveFactoryPublicUrl` is the exported way to
 * ask this question, and it already applies this default; exporting the bare
 * constant as well would invite callers to restate the rule as
 * `publicUrl ?? DEFAULT_FACTORY_PUBLIC_URL` and skip the trailing-slash
 * normalization the function also does — which is the drift the function
 * exists to prevent.
 */
const DEFAULT_FACTORY_PUBLIC_URL = 'http://localhost:4111';

/**
 * Normalize a factory `publicUrl` the way `prepare()` does. Exported so anything
 * deriving from the same origin derives it from one function, not a restated rule.
 * Uses `??` (not `||`) to match the current prepare() expression exactly.
 */
export function resolveFactoryPublicUrl(publicUrl: string | undefined): string {
  return (publicUrl ?? DEFAULT_FACTORY_PUBLIC_URL).replace(/\/+$/, '');
}

/**
 * Whether the config asked for auth to be off. Reads a property no provider has:
 * `IMastraAuthProvider` declares name/protected/public/authenticateToken/
 * authorizeUser/mapUserToResourceId and nothing else. `=== true` rather than
 * truthiness, because a provider that ever grew a truthy `disabled` would
 * otherwise read as "auth off" — a fail-open.
 */
export function isAuthDisabled(auth: FactoryAuthConfig): auth is FactoryAuthDisabled {
  return (auth as Partial<FactoryAuthDisabled>).disabled === true;
}

/** Runtime guard for callers the type system does not reach (plain JS, `as never`, widened types). */
export function assertFactoryAuthConfig(auth: unknown): asserts auth is FactoryAuthConfig {
  if (typeof auth === 'object' && auth !== null) {
    if ((auth as FactoryAuthDisabled).disabled === true) return;
    const candidate = auth as Partial<IMastraAuthProvider>;
    if (typeof candidate.authenticateToken === 'function' && typeof candidate.authorizeUser === 'function') return;
  }
  throw new Error(
    `MastraFactory: 'auth' is required, and must be an auth provider instance or AUTH_DISABLED. ` +
      `Received ${describeAuthValue(auth)}. ` +
      `Pass a provider — new MastraAuthWorkos({ fetchMemberships: true }) from '@mastra/auth-workos', or ` +
      `createMastraPlatformAuth({ publicUrl }) from '@mastra/factory' for platform-proxied identity — or ` +
      `AUTH_DISABLED (also from '@mastra/factory') to run an open server with no authentication.`,
  );
}

function describeAuthValue(auth: unknown): string {
  if (auth === undefined) return 'undefined — the slot was omitted, which no longer selects a default provider';
  if (auth === null) return 'null — `null` no longer disables auth; use AUTH_DISABLED';
  if (typeof auth === 'object') return 'an object with no authenticateToken/authorizeUser';
  return `a ${typeof auth}`;
}

export interface MastraPlatformAuthOptions {
  /** The factory's browser-facing origin. Pass the same value as `publicUrl`. */
  publicUrl?: string;
}

/**
 * `MastraAuthStudio`, configured the way the factory used to configure it when
 * `auth` was omitted: identity proxied to the shared Mastra platform API, session
 * cookie's parent domain derived from `publicUrl`. `MastraAuthStudio` resolves
 * `MASTRA_SHARED_API_URL`, `MASTRA_ORGANIZATION_ID`, and `MASTRA_COOKIE_DOMAIN`
 * from env on its own — this helper only derives a cookie-domain fallback from
 * the factory's `publicUrl`.
 *
 * Cookie-domain resolution (Studio picks the first that wins):
 *   1. explicit `MASTRA_COOKIE_DOMAIN` env, if set;
 *   2. `.mastra.ai` when `sharedApiUrl` is on `.mastra.ai`;
 *   3. this parent-domain fallback derived from `publicUrl` — so a deploy on
 *      `https://foo.mastra.cloud` mints cookies with `Domain=.mastra.cloud`
 *      without the caller wiring the env var by hand.
 *   4. otherwise host-only (no `Domain=`), which is correct for `localhost`.
 */
export function createMastraPlatformAuth(options: MastraPlatformAuthOptions = {}): IMastraAuthProvider {
  return new MastraAuthStudio({
    cookieDomain: parentDomainFromPublicUrl(resolveFactoryPublicUrl(options.publicUrl)),
  });
}

/**
 * Derive a parent cookie domain from `publicUrl` by stripping the leftmost
 * label — the same shape platform-API's env injection uses (see
 * `platform/servers/api/src/lib/studio-env-vars.ts`: `.${routingDomain.replace(/^[^.]+\./, '')}`).
 *
 * Rather than a generic `strip-left-label` heuristic — which either emits
 * cookies scoped to a public suffix (`sub.example.co.uk` → `.example.co.uk`
 * requires PSL data to be safe) or misclassifies numeric hostnames like
 * `3scale.example.com` as IPv4 — we only derive a parent domain when the
 * host sits under one of the platform's known registrable domains. Anything
 * else (custom domains, arbitrary tenant hostnames, IPs, `localhost`)
 * falls through to host-only cookies. Callers that need a different scope
 * pass `MASTRA_COOKIE_DOMAIN` explicitly (Studio honors that first).
 */
const KNOWN_PLATFORM_COOKIE_PARENTS = ['mastra.cloud', 'mastra.ai'] as const;

function isIpLiteral(hostname: string): boolean {
  // IPv6 addresses in URLs are bracketed; `URL.hostname` strips the brackets
  // but the address itself still contains `:`. IPv4 is four dot-separated
  // numeric octets — trust the parser to have already validated shape.
  if (hostname.includes(':')) return true;
  return /^\d+(?:\.\d+){3}$/.test(hostname);
}

function parentDomainFromPublicUrl(publicUrl: string): string | undefined {
  let hostname: string;
  try {
    hostname = new URL(publicUrl).hostname.toLowerCase();
  } catch {
    return undefined;
  }
  if (hostname === 'localhost' || isIpLiteral(hostname)) return undefined;
  for (const parent of KNOWN_PLATFORM_COOKIE_PARENTS) {
    // Exact match → we're already on the parent, host-only is correct.
    // Subdomain match → mint the parent-scoped cookie.
    if (hostname === parent) return undefined;
    if (hostname.endsWith(`.${parent}`)) return `.${parent}`;
  }
  return undefined;
}
