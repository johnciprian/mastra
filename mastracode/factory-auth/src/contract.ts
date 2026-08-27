/**
 * The single import site.
 *
 * Every other module in this package reaches the Mastra auth contract through
 * here, and this file reaches it through exactly one specifier:
 * `@mastra/core/server`. If that entry point moves a symbol, one file changes.
 *
 * WHY THIS IS THE ONLY ALLOWED PATH
 * `@mastra/core/server` is the one `@mastra/core` entry point whose runtime
 * graph is free of enterprise (`ee/`) code - measured at 19 modules, 0 of them
 * under an `ee/` directory. `@mastra/core/auth` reaches 11, the `@mastra/core`
 * root barrel reaches 14. `eslint.config.js` bans the others and
 * `src/__tests__/no-ee-boundary.test.ts` proves this file's graph stays clean.
 *
 * THE RULE FOR WHAT MAY BE ADDED HERE
 * Re-export from `@mastra/core/server` only symbols that are themselves free of
 * enterprise declarations. That is a rule, not a list: the set below satisfies
 * it, but it would be easy to add a neighbouring symbol that does not.
 *
 * Four symbols on that entry point are permanently off limits -
 * `MastraAuthConfig`, `ApiRoute`, `ApiRouteHandler` and `StudioConfig`. Each is
 * structurally defined in terms of enterprise interfaces
 * (`packages/core/src/server/types.ts` lines 24, 424, 433, 560 and 567), and
 * `packages/core/tsdown.config.ts` rolls those declarations into core's emitted
 * types. Re-exporting one would copy enterprise declaration text into an
 * Apache-2.0 package's published type surface - a licence problem even though
 * nothing executes. `src/__tests__/contract-surface.test.ts` asserts all four
 * stay out, of this file and of `dist/`.
 *
 * If you need route or server configuration types, import them from
 * `@mastra/core/server` at the point of use in the host application, which is
 * not Apache-2.0-constrained the way this package is.
 */

/**
 * The provider base class and the structural capability guards.
 *
 * There are eight guards, and they answer "which optional capabilities does
 * this provider implement". Note `hasAuthInit` rather than `isAuthInit`, and
 * note there is no guard for `IMastraAuthProvider` itself: implementing the
 * base contract is a precondition, not a capability to test for.
 *
 * All seven are structural (`typeof provider.getLoginUrl === 'function'`), never
 * `instanceof`, so they work across duplicate copies of `@mastra/core` in a
 * dependency tree.
 */
export {
  MastraAuthProvider,
  isSSOProvider,
  isSessionProvider,
  isUserProvider,
  isCredentialsProvider,
  isOrganizationsProvider,
  canClearSession,
  canManageSessions,
  isAuthHttpHandler,
  hasAuthInit,
} from '@mastra/core/server';

/**
 * The base contract every provider implements, and its constructor options.
 */
export type { IMastraAuthProvider, MastraAuthProviderOptions } from '@mastra/core/server';

/**
 * The capability interfaces the eight guards narrow to, plus the context handed
 * to a provider's optional `init` hook.
 */
export type {
  AuthInitContext,
  IAuthHttpHandler,
  IAuthInit,
  ICredentialsProvider,
  IOrganizationsProvider,
  ISessionClearer,
  ISessionManager,
  ISessionProvider,
  ISSOProvider,
  IUserProvider,
} from '@mastra/core/server';

/**
 * Framework-neutral request primitives.
 *
 * These come from `packages/core/src/server/request-types.ts`, which since P26
 * re-exports them from `@internal/auth/types` rather than declaring its own
 * copy - core had two divergent versions and `./server` exported the wrong one.
 * That module imports nothing itself, so these still carry no framework and no
 * transitive graph, and `@mastra/core/server` already bundled the same code by
 * way of `MastraAuthProvider`.
 *
 * They are re-exported here rather than left to callers because of what this
 * module claims to be. `./cookie` has to read a `Cookie` header and
 * `./oauth-state` has to read a query string; if either imported
 * `@mastra/core/server` directly for that, this file would stop being the single
 * import site on the first day it mattered. Taking them from here also keeps
 * `hono` out of this package's dependencies, which matters because provider
 * packages will depend on it for the conformance suite.
 */
export { getRequestHeader, getWebRequest } from '@mastra/core/server';
export type { HonoRequestLike, MastraAuthRequest } from '@mastra/core/server';
