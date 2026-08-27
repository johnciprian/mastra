/**
 * The framework-neutral request primitives, re-exported from `@internal/auth`.
 *
 * WHY THIS FILE IS A RE-EXPORT AND NOT A DECLARATION
 *
 * It used to declare its own copy of `HonoRequestLike`, `MastraAuthRequest`,
 * `getRequestHeader` and `getWebRequest`. That copy had drifted from the one
 * `MastraAuthProvider` is declared against — `header()` was required and
 * `headers` was `Headers` only — and the drift was not cosmetic:
 *
 *   - The abstract `authenticateToken`/`authorizeUser` signatures, and the
 *     `authorizeUser` option callback, come from `@internal/auth` by way of
 *     `./auth`. So the request a provider is handed was the internal type,
 *     while `getWebRequest` exported two lines below it from the same entry
 *     point wanted the local one. Passing the former to the latter failed with
 *     `TS2345`, which meant the most obvious way to write a provider — take the
 *     request your own callback receives and hand it to the helper this package
 *     exports for it — did not compile.
 *   - The local `getRequestHeader` read `request.headers?.get(name)` and then
 *     `request.header(name)` unguarded, so an Express-style request carrying
 *     plain-object `headers` and no `header()` method threw a `TypeError`
 *     rather than returning the header. The `@internal/auth` implementation
 *     handles that shape deliberately and has tests for it.
 *
 * `@mastra/core/auth` already re-exports these same names from `@internal/auth`,
 * and `@mastra/core/server` already bundles that implementation because `./auth`
 * pulls in `MastraAuthProvider`. Two copies of the same two functions were being
 * shipped in one package, and only one of them was correct.
 */
export type { AuthenticateTokenFn, AuthorizeUserFn, HonoRequestLike, MastraAuthRequest } from '@internal/auth/types';
export { getRequestHeader, getWebRequest } from '@internal/auth/types';
