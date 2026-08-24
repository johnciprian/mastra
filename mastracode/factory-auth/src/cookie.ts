/**
 * The host-owned session cookie.
 *
 * K12 fills this in: one declared cookie name, `mintSessionCookie`,
 * `readSessionCookie`, `clearSessionCookie`, and the SameSite/Secure derivation
 * for cross-site deployments. HMAC over `node:crypto` only - no dependencies.
 *
 * Written fresh rather than reused from `@internal/auth/session` because that
 * package is private to the monorepo and cannot be a dependency of a published
 * package, its cookie module's declaration chain reaches the ee/-bearing root
 * barrel, and the Factory needs cross-site attributes the shipped provider does
 * not have.
 *
 * Named `./cookie`, not `./session`: `ISessionProvider` in the contract is a
 * different thing, and `mastracode/factory/src/session/` is a third. This module
 * ships a cookie, so it says cookie.
 */
export {};
