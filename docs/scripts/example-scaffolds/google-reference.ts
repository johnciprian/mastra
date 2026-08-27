/**
 * Context for the one-line method fragments on
 * `reference/auth/google.mdx`.
 *
 * A reference page documents a method by showing the call, not the surrounding
 * handler. Those calls are still worth checking: they name real methods with
 * real arities, and a renamed method or a changed parameter list in
 * `@mastra/auth-google` is exactly the drift this check exists to catch.
 *
 * Everything here stands in for something the page's prose already gave the
 * reader: a configured provider, a configured RBAC provider, the request the
 * route handler received, and the token or user id it read. Nothing here is
 * documentation.
 *
 * Types are written as inline `import(...)` so a documented block importing the
 * same name does not collide with this file.
 */

/** Stands in for the provider the page configured under "Usage example". */
export declare const auth: import('@mastra/auth-google').MastraAuthGoogle

/** Stands in for the RBAC provider the page configured under "Usage example". */
export declare const rbac: import('@mastra/auth-google').MastraRBACGoogle

/** Stands in for an authenticated user the surrounding handler already has. */
export declare const user: import('@mastra/auth-google').GoogleUser

/** Stands in for the request a route handler received. */
export declare const request: Request

/** Stands in for a Google ID token read from the `Authorization` header. */
export declare const idToken: string

/** Stands in for a user id a route's parameters carried. */
export declare const userId: string
