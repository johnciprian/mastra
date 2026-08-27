/**
 * Context for fragments that show one method of a fine-grained authorization
 * provider.
 *
 * `IFGAProvider` requires `check`, `require` and `filterAccessible`, and the
 * reference page explains `requireActor` by showing that method alone. Composing
 * the fragment into the class below keeps it checked against the real interface
 * instead of skipped.
 *
 * Every type here is written as an inline `import(...)` rather than a named
 * import on purpose: a named import would collide with the same name imported by
 * the documented block, and the resulting duplicate-identifier error would name
 * a line the reader never wrote.
 *
 * Keep this minimal. A member that only exists here is a member no reader saw
 * declared, and needing one is a signal that the fragment is under-explained on
 * the page.
 */

/** Stands in for the trusted per-agent grant lookup the page's prose describes. */
type GrantLookup = (agentId: string | undefined) => Promise<string[]>

/** Locally named so `implements` has an identifier, without shadowing a documented import. */
type ScaffoldFgaProvider = import('@mastra/core/auth/ee').IFGAProvider

export abstract class FgaScaffoldProvider implements ScaffoldFgaProvider {
  abstract check(user: unknown, params: import('@mastra/core/auth/ee').FGACheckParams): Promise<boolean>

  abstract require(user: unknown, params: import('@mastra/core/auth/ee').FGACheckParams): Promise<void>

  abstract filterAccessible<T extends { id: string }>(
    user: unknown,
    resources: T[],
    resourceType: string,
    permission: import('@mastra/core/auth/ee').MastraFGAPermissionInput,
  ): Promise<T[]>

  protected grantsForAgent!: GrantLookup
}

/** Stands in for the authenticated user a page's surrounding handler already has. */
export declare const user: unknown
