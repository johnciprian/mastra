/**
 * The single import site.
 *
 * K7 fills this in: re-export the 8 capability interfaces, the 7 structural
 * guards, and the `MastraAuthProvider` base class from `@mastra/core/server`,
 * and nothing else. Every other module in this package reaches the Mastra
 * contract through here, so a change upstream is a one-file change here.
 *
 * Rule, not a list: only re-export symbols that are themselves free of
 * enterprise (ee/) declarations. `MastraAuthConfig`, `ApiRoute`,
 * `ApiRouteHandler` and `StudioConfig` are exported from `@mastra/core/server`
 * but reference ee/-authored interfaces, so they must never be re-exported here.
 */
export {};
