/**
 * The provider conformance suite, for people *writing* a provider.
 *
 * K18 fills this in: `describeAuthProvider(name, factory, options)` plus one
 * obligation module per rule, so a failure names the obligation in the file path
 * rather than in a string inside a long suite.
 *
 * This is the only module in the package that imports vitest, which is why
 * vitest is an optional peer dependency and why `src/index.ts` never re-exports
 * this subpath.
 */
export {};
