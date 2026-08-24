/**
 * `@mastra/factory-auth` - the front door.
 *
 * The root export holds the pure layer only: types, structural guards, and pure
 * functions. Nothing here touches `node:crypto`, and nothing here reaches a test
 * framework, so a browser bundle can import it safely.
 *
 * `./cookie` and `./oauth-state` are server-only and stay behind their own
 * subpaths. `./testing` and `./conformance` are test-time and must never be
 * re-exported from here: `./conformance` is the one module that imports vitest,
 * and the root barrel must not drag a test framework into production graphs.
 */
export * from './contract.js';
export * from './identity.js';
export * from './capabilities.js';
