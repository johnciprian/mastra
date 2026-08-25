/**
 * `@mastra/factory-auth` - the front door.
 *
 * The root export holds the pure layer: types, structural guards, and pure
 * functions. Nothing re-exported here executes anything at import time, reads a
 * request, touches a secret, or reaches a test framework.
 *
 * WHAT "PURE LAYER" DOES AND DOES NOT PROMISE
 *
 * It is a statement about this package's own code, not about its module graph.
 * No module behind this barrel imports `node:crypto` - `./cookie` and
 * `./oauth-state` do, and they stay behind their own subpaths for that reason.
 * But `./contract` re-exports from `@mastra/core/server`, and that package's
 * built graph does reach `stream`, so a bundler targeting the browser will still
 * have to resolve or stub a Node builtin. Measured, not assumed: walking
 * `dist/server/index.js` reaches `stream` in five modules, and it is retained
 * because a class extends `Transform`.
 *
 * So: importing this barrel runs no server code and needs no secret, which is
 * the property the SPA actually depends on when it wants
 * `import type { AuthDescriptor }`. It is not a promise that the barrel drops
 * cleanly into a browser bundle with no Node polyfills.
 * `src/__tests__/contract-surface.test.ts` pins both halves of that.
 *
 * `./testing` and `./conformance` are test-time and must never be re-exported
 * from here: `./conformance` is the one module that imports vitest, and the root
 * barrel must not drag a test framework into production graphs.
 */
export * from './contract.js';
export * from './identity.js';
export * from './capabilities.js';
