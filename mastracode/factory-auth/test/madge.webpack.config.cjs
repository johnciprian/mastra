/**
 * Resolution config for the EE boundary test (`src/__tests__/no-ee-boundary.test.ts`).
 *
 * It reuses the repo's shared workspace alias table, which maps every workspace
 * package name AND exported subpath onto TypeScript source. Combined with empty
 * `exportsFields` / `mainFields` / `aliasFields`, that forces resolution onto
 * `src/` instead of built `dist/` output.
 *
 * That is the whole point. `packages/core/tsdown.config.ts` `alwaysBundle`s
 * `@internal/auth`, so enterprise code is inlined into core's `dist` with no `ee`
 * path segment anywhere - a scan of built output is structurally blind to it.
 * Resolving over source keeps `ee/` a literal, visible path segment.
 */
const path = require('node:path');
const { buildWorkspaceSourceAliases } = require('../../../scripts/workspace-source-aliases.cjs');

const ROOT = path.join(__dirname, '..', '..', '..');

const alias = buildWorkspaceSourceAliases(ROOT).map(({ name, target, exact }) => ({
  name,
  alias: target,
  onlyModule: exact,
}));

module.exports = {
  resolve: {
    alias,
    extensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json'],
    extensionAlias: { '.js': ['.ts', '.tsx', '.js'] },
    exportsFields: [],
    mainFields: [],
    aliasFields: [],
  },
};
