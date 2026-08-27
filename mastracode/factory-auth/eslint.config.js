import { createConfig } from '@internal/lint/eslint';
import tseslint from 'typescript-eslint';

const config = await createConfig();

/**
 * Enterprise Edition boundary.
 *
 * This package is Apache-2.0. Every directory named `ee/` in this repository is
 * licensed under the Mastra Enterprise Edition License (`ee/LICENSE`), so no
 * module in this package may reach one - directly, as types, or transitively
 * through an Apache-2.0 barrel that happens to reach EE.
 *
 * Three things about this block are deliberate. Do not "tidy" them away:
 *
 * 1. It restates the shared base's "Do not import test files in source files"
 *    group. ESLint flat config REPLACES rule options for matching files, it does
 *    not merge them, so declaring `no-restricted-imports` here would otherwise
 *    silently delete the group bound in packages/_config/src/eslint.js.
 * 2. It carries no `ignores`. The shared base exempts test files from
 *    `no-restricted-imports`; this package's own tests are Apache-2.0 output too
 *    and must not be exempt from the EE ban.
 * 3. It is ordered after `...config`, which ends with
 *    `oxlint.buildFromOxlintConfig(...)` and switches this rule off for TS/JS.
 *
 * The same ban lives in oxlint.config.ts, because `lint` is `oxlint . && eslint .`
 * and lint-staged runs oxlint first. Keep the two lists in step.
 */
const EE_PATH_MESSAGE =
  'This path is enterprise-licensed (ee/) code, and this package is Apache-2.0 so its module graph must stay free of ee/. Build what you need here from the Apache-2.0 interfaces in @mastra/core/server, without reading the ee/ source. See mastracode/factory-auth/README.md#the-ee-boundary.';

const CORE_AUTH_MESSAGE =
  "@mastra/core/auth loads enterprise (ee/) code through its barrel, and this package is Apache-2.0 so it can't reach ee/. Import the contract and guards from @mastra/core/server instead, through src/contract.ts. See mastracode/factory-auth/README.md#the-ee-boundary.";

const INTERNAL_AUTH_MESSAGE =
  '@internal/auth re-exports ee/ from its barrel and is private to the monorepo. This package takes the contract from the public, Apache-2.0 @mastra/core/server entry point instead. See mastracode/factory-auth/README.md#the-ee-boundary.';

const TRANSITIVE_MESSAGE =
  'This barrel is Apache-2.0, but its runtime graph reaches enterprise (ee/) code, so importing it puts ee/ into this package. @mastra/core root reaches it through tools/tool-builder/builder.ts, which imports a runtime value from ../../auth/ee. Import a narrow ee-free subpath instead: @mastra/core/server, /error, /base, /types, /request-context, /di, /telemetry, /logger. See mastracode/factory-auth/README.md#the-ee-boundary.';

const PROVIDER_MESSAGE =
  '@mastra/auth-* provider packages reach enterprise (ee/) code at runtime: @mastra/auth-workos pulls 11 ee/ modules into the graph today. This package is Apache-2.0 and provider-agnostic, so it never names a vendor. Take the contract from @mastra/core/server and let the host pass a provider in. See mastracode/factory-auth/README.md#the-ee-boundary.';

/** @type {import("eslint").Linter.Config[]} */
export default [
  ...config,
  {
    files: ['**/*.ts?(x)'],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    files: ['**/*.ts?(x)', '**/*.js?(x)'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          // `paths` matches the specifier exactly. `patterns` are gitignore-style,
          // where a bare `@mastra/core` would also match `@mastra/core/server` -
          // the one import this package is supposed to make. Measured: with
          // `@mastra/core` in `patterns`, ESLint rejects `@mastra/core/server`
          // while oxlint accepts it. Root barrels that must be banned without
          // their subpaths belong here, not below.
          paths: [
            {
              name: '@mastra/core',
              message: TRANSITIVE_MESSAGE,
            },
          ],
          patterns: [
            {
              group: ['**/tests/**', '**/#tests/**', '**/__tests__/**/*', '**/*.test.*', '**/*.spec.*'],
              message: 'Do not import test files in source files',
            },
            {
              group: [
                '**/ee',
                '**/ee/**',
                './ee',
                './ee/**',
                '../ee',
                '../ee/**',
                '*/ee',
                '*/ee/**',
                '@mastra/playground-ui/ee/**',
              ],
              message: EE_PATH_MESSAGE,
            },
            {
              group: ['@mastra/core/auth', '@mastra/core/auth/*', '@mastra/core/auth/**'],
              message: CORE_AUTH_MESSAGE,
            },
            {
              group: ['@internal/auth', '@internal/auth/*', '@internal/auth/**'],
              message: INTERNAL_AUTH_MESSAGE,
            },
            {
              group: [
                '@mastra/core/utils',
                '@mastra/core/storage',
                '@mastra/core/storage/**',
                '@mastra/core/agent',
                '@mastra/core/agent/**',
                '@mastra/core/mastra',
                '@mastra/core/memory',
                '@mastra/core/memory/**',
                '@mastra/core/tools',
                '@mastra/core/tools/**',
                '@mastra/core/workflows',
                '@mastra/core/workflows/**',
                '@mastra/core/agent-builder',
                '@mastra/core/agent-builder/**',
                '@mastra/editor',
                '@mastra/editor/**',
              ],
              message: TRANSITIVE_MESSAGE,
            },
            {
              group: ['@mastra/auth-*', '@mastra/auth-*/**'],
              message: PROVIDER_MESSAGE,
            },
          ],
        },
      ],
    },
  },
];
