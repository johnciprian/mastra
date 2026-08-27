import { defineConfig } from 'oxlint';
import rootConfig from '../../oxlint.config.ts';

/**
 * Half of the Enterprise Edition boundary. `lint` is `oxlint . && eslint .` and
 * lint-staged runs `oxlint --fix --deny-warnings` first, so oxlint sees a bad
 * import before ESLint does. mastracode/* packages ship no oxlint config and so
 * inherit nothing from the root, which is why this file exists at all.
 *
 * The authoritative copy of these patterns and messages is eslint.config.js.
 * Keep the two lists in step.
 *
 * The `overrides` entry re-enables the rule for test files: the root config
 * turns `no-restricted-imports` off there, and this package's own tests are
 * Apache-2.0 output that must not be exempt from the EE ban.
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

const eeBoundaryRule = [
  'error',
  {
    // `paths` matches the specifier exactly. Root barrels that must be banned
    // without also banning their subpaths belong here: a bare `@mastra/core` in
    // `patterns` is gitignore-style under ESLint and would reject
    // `@mastra/core/server`, the one import this package is supposed to make.
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
];

export default defineConfig({
  extends: [rootConfig],
  rules: {
    'no-restricted-imports': eeBoundaryRule,
  },
  overrides: [
    {
      files: ['**/*.ts?(x)', '**/*.js?(x)'],
      rules: {
        'no-restricted-imports': eeBoundaryRule,
      },
    },
    {
      files: ['**/tests/**', '**/#tests/**', '**/__tests__/**/*', '**/*.test.*', '**/*.spec.*'],
      rules: {
        'no-restricted-imports': eeBoundaryRule,
      },
    },
  ],
});
