import { defineConfig } from 'oxlint';
import rootConfig from '../../oxlint.config.ts';

/**
 * Half of the Factory's Enterprise Edition boundary. `lint` is
 * `oxlint . && eslint .` and lint-staged runs `oxlint --fix --deny-warnings`
 * first, so oxlint sees a bad import before ESLint does.
 *
 * The authoritative copy of these patterns, and the reasoning for why this ban
 * is narrower than mastracode/factory-auth's, is eslint.config.js. Keep the two
 * lists in step. In short: this package is Apache-2.0 like the kit, but it is
 * the host application and its dependency surface reaches ee/ through the
 * @mastra/core barrels that are its job, so the only reaches it can honestly
 * forbid are the ones it makes zero of and could only introduce itself.
 *
 * The `overrides` entries re-enable the rule where the root config would drop
 * it: the root turns `no-restricted-imports` off for test files, and this
 * package's 91 test files are Apache-2.0 output that must not be exempt.
 */
const EE_PATH_MESSAGE =
  'This specifier names enterprise-licensed (ee/) source directly. mastracode/factory is Apache-2.0 under the repository LICENSE.md, and while its dependencies already reach ee/, naming an ee/ path from this package is a breach entirely of its own making. Take the auth contract from @mastra/core/server and the Factory-side helpers from @mastra/factory-auth. See mastracode/factory-auth/README.md#the-ee-boundary.';

const CORE_AUTH_MESSAGE =
  '@mastra/core/auth pulls 11 enterprise (ee/) modules into the runtime graph. @mastra/core/server exposes the same auth interfaces and guards with zero ee/ modules at runtime, and this package already imports it in 45 places - use that, or @mastra/factory-auth/contract, instead. See mastracode/factory-auth/README.md#the-ee-boundary.';

const INTERNAL_AUTH_MESSAGE =
  '@internal/auth re-exports ee/ from its barrel (11 ee/ modules at runtime) and is private to the monorepo, so a published package must not name it. This package does not depend on it and should not start: take the contract from @mastra/core/server, or @mastra/factory-auth/contract. See mastracode/factory-auth/README.md#the-ee-boundary.';

const VENDOR_AUTH_MESSAGE =
  'This package names no auth vendor package except in src/auth-config.ts, where createMastraPlatformAuth() constructs MastraAuthStudio for hosts that ask for platform-proxied identity by name. Everything else composes whatever provider the host was given, via the capability guards. Take the contract from @mastra/core/server and the Factory-side helpers from @mastra/factory-auth. If you need a vendor client for an integration, take it from the host through the integration constructor - integrations/workos/ does exactly that, which is what let @mastra/auth-workos leave this package (P14).';

const EE_BOUNDARY_GROUPS = [
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
];

/**
 * Provider packages, banned everywhere except `src/auth-config.ts`, where
 * `createMastraPlatformAuth()` constructs `MastraAuthStudio` for hosts that ask
 * for platform-proxied identity by name. This was scoped to `src/auth.ts` alone
 * until P14 took `@mastra/auth-workos` out of the package, then to
 * `src/factory.ts` while that file still constructed a default provider — it no
 * longer does, because `auth` is a required config slot. See eslint.config.js
 * for the full reasoning and for why the exemption is a separate block rather
 * than a negated pattern.
 */
const VENDOR_AUTH_GROUP = {
  group: ['@mastra/auth-*', '@mastra/auth-*/**'],
  message: VENDOR_AUTH_MESSAGE,
};

const eeBoundaryRule = ['error', { patterns: EE_BOUNDARY_GROUPS }];

const vendorAuthRule = ['error', { patterns: [...EE_BOUNDARY_GROUPS, VENDOR_AUTH_GROUP] }];

export default defineConfig({
  extends: [rootConfig],
  rules: {
    'no-restricted-imports': vendorAuthRule,
  },
  overrides: [
    {
      files: ['**/*.ts?(x)', '**/*.js?(x)'],
      rules: {
        'no-restricted-imports': vendorAuthRule,
      },
    },
    {
      files: ['**/tests/**', '**/#tests/**', '**/__tests__/**/*', '**/*.test.*', '**/*.spec.*'],
      rules: {
        'no-restricted-imports': vendorAuthRule,
      },
    },
    {
      // Last, so it wins for the one file allowed to name a provider.
      files: ['src/auth-config.ts'],
      rules: {
        'no-restricted-imports': eeBoundaryRule,
      },
    },
  ],
});
