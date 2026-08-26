import { createConfig } from '@internal/lint/eslint';
import tseslint from 'typescript-eslint';

const config = await createConfig();

/**
 * Enterprise Edition boundary - the Factory's half of it.
 *
 * This is NOT the same ban as mastracode/factory-auth/eslint.config.js, and the
 * difference is deliberate. Read this before widening or narrowing it.
 *
 * ## Same licence, different dependency surface
 *
 * mastracode/factory is Apache-2.0 and published (package.json `license` and
 * `publishConfig.access: public`); it ships no package-local LICENSE, so the
 * root LICENSE.md governs, and that grants Apache-2.0 to everything outside a
 * directory named `ee/`. So the Factory carries exactly the same licence
 * obligation as the kit.
 *
 * What differs is what each package is allowed to depend on. The kit is a leaf
 * library whose entire external surface is one specifier, `@mastra/core/server`,
 * which resolves to 19 source modules and 0 under `ee/`. That is what lets it
 * ban every barrel that reaches EE and still compile.
 *
 * The Factory is the host application, and its runtime graph reaches `ee/`
 * through the barrels that are its actual job. Measured over TypeScript source
 * with the repo's own resolver (madge + mastracode/factory-auth/test/
 * madge.webpack.config.cjs, `skipTypeImports: true`), counting modules whose
 * path has a whole `ee` segment:
 *
 *     @mastra/core/storage           ee=14   (36 import sites here)
 *     @mastra/core/agent-controller  ee=14   (20)
 *     @mastra/core/workspace         ee=14   (18)
 *     @mastra/core/worker            ee=14   (18)
 *     @mastra/core/channels          ee=14   (6)
 *     @mastra/core/mastra            ee=14   (4)
 *     @mastra/core/tools             ee=14   (3)
 *     @mastra/core (root)            ee=14   (3)
 *     @mastra/core/agent             ee=14   (3)
 *     @mastra/code-sdk               ee=14   (a first-class dependency)
 *     @mastra/auth-workos            ee=11   (3)
 *     @mastra/auth-studio            ee=11   (2)
 *
 * Copying the kit's ban here would fail on roughly fifty existing imports and
 * could only be made green by a blanket exception for each one, which would
 * make the rule say nothing. Nor is this a temporary state: the backend lane
 * ends at B7, which removes @mastra/auth-workos only - @mastra/auth-studio and
 * every @mastra/core barrel above stay. A zero-EE claim is not available to
 * this package now and will not become available at the end of the plan.
 *
 * ## What this rule does claim
 *
 * It bans the three reaches that are entirely this package's own doing, that it
 * makes zero of today, and that the auth work in this lane is most likely to
 * introduce:
 *
 *   1. `@mastra/core/auth` - ee=11 at runtime. The barrel whose name matches the
 *      job, and the wrong turn anyone touching src/auth.ts is likeliest to take.
 *      `@mastra/core/server` re-exports the same auth interfaces and guards at
 *      ee=0 and is already this package's dominant core import (45 sites).
 *   2. `@internal/auth` - ee=11 at runtime, private to the monorepo, and not a
 *      dependency of this package. It must not become one.
 *   3. Any specifier with a whole `ee` path segment - naming enterprise source
 *      directly, which no transitive dependency can excuse.
 *
 * That is a rule that fails on what it forbids and passes on what this package
 * legitimately does. The provider ban belongs to the kit, not here; once B6/B7
 * land and `@mastra/auth-workos` is gone, the remaining half can be revisited.
 *
 * ## Mechanics - do not "tidy" these away
 *
 * 1. It restates the shared base's "Do not import test files in source files"
 *    group. ESLint flat config REPLACES rule options for matching files rather
 *    than merging them, so declaring `no-restricted-imports` here would
 *    otherwise silently delete the group bound in packages/_config/src/eslint.js.
 * 2. It carries no `ignores`. The shared base exempts test files from
 *    `no-restricted-imports`; this package's 91 test files are Apache-2.0 output
 *    too and must not be exempt. No file here imports a test file, so folding
 *    both groups into one un-ignored block loses nothing.
 * 3. It is ordered after `...config`, which ends with
 *    `oxlint.buildFromOxlintConfig(...)` and switches this rule off for TS/JS.
 *    Measured: before this block existed, no `no-restricted-imports` violation
 *    was reportable by ESLint in this package at all.
 * 4. There is no `paths` entry. The kit needs one because it bans the
 *    `@mastra/core` root barrel while keeping `@mastra/core/server` legal, and
 *    ESLint `patterns` are gitignore-style, so a bare `@mastra/core` there would
 *    also reject its subpaths. This package bans no root barrel, and every
 *    pattern below is meant to cover its subpaths.
 *
 * The same ban lives in oxlint.config.ts, because `lint` is `oxlint . && eslint .`
 * and lint-staged runs oxlint first. Keep the two lists in step.
 */
const EE_PATH_MESSAGE =
  'This specifier names enterprise-licensed (ee/) source directly. mastracode/factory is Apache-2.0 under the repository LICENSE.md, and while its dependencies already reach ee/, naming an ee/ path from this package is a breach entirely of its own making. Take the auth contract from @mastra/core/server and the Factory-side helpers from @mastra/factory-auth. See mastracode/factory-auth/README.md#the-ee-boundary.';

const CORE_AUTH_MESSAGE =
  '@mastra/core/auth pulls 11 enterprise (ee/) modules into the runtime graph. @mastra/core/server exposes the same auth interfaces and guards with zero ee/ modules at runtime, and this package already imports it in 45 places - use that, or @mastra/factory-auth/contract, instead. See mastracode/factory-auth/README.md#the-ee-boundary.';

const INTERNAL_AUTH_MESSAGE =
  '@internal/auth re-exports ee/ from its barrel (11 ee/ modules at runtime) and is private to the monorepo, so a published package must not name it. This package does not depend on it and should not start: take the contract from @mastra/core/server, or @mastra/factory-auth/contract. See mastracode/factory-auth/README.md#the-ee-boundary.';

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
          ],
        },
      ],
    },
  },
];
