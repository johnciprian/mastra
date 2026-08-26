import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit:packages/_internals/auth',
          environment: 'node',
          include: ['src/**/*.test.ts'],
          setupFiles: ['@internal/test-utils/setup'],
          testTimeout: 120000,
        },
      },
      {
        /**
         * Typechecks `src/provider/capability-guards.test.ts`.
         *
         * That file pins each capability guard's member list to the required
         * keys of the interface it asserts, using a `satisfies` check that
         * fails to compile - not to run - when the two diverge. vitest
         * transpiles test files without typechecking them and `tsconfig.json`
         * excludes `**\/*.test.ts`, so without this project the pin would be
         * inert and a new required member could be added to an interface with
         * the guard left behind.
         *
         * The name rides the `--project 'typecheck:*'` selector the unit job in
         * .github/workflows/test-suite.yml already passes, so it runs on a pull
         * request with no workflow change, and from this package too
         * (`pnpm --filter @internal/auth test`).
         *
         * `tsconfig.conformance.json` re-excludes `**\/*.test.ts` and then
         * names the one file in `files`, which TypeScript never applies
         * `exclude` to - so the list is deliberate rather than a glob.
         */
        test: {
          name: 'typecheck:packages/_internals/auth',
          include: [],
          typecheck: {
            enabled: true,
            only: true,
            include: ['src/provider/capability-guards.test.ts'],
            tsconfig: './tsconfig.conformance.json',
          },
        },
      },
    ],
  },
});
