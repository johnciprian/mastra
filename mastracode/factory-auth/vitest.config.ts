import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'unit:mastra-factory-auth',
    environment: 'node',
    include: ['src/**/*.test.ts'],
    exclude: ['**/node_modules/**', '**/dist/**'],
    // The EE boundary test walks @mastra/core's source graph, which is large.
    testTimeout: 120_000,
    hookTimeout: 120_000,

    /**
     * Coverage runs on every `pnpm test`, and the thresholds below are the
     * point of it.
     *
     * Enabled by default rather than behind a flag, because a threshold nobody
     * runs is a comment. The cost is about a second on a two-second suite, and
     * the reporter is the four-line summary so an ordinary run stays quiet; add
     * `--coverage.reporter=text` for the per-file table when one of these fails.
     *
     * WHAT THE NUMBERS ARE, AND WHY THEY ARE NOT ALL 100
     *
     * Lines and functions are at 100 and there is no reason to accept less. A
     * function nobody executes is the gap this threshold exists to catch, and
     * every line of this package is reached by something today, so the floor is
     * where the suite already stands. These are the two that would notice a new
     * export arriving with no test behind it.
     *
     * Statements and branches sit a little under, and the shortfall is
     * accounted for rather than tolerated in general:
     *
     * - `src/cookie.ts` has two branches that are unreachable by construction
     *   and documented as defensive - the signature length re-check that the
     *   43-character regex has already decided, and a `?? ''` after a `split`
     *   that cannot return an empty array. Removing either would be a worse file.
     * - `src/conformance/index.ts` is mostly guidance prose reached through
     *   `expect.fail`, which is typed `never`: each failure block counts
     *   statements that only run for a provider shape somebody has to build on
     *   purpose. `src/__tests__/conformance.test.ts` builds one per check, and
     *   what remains is the second and third way a single check can go red.
     *
     * So the floors are set just below where the suite stands - roughly a point
     * of headroom on statements and branches - which is enough that an honest
     * refactor does not fail CI, and tight enough that deleting one of the
     * conformance red cases or landing an untested branch does.
     */
    coverage: {
      enabled: true,
      provider: 'v8',
      reporter: ['text-summary'],
      // `.vitest-reports/` is already ignored repo-wide; nothing here is committed.
      reportsDirectory: './.vitest-reports/coverage',
      include: ['src/**/*.ts'],
      exclude: ['src/**/*.test.ts', 'src/__tests__/**'],
      thresholds: {
        lines: 100,
        functions: 100,
        statements: 97,
        branches: 94,
      },
    },
  },
});
