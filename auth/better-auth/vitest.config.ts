import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit:auth/better-auth',
          // Isolated, unlike almost every other project in this repo: these
          // packages run a suite that mocks the vendor SDK next to a conformance
          // suite that must NOT have it mocked, and with a shared module registry
          // whichever file loads the module first wins. Costs nothing measurable
          // here - isolated and shared time the same, to within 1%. See the
          // isolation check in .github/workflows/auth-conformance-gate.test.ts.
          isolate: true,
          globals: true,
          include: ['src/**/*.test.ts'],
        },
      },
      {
        /**
         * Typechecks every test file under `src/`. Nothing did, before.
         *
         * vitest transpiles test files without typechecking them, and
         * `tsconfig.json` excludes `**\/*.test.ts` so the build never sees them
         * either. A test file could therefore carry a type error forever and
         * stay green on every run - which is how `getLoginUrl` and
         * `handleCallback` came to be called on provider types that do not
         * declare them, and how another 64 errors accumulated across auth/*:
         * partial SDK fixtures, `mock.calls[0][0]` indexed without a check
         * under `noUncheckedIndexedAccess`, and a DOM-only `RequestInfo` in
         * packages that compile with `lib: ["ES2023"]`.
         *
         * This project rides the `--project 'typecheck:*'` selector the unit job
         * in .github/workflows/test-suite.yml already passes, so it needs no
         * workflow change to run on a pull request, and it runs from this
         * package too (`pnpm --filter @mastra/auth-better-auth test`) so the error
         * shows up before the push rather than in CI.
         *
         * WHICH FILES ARE CHECKED
         *
         * `tsconfig.conformance.json` decides, and it no longer names one file:
         * it drops the `**\/*.test.ts` exclusion the base config carries, so
         * `src/**\/*` reaches the suites as well as the sources. A test file
         * added tomorrow is checked the day it lands, with no list to remember
         * to update. The file keeps the name it was born with; its scope is now
         * the whole of `src/`.
         *
         * `typecheck.include` below matches that, so vitest attributes each
         * error to the test that owns it instead of reporting it against the
         * project. Widening one without the other is the failure mode to watch
         * for: a tsconfig that admits files the include never names, or an
         * include that names files the tsconfig excludes.
         */
        test: {
          name: 'typecheck:auth/better-auth',
          include: [],
          typecheck: {
            enabled: true,
            only: true,
            include: ['src/**/*.test.ts'],
            tsconfig: './tsconfig.conformance.json',
          },
        },
      },
    ],
  },
});
