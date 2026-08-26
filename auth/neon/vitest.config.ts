import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit:auth/neon',
          isolate: false,
          globals: true,
          include: ['src/**/*.test.ts'],
        },
      },
      {
        /**
         * Typechecks `src/conformance.test.ts`. Nothing else did.
         *
         * vitest transpiles test files without typechecking them, and
         * `tsconfig.json` excludes `**\/*.test.ts` so the build never sees them
         * either. A conformance suite could therefore carry a type error
         * forever and stay green on every run - which is how `getLoginUrl` and
         * `handleCallback` came to be called on provider types that do not
         * declare them.
         *
         * This project rides the `--project 'typecheck:*'` selector the unit job
         * in .github/workflows/test-suite.yml already passes, so it needs no
         * workflow change to run on a pull request, and it runs from this
         * package too (`pnpm --filter @mastra/auth-neon test`) so the error
         * shows up before the push rather than in CI.
         *
         * WHICH FILES ARE CHECKED, AND WHY ONLY ONE
         *
         * `tsconfig.conformance.json` decides, and its name is the boundary. It
         * re-excludes `**\/*.test.ts` and then names `src/conformance.test.ts`
         * in `files`, which TypeScript never applies `exclude` to - so the file
         * list is deliberate rather than an accident of globbing.
         *
         * The other suites under `src/` are left out knowingly: across auth/*
         * they carry 66 type errors in seven files across five packages -
         * better-auth, cloud, google, neon and workos - mostly partial object
         * literals standing in for full SDK types. Fixing those is a separate
         * job from wiring the check up. Widening this to `src/**\/*.test.ts`
         * is the follow-up, one package at a time.
         */
        test: {
          name: 'typecheck:auth/neon',
          include: [],
          typecheck: {
            enabled: true,
            only: true,
            include: ['src/conformance.test.ts'],
            tsconfig: './tsconfig.conformance.json',
          },
        },
      },
    ],
  },
});
