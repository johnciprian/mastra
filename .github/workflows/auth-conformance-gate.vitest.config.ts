/**
 * The runner for `auth-conformance-gate.test.ts`.
 *
 * It needs its own config because the root `vitest.config.ts` builds its
 * project list from a fixed set of globs - `packages/*`, `auth/*`, `stores/*`
 * and so on - and none of them reaches `.github/`. A test file that matches no
 * project is not run and not reported; `pnpm vitest run` at the root would
 * simply say no test files were found.
 *
 * That is the right outcome rather than a problem to route around. The gate
 * audits the `unit:*` selector, so it must not be selected BY that selector: a
 * gate that a broken project list can silently switch off is a gate that fails
 * open on exactly the fault it exists to catch. `auth/cloud` is the live proof
 * that this fault happens here - its project is misnamed and none of its tests
 * have ever run in the PR gate.
 *
 * So the gate runs in its own job, from this config, the same way the kit's EE
 * boundary test runs in its own job in `lint.yml`.
 *
 * A non-YAML file in `.github/workflows/` is inert as far as GitHub Actions is
 * concerned - it only reads `*.yml`/`*.yaml` here - and there is precedent
 * beside it: `e2e-experiments.test.ts` is a test about workflow contracts that
 * already lives in this directory.
 */
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    name: 'gate:auth-conformance',
    root: '.',
    include: ['.github/workflows/auth-conformance-gate.test.ts'],
    // Never. A gate that passes because it found no test file to run is the
    // failure mode this whole file exists to avoid.
    passWithNoTests: false,
  },
});
