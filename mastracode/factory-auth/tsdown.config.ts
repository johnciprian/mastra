import { generateTypes } from '@internal/types-builder';
import { defineConfig } from 'tsdown';

/**
 * Entries are listed explicitly, one per subpath in package.json `exports`.
 * Never switch to a `./*` wildcard export: every internal file would become
 * public API. See e2e-tests/pkg-outputs/bundle.test.ts and issue #15758.
 *
 * `src/index.ts` must stay in this list. Rolldown derives output paths from the
 * common ancestor of all entries, so dropping it shifts the base and moves every
 * dist path out from under the exports map.
 */
export default defineConfig({
  entry: [
    'src/index.ts',
    'src/contract.ts',
    'src/identity.ts',
    'src/capabilities.ts',
    'src/organizations.ts',
    'src/cookie.ts',
    'src/oauth-state.ts',
    'src/testing/index.ts',
    'src/conformance/index.ts',
    '!src/**/*.test.ts',
    '!src/**/__tests__/**',
  ],
  format: ['esm', 'cjs'],
  fixedExtension: false,
  nodeProtocol: 'strip',
  clean: true,
  dts: false,
  treeshake: true,
  sourcemap: true,
  onSuccess: async () => {
    await generateTypes(process.cwd());
  },
});
