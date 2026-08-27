/**
 * Writes the root-level CommonJS shim `.d.ts` files named by a package's
 * `exports` map, each re-exporting from the matching declaration under `dist/`.
 *
 * WHAT THIS TASK OWNS, AND WHAT IT MUST NOT CLAIM
 *
 * It writes the shims and nothing else. `dist/` belongs to `build:lib`, which
 * runs before it. A package whose `build:patch-commonjs` declares
 * `outputs: ["./**\/*.d.ts"]` therefore claims both: in `@mastra/core` that
 * matched 84 shims and the 1000 declarations `build:lib` had just emitted.
 *
 * Two tasks claiming the same outputs means a cache restore for the later one
 * can clear what the earlier one produced, leaving `dist` with no declarations
 * while the build reports success. The symptom is indistinguishable from having
 * broken the types: every consumer fails with "has no exported member", and the
 * entry point appears to have lost exports it still declares in source. It cost
 * two separate diagnostic cycles before anyone looked here.
 *
 * So the outputs glob has to exclude `dist/**`. See packages/core/turbo.json.
 */
import { readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import { dirname, join, relative } from 'node:path';
import { glob as globby } from 'tinyglobby';

/** Convert Windows backslashes to posix forward slashes */
function slash(p) {
  return p.replaceAll('\\', '/');
}

async function cleanupDtsFiles() {
  const rootPath = process.cwd();
  const files = await globby('./*.d.ts', { cwd: rootPath });

  for (const file of files) {
    await rm(join(rootPath, file), { force: true });
  }
}

async function writeDtsFiles() {
  const rootPath = process.cwd();
  const packageJson = JSON.parse(await readFile(join(rootPath, 'package.json')));

  const exports = packageJson.exports;

  // Handle specific path exports
  for (const [key, value] of Object.entries(exports)) {
    if (key !== '.' && value?.require?.types) {
      const pattern = value.require.types;
      const matches = await globby(pattern, {
        cwd: rootPath,
        absolute: true,
      });

      for (const file of matches) {
        if (key.endsWith('*')) {
          // For wildcard patterns, derive the subpath relative to dist/
          const dir = dirname(file);
          const distRoot = join(rootPath, 'dist');
          const subPath = slash(relative(distRoot, dir));
          // split/join replaces every '*' and doesn't interpret '$' patterns
          // in the replacement (CodeQL js/incomplete-sanitization)
          const filename = key.split('*').join(subPath);

          const targetPath = join(rootPath, filename) + '.d.ts';
          await mkdir(dirname(targetPath), { recursive: true });

          const relPath = slash(relative(dirname(targetPath), file)).replace('/index.d.ts', '');
          await writeFile(targetPath, `export * from './${relPath}';`);
        } else {
          const targetPath = join(rootPath, key) + '.d.ts';
          await mkdir(dirname(targetPath), { recursive: true });

          const relPath = slash(relative(dirname(targetPath), file)).replace('/index.d.ts', '');
          await writeFile(targetPath, `export * from './${relPath}';`);
        }
      }
    }
  }
}

await cleanupDtsFiles();
await writeDtsFiles();
