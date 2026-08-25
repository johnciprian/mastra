#!/usr/bin/env node
/**
 * Copy `@mastra/factory`'s skill assets into this project's Mastra `public/`
 * directory, so `mastra build` places them at the root of `.mastra/output/`.
 *
 * WHY THIS EXISTS
 * `FACTORY_SKILLS_SOURCE_PATH` (mastracode/factory/src/workspace.ts) resolves
 * skills from the first of three locations that exists:
 *
 *   1. next to the built server module  <- what this script produces
 *   2. `dist/../factory-skills`, i.e. inside the installed package
 *   3. `cwd/src/mastra/public/factory-skills`
 *
 * Without this copy the deploy output still worked, but only through (2) —
 * which holds solely because `@mastra/factory` is externalized into the
 * output's `node_modules`. Bundle it instead and the directory disappears,
 * and skills break at runtime with nothing failing at build time.
 *
 * `scripts/validate-output.mjs` asserts (1), so this also turns that silent
 * dependency into a checked one.
 */
import { createRequire } from 'node:module';
import { cp, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const webRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const require = createRequire(join(webRoot, 'package.json'));

// Resolve through the package's own manifest rather than a hardcoded
// node_modules path, so a `link:` workspace checkout and a published install
// both land on the real directory.
const factoryPackageJson = require.resolve('@mastra/factory/package.json');
const source = join(dirname(factoryPackageJson), 'factory-skills');
const destination = join(webRoot, 'src', 'mastra', 'public', 'factory-skills');

if (!existsSync(source)) {
  console.error(
    `copy-factory-skills: no skills at ${source}\n` +
      `  @mastra/factory resolved to ${dirname(factoryPackageJson)}, but it ships no factory-skills/ directory.\n` +
      `  Check that "factory-skills" is still listed in that package's "files".`,
  );
  process.exit(1);
}

// Replace rather than merge: a skill deleted upstream must not survive here.
await rm(destination, { recursive: true, force: true });
await mkdir(dirname(destination), { recursive: true });
await cp(source, destination, { recursive: true });

console.log(`copy-factory-skills: ${relative(webRoot, destination)} <- ${source}`);
