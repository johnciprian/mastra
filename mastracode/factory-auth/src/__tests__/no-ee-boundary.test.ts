/**
 * The Enterprise Edition boundary, as a test.
 *
 * `@mastra/factory-auth` is Apache-2.0. Every directory named `ee/` in this
 * repository is licensed under the Mastra Enterprise Edition License
 * (`ee/LICENSE`), so no module in this package may reach one.
 *
 * Read this before you change anything here.
 *
 * WHY THIS RESOLVES SOURCE, NOT BUILT OUTPUT
 * `packages/core/tsdown.config.ts` `alwaysBundle`s `@internal/auth`, so
 * enterprise code is INLINED into `@mastra/core`'s `dist` and lands in shared
 * chunks whose filenames carry no `ee` segment. A scan of built output for
 * `/ee` specifiers therefore returns green on `@mastra/core/auth` - the single
 * import this package exists to keep out. Resolving over source through the
 * repo's shared workspace alias table keeps `ee/` a literal path segment.
 *
 * WHY TYPE IMPORTS ARE SKIPPED FOR THE GRAPH ASSERTION
 * `packages/core/src/server/types.ts` type-imports three EE interface modules.
 * Those edges are erased at runtime (`verbatimModuleSyntax` is on), which is
 * exactly the property that makes `@mastra/core/server` safe: measured, its
 * runtime graph is ee=0 while its all-imports graph is ee=28. Without
 * `skipTypeImports` this assertion would go red on correct code.
 *
 * The gap that opens is closed by the third assertion, which scans built `.d.ts`
 * output for EE identifiers - a type-only path into EE carries no code but is
 * still a licence problem in a published Apache-2.0 package's type surface.
 *
 * WHAT THIS TEST CANNOT DO
 * It resolves specifiers, so a lazy `await import()` behind a runtime flag is
 * seen, but code loaded by string concatenation is not. Lint (`eslint.config.js`)
 * covers source syntax and runs without a build; this covers what a dependency
 * drags in and survives a version bump. Neither is sufficient alone.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { isBuiltin } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const THIS_FILE = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = path.resolve(path.dirname(THIS_FILE), '..', '..');
const REPO_ROOT = path.resolve(PACKAGE_ROOT, '..', '..');
const SRC_DIR = path.join(PACKAGE_ROOT, 'src');
const DIST_DIR = path.join(PACKAGE_ROOT, 'dist');
const WEBPACK_CONFIG = path.join(PACKAGE_ROOT, 'test', 'madge.webpack.config.cjs');
const README_POINTER = 'Read mastracode/factory-auth/README.md#the-ee-boundary before you change this test.';

/**
 * A whole path segment equal to `ee`. Never a substring: the repo contains
 * `Tree/`, `deepeval`, `speechify`, `estree-walker`, `chunk-3ee1b2.js` and many
 * other innocent matches for a naive `includes('ee')`.
 */
const EE_SEGMENT = /(?:^|\/)ee(?:\/|$)/;

/**
 * External specifiers this package is allowed to import, mapped to the source
 * files allowed to import them. Fail-closed on purpose: a denylist can be routed
 * around, an allowlist cannot. Adding a line here is a reviewable diff, and the
 * reviewer's job is to confirm the new specifier's own graph is ee-free.
 */
const ALLOWED_EXTERNAL_SPECIFIERS = new Map<string, RegExp>([
  // The one import site. Measured ee=0 in the runtime graph.
  ['@mastra/core/server', /^src\//],
  // Only the conformance suite and this package's own tests may touch a runner.
  ['vitest', /^src\/(?:conformance|__tests__)\//],
  // The module-graph resolver used by this test, and nowhere else.
  ['madge', /^src\/__tests__\//],
]);

/**
 * Specifiers the resolver is allowed to leave unresolved, each with a reason.
 * Node builtins are handled separately and never need a line here.
 */
const ALLOWED_UNRESOLVED = new Map<string, string>();

/** EE-authored identifiers. A hit in built output means EE reached this package. */
const EE_IDENTIFIERS = [
  'MastraFGAPermissions',
  'MastraFGAPermissionInput',
  'IFGAProvider',
  'IRBACProvider',
  'FGADeniedError',
  'StaticRBACProvider',
  'buildCapabilities',
  'PERMISSION_PATTERNS',
  'isEELicenseValid',
  'startLicenseValidation',
  'mastra.eeTelemetryBridge',
];

interface ExportEntry {
  /** The subpath as written in package.json, e.g. `.` or `./cookie`. */
  subpath: string;
  /** Repo-relative source file behind it, e.g. `mastracode/factory-auth/src/cookie.ts`. */
  sourceRelativeToRepo: string;
  /** Absolute path to that source file. */
  sourceAbsolute: string;
  exists: boolean;
}

function toRepoRelative(absoluteOrRelative: string): string {
  const absolute = path.isAbsolute(absoluteOrRelative)
    ? absoluteOrRelative
    : path.resolve(REPO_ROOT, absoluteOrRelative);
  return path.relative(REPO_ROOT, absolute).split(path.sep).join('/');
}

/**
 * Whole-segment `ee` test for a resolved module path.
 *
 * Anything outside the repo is rejected first, and that is not a nicety: pnpm's
 * global virtual store shards content by the first two hex characters of a hash,
 * so `~/.local/share/pnpm/store/v11/files/ee/<hash>` exists on any machine that
 * has run an install here. Its `ee` segment has nothing to do with enterprise
 * code.
 */
function isEeModulePath(modulePath: string): boolean {
  const relative = toRepoRelative(modulePath);
  if (relative === '' || relative.startsWith('../')) return false;
  return EE_SEGMENT.test(relative);
}

function listFiles(dir: string, predicate: (file: string) => boolean): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules') continue;
      found.push(...listFiles(full, predicate));
    } else if (entry.isFile() && predicate(full)) {
      found.push(full);
    }
  }
  return found;
}

/** Strip comments so prose about `@mastra/core/auth` is never read as an import. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/** Every module specifier in a file: static, side-effect, dynamic and require. */
function readSpecifiers(file: string): string[] {
  const source = stripComments(readFileSync(file, 'utf8'));
  const specifiers: string[] = [];
  const patterns = [
    /\bfrom\s*['"]([^'"]+)['"]/g,
    /^[ \t]*import\s+['"]([^'"]+)['"]/gm,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier) specifiers.push(specifier);
    }
  }
  return specifiers;
}

function readExportEntries(): ExportEntry[] {
  const manifest = JSON.parse(readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
    exports: Record<string, unknown>;
  };

  const entries: ExportEntry[] = [];
  for (const [subpath, value] of Object.entries(manifest.exports)) {
    if (subpath === './package.json') continue;
    const importCondition = (value as { import?: { default?: string } }).import;
    const distPath = importCondition?.default;
    if (typeof distPath !== 'string') {
      throw new Error(`package.json exports["${subpath}"] has no import.default path. ${README_POINTER}`);
    }
    const sourceRelativeToPackage = distPath.replace(/^\.\/dist\//, 'src/').replace(/\.js$/, '.ts');
    const sourceAbsolute = path.join(PACKAGE_ROOT, sourceRelativeToPackage);
    entries.push({
      subpath,
      sourceRelativeToRepo: toRepoRelative(sourceAbsolute),
      sourceAbsolute,
      exists: existsSync(sourceAbsolute),
    });
  }
  return entries;
}

/** Shortest chain from one of this package's entries to `target`, as repo paths. */
function findChain(graph: Record<string, string[]>, roots: string[], target: string): string[] {
  const queue: string[][] = roots.filter(root => graph[root] !== undefined).map(root => [root]);
  const seen = new Set(roots);
  while (queue.length > 0) {
    const chain = queue.shift()!;
    const head = chain[chain.length - 1]!;
    if (head === target) return chain;
    for (const next of graph[head] ?? []) {
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push([...chain, next]);
    }
  }
  return [target];
}

function formatViolations(graph: Record<string, string[]>, roots: string[], offenders: string[]): string {
  const count = offenders.length;
  const lines = [
    'EE boundary violation. @mastra/factory-auth is Apache-2.0 and must not reach ee/ code.',
    '',
    `${count} module${count === 1 ? '' : 's'} in the resolved graph ${count === 1 ? 'is' : 'are'} inside an ee/ directory:`,
    '',
  ];

  for (const offender of offenders) {
    const chain = findChain(graph, roots, offender);
    lines.push(`  ${offender}`);
    lines.push(`    ${chain[0]}`);
    chain.slice(1).forEach((hop, index) => {
      // The marker sits on the first hop out of this package: that is the only
      // line the reader can actually delete.
      lines.push(`      -> ${hop}${index === 0 ? '      <- remove this import' : ''}`);
    });
    lines.push('');
  }

  lines.push("Fix the import marked above. The contract and guards live in '@mastra/core/server'.");
  lines.push(README_POINTER);
  return lines.join('\n');
}

const exportEntries = readExportEntries();
const entryRoots = exportEntries.filter(entry => entry.exists).map(entry => entry.sourceRelativeToRepo);

describe('EE licence boundary', () => {
  it('scans every entry point declared in package.json exports', () => {
    const missing = exportEntries.filter(entry => !entry.exists);
    if (missing.length > 0) {
      expect.fail(
        `EE boundary test scanned ${entryRoots.length} of the ${exportEntries.length} entry points in package.json exports. ` +
          `Every published entry must be scanned.\n` +
          `Not scanned: ${missing.map(entry => entry.subpath).join(', ')}\n` +
          `Each of those declares a dist path with no source file behind it, which is also ERR_MODULE_NOT_FOUND in a consumer.`,
      );
    }
    expect(entryRoots.length).toBe(exportEntries.length);
  });

  it('reaches no ee/ module through the resolved source graph', async () => {
    const madge = (await import('madge')).default;
    // Entries are resolved against process.cwd(), so they are passed absolute.
    // `baseDir` only controls how graph keys are reported, which is why every
    // key below is repo-relative.
    const result = await madge(
      exportEntries.filter(entry => entry.exists).map(entry => entry.sourceAbsolute),
      {
        baseDir: REPO_ROOT,
        // Absolute: filing-cabinet resolves this against process.cwd(), and a
        // relative path silently yields an empty resolver that skips everything.
        webpackConfig: WEBPACK_CONFIG,
        fileExtensions: ['ts', 'tsx', 'js', 'jsx'],
        detectiveOptions: { ts: { skipTypeImports: true }, tsx: { skipTypeImports: true } },
      },
    );

    const graph = result.obj() as Record<string, string[]>;
    const modules = Object.keys(graph);

    // False-green guard 1: a boundary test that looked at nothing is worse than
    // no test, because it converts ignorance into a green check.
    if (modules.length === 0) {
      expect.fail(
        'EE boundary test scanned 0 modules, so it proved nothing.\n' +
          'Resolution starts from the source files behind package.json exports. Check that those files exist ' +
          'and that dependencies are installed: pnpm install',
      );
    }

    // False-green guard 2: every declared entry must be present in the graph.
    const missingRoots = entryRoots.filter(root => graph[root] === undefined);
    if (missingRoots.length > 0) {
      expect.fail(
        `EE boundary test scanned ${entryRoots.length - missingRoots.length} of the ${exportEntries.length} entry points in package.json exports. ` +
          `Every published entry must be scanned.\n` +
          `Not scanned: ${missingRoots.join(', ')}`,
      );
    }

    // The boundary assertion runs before the last false-green guard, so a real
    // violation is reported as a violation rather than as whatever npm package
    // the offending dependency happened to drag in behind it.
    const offenders = modules.filter(isEeModulePath).sort();
    if (offenders.length > 0) {
      expect.fail(formatViolations(graph, entryRoots, offenders));
    }
    expect(offenders).toEqual([]);

    // False-green guard 3: an unresolvable import is not proof of anything.
    //
    // Scoped to this package's own files on purpose. The shared alias table
    // empties `exportsFields` / `mainFields` to force workspace resolution onto
    // source, and the cost is that ordinary npm packages deep inside a workspace
    // dependency (`@isaacs/ttlcache` inside @mastra/core, for one) do not
    // resolve. Those live outside the repo and cannot be ee/ code. What must
    // resolve is every specifier this package writes itself - plus anything
    // anywhere whose text has an `ee` segment, which is the one way an
    // unresolvable specifier could hide a violation.
    const kitPrefix = `${toRepoRelative(SRC_DIR)}/`;
    const kitSpecifiers = new Set(
      modules
        .filter(module => module.startsWith(kitPrefix))
        .flatMap(module => readSpecifiers(path.join(REPO_ROOT, module))),
    );
    const skipped = result
      .warnings()
      .skipped.filter(specifier => !specifier.startsWith('node:') && !isBuiltin(specifier))
      .filter(specifier => !ALLOWED_UNRESOLVED.has(specifier))
      .filter(specifier => kitSpecifiers.has(specifier) || EE_SEGMENT.test(specifier));
    if (skipped.length > 0) {
      const importers = new Map<string, string>();
      for (const specifier of skipped) {
        const importer = modules.find(module => readSpecifiers(path.join(REPO_ROOT, module)).includes(specifier));
        importers.set(specifier, importer ?? 'an unknown file in the scanned graph');
      }
      expect.fail(
        skipped
          .map(
            specifier =>
              `EE boundary test could not resolve '${specifier}', imported by ${importers.get(specifier)}. ` +
              `An unresolvable import is not proof of anything. Resolve it, or add it to the documented allowlist ` +
              `at the top of this test with a reason.`,
          )
          .join('\n'),
      );
    }
  });

  it('imports only allowlisted external specifiers', () => {
    const sourceFiles = listFiles(SRC_DIR, file => file.endsWith('.ts') || file.endsWith('.tsx'));
    expect(sourceFiles.length).toBeGreaterThan(0);

    const violations: string[] = [];
    for (const file of sourceFiles) {
      const relativeToPackage = path.relative(PACKAGE_ROOT, file).split(path.sep).join('/');
      for (const specifier of readSpecifiers(file)) {
        if (specifier.startsWith('.') || specifier.startsWith('/')) continue;
        if (specifier.startsWith('node:') || isBuiltin(specifier)) continue;

        const allowedIn = ALLOWED_EXTERNAL_SPECIFIERS.get(specifier);
        if (!allowedIn) {
          violations.push(`  ${relativeToPackage} imports '${specifier}', which is not on the allowlist.`);
          continue;
        }
        if (!allowedIn.test(relativeToPackage)) {
          violations.push(
            `  ${relativeToPackage} imports '${specifier}', which is allowed only in files matching ${String(allowedIn)}.`,
          );
        }
      }
    }

    if (violations.length > 0) {
      expect.fail(
        'EE boundary violation. @mastra/factory-auth is Apache-2.0 and must not reach ee/ code.\n\n' +
          'An external specifier outside the allowlist can reach ee/ without ever naming it: @mastra/core bundles\n' +
          '@internal/auth into its dist, so enterprise code arrives with no ee path segment anywhere.\n\n' +
          `${violations.join('\n')}\n\n` +
          "Use '@mastra/core/server', or add the specifier to ALLOWED_EXTERNAL_SPECIFIERS with a reason once you have\n" +
          `confirmed its own graph is ee-free.\n${README_POINTER}`,
      );
    }
    expect(violations).toEqual([]);
  });

  it.skipIf(!existsSync(DIST_DIR))('ships no enterprise identifiers in built output', () => {
    const builtFiles = listFiles(
      DIST_DIR,
      file => file.endsWith('.js') || file.endsWith('.cjs') || file.endsWith('.d.ts'),
    );

    if (builtFiles.length === 0) {
      expect.fail(
        'EE boundary test scanned 0 modules, so it proved nothing.\n' +
          'Build the package first: pnpm --filter ./mastracode/factory-auth build',
      );
    }

    const violations: string[] = [];
    for (const file of builtFiles) {
      const relativeToPackage = path.relative(PACKAGE_ROOT, file).split(path.sep).join('/');
      const contents = readFileSync(file, 'utf8');

      for (const identifier of EE_IDENTIFIERS) {
        if (contents.includes(identifier)) {
          violations.push(`  ${relativeToPackage} contains the enterprise identifier '${identifier}'.`);
        }
      }
      for (const specifier of readSpecifiers(file)) {
        if (EE_SEGMENT.test(specifier.replace(/^\0/, '').replace(/[?#].*$/, ''))) {
          violations.push(`  ${relativeToPackage} imports '${specifier}', which has an ee path segment.`);
        }
      }
    }

    if (violations.length > 0) {
      expect.fail(
        'EE boundary violation. @mastra/factory-auth is Apache-2.0 and must not reach ee/ code.\n\n' +
          'This is the gap that skipping type imports opens: an erased import carries no code, but an enterprise\n' +
          "declaration copied into a published Apache-2.0 package's .d.ts is still a licence problem.\n\n" +
          `${violations.join('\n')}\n\n` +
          `${README_POINTER}`,
      );
    }
    expect(violations).toEqual([]);
  });
});
