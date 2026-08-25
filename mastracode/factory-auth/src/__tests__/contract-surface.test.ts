/**
 * The contract's own rules, as tests.
 *
 * `src/__tests__/no-ee-boundary.test.ts` proves this package reaches no `ee/`
 * module. This file proves the narrower thing that keeps it that way: that
 * `src/contract.ts` re-exports what it says it does, only from
 * `@mastra/core/server`, and never the four symbols on that entry point whose
 * declarations are structurally defined in terms of enterprise interfaces.
 *
 * The audit that produced this package found the original symbol list avoided
 * those four by luck of selection rather than by rule. This file is the rule.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as contract from '../contract.js';
import * as rootBarrel from '../index.js';

const THIS_FILE = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = path.resolve(path.dirname(THIS_FILE), '..', '..');
const SRC_DIR = path.join(PACKAGE_ROOT, 'src');
const DIST_DIR = path.join(PACKAGE_ROOT, 'dist');

/**
 * Exported from `@mastra/core/server`, and permanently off limits here.
 *
 * Each one references enterprise interfaces in
 * `packages/core/src/server/types.ts` - `requiresPermission` at line 24,
 * `rbac` at 424 and 560, `fga` at 433 and 567 - and core's type build rolls
 * `@internal/auth` declarations into its emitted types. Re-exporting one would
 * put enterprise declaration text into this Apache-2.0 package's published type
 * surface. Nothing would execute; it would still be a licence problem.
 *
 * A host application that needs these should import them from
 * `@mastra/core/server` directly, at the point of use.
 */
const FORBIDDEN_REEXPORTS = ['MastraAuthConfig', 'ApiRoute', 'ApiRouteHandler', 'StudioConfig'];

/** Every runtime value `./contract` is expected to expose, and nothing else. */
const EXPECTED_VALUE_EXPORTS = [
  'MastraAuthProvider',
  'getRequestHeader',
  'getWebRequest',
  'hasAuthInit',
  'isAuthHttpHandler',
  'isCredentialsProvider',
  'isOrganizationsProvider',
  'isSSOProvider',
  'isSessionProvider',
  'isUserProvider',
];

/**
 * The seven structural capability guards, with the methods each one actually
 * looks for. Note `hasAuthInit`, not `isAuthInit`.
 *
 * The method lists are read from the guards' implementations rather than
 * assumed, and pinning them here is half the point of this test: a provider
 * author's most common mistake is implementing one of a pair, and these are the
 * pairs.
 */
const GUARDS = {
  isSSOProvider: ['getLoginUrl', 'handleCallback'],
  isSessionProvider: ['validateSession', 'createSession'],
  isUserProvider: ['getCurrentUser'],
  isCredentialsProvider: ['signIn'],
  isOrganizationsProvider: ['ensureOrganization', 'isOrganizationAdmin'],
  isAuthHttpHandler: ['handleAuthRequest'],
  hasAuthInit: ['init'],
} as const satisfies Record<string, readonly string[]>;

type GuardName = keyof typeof GUARDS;
const GUARD_NAMES = Object.keys(GUARDS) as GuardName[];

/** An object implementing exactly the named methods. */
function providerWith(methods: readonly string[]): Record<string, () => void> {
  return Object.fromEntries(methods.map(name => [name, () => {}]));
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

/**
 * Comments are stripped before scanning, unlike the enterprise-identifier sweep
 * in the boundary test. The difference is deliberate: naming an enterprise
 * symbol in a comment here is itself worth flagging, but these four names have
 * to be written down in prose - in `src/contract.ts`, and in this file - for the
 * rule to be legible at all.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

function findForbidden(files: string[]): string[] {
  const violations: string[] = [];
  for (const file of files) {
    if (file === THIS_FILE) continue;
    const contents = stripComments(readFileSync(file, 'utf8'));
    const relative = path.relative(PACKAGE_ROOT, file).split(path.sep).join('/');
    for (const name of FORBIDDEN_REEXPORTS) {
      if (new RegExp(`(?<![\\w$])${name}(?![\\w$])`).test(contents)) {
        violations.push(`  ${relative} names '${name}'.`);
      }
    }
  }
  return violations;
}

const FORBIDDEN_MESSAGE =
  `These symbols are exported from '@mastra/core/server' but are structurally defined in terms of\n` +
  `enterprise interfaces, and core rolls those declarations into its emitted types. Re-exporting one\n` +
  `copies enterprise declaration text into this Apache-2.0 package's published type surface.\n\n` +
  `A host application should import them from '@mastra/core/server' at the point of use instead.\n` +
  `Read mastracode/factory-auth/README.md#the-ee-boundary before you change this test.`;

describe('the contract surface', () => {
  it('re-exports the provider base class and the seven capability guards', () => {
    expect(typeof contract.MastraAuthProvider).toBe('function');
    expect(GUARD_NAMES).toHaveLength(7);
    for (const guard of GUARD_NAMES) {
      expect(typeof contract[guard], `${guard} should be a function`).toBe('function');
    }
  });

  it('exposes guards that are structural, so a plain object can satisfy them', () => {
    // Structural, never `instanceof`: a provider built against a duplicate copy
    // of @mastra/core in the dependency tree still narrows correctly, which is
    // why peer-vs-dependency is a hygiene call here and not a correctness one.
    for (const guard of GUARD_NAMES) {
      const required = GUARDS[guard];
      expect(contract[guard]({} as never), `${guard} should reject an empty object`).toBe(false);
      expect(contract[guard](providerWith(required) as never), `${guard} should accept ${required.join(' + ')}`).toBe(
        true,
      );

      // Half a pair is not a capability. This is the mistake the conformance
      // suite exists to catch, so pin it here too.
      for (const omitted of required) {
        if (required.length < 2) continue;
        const partial = providerWith(required.filter(name => name !== omitted));
        expect(contract[guard](partial as never), `${guard} should reject a provider missing ${omitted}`).toBe(false);
      }
    }
  });

  it('re-exports request primitives that read a header without a framework', () => {
    const request = new Request('https://example.test/', { headers: { cookie: 'session=abc' } });
    expect(contract.getRequestHeader(request, 'cookie')).toBe('session=abc');
    expect(contract.getRequestHeader(request, 'authorization')).toBeNull();
    expect(contract.getWebRequest(request)).toBe(request);

    // The Hono-shaped branch, satisfied without importing hono.
    const honoLike = { header: (name: string) => (name === 'cookie' ? 'session=xyz' : undefined) };
    expect(contract.getRequestHeader(honoLike, 'cookie')).toBe('session=xyz');
    expect(contract.getWebRequest(honoLike)).toBeUndefined();
  });

  it('exposes exactly the expected runtime values and no more', () => {
    // An accidental `export *` would show up here rather than in a review.
    expect(Object.keys(contract).sort()).toEqual(EXPECTED_VALUE_EXPORTS);
  });

  it('never names the EE-tainted symbols in source', () => {
    const sourceFiles = listFiles(SRC_DIR, file => file.endsWith('.ts') || file.endsWith('.tsx'));
    expect(sourceFiles.length).toBeGreaterThan(0);

    const violations = findForbidden(sourceFiles);
    if (violations.length > 0) {
      expect.fail(`EE-tainted type surface re-exported.\n\n${violations.join('\n')}\n\n${FORBIDDEN_MESSAGE}`);
    }
    expect(violations).toEqual([]);
  });

  it('never ships the EE-tainted symbols in built output', ctx => {
    if (!existsSync(DIST_DIR)) {
      const message =
        'Contract surface test found no dist/, so the built-output half proved nothing.\n' +
        'Build the package first: pnpm --filter ./mastracode/factory-auth build';
      if (process.env.CI) expect.fail(message);
      ctx.skip(message);
      return;
    }

    const builtFiles = listFiles(
      DIST_DIR,
      file => file.endsWith('.d.ts') || file.endsWith('.js') || file.endsWith('.cjs'),
    );
    expect(builtFiles.length).toBeGreaterThan(0);

    const violations = findForbidden(builtFiles);
    if (violations.length > 0) {
      expect.fail(`EE-tainted type surface re-exported.\n\n${violations.join('\n')}\n\n${FORBIDDEN_MESSAGE}`);
    }
    expect(violations).toEqual([]);
  });
});

/**
 * Everything the root barrel is allowed to expose at runtime: `./contract`,
 * `./identity` and `./capabilities`, and nothing else.
 *
 * A reviewer appended `export * from './cookie.js'` to `src/index.ts` and every
 * check in this package passed - typecheck, build, lint and the whole suite -
 * while `node:crypto` entered the root graph. The barrel's documented invariant
 * had no test behind it. This is that test.
 */
const EXPECTED_ROOT_EXPORTS = [
  'DEFAULT_CREDENTIALS_BASE_PATH',
  'DEFAULT_PROVIDER_HINT',
  'MastraAuthProvider',
  'getRequestHeader',
  'getWebRequest',
  'hasAuthInit',
  'isAuthHttpHandler',
  'isCredentialsProvider',
  'isIdentityProvider',
  'isOrganizationsProvider',
  'isSSOProvider',
  'isSessionProvider',
  'isUserProvider',
  'toAuthDescriptor',
  'toAuthIdentity',
];

/** The three modules `src/index.ts` may re-export, in the order it lists them. */
const ALLOWED_ROOT_REEXPORTS = ['./contract.js', './identity.js', './capabilities.js'];

/**
 * Node builtins that must not appear anywhere in the root barrel's built graph.
 *
 * `node:crypto` is the one that matters: it is what `./cookie` and
 * `./oauth-state` need and what the root barrel promises to stay clear of.
 * `vitest` is here because `./conformance` imports it and a barrel that reached
 * it would put a test framework in a production graph.
 */
const FORBIDDEN_ROOT_GRAPH_SPECIFIERS = ['node:crypto', 'crypto', 'vitest'];

/** Follow relative imports out of a built module, returning every external specifier. */
function externalSpecifiersOf(entry: string): { modules: string[]; externals: string[] } {
  const visited = new Set<string>();
  const externals = new Set<string>();
  const queue = [entry];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (visited.has(file) || !existsSync(file)) continue;
    visited.add(file);
    for (const match of readFileSync(file, 'utf8').matchAll(/(?:from|import)\s*['"]([^'"]+)['"]/g)) {
      const specifier = match[1]!;
      if (!specifier.startsWith('.')) {
        externals.add(specifier);
        continue;
      }
      const resolved = path.resolve(path.dirname(file), specifier);
      queue.push(existsSync(resolved) ? resolved : `${resolved}.js`);
    }
  }
  return { modules: [...visited], externals: [...externals] };
}

describe('the root barrel', () => {
  it('re-exports the three pure modules and nothing else', () => {
    const source = stripComments(readFileSync(path.join(SRC_DIR, 'index.ts'), 'utf8'));
    const reexported = [...source.matchAll(/from\s*'([^']+)'/g)].map(match => match[1]!);
    expect(reexported).toEqual(ALLOWED_ROOT_REEXPORTS);
  });

  it('exposes exactly the expected runtime values and no more', () => {
    expect(Object.keys(rootBarrel).sort()).toEqual(EXPECTED_ROOT_EXPORTS);
  });

  it('never reaches node:crypto or a test framework in built output', ctx => {
    const entry = path.join(DIST_DIR, 'index.js');
    if (!existsSync(entry)) {
      const message =
        'Root barrel test found no dist/index.js, so the graph half proved nothing.\n' +
        'Build the package first: pnpm --filter ./mastracode/factory-auth build';
      if (process.env.CI) expect.fail(message);
      ctx.skip(message);
      return;
    }

    const { modules, externals } = externalSpecifiersOf(entry);
    // A walk that followed nothing would pass this vacuously.
    expect(modules.length).toBeGreaterThan(1);

    const violations = externals.filter(specifier => FORBIDDEN_ROOT_GRAPH_SPECIFIERS.includes(specifier));
    if (violations.length > 0) {
      expect.fail(
        `The root barrel reached ${violations.map(v => `'${v}'`).join(', ')} through its built graph.\n\n` +
          'The root export is the pure layer: importing it must not pull in the session cookie, the OAuth state\n' +
          'codec, or a test framework. Those live behind ./cookie, ./oauth-state, ./testing and ./conformance,\n' +
          'and src/index.ts must not re-export them.\n\n' +
          `Reached: ${externals.sort().join(', ')}`,
      );
    }
    expect(violations).toEqual([]);
  });
});
