/**
 * The published surface, as a checklist.
 *
 * Every other test file in this package asserts what a symbol *does*. This one
 * asserts which symbols there are, because that is the question the rest of the
 * suite cannot answer: a test proves the behaviour of the exports it happens to
 * import, and an export nobody imported is invisible to all of them at once.
 *
 * WHY THIS READS `dist/`, NOT `src/`
 *
 * `package.json` `exports` names nine subpaths and every one of them points at a
 * built `.d.ts`. That file is what a consumer's `tsc` resolves, so it is the only
 * honest statement of the surface: re-exports are flattened into it, `export *`
 * has already been followed, and a symbol that exists in source but never reaches
 * a declaration file is not API. Reading source instead would inventory this
 * package's intentions rather than its output.
 *
 * The nine lists below are therefore the checklist. Adding, removing or renaming
 * anything a consumer can import is a diff on this file, and a diff on this file
 * is the review.
 *
 * WHY THE LISTS SPLIT VALUES FROM TYPES
 *
 * They are checked against different things and they fail in different ways.
 *
 * - A **value** has to exist twice over: in the `.d.ts` and on the module object
 *   at runtime. A type that claims a runtime export the JavaScript does not have
 *   is a `TypeError` in a consumer with a green build here, so both halves are
 *   asserted and cross-checked.
 * - A **type** exists only in the `.d.ts`. There is no runtime half to check, and
 *   there is no compile-time half either: `tsconfig.json` excludes every
 *   `.test.ts` and vitest transpiles without typechecking, so a `satisfies`
 *   written in this directory would be read by nothing at all. The declaration
 *   file is where a type export is observable, so that is where it is pinned.
 *
 * `src/testing/index.ts` carries the one type-level assertion this package can
 * actually enforce - `FakeGuardNarrowing` - and it lives in a non-test file for
 * exactly that reason. `pnpm check` reads it; this file cannot.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import * as capabilities from '../capabilities.js';
import * as conformance from '../conformance/index.js';
import * as contract from '../contract.js';
import * as cookie from '../cookie.js';
import * as identity from '../identity.js';
import * as rootBarrel from '../index.js';
import * as oauthState from '../oauth-state.js';
import * as organizations from '../organizations.js';
import * as testing from '../testing/index.js';

const THIS_FILE = fileURLToPath(import.meta.url);
const PACKAGE_ROOT = path.resolve(path.dirname(THIS_FILE), '..', '..');
const DIST_DIR = path.join(PACKAGE_ROOT, 'dist');

/** One subpath's surface, split by what can be checked about each half. */
interface Surface {
  /** Exports with a runtime form: functions, classes, consts. */
  readonly values: readonly string[];
  /** Exports with no runtime form: interfaces and type aliases. */
  readonly types: readonly string[];
  /** The module object, imported from source, for the runtime half. */
  readonly module: Record<string, unknown>;
}

// ============================================================================
// The inventory
// ============================================================================

/**
 * `./contract` - the single import site.
 *
 * Ten values and twelve types, all of them re-exported from
 * `@mastra/core/server` and none of them declared here. That is why this entry
 * is worth pinning twice over: the names come from another package, so they can
 * change without a line of this package's source changing, and
 * `src/__tests__/contract-surface.test.ts` asserts the other half - that the four
 * EE-tainted symbols on that same entry point never join them.
 */
const CONTRACT: Omit<Surface, 'module'> = {
  values: [
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
  ],
  types: [
    'AuthInitContext',
    'HonoRequestLike',
    'IAuthHttpHandler',
    'IAuthInit',
    'ICredentialsProvider',
    'IMastraAuthProvider',
    'IOrganizationsProvider',
    'ISSOProvider',
    'ISessionProvider',
    'IUserProvider',
    'MastraAuthProviderOptions',
    'MastraAuthRequest',
  ],
};

/** `./identity` - the normalizer, its shape, and the provider escape hatch. */
const IDENTITY: Omit<Surface, 'module'> = {
  values: ['isIdentityProvider', 'toAuthIdentity'],
  types: ['AuthIdentity', 'IIdentityProvider'],
};

/** `./capabilities` - the descriptor a sign-in screen renders from. */
const CAPABILITIES: Omit<Surface, 'module'> = {
  values: ['DEFAULT_CREDENTIALS_BASE_PATH', 'DEFAULT_PROVIDER_HINT', 'toAuthDescriptor'],
  types: [
    'AuthDescriptor',
    'AuthDescriptorOverrides',
    'AuthFeatureDescriptor',
    'AuthProviderHint',
    'AuthSignInDescriptor',
    'AuthSignInKind',
  ],
};

/** `./organizations` - the wrapper, the resolver, and the shared derivation. */
const ORGANIZATIONS: Omit<Surface, 'module'> = {
  values: [
    'SYNTHETIC_ORGANIZATION_PREFIX',
    'isSyntheticOrganizationId',
    'resolveOrganizationId',
    'syntheticOrganizationId',
    'withSyntheticOrganizations',
  ],
  types: ['SyntheticOrganizationOptions'],
};

/** `./cookie` - the host-owned session cookie. Reaches `node:crypto`. */
const COOKIE: Omit<Surface, 'module'> = {
  values: [
    'DEFAULT_SESSION_MAX_AGE_SECONDS',
    'SESSION_COOKIE_HOST_NAME',
    'SESSION_COOKIE_NAME',
    'clearSessionCookie',
    'mintSessionCookie',
    'readSessionCookie',
    'sessionCookieName',
    'toCookieHeader',
  ],
  types: ['MintSessionCookieOptions', 'ReadSessionCookieOptions', 'SessionCookieSite'],
};

/** `./oauth-state` - the `state` codec. Reaches `node:crypto`. */
const OAUTH_STATE: Omit<Surface, 'module'> = {
  values: ['DEFAULT_RETURN_TO', 'OAUTH_STATE_DELIMITER', 'decodeState', 'encodeState', 'parseStateId'],
  types: ['DecodedOAuthState'],
};

/** `./testing` - the fakes. Runner-free, so a browser fixture can load them. */
const TESTING: Omit<Surface, 'module'> = {
  values: [
    'AUTH_OBLIGATIONS',
    'AUTH_OBLIGATION_SUMMARY',
    'FAKE_COOKIE_NAME',
    'FAKE_STATE_DELIMITER',
    'FAKE_TOKEN',
    'FAKE_TOKEN_EXPIRES_AT',
    'createCallLog',
    'fakeProvider',
    'fakeViolating',
    'fullyCapableFake',
    'withCredentials',
    'withHttpHandler',
    'withInit',
    'withOrganizations',
    'withSSO',
    'withSession',
    'withUser',
  ],
  types: [
    'AuthObligation',
    'FakeAuthPayload',
    'FakeCall',
    'FakeCallLog',
    'FakeCredentialsCapability',
    'FakeCredentialsOptions',
    'FakeCredentialsResult',
    'FakeGuardNarrowing',
    'FakeHttpHandlerCapability',
    'FakeHttpHandlerOptions',
    'FakeInitCapability',
    'FakeInitOptions',
    'FakeMethod',
    'FakeOrganizationsCapability',
    'FakeOrganizationsOptions',
    'FakeProvider',
    'FakeProviderOptions',
    'FakeSSOCallbackResult',
    'FakeSSOCapability',
    'FakeSSOLoginConfig',
    'FakeSSOOptions',
    'FakeSession',
    'FakeSessionCapability',
    'FakeSessionOptions',
    'FakeUser',
    'FakeUserCapability',
    'FakeUserOptions',
    'FullyCapableFake',
    'FullyCapableFakeOptions',
  ],
};

/** `./conformance` - the suite. The one subpath that imports a test runner. */
const CONFORMANCE: Omit<Surface, 'module'> = {
  values: [
    'AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX',
    'AUTH_OBLIGATION_COUNT',
    'AUTH_OBLIGATION_GUIDANCE',
    'CONFORMANCE_DOCS_URL',
    'KNOWN_FAILURE_TITLE_PREFIX',
    'authConformanceChecks',
    'describeAuthProvider',
    'formatConformanceFailure',
    'formatKnownFailure',
    'formatStaleKnownFailure',
    'isFixtureFailureCode',
    'readFailureCode',
    'runAuthConformanceCheck',
  ],
  types: [
    'AuthConformanceCheck',
    'AuthConformanceFailureCode',
    'AuthConformanceKnownFailure',
    'AuthConformanceOutcome',
    'AuthConformanceSSOOptions',
    'AuthObligationGuidance',
    'AuthProviderConformanceOptions',
    'ConformanceFailure',
    'KnownFailureReport',
    'StaleKnownFailureKind',
    'StaleKnownFailureReport',
  ],
};

/**
 * `.` - the root barrel, which is `./contract` + `./identity` + `./capabilities`
 * and nothing else.
 *
 * Composed rather than written out, and that is the assertion rather than a
 * shortcut: the barrel's whole contract is that it re-exports those three
 * modules entirely and adds nothing of its own. A hand-copied list would go green
 * on a barrel that had quietly dropped one symbol and gained another. The
 * composition cannot, and `src/__tests__/contract-surface.test.ts` pins the other
 * direction - that `src/index.ts` names exactly those three files.
 */
const ROOT: Omit<Surface, 'module'> = {
  values: [...CONTRACT.values, ...IDENTITY.values, ...CAPABILITIES.values],
  types: [...CONTRACT.types, ...IDENTITY.types, ...CAPABILITIES.types],
};

/** Every published subpath, keyed as `package.json` spells it. */
const SURFACE: Readonly<Record<string, Surface>> = {
  '.': { ...ROOT, module: rootBarrel },
  './contract': { ...CONTRACT, module: contract },
  './identity': { ...IDENTITY, module: identity },
  './capabilities': { ...CAPABILITIES, module: capabilities },
  './organizations': { ...ORGANIZATIONS, module: organizations },
  './cookie': { ...COOKIE, module: cookie },
  './oauth-state': { ...OAUTH_STATE, module: oauthState },
  './testing': { ...TESTING, module: testing },
  './conformance': { ...CONFORMANCE, module: conformance },
};

/**
 * How many symbols a consumer can import in total, counting a name shared by the
 * root and its source module once.
 *
 * A single number, so that "one export appeared and another vanished" cannot net
 * out to a green run across nine separate list comparisons.
 */
const TOTAL_DISTINCT_EXPORTS = 128;

// ============================================================================
// Reading the built declarations
// ============================================================================

/** `package.json`, only as far as this file cares about it. */
interface Manifest {
  exports: Record<string, { import?: { types?: string } } | string>;
}

const manifest = JSON.parse(readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as Manifest;

/** The `.d.ts` a consumer's `tsc` resolves for one subpath. */
function declarationFileFor(subpath: string): string {
  const entry = manifest.exports[subpath];
  const types = typeof entry === 'object' ? entry.import?.types : undefined;
  if (typeof types !== 'string') {
    throw new Error(`package.json exports["${subpath}"] declares no import.types path.`);
  }
  return path.join(PACKAGE_ROOT, types);
}

/**
 * Every name a `.d.ts` exports, following `export *` into sibling declarations.
 *
 * Deliberately a reader rather than a compiler. `typescript` is not on the EE
 * boundary test's import allowlist and does not belong in this package's test
 * graph for one file's benefit; the generated declarations are regular enough to
 * read directly, and a parse that silently found nothing is caught by the
 * emptiness guard in the caller.
 *
 * `A as B` exports `B`, which is why the alias is read from the right of the
 * `as` rather than the left.
 */
function exportedNamesOf(file: string, seen: Set<string> = new Set()): Set<string> {
  const names = new Set<string>();
  if (seen.has(file)) return names;
  seen.add(file);

  const source = readFileSync(file, 'utf8');

  // `export * from './contract.js'` - the only form that needs following.
  for (const match of source.matchAll(/^export\s+\*\s+from\s+'(\.[^']+)';/gm)) {
    const target = path.resolve(path.dirname(file), match[1]!.replace(/\.js$/, '.d.ts'));
    for (const name of exportedNamesOf(target, seen)) names.add(name);
  }

  // `export { A, B }` and `export type { A, B }`, with or without a `from`.
  for (const match of source.matchAll(/^export\s+(?:type\s+)?\{([^}]*)\}/gm)) {
    for (const clause of match[1]!.split(',')) {
      const parts = clause
        .trim()
        .replace(/^type\s+/, '')
        .split(/\s+as\s+/);
      const name = parts[parts.length - 1]?.trim();
      if (name !== undefined && /^[A-Za-z_$][\w$]*$/.test(name)) names.add(name);
    }
  }

  // `export declare function f`, `export interface I`, `export type T = ...`.
  const declaration =
    /^export\s+(?:declare\s+)?(?:abstract\s+)?(?:const|let|var|function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/gm;
  for (const match of source.matchAll(declaration)) names.add(match[1]!);

  return names;
}

/** Skip with a message when the package has not been built, as its siblings do. */
function requireDist(ctx: { skip: (reason: string) => void }): boolean {
  if (existsSync(DIST_DIR)) return true;
  const message =
    'Public surface test found no dist/, so the declaration half proved nothing.\n' +
    'Build the package first: pnpm --filter ./mastracode/factory-auth build';
  if (process.env.CI) expect.fail(message);
  ctx.skip(message);
  return false;
}

const subpaths = Object.keys(SURFACE);

// ============================================================================
// The tests
// ============================================================================

describe('the published surface', () => {
  it('inventories every subpath package.json exports', () => {
    // `./package.json` is a file, not a module surface, so it is the one
    // documented omission. Anything else missing here is a subpath a consumer can
    // import that no list below describes.
    const published = Object.keys(manifest.exports).filter(subpath => subpath !== './package.json');
    expect(published.sort()).toEqual([...subpaths].sort());
    expect(published).toHaveLength(9);
  });

  it.each(subpaths)('%s exports exactly the inventoried names', (subpath: string) => {
    const { values, types } = SURFACE[subpath]!;
    const declared = new Set([...values, ...types]);

    // A name in both halves would make the two assertions below disagree about
    // what it is, and one of them would be wrong without saying so.
    expect(declared.size, `${subpath} lists a name as both a value and a type`).toBe(values.length + types.length);
  });

  it.each(subpaths)('%s declares exactly the inventoried names in its built .d.ts', (subpath: string, ...rest) => {
    const ctx = rest[rest.length - 1] as { skip: (reason: string) => void };
    if (!requireDist(ctx)) return;

    const { values, types } = SURFACE[subpath]!;
    const file = declarationFileFor(subpath);
    expect(existsSync(file), `${subpath} declares ${path.relative(PACKAGE_ROOT, file)}, which does not exist`).toBe(
      true,
    );

    const found = [...exportedNamesOf(file)].sort();
    // A reader that matched nothing would agree with an empty inventory, and no
    // subpath has one.
    expect(found.length, `no exports parsed out of ${path.relative(PACKAGE_ROOT, file)}`).toBeGreaterThan(0);
    expect(found).toEqual([...values, ...types].sort());
  });

  it.each(subpaths)('%s exposes exactly the inventoried values at runtime', (subpath: string) => {
    const { values, module } = SURFACE[subpath]!;
    expect(Object.keys(module).sort()).toEqual([...values].sort());
  });

  it.each(subpaths)('%s has a runtime form for every value it declares', (subpath: string) => {
    // The cross-check. A `.d.ts` that promises a runtime export the JavaScript
    // does not have is a TypeError in a consumer and a green build here, because
    // nothing else compares the two halves.
    const { values, module } = SURFACE[subpath]!;
    for (const name of values) {
      expect(
        module[name],
        `${subpath} declares '${name}' as a value but exports nothing under that name`,
      ).toBeDefined();
    }
  });

  it.each(subpaths)('%s declares no type under a name it also exports at runtime', (subpath: string) => {
    const { types, module } = SURFACE[subpath]!;
    for (const name of types) {
      expect(name in module, `${subpath} lists '${name}' as a type, but it has a runtime form`).toBe(false);
    }
  });

  it('publishes the number of symbols it thinks it does', () => {
    const distinct = new Set(subpaths.flatMap(subpath => [...SURFACE[subpath]!.values, ...SURFACE[subpath]!.types]));
    expect(distinct.size).toBe(TOTAL_DISTINCT_EXPORTS);
  });

  /**
   * The runner-free promise, as a surface claim rather than a graph claim.
   *
   * `src/__tests__/contract-surface.test.ts` proves the root barrel's built graph
   * reaches no test framework. This is the narrower statement a consumer reads
   * first: `./conformance` is the only subpath whose module even mentions vitest,
   * so every other one can be imported from production code.
   */
  it('keeps the test runner behind ./conformance alone', ctx => {
    if (!requireDist(ctx)) return;
    const importsVitest = subpaths.filter(subpath => {
      const javascript = declarationFileFor(subpath).replace(/\.d\.ts$/, '.js');
      return existsSync(javascript) && /['"]vitest['"]/.test(readFileSync(javascript, 'utf8'));
    });
    expect(importsVitest).toEqual(['./conformance']);
  });
});
