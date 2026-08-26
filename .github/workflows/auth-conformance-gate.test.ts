/**
 * The conformance gate: every shipped auth provider runs `describeAuthProvider`,
 * and the suite that runs it is actually selected by CI.
 *
 * Read this before you change anything here.
 *
 * WHY THIS IS A TEST AND NOT A WORKFLOW STEP
 *
 * The requirement is not "run the conformance suites". It is "a new provider
 * that skips conformance cannot be merged". Those are different asks, and only
 * the second one is a gate.
 *
 * A workflow step runs the suites that exist. Add `auth/acme` with no
 * `conformance.test.ts` and every step in `test-suite.yml` stays green: there
 * is nothing to select, `--passWithNoTests` is on, and the run is greener than
 * before because one more package reported no failures. Nothing in YAML can
 * express "and there should have been a suite here", because YAML has no way to
 * enumerate what shipped.
 *
 * So the gate enumerates. It reads `auth/` from disk, and every non-private
 * package it finds owes a conformance suite. That is the only shape that
 * notices a provider nobody told it about, which is the entire point.
 *
 * The precedent is `mastracode/factory-auth/src/__tests__/no-ee-boundary.test.ts`,
 * which guards a licence boundary the same way and for the same reason. The
 * false-green guards below are modelled on its: a gate that discovers nothing
 * must go red, because discovering nothing means the discovery broke, not that
 * everything passed.
 *
 * THE TWO HALVES, AND WHY THE SECOND ONE IS NOT REDUNDANT
 *
 * A conformance file that exists is not a conformance suite that runs. Those
 * came apart in this repository already, twice, in the same way:
 *
 *  - `vitest.config.ts` at the repo root globs `mastracode/vitest.config.ts`,
 *    a file that does not exist, so nothing under `mastracode/` is in the PR
 *    gate at all. The kit's own suite needed a dedicated job in `lint.yml`.
 *  - `auth/cloud/vitest.config.ts` declares no `name`, so vitest falls back to
 *    the package.json name and the project is called `@mastra/auth-cloud`. The
 *    unit job selects `--project 'unit:*'`. `auth/cloud`'s tests have never run
 *    in the PR gate, and if somebody adds conformance there tomorrow it still
 *    will not run.
 *
 * Both are invisible to a check that only asks "does the file exist". So the
 * second assertion asks the real selector, in a real subprocess, which files it
 * would actually pick: `vitest list --filesOnly` with the `--project` patterns
 * read out of `test-suite.yml` itself. Nothing here restates what the workflow
 * says - it reads the workflow and then makes the workflow's own tooling answer.
 *
 * WHY THE ALLOWLIST EXISTS AND WHY IT CANNOT GROW QUIETLY
 *
 * Five providers ship today with no conformance suite. Writing five suites is
 * not this task, and leaving the gate red until somebody stops reading it is
 * the outcome every part of this system is designed to avoid. So they are
 * recorded, in {@link NO_CONFORMANCE_YET}, each with a reason.
 *
 * An entry is not an exclusion. It is checked in both directions on every run,
 * exactly like `knownFailures` inside the kit:
 *
 *  - an entry naming a package that does not exist fails, so a rename or a
 *    deletion cannot leave a dead line behind still granting cover;
 *  - an entry naming a package that DOES have conformance fails, and says to
 *    delete the line. That is what makes the list shrink and never grow back;
 *  - an entry with an empty reason fails at load. An exemption with no stated
 *    reason is how the four undocumented obligations happened in the first
 *    place: everybody knew why at the time, and the knowledge left with them.
 *
 * WHAT THIS CANNOT SEE
 *
 * That a conformance suite is meaningful. `describeAuthProvider` called on a
 * provider whose `createProvider` returns a stub would satisfy this gate and
 * prove nothing; so would a suite whose every check is recorded in
 * `knownFailures`. The kit polices that end - a recorded failure that starts
 * passing fails the suite - and this gate polices the other end, which is
 * whether a suite exists and runs at all. Neither is sufficient alone.
 *
 * @module
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const THIS_FILE = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(THIS_FILE), '..', '..');

const GATE_POINTER = `This gate is ${path.relative(REPO_ROOT, THIS_FILE).split(path.sep).join('/')}. Read its header before changing it.`;

// Checked at load, before any assertion can be written in terms of a wrong root.
//
// Every path in this file hangs off REPO_ROOT, which is computed by walking two
// directories up from here. Move this file one level and the walk lands
// somewhere with no `auth/` in it - and the discovery guard would then report
// "providers moved" when what actually moved is this file. One is a real
// finding and the other is a wild goose chase, so they are told apart here.
if (!statSync(path.join(REPO_ROOT, 'pnpm-workspace.yaml'), { throwIfNoEntry: false })?.isFile()) {
  throw new Error(
    `The conformance gate resolved the repo root to ${REPO_ROOT}, which has no pnpm-workspace.yaml. ` +
      'This file computes the root by walking up two directories, so moving it breaks every path in it. ' +
      GATE_POINTER,
  );
}

/**
 * Where provider packages live, relative to the repo root.
 *
 * A constant rather than an inline string so that the false-green guard below
 * has something to name when it fires. If providers move, this is the one line
 * to change - and the guard is what makes sure somebody notices they moved.
 */
const PROVIDERS_DIR = 'auth';

/** The workflow whose unit job is the PR gate for `unit:*` projects. */
const UNIT_TEST_WORKFLOW = '.github/workflows/test-suite.yml';

/**
 * The kit subpath a conformance suite imports. Importing it is what makes a
 * test file a conformance suite rather than a test that happens to say the word.
 */
const CONFORMANCE_SPECIFIER = '@mastra/factory-auth/conformance';

/** The suite entry point. Both this and the import above must be present. */
const SUITE_ENTRY_POINT = 'describeAuthProvider';

/**
 * Shipped providers with no conformance suite yet, each with a reason.
 *
 * Keyed by directory name under `auth/`. Every entry is a debt, not a decision:
 * the reason says why it is outstanding and what closing it takes. Deleting a
 * line is how the debt is paid, and the stale-entry assertion below makes the
 * deletion mandatory rather than optional - once a package conforms, its entry
 * fails the gate until it is removed.
 *
 * Do not add a line here to make a red gate green. A new provider arriving
 * without conformance is the exact thing this gate exists to stop, and an entry
 * added in the same PR that adds the provider is that stop being routed around
 * in plain sight. The reviewable question is always "why can this one not have
 * a suite today", and "we did not write one" is not an answer for new code.
 */
const NO_CONFORMANCE_YET = new Map<string, string>([
  [
    'auth0',
    'Not yet converted. Lane C (C1-C5) took six providers through conformance - better-auth, okta, ' +
      'supabase, firebase, workos, studio - and no task in .plans/auth/tasks.json covers this one. ' +
      'The suite is roughly 40 lines: stub the Auth0 JWKS verifier the way src/index.test.ts already ' +
      'does, then call describeAuthProvider with a token that verifier accepts.',
  ],
  [
    'clerk',
    'Not yet converted, and no task in .plans/auth/tasks.json covers it. Same shape as auth0: ' +
      'MastraAuthClerk verifies bearer tokens against Clerk, so conformance needs the verifier ' +
      'injected in createProvider and nothing else.',
  ],
  [
    'cloud',
    'Not yet converted, and blocked twice over. auth/cloud/vitest.config.ts declares no `name`, so ' +
      "its project is called @mastra/auth-cloud and the unit job (--project 'unit:*') has never " +
      'selected any of its tests - a conformance suite added today would not run. Fix the project ' +
      'name first, then add the suite; the CI-reachability assertion in this file will hold the ' +
      'second half once the first is done.',
  ],
  [
    'google',
    'Not yet converted, and no task in .plans/auth/tasks.json covers it. MastraAuthGoogle validates ' +
      'Google ID tokens; conformance needs the token verification seam stubbed in createProvider.',
  ],
  [
    'neon',
    'Not yet converted, and no task in .plans/auth/tasks.json covers it. MastraAuthNeon declares ' +
      'more of the contract than the others (it carries an RBAC provider), so this one is the most ' +
      'likely of the five to surface real findings and the most worth doing next.',
  ],
]);

// ============================================================================
// Discovery
// ============================================================================

interface ProviderPackage {
  /** Directory name under `auth/`, e.g. `okta`. The allowlist key. */
  readonly dir: string;
  /** Repo-relative package root, e.g. `auth/okta`. */
  readonly root: string;
  /** Published package name from package.json, e.g. `@mastra/auth-okta`. */
  readonly name: string;
  /** Repo-relative conformance suites found in this package. Usually 0 or 1. */
  readonly suites: readonly string[];
}

function toRepoRelative(absolute: string): string {
  return path.relative(REPO_ROOT, absolute).split(path.sep).join('/');
}

function listFiles(dir: string, predicate: (file: string) => boolean): string[] {
  if (!existsSync(dir)) return [];
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      found.push(...listFiles(full, predicate));
    } else if (entry.isFile() && predicate(full)) {
      found.push(full);
    }
  }
  return found;
}

/**
 * Strip comments before looking for the suite.
 *
 * Without this, a file explaining why it does NOT run conformance would satisfy
 * the gate by naming it in prose. Several provider test files discuss the kit
 * in their headers, so this is a live concern rather than a theoretical one.
 */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

/**
 * Is this file a conformance suite?
 *
 * Both halves are required. The import alone is satisfied by a file that pulls
 * in a type; the call alone is satisfied by a locally defined function with the
 * same name. Together they mean the kit's suite is registered against something.
 */
function isConformanceSuite(file: string): boolean {
  const source = stripComments(readFileSync(file, 'utf8'));
  return source.includes(CONFORMANCE_SPECIFIER) && new RegExp(`\\b${SUITE_ENTRY_POINT}\\s*\\(`).test(source);
}

/**
 * Every shipped provider package under `auth/`.
 *
 * "Shipped" is `package.json` without `private: true`, and it is deliberately
 * the only test applied. Deriving it from something cleverer - does the package
 * export a class extending `MastraAuthProvider`? - would hand anybody who wants
 * out of this gate a way to take it by renaming a base class. A published
 * package under `auth/` owes a conformance suite or an allowlist line with a
 * reason, and a shared helper that genuinely owes neither is a one-line
 * reviewable diff. Fail closed: a denylist can be routed around, an allowlist
 * cannot.
 */
function discoverProviders(): ProviderPackage[] {
  const providersRoot = path.join(REPO_ROOT, PROVIDERS_DIR);
  if (!existsSync(providersRoot)) return [];

  const providers: ProviderPackage[] = [];
  for (const entry of readdirSync(providersRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const root = path.join(providersRoot, entry.name);
    const manifestPath = path.join(root, 'package.json');
    if (!existsSync(manifestPath)) continue;

    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { name?: string; private?: boolean };
    if (manifest.private === true) continue;

    const srcDir = path.join(root, 'src');
    const suites = listFiles(srcDir, file => /\.test\.tsx?$/.test(file))
      .filter(isConformanceSuite)
      .map(toRepoRelative)
      .sort();

    providers.push({
      dir: entry.name,
      root: toRepoRelative(root),
      name: manifest.name ?? `(package.json in ${toRepoRelative(root)} declares no name)`,
      suites,
    });
  }
  return providers.sort((left, right) => left.dir.localeCompare(right.dir));
}

// ============================================================================
// What CI actually selects
// ============================================================================

/**
 * The literal `--project` patterns the unit job runs with, read from the
 * workflow rather than restated here.
 *
 * Patterns carrying a `${{ }}` expression are skipped: `--project
 * 'e2e:${{ matrix.project }}'` is not a literal and cannot be handed to vitest
 * from here. What survives is `unit:*` and `typecheck:*`, which is exactly the
 * selection the PR gate makes for these packages.
 */
function unitProjectPatterns(): string[] {
  const workflow = path.join(REPO_ROOT, UNIT_TEST_WORKFLOW);
  if (!existsSync(workflow)) return [];
  const contents = readFileSync(workflow, 'utf8');
  const patterns = new Set<string>();
  for (const match of contents.matchAll(/--project\s+'([^']+)'/g)) {
    const pattern = match[1];
    if (pattern !== undefined && !pattern.includes('${{')) patterns.add(pattern);
  }
  return [...patterns].sort();
}

/**
 * Ask vitest which files those patterns select, in a real subprocess.
 *
 * `vitest list --filesOnly` resolves every project config and prints one
 * `[project] repo/relative/path.test.ts` line per selected file. It imports no
 * test file and needs no build, which is why this costs a couple of seconds
 * rather than a couple of minutes.
 *
 * Run through `process.execPath` against vitest's own entry rather than the
 * `.bin` shim, so there is no shell and no platform difference. Every `VITEST_`
 * variable is dropped from the child's environment: this test is itself running
 * under vitest, and a child that inherits the parent's pool and worker ids
 * reports on the parent's run instead of doing its own.
 */
function filesSelectedByCi(patterns: readonly string[]): Set<string> {
  const vitestEntry = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');
  if (!existsSync(vitestEntry)) {
    expect.fail(
      `The conformance gate could not find vitest at ${toRepoRelative(vitestEntry)}, so it could not ask ` +
        'which files CI selects and proved nothing.\nInstall dependencies first: pnpm install\n' +
        GATE_POINTER,
    );
  }

  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (!key.startsWith('VITEST')) env[key] = value;
  }

  const args = ['list', '--filesOnly', ...patterns.flatMap(pattern => ['--project', pattern])];
  let stdout: string;
  try {
    stdout = execFileSync(process.execPath, [vitestEntry, ...args], {
      cwd: REPO_ROOT,
      env,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const shown = ['list', '--filesOnly', ...patterns.flatMap(pattern => ['--project', `'${pattern}'`])];
    expect.fail(
      `The conformance gate could not run \`vitest ${shown.join(' ')}\`, so it could not tell which files ` +
        'CI selects and proved nothing.\n' +
        'A pattern that matches no project is itself the finding: it means the unit job selects projects ' +
        'that do not exist, so it runs nothing.\n' +
        `${detail}\n${GATE_POINTER}`,
    );
  }

  const selected = new Set<string>();
  for (const line of stdout.split('\n')) {
    // `[unit:auth/okta] auth/okta/src/conformance.test.ts`
    const match = /^\[[^\]]+\]\s+(.+\.tsx?)$/.exec(line.trim());
    if (match?.[1] !== undefined) selected.add(match[1].split(path.sep).join('/'));
  }
  return selected;
}

// ============================================================================
// The gate
// ============================================================================

const providers = discoverProviders();
const conforming = providers.filter(provider => provider.suites.length > 0);

describe('auth provider conformance gate', () => {
  it('discovers the shipped provider packages', () => {
    // False-green guard 1: a gate that enumerated nothing is worse than no
    // gate, because it converts ignorance into a green check. Every assertion
    // below iterates `providers`, so all of them pass vacuously at zero.
    if (providers.length === 0) {
      expect.fail(
        `The conformance gate discovered 0 shipped provider packages under ${PROVIDERS_DIR}/, so it proved nothing.\n` +
          'Every other assertion in this file iterates that list and passes vacuously when it is empty.\n' +
          `Either ${PROVIDERS_DIR}/ moved - update PROVIDERS_DIR - or every package under it is now ` +
          'private, which would itself be worth a look.\n' +
          GATE_POINTER,
      );
    }

    console.info(
      `[conformance-gate] providers=${providers.length} with-suite=${conforming.length} ` +
        `recorded-without=${NO_CONFORMANCE_YET.size}`,
    );
    expect(providers.length).toBeGreaterThan(0);
  });

  it('finds conformance suites where they are known to exist', () => {
    // False-green guard 2: the floor.
    //
    // Guard 1 cannot see this one. Providers can be discovered perfectly while
    // `isConformanceSuite` matches nothing - a renamed kit subpath, a renamed
    // entry point, a comment stripper that ate the file - and then every
    // provider looks unconverted, the allowlist covers five of them, and the
    // gate reports eleven failures that are all about itself. Six suites exist
    // today; if the detector finds none, the detector is broken.
    if (conforming.length === 0) {
      expect.fail(
        'The conformance gate found 0 conformance suites, so its detector is broken rather than the ' +
          'repository being unconverted.\n' +
          `It looks for a test file under <package>/src that imports '${CONFORMANCE_SPECIFIER}' and calls ` +
          `${SUITE_ENTRY_POINT}(). If the kit renamed either, update CONFORMANCE_SPECIFIER and ` +
          'SUITE_ENTRY_POINT together.\n' +
          GATE_POINTER,
      );
    }
    expect(conforming.length).toBeGreaterThan(0);
  });

  it('requires every shipped provider to run the conformance suite', () => {
    const unaccounted = providers.filter(
      provider => provider.suites.length === 0 && !NO_CONFORMANCE_YET.has(provider.dir),
    );

    if (unaccounted.length > 0) {
      const lines = unaccounted.map(
        provider => `  ${provider.root} (${provider.name}) ships no conformance suite and has no recorded reason.`,
      );
      expect.fail(
        `${unaccounted.length} shipped auth provider${unaccounted.length === 1 ? '' : 's'} ` +
          `${unaccounted.length === 1 ? 'does' : 'do'} not run the Factory auth conformance suite.\n\n` +
          `${lines.join('\n')}\n\n` +
          'A provider that ships without conformance ships with nobody having checked that it honours the ' +
          'contract, and the four obligations no interface states are exactly the ones that go unnoticed.\n\n' +
          `Add ${firstOffenderRoot(unaccounted)}/src/conformance.test.ts:\n\n` +
          `  import { ${SUITE_ENTRY_POINT} } from '${CONFORMANCE_SPECIFIER}';\n` +
          `  import { MyAuthProvider } from './index';\n\n` +
          `  ${SUITE_ENTRY_POINT}({\n` +
          "    name: '@mastra/auth-my-provider',\n" +
          '    createProvider: () => new MyAuthProvider({ /* verifier injected, no network */ }),\n' +
          "    token: 'a-token-my-provider-accepts',\n" +
          '  });\n\n' +
          'It needs no network, no identity provider and no environment variables. If a check goes red and ' +
          'the fix is not small, record it in `knownFailures` with a reason rather than dropping the suite - ' +
          'the kit is built for that and re-checks the record on every run.\n\n' +
          'If this package genuinely cannot carry a suite today, add it to NO_CONFORMANCE_YET with a reason. ' +
          "That is a reviewable line, and the reviewer's question is why this one is different.\n" +
          GATE_POINTER,
      );
    }
    expect(unaccounted).toEqual([]);
  });

  it('keeps the recorded-without-conformance list honest and shrinking', () => {
    const byDir = new Map(providers.map(entry => [entry.dir, entry]));
    const problems: string[] = [];

    for (const [dir, reason] of NO_CONFORMANCE_YET) {
      const entry = byDir.get(dir);

      if (typeof reason !== 'string' || reason.trim() === '') {
        problems.push(
          `  '${dir}' is recorded with no reason. An exemption nobody wrote a reason for is ` +
            'indistinguishable from one nobody can justify.',
        );
        continue;
      }

      if (entry === undefined) {
        problems.push(
          `  '${dir}' is recorded here but there is no shipped package at ${PROVIDERS_DIR}/${dir}. ` +
            'A record for a package that does not exist is never re-examined, so it would sit here ' +
            'granting cover forever. If the package was renamed, rename this key with it; if it was ' +
            'deleted or made private, delete this line.',
        );
        continue;
      }

      if (entry.suites.length > 0) {
        problems.push(
          `  '${dir}' is recorded as having no conformance suite, and it now has one ` +
            `(${entry.suites.join(', ')}). Delete this line - the debt is paid.`,
        );
      }
    }

    if (problems.length > 0) {
      expect.fail(
        `The recorded-without-conformance list is out of date in ${problems.length} ` +
          `place${problems.length === 1 ? '' : 's'}.\n\n${problems.join('\n')}\n\n` +
          'This list is checked in both directions on every run, the same way the kit checks ' +
          '`knownFailures`. That is what stops it becoming a permanent exemption nobody revisits.\n' +
          GATE_POINTER,
      );
    }
    expect(problems).toEqual([]);
  });

  it('requires every conformance suite to be selected by the CI unit job', { timeout: 180_000 }, () => {
    const patterns = unitProjectPatterns();

    // False-green guard 3: no patterns means the workflow was not read.
    if (patterns.length === 0) {
      expect.fail(
        `The conformance gate read no literal --project patterns out of ${UNIT_TEST_WORKFLOW}, so it ` +
          'could not tell which files CI selects and proved nothing.\n' +
          "It looks for `--project 'name'` in single quotes. If the unit job now selects projects some " +
          'other way, teach unitProjectPatterns() how to read it.\n' +
          GATE_POINTER,
      );
    }

    const selected = filesSelectedByCi(patterns);

    // False-green guard 4: an empty selection would clear every assertion
    // below by making the comparison set empty rather than by passing it.
    if (selected.size === 0) {
      expect.fail(
        `The conformance gate asked vitest which files ${patterns.map(p => `--project '${p}'`).join(' ')} ` +
          'selects and got none back, so it proved nothing.\n' +
          'That is a broken query rather than an empty repository. Check that dependencies are installed ' +
          'and that the root vitest.config.ts still discovers projects.\n' +
          GATE_POINTER,
      );
    }

    console.info(
      `[conformance-gate] ci patterns=${patterns.map(p => `'${p}'`).join(' ')} selected-files=${selected.size}`,
    );

    const unreachable: string[] = [];
    for (const entry of conforming) {
      for (const suite of entry.suites) {
        if (!selected.has(suite)) unreachable.push(`  ${suite} (${entry.name})`);
      }
    }

    if (unreachable.length > 0) {
      expect.fail(
        `${unreachable.length} conformance suite${unreachable.length === 1 ? '' : 's'} ` +
          `exist${unreachable.length === 1 ? 's' : ''} but ${unreachable.length === 1 ? 'is' : 'are'} ` +
          'not selected by the CI unit job, so nothing runs them on a pull request.\n\n' +
          `${unreachable.join('\n')}\n\n` +
          `The unit job in ${UNIT_TEST_WORKFLOW} runs ` +
          `${patterns.map(p => `--project '${p}'`).join(' ')}. A package whose vitest.config.ts declares ` +
          'no `name` gets its package.json name instead - `@mastra/auth-cloud`, not `unit:auth/cloud` - ' +
          "and matches none of those patterns. A file outside the config's `include` globs is invisible " +
          'the same way.\n\n' +
          "Give the package's vitest.config.ts a project name matching the pattern:\n\n" +
          '  export default defineConfig({\n' +
          "    test: { name: 'unit:auth/<package>', include: ['src/**/*.test.ts'] },\n" +
          '  });\n\n' +
          'A suite that exists but never runs is the most expensive kind of green: it looks like ' +
          'coverage in every report and checks nothing.\n' +
          GATE_POINTER,
      );
    }
    expect(unreachable).toEqual([]);
  });
});

/** The first offender's path, for the worked example in the failure message. */
function firstOffenderRoot(entries: readonly ProviderPackage[]): string {
  return entries[0]?.root ?? `${PROVIDERS_DIR}/<package>`;
}
