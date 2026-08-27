import { globSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { loadConfigFromFile } from 'vite';
import type { TestProjectConfiguration, UserWorkspaceConfig } from 'vitest/config';
import { defineConfig } from 'vitest/config';

// Directories to exclude from project discovery
const EXCLUDED_DIRS = new Set([
  'packages/_config',
  'packages/_types-builder',
  'packages/_vendored',
  'server-adapters/_test-utils',
  'observability/_examples',
]);

/**
 * `mastracode/` packages this root project list runs, and the ones it does not.
 *
 * The entry that used to stand here was `mastracode/vitest.config.ts` — a file
 * that has never existed. Project discovery therefore reached nothing at all
 * under `mastracode/`, and every suite there was invisible to the pull-request
 * gate. This replaces it.
 *
 * Globbing `mastracode/*​/vitest.config.ts` is the obvious repair and it is the
 * wrong one. Measured, it does four things nobody wants:
 *
 * - It reaches `mastracode/web`, which is a *separate pnpm project* with its own
 *   `pnpm-lock.yaml` and `pnpm-workspace.yaml`. The root install leaves
 *   `mastracode/web/node_modules` absent, so its two `unit:` files fail on the
 *   spot — a missing `hono`, and a missing `varlock` binary.
 * - It appears to switch on `mastracode/mastra-factory` and does not. That config
 *   names no project, so it is called `create-factory`, and the gate's
 *   `--project 'unit:*'` selector never matches it. A silent no-op.
 * - It duplicates `mastracode/factory-auth`, which already runs in its own job,
 *   and would drop the coverage thresholds that job exists to enforce, because
 *   vitest ignores coverage configured on a project.
 * - It switches on three suites that are not green — see MASTRACODE_NOT_HERE.
 *
 * So every package states its own answer. The check in `mastracodeProjects()`
 * fails the whole vitest run if a package under `mastracode/` appears in neither
 * list, so a suite cannot go unwatched again by nobody noticing it.
 */
const MASTRACODE_IN_ROOT_GATE = [
  // 91 files, 1,889 tests, ~50s. Green from the repository root.
  'mastracode/factory/vitest.config.ts',
  /**
   * Two projects, and only one of them runs here.
   *
   * `unit:factory-ui` (27 files, 268 tests, ~7s) is node-environment and green
   * from the repository root, so the gate's `--project 'unit:*'` selector runs
   * it — and with it `src/ui/__tests__/no-provider-literals.test.ts`, the
   * sign-in seam gate.
   *
   * `msw:factory-ui` (131 files, 698 tests) is also discovered from this entry,
   * but no selector in test-suite.yml matches `msw:`, so nothing here runs it.
   * That is deliberate: it is jsdom + React + MSW and is sensitive to the
   * directory vitest starts in. Identical config and files, it is green from the
   * package and fails 7 tests in 4 files on accessible-name lookups from the
   * root. The factory-ui-test job in test-suite.yml runs it from the package,
   * which is where it works and what mastracode/factory-ui/AGENTS.md documents.
   */
  'mastracode/factory-ui/vitest.config.ts',
];

/**
 * Packages under `mastracode/` this list deliberately does not run, and why.
 *
 * "Not here" is not the same as "not gated": factory-auth runs in its own job,
 * which is the right shape for it. The rest are genuinely not gated, and each
 * names the thing that has to be fixed first.
 */
const MASTRACODE_NOT_HERE: Record<string, string> = {
  'mastracode/factory-auth':
    'GATED ELSEWHERE: the factory-auth-ee-boundary job in lint.yml. That job is also ' +
    'where its coverage thresholds are enforced, and vitest ignores coverage ' +
    'configured on a project, so folding it in here would quietly delete them.',
  'mastracode/sdk':
    'NOT GATED: 105 files, 1,441 tests, ~97s, and one of them does not pass in a ' +
    'container — `sandbox-filesystem.conformance.test.ts` writes a large file by ' +
    'passing it as an argv and dies on `spawn E2BIG`. It fails the same way from ' +
    'the package directory, so this is the suite, not the wiring. Fix that test, ' +
    'then add it here.',
  'mastracode/tui':
    'NOT GATED: 113 files, 1,287 tests, ~80s, with one pre-existing failure — ' +
    '`handlers/__tests__/message.test.ts` misses an `instanceof` on the streamed ' +
    'Subconscious component. It fails from the package directory too. Fix that ' +
    'test, then add it here.',
  'mastracode/mastra-factory':
    'NOT GATED: 6 files, 51 tests, ~2s, with one pre-existing failure — ' +
    '`create.test.ts` expects git not to run when .gitignore cannot be updated, and ' +
    'it does. Worth fixing on its own account: that test is about .env secrets ' +
    'never being staged. It also needs a `unit:` project name before any ' +
    "`--project 'unit:*'` selector could reach it.",
  'mastracode/web':
    'NOT GATED: not a workspace package. It carries its own pnpm-lock.yaml and ' +
    'pnpm-workspace.yaml, the root install never populates its node_modules, and ' +
    'its suite wants the docker-compose database. Gating it needs a job with its ' +
    'own install and services.',
};

/**
 * The `mastracode/` configs this list runs, after checking that every package
 * under `mastracode/` has been decided about one way or the other.
 */
function mastracodeProjects(): string[] {
  const present = globSync('mastracode/*/vitest.config.ts').sort();
  const decided = new Set([
    ...MASTRACODE_IN_ROOT_GATE,
    ...Object.keys(MASTRACODE_NOT_HERE).map(dir => `${dir}/vitest.config.ts`),
  ]);
  const undecided = present.filter(configPath => !decided.has(configPath));

  if (undecided.length > 0) {
    throw new Error(
      `vitest.config.ts: ${undecided.join(', ')} is not accounted for.\n` +
        'Every vitest project under mastracode/ must be listed in MASTRACODE_IN_ROOT_GATE, ' +
        'so a pull request runs it, or in MASTRACODE_NOT_HERE with the reason it does not.',
    );
  }

  return MASTRACODE_IN_ROOT_GATE;
}

// Directories to scan for vitest configs
const PROJECT_GLOBS = [
  'packages/*/vitest.config.ts',
  // `packages/_internals/*` sits one level deeper than the glob above reaches,
  // so its suites ran only from their own package and never on a pull request.
  // `@internal/auth` owns the capability interfaces and guards every auth
  // provider narrows with, which is not a thing to leave outside the gate.
  'packages/_internals/*/vitest.config.ts',
  'stores/*/vitest.config.ts',
  'deployers/*/vitest.config.ts',
  'voice/*/vitest.config.ts',
  'server-adapters/*/vitest.config.ts',
  'client-sdks/*/vitest.config.ts',
  'auth/*/vitest.config.ts',
  'observability/*/vitest.config.ts',
  'pubsub/*/vitest.config.ts',
  'signals/*/vitest.config.ts',
  'workflows/*/vitest.config.ts',
  'code-mode/*/vitest.config.ts',
];

/**
 * Discovers all vitest projects from package configs.
 * For configs with nested projects, expands them with the correct root path.
 * For simple configs, returns the directory as a project path.
 */
async function discoverProjects(): Promise<TestProjectConfiguration[]> {
  const projects: TestProjectConfiguration[] = [];

  // Find all vitest.config.ts files
  const configPaths = [...PROJECT_GLOBS.flatMap(pattern => globSync(pattern)), ...mastracodeProjects()];

  for (const configPath of configPaths) {
    const projectDir = dirname(configPath);

    // Skip excluded directories
    if (EXCLUDED_DIRS.has(projectDir)) {
      continue;
    }

    // Read the config file to check if it has nested projects
    const configContent = readFileSync(configPath, 'utf-8');
    const hasNestedProjects = /test:\s*\{[\s\S]*?projects:\s*\[/.test(configContent);

    if (!hasNestedProjects) {
      // Simple config - use directory path
      projects.push(projectDir);
      continue;
    }

    // Config has nested projects - load it using Vite's config loader
    try {
      const absolutePath = resolve(process.cwd(), configPath);
      const loaded = await loadConfigFromFile({} as any, absolutePath);
      if (!loaded) {
        projects.push(projectDir);
        continue;
      }
      const config = loaded.config as UserWorkspaceConfig;

      if (!config.test?.projects) {
        // Fallback if config parsing didn't work as expected
        projects.push(projectDir);
        continue;
      }

      // Expand nested projects with root path
      for (const nestedProject of config.test.projects) {
        if (typeof nestedProject === 'string') {
          // String reference - resolve relative to the config's directory
          projects.push(`${projectDir}/${nestedProject}`);
        } else {
          // Inline project config - add root path
          const projectConfig = nestedProject as UserWorkspaceConfig;
          projects.push({
            ...projectConfig,
            test: {
              ...projectConfig.test,
              root: `./${projectDir}`,
            },
          });
        }
      }
    } catch (error) {
      // If we can't import the config, fall back to using the directory path
      console.warn(`Warning: Could not import ${configPath}, using directory path instead:`, error);
      projects.push(projectDir);
    }
  }

  return projects;
}

export default defineConfig(async () => ({
  test: {
    projects: await discoverProjects(),
  },
}));
