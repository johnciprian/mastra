/**
 * GATE: `RouteAuth` is the only way production code learns who the caller is.
 *
 * The auth gate stashes the authenticated user on the Hono context under
 * `factoryAuthUser`. That variable is an implementation detail of `src/auth.ts`,
 * but it is a *global* implementation detail: any handler holding a `Context`
 * can read it, and for a long time several did. Each of those reads was a
 * second identity path — one that skipped the port's organization resolution,
 * its blank-id guard, and its treatment of a user whose provider has no
 * organization concept. They did not disagree with the port on purpose; they
 * disagreed with it by being written separately, which is the only way this
 * class of bug ever happens.
 *
 * Three such reads were removed by porting their callers onto `RouteAuth`. The
 * fourth was `storage/domains/audit/domain.ts`, and it was different in kind:
 * it wanted the acting user's *name and avatar*, and the port had no member
 * that could answer, so there was genuinely nowhere else for it to go.
 * `RouteAuth.profile()` is that member, and the domain now goes through it.
 *
 * WHY THIS TEST EXISTS RATHER THAN A CODE REVIEW NOTE
 *
 * Nothing structural stops a fifth read. `c.get('factoryAuthUser')` compiles,
 * runs, and looks correct on whichever deployment the author tested — it is
 * only wrong for the user whose provider has no organization, or whose id is
 * blank, and neither of those is the author. A reviewer has to notice a single
 * line in a large diff. This notices instead.
 *
 * WHAT IT BANS, AND WHERE
 *
 * The bare token `factoryAuthUser`, on any non-comment line of any production
 * module under `src/` other than `src/auth.ts`. Banning the token rather than
 * the `get(...)` call shape catches the `set(...)` half too: a module that
 * writes the variable has taken over the gate's job, which is the same
 * structural mistake pointed the other way. Comment lines are skipped so the
 * variable can still be *discussed* — `routes/route.ts` explains on the
 * `profile()` member why it exists, and a gate that made that sentence
 * unwritable would be worked around rather than kept.
 *
 * THE TWO EXEMPTIONS, BOTH ASSERTED RATHER THAN ASSUMED
 *
 * 1. `src/auth.ts` owns the variable. The test asserts it really does contain
 *    the token, so this allowlist entry cannot quietly go stale and start
 *    exempting a file that no longer has anything to exempt.
 * 2. `routes/test-utils.ts` is the `RouteAuth` fake the suites are built on. It
 *    has to read the variable, because its whole job is to model what the gate
 *    does. It is exempt because it never ships — and the test checks the build
 *    config still says so, so the exemption fails the day it stops being true.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/** `<package>/src` — this file lives at `src/__tests__/`. */
const SRC_ROOT = fileURLToPath(new URL('..', import.meta.url));

/** `<package>/tsdown.config.ts`, read to verify the test-helper exemption. */
const TSDOWN_CONFIG = fileURLToPath(new URL('../../tsdown.config.ts', import.meta.url));

/** The context variable the auth gate owns. */
const AUTH_CONTEXT_VARIABLE = 'factoryAuthUser';

/** The one production module allowed to name it: the gate that sets it. */
const GATE_MODULE = 'auth.ts';

/**
 * The tsdown entry pattern that keeps the shared test helpers out of `dist/`.
 * Their exemption below rests entirely on this, so it is asserted, not assumed.
 */
const HELPER_BUILD_EXCLUSION = "'!src/**/test-utils.ts'";

/**
 * Shared test helpers, exempt because the build drops them. Listed rather than
 * matched so a fourth cannot appear unremarked — `routes/test-utils.ts` is the
 * one that reads the variable; the other two are here because they carry the
 * same filename and the same exemption, and a reader should not have to work
 * out which of the three the rule is really about.
 */
const BUILD_EXCLUDED_HELPERS = ['integrations/platform/test-utils.ts', 'routes/test-utils.ts', 'storage/test-utils.ts'];

/** A path is a helper exempted above. */
function isBuildExcludedHelper(relativePath: string): boolean {
  return BUILD_EXCLUDED_HELPERS.includes(relativePath);
}

/**
 * Production source: what ends up in `dist/` and runs in front of a real user.
 *
 * Tests and `__tests__/` fixtures are excluded because they must be able to
 * stage a signed-in user by hand — that is how the auth-dependent behaviour is
 * tested at all. `test-utils.ts` is handled separately so the exemption can be
 * counted rather than merely applied.
 */
function isProductionSource(relativePath: string): boolean {
  if (relativePath.includes('__tests__/')) return false;
  if (/\.(test|spec)\.tsx?$/.test(relativePath)) return false;
  if (isBuildExcludedHelper(relativePath)) return false;
  return /\.tsx?$/.test(relativePath);
}

function collectFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      collectFiles(full, acc);
    } else {
      acc.push(full);
    }
  }
  return acc;
}

function toRelative(absolutePath: string): string {
  return relative(SRC_ROOT, absolutePath).split('\\').join('/');
}

/**
 * Whether a line is comment prose to be skipped.
 *
 * Line-based rather than a comment parser, deliberately: a parser that
 * mis-tracks a quote could blank a region of real code and stop enforcing
 * anything while still reporting success. This can only ever fail to skip a
 * trailing comment — a visible false positive someone fixes, never an
 * invisible false negative.
 */
function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*');
}

interface ScannedFile {
  relativePath: string;
  /** Non-comment lines naming the gate's context variable, 1-based. */
  hits: { number: number; text: string }[];
}

function scan(absolutePath: string): ScannedFile {
  const hits = readFileSync(absolutePath, 'utf8')
    .split('\n')
    .map((text, index) => ({ number: index + 1, text }))
    .filter(line => !isCommentLine(line.text) && line.text.includes(AUTH_CONTEXT_VARIABLE));
  return { relativePath: toRelative(absolutePath), hits };
}

const allFiles = collectFiles(SRC_ROOT).map(toRelative);
const productionFiles = collectFiles(SRC_ROOT)
  .filter(absolutePath => isProductionSource(toRelative(absolutePath)))
  .map(scan);

describe('RouteAuth is the only identity path in production code', () => {
  it('scans a plausible number of production modules, so a broken glob cannot pass vacuously', () => {
    // Without this, a path bug that collected nothing would make every
    // assertion below pass and the gate would be decorative.
    expect(productionFiles.length).toBeGreaterThan(50);
    const scanned = productionFiles.map(file => file.relativePath);
    expect(scanned).toContain(GATE_MODULE);
    // The module that held the last bypass, and the port it now goes through.
    expect(scanned).toContain('storage/domains/audit/domain.ts');
    expect(scanned).toContain('routes/route.ts');
  });

  it('reads the auth context variable in no production module but the gate', () => {
    const violations = productionFiles
      .filter(file => file.relativePath !== GATE_MODULE)
      .flatMap(file =>
        file.hits.map(
          hit =>
            `${file.relativePath}:${hit.number} names '${AUTH_CONTEXT_VARIABLE}' directly: ${hit.text.trim()}\n` +
            '    Take identity from the RouteAuth port instead — tenant() for (orgId, userId),\n' +
            '    runTenant() under an agent RequestContext, profile() for display fields.',
        ),
      );

    expect(violations).toEqual([]);
  });

  it('keeps the gate exemption honest: src/auth.ts still owns the variable', () => {
    // If this ever goes empty the allowlist entry is stale, and a stale entry
    // is an exemption sitting open for whatever moves into that filename next.
    const gate = productionFiles.find(file => file.relativePath === GATE_MODULE);
    expect(gate?.hits.length).toBeGreaterThan(0);
  });

  it('exempts only test helpers the build actually drops', () => {
    // Both directions. A new `test-utils.ts` anywhere under src/ would be
    // silently exempt without the first assertion; the second checks the build
    // config still keeps each exempted helper out of dist/, which is the whole
    // reason it is allowed to read the variable.
    const helpers = allFiles.filter(path => /(^|\/)test-utils\.tsx?$/.test(path));
    expect(helpers.sort()).toEqual([...BUILD_EXCLUDED_HELPERS].sort());

    const tsdown = readFileSync(TSDOWN_CONFIG, 'utf8');
    expect(tsdown, `the helpers stay out of dist/ only while ${HELPER_BUILD_EXCLUSION} is an entry pattern`).toContain(
      HELPER_BUILD_EXCLUSION,
    );
  });
});
