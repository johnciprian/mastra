/**
 * GATE: the sign-in seam must not slide back to branching on provider identity.
 *
 * The SPA used to ask "which provider is this?" and render from the answer,
 * which is why a deployment on an unrecognized identity provider was shown a
 * GitHub logo and told to "Continue with GitHub". The capability descriptor
 * replaced that question, but nothing structural stops it coming back: one
 * `provider === 'some-name'` in a hurry restores the coupling, and it will look
 * like it works on whichever deployment the author happened to test.
 *
 * This test is what stops that. It fails the build on a provider name used as
 * code anywhere in the SPA, and on a vendor mark reaching the auth surface.
 *
 * WHY IT BANS NAMES-AS-CODE RATHER THAN NAMES-ANYWHERE
 *
 * "WorkOS" appears in perfectly good prose all over this package — the WorkOS
 * auth gate, WorkOS user ids, an audit link into the WorkOS console. None of
 * that is the seam, and a gate that failed on it would be turned off within a
 * week. What is the seam is the machine id: `'workos'`, `'better-auth'`,
 * `'mastra-studio'` are values that only ever appear in code that compares or
 * looks up by provider. So the ban is on the lowercase ids, and comment lines
 * are skipped. The two rules together have no false positives on this tree,
 * which is what makes the gate keepable.
 *
 * SCOPE OF THE VENDOR-MARK RULE
 *
 * `GithubIcon` and `LogoWithoutText` are legitimate nearly everywhere here:
 * GitHub is this product's source-control integration, and the Mastra logo is
 * the Mastra logo. They are only wrong on the *auth* surface, where the hint
 * token decides the icon and a vendor mark would smuggle provider identity back
 * into a map that is supposed to be free of it. So that rule is scoped to the
 * sign-in page and the auth domain.
 *
 * THE ONE EXEMPTION
 *
 * A single `LEGACY:` … `END LEGACY` region in `SignInPage.tsx` serves servers
 * that predate the descriptor. It is asserted to be the only one, so a second
 * cannot be opened quietly, and it goes when the legacy branch does.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

/** `<package>/src` — this file lives at `src/ui/__tests__/`. */
const SRC_ROOT = fileURLToPath(new URL('../..', import.meta.url));

/**
 * Auth provider machine ids. These are the values a provider-name branch is
 * written against; they never appear as prose. Deliberately excludes `github`,
 * which is a source-control integration id here (`'github-issue'`,
 * `'github-copilot'`) and not an auth provider at all.
 */
const AUTH_PROVIDER_IDS = ['workos', 'better-auth', 'mastra-studio', 'auth0', 'okta', 'clerk', 'supabase', 'firebase'];

/** Vendor marks that must not decide anything on the auth surface. */
const VENDOR_MARKS = ['GithubIcon', 'GithubCoinIcon', 'GoogleIcon', 'LogoWithoutText'];

/** The auth surface: where a provider-shaped decision could plausibly be made. */
function isAuthSurface(relativePath: string): boolean {
  return relativePath === 'ui/pages/SignInPage.tsx' || relativePath.startsWith('ui/domains/auth/');
}

/** Production source only — fixtures must be able to name providers to test the legacy path at all. */
function isProductionSource(relativePath: string): boolean {
  if (relativePath.includes('__tests__/')) return false;
  if (/\.test\.tsx?$/.test(relativePath)) return false;
  return /\.tsx?$/.test(relativePath);
}

function collectSourceFiles(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist') continue;
      collectSourceFiles(full, acc);
    } else if (isProductionSource(relative(SRC_ROOT, full))) {
      acc.push(full);
    }
  }
  return acc;
}

/**
 * Whether a line is comment prose to be skipped.
 *
 * Line-based rather than a full comment parser, and that is deliberate for a
 * gate: a parser that mis-tracks an apostrophe in JSX text could blank a region
 * of real code and quietly stop enforcing anything. This can only ever fail to
 * skip a trailing comment, which is a visible false positive someone fixes —
 * never an invisible false negative.
 */
function isCommentLine(line: string): boolean {
  const trimmed = line.trim();
  return trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*');
}

/** Match a token not glued to surrounding word characters; hyphens count as part of the token. */
function containsToken(line: string, token: string): boolean {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^A-Za-z0-9_-])${escaped}([^A-Za-z0-9_-]|$)`).test(line);
}

interface ScannedFile {
  relativePath: string;
  /** Lines outside every LEGACY region, 1-based line numbers preserved. */
  lines: { number: number; text: string }[];
  legacyRegions: number;
}

/**
 * Whether a line opens or closes the legacy banner.
 *
 * The marker must sit on a line that *opens* a block comment, which is what the
 * two banner delimiters do. Matching the words anywhere would let the banner's
 * own body text close the region: the prose inside it says "everything down to
 * the END LEGACY marker", and a looser check ended the region on that sentence
 * and silently stopped scanning the thirty lines that followed. A gate with a
 * hole that shape is worse than no gate, because it reports success.
 */
function legacyMarker(line: string): 'begin' | 'end' | null {
  if (!line.trim().startsWith('/*')) return null;
  if (/\bEND LEGACY\b/.test(line)) return 'end';
  if (/\bLEGACY:/.test(line)) return 'begin';
  return null;
}

/** Read a file, drop comment lines, and split out anything inside a LEGACY region. */
function scan(absolutePath: string): ScannedFile {
  const relativePath = relative(SRC_ROOT, absolutePath).split('\\').join('/');
  const lines: { number: number; text: string }[] = [];
  let legacyRegions = 0;
  let insideLegacy = false;

  readFileSync(absolutePath, 'utf8')
    .split('\n')
    .forEach((text, index) => {
      const marker = legacyMarker(text);
      if (!insideLegacy && marker === 'begin') {
        insideLegacy = true;
        legacyRegions += 1;
        return;
      }
      if (insideLegacy) {
        if (marker === 'end') insideLegacy = false;
        return;
      }
      if (isCommentLine(text)) return;
      // An import alone renders nothing; the rules below catch the line that
      // actually uses the symbol, which is where a seam would reappear.
      if (/^\s*import\b/.test(text)) return;
      lines.push({ number: index + 1, text });
    });

  return { relativePath, lines, legacyRegions };
}

const scannedFiles = collectSourceFiles(SRC_ROOT).map(scan);

describe('the SPA does not branch on auth provider identity', () => {
  it('scans a plausible number of files, so a broken glob cannot pass vacuously', () => {
    // Without this, a path bug that collected nothing would make every
    // assertion below pass and the gate would be decorative.
    expect(scannedFiles.length).toBeGreaterThan(50);
    expect(scannedFiles.map(file => file.relativePath)).toContain('ui/pages/SignInPage.tsx');
  });

  it('uses no auth provider name as code outside the legacy region', () => {
    const violations = scannedFiles.flatMap(file =>
      file.lines.flatMap(line =>
        AUTH_PROVIDER_IDS.filter(id => containsToken(line.text, id)).map(
          id => `${file.relativePath}:${line.number} uses the provider id '${id}': ${line.text.trim()}`,
        ),
      ),
    );

    expect(violations).toEqual([]);
  });

  it('puts no vendor mark on the auth surface outside the legacy region', () => {
    const violations = scannedFiles
      .filter(file => isAuthSurface(file.relativePath))
      .flatMap(file =>
        file.lines.flatMap(line =>
          VENDOR_MARKS.filter(mark => containsToken(line.text, mark)).map(
            mark => `${file.relativePath}:${line.number} reaches for ${mark}: ${line.text.trim()}`,
          ),
        ),
      );

    expect(violations).toEqual([]);
  });

  it('keeps the legacy exemption to exactly one region, in the sign-in page', () => {
    const withLegacy = scannedFiles
      .filter(file => file.legacyRegions > 0)
      .map(file => `${file.relativePath} (${file.legacyRegions})`);

    expect(withLegacy).toEqual(['ui/pages/SignInPage.tsx (1)']);
  });
});
