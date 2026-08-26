/**
 * Type-check the TypeScript examples embedded in the auth documentation.
 *
 * WHY THIS EXISTS
 *
 * Three separate fabricated-API incidents reached `main` in this area: a
 * changeset naming four exports that do not exist, a `encodeState` call with
 * the wrong arity, and a documented `SSOLoginConfig` import that no public
 * entry point offers. Every one was caught by a person re-reading prose. This
 * script is the machine that catches the next one.
 *
 * THE SCOPE RULE IS OPT-OUT, AND DELIBERATELY SO
 *
 * Every fenced `ts`/`typescript`/`tsx` block under the directories in
 * {@link SCOPES} is checked. Coverage follows a directory glob rather than a
 * file list, so a new auth page is covered the day it is added rather than the
 * day somebody remembers to register it.
 *
 * A block leaves the check only by saying so in its own fence, and only with a
 * reason:
 *
 *     ```typescript docscheck=skip docscheck-reason="deliberately broken probe"
 *
 * `skip` without a reason is a hard error. That keeps the escape hatch usable
 * for the cases that need it (a "before" snippet in a migration, a probe meant
 * to fail lint) while making a silent opt-out impossible to write by accident.
 *
 * BLOCKS ACCUMULATE PER FILE, WHICH IS THE WHOLE POINT
 *
 * Checking each block in isolation would have missed the defect that motivated
 * this script. A reader following a build-along guide copies successive blocks
 * into one file, and the failure was *between* blocks: an options interface
 * that never declared a field the constructor read, and a constructor that
 * never assigned three fields a later block used. Both blocks type-check alone.
 * The file the reader ends up with does not.
 *
 * So blocks sharing a `title` within one page are concatenated in document
 * order into a single virtual module, and that composite is what `tsc` sees.
 * `docscheck=member` appends a block into the body of the class the accumulated
 * file already declares, which is how a guide adds methods without re-listing
 * the class. See {@link BlockMode}.
 *
 * IMPORTS RESOLVE AGAINST BUILT PACKAGES, NOT AGAINST STAND-INS
 *
 * A documented `import` is only worth checking if it resolves to the same
 * declarations a reader gets from npm. {@link CHECKED_PACKAGES} lists the
 * workspace packages the examples may import, each mapped to its emitted
 * `dist`; {@link VENDORED_PACKAGES} does the same for a third-party package,
 * resolved through the workspace package that depends on it. A page reporting
 * "cannot find module" for a real package needs a line in one of those, not an
 * opt-out.
 *
 * DIAGNOSTICS POINT AT THE MDX, NOT AT THE FIXTURE
 *
 * Every generated line remembers the `.mdx` file and line it came from, so a
 * developer who breaks an example is told the page, the line, the fenced block,
 * and the compiler's own message. "docs typecheck failed" is not a useful
 * failure and this script never emits one.
 */
import { spawnSync } from 'node:child_process'
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const DOCS_ROOT = resolve(HERE, '..')
const REPO_ROOT = resolve(DOCS_ROOT, '..')

/**
 * The documentation this script covers, as directories rather than files.
 *
 * Widening this is the intended way to grow coverage. Adding a directory whose
 * examples were never written to compile will produce a lot of noise at once,
 * so widen one directory at a time.
 */
const SCOPES = ['src/content/en/docs/auth', 'src/content/en/reference/auth']

/**
 * Pages inside {@link SCOPES} that predate this check, with the reason each is
 * not checked yet. **Debt, not policy.**
 *
 * **This map is empty, and that is the point.** Every page in scope is checked.
 * It stays here because emptiness is the interesting state: a page can only
 * leave the check by adding a line, in a diff, with a reason a reviewer reads.
 * Nothing about the default is opt-in.
 *
 * Adding a line is a last resort. A page whose examples import a package the
 * check cannot resolve belongs in {@link CHECKED_PACKAGES} or
 * {@link VENDORED_PACKAGES}; a block that is genuinely not compilable source -
 * pseudocode, a bare signature - belongs behind `docscheck=skip` with its own
 * reason, which excludes one block instead of a whole page.
 *
 * A listed page that no longer exists fails the run, so the map cannot rot.
 */
const LEGACY_UNCHECKED: Readonly<Record<string, string>> = {}

/** Where the generated fixtures land. Removed and rebuilt on every run. */
const OUT_DIR = join(DOCS_ROOT, '.typecheck-examples')

/** A workspace package the examples are allowed to import. */
interface CheckedPackage {
  /** The specifier a documented example writes. */
  readonly name: string
  /** Its `dist` directory, relative to the repository root. */
  readonly dist: string
  /** The turbo filter that produces that directory. */
  readonly filter: string
  /** A declaration file that exists only after a successful build. */
  readonly proof: string
  /**
   * Where subpath imports resolve, as patterns under `dist`. The default suits
   * a package whose `./x` entry point emits `dist/x/index.d.ts` or `dist/x.d.ts`.
   */
  readonly subpaths?: readonly string[]
}

/**
 * The emitted declarations the examples are checked against.
 *
 * Every one is a build output, so this script needs it present. The workflow
 * that runs this script builds them by filter, and on a documentation-only
 * change every input to them is unchanged, so a warm turbo cache turns that
 * command into a restore rather than a build.
 *
 * Adding a package here is how a page whose examples import it stops being
 * legacy debt: the import resolves against what a reader installing the package
 * actually gets, rather than against a hand-written stand-in that can drift.
 * The examples are checked against emitted declarations rather than sources
 * because checking through `packages/core/src` pulls core's whole tree into the
 * program, reports core's own pre-existing diagnostics as documentation
 * failures, and takes minutes.
 *
 * `.github/workflows/lint-docs.yml` builds this list. Keep the two in step.
 */
const CHECKED_PACKAGES: readonly CheckedPackage[] = [
  {
    name: '@mastra/factory-auth',
    dist: 'mastracode/factory-auth/dist',
    filter: './mastracode/factory-auth',
    proof: 'index.d.ts',
  },
  { name: '@mastra/core', dist: 'packages/core/dist', filter: './packages/core', proof: 'server/index.d.ts' },
  { name: '@mastra/auth', dist: 'packages/auth/dist', filter: './packages/auth', proof: 'index.d.ts' },
  {
    name: '@mastra/client-js',
    dist: 'client-sdks/client-js/dist',
    filter: './client-sdks/client-js',
    proof: 'index.d.ts',
  },
  {
    name: '@mastra/server',
    dist: 'packages/server/dist',
    filter: './packages/server',
    proof: 'index.d.ts',
    subpaths: ['server/*/index.d.ts', 'server/*.d.ts', '*/index.d.ts', '*.d.ts'],
  },
  { name: '@mastra/auth-auth0', dist: 'auth/auth0/dist', filter: './auth/auth0', proof: 'index.d.ts' },
  {
    name: '@mastra/auth-better-auth',
    dist: 'auth/better-auth/dist',
    filter: './auth/better-auth',
    proof: 'index.d.ts',
  },
  { name: '@mastra/auth-clerk', dist: 'auth/clerk/dist', filter: './auth/clerk', proof: 'index.d.ts' },
  { name: '@mastra/auth-firebase', dist: 'auth/firebase/dist', filter: './auth/firebase', proof: 'index.d.ts' },
  { name: '@mastra/auth-google', dist: 'auth/google/dist', filter: './auth/google', proof: 'index.d.ts' },
  { name: '@mastra/auth-okta', dist: 'auth/okta/dist', filter: './auth/okta', proof: 'index.d.ts' },
  { name: '@mastra/auth-supabase', dist: 'auth/supabase/dist', filter: './auth/supabase', proof: 'index.d.ts' },
  { name: '@mastra/auth-workos', dist: 'auth/workos/dist', filter: './auth/workos', proof: 'index.d.ts' },
]

/**
 * Third-party packages a documented example imports, resolved through the
 * workspace package that depends on them.
 *
 * A provider reference page shows the vendor's own entry point next to the
 * Mastra one, because that is what the reader writes. Installing a second copy
 * into the documentation site would pin a version that can drift from the one
 * the provider package is built against; resolving through that package's own
 * `node_modules` checks the example against the version a reader installs
 * alongside it.
 *
 * The mapping points at the package directory rather than at a file inside it,
 * so the package's own `exports` map decides which declarations are used.
 */
interface VendoredPackage {
  /** The specifier a documented example writes. */
  readonly name: string
  /** The workspace package that depends on it, relative to the repository root. */
  readonly through: string
}

const VENDORED_PACKAGES: readonly VendoredPackage[] = [{ name: 'better-auth', through: 'auth/better-auth' }]

const DEFAULT_SUBPATHS = ['*/index.d.ts', '*.d.ts'] as const

function distDir(entry: CheckedPackage): string {
  return join(REPO_ROOT, entry.dist)
}

function vendoredDir(entry: VendoredPackage): string {
  return join(REPO_ROOT, entry.through, 'node_modules', entry.name)
}

/** The `compilerOptions.paths` the checked packages resolve through. */
function packagePaths(): Record<string, string[]> {
  const paths: Record<string, string[]> = {}
  for (const entry of CHECKED_PACKAGES) {
    const dist = distDir(entry)
    paths[entry.name] = [join(dist, 'index.d.ts')]
    paths[`${entry.name}/*`] = (entry.subpaths ?? DEFAULT_SUBPATHS).map(pattern => join(dist, pattern))
  }
  for (const entry of VENDORED_PACKAGES) {
    const dir = vendoredDir(entry)
    paths[entry.name] = [dir]
    paths[`${entry.name}/*`] = [join(dir, '*')]
  }
  return paths
}

/** Fence languages this script treats as TypeScript. */
const TS_LANGUAGES = new Set(['ts', 'typescript', 'tsx'])

/**
 * How a block joins the virtual file its `title` names.
 *
 * - `module` (the default) - the block is module-level source. Appended as-is.
 * - `member` - the block is one or more class members. Appended inside the body
 *   of the last class the accumulated file declares, which is how a build-along
 *   adds methods to a class an earlier block already introduced.
 * - `statements` - the block is loose statements. Wrapped in an async function
 *   so `await` and non-declaration code type-check.
 * - `replace` - the block is a complete file that supersedes what earlier
 *   blocks under this title built up. Accumulation restarts here. Use it for
 *   the finished artifact at the end of a build-along, so the page can show a
 *   whole file instead of a partial one under a `// ... as above` comment.
 * - `skip` - not checked. Requires `docscheck-reason`.
 */
type BlockMode = 'module' | 'member' | 'statements' | 'replace' | 'skip'

interface Block {
  readonly mdxPath: string
  /** 1-based line of the opening fence. */
  readonly fenceLine: number
  /** 1-based line of the first line of code. */
  readonly firstCodeLine: number
  readonly code: string
  readonly title: string | undefined
  readonly mode: BlockMode
  readonly reason: string | undefined
  /** Name of a file in `scripts/example-scaffolds` to compose this block into. */
  readonly scaffold: string | undefined
  /** True for a `tsx` fence, so the composed file is written with a `.tsx` extension. */
  readonly jsx: boolean
}

/** One generated line, and where in the documentation it came from. */
interface Origin {
  readonly mdxPath: string
  readonly mdxLine: number
  readonly fenceLine: number
}

class DocsExampleError extends Error {}

// ============================================================================
// Discovery
// ============================================================================

function walkMdx(dir: string): string[] {
  const found: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      found.push(...walkMdx(full))
      continue
    }
    if (entry.isFile() && entry.name.endsWith('.mdx')) found.push(full)
  }
  return found.sort()
}

function discover(): string[] {
  const files: string[] = []
  for (const scope of SCOPES) {
    const dir = join(DOCS_ROOT, scope)
    let stats
    try {
      stats = statSync(dir)
    } catch {
      throw new DocsExampleError(
        `typecheck-examples: the configured scope '${scope}' does not exist under ${DOCS_ROOT}. ` +
          'Update SCOPES in this script when a documentation directory moves.',
      )
    }
    if (!stats.isDirectory()) {
      throw new DocsExampleError(`typecheck-examples: the configured scope '${scope}' is not a directory.`)
    }
    files.push(...walkMdx(dir))
  }

  const known = new Set(files.map(file => relative(DOCS_ROOT, file)))
  const stale = Object.keys(LEGACY_UNCHECKED).filter(page => !known.has(page))
  if (stale.length > 0) {
    throw new DocsExampleError(
      'typecheck-examples: LEGACY_UNCHECKED names pages that no longer exist, so the list has rotted:\n' +
        stale.map(page => `  ${page}`).join('\n') +
        '\nDelete those lines. A stale exclusion silently un-checks nothing and hides a real one.',
    )
  }

  return files.filter(file => LEGACY_UNCHECKED[relative(DOCS_ROOT, file)] === undefined)
}

// ============================================================================
// Fence parsing
// ============================================================================

/** Read `key="value"` and `key=value` out of a fence's metadata string. */
function readMeta(meta: string, key: string): string | undefined {
  const quoted = new RegExp(`(?:^|\\s)${key}="([^"]*)"`).exec(meta)
  if (quoted !== null) return quoted[1]
  const bare = new RegExp(`(?:^|\\s)${key}=([^\\s]+)`).exec(meta)
  return bare === null ? undefined : bare[1]
}

function readMode(meta: string, where: string): BlockMode {
  const raw = readMeta(meta, 'docscheck')
  if (raw === undefined) return 'module'
  if (raw === 'module' || raw === 'member' || raw === 'statements' || raw === 'replace' || raw === 'skip') {
    return raw
  }
  throw new DocsExampleError(
    `${where}: unknown docscheck mode '${raw}'. Use module, member, statements, replace, or skip.`,
  )
}

function parseBlocks(mdxPath: string): Block[] {
  const lines = readFileSync(mdxPath, 'utf8').split('\n')
  const blocks: Block[] = []
  const rel = relative(REPO_ROOT, mdxPath)

  let index = 0
  while (index < lines.length) {
    const line = lines[index]!
    const opening = /^(\s*)```(\S*)\s*(.*)$/.exec(line)
    if (opening === null) {
      index += 1
      continue
    }
    const [, indent, language, meta] = opening as unknown as [string, string, string, string]

    // Find the closing fence at the same indentation.
    let end = index + 1
    while (end < lines.length && lines[end]!.trimEnd() !== `${indent}\`\`\``) end += 1

    if (TS_LANGUAGES.has(language)) {
      const where = `${rel}:${index + 1}`
      const mode = readMode(meta, where)
      const reason = readMeta(meta, 'docscheck-reason')
      if (mode === 'skip' && (reason === undefined || reason.trim() === '')) {
        throw new DocsExampleError(
          `${where}: docscheck=skip needs docscheck-reason="why this block cannot be checked". ` +
            'An unexplained opt-out is the failure mode this script exists to prevent.',
        )
      }
      blocks.push({
        mdxPath: rel,
        fenceLine: index + 1,
        firstCodeLine: index + 2,
        code: lines.slice(index + 1, end).join('\n'),
        title: readMeta(meta, 'title'),
        mode,
        reason,
        scaffold: readMeta(meta, 'docscheck-scaffold'),
        jsx: language === 'tsx',
      })
    }

    index = end + 1
  }

  return blocks
}

// ============================================================================
// Fixture assembly
// ============================================================================

/** A virtual file under construction: emitted lines plus where each came from. */
interface Fixture {
  readonly name: string
  /** The fence `title` this file was built from, when the blocks carried one. */
  readonly title: string | undefined
  /**
   * True when this file is a fragment composed into a scaffold rather than the
   * file the page documents, so a relative import must not be pointed at it.
   */
  readonly scaffolded: boolean
  readonly lines: string[]
  readonly origins: (Origin | null)[]
  /** True once any block in this file came from a `tsx` fence. */
  jsx: boolean
}

/** The file name a fixture is written under. JSX only parses in a `.tsx` file. */
function fixtureFileName(fixture: Fixture): string {
  return `${fixture.name}.${fixture.jsx ? 'tsx' : 'ts'}`
}

/** A quoted relative module specifier, such as `'./auth-provider'` or `'../lib/client'`. */
const RELATIVE_SPECIFIER = /(['"])((?:\.\.?\/)+[A-Za-z0-9._/-]+)\1/g

/** The file name a path refers to, without directories or extension. */
function moduleBaseName(path: string): string {
  return path.replace(/^.*\//, '').replace(/\.[cm]?tsx?$/, '')
}

function push(fixture: Fixture, text: string, origin: Origin | null): void {
  fixture.lines.push(text)
  fixture.origins.push(origin)
}

/**
 * Append a block's code, recording the documentation line behind each emitted
 * line. `indentBy` shifts a `member` block into a class body.
 */
function appendCode(fixture: Fixture, block: Block, indentBy: string): void {
  const codeLines = block.code.split('\n')
  codeLines.forEach((text, offset) => {
    push(fixture, text === '' ? '' : `${indentBy}${text}`, {
      mdxPath: block.mdxPath,
      mdxLine: block.firstCodeLine + offset,
      fenceLine: block.fenceLine,
    })
  })
}

/**
 * Split a `member` block into the imports it opens with and the members that
 * follow.
 *
 * A page showing one method routinely shows the import that method needs
 * directly above it, because that is the useful thing to read. Indenting an
 * `import` into a class body is a syntax error, so the imports are hoisted to
 * module level and the rest becomes class members. Returned as line index
 * ranges so each line keeps the documentation line it came from.
 */
function splitMemberImports(code: string): { importLines: number[]; memberLines: number[] } {
  const lines = code.split('\n')
  const importLines: number[] = []
  const memberLines: number[] = []

  let index = 0
  let seenMember = false
  while (index < lines.length) {
    const line = lines[index]!
    // Only hoist imports that appear before any member, so a string containing
    // the word `import` further down is never mistaken for one.
    if (!seenMember && /^import\b/.test(line)) {
      importLines.push(index)
      // A multi-line import runs until the line carrying its specifier.
      while (!/from\s+['"][^'"]+['"];?\s*$/.test(lines[index]!) && index + 1 < lines.length) {
        index += 1
        importLines.push(index)
      }
      index += 1
      continue
    }
    if (line.trim() !== '') seenMember = true
    memberLines.push(index)
    index += 1
  }

  return { importLines, memberLines }
}

/**
 * The index of the line holding the final `}` of the last class in a fixture.
 *
 * Deliberately simple: the last line that is exactly `}` at column zero, which
 * is what a formatted class declaration ends with. A `member` block whose
 * fixture has no such line is a documentation mistake rather than a parser
 * limitation, and it is reported as one.
 */
function lastClassClose(fixture: Fixture): number {
  for (let index = fixture.lines.length - 1; index >= 0; index -= 1) {
    if (fixture.lines[index] === '}') return index
  }
  return -1
}

const SCAFFOLD_DIR = join(HERE, 'example-scaffolds')

/**
 * Read a named scaffold: declarations a page deliberately leaves out, so a
 * fragment showing one method can still be checked against the real API.
 */
function loadScaffold(name: string, block: Block): string {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) {
    throw new DocsExampleError(
      `${block.mdxPath}:${block.fenceLine}: docscheck-scaffold='${name}' is not a scaffold name. ` +
        'Use lowercase letters, digits and hyphens.',
    )
  }
  try {
    return readFileSync(join(SCAFFOLD_DIR, `${name}.ts`), 'utf8')
  } catch {
    throw new DocsExampleError(
      `${block.mdxPath}:${block.fenceLine}: no scaffold named '${name}'. ` +
        `Add ${relative(REPO_ROOT, join(SCAFFOLD_DIR, `${name}.ts`))} or correct the fence.`,
    )
  }
}

/**
 * A page's identity inside the flat fixture directory.
 *
 * The route rather than the file name, because `docs/auth/jwt.mdx` and
 * `reference/auth/jwt.mdx` are two different pages: keying on the base name
 * alone merged their fixtures and reported each page's declarations as
 * duplicates of the other's.
 */
function pageKeyFor(mdxPath: string): string {
  return mdxPath
    .replace(/^.*\/content\/en\//, '')
    .replace(/\.mdx$/, '')
    .replace(/[^A-Za-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

function fixtureNameFor(mdxPath: string, title: string | undefined, fallback: number): string {
  const base = title === undefined ? `block-${fallback}` : title.replace(/[^A-Za-z0-9]+/g, '-').replace(/^-|-$/g, '')
  return `${pageKeyFor(mdxPath)}__${base}`
}

function buildFixtures(blocks: Block[]): Map<string, Fixture> {
  const fixtures = new Map<string, Fixture>()
  /** Title-name to the fixture key later blocks under that title append to. */
  const current = new Map<string, string>()
  const generations = new Map<string, number>()

  blocks.forEach((block, ordinal) => {
    if (block.mode === 'skip') return

    const scaffold = block.scaffold
    const name =
      scaffold === undefined
        ? fixtureNameFor(block.mdxPath, block.title, ordinal)
        : `${fixtureNameFor(block.mdxPath, block.title, ordinal)}--${scaffold}-${ordinal}`
    let key = current.get(name)

    if (key === undefined || block.mode === 'replace') {
      // `replace` restarts accumulation under a fresh key, so the partial
      // build-up and the finished file are both checked rather than one
      // overwriting the other.
      const generation = key === undefined ? 0 : (generations.get(name) ?? 0) + 1
      generations.set(name, generation)
      key = generation === 0 ? name : `${name}--${generation}`
      current.set(name, key)
      const fresh: Fixture = {
        name: key,
        title: block.title,
        scaffolded: scaffold !== undefined,
        lines: [],
        origins: [],
        jsx: false,
      }
      if (scaffold !== undefined) {
        for (const text of loadScaffold(scaffold, block).split('\n')) push(fresh, text, null)
      }
      fixtures.set(key, fresh)
    }

    const fixture = fixtures.get(key)!
    if (block.jsx) fixture.jsx = true

    if (block.mode === 'member') {
      const close = lastClassClose(fixture)
      if (close === -1) {
        throw new DocsExampleError(
          `${block.mdxPath}:${block.fenceLine}: docscheck=member needs a class to append to, and the ` +
            `accumulated file for title '${block.title ?? '(none)'}' declares none yet. Either an earlier ` +
            'block on this page must declare the class under the same title, or this block is not a member fragment.',
        )
      }
      const { importLines, memberLines } = splitMemberImports(block.code)
      const codeLines = block.code.split('\n')
      const originFor = (offset: number): Origin => ({
        mdxPath: block.mdxPath,
        mdxLine: block.firstCodeLine + offset,
        fenceLine: block.fenceLine,
      })

      // Imports go above the class, members go inside it.
      const tail = { lines: fixture.lines.splice(close), origins: fixture.origins.splice(close) }
      for (const offset of memberLines) {
        const text = codeLines[offset]!
        push(fixture, text === '' ? '' : `  ${text}`, originFor(offset))
      }
      tail.lines.forEach((text, offset) => push(fixture, text, tail.origins[offset] ?? null))
      if (importLines.length > 0) {
        const hoisted = importLines.map(offset => ({ text: codeLines[offset]!, origin: originFor(offset) }))
        fixture.lines.unshift(...hoisted.map(entry => entry.text))
        fixture.origins.unshift(...hoisted.map(entry => entry.origin))
      }
      return
    }

    if (block.mode === 'statements') {
      const { importLines, memberLines } = splitMemberImports(block.code)
      const codeLines = block.code.split('\n')
      const originFor = (offset: number): Origin => ({
        mdxPath: block.mdxPath,
        mdxLine: block.firstCodeLine + offset,
        fenceLine: block.fenceLine,
      })

      for (const offset of importLines) push(fixture, codeLines[offset]!, originFor(offset))
      push(fixture, `async function docsExample${ordinal}(): Promise<void> {`, null)
      for (const offset of memberLines) {
        const text = codeLines[offset]!
        push(fixture, text === '' ? '' : `  ${text}`, originFor(offset))
      }
      push(fixture, '}', null)
      push(fixture, `void docsExample${ordinal};`, null)
      return
    }

    if (fixture.lines.length > 0) push(fixture, '', null)
    appendCode(fixture, block, '')
  })

  return fixtures
}

// ============================================================================
// Type-checking
// ============================================================================

const TSCONFIG = {
  compilerOptions: {
    target: 'ES2022',
    lib: ['ES2023', 'DOM'],
    module: 'Preserve',
    moduleResolution: 'Bundler',
    strict: true,
    noEmit: true,
    // The examples are read by people, not bundled. An unused local in a
    // fragment that shows one method is not a documentation defect.
    noUnusedLocals: false,
    noUnusedParameters: false,
    // `@mastra/core`'s emitted declarations are checked by its own build.
    skipLibCheck: true,
    types: ['node'],
    resolveJsonModule: true,
    jsx: 'react-jsx',
    // Resolved against the built packages rather than their sources. See
    // {@link CHECKED_PACKAGES}.
    paths: packagePaths(),
  },
  include: ['*.ts', '*.tsx'],
}

interface Diagnostic {
  readonly file: string
  readonly line: number
  readonly column: number
  readonly text: string
}

/** `path/to/file.ts(12,5): error TS2339: ...` */
function parseDiagnostics(stdout: string): Diagnostic[] {
  const found: Diagnostic[] = []
  for (const line of stdout.split('\n')) {
    const match = /^(.+?)\((\d+),(\d+)\):\s*(.*)$/.exec(line)
    if (match === null) continue
    found.push({
      file: match[1]!,
      line: Number(match[2]),
      column: Number(match[3]),
      text: match[4]!,
    })
  }
  return found
}

function report(diagnostics: Diagnostic[], origins: Map<string, (Origin | null)[]>): string[] {
  const messages: string[] = []
  for (const diagnostic of diagnostics) {
    const key = diagnostic.file.replace(/^.*\//, '')
    const lineOrigins = origins.get(key)
    const origin = lineOrigins?.[diagnostic.line - 1] ?? null
    if (origin === null || origin === undefined) {
      messages.push(
        `  ${key}(${diagnostic.line},${diagnostic.column}): ${diagnostic.text}\n` +
          '    (in generated scaffolding rather than in a documented line)',
      )
      continue
    }
    messages.push(
      `  ${origin.mdxPath}:${origin.mdxLine}  ${diagnostic.text}\n` +
        `    in the code block opening at ${origin.mdxPath}:${origin.fenceLine}`,
    )
  }
  return messages
}

// ============================================================================
// Main
// ============================================================================

/**
 * Fail early and specifically when the packages the examples import have not
 * been built, rather than reporting a documented import as missing.
 */
function requireBuiltPackages(): void {
  const missing = CHECKED_PACKAGES.filter(entry => {
    try {
      statSync(join(distDir(entry), entry.proof))
      return false
    } catch {
      return true
    }
  })

  if (missing.length === 0) return

  throw new DocsExampleError(
    'typecheck-examples: the examples are checked against emitted declarations, and these are not built:\n' +
      missing.map(entry => `  ${entry.name} (expected ${entry.dist}/${entry.proof})`).join('\n') +
      '\n\nBuild them from the repository root:\n' +
      `  pnpm turbo build ${CHECKED_PACKAGES.map(entry => `--filter ${entry.filter}`).join(' ')}\n\n` +
      'Reporting this as a build problem rather than as a missing module keeps a stale checkout from ' +
      'looking like a documentation defect.',
  )
}

/**
 * Fail early and specifically when a vendored dependency has not been installed,
 * for the same reason: a missing `node_modules` is not a documentation defect.
 */
function requireVendoredPackages(): void {
  const missing = VENDORED_PACKAGES.filter(entry => {
    try {
      statSync(join(vendoredDir(entry), 'package.json'))
      return false
    } catch {
      return true
    }
  })

  if (missing.length === 0) return

  throw new DocsExampleError(
    'typecheck-examples: the examples import these third-party packages through the workspace package ' +
      'that depends on each, and they are not installed:\n' +
      missing.map(entry => `  ${entry.name} (expected ${entry.through}/node_modules/${entry.name})`).join('\n') +
      '\n\nRun pnpm install from the repository root.',
  )
}

function main(): number {
  requireBuiltPackages()
  requireVendoredPackages()
  const mdxFiles = discover()
  const blocks = mdxFiles.flatMap(parseBlocks)
  const checked = blocks.filter(block => block.mode !== 'skip')
  const skipped = blocks.filter(block => block.mode === 'skip')

  if (checked.length === 0) {
    console.error(
      'typecheck-examples: found no TypeScript examples to check. That is almost certainly a bug in ' +
        'this script or a moved directory rather than a documentation change.',
    )
    return 1
  }

  const fixtures = buildFixtures(checked)

  rmSync(OUT_DIR, { recursive: true, force: true })
  mkdirSync(OUT_DIR, { recursive: true })

  // Copy every scaffold next to the fixtures so a documented relative import
  // such as `./auth-provider` resolves to a real module.
  for (const entry of readdirSync(SCAFFOLD_DIR)) {
    if (entry.endsWith('.ts')) writeFileSync(join(OUT_DIR, entry), readFileSync(join(SCAFFOLD_DIR, entry), 'utf8'))
  }

  // A page's examples import each other by relative path (`./auth-provider`, or
  // `../../lib/mastra-client` from a component). Point those at the composed
  // fixture the same page built under that file name, so a conformance example
  // is checked against the provider the page actually documented rather than
  // against a stand-in that can drift from it. Everything lands in one flat
  // directory, so only the file name can carry the link, not the directories
  // above it.
  const byPageAndModule = new Map<string, string>()
  for (const fixture of fixtures.values()) {
    if (fixture.title === undefined || fixture.scaffolded) continue
    const page = /^(.+?)__/.exec(fixture.name)?.[1] ?? ''
    byPageAndModule.set(`${page}::${moduleBaseName(fixture.title)}`, fixture.name)
  }

  const origins = new Map<string, (Origin | null)[]>()
  for (const fixture of fixtures.values()) {
    const page = /^(.+?)__/.exec(fixture.name)?.[1] ?? ''
    const resolved = fixture.lines.map(line =>
      line.replace(RELATIVE_SPECIFIER, (whole, quote: string, specifier: string) => {
        const target = byPageAndModule.get(`${page}::${moduleBaseName(specifier)}`)
        return target === undefined || target === fixture.name ? whole : `${quote}./${target}${quote}`
      }),
    )
    const fileName = fixtureFileName(fixture)
    writeFileSync(join(OUT_DIR, fileName), `${resolved.join('\n')}\n`, 'utf8')
    origins.set(fileName, fixture.origins)
  }
  writeFileSync(join(OUT_DIR, 'tsconfig.json'), `${JSON.stringify(TSCONFIG, null, 2)}\n`, 'utf8')

  const tsc = spawnSync(
    process.execPath,
    [join(DOCS_ROOT, 'node_modules', 'typescript', 'bin', 'tsc'), '-p', join(OUT_DIR, 'tsconfig.json')],
    { cwd: DOCS_ROOT, encoding: 'utf8' },
  )

  const output = `${tsc.stdout ?? ''}${tsc.stderr ?? ''}`
  const diagnostics = parseDiagnostics(output)

  console.log(
    `Checked ${checked.length} TypeScript example${checked.length === 1 ? '' : 's'} ` +
      `from ${mdxFiles.length} page${mdxFiles.length === 1 ? '' : 's'}, ` +
      `as ${fixtures.size} composed file${fixtures.size === 1 ? '' : 's'}.`,
  )
  for (const block of skipped) {
    console.log(`  skipped ${block.mdxPath}:${block.fenceLine} - ${block.reason}`)
  }

  const debt = Object.keys(LEGACY_UNCHECKED).length
  if (debt > 0) {
    console.log(
      `${debt} page${debt === 1 ? '' : 's'} in scope are not checked yet (LEGACY_UNCHECKED in this script). ` +
        'Annotating one page and deleting its line is a self-contained change.',
    )
  }

  if (tsc.status === 0 && diagnostics.length === 0) {
    console.log('All documented examples type-check against the current contract.')
    return 0
  }

  console.error('\nDocumented examples do not type-check.\n')
  const messages = report(diagnostics, origins)
  if (messages.length > 0) {
    for (const message of messages) console.error(message)
  } else {
    console.error(output.trim() === '' ? '  tsc produced no output.' : output)
  }
  console.error(
    `\nThe generated files are in ${relative(REPO_ROOT, OUT_DIR)} if you want to read the composed source.\n` +
      'Every example on these pages is checked. To exclude one, add docscheck=skip and\n' +
      'docscheck-reason="..." to its fence, and expect a reviewer to ask about the reason.',
  )
  return 1
}

try {
  process.exit(main())
} catch (error) {
  if (error instanceof DocsExampleError) {
    console.error(error.message)
    process.exit(1)
  }
  throw error
}
