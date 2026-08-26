/**
 * What each conformance failure says, and why it says it.
 *
 * A conformance suite is only worth running if a red test teaches the person
 * who wrote the provider something they did not already know. "expected null to
 * be truthy" does not. So the failure text is treated here as the deliverable
 * rather than as a by-product of an assertion, and every message this package
 * emits is built from one shape:
 *
 *   headline   - what is wrong, naming the provider and the obligation
 *   OBSERVED   - what the suite actually did and what came back
 *   WHY        - the failure this obligation exists to prevent
 *   HOW TO FIX - code, against the real public API
 *   Docs       - a URL, because the reader may never have seen this repo
 *
 * The four obligations are named from {@link AUTH_OBLIGATIONS} and summarized
 * from {@link AUTH_OBLIGATION_SUMMARY} rather than restated, so a suite that
 * reports an obligation, a fake that violates one, and the guidance printed when
 * one fails all read from a single source. Adding a fifth obligation there is a
 * type error here until it is given guidance, which is the intended order of
 * work: nobody should be able to add an unexplained obligation.
 *
 * Nothing in this module imports a test runner. It is prose and string
 * assembly, so `src/__tests__/` can assert on the text a provider author will
 * read without registering a suite to do it.
 */
import { AUTH_OBLIGATION_SUMMARY, AUTH_OBLIGATIONS } from '../testing/index.js';
import type { AuthObligation } from '../testing/index.js';

/**
 * Where a provider author goes to read the long version.
 *
 * A full URL rather than a repo-relative path on purpose. The audience for
 * these messages is somebody publishing a provider from their own repository,
 * who has a stack trace and no checkout of this one.
 */
export const CONFORMANCE_DOCS_URL =
  'https://github.com/mastra-ai/mastra/blob/main/mastracode/factory-auth/README.md#start-here';

/**
 * This package's published name, as a value rather than as literal text inside
 * the code samples below.
 *
 * Not a stylistic choice, and worth the explanation. Every failure message here
 * carries copy-pasteable code, and copy-pasteable code contains import
 * statements. `src/__tests__/no-ee-boundary.test.ts` finds this package's
 * imports by scanning source for the literal shape `from` followed by a quoted
 * specifier, and it is fail-closed: a documentation sample written out in full
 * looks exactly like a real self-import to it, and it correctly refuses to guess
 * which one it is reading.
 *
 * So the samples are assembled from these values instead. That leaves the
 * scanner's job intact rather than evading it - a real import still has to be
 * written as a literal and would still be caught, and the graph assertion
 * resolves what is actually reachable either way.
 *
 * **The rule for anyone editing the prose in this file or in `./index.ts`:
 * never write the token `from` followed by a quote inside a string.** That
 * includes ordinary English - "tell a denial from \"broken\"" trips it too.
 */
export const KIT_PACKAGE_NAME = '@mastra/factory-auth';

/** The quote character {@link kitImport} wraps a specifier in. See {@link KIT_PACKAGE_NAME}. */
const QUOTE = "'";

/**
 * One import line for a code sample.
 *
 * ```ts
 * kitImport('{ getRequestHeader }', '/contract');
 * // import { getRequestHeader } from '@mastra/factory-auth/contract';
 * ```
 *
 * @param binding the import clause, braces and `type` included
 * @param subpath the entry point, with its leading slash
 */
export function kitImport(binding: string, subpath: string): string {
  return `import ${binding} from ${QUOTE}${KIT_PACKAGE_NAME}${subpath}${QUOTE};`;
}

/** How many obligations there are, for `obligation N of M`. */
export const AUTH_OBLIGATION_COUNT = AUTH_OBLIGATIONS.length;

/** The explanation printed when one obligation is not met. */
export interface AuthObligationGuidance {
  /** Which obligation. One of {@link AUTH_OBLIGATIONS}. */
  readonly obligation: AuthObligation;

  /**
   * Its 1-based position in {@link AUTH_OBLIGATIONS}, so a message can say
   * "obligation 2 of 4" and the README's numbered list and this suite agree.
   */
  readonly ordinal: number;

  /** The one-line statement of the rule, from {@link AUTH_OBLIGATION_SUMMARY}. */
  readonly summary: string;

  /**
   * The failure this obligation prevents, in the terms the person operating the
   * deployment would describe it.
   *
   * Every one of these is a real incident the auth audit found rather than a
   * hypothetical, which is why they read as symptoms ("signed in, then
   * immediately signed out") rather than as rules.
   */
  readonly why: string;

  /** How to satisfy it, as code against the published API. */
  readonly how: string;
}

/**
 * One entry per obligation. Prose, kept next to the rule it explains.
 *
 * `Readonly<Record<AuthObligation, ...>>` rather than an array: a new obligation
 * in `src/testing/index.ts` fails to compile here until somebody writes down
 * what it is for.
 */
export const AUTH_OBLIGATION_GUIDANCE: Readonly<Record<AuthObligation, AuthObligationGuidance>> = {
  flatId: {
    obligation: 'flatId',
    ordinal: AUTH_OBLIGATIONS.indexOf('flatId') + 1,
    summary: AUTH_OBLIGATION_SUMMARY.flatId,
    why:
      'Every Factory surface that persists anything keys on this id: agent state, stored model\n' +
      'credentials, run history, and the organization fallback. A payload that carries its id\n' +
      'somewhere nested - `{ data: { user: { id } } }` is the shape that actually ships - leaves the\n' +
      'host with no key, so the request authenticates as nobody and then fails somewhere unrelated,\n' +
      'with a message about whatever ran next.',
    how:
      'Return the id at the top level, under `id`, `uid` or `sub`:\n' +
      '\n' +
      '  async authenticateToken(token, request) {\n' +
      '    const claims = await this.verify(token);\n' +
      '    return { id: claims.sub, email: claims.email };\n' +
      '  }\n' +
      '\n' +
      'Or keep your payload shape and map it yourself. `toAuthIdentity` hands the whole job to a\n' +
      'provider that implements `toIdentity`, including when it answers null:\n' +
      '\n' +
      `  ${kitImport('type { IIdentityProvider }', '/identity')}\n` +
      '\n' +
      '  class MyProvider extends MastraAuthProvider implements IIdentityProvider {\n' +
      '    toIdentity(raw: unknown) {\n' +
      '      const user = (raw as { data?: { user?: { id?: string } } }).data?.user;\n' +
      '      return user?.id ? { id: user.id, email: user.email } : null;\n' +
      '    }\n' +
      '  }',
  },

  cookieAuth: {
    obligation: 'cookieAuth',
    ordinal: AUTH_OBLIGATIONS.indexOf('cookieAuth') + 1,
    summary: AUTH_OBLIGATION_SUMMARY.cookieAuth,
    why:
      'A browser navigating to your app sends no Authorization header. It sends cookies. A provider\n' +
      'that reads only the bearer token therefore authenticates every browser navigation as nobody,\n' +
      'and the person sees "signed in, then immediately signed out" - a redirect loop with nothing in\n' +
      'the logs that says why. The empty string is the host telling you this request has no bearer\n' +
      'token, so look where a browser would have put one.',
    how:
      'Fall back to the Cookie header when `token` is empty:\n' +
      '\n' +
      `  ${kitImport('{ getRequestHeader }', '/contract')}\n` +
      '\n' +
      '  async authenticateToken(token, request) {\n' +
      "    const header = getRequestHeader(request, 'cookie') ?? '';\n" +
      '    const bearer = token || readMyCookie(header);\n' +
      '    if (!bearer) return null;\n' +
      '    return this.verify(bearer);\n' +
      '  }\n' +
      '\n' +
      '`getRequestHeader` is re-exported from this package and reads a plain Request, a Hono context\n' +
      'request, and anything shaped like one, so it costs you no web-framework dependency.\n' +
      '\n' +
      'If you would rather the host own the cookie than parse your own,\n' +
      '`@mastra/factory-auth/cookie` mints and reads a signed, HttpOnly one under a name it declares -\n' +
      'see `readSessionCookie`. Either way the provider has to read the header; nothing upstream can\n' +
      'do it for you, because only you know what your token looks like.',
  },

  stateCodec: {
    obligation: 'stateCodec',
    ordinal: AUTH_OBLIGATIONS.indexOf('stateCodec') + 1,
    summary: AUTH_OBLIGATION_SUMMARY.stateCodec,
    why:
      '`state` is the only value that survives the whole hosted-login round trip, so the host uses it\n' +
      'to carry where the person was going before they were bounced to a login screen. Two failures\n' +
      'follow from breaking it, and neither one gets filed as a bug. A provider that re-encodes\n' +
      '`state` degrades every post-login redirect to `/`, which just looks like the app being\n' +
      'forgetful. A provider that keys its own state store on one substring and looks it up under\n' +
      'another rejects the callback outright with "invalid or expired state", on every sign-in,\n' +
      'forever.',
    how:
      'Treat `state` as opaque. Put exactly what you were handed into the authorization URL:\n' +
      '\n' +
      '  getLoginUrl(redirectUri, state) {\n' +
      '    const url = new URL(`${this.issuer}/authorize`);\n' +
      "    url.searchParams.set('redirect_uri', redirectUri);\n" +
      "    url.searchParams.set('state', state); // unchanged - URLSearchParams escapes it for you\n" +
      '    return url.toString();\n' +
      '  }\n' +
      '\n' +
      'If you keep a state store, key it on the same value the callback will hand back. The host\n' +
      'passes `handleCallback` the raw `state` from the query string, so that is the key:\n' +
      '\n' +
      '  getLoginUrl(redirectUri, state) { this.states.set(state, { redirectUri }); /* ... */ }\n' +
      '  async handleCallback(code, state) {\n' +
      '    const stored = this.states.get(state); // the same string, not a slice of it\n' +
      '  }\n' +
      '\n' +
      'To read the two halves, use the codec rather than splitting by hand: `parseStateId(state)` is\n' +
      'the id and `decodeState(state).returnTo` is the destination, both from\n' +
      "'@mastra/factory-auth/oauth-state'. The first `|` is the delimiter and the only significant\n" +
      'one; a returnTo may contain more.',
  },

  organizationId: {
    obligation: 'organizationId',
    ordinal: AUTH_OBLIGATIONS.indexOf('organizationId') + 1,
    summary: AUTH_OBLIGATION_SUMMARY.organizationId,
    why:
      'Every organization-scoped surface in the Factory writes to one column that is not nullable. A\n' +
      'provider that resolves no organization leaves each of those surfaces to invent its own\n' +
      'fallback or to answer 403, and historically they have done both - so the same user could store\n' +
      'a model credential and then be refused the page that reads it back.\n' +
      '\n' +
      'Having no organization concept is not the problem, and it is not a reason to fail this. Not\n' +
      'resolving to anything is.',
    how:
      'If your provider has no organizations, wrap it once. Every capability it had is preserved and\n' +
      'one is added:\n' +
      '\n' +
      `  ${kitImport('{ withSyntheticOrganizations }', '/organizations')}\n` +
      '\n' +
      '  export const auth = withSyntheticOrganizations(new MyProvider());\n' +
      '\n' +
      'The id it derives is `user:${userId}`: a pure function of the user id, with no store behind it,\n' +
      'so two processes agree without talking to each other.\n' +
      '\n' +
      'If your provider does have organizations, implement `IOrganizationsProvider` and make\n' +
      '`ensureOrganization` deterministic - the same user id must get the same organization id on\n' +
      'every call and in every process. A value that changes per call silently partitions that\n' +
      "user's data against itself. Wrapping is still worth doing: `ensureOrganization` is documented\n" +
      'as best-effort, and the wrapper supplies the synthetic id exactly when your implementation\n' +
      'declines to supply one, never overriding an answer you gave.',
  },
};

// ============================================================================
// Failure codes
// ============================================================================

/**
 * The stable name of one *way* a check can go red.
 *
 * Every check can fail for several different reasons - `sessions/round-trip`
 * has five - and until this existed nothing told those reasons apart except the
 * prose of the message, which this package's own semver policy declares
 * patch-level and asks you not to assert on. So the reasons are named
 * separately here, and the name rather than the wording is what
 * {@link AuthConformanceKnownFailure} records.
 *
 * The format is the check id, a `#`, and a slug:
 * `sessions/round-trip#validate-rejects-fresh-session`. That makes the check a
 * code belongs to readable without a lookup, and lets a mistyped pairing be
 * caught rather than accepted.
 *
 * One namespace is deliberately not check-scoped. A failure raised by a shared
 * fixture step - the `token` option the provider will not accept, the missing
 * `userId` - is named `fixture/...`, because the same fault surfaces from
 * whichever check happened to need a payload first. Those are mistakes in the
 * calling test file rather than provider defects, and
 * {@link AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX} is what keeps them out of the set
 * a `knownFailures` entry may name: "my fixtures are wrong" is not a thing to
 * grant a provider an exemption for.
 */
export type AuthConformanceFailureCode = string;

/** The namespace for a failure that is about the fixtures, not about the provider. */
export const AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX = 'fixture/';

/** Whether `code` names a fixture fault rather than a provider defect. */
export function isFixtureFailureCode(code: string): boolean {
  return code.startsWith(AUTH_CONFORMANCE_FIXTURE_CODE_PREFIX);
}

/**
 * Where {@link attachFailureCode} puts the code, and
 * {@link readFailureCode} reads it back.
 *
 * A property on the thrown assertion rather than a substring of the rendered
 * message. The message is prose and may be reworded in a patch; the code is the
 * thing callers key on, so it travels structurally and survives any rewording.
 * Non-enumerable, so a reporter that serializes the error does not grow a field.
 */
const FAILURE_CODE_PROPERTY = '__mastraAuthConformanceFailureCode';

/**
 * Mark `error` as the failure named by `code`, and hand it back.
 *
 * Called on an assertion that vitest built, so the value keeps its
 * `AssertionError` identity and still reports as "your provider is wrong"
 * rather than as "the conformance suite crashed".
 */
export function attachFailureCode<T>(error: T, code: string): T {
  if (typeof error === 'object' && error !== null) {
    Object.defineProperty(error, FAILURE_CODE_PROPERTY, {
      value: code,
      enumerable: false,
      configurable: true,
      writable: true,
    });
  }
  return error;
}

/**
 * The code {@link attachFailureCode} put on this error, or `null`.
 *
 * `null` for anything the suite did not raise itself - a provider that threw
 * out of a check body in a way no `fail` site anticipated, or a bare `expect`
 * somewhere. That distinction matters to the known-failure machinery: an
 * uncoded failure can never match a recorded entry, so it can never be covered
 * by one.
 */
export function readFailureCode(error: unknown): string | null {
  if (typeof error !== 'object' || error === null) return null;
  const code: unknown = (error as Record<string, unknown>)[FAILURE_CODE_PROPERTY];
  return typeof code === 'string' && code !== '' ? code : null;
}

/** One conformance failure, before it is turned into text. */
export interface ConformanceFailure {
  /** The provider, as the caller named it in the suite options. */
  readonly provider: string;

  /**
   * Which way this check went red. See {@link AuthConformanceFailureCode}.
   *
   * Optional on this type and required at every call site inside the suite: an
   * external caller of {@link formatConformanceFailure} predates the field, and
   * making it required here would narrow a published input. `src/conformance/
   * index.ts` narrows it back for its own use.
   */
  readonly code?: string;

  /**
   * The obligation this failure belongs to, when it is one of the four.
   *
   * Absent for a failure against the declared contract - a `getLoginButtonConfig`
   * that returns no text is wrong, but it is not one of the four things the
   * contract never wrote down.
   */
  readonly obligation?: AuthObligation;

  /**
   * What is wrong, in one line, when the obligation's own summary is not the
   * right sentence. Required for a contract failure, which has no obligation to
   * borrow one from.
   */
  readonly headline?: string;

  /**
   * What the suite did and what came back, one line per fact.
   *
   * Write the call and the answer, not the assertion. "authenticateToken('',
   * request) resolved to null" is a fact the reader can go and reproduce;
   * "expected null to be truthy" is a fact about vitest.
   */
  readonly observed: readonly string[];

  /** Why it matters. Defaults to the obligation's, and is required without one. */
  readonly why?: string;

  /** How to fix it. Defaults to the obligation's, and is required without one. */
  readonly how?: string;
}

/** Indent every line of a block by two spaces, leaving blank lines blank. */
function indent(block: string): string {
  return block
    .split('\n')
    .map(line => (line.length === 0 ? line : `  ${line}`))
    .join('\n');
}

/**
 * The layout every message in this package shares: a title, then shouted
 * section headings over indented blocks, then the docs URL.
 *
 * Factored out rather than repeated, because there are now three kinds of
 * message - a violation, a recorded known failure, and a recorded entry that has
 * gone stale - and a reader who has learned to scan one has learned to scan all
 * three. A section whose body is `undefined` is dropped entirely.
 */
function renderSections(title: string, sections: readonly (readonly [string | null, string | undefined])[]): string {
  const lines: string[] = [title];
  for (const [heading, body] of sections) {
    if (body === undefined) continue;
    lines.push('');
    if (heading !== null) lines.push(heading);
    lines.push(indent(body));
  }
  lines.push('', `Docs: ${CONFORMANCE_DOCS_URL}`);
  return lines.join('\n');
}

/**
 * The `CODE` block, and the offer that goes with it.
 *
 * Printed on every provider defect, because the moment somebody is reading a
 * red is the moment they need to know both the name of what broke and that
 * recording it is an option. A fixture fault gets the name without the offer:
 * `knownFailures` grants a provider an exemption, and "the token I told the
 * suite to use does not work" is not something to be exempt from.
 */
function codeBlock(code: string | undefined): string | undefined {
  if (code === undefined || code === '') return undefined;
  if (isFixtureFailureCode(code)) return code;
  return (
    `${code}\n` +
    '\n' +
    'Cannot fix this one now? Record it rather than excluding the provider or leaving CI red:\n' +
    '\n' +
    '  knownFailures: [\n' +
    `    { check: ${QUOTE}${code.split('#')[0]}${QUOTE}, code: ${QUOTE}${code}${QUOTE}, reason: ${QUOTE}why, and where the diagnosis lives${QUOTE} },\n` +
    '  ]\n' +
    '\n' +
    'The suite then reports it as a known failure instead of a red, and goes red again the day it\n' +
    'stops failing, stops applying, or starts failing for a different reason than the one recorded.'
  );
}

/**
 * Render a failure as the text a provider author reads.
 *
 * The layout follows `src/__tests__/no-ee-boundary.test.ts`: a headline that
 * names the violation, the offending detail with enough context to act on, and
 * a pointer to the documentation. The sections are shouted in caps for the same
 * reason that test's are - a vitest failure arrives inside a wall of stack
 * frames, and the reader is scanning rather than reading.
 *
 * @throws Error when a failure carries no obligation and no `headline`, `why` or
 * `how`. That is a bug in the suite rather than in the provider under test, and
 * an unexplained failure message is the one outcome this module exists to
 * prevent.
 */
export function formatConformanceFailure(failure: ConformanceFailure): string {
  const guidance = failure.obligation === undefined ? undefined : AUTH_OBLIGATION_GUIDANCE[failure.obligation];
  const headline = failure.headline ?? guidance?.summary;
  const why = failure.why ?? guidance?.why;
  const how = failure.how ?? guidance?.how;

  if (headline === undefined || why === undefined || how === undefined) {
    throw new Error(
      'formatConformanceFailure was given a failure with no obligation and no headline/why/how. ' +
        'Every conformance failure has to explain itself; see src/conformance/obligations.ts.',
    );
  }

  const title =
    guidance === undefined
      ? `Auth conformance violation: ${failure.provider} does not meet the provider contract.`
      : `Auth conformance violation: ${failure.provider} does not meet obligation ` +
        `${guidance.ordinal} of ${AUTH_OBLIGATION_COUNT}, '${guidance.obligation}'.`;

  return renderSections(title, [
    [null, headline],
    ['OBSERVED', failure.observed.join('\n')],
    ['WHY THIS EXISTS', why],
    ['HOW TO FIX IT', how],
    ['CODE', codeBlock(failure.code)],
  ]);
}

// ============================================================================
// Known failures
// ============================================================================

/**
 * The marker on the title of a check the caller recorded as a known failure.
 *
 * A prefix on the `it` title rather than only a note on the skip, so the
 * declaration is visible in any output that prints test names at all - a
 * verbose run, a list reporter, a CI job summary - without the reader having to
 * expand a skip reason. Exported so a host that filters or greps a run can key
 * on it instead of on a substring somebody may reword.
 */
export const KNOWN_FAILURE_TITLE_PREFIX = 'known failure: ';

/** One recorded known failure, as it is reported when it fails as recorded. */
export interface KnownFailureReport {
  /** The provider, as the caller named it in the suite options. */
  readonly provider: string;

  /** The check that failed. */
  readonly check: string;

  /** The failure code recorded for it, which is the one it produced. */
  readonly code: string;

  /** The caller's stated reason. */
  readonly reason: string;

  /** What the check actually said, unedited. */
  readonly message: string;
}

/**
 * Render a check that failed exactly as its `knownFailures` entry recorded.
 *
 * Deliberately *not* quiet. The suite stays green, and the run has to stay
 * obviously different from a clean one - so this carries the same shouted
 * layout as a violation, quotes the reason the caller gave, and reproduces the
 * original failure underneath it. A reader scanning CI sees a provider that
 * does not conform and the sentence somebody wrote about why.
 */
export function formatKnownFailure(report: KnownFailureReport): string {
  return renderSections(
    `Auth conformance KNOWN FAILURE: ${report.provider} does not conform, and this suite was told to expect it.`,
    [
      [null, `${report.check} failed with ${report.code}, which is what its knownFailures entry records.`],
      ['RECORDED REASON', report.reason],
      ['THE FAILURE ITSELF, UNCHANGED', report.message],
      [
        'WHAT MAKES THIS DIFFERENT FROM AN EXCLUSION',
        'The entry is checked in both directions on every run. This check going green, ceasing to\n' +
          'apply, or failing for a different reason than the one recorded all fail the suite, so the\n' +
          'entry cannot quietly outlive the defect it describes.',
      ],
    ],
  );
}

/** Why a recorded entry is no longer true. */
export type StaleKnownFailureKind = 'passed' | 'skipped' | 'different-code';

/** One recorded entry that no longer describes what the check does. */
export interface StaleKnownFailureReport {
  /** The provider, as the caller named it in the suite options. */
  readonly provider: string;

  /** The check the entry names. */
  readonly check: string;

  /** The code the entry records. */
  readonly code: string;

  /** The caller's stated reason. */
  readonly reason: string;

  /** What happened instead. */
  readonly kind: StaleKnownFailureKind;

  /** The gate's reason, for `skipped`; the actual failure, for `different-code`. */
  readonly detail?: string;

  /** The code the check actually produced, for `different-code`. */
  readonly actualCode?: string | null;
}

/**
 * Render a recorded entry that has stopped being true.
 *
 * This is the assertion that keeps the list from rotting, and it is a failure
 * of the *test file* rather than of the provider - so the title says so. A
 * provider whose defect was fixed must lose its entry in the same change,
 * because an exemption nobody is forced to delete is how a list becomes fiction.
 */
export function formatStaleKnownFailure(report: StaleKnownFailureReport): string {
  const headline =
    report.kind === 'passed'
      ? `${report.check} is recorded as a known failure, and it passed.`
      : report.kind === 'skipped'
        ? `${report.check} is recorded as a known failure, and it did not run at all.`
        : `${report.check} is recorded as a known failure, and it failed for a different reason.`;

  const observed =
    report.kind === 'passed'
      ? [
          `The knownFailures entry records ${report.code}.`,
          `${report.check} passed, so there is nothing for the entry to cover.`,
        ].join('\n')
      : report.kind === 'skipped'
        ? [
            `The knownFailures entry records ${report.code}.`,
            `${report.check} was skipped, because a structural guard says it does not apply to this`,
            'provider:',
            `  ${report.detail ?? '(no reason given)'}`,
            'A check that does not apply cannot be failing, so the entry covers nothing.',
          ].join('\n')
        : [
            `The knownFailures entry records ${report.code}.`,
            `${report.check} failed with ${report.actualCode ?? '(no code: the failure did not come from a check assertion)'}.`,
            '',
            'What it actually said:',
            indent(report.detail ?? '(no message)'),
          ].join('\n');

  const why =
    report.kind === 'different-code'
      ? 'An entry records one named defect, not "this check may fail". Letting any failure of a listed\n' +
        'check count would make the entry cover a second, unrelated regression that arrived later in\n' +
        'the same check - which is the exact outcome recording a known failure is supposed to rule\n' +
        'out. A check with several ways to go red is the normal case: matching on which one is what\n' +
        'keeps the record specific enough to be worth having.'
      : 'A recorded known failure is an admission with an expiry date. The suite fails when one stops\n' +
        'being true so that fixing the defect forces the entry to be deleted in the same change. An\n' +
        'exemption nobody is ever made to remove stops describing the provider and starts granting it\n' +
        'cover, and nothing reports that it happened.';

  const how =
    report.kind === 'passed'
      ? `Delete the knownFailures entry for ${report.check}. If the defect was fixed, that is the whole\n` +
        'change, and this failure is the suite asking you to make it.'
      : report.kind === 'skipped'
        ? `Delete the knownFailures entry for ${report.check}. The provider no longer declares the\n` +
          'capability the check is about, so the check is not being skipped over a defect - there is\n' +
          'nothing left for the entry to admit to.'
        : 'Read the failure above. If it is the same defect surfacing at a different point, update the\n' +
          "entry's `code` and its `reason` to match. If it is a new defect, that is a regression this\n" +
          'record just caught: fix it, or record it separately and say so.';

  return renderSections(
    `Auth conformance knownFailures entry is stale: ${report.provider} lists ${report.check}, ` +
      'and that is no longer what happens.',
    [
      [null, headline],
      ['OBSERVED', observed],
      ['RECORDED REASON', report.reason],
      ['WHY THIS EXISTS', why],
      ['HOW TO FIX IT', how],
    ],
  );
}
