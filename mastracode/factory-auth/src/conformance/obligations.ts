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

/** One conformance failure, before it is turned into text. */
export interface ConformanceFailure {
  /** The provider, as the caller named it in the suite options. */
  readonly provider: string;

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

  return [
    title,
    '',
    indent(headline),
    '',
    'OBSERVED',
    indent(failure.observed.join('\n')),
    '',
    'WHY THIS EXISTS',
    indent(why),
    '',
    'HOW TO FIX IT',
    indent(how),
    '',
    `Docs: ${CONFORMANCE_DOCS_URL}`,
  ].join('\n');
}
