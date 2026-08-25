/**
 * The OAuth `state` parameter codec.
 *
 * `state` is the one value that survives the whole hosted-login round trip: the
 * host mints it, hands it to `getLoginUrl`, the identity provider echoes it back
 * on the callback, and the host hands the raw value to `handleCallback`. Because
 * it is the only channel that crosses that boundary, the host uses it to carry
 * where the user was going before they were bounced to a login screen.
 *
 * That makes its format a contract between the host and every provider, and the
 * audit found it written down nowhere. One of the four undocumented obligations
 * is exactly this: a provider that re-encodes `state`, or that reads it as JSON,
 * or that splits it on the wrong character, silently degrades every post-login
 * redirect to `/` - and a redirect that quietly goes to the wrong place is the
 * kind of bug nobody files.
 *
 * So the format is declared here, in one place, with the encoder and the decoder
 * next to it.
 *
 * THE WIRE FORMAT
 *
 *   state          := id "|" encodedReturnTo
 *   id             := one or more characters, none of them "|"
 *   encodedReturnTo := encodeURIComponent(returnTo)
 *
 * Concretely, `encodeState('/agents/42')` produces:
 *
 *   3f2b8c1e-...-9a7d|%2Fagents%2F42
 *
 * Three properties hold this together, and each one is load-bearing:
 *
 * 1. **The FIRST `|` is the delimiter, and it is the only significant one.**
 *    Everything after it is the encoded `returnTo`, however many further pipes
 *    appear. Splitting on every `|` and taking element 1 works right up until a
 *    `returnTo` contains one.
 * 2. **`returnTo` is percent-encoded, so it cannot contain a raw `|`.**
 *    `encodeURIComponent('|')` is `%7C`. A `returnTo` of `/search?q=a|b` round
 *    trips exactly, which is the case that makes property 1 observable.
 * 3. **The id never contains `|`.** `encodeState` generates a UUID, which cannot
 *    contain one, and rejects a caller-supplied id that does. So "before the
 *    first pipe" and "the id" are the same substring, always.
 *
 * WHAT `state` IS NOT
 *
 * It is not signed, not encrypted, and not authenticated. Anyone who can see a
 * login URL can read the `returnTo` out of it, and anyone can craft a `state`
 * value from nothing. The id half exists so a host can implement CSRF protection
 * on top - mint it, stash it somewhere the attacker cannot write, and compare it
 * with {@link parseStateId} on the callback - but this module performs no such
 * check and cannot. If you need integrity, sign the value; see `./cookie` for
 * this package's HMAC helpers.
 *
 * That is also why {@link decodeState} sanitizes rather than trusts: see its own
 * documentation for the exact guarantee.
 *
 * Named `./oauth-state`, not `./state`: `FactoryAuthState` in factory-ui already
 * means "am I signed in", and `mastracode/factory/src/state-signing.ts` owns a
 * different signed `state` for integration installs. This is the OAuth spec
 * parameter: a nonce plus where to send the user after login.
 */
import { randomUUID } from 'node:crypto';

/**
 * The single significant delimiter, exported so a provider implementing the
 * other half of the contract does not have to hardcode it.
 */
export const OAUTH_STATE_DELIMITER = '|';

/**
 * Where a user goes when the `state` carries no usable destination.
 *
 * Every failure mode in {@link decodeState} lands here: absent input, a value
 * with no delimiter, a malformed percent escape, and every rejected redirect.
 * "Signed in, but back at the top of the app" is a mildly annoying outcome;
 * "signed in, and redirected to an attacker's page" is not.
 */
export const DEFAULT_RETURN_TO = '/';

/** The two halves of a decoded `state`. */
export interface DecodedOAuthState {
  /**
   * The opaque id half, or `null` when the value carries none.
   *
   * Compare it against something you stored at login time to get CSRF
   * protection. On its own it proves nothing: see {@link parseStateId}.
   */
  id: string | null;

  /**
   * Where to send the user, always safe to use as a same-origin redirect
   * target. See {@link decodeState} for precisely what that guarantees.
   */
  returnTo: string;
}

/**
 * Reduce an untrusted `returnTo` to a same-origin path, or to
 * {@link DEFAULT_RETURN_TO}.
 *
 * Rejects, in order:
 *
 * - anything that is not an absolute path, which covers `https://evil.com` and
 *   `javascript:alert(1)` in one rule;
 * - `//evil.com` and `/\evil.com`, which are protocol-relative URLs that a
 *   naive "starts with a slash" check waves straight through;
 * - anything containing a control character, because a `returnTo` normally ends
 *   up in a `Location` header and a raw CR or LF there is response splitting.
 *
 * Deliberately not a URL parser. A parser would have to decide what to do with
 * every exotic-but-valid URL, and this only needs to answer one question: is
 * this a path inside our own app.
 */
function sanitizeReturnTo(candidate: string | null | undefined): string {
  if (!candidate) return DEFAULT_RETURN_TO;
  if (!candidate.startsWith('/')) return DEFAULT_RETURN_TO;
  if (candidate.startsWith('//') || candidate.startsWith('/\\')) return DEFAULT_RETURN_TO;
  // eslint-disable-next-line no-control-regex -- matching control characters is the point.
  if (/[\u0000-\u001f\u007f]/.test(candidate)) return DEFAULT_RETURN_TO;
  return candidate;
}

/**
 * Build an OAuth `state` value carrying a post-login destination.
 *
 * ```ts
 * const state = encodeState(c.req.query('returnTo'));
 * const loginUrl = await provider.getLoginUrl(redirectUri, state);
 * ```
 *
 * Pass an explicit `id` when you intend to check it on the callback: mint it,
 * store it where the user's browser cannot forge it, then compare it with
 * {@link parseStateId}. Omit it and a UUID is generated, which carries the
 * `returnTo` correctly but gives you nothing to compare against.
 *
 * ENCODE TRUSTS ITS CALLER; DECODE TRUSTS NOTHING
 *
 * The two halves of this codec are handed different kinds of input, so they
 * behave differently on bad input, on purpose:
 *
 * - `returnTo` is usually a query parameter, so it is hostile by default. It is
 *   sanitized to {@link DEFAULT_RETURN_TO} rather than rejected, because
 *   throwing here would turn "someone poked at your login URL" into a 500.
 * - `id` comes from your own code. A bad one is a bug, and it corrupts the wire
 *   format for every later reader, so it throws immediately.
 *
 * @param returnTo Where to send the user after login. Anything that is not a
 * safe same-origin path becomes {@link DEFAULT_RETURN_TO}.
 * @param id Optional caller-supplied id. Must be non-empty and must not contain
 * `|`.
 * @throws Error when `id` is empty or contains the delimiter.
 */
export function encodeState(returnTo?: string | null, id: string = randomUUID()): string {
  if (id.length === 0) {
    throw new Error(
      'encodeState was given an empty state id. Pass a non-empty id, or omit it to get a generated UUID.',
    );
  }
  if (id.includes(OAUTH_STATE_DELIMITER)) {
    throw new Error(
      `encodeState was given a state id containing '${OAUTH_STATE_DELIMITER}', which is the format's delimiter: ` +
        `'${id}'. Everything after the first delimiter is read as the returnTo, so this id would be truncated and ` +
        `the returnTo lost. Use an id with no '${OAUTH_STATE_DELIMITER}' in it.`,
    );
  }
  return `${id}${OAUTH_STATE_DELIMITER}${encodeURIComponent(sanitizeReturnTo(returnTo))}`;
}

/**
 * Read the id half out of a raw `state`, without decoding the rest.
 *
 * Separate from {@link decodeState} because the two answer different questions
 * at different moments. A host checking CSRF on the callback wants the id and
 * nothing else, and wants it even when the `returnTo` half is garbage - a
 * tampered destination should still let you detect the tampering rather than
 * throw the whole value away.
 *
 * ```ts
 * if (parseStateId(c.req.query('state')) !== stashedStateId) return unauthorized();
 * ```
 *
 * A value with no delimiter is treated as all id and no destination, which is
 * what a `state` minted by something other than {@link encodeState} looks like.
 * So a non-`null` return means "there was something here to call an id" and
 * never "this value came from this package".
 *
 * @returns The id, or `null` when the input is absent or its id half is empty.
 */
export function parseStateId(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const delimiter = raw.indexOf(OAUTH_STATE_DELIMITER);
  if (delimiter === -1) return raw;
  if (delimiter === 0) return null;
  return raw.slice(0, delimiter);
}

/**
 * Read a raw `state` back into its two halves.
 *
 * ```ts
 * const { returnTo } = decodeState(c.req.query('state'));
 * return c.redirect(returnTo);
 * ```
 *
 * WHAT THIS GUARANTEES
 *
 * - It never throws and never rejects. Every input produces a
 *   {@link DecodedOAuthState}, including `undefined`, `''`, a JSON blob, and a
 *   value with a malformed percent escape.
 * - `returnTo` is always safe to hand to a redirect: it begins with exactly one
 *   `/`, is never protocol-relative (`//evil.com`, `/\evil.com`), never carries
 *   a scheme, and contains no control characters. When the input does not yield
 *   such a path, it is {@link DEFAULT_RETURN_TO}.
 * - A `returnTo` that contains the delimiter round trips through
 *   {@link encodeState} unchanged.
 *
 * WHAT THIS DOES NOT GUARANTEE
 *
 * - **Not authenticity.** The value is unsigned. A non-default `returnTo` only
 *   means somebody encoded a path, not that we encoded it.
 * - **Not freshness.** There is no nonce store, no expiry and no replay
 *   protection here. Comparing {@link DecodedOAuthState.id} against a value you
 *   stashed at login time is the caller's job.
 * - **Not that the route exists.** `/nope` sanitizes clean. A 404 after login is
 *   the router's business.
 * - **Not that the input came from {@link encodeState}.** A foreign `state`
 *   decodes to its own text as the id and {@link DEFAULT_RETURN_TO} as the
 *   destination, rather than failing. That is deliberate: providers that mint
 *   their own `state` still have to be able to complete a callback.
 */
export function decodeState(raw: string | null | undefined): DecodedOAuthState {
  const id = parseStateId(raw);
  if (!raw) return { id, returnTo: DEFAULT_RETURN_TO };

  const delimiter = raw.indexOf(OAUTH_STATE_DELIMITER);
  if (delimiter === -1) return { id, returnTo: DEFAULT_RETURN_TO };

  const encoded = raw.slice(delimiter + 1);
  let decoded: string;
  try {
    decoded = decodeURIComponent(encoded);
  } catch {
    // A malformed percent escape such as `%zz`. Not recoverable, and not worth
    // distinguishing from any other unusable destination.
    return { id, returnTo: DEFAULT_RETURN_TO };
  }
  return { id, returnTo: sanitizeReturnTo(decoded) };
}
