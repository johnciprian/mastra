/**
 * The host-owned session cookie.
 *
 * A browser navigating to the app sends no `Authorization` header. It sends
 * cookies. So every provider that can sign a user in from a browser needs a
 * cookie somewhere in the loop, and the audit found that nobody owned it: the
 * host reached through to one provider's cookie name by regex, which works for
 * exactly that provider and fails silently - as "signed in, then immediately
 * signed out" - for every other one.
 *
 * This module gives the host its own cookie, under its own name, signed with its
 * own secret, with no provider involved. A provider's `authenticateToken` then
 * gets a token it can verify, and the question "whose cookie is this" stops
 * being a regex.
 *
 * WRITTEN FRESH, NOT PORTED
 *
 * `CookieSessionProvider` in `@internal/auth` is Apache-2.0 and does something
 * adjacent, but it is not reachable from here: that package is private to the
 * monorepo, its barrel re-exports `ee/`, and its declaration chain reaches the
 * enterprise-bearing root barrel. It also has no cross-site story, which is the
 * half the Factory actually needs. So this is a new implementation over
 * `node:crypto`, with zero dependencies.
 *
 * Named `./cookie`, not `./session`: `ISessionProvider` in the contract is a
 * different thing, and `mastracode/factory/src/session/` is a third. This module
 * ships a cookie, so it says cookie.
 *
 * THE COOKIE VALUE FORMAT
 *
 *   value     := version "." payload "." expiresAt "." signature
 *   version   := "v1"
 *   payload   := base64url(utf8(value))
 *   expiresAt := decimal milliseconds since the epoch
 *   signature := base64url(HMAC-SHA256(secret, version "." payload "." expiresAt))
 *
 * Every character in that alphabet - base64url plus `.` plus digits - is a
 * legal cookie octet, so the value needs no further quoting or escaping. `.`
 * appears in none of the four fields, so splitting on it is unambiguous.
 *
 * Three decisions worth stating:
 *
 * - **The version is inside the signed material.** Otherwise an attacker could
 *   downgrade a `v2` cookie to `v1` and have it verified by whichever code path
 *   is weaker.
 * - **The expiry is inside the signed material, as well as in `Max-Age`.**
 *   `Max-Age` is a request to the browser and an attacker replaying a stolen
 *   cookie is not using a browser. The signed expiry is the one the server
 *   enforces.
 * - **There is no session id and no server-side store.** This cookie carries a
 *   value the provider can verify, and that is all. Revoking one before it
 *   expires needs a provider that implements `destroySession`; see
 *   `./capabilities` for how to ask whether yours does.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { getRequestHeader, type MastraAuthRequest } from './contract.js';

/**
 * The session cookie name for deployments where `__Host-` is not legal.
 *
 * Exported because the whole point is that it is declared rather than guessed.
 * A provider's `authenticateToken` that wants to read the host session directly
 * should read this name, and nothing should ever regex a provider's own cookie
 * name out of a `Cookie` header again.
 *
 * Prefer {@link sessionCookieName}, which returns {@link SESSION_COOKIE_HOST_NAME}
 * for the default deployment shape.
 */
export const SESSION_COOKIE_NAME = 'mastra_factory_session';

/**
 * The session cookie name for every deployment that can have it, which is the
 * default one.
 *
 * The `__Host-` prefix is not decoration. A browser refuses to store a cookie
 * whose name starts with it unless the cookie is `Secure`, carries no `Domain`,
 * and has `Path=/`. Those three conditions together mean the cookie can only
 * have been set by this exact host over HTTPS - not by a sibling subdomain, not
 * by a parent domain, not over plain HTTP.
 *
 * That closes cookie tossing. Without the prefix, a page on `evil.example.com`
 * can set `mastra_factory_session=<its own valid session>; Domain=example.com;
 * Path=/deep`, and the browser will send both cookies to `app.example.com` with
 * no way to tell them apart. RFC 6265 orders longer paths first, so the attacker
 * chooses the order, and the victim ends up working inside the attacker's
 * session. With the prefix the browser rejects that `Set-Cookie` outright.
 */
export const SESSION_COOKIE_HOST_NAME = `__Host-${SESSION_COOKIE_NAME}`;

/**
 * The cookie name a given deployment shape uses.
 *
 * Returns {@link SESSION_COOKIE_HOST_NAME} when the `__Host-` prefix is legal -
 * `Secure`, no `Domain`, `Path=/` - and {@link SESSION_COOKIE_NAME} otherwise.
 * The default options ({@link mintSessionCookie} with nothing but a secret and
 * `crossSite`) satisfy all three, so the default deployment gets the prefix, and
 * a cross-site deployment does too because it is forced `Secure`.
 *
 * Setting `domain`, setting a `path` other than `/`, or setting `secure: false`
 * for local HTTP each make the prefix illegal, and a browser would silently drop
 * the cookie rather than store it under a name it refuses. Those deployments get
 * the plain name and, with it, the tossing exposure the prefix exists to remove.
 *
 * Exported so a host that has to name the cookie elsewhere - a proxy rule, a
 * log filter, an integration test - can ask rather than guess.
 */
export function sessionCookieName(site: SessionCookieSite): string {
  const { secure } = deriveAttributes(site);
  const eligible = secure && site.domain === undefined && (site.path ?? '/') === '/';
  return eligible ? SESSION_COOKIE_HOST_NAME : SESSION_COOKIE_NAME;
}

/** Prefix of the signed value, and part of the signed material. */
const SESSION_COOKIE_VERSION = 'v1';

/** Seven days, matching how long a person expects to stay signed in to a tool. */
export const DEFAULT_SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;

/** Length of an HMAC-SHA256 digest, in bytes. */
const SIGNATURE_BYTES = 32;

/**
 * Where the browser sits relative to the API, plus the attributes that follow
 * from it.
 *
 * This is the input to the `SameSite` and `Secure` derivation, which is the part
 * of a session cookie people get wrong. See {@link mintSessionCookie}.
 */
export interface SessionCookieSite {
  /**
   * Whether the browser reaches this API from a different site than the one it
   * loaded the app from.
   *
   * `true` for a deployment where the SPA is served from one origin and the API
   * from another. `false` for the ordinary case where both come from the same
   * origin, including local development.
   *
   * If you are unsure, you are same-site: cross-site is a deliberate deployment
   * shape, not something that happens by accident.
   */
  crossSite: boolean;

  /**
   * Whether to mark the cookie `Secure`, so the browser only sends it over
   * HTTPS. Defaults to `true`.
   *
   * Set it to `false` only for local development over plain `http://`, and only
   * when `crossSite` is `false`: a cross-site cookie must be `Secure`, and
   * asking for both throws rather than minting a cookie the browser drops.
   */
  secure?: boolean;

  /** Cookie `Path`. Defaults to `/`. */
  path?: string;

  /** Cookie `Domain`. Omitted by default, which scopes the cookie to the exact host. */
  domain?: string;
}

/** Options for {@link mintSessionCookie}. */
export interface MintSessionCookieOptions extends SessionCookieSite {
  /**
   * The HMAC secret. Must be non-empty.
   *
   * Use a high-entropy value from your configuration, not a literal, and use the
   * same one everywhere a request might land. Two API instances with different
   * secrets means a user gets signed out every time the load balancer moves
   * them.
   */
  secret: string;

  /** How long the cookie lives, in seconds. Defaults to {@link DEFAULT_SESSION_MAX_AGE_SECONDS}. */
  maxAgeSeconds?: number;

  /** Current time in epoch milliseconds. Defaults to `Date.now()`; injectable for tests. */
  now?: number;
}

/** Options for {@link readSessionCookie}. */
export interface ReadSessionCookieOptions {
  /** The same secret {@link mintSessionCookie} used. Must be non-empty. */
  secret: string;

  /** Current time in epoch milliseconds. Defaults to `Date.now()`; injectable for tests. */
  now?: number;
}

/**
 * The shortest secret this module will use.
 *
 * 32 bytes is HMAC-SHA256's block-filling key length and the point past which
 * brute force stops being the cheapest attack on the cookie. Shorter secrets are
 * rejected rather than accepted with a warning nobody reads: a four-character
 * secret produces a cookie that looks exactly as legitimate as a good one, so
 * there is no signal at runtime that anything is wrong.
 */
const MINIMUM_SECRET_BYTES = 32;

function requireSecret(secret: string, caller: string): void {
  if (typeof secret !== 'string') {
    throw new Error(
      `${caller} was given a session secret that is not a string. Configure a high-entropy string and pass it here.`,
    );
  }
  const bytes = Buffer.byteLength(secret, 'utf8');
  if (bytes === 0) {
    throw new Error(
      `${caller} was given an empty session secret. An empty HMAC key signs and verifies anything, so every ` +
        'forged cookie would be accepted. Configure a high-entropy secret and pass it here.',
    );
  }
  if (bytes < MINIMUM_SECRET_BYTES) {
    throw new Error(
      `${caller} was given a session secret of ${bytes} bytes. It must be at least ${MINIMUM_SECRET_BYTES}, ` +
        'because a short HMAC key is brute-forceable and a forged cookie is indistinguishable from a real one. ' +
        "Generate one with `openssl rand -base64 32` or `crypto.randomBytes(32).toString('base64url')`, keep it " +
        'in configuration rather than in source, and use the same value on every instance a request might reach.',
    );
  }
}

/**
 * Reject an attribute value that could break out of the `Set-Cookie` header.
 *
 * `path` and `domain` are configuration rather than user input, so this is not
 * the last line of defence against anything. It is here because every other
 * value in the header is either generated or validated, and a header assembler
 * with one unchecked interpolation is the kind of thing that becomes reachable
 * later when a deployment starts reading its config from an environment the
 * operator does not fully control.
 */
function requireHeaderSafe(value: string, field: string): string {
  // Printable ASCII only, minus the two characters that delimit things in and
  // around a Set-Cookie header: `;` separates attributes, and `,` is what naive
  // parsers split a folded Set-Cookie on.
  // eslint-disable-next-line no-control-regex -- rejecting control characters is the point.
  if (/[^ -~]|[;,]/.test(value)) {
    throw new Error(
      `mintSessionCookie was given a session cookie ${field} containing a character that cannot appear in a ` +
        'Set-Cookie header. Control characters, semicolons and non-ASCII are all rejected, because a header ' +
        `assembled around them would either be dropped by the browser or split into a header the caller did not ` +
        `write. Received: ${JSON.stringify(value)}`,
    );
  }
  return value;
}

/**
 * Derive `SameSite` and `Secure` from the deployment shape.
 *
 * The rules, and why each one is what it is:
 *
 * - **Cross-site gets `SameSite=None; Secure`.** A `Lax` cookie is not sent on a
 *   cross-site request at all, so the API sees an anonymous request on every
 *   call and the user appears signed out. `None` is the only value that gets the
 *   cookie sent, and every current browser refuses a `SameSite=None` cookie that
 *   is not also `Secure`. The two travel together; there is no valid third
 *   combination.
 * - **Same-site gets `SameSite=Lax`, not `Strict`.** `Strict` withholds the
 *   cookie on cross-site top-level navigations, and the redirect back from a
 *   hosted login screen is exactly that. Under `Strict` the user completes login
 *   at the identity provider, lands back on the app, and arrives logged out.
 *   `Lax` sends the cookie on top-level GET navigations, which is what the
 *   callback is.
 * - **`HttpOnly` always.** The SPA never needs to read this value - it learns
 *   whether it is signed in from an API call - and `HttpOnly` takes the cookie
 *   out of reach of any script that gets injected into the page.
 *
 * @throws Error when `crossSite` is `true` and `secure` is explicitly `false`.
 */
function deriveAttributes(site: SessionCookieSite): { sameSite: 'Lax' | 'None'; secure: boolean } {
  if (site.crossSite) {
    if (site.secure === false) {
      throw new Error(
        'A cross-site session cookie was requested with secure: false. Browsers reject SameSite=None without ' +
          'Secure, including on localhost, so this cookie would be dropped and the user would never stay signed ' +
          'in. Serve the API over HTTPS, or set crossSite: false when the app and the API share an origin.',
      );
    }
    return { sameSite: 'None', secure: true };
  }
  return { sameSite: 'Lax', secure: site.secure ?? true };
}

/**
 * Assemble a `Set-Cookie` header value.
 *
 * Kept in one place so {@link mintSessionCookie} and {@link clearSessionCookie}
 * cannot drift. A browser only replaces a cookie when the name, `Path` and
 * `Domain` all match, so a clear built with different attributes than the mint
 * leaves the original cookie in place and the user stays signed in through
 * sign-out.
 */
function buildSetCookie(value: string, maxAgeSeconds: number, site: SessionCookieSite): string {
  const { sameSite, secure } = deriveAttributes(site);
  const path = requireHeaderSafe(site.path ?? '/', 'path');
  const parts = [`${sessionCookieName(site)}=${value}`, `Path=${path}`];
  if (site.domain !== undefined) parts.push(`Domain=${requireHeaderSafe(site.domain, 'domain')}`);
  parts.push(`Max-Age=${maxAgeSeconds}`, 'HttpOnly', `SameSite=${sameSite}`);
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function sign(secret: string, signedMaterial: string): Buffer {
  return createHmac('sha256', secret).update(signedMaterial, 'utf8').digest();
}

/**
 * Verify a signed cookie value and return the value that was signed.
 *
 * Returns `null` for every failure, with no distinction between them: a caller
 * that could tell "wrong signature" from "expired" from "malformed" would be a
 * caller that could leak that difference to whoever sent the cookie.
 */
function verify(signed: string, secret: string, now: number): string | null {
  const parts = signed.split('.');
  if (parts.length !== 4) return null;
  const [version, payload, expiresAt, signature] = parts as [string, string, string, string];

  if (version !== SESSION_COOKIE_VERSION) return null;
  if (!/^\d+$/.test(expiresAt)) return null;

  // The signature field has to be canonical, not merely decodable.
  //
  // `Buffer.from(x, 'base64url')` SKIPS characters outside the alphabet instead
  // of throwing, and ignores trailing bits that do not complete a byte. So a
  // signature with junk appended, with padding, or with a different final
  // character decodes to the same 32 bytes and verifies. No forgery follows -
  // the bytes still have to be right - but the cookie string is then malleable,
  // and anything downstream keyed on the raw value (a cache, a rate limiter, a
  // revocation list) can be bypassed by permuting characters the HMAC never
  // sees. 43 base64url characters is exactly 32 bytes with no padding.
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) return null;

  const provided = Buffer.from(signature, 'base64url');
  // Defensive: the regex above already fixes the length. `timingSafeEqual`
  // throws on mismatched lengths, and this is cheaper than finding that out.
  if (provided.length !== SIGNATURE_BYTES) return null;

  const expected = sign(secret, `${version}.${payload}.${expiresAt}`);
  if (!timingSafeEqual(provided, expected)) return null;

  const expiry = Number(expiresAt);
  if (!Number.isSafeInteger(expiry) || expiry <= now) return null;

  return Buffer.from(payload, 'base64url').toString('utf8');
}

/**
 * Every value in a `Cookie` header carrying the given name.
 *
 * Returns a list rather than one value because a `Cookie` header can genuinely
 * carry the same name twice - two cookies with the same name and different
 * `Path` or `Domain` are two different cookies to the browser, and it sends both
 * with no way to tell them apart. See {@link readSessionCookie} for what is done
 * about that; position is not evidence of anything, so it is not used here.
 *
 * SPLIT ON `;` AND NOTHING ELSE
 *
 * `;` is the only separator RFC 6265 defines for a `Cookie` header, and it is
 * the only one anything produces. Measured on Node 22: repeated `Cookie` request
 * headers are joined with `"; "` by both `node:http` and undici's `Headers`,
 * which special-case cookies. It is other headers that get joined with `", "`.
 * An earlier version of this function split on `,` as well, on the belief that
 * cookies were joined that way too. They are not, and that extra separator was
 * an attack: any foreign cookie the attacker can set - a theme preference, an
 * analytics id - could carry `,mastra_factory_session=<their value>` inside its
 * own value and have this function read it as a real cookie of ours.
 *
 * NO QUOTE STRIPPING
 *
 * RFC 6265 permits a double-quoted `cookie-value`, but quoting does NOT make the
 * value `;`-transparent: a `;` inside the quotes still ends the cookie as far as
 * every parser is concerned. So `theme="a;mastra_factory_session=<their value>"`
 * arrives here as two segments, and stripping the quotes from the second one
 * turned it into a clean value of ours. Nothing this module mints is ever
 * quoted, so a quoted value is either an oddity or an attack, and both are
 * better rejected than unwrapped.
 */
function readCookieValues(header: string, name: string): string[] {
  const values: string[] = [];
  for (const segment of header.split(';')) {
    const separator = segment.indexOf('=');
    if (separator === -1) continue;
    if (segment.slice(0, separator).trim() !== name) continue;
    values.push(segment.slice(separator + 1).trim());
  }
  return values;
}

/**
 * Mint a `Set-Cookie` header value carrying a signed session value.
 *
 * ```ts
 * headers.append(
 *   'Set-Cookie',
 *   mintSessionCookie(token, { secret, crossSite: isCrossSiteDeploy() }),
 * );
 * ```
 *
 * `value` is whatever the host wants back on the next request - typically the
 * token a provider's `authenticateToken` can verify. It is signed, not
 * encrypted: anyone holding the cookie can read it, they just cannot change it.
 * Do not put anything in it that the bearer should not see.
 *
 * See {@link SessionCookieSite} for how `SameSite` and `Secure` are derived, and
 * why a cross-site deployment has no choice about either. See
 * {@link sessionCookieName} for why the default deployment gets a `__Host-`
 * prefixed name and which options give that up.
 *
 * @throws Error when `secret` is shorter than 32 bytes, when `maxAgeSeconds` is
 * not a positive whole number, when `path` or `domain` contains a character that
 * cannot appear in a `Set-Cookie` header, or when a cross-site cookie is
 * requested with `secure: false`.
 */
export function mintSessionCookie(value: string, options: MintSessionCookieOptions): string {
  requireSecret(options.secret, 'mintSessionCookie');

  const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_SESSION_MAX_AGE_SECONDS;
  // A negative age mints a cookie that is dead on arrival, and a fractional one
  // is truncated by the browser - `0.5` becomes a session cookie that vanishes
  // when the window closes. Both look like a working sign-in on the server and
  // like an instant sign-out to the person, with nothing in between to read.
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
    throw new Error(
      `mintSessionCookie was given maxAgeSeconds: ${String(maxAgeSeconds)}. It must be a positive whole number of ` +
        'seconds. A negative or zero age mints a cookie the browser discards immediately, and a fractional one is ' +
        'truncated, so the session would end the moment the window closed. To sign someone out, use ' +
        'clearSessionCookie rather than a short age.',
    );
  }
  const now = options.now ?? Date.now();
  const expiresAt = String(now + maxAgeSeconds * 1000);
  const payload = Buffer.from(value, 'utf8').toString('base64url');
  const signedMaterial = `${SESSION_COOKIE_VERSION}.${payload}.${expiresAt}`;
  const signature = sign(options.secret, signedMaterial).toString('base64url');

  return buildSetCookie(`${signedMaterial}.${signature}`, maxAgeSeconds, options);
}

/**
 * Read and verify the session value out of a request's `Cookie` header.
 *
 * ```ts
 * const token = readSessionCookie(request, { secret }) ?? '';
 * const user = await provider.authenticateToken(token, request);
 * ```
 *
 * Returns `null` when there is no cookie, when the signature does not verify,
 * when the value has expired, and when the value is malformed - deliberately
 * without saying which. Never throws on the request or on the cookie: both are
 * attacker-controlled. A missing or too-short `secret` still throws, because
 * that is your configuration rather than their input.
 *
 * The request is read through `getRequestHeader` from `./contract`, so a plain
 * `Request`, a Hono context request, and anything else shaped like one all work
 * without this package depending on a web framework.
 *
 * TWO COOKIES WITH OUR NAME
 *
 * The browser can send more than one, because two cookies that differ only in
 * `Path` or `Domain` are two different cookies to it, and it sends both with no
 * way to tell them apart. That is not hypothetical: it is how cookie tossing
 * works. A page on a sibling host sets a session of its own on the shared parent
 * domain with a longer `Path`, RFC 6265 puts longer paths first, and whoever
 * picks by position has let the attacker pick.
 *
 * Two rules, in order:
 *
 * 1. **A `__Host-` cookie wins outright.** A browser only stores that name for
 *    the exact host, over HTTPS, with no `Domain`. So its presence is proof of
 *    origin, and when one is present the unprefixed name is not even considered.
 * 2. **Ambiguity is not resolved, it is refused.** If more than one candidate
 *    verifies and they do not all carry the same value, this returns `null`
 *    rather than choosing. Choosing by position hands the choice to whoever
 *    controls the order; choosing at all means the victim might work inside
 *    someone else's session and never know. `null` signs them out instead, which
 *    is visible, recoverable, and the safe direction. A host that sees this
 *    should send {@link clearSessionCookie} so the browser drops the cookie it
 *    can reach.
 *
 * The residual exposure is that an attacker who can set a valid cookie of ours
 * on a shared parent domain can keep a victim signed out. That is a denial of
 * service they can already achieve by other means, and it is strictly better
 * than the alternative it replaces.
 */
export function readSessionCookie(request: MastraAuthRequest, options: ReadSessionCookieOptions): string | null {
  requireSecret(options.secret, 'readSessionCookie');
  const now = options.now ?? Date.now();

  let header: string | null;
  try {
    header = getRequestHeader(request, 'cookie');
  } catch {
    return null;
  }
  // An adapter that hands back something other than a string or null. Not
  // observed in any adapter we ship against; one line to make it impossible for
  // an attacker-shaped request to reach `String.prototype.split`.
  if (typeof header !== 'string' || header.length === 0) return null;

  const hostScoped = readCookieValues(header, SESSION_COOKIE_HOST_NAME);
  const candidates = hostScoped.length > 0 ? hostScoped : readCookieValues(header, SESSION_COOKIE_NAME);

  let resolved: string | null = null;
  for (const candidate of candidates) {
    const value = verify(candidate, options.secret, now);
    if (value === null) continue;
    if (resolved === null) {
      resolved = value;
      continue;
    }
    // Two cookies that both verify, carrying different values. See rule 2 above.
    if (resolved !== value) return null;
  }
  return resolved;
}

/**
 * Build the `Set-Cookie` header value that removes the session cookie.
 *
 * ```ts
 * headers.append('Set-Cookie', clearSessionCookie({ crossSite: isCrossSiteDeploy() }));
 * ```
 *
 * Pass the same {@link SessionCookieSite} you passed to
 * {@link mintSessionCookie}. A browser matches a replacement cookie on name,
 * `Path` and `Domain`, so clearing with different attributes writes a second,
 * already-expired cookie and leaves the real one in place - which reads as
 * "sign out did nothing".
 *
 * No secret is needed: this writes an empty value with `Max-Age=0`, and there is
 * nothing to sign.
 *
 * @throws Error when a cross-site cookie is requested with `secure: false`.
 */
export function clearSessionCookie(site: SessionCookieSite): string {
  return buildSetCookie('', 0, site);
}

/**
 * Turn a `Set-Cookie` header value into the `Cookie` header a browser would send
 * back for it.
 *
 * ```ts
 * const setCookie = mintSessionCookie(token, { secret, crossSite: false });
 * const response = await app.request('/me', {
 *   headers: { cookie: toCookieHeader(setCookie) },
 * });
 * ```
 *
 * A `Set-Cookie` value is `name=value` followed by attributes; a `Cookie` header
 * is just `name=value`, with several joined by `"; "`. Every test that wants to
 * check a round trip needs that conversion, and every one of them was writing it
 * inline - which meant the conversion itself was never the thing under test, and
 * a mistake in it would look like a bug in the cookie.
 *
 * Test and development helper. Nothing on the request path needs it: a real
 * browser does this itself, and it ignores `Path`, `Domain`, `Max-Age` and
 * `Secure`, which a browser would not. Pass more than one value to model a
 * request carrying several cookies, including the same name twice.
 */
export function toCookieHeader(...setCookieValues: string[]): string {
  return setCookieValues
    .map(setCookie => setCookie.split(';')[0]?.trim() ?? '')
    .filter(pair => pair.length > 0)
    .join('; ');
}
