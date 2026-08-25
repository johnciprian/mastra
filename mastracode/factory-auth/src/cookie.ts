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
 * The one cookie name this package mints, reads and clears.
 *
 * Exported because the whole point is that it is declared rather than guessed.
 * A provider's `authenticateToken` that wants to read the host session directly
 * should read this name, and nothing should ever regex a provider's own cookie
 * name out of a `Cookie` header again.
 */
export const SESSION_COOKIE_NAME = 'mastra_factory_session';

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

function requireSecret(secret: string, caller: string): void {
  if (secret.length === 0) {
    throw new Error(
      `${caller} was given an empty session secret. An empty HMAC key signs and verifies anything, so every ` +
        'forged cookie would be accepted. Configure a high-entropy secret and pass it here.',
    );
  }
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
  const parts = [`${SESSION_COOKIE_NAME}=${value}`, `Path=${site.path ?? '/'}`];
  if (site.domain !== undefined) parts.push(`Domain=${site.domain}`);
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

  const provided = Buffer.from(signature, 'base64url');
  // `Buffer.from` with base64url skips characters outside the alphabet rather
  // than throwing, so a tampered signature arrives here as the wrong length or
  // the wrong bytes. Both are rejected below. The length check runs first
  // because `timingSafeEqual` throws on mismatched lengths; it leaks only the
  // length of a value that is a fixed 32 bytes whenever it is genuine.
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
 * with no way to tell them apart. A page on a sibling host can set one on a
 * shared parent domain, so "the first one wins" is a denial of service someone
 * else controls. {@link readSessionCookie} therefore takes the first that
 * verifies, not the first that appears.
 *
 * The split covers `,` as well as `;`. `Headers.get('cookie')` joins repeated
 * header lines with `, `, and a value this module mints contains neither
 * character, so splitting on both can only ever help.
 */
function readCookieValues(header: string | null, name: string): string[] {
  if (!header) return [];
  const values: string[] = [];
  for (const segment of header.split(/[;,]/)) {
    const separator = segment.indexOf('=');
    if (separator === -1) continue;
    if (segment.slice(0, separator).trim() !== name) continue;
    // RFC 6265 permits a double-quoted cookie-value; nothing here mints one, but
    // an intermediary may add the quotes.
    values.push(
      segment
        .slice(separator + 1)
        .trim()
        .replace(/^"(.*)"$/, '$1'),
    );
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
 * why a cross-site deployment has no choice about either.
 *
 * @throws Error when `secret` is empty, or when a cross-site cookie is requested
 * with `secure: false`.
 */
export function mintSessionCookie(value: string, options: MintSessionCookieOptions): string {
  requireSecret(options.secret, 'mintSessionCookie');

  const maxAgeSeconds = options.maxAgeSeconds ?? DEFAULT_SESSION_MAX_AGE_SECONDS;
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
 * attacker-controlled. An empty `secret` still throws, because that is your
 * configuration rather than their input.
 *
 * The request is read through `getRequestHeader` from `./contract`, so a plain
 * `Request`, a Hono context request, and anything else shaped like one all work
 * without this package depending on a web framework.
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

  for (const candidate of readCookieValues(header, SESSION_COOKIE_NAME)) {
    const value = verify(candidate, options.secret, now);
    if (value !== null) return value;
  }
  return null;
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
