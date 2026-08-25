/**
 * The host-owned session cookie.
 *
 * Two halves. The attribute tests pin the `SameSite`/`Secure` matrix, which is
 * the part that decides whether a cross-site deployment can stay signed in at
 * all. The verification tests treat the cookie as attacker-supplied, because on
 * the read path it is: the browser sends whatever it holds, and whatever it
 * holds is whatever anyone with script access to a sibling host put there.
 */
import { describe, expect, it } from 'vitest';
import type { MastraAuthRequest } from '../contract.js';
import {
  DEFAULT_SESSION_MAX_AGE_SECONDS,
  SESSION_COOKIE_HOST_NAME,
  SESSION_COOKIE_NAME,
  clearSessionCookie,
  mintSessionCookie,
  readSessionCookie,
  sessionCookieName,
  toCookieHeader,
} from '../cookie.js';

const SECRET = 'a-test-secret-with-plenty-of-entropy';
const OTHER_SECRET = 'a-different-test-secret-entirely';
const NOW = 1_700_000_000_000;

/** The `name=value` half of a `Set-Cookie`, without the attributes. */
function cookieValueOf(setCookie: string): string {
  const pair = setCookie.split('; ')[0]!;
  return pair.slice(pair.indexOf('=') + 1);
}

function attributesOf(setCookie: string): string[] {
  return setCookie.split('; ').slice(1);
}

function webRequest(cookieHeader: string | undefined): MastraAuthRequest {
  return new Request('https://example.test/', cookieHeader === undefined ? {} : { headers: { cookie: cookieHeader } });
}

/** A Hono-shaped request, which is the other thing `getRequestHeader` accepts. */
function honoRequest(cookieHeader: string | undefined): MastraAuthRequest {
  return {
    header: (name: string) => (name.toLowerCase() === 'cookie' ? cookieHeader : undefined),
  };
}

/**
 * A Hono context request as Hono actually builds one: a `raw` web `Request`
 * alongside the `header()` accessor.
 *
 * This is the shape a real host passes, and `getRequestHeader` reads `raw` in
 * preference to calling `header()`. The bare `header()`-only object above is a
 * test fixture; this one is production.
 */
function honoContextRequest(cookieHeader: string): MastraAuthRequest {
  return {
    raw: new Request('https://example.test/', { headers: { cookie: cookieHeader } }),
    header: () => {
      throw new Error('header() should not be reached when a raw Request is present');
    },
  } as unknown as MastraAuthRequest;
}

/**
 * The name `mint()` actually writes. The default deployment shape is eligible
 * for the `__Host-` prefix, so a test that hand-built a header around
 * `SESSION_COOKIE_NAME` would be testing a cookie the code no longer mints.
 */
const DEFAULT_NAME = sessionCookieName({ crossSite: false });

function headerFor(value: string): string {
  return `${DEFAULT_NAME}=${value}`;
}

function mint(value = 'session-token', overrides: Partial<Parameters<typeof mintSessionCookie>[1]> = {}): string {
  return mintSessionCookie(value, { secret: SECRET, crossSite: false, now: NOW, ...overrides });
}

/** Replace one dot-separated field of a signed value. */
function tamper(value: string, index: 0 | 1 | 2 | 3, replacement: string): string {
  const parts = value.split('.');
  parts[index] = replacement;
  return parts.join('.');
}

describe('mint and read', () => {
  it('round trips a value', () => {
    const value = cookieValueOf(mint('session-token'));
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW })).toBe('session-token');
  });

  it('reads through a Hono-shaped request as well as a web Request', () => {
    const value = cookieValueOf(mint('session-token'));
    expect(readSessionCookie(honoRequest(headerFor(value)), { secret: SECRET, now: NOW })).toBe('session-token');
  });

  it('reads through a Hono context that carries a raw Request', () => {
    // The shape a real host passes, and the one neither fixture above models:
    // Hono's `c.req` has both `raw` and `header()`, and `getRequestHeader` reads
    // `raw` first. Nothing in this package pinned that branch, so a change to
    // which one is preferred would have shown up as "signed in, then immediately
    // signed out" in a host rather than as a red test here.
    const value = cookieValueOf(mint('session-token'));
    expect(readSessionCookie(honoContextRequest(headerFor(value)), { secret: SECRET, now: NOW })).toBe('session-token');
  });

  it('finds the cookie among others', () => {
    const value = cookieValueOf(mint('session-token'));
    const header = `theme=dark; ${DEFAULT_NAME}=${value}; locale=en-GB`;
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW })).toBe('session-token');
  });

  it.each([
    ['a JWT, which contains the field separator', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'],
    ['a value containing a semicolon', 'a;b'],
    ['a value containing a comma', 'a,b'],
    ['a value containing an equals sign', 'a=b=c'],
    ['a value containing a space', 'a b'],
    ['a value containing quotes', '"quoted"'],
    ['a non-ascii value', 'ünïcödé-tökén'],
    ['an empty value', ''],
  ])('survives %s, because the payload is base64url', (_label, raw) => {
    const value = cookieValueOf(mint(raw));
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW })).toBe(raw);
  });

  it('mints four dot-separated fields', () => {
    expect(cookieValueOf(mint()).split('.')).toHaveLength(4);
  });
});

describe('rejects a cookie it did not sign', () => {
  const read = (value: string) => readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW });

  it('rejects an edited payload', () => {
    const value = cookieValueOf(mint('user-1'));
    const forged = tamper(value, 1, Buffer.from('user-2', 'utf8').toString('base64url'));
    expect(forged).not.toBe(value);
    expect(read(forged)).toBeNull();
  });

  it('rejects an edited signature', () => {
    const value = cookieValueOf(mint());
    const parts = value.split('.');
    const flipped = parts[3]!.startsWith('A') ? `B${parts[3]!.slice(1)}` : `A${parts[3]!.slice(1)}`;
    expect(read(tamper(value, 3, flipped))).toBeNull();
  });

  it('rejects an edited payload with a matching re-signature from the wrong secret', () => {
    // The attacker controls both fields, and signs with a secret they own. This
    // is the case a naive "does it parse" check waves through.
    const forged = cookieValueOf(mintSessionCookie('admin', { secret: OTHER_SECRET, crossSite: false, now: NOW }));
    expect(read(forged)).toBeNull();
  });

  it('rejects a cookie signed with a different secret', () => {
    const value = cookieValueOf(
      mintSessionCookie('session-token', { secret: OTHER_SECRET, crossSite: false, now: NOW }),
    );
    expect(read(value)).toBeNull();
  });

  it('rejects an extended expiry, because the expiry is inside the signature', () => {
    const value = cookieValueOf(mint());
    expect(read(tamper(value, 2, String(NOW + 10_000 * 1000)))).toBeNull();
  });

  it('rejects a downgraded version, because the version is inside the signature', () => {
    const value = cookieValueOf(mint());
    expect(read(tamper(value, 0, 'v0'))).toBeNull();
  });

  it.each([
    ['an empty value', ''],
    ['a value with too few fields', 'v1.abc.123'],
    ['a value with too many fields', 'v1.abc.123.sig.extra'],
    ['a non-numeric expiry', 'v1.abc.notanumber.sig'],
    ['an exponent-shaped expiry', 'v1.abc.1e20.sig'],
    ['a negative expiry', 'v1.abc.-1.sig'],
    ['a signature of the wrong length', 'v1.abc.99999999999999.QQ'],
    ['an empty signature', 'v1.abc.99999999999999.'],
    ['unrelated text', 'not-a-cookie-at-all'],
  ])('rejects %s without throwing', (_label, value) => {
    expect(read(value)).toBeNull();
  });

  it('rejects an expiry it cannot represent exactly, even though the signature verifies', () => {
    // 10^16 milliseconds is all digits, so it passes the format check, and it is
    // signed by this module, so it verifies. It is also past
    // Number.MAX_SAFE_INTEGER, which means `Number(expiresAt)` is a value the
    // server cannot compare reliably: two different expiries that far out are the
    // same double. An expiry the server cannot evaluate is not an expiry, and the
    // safe direction for one is to reject.
    const value = cookieValueOf(mint('session-token', { maxAgeSeconds: 10_000_000_000_000, now: 0 }));
    const expiresAt = value.split('.')[2]!;
    expect(expiresAt).toMatch(/^\d+$/);
    expect(Number.isSafeInteger(Number(expiresAt))).toBe(false);

    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW })).toBeNull();
  });

  it('rejects an expired cookie', () => {
    const value = cookieValueOf(mint('session-token', { maxAgeSeconds: 60 }));
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW + 59_000 })).toBe(
      'session-token',
    );
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW + 60_000 })).toBeNull();
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW + 61_000 })).toBeNull();
  });
});

describe('cookie header parsing', () => {
  it('returns null when there is no Cookie header', () => {
    expect(readSessionCookie(webRequest(undefined), { secret: SECRET, now: NOW })).toBeNull();
    expect(readSessionCookie(honoRequest(undefined), { secret: SECRET, now: NOW })).toBeNull();
  });

  it('returns null when the header carries no cookie of ours', () => {
    expect(readSessionCookie(webRequest('theme=dark; locale=en-GB'), { secret: SECRET, now: NOW })).toBeNull();
  });

  it.each([
    ['an empty header', ''],
    ['a header of separators', ';;;'],
    ['a name with no value', 'justaname'],
    ['our name with no value', `${DEFAULT_NAME}`],
    ['our name with an empty value', `${DEFAULT_NAME}=`],
  ])('returns null for %s', (_label, header) => {
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW })).toBeNull();
  });

  it('ignores a duplicate that cannot verify, whichever side it is on', () => {
    // A cookie signed with somebody else's secret is not a candidate at all, so
    // position cannot matter. This is the easy half; the half that decides the
    // security of this module is in `cookie tossing` below, where BOTH cookies
    // verify.
    const ours = cookieValueOf(mint('real-session'));
    const shadow = cookieValueOf(mintSessionCookie('forged', { secret: OTHER_SECRET, crossSite: false, now: NOW }));

    const shadowFirst = `${DEFAULT_NAME}=${shadow}; ${DEFAULT_NAME}=${ours}`;
    const shadowSecond = `${DEFAULT_NAME}=${ours}; ${DEFAULT_NAME}=${shadow}`;

    expect(readSessionCookie(webRequest(shadowFirst), { secret: SECRET, now: NOW })).toBe('real-session');
    expect(readSessionCookie(webRequest(shadowSecond), { secret: SECRET, now: NOW })).toBe('real-session');
  });

  it('skips an expired duplicate in favour of a live one', () => {
    const stale = cookieValueOf(mint('stale', { maxAgeSeconds: 60 }));
    const fresh = cookieValueOf(mint('fresh', { now: NOW + 120_000 }));
    const header = `${DEFAULT_NAME}=${stale}; ${DEFAULT_NAME}=${fresh}`;
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW + 120_000 })).toBe('fresh');
  });

  it('treats a comma as part of a value, not as a separator', () => {
    // The premise this replaces was measured and false. Repeated `Cookie`
    // request headers are joined with '; ' by both node:http and undici's
    // Headers, which special-case cookies; it is other headers that are joined
    // with ', '. Splitting on ',' therefore bought nothing and let any foreign
    // cookie smuggle one of ours inside its own value.
    const value = cookieValueOf(mint('session-token'));
    const header = `theme=dark, ${DEFAULT_NAME}=${value}`;
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW })).toBeNull();
  });

  it('joins repeated Cookie headers with a semicolon, as the runtime does', () => {
    // The behaviour the comma test was reaching for, asserted against the
    // runtime rather than against a belief about it.
    const value = cookieValueOf(mint('session-token'));
    const request = new Request('https://example.test/', {
      headers: [
        ['cookie', 'theme=dark'],
        ['cookie', `${DEFAULT_NAME}=${value}`],
      ],
    });
    expect(request.headers.get('cookie')).toBe(`theme=dark; ${DEFAULT_NAME}=${value}`);
    expect(readSessionCookie(request, { secret: SECRET, now: NOW })).toBe('session-token');
  });

  it('rejects a value wrapped in double quotes rather than unwrapping it', () => {
    // RFC 6265 permits a quoted cookie-value, but quoting does not make the
    // value ';'-transparent, so unwrapping it was an attack surface rather than
    // a compatibility feature: see `header smuggling` below. Nothing this module
    // mints is ever quoted.
    const value = cookieValueOf(mint('session-token'));
    expect(readSessionCookie(webRequest(`${DEFAULT_NAME}="${value}"`), { secret: SECRET, now: NOW })).toBeNull();
  });
});

describe('SameSite and Secure', () => {
  it('gives a same-site deployment SameSite=Lax and Secure', () => {
    const attributes = attributesOf(mint('t', { crossSite: false }));
    expect(attributes).toContain('SameSite=Lax');
    expect(attributes).toContain('Secure');
  });

  it('drops Secure for same-site plain http, for local development', () => {
    const attributes = attributesOf(mint('t', { crossSite: false, secure: false }));
    expect(attributes).toContain('SameSite=Lax');
    expect(attributes).not.toContain('Secure');
  });

  it('gives a cross-site deployment SameSite=None and Secure', () => {
    const attributes = attributesOf(mint('t', { crossSite: true }));
    expect(attributes).toContain('SameSite=None');
    expect(attributes).toContain('Secure');
  });

  it('forces Secure on a cross-site cookie even when the caller asks for it', () => {
    expect(attributesOf(mint('t', { crossSite: true, secure: true }))).toContain('Secure');
  });

  it('throws rather than mint a cross-site cookie without Secure, which every browser drops', () => {
    expect(() => mint('t', { crossSite: true, secure: false })).toThrow(/SameSite=None without Secure/);
    expect(() => clearSessionCookie({ crossSite: true, secure: false })).toThrow(/SameSite=None without Secure/);
  });

  it('never uses SameSite=Strict, which would drop the cookie on the login callback', () => {
    for (const crossSite of [true, false]) {
      expect(mint('t', { crossSite })).not.toContain('Strict');
    }
  });
});

describe('other attributes', () => {
  it('is always HttpOnly', () => {
    expect(attributesOf(mint('t', { crossSite: false }))).toContain('HttpOnly');
    expect(attributesOf(mint('t', { crossSite: true }))).toContain('HttpOnly');
    expect(attributesOf(clearSessionCookie({ crossSite: false }))).toContain('HttpOnly');
  });

  it('defaults Path to / and omits Domain', () => {
    const attributes = attributesOf(mint());
    expect(attributes).toContain('Path=/');
    expect(attributes.some(attribute => attribute.startsWith('Domain='))).toBe(false);
  });

  it('honours Path and Domain overrides, and gives up the __Host- prefix for them', () => {
    const setCookie = mint('t', { path: '/factory', domain: 'example.test' });
    const attributes = attributesOf(setCookie);
    expect(attributes).toContain('Path=/factory');
    expect(attributes).toContain('Domain=example.test');
    // A browser refuses to store a __Host- cookie that carries a Domain or a
    // Path other than '/', so minting one under that name would produce a
    // cookie the browser silently drops.
    expect(setCookie).toMatch(new RegExp(`^${SESSION_COOKIE_NAME}=`));
  });

  it('defaults Max-Age to a week and honours an override', () => {
    expect(attributesOf(mint())).toContain(`Max-Age=${DEFAULT_SESSION_MAX_AGE_SECONDS}`);
    expect(attributesOf(mint('t', { maxAgeSeconds: 900 }))).toContain('Max-Age=900');
  });

  it('names the cookie once, and declares that name', () => {
    expect(SESSION_COOKIE_NAME).toBe('mastra_factory_session');
    expect(SESSION_COOKIE_HOST_NAME).toBe('__Host-mastra_factory_session');
    expect(mint()).toMatch(new RegExp(`^${SESSION_COOKIE_HOST_NAME}=`));
  });
});

describe('clearSessionCookie', () => {
  it('expires the cookie with an empty value', () => {
    const cleared = clearSessionCookie({ crossSite: false });
    expect(cookieValueOf(cleared)).toBe('');
    expect(attributesOf(cleared)).toContain('Max-Age=0');
  });

  it('matches the minted attributes, or the browser keeps the original cookie', () => {
    const site = { crossSite: true, path: '/factory', domain: 'example.test' } as const;
    const minted = attributesOf(mint('t', site)).filter(attribute => !attribute.startsWith('Max-Age='));
    const cleared = attributesOf(clearSessionCookie(site)).filter(attribute => !attribute.startsWith('Max-Age='));
    expect(cleared).toEqual(minted);
  });

  it('needs no secret, because there is nothing to sign', () => {
    expect(() => clearSessionCookie({ crossSite: false })).not.toThrow();
  });
});

describe('secret handling', () => {
  it('refuses to mint with an empty secret', () => {
    expect(() => mintSessionCookie('t', { secret: '', crossSite: false })).toThrow(/empty session secret/);
  });

  it('refuses to read with an empty secret', () => {
    expect(() => readSessionCookie(webRequest('a=b'), { secret: '' })).toThrow(/empty session secret/);
  });

  it.each([
    ['one character', 'a'],
    ['a short word', 'secret'],
    ['31 bytes, one short', 'a'.repeat(31)],
  ])('refuses a secret of %s', (_label, secret) => {
    // A short HMAC key is brute-forceable, and a cookie signed with one looks
    // exactly like a cookie signed with a good one. There is no signal at
    // runtime, so the only place to catch it is here.
    expect(() => mintSessionCookie('t', { secret, crossSite: false })).toThrow(/at least 32/);
    expect(() => readSessionCookie(webRequest('a=b'), { secret })).toThrow(/at least 32/);
  });

  it('accepts a secret of exactly 32 bytes', () => {
    const secret = 'a'.repeat(32);
    expect(() => mintSessionCookie('t', { secret, crossSite: false })).not.toThrow();
  });

  it.each([
    ['undefined, which is what a missing config key gives you', undefined],
    ['null', null],
    ['a number', 12345678901234567890],
    ['a Buffer, which is a plausible thing to reach for', Buffer.alloc(32)],
    ['an object', { secret: 'a'.repeat(32) }],
  ])('refuses a secret that is %s, rather than measuring its bytes', (_label, secret) => {
    // `Buffer.byteLength` accepts a Buffer and a TypedArray and throws a
    // TypeError on a number, so without this guard the three cases below split
    // three ways: a Buffer would be silently accepted and then HMAC'd as a
    // different key than the string a second instance configured, a number would
    // crash with a message about byteLength, and undefined would crash too. One
    // check, one message, naming the option.
    expect(() => mintSessionCookie('t', { secret: secret as never, crossSite: false })).toThrow(/not a string/);
    expect(() => readSessionCookie(webRequest('a=b'), { secret: secret as never })).toThrow(/not a string/);
  });

  it('counts bytes rather than characters', () => {
    // `é` is two bytes in UTF-8, so 16 of them is 32 bytes from a string whose
    // `length` is 16. The key an HMAC uses is the bytes, so that is what is
    // measured - a `secret.length >= 32` check would have accepted 16 bytes of
    // real entropy here and rejected 32.
    expect(Buffer.byteLength('é'.repeat(16), 'utf8')).toBe(32);
    expect(() => mintSessionCookie('t', { secret: 'é'.repeat(16), crossSite: false })).not.toThrow();
    expect(() => mintSessionCookie('t', { secret: 'é'.repeat(15), crossSite: false })).toThrow(/at least 32/);
  });
});

describe('cookie tossing', () => {
  // The attack this module has to survive. An attacker signs in legitimately, so
  // they hold a cookie that verifies under the real secret. From a page on a
  // sibling host they set it again on the shared parent domain with a longer
  // Path. The browser now sends two cookies with our name, RFC 6265 orders the
  // longer Path first, and the victim's request carries the attacker's session
  // ahead of their own. "First that verifies" hands the attacker the choice.
  const attacker = () => cookieValueOf(mint('ATTACKER'));
  const victim = () => cookieValueOf(mint('VICTIM'));
  const read = (header: string) => readSessionCookie(webRequest(header), { secret: SECRET, now: NOW });

  it('refuses to choose when two cookies verify to different values', () => {
    expect(read(`${DEFAULT_NAME}=${attacker()}; ${DEFAULT_NAME}=${victim()}`)).toBeNull();
    expect(read(`${DEFAULT_NAME}=${victim()}; ${DEFAULT_NAME}=${attacker()}`)).toBeNull();
  });

  it('does not depend on order, which is the whole point', () => {
    const forwards = read(`${DEFAULT_NAME}=${attacker()}; ${DEFAULT_NAME}=${victim()}`);
    const backwards = read(`${DEFAULT_NAME}=${victim()}; ${DEFAULT_NAME}=${attacker()}`);
    expect(forwards).toBe(backwards);
  });

  it('still reads a value duplicated with itself', () => {
    // The same session sent twice - a browser can do this after a Path change -
    // is not ambiguous, so it is not refused.
    const ours = cookieValueOf(mint('real-session'));
    expect(read(`${DEFAULT_NAME}=${ours}; ${DEFAULT_NAME}=${ours}`)).toBe('real-session');
  });

  it('prefers a __Host- cookie and ignores the unprefixed name entirely', () => {
    // A browser only stores a __Host- cookie for the exact host, over HTTPS,
    // with no Domain. Its presence is proof of origin, so an unprefixed cookie
    // alongside it is not a competing candidate.
    const hostScoped = cookieValueOf(mint('real-session'));
    const tossed = cookieValueOf(mint('ATTACKER'));
    expect(read(`${SESSION_COOKIE_NAME}=${tossed}; ${SESSION_COOKIE_HOST_NAME}=${hostScoped}`)).toBe('real-session');
    expect(read(`${SESSION_COOKIE_HOST_NAME}=${hostScoped}; ${SESSION_COOKIE_NAME}=${tossed}`)).toBe('real-session');
  });

  it('gives the default deployment a __Host- name, and every eligible shape too', () => {
    expect(sessionCookieName({ crossSite: false })).toBe(SESSION_COOKIE_HOST_NAME);
    expect(sessionCookieName({ crossSite: true })).toBe(SESSION_COOKIE_HOST_NAME);
    expect(sessionCookieName({ crossSite: false, path: '/' })).toBe(SESSION_COOKIE_HOST_NAME);
  });

  it.each([
    ['a Domain is set', { crossSite: false, domain: 'example.test' }],
    ['a Path other than / is set', { crossSite: false, path: '/factory' }],
    ['Secure is off for local http', { crossSite: false, secure: false }],
  ])('falls back to the plain name when %s, because the prefix would be illegal', (_label, site) => {
    expect(sessionCookieName(site)).toBe(SESSION_COOKIE_NAME);
  });

  it('refuses to name a cookie for a deployment shape that cannot exist', () => {
    // Cross-site plus `secure: false` is not a deployment, it is a contradiction:
    // every browser drops a SameSite=None cookie that is not Secure, so there is
    // no name to give one. `mintSessionCookie` already throws for it, and this
    // pins that asking only for the name throws too. A `sessionCookieName` that
    // derived `secure` itself rather than going through the same derivation would
    // answer 'mastra_factory_session' here - a name for a cookie that will never
    // be stored, handed to whoever wrote the proxy rule or the log filter.
    expect(() => sessionCookieName({ crossSite: true, secure: false })).toThrow(/SameSite=None without Secure/);
  });

  it('lets a __Host- cookie that does not verify suppress an unprefixed one that does', () => {
    // Rule 1 is about the NAME, not about the value: a browser only stores a
    // __Host- cookie for the exact host over HTTPS, so its presence is proof of
    // origin and the unprefixed name stops being a candidate at all. That has to
    // hold when the host-scoped cookie is stale or forged, which is the only case
    // where the two rules could be confused for one another - "prefer the one
    // that works" would quietly hand the session back to whoever set the
    // unprefixed cookie on the parent domain.
    const staleHostScoped = cookieValueOf(
      mintSessionCookie('EXPIRED', { secret: SECRET, crossSite: false, now: NOW, maxAgeSeconds: 60 }),
    );
    const tossed = cookieValueOf(mint('ATTACKER'));
    const header = `${SESSION_COOKIE_HOST_NAME}=${staleHostScoped}; ${SESSION_COOKIE_NAME}=${tossed}`;

    // The unprefixed cookie is perfectly valid on its own, which is what makes
    // this a claim about the rule rather than about verification.
    expect(readSessionCookie(webRequest(`${SESSION_COOKIE_NAME}=${tossed}`), { secret: SECRET, now: NOW })).toBe(
      'ATTACKER',
    );
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW + 120_000 })).toBeNull();
  });
});

describe('header smuggling', () => {
  // Both payloads carry a complete, validly-signed cookie of ours inside a
  // foreign cookie's value. Neither is a forgery - the attacker signs their own
  // session - so verification cannot be what stops them. Parsing has to.
  const read = (header: string) => readSessionCookie(webRequest(header), { secret: SECRET, now: NOW });

  it('does not read a cookie of ours out of a foreign value after a comma', () => {
    const attacker = cookieValueOf(mint('ATTACKER'));
    const victim = cookieValueOf(mint('VICTIM'));
    expect(read(`theme=dark,${DEFAULT_NAME}=${attacker}; ${DEFAULT_NAME}=${victim}`)).toBe('VICTIM');
  });

  it('does not read a cookie of ours out of a quoted foreign value', () => {
    const attacker = cookieValueOf(mint('ATTACKER'));
    const victim = cookieValueOf(mint('VICTIM'));
    // The `;` inside the quotes still ends the cookie for every parser, so this
    // arrives as two segments. Stripping the closing quote off the second one
    // used to turn it into a clean value of ours.
    expect(read(`theme="a;${DEFAULT_NAME}=${attacker}"; ${DEFAULT_NAME}=${victim}`)).toBe('VICTIM');
  });

  it('does not read one out of a foreign value at all, however it is dressed', () => {
    const attacker = cookieValueOf(mint('ATTACKER'));
    for (const header of [
      `theme=dark,${DEFAULT_NAME}=${attacker}`,
      `theme="a;${DEFAULT_NAME}=${attacker}"`,
      `theme=${DEFAULT_NAME}=${attacker}`,
    ]) {
      expect(read(header)).toBeNull();
    }
  });
});

describe('signature canonicality', () => {
  const read = (value: string) => readSessionCookie(webRequest(headerFor(value)), { secret: SECRET, now: NOW });

  it('accepts the signature exactly as minted', () => {
    expect(read(cookieValueOf(mint('session-token')))).toBe('session-token');
  });

  it.each([
    ['characters appended outside the alphabet', (sig: string) => `${sig}!!!`],
    ['base64 padding', (sig: string) => `${sig}=`],
    ['a quote from an unwrapped value', (sig: string) => `${sig}"`],
    ['whitespace inside the field', (sig: string) => `${sig.slice(0, 20)} ${sig.slice(21)}`],
    ['a non-canonical final character', (sig: string) => `${sig.slice(0, 42)}${sig[42] === 'A' ? 'B' : 'A'}`],
    ['standard base64 characters', (sig: string) => `${sig.slice(0, 42)}+`],
  ])('rejects %s', (_label, mutate) => {
    // `Buffer.from(x, 'base64url')` skips characters outside the alphabet and
    // ignores trailing bits, so several of these decode to the same 32 bytes and
    // used to verify. No forgery followed, but the cookie string was malleable,
    // and anything downstream keyed on the raw value could be bypassed by
    // permuting characters the HMAC never sees.
    const value = cookieValueOf(mint('session-token'));
    const parts = value.split('.');
    parts[3] = mutate(parts[3]!);
    expect(read(parts.join('.'))).toBeNull();
  });

  it('mints a signature of exactly 43 base64url characters', () => {
    expect(cookieValueOf(mint()).split('.')[3]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('still tolerates the optional whitespace RFC 6265 allows around a value', () => {
    // Distinct from the cases above: this is whitespace OUTSIDE the value, which
    // every cookie parser trims and which carries no information. Rejecting it
    // would break real intermediaries for no gain.
    const value = cookieValueOf(mint('session-token'));
    expect(readSessionCookie(webRequest(`${DEFAULT_NAME}=  ${value}  `), { secret: SECRET, now: NOW })).toBe(
      'session-token',
    );
  });
});

describe('attribute validation', () => {
  it.each([
    ['a CR', '/a\rb'],
    ['an LF', '/a\nb'],
    ['a full header injection', '/a\r\nSet-Cookie: evil=1'],
    ['a semicolon', '/a;Secure'],
    ['a comma', '/a,b'],
    ['a non-ascii character', '/café'],
  ])('refuses a path containing %s', (_label, path) => {
    expect(() => mint('t', { path })).toThrow(/cannot appear in a Set-Cookie header/);
  });

  it('refuses a domain containing a newline', () => {
    expect(() => mint('t', { domain: 'example.test\r\nSet-Cookie: evil=1' })).toThrow(
      /cannot appear in a Set-Cookie header/,
    );
  });

  it.each([
    ['negative', -1],
    ['zero', 0],
    ['fractional', 0.5],
    ['not a number', Number.NaN],
    ['infinite', Number.POSITIVE_INFINITY],
  ])('refuses a %s maxAgeSeconds', (_label, maxAgeSeconds) => {
    // -1 mints a cookie that is dead on arrival and 0.5 is truncated to a
    // session cookie. Both look like a working sign-in on the server and like an
    // instant sign-out to the person.
    expect(() => mint('t', { maxAgeSeconds })).toThrow(/positive whole number/);
  });

  it('accepts one second', () => {
    expect(attributesOf(mint('t', { maxAgeSeconds: 1 }))).toContain('Max-Age=1');
  });
});

describe('a request that misbehaves', () => {
  it('returns null when the header accessor hands back a non-string', () => {
    // Not observed in any adapter we ship against. One line, so that an
    // attacker-shaped request cannot reach String.prototype.split.
    for (const header of [42, {}, [], true]) {
      const request = { header: () => header } as never;
      expect(readSessionCookie(request, { secret: SECRET, now: NOW })).toBeNull();
    }
  });

  it('returns null when the header accessor throws', () => {
    const request = {
      header: () => {
        throw new Error('adapter exploded');
      },
    } as never;
    expect(readSessionCookie(request, { secret: SECRET, now: NOW })).toBeNull();
  });
});

describe('toCookieHeader', () => {
  it('turns what mint returns into what a browser would send back', () => {
    const setCookie = mint('session-token');
    expect(readSessionCookie(webRequest(toCookieHeader(setCookie)), { secret: SECRET, now: NOW })).toBe(
      'session-token',
    );
  });

  it('drops every attribute, because a Cookie header carries none', () => {
    const header = toCookieHeader(mint('t', { crossSite: true }));
    expect(header).not.toContain('SameSite');
    expect(header).not.toContain('HttpOnly');
    expect(header).not.toContain('Max-Age');
    expect(header.split(';')).toHaveLength(1);
  });

  it('joins several cookies the way a browser does', () => {
    const first = mint('one');
    const second = mintSessionCookie('two', { secret: SECRET, crossSite: false, now: NOW, path: '/factory' });
    const header = toCookieHeader(first, second);
    expect(header).toBe(`${toCookieHeader(first)}; ${toCookieHeader(second)}`);
  });

  it('models a request carrying nothing', () => {
    expect(toCookieHeader()).toBe('');
    expect(readSessionCookie(webRequest(toCookieHeader()), { secret: SECRET, now: NOW })).toBeNull();
  });
});

describe('the clock', () => {
  it('defaults to the real clock when none is injected', () => {
    const value = cookieValueOf(mintSessionCookie('session-token', { secret: SECRET, crossSite: false }));
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET })).toBe('session-token');
  });
});
