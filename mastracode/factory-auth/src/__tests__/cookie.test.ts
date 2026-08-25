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
  SESSION_COOKIE_NAME,
  clearSessionCookie,
  mintSessionCookie,
  readSessionCookie,
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

function headerFor(value: string): string {
  return `${SESSION_COOKIE_NAME}=${value}`;
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

  it('finds the cookie among others', () => {
    const value = cookieValueOf(mint('session-token'));
    const header = `theme=dark; ${SESSION_COOKIE_NAME}=${value}; locale=en-GB`;
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
    ['our name with no value', `${SESSION_COOKIE_NAME}`],
    ['our name with an empty value', `${SESSION_COOKIE_NAME}=`],
  ])('returns null for %s', (_label, header) => {
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW })).toBeNull();
  });

  it('takes the first cookie that verifies, not the first that appears', () => {
    // A page on a sibling host can set a same-named cookie on a shared parent
    // domain. The browser sends both and does not say which is which, so
    // position is not evidence of anything.
    const ours = cookieValueOf(mint('real-session'));
    const shadow = cookieValueOf(mintSessionCookie('forged', { secret: OTHER_SECRET, crossSite: false, now: NOW }));

    const shadowFirst = `${SESSION_COOKIE_NAME}=${shadow}; ${SESSION_COOKIE_NAME}=${ours}`;
    const shadowSecond = `${SESSION_COOKIE_NAME}=${ours}; ${SESSION_COOKIE_NAME}=${shadow}`;

    expect(readSessionCookie(webRequest(shadowFirst), { secret: SECRET, now: NOW })).toBe('real-session');
    expect(readSessionCookie(webRequest(shadowSecond), { secret: SECRET, now: NOW })).toBe('real-session');
  });

  it('skips an expired duplicate in favour of a live one', () => {
    const stale = cookieValueOf(mint('stale', { maxAgeSeconds: 60 }));
    const fresh = cookieValueOf(mint('fresh', { now: NOW + 120_000 }));
    const header = `${SESSION_COOKIE_NAME}=${stale}; ${SESSION_COOKIE_NAME}=${fresh}`;
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW + 120_000 })).toBe('fresh');
  });

  it('reads duplicate header lines joined with a comma', () => {
    // `Headers.get('cookie')` joins repeated header lines with ', '.
    const value = cookieValueOf(mint('session-token'));
    const header = `theme=dark, ${SESSION_COOKIE_NAME}=${value}`;
    expect(readSessionCookie(webRequest(header), { secret: SECRET, now: NOW })).toBe('session-token');
  });

  it('reads a value an intermediary wrapped in double quotes', () => {
    const value = cookieValueOf(mint('session-token'));
    expect(readSessionCookie(webRequest(`${SESSION_COOKIE_NAME}="${value}"`), { secret: SECRET, now: NOW })).toBe(
      'session-token',
    );
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

  it('honours Path and Domain overrides', () => {
    const attributes = attributesOf(mint('t', { path: '/factory', domain: 'example.test' }));
    expect(attributes).toContain('Path=/factory');
    expect(attributes).toContain('Domain=example.test');
  });

  it('defaults Max-Age to a week and honours an override', () => {
    expect(attributesOf(mint())).toContain(`Max-Age=${DEFAULT_SESSION_MAX_AGE_SECONDS}`);
    expect(attributesOf(mint('t', { maxAgeSeconds: 900 }))).toContain('Max-Age=900');
  });

  it('names the cookie once, and declares that name', () => {
    expect(mint()).toMatch(new RegExp(`^${SESSION_COOKIE_NAME}=`));
    expect(SESSION_COOKIE_NAME).toBe('mastra_factory_session');
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
});

describe('the clock', () => {
  it('defaults to the real clock when none is injected', () => {
    const value = cookieValueOf(mintSessionCookie('session-token', { secret: SECRET, crossSite: false }));
    expect(readSessionCookie(webRequest(headerFor(value)), { secret: SECRET })).toBe('session-token');
  });
});
