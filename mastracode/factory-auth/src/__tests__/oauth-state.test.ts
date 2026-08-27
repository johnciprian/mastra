/**
 * The OAuth `state` codec, tested as a parser of hostile input.
 *
 * `decodeState` reads a query parameter, so every one of its inputs is written
 * by whoever sent the request. The round-trip cases below prove the format
 * works; the rest prove it fails safely, which is the half that matters.
 */
import { describe, expect, it } from 'vitest';
import { DEFAULT_RETURN_TO, decodeState, encodeState, OAUTH_STATE_DELIMITER, parseStateId } from '../oauth-state.js';

describe('encodeState', () => {
  it('produces id, delimiter, percent-encoded returnTo', () => {
    const state = encodeState('/agents/42', 'state-id');
    expect(state).toBe('state-id|%2Fagents%2F42');
  });

  it('generates a distinct id when none is supplied', () => {
    const first = parseStateId(encodeState('/'));
    const second = parseStateId(encodeState('/'));
    expect(first).toBeTruthy();
    expect(first).not.toBe(second);
  });

  it('sanitizes a hostile returnTo instead of throwing, because it is usually a query parameter', () => {
    expect(decodeState(encodeState('https://evil.com')).returnTo).toBe(DEFAULT_RETURN_TO);
    expect(decodeState(encodeState('//evil.com')).returnTo).toBe(DEFAULT_RETURN_TO);
  });

  it('throws on an id containing the delimiter, because that silently corrupts the format', () => {
    expect(() => encodeState('/', `a${OAUTH_STATE_DELIMITER}b`)).toThrow(/delimiter/);
  });

  it('throws on an empty id', () => {
    expect(() => encodeState('/', '')).toThrow(/empty state id/);
  });
});

describe('round trip', () => {
  it.each([
    ['a plain path', '/'],
    ['a nested path', '/agents/42/settings'],
    ['a query string', '/search?q=hello&page=2'],
    ['a fragment', '/docs#section'],
    ['a literal delimiter in returnTo', '/search?q=a|b'],
    ['several literal delimiters', '/a|b|c|d'],
    ['a percent sign', '/search?q=100%25'],
    ['a space', '/my documents'],
  ])('preserves %s', (_label, returnTo) => {
    expect(decodeState(encodeState(returnTo)).returnTo).toBe(returnTo);
  });

  it.each([
    ['latin-1 non-ascii', '/agents/ünïcödé', '/agents/%C3%BCn%C3%AFc%C3%B6d%C3%A9'],
    ['CJK', '/日本', '/%E6%97%A5%E6%9C%AC'],
    ['an emoji outside the BMP', '/rooms/🙂', '/rooms/%F0%9F%99%82'],
    ['a control character', '/a\r\nb', '/a%0D%0Ab'],
  ])('percent-encodes %s so it can go in a Location header', (_label, returnTo, expected) => {
    // A Location header is a ByteString. Anything above U+00FF throws on the way
    // in - TypeError under a Response, ERR_INVALID_CHAR under node:http - which
    // on an OAuth callback is an unauthenticated 500. Encoding keeps the route
    // reachable AND keeps the header constructible.
    const decoded = decodeState(encodeState(returnTo)).returnTo;
    expect(decoded).toBe(expected);
    expect(() => new Response(null, { status: 302, headers: { location: decoded } })).not.toThrow();
    // Still the same route once the router decodes it.
    expect(decodeURIComponent(decoded)).toBe(returnTo);
  });

  it('would have thrown before, which is the point of the case above', () => {
    // Pinning the failure mode itself: the raw path is what used to reach the
    // header, and this is what it did there.
    expect(() => new Response(null, { status: 302, headers: { location: '/日本' } })).toThrow(TypeError);
  });

  it('discards a lone surrogate rather than throwing while encoding it', () => {
    // encodeURIComponent throws on an unpaired surrogate. That is malformed
    // input rather than a path, so it gets the default destination.
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}${encodeURIComponent('/ok')}`).returnTo).toBe('/ok');
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}/lone\ud800surrogate`).returnTo).toBe(DEFAULT_RETURN_TO);
  });

  it('preserves the caller-supplied id alongside the returnTo', () => {
    const decoded = decodeState(encodeState('/a|b', 'nonce-123'));
    expect(decoded).toEqual({ id: 'nonce-123', returnTo: '/a|b' });
  });

  it('keeps the delimiter out of the encoded half, so the first split is the only split', () => {
    const state = encodeState('/a|b', 'nonce-123');
    expect(state.indexOf(OAUTH_STATE_DELIMITER)).toBe(state.lastIndexOf(OAUTH_STATE_DELIMITER));
  });
});

describe('decodeState rejects open redirects', () => {
  it.each([
    ['an absolute https URL', 'https://evil.com/path'],
    ['an absolute http URL', 'http://evil.com/path'],
    ['a javascript: URL', 'javascript:alert(1)'],
    ['a data: URL', 'data:text/html,<script>alert(1)</script>'],
    ['a protocol-relative URL', '//evil.com'],
    ['a protocol-relative URL with a path', '//evil.com/callback'],
    ['a backslash protocol-relative URL', '/\\evil.com'],
    ['a scheme-relative triple slash', '///evil.com'],
    ['a bare relative path', 'agents/42'],
    ['an empty destination', ''],
  ])('sends %s to the default', (_label, hostile) => {
    // Through the encoder, which is the path a query parameter takes.
    expect(decodeState(encodeState(hostile)).returnTo).toBe(DEFAULT_RETURN_TO);
    // And hand-crafted, which is the path an attacker takes.
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}${encodeURIComponent(hostile)}`).returnTo).toBe(DEFAULT_RETURN_TO);
  });

  it('defuses a destination carrying a control character, which would be response splitting', () => {
    // This used to answer DEFAULT_RETURN_TO. It now answers an encoded path
    // instead, and that is a deliberate change rather than a weakening: the
    // characters that made it response splitting are gone either way, and
    // encoding is what also lets a legitimate non-ASCII route survive. What
    // matters is the property, so assert the property.
    const injected = '/ok\r\nSet-Cookie: session=stolen';
    const returnTo = decodeState(`id${OAUTH_STATE_DELIMITER}${encodeURIComponent(injected)}`).returnTo;

    expect(returnTo).not.toContain('\r');
    expect(returnTo).not.toContain('\n');
    // The space survives: 0x20 is printable ASCII, it fits in a ByteString, and
    // it splits nothing. Only what cannot appear in a header is encoded.
    expect(returnTo).toBe('/ok%0D%0ASet-Cookie: session=stolen');

    // The header it produces carries one header, not two.
    const response = new Response(null, { status: 302, headers: { location: returnTo } });
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(response.headers.get('location')).toBe(returnTo);
  });

  it('rejects a protocol-relative URL hidden behind percent encoding', () => {
    // `%2F%2Fevil.com` only becomes `//evil.com` after decoding, so a check that
    // ran before `decodeURIComponent` would wave this through.
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}%2F%2Fevil.com`).returnTo).toBe(DEFAULT_RETURN_TO);
  });
});

describe('decodeState on malformed input', () => {
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['an empty string', ''],
  ])('returns a null id and the default destination for %s', (_label, raw) => {
    expect(decodeState(raw)).toEqual({ id: null, returnTo: DEFAULT_RETURN_TO });
  });

  it('never throws on a malformed percent escape', () => {
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}%zz`)).toEqual({ id: 'id', returnTo: DEFAULT_RETURN_TO });
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}%`)).toEqual({ id: 'id', returnTo: DEFAULT_RETURN_TO });
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}%E0%A4%A`)).toEqual({ id: 'id', returnTo: DEFAULT_RETURN_TO });
  });

  it('treats a leading delimiter as an absent id', () => {
    expect(decodeState(`${OAUTH_STATE_DELIMITER}%2Fdashboard`)).toEqual({ id: null, returnTo: '/dashboard' });
  });

  it('treats a trailing delimiter as an absent destination', () => {
    expect(decodeState(`id${OAUTH_STATE_DELIMITER}`)).toEqual({ id: 'id', returnTo: DEFAULT_RETURN_TO });
  });
});

describe('decodeState on a state this package did not produce', () => {
  it('reads an opaque provider-minted state as all id and no destination', () => {
    expect(decodeState('cWFhOTdiNGYtZTVhMS00')).toEqual({
      id: 'cWFhOTdiNGYtZTVhMS00',
      returnTo: DEFAULT_RETURN_TO,
    });
  });

  it('does not read a JSON state as a destination', () => {
    const json = JSON.stringify({ returnTo: '/agents', nonce: 'abc' });
    expect(decodeState(json).returnTo).toBe(DEFAULT_RETURN_TO);
  });

  it('does not treat a URL-shaped state as a destination', () => {
    expect(decodeState('https://evil.com/?x=1').returnTo).toBe(DEFAULT_RETURN_TO);
  });
});

describe('parseStateId', () => {
  it('returns the id half of a value from encodeState', () => {
    expect(parseStateId(encodeState('/agents', 'nonce-123'))).toBe('nonce-123');
  });

  it('returns the whole value when there is no delimiter', () => {
    expect(parseStateId('opaque-provider-state')).toBe('opaque-provider-state');
  });

  it('returns null for absent input', () => {
    expect(parseStateId(undefined)).toBeNull();
    expect(parseStateId(null)).toBeNull();
    expect(parseStateId('')).toBeNull();
  });

  it('returns null when the id half is empty', () => {
    expect(parseStateId(`${OAUTH_STATE_DELIMITER}%2Fdashboard`)).toBeNull();
  });

  it('is unaffected by a destination it cannot decode, so CSRF still works on a tampered value', () => {
    expect(parseStateId(`nonce-123${OAUTH_STATE_DELIMITER}%zz`)).toBe('nonce-123');
  });

  it('agrees with decodeState on every input', () => {
    const inputs = [
      undefined,
      null,
      '',
      'opaque',
      `${OAUTH_STATE_DELIMITER}%2Fx`,
      `id${OAUTH_STATE_DELIMITER}`,
      encodeState('/a|b', 'nonce'),
    ];
    for (const raw of inputs) {
      expect(decodeState(raw).id).toBe(parseStateId(raw));
    }
  });
});

describe('input that is not a string', () => {
  // `decodeState` and `parseStateId` are documented as total. They read a query
  // parameter, and a query-string parser is entitled to hand back something
  // other than a string: Express's `qs` turns `?state=a&state=b` into an array
  // and `?state[x]=y` into an object. Both are attacker-reachable.
  const notStrings: unknown[] = [
    42,
    0,
    true,
    false,
    {},
    [],
    ['a|%2Fx', 'b'],
    { toString: () => 'x|y' },
    Symbol.for('s'),
  ];

  it.each(
    notStrings.map(value => [typeof value === 'symbol' ? 'a symbol' : (JSON.stringify(value) ?? 'a symbol'), value]),
  )('decodeState(%s) returns the default rather than throwing', (_label, value) => {
    const decoded = decodeState(value as never);
    expect(decoded).toEqual({ id: null, returnTo: DEFAULT_RETURN_TO });
    // The declared type says `string | null`, so an Array must never come back.
    expect(decoded.id === null || typeof decoded.id === 'string').toBe(true);
  });

  it.each(
    notStrings.map(value => [typeof value === 'symbol' ? 'a symbol' : (JSON.stringify(value) ?? 'a symbol'), value]),
  )('parseStateId(%s) returns null rather than throwing', (_label, value) => {
    expect(parseStateId(value as never)).toBeNull();
  });

  it('never returns an array as an id, which the declared type forbids', () => {
    const decoded = decodeState(['a|%2Fx', 'b'] as never);
    expect(Array.isArray(decoded.id)).toBe(false);
    expect(decoded.id).toBeNull();
  });
});
