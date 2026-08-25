/**
 * Identity normalization, as tests.
 *
 * The shapes below are the ones real providers return, written out rather than
 * reduced to `{ id: 'x' }`, because the point of this module is that the noise
 * around the id differs per provider and the id does not.
 *
 * Three groups, matching the three things that can go wrong:
 *
 * - the four shapes, which is what the module is for;
 * - the ambiguous inputs, which is where an accidental precedence would hide -
 *   two competing id keys, a blank id, a numeric id, a non-object;
 * - the provider escape hatch, where the question is not "does it work" but
 *   "whose answer wins", including when that answer is `null`.
 */
import { describe, expect, it, vi } from 'vitest';
import type { AuthIdentity, IIdentityProvider } from '../identity.js';
import { isIdentityProvider, toAuthIdentity } from '../identity.js';

/** Every key {@link AuthIdentity} declares, and nothing else. */
const IDENTITY_KEYS = ['id', 'email', 'name', 'avatarUrl', 'organizationId'];

/** A provider that maps its own payloads, and nothing more. */
function mapperProvider(toIdentity: (raw: unknown) => AuthIdentity | null): IIdentityProvider {
  return { toIdentity };
}

describe('toAuthIdentity', () => {
  describe('the four shapes', () => {
    it('reads a flat provider user', () => {
      expect(
        toAuthIdentity({
          id: 'user_01H',
          email: 'ada@example.com',
          name: 'Ada Lovelace',
          avatarUrl: 'https://example.com/ada.png',
          organizationId: 'org_01H',
        }),
      ).toEqual({
        id: 'user_01H',
        email: 'ada@example.com',
        name: 'Ada Lovelace',
        avatarUrl: 'https://example.com/ada.png',
        organizationId: 'org_01H',
      });
    });

    it('reads a flat user carrying nothing but an id', () => {
      expect(toAuthIdentity({ id: 'user_01H' })).toEqual({
        id: 'user_01H',
        email: undefined,
        name: undefined,
        avatarUrl: undefined,
        organizationId: undefined,
      });
    });

    it('reads uid, as Firebase DecodedIdToken returns it', () => {
      // A real decoded token: `uid` and `sub` hold the same value, and the
      // display fields sit among the JWT claims.
      const decoded = {
        aud: 'my-firebase-project',
        auth_time: 1_700_000_000,
        exp: 1_700_003_600,
        firebase: { identities: {}, sign_in_provider: 'google.com' },
        iat: 1_700_000_000,
        iss: 'https://securetoken.google.com/my-firebase-project',
        sub: 'FIREBASE_UID_123',
        uid: 'FIREBASE_UID_123',
        email: 'grace@example.com',
        email_verified: true,
        name: 'Grace Hopper',
        picture: 'https://example.com/grace.png',
      };

      expect(toAuthIdentity(decoded)).toEqual({
        id: 'FIREBASE_UID_123',
        email: 'grace@example.com',
        name: 'Grace Hopper',
        // Firebase names the avatar `picture`, and this module reads
        // `avatarUrl` only. A provider that wants that field mapped implements
        // `IIdentityProvider` - it is the case the escape hatch is for.
        avatarUrl: undefined,
        organizationId: undefined,
      });
    });

    it('reads sub, as raw OIDC claims carry it', () => {
      expect(
        toAuthIdentity({
          iss: 'https://accounts.example.com',
          sub: '248289761001',
          aud: 'client_id',
          exp: 1_700_003_600,
          iat: 1_700_000_000,
          email: 'jane@example.com',
          name: 'Jane Doe',
        }),
      ).toEqual({
        id: '248289761001',
        email: 'jane@example.com',
        name: 'Jane Doe',
        avatarUrl: undefined,
        organizationId: undefined,
      });
    });

    it('reads the { session, user } wrapper, with the org on the session', () => {
      expect(
        toAuthIdentity({
          session: {
            id: 'sess_abc',
            userId: 'user_xyz',
            expiresAt: '2026-01-01T00:00:00.000Z',
            activeOrganizationId: 'org_active',
          },
          user: {
            id: 'user_xyz',
            email: 'linus@example.com',
            name: 'Linus',
            avatarUrl: 'https://example.com/linus.png',
          },
        }),
      ).toEqual({
        id: 'user_xyz',
        email: 'linus@example.com',
        name: 'Linus',
        avatarUrl: 'https://example.com/linus.png',
        organizationId: 'org_active',
      });
    });
  });

  describe('the { session, user } wrapper', () => {
    it('prefers the session organization over one on the user half', () => {
      const identity = toAuthIdentity({
        session: { id: 'sess_abc', activeOrganizationId: 'org_from_session' },
        user: { id: 'user_xyz', organizationId: 'org_from_user' },
      });

      // The session is the authenticated context: a user in three organizations
      // is acting in exactly one of them for this request.
      expect(identity?.organizationId).toBe('org_from_session');
    });

    it('falls back to the user organization when the session names none', () => {
      const identity = toAuthIdentity({
        session: { id: 'sess_abc' },
        user: { id: 'user_xyz', organizationId: 'org_from_user' },
      });

      expect(identity?.organizationId).toBe('org_from_user');
    });

    it('leaves the organization absent when neither half names one', () => {
      const identity = toAuthIdentity({ session: { id: 'sess_abc' }, user: { id: 'user_xyz' } });

      expect(identity?.organizationId).toBeUndefined();
    });

    it('applies the same id precedence inside the user half', () => {
      expect(toAuthIdentity({ session: {}, user: { uid: 'user_uid' } })?.id).toBe('user_uid');
      expect(toAuthIdentity({ session: {}, user: { sub: 'user_sub' } })?.id).toBe('user_sub');
    });

    it('does not fall through to the top level when the user half names nobody', () => {
      // `session.id` is a session id and the top-level `id` here belongs to the
      // wrapper, not to a person. Reaching past the user half would key the
      // host's storage on the wrong subject, so this is null on purpose.
      expect(
        toAuthIdentity({
          id: 'not_a_user_id',
          sub: 'also_not_a_user_id',
          session: { id: 'sess_abc', activeOrganizationId: 'org_active' },
          user: { email: 'nobody@example.com' },
        }),
      ).toBeNull();
    });

    it('does not read an array as a payload', () => {
      // `typeof [] === 'object'`, so without an explicit Array check an array
      // would be treated as a keyed payload. It has no `id`, so the result is
      // the same null - which is exactly why the check needs its own test: the
      // outcome does not distinguish a working guard from a missing one.
      expect(toAuthIdentity([])).toBeNull();
      expect(toAuthIdentity(['id_from_array'])).toBeNull();
      expect(toAuthIdentity(Object.assign(['x'], { id: 'user_smuggled' }))).toBeNull();
      // Nested, where the wrapper shape would otherwise pick it up.
      expect(toAuthIdentity({ session: {}, user: ['user_1'] })).toBeNull();
      expect(toAuthIdentity({ session: [], user: { id: 'user_1' } })?.id).toBeUndefined();
    });

    it('needs both halves to be objects before it is a wrapper', () => {
      // Only `user`: not the wrapper, so the top level is read flat.
      expect(toAuthIdentity({ id: 'top_level', user: { id: 'nested' } })?.id).toBe('top_level');
      // Only `session`: same.
      expect(toAuthIdentity({ id: 'top_level', session: { id: 'sess_abc' } })?.id).toBe('top_level');
      // A `user` that is not an object cannot be the authenticated subject.
      expect(toAuthIdentity({ id: 'top_level', session: {}, user: 'user_xyz' })?.id).toBe('top_level');
      expect(toAuthIdentity({ id: 'top_level', session: {}, user: null })?.id).toBe('top_level');
    });
  });

  describe('precedence between competing id keys', () => {
    it('prefers id over sub', () => {
      expect(toAuthIdentity({ id: 'from_id', sub: 'from_sub' })?.id).toBe('from_id');
    });

    it('prefers id over uid', () => {
      expect(toAuthIdentity({ id: 'from_id', uid: 'from_uid' })?.id).toBe('from_id');
    });

    it('prefers uid over sub', () => {
      expect(toAuthIdentity({ uid: 'from_uid', sub: 'from_sub' })?.id).toBe('from_uid');
    });

    it('prefers id over both when all three disagree', () => {
      expect(toAuthIdentity({ id: 'from_id', uid: 'from_uid', sub: 'from_sub' })?.id).toBe('from_id');
    });
  });

  describe('an id that is present but unusable', () => {
    it('treats an empty-string id as absent and reads the next key', () => {
      expect(toAuthIdentity({ id: '', sub: 'from_sub' })?.id).toBe('from_sub');
    });

    it('treats a whitespace-only id as absent', () => {
      // A blank id is a storage key every user would share.
      expect(toAuthIdentity({ id: '   ', uid: 'from_uid' })?.id).toBe('from_uid');
      expect(toAuthIdentity({ id: '\t\n' })).toBeNull();
    });

    it('returns null when the only id present is blank', () => {
      expect(toAuthIdentity({ id: '' })).toBeNull();
    });

    it('treats an explicitly undefined id as absent', () => {
      expect(toAuthIdentity({ id: undefined, uid: 'from_uid' })?.id).toBe('from_uid');
      expect(toAuthIdentity({ id: null, sub: 'from_sub' })?.id).toBe('from_sub');
    });

    it('does not trim an id it accepts', () => {
      expect(toAuthIdentity({ id: ' user_01H ' })?.id).toBe(' user_01H ');
    });
  });

  describe('an id that is not a string', () => {
    it('coerces a finite number to its decimal form', () => {
      expect(toAuthIdentity({ id: 4711 })?.id).toBe('4711');
      expect(toAuthIdentity({ sub: -12 })?.id).toBe('-12');
    });

    it('coerces the numeric id zero, which is falsy but perfectly valid', () => {
      expect(toAuthIdentity({ id: 0 })?.id).toBe('0');
    });

    it('coerces a bigint', () => {
      expect(toAuthIdentity({ id: 9_007_199_254_740_993n })?.id).toBe('9007199254740993');
    });

    it('rejects NaN and Infinity, which have no key form', () => {
      expect(toAuthIdentity({ id: Number.NaN, sub: 'from_sub' })?.id).toBe('from_sub');
      expect(toAuthIdentity({ id: Number.POSITIVE_INFINITY })).toBeNull();
    });

    it('rejects a boolean or an object id rather than stringifying a provider bug', () => {
      expect(toAuthIdentity({ id: true })).toBeNull();
      expect(toAuthIdentity({ id: { toString: () => 'user_01H' } })).toBeNull();
      expect(toAuthIdentity({ id: ['user_01H'] })).toBeNull();
    });

    it('coerces a numeric organizationId the same way', () => {
      expect(toAuthIdentity({ id: 'user_01H', organizationId: 42 })?.organizationId).toBe('42');
    });
  });

  describe('the optional display fields', () => {
    it('drops a non-string email, name or avatarUrl', () => {
      expect(toAuthIdentity({ id: 'user_01H', email: 42, name: false, avatarUrl: { href: 'x' } })).toEqual({
        id: 'user_01H',
        email: undefined,
        name: undefined,
        avatarUrl: undefined,
        organizationId: undefined,
      });
    });

    it('drops a blank email or name, so callers branch on one absent value', () => {
      expect(toAuthIdentity({ id: 'user_01H', email: '', name: '  ' })).toEqual({
        id: 'user_01H',
        email: undefined,
        name: undefined,
        avatarUrl: undefined,
        organizationId: undefined,
      });
    });

    it('carries no key beyond the ones AuthIdentity declares', () => {
      const identity = toAuthIdentity({ id: 'user_01H', workosId: 'wos_1', role: 'admin', tenant: 't1' });

      expect(identity).not.toBeNull();
      expect(Object.keys(identity as AuthIdentity).sort()).toEqual([...IDENTITY_KEYS].sort());
    });
  });

  describe('input that names no user at all', () => {
    it.each([
      ['null', null],
      ['undefined', undefined],
      ['a string', 'user_01H'],
      ['a number', 4711],
      ['a boolean', true],
      ['an empty object', {}],
      ['an array', ['user_01H']],
      ['an array of users', [{ id: 'user_01H' }]],
      ['a function', () => ({ id: 'user_01H' })],
      ['an object with no id key', { email: 'ada@example.com', organizationId: 'org_01H' }],
    ])('returns null for %s', (_label, raw) => {
      expect(toAuthIdentity(raw)).toBeNull();
    });
  });
});

describe('isIdentityProvider', () => {
  it('is true for anything with a toIdentity method', () => {
    expect(isIdentityProvider({ toIdentity: () => null })).toBe(true);
  });

  it('is true for a class instance, without instanceof', () => {
    // Structural on purpose: duplicate copies of a package in a dependency tree
    // make instanceof false for an object that implements the interface fully.
    class MyProvider {
      toIdentity(): AuthIdentity | null {
        return null;
      }
    }

    expect(isIdentityProvider(new MyProvider())).toBe(true);
  });

  it.each([
    ['null', null],
    ['undefined', undefined],
    ['an object with no toIdentity', { authenticateToken: () => null }],
    ['a non-function toIdentity', { toIdentity: 'yes' }],
    ['a toIdentity that is only a truthy value', { toIdentity: true }],
    ['a string', 'toIdentity'],
    ['a number', 1],
    // Matches the seven guards in ./contract, which all require typeof
    // 'object'. A provider is an object, not a function.
    ['a function carrying toIdentity', Object.assign(() => null, { toIdentity: () => null })],
  ])('is false for %s', (_label, candidate) => {
    expect(isIdentityProvider(candidate)).toBe(false);
  });

  it('narrows the type for a caller', () => {
    const candidate: unknown = { toIdentity: () => ({ id: 'user_01H' }) };

    expect(isIdentityProvider(candidate) ? candidate.toIdentity(null)?.id : 'not narrowed').toBe('user_01H');
  });
});

describe('toAuthIdentity with a provider mapper', () => {
  it('prefers the mapper over built-in shape detection', () => {
    const provider = mapperProvider(() => ({ id: 'from_mapper' }));

    // The raw payload has a flat id the built-in path would happily read.
    expect(toAuthIdentity({ id: 'from_shape_detection' }, provider)?.id).toBe('from_mapper');
  });

  it('hands the mapper the raw payload, untouched', () => {
    const raw = { claims: { 'https://example.com/uid': 'ns_user' } };
    const toIdentity = vi.fn(() => ({ id: 'ns_user' }));

    toAuthIdentity(raw, mapperProvider(toIdentity));

    expect(toIdentity).toHaveBeenCalledTimes(1);
    expect(toIdentity).toHaveBeenCalledWith(raw);
  });

  it('respects a null from the mapper instead of falling through', () => {
    // The raw payload carries a perfectly good `sub`. The mapper said no, and a
    // mapper says no for reasons only it knows - a service account, an
    // unverified email, a missing custom claim. Falling back to shape detection
    // would hand back an identity the provider had just refused.
    const provider = mapperProvider(() => null);

    expect(toAuthIdentity({ sub: '248289761001', id: 'from_id' }, provider)).toBeNull();
  });

  it('treats a mapper result with no usable id exactly like a null', () => {
    expect(
      toAuthIdentity(
        { sub: 'from_sub' },
        mapperProvider(() => ({ id: '' })),
      ),
    ).toBeNull();
    expect(
      toAuthIdentity(
        { sub: 'from_sub' },
        mapperProvider(() => ({}) as AuthIdentity),
      ),
    ).toBeNull();
    expect(
      toAuthIdentity(
        { sub: 'from_sub' },
        mapperProvider(() => undefined as unknown as null),
      ),
    ).toBeNull();
    expect(
      toAuthIdentity(
        { sub: 'from_sub' },
        mapperProvider(() => 'user_01H' as unknown as null),
      ),
    ).toBeNull();
  });

  it('normalizes what the mapper returns rather than trusting it', () => {
    // A mapper chooses which fields. It does not get to break the invariant the
    // type promises and the conformance suite asserts.
    expect(
      toAuthIdentity(
        {},
        mapperProvider(() => ({ id: 4711, email: 42, name: '  ' }) as unknown as AuthIdentity),
      ),
    ).toEqual({
      id: '4711',
      email: undefined,
      name: undefined,
      avatarUrl: undefined,
      organizationId: undefined,
    });
  });

  it('applies the same id precedence to the mapper result', () => {
    expect(
      toAuthIdentity(
        {},
        mapperProvider(() => ({ uid: 'from_mapper_uid' }) as unknown as AuthIdentity),
      )?.id,
    ).toBe('from_mapper_uid');
  });

  it('lets a mapper delegate back to the built-in behaviour', () => {
    // The escape from the no-fallthrough rule, in the direction that is safe.
    const provider = mapperProvider(raw => toAuthIdentity(raw));

    expect(toAuthIdentity({ uid: 'FIREBASE_UID_123' }, provider)?.id).toBe('FIREBASE_UID_123');
    expect(toAuthIdentity({ nothing: true }, provider)).toBeNull();
  });

  it('lets a throwing mapper propagate', () => {
    const provider = mapperProvider(() => {
      throw new Error('token is for a service account');
    });

    expect(() => toAuthIdentity({ sub: '248289761001' }, provider)).toThrow('token is for a service account');
  });

  it.each([
    ['no second argument', undefined],
    ['a provider without toIdentity', { authenticateToken: () => null }],
    ['a non-object', 'provider'],
    ['null', null],
  ])('uses built-in shape detection given %s', (_label, provider) => {
    expect(toAuthIdentity({ uid: 'FIREBASE_UID_123' }, provider)?.id).toBe('FIREBASE_UID_123');
  });
});
