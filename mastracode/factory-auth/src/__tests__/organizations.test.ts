/**
 * Synthetic organizations, and the host-side resolver.
 *
 * Two properties carry most of this file, and neither is checkable by reading
 * the implementation.
 *
 * The first is determinism. `ensureOrganization` has to produce the same string
 * in a process that has never seen the user before, on a deploy three months
 * later, on a different machine. A test that calls it twice in one closure
 * proves almost nothing about that, so the determinism tests below call it
 * through independently constructed wrappers and compare against a literal
 * written out by hand - `'user:8f21ac'`, not `` `${PREFIX}8f21ac` ``. A literal
 * is the only form that fails when the derivation changes, which is the day the
 * failure is worth having.
 *
 * The second is preservation. A wrapper that dropped `ISSOProvider` would break
 * sign-in on every deployment that used it, and would do so at the moment a user
 * clicked a button rather than at build time. So every guard in `./contract` is
 * asserted through the wrapper in both directions: a capability that was there
 * is still there, and one that was absent has not been invented.
 *
 * The fakes are plain objects wherever the guards are what is under test - the
 * guards are structural, so a plain object is exactly as much of a provider as a
 * class is - and a real class where the thing under test is what happens to
 * `this`.
 */
import { describe, expect, it, vi } from 'vitest';
import { toAuthDescriptor } from '../capabilities.js';
import {
  hasAuthInit,
  isAuthHttpHandler,
  isCredentialsProvider,
  isOrganizationsProvider,
  isSessionProvider,
  isSSOProvider,
  isUserProvider,
  type IMastraAuthProvider,
} from '../contract.js';
import {
  isSyntheticOrganizationId,
  resolveOrganizationId,
  SYNTHETIC_ORGANIZATION_PREFIX,
  syntheticOrganizationId,
  withSyntheticOrganizations,
  type SyntheticOrganizationOptions,
} from '../organizations.js';

/** The base contract and nothing else: a bearer-token validator. */
const bearerOnly = {
  name: 'fake',
  authenticateToken: async () => null,
  authorizeUser: async () => true,
};

function provider(...capabilities: object[]): IMastraAuthProvider {
  return Object.assign({}, bearerOnly, ...capabilities) as IMastraAuthProvider;
}

const sso = {
  getLoginUrl: () => 'https://idp.test/authorize',
  handleCallback: async () => ({ user: {} }),
};
const session = { createSession: async () => ({}), validateSession: async () => null };
const user = { getCurrentUser: async () => null };
const credentials = { signIn: async () => ({ user: {} }), signUp: async () => ({ user: {} }) };
const httpHandler = { handleAuthRequest: async () => new Response() };
const init = { init: async () => {} };

/** A provider with real organizations of its own. */
function withRealOrganizations(
  ensure: (userId: string) => Promise<string | undefined>,
  admin: (organizationId: string, userId: string) => Promise<boolean> = async () => true,
) {
  return { ensureOrganization: vi.fn(ensure), isOrganizationAdmin: vi.fn(admin) };
}

describe('SYNTHETIC_ORGANIZATION_PREFIX', () => {
  // Pinned as a literal on purpose. The Factory writes `user:${userId}` today at
  // mastracode/factory/src/routes/provider-credentials.ts, and rows keyed that
  // way exist in deployed databases. Changing this constant orphans them
  // silently, so the change has to be a visible diff on this line.
  it('is the string the Factory already writes', () => {
    expect(SYNTHETIC_ORGANIZATION_PREFIX).toBe('user:');
  });
});

describe('syntheticOrganizationId', () => {
  it('derives the id from the user id and nothing else', () => {
    expect(syntheticOrganizationId('8f21ac')).toBe('user:8f21ac');
  });

  it('returns the same string every call', () => {
    const first = syntheticOrganizationId('8f21ac');
    const second = syntheticOrganizationId('8f21ac');
    expect(first).toBe('user:8f21ac');
    expect(second).toBe(first);
  });

  it('reads nothing but its argument, so two different users never collide', () => {
    expect(syntheticOrganizationId('a')).not.toBe(syntheticOrganizationId('b'));
  });

  it('coerces a numeric id, because serial primary keys are ordinary', () => {
    expect(syntheticOrganizationId(7 as unknown as string)).toBe('user:7');
    expect(syntheticOrganizationId(7n as unknown as string)).toBe('user:7');
  });

  // The bare prefix would be one organization shared by every user whose id
  // failed to resolve, which is the exact failure this module exists to prevent.
  it.each([
    ['an empty string', ''],
    ['whitespace only', '   '],
    ['undefined', undefined],
    ['null', null],
    ['a boolean', true],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['an object', {}],
  ])('is undefined for %s rather than the bare prefix', (_label, value) => {
    expect(syntheticOrganizationId(value as unknown as string)).toBeUndefined();
  });

  it('does not trim, because rewriting a storage key is not its job', () => {
    expect(syntheticOrganizationId(' a ')).toBe('user: a ');
  });

  it('honours a configured prefix', () => {
    expect(syntheticOrganizationId('8f21ac', { prefix: 'personal/' })).toBe('personal/8f21ac');
  });

  it.each([
    ['an empty prefix', ''],
    ['a non-string prefix', 1],
    ['a null prefix', null],
  ])('rejects %s', (_label, prefix) => {
    expect(() => syntheticOrganizationId('8f21ac', { prefix } as unknown as SyntheticOrganizationOptions)).toThrow(
      TypeError,
    );
  });
});

describe('isSyntheticOrganizationId', () => {
  it('recognizes an id this module derived', () => {
    expect(isSyntheticOrganizationId(syntheticOrganizationId('8f21ac')!)).toBe(true);
  });

  it('does not claim a provider organization id', () => {
    expect(isSyntheticOrganizationId('org_01H8XYZ')).toBe(false);
  });

  it('follows the configured prefix', () => {
    expect(isSyntheticOrganizationId('user:8f21ac', { prefix: 'personal/' })).toBe(false);
    expect(isSyntheticOrganizationId('personal/8f21ac', { prefix: 'personal/' })).toBe(true);
  });

  it('is false for anything that is not a string', () => {
    expect(isSyntheticOrganizationId(undefined as unknown as string)).toBe(false);
    expect(isSyntheticOrganizationId(null as unknown as string)).toBe(false);
  });
});

describe('resolveOrganizationId', () => {
  it('returns the declared organization when the identity has one', () => {
    expect(resolveOrganizationId({ id: '8f21ac', organizationId: 'org_01H8XYZ' })).toBe('org_01H8XYZ');
  });

  // The generalization of tenantOrgId in
  // mastracode/factory/src/routes/provider-credentials.ts. Same string, so a row
  // that route already wrote is the row this resolver finds.
  it('falls back to the same id the Factory route already writes', () => {
    expect(resolveOrganizationId({ id: '8f21ac' })).toBe('user:8f21ac');
  });

  it('treats a blank organization id as absent', () => {
    expect(resolveOrganizationId({ id: '8f21ac', organizationId: '   ' })).toBe('user:8f21ac');
  });

  it('is stable across calls', () => {
    expect(resolveOrganizationId({ id: '8f21ac' })).toBe(resolveOrganizationId({ id: '8f21ac' }));
  });

  it('never returns undefined, so no caller has to write the 403 branch', () => {
    const resolved: string = resolveOrganizationId({ id: '8f21ac' });
    expect(typeof resolved).toBe('string');
  });

  it('honours a configured prefix', () => {
    expect(resolveOrganizationId({ id: '8f21ac' }, { prefix: 'personal/' })).toBe('personal/8f21ac');
  });

  it('throws rather than invent a key shared by every broken identity', () => {
    expect(() => resolveOrganizationId({ id: '' })).toThrow(TypeError);
    expect(() => resolveOrganizationId({} as { id: string })).toThrow(/no usable id/);
  });

  it('throws on a missing identity rather than resolving one', () => {
    expect(() => resolveOrganizationId(undefined as unknown as { id: string })).toThrow(TypeError);
  });
});

describe('withSyntheticOrganizations', () => {
  it('makes a bare provider satisfy isOrganizationsProvider', () => {
    expect(isOrganizationsProvider(provider())).toBe(false);
    expect(isOrganizationsProvider(withSyntheticOrganizations(provider()))).toBe(true);
  });

  it('does not mutate the provider it wrapped', () => {
    const bare = provider();
    withSyntheticOrganizations(bare);
    expect(isOrganizationsProvider(bare)).toBe(false);
    expect(Object.keys(bare)).not.toContain('ensureOrganization');
  });

  it('is visible to the capability descriptor', () => {
    expect(toAuthDescriptor(provider()).features.organizations).toBe(false);
    expect(toAuthDescriptor(withSyntheticOrganizations(provider())).features.organizations).toBe(true);
  });

  it('rejects an unusable prefix at wrap time', () => {
    expect(() => withSyntheticOrganizations(provider(), { prefix: '' })).toThrow(TypeError);
  });
});

describe('withSyntheticOrganizations: ensureOrganization determinism', () => {
  it('resolves to the id the resolver and the Factory route agree on', async () => {
    await expect(withSyntheticOrganizations(provider()).ensureOrganization('8f21ac')).resolves.toBe('user:8f21ac');
  });

  it('is the same across repeated calls on one wrapper', async () => {
    const wrapped = withSyntheticOrganizations(provider());
    const answers = await Promise.all([
      wrapped.ensureOrganization('8f21ac'),
      wrapped.ensureOrganization('8f21ac'),
      wrapped.ensureOrganization('8f21ac'),
    ]);
    expect(new Set(answers)).toEqual(new Set(['user:8f21ac']));
  });

  // The property that matters is not "twice in a row" but "in a process that has
  // never seen this user". Two wrappers built from two providers stand in for
  // two deploys: no shared closure, no shared state, same answer.
  it('is the same across independently constructed wrappers', async () => {
    const first = await withSyntheticOrganizations(provider()).ensureOrganization('8f21ac');
    const second = await withSyntheticOrganizations(provider(sso, session)).ensureOrganization('8f21ac');
    expect(first).toBe('user:8f21ac');
    expect(second).toBe(first);
  });

  it('agrees with resolveOrganizationId for a no-org identity', async () => {
    const wrapped = withSyntheticOrganizations(provider());
    expect(await wrapped.ensureOrganization('8f21ac')).toBe(resolveOrganizationId({ id: '8f21ac' }));
  });

  it('declines rather than bootstrap a shared organization for a blank id', async () => {
    await expect(withSyntheticOrganizations(provider()).ensureOrganization('')).resolves.toBeUndefined();
  });
});

describe('withSyntheticOrganizations: delegation to a real organizations provider', () => {
  it("returns the provider's own organization untouched", async () => {
    const organizations = withRealOrganizations(async () => 'org_01H8XYZ');
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.ensureOrganization('8f21ac')).resolves.toBe('org_01H8XYZ');
    expect(organizations.ensureOrganization).toHaveBeenCalledWith('8f21ac');
  });

  // `ensureOrganization` is documented as best-effort and may return undefined.
  // A host column is not nullable, so the wrapper supplies the answer the
  // delegate declined to give.
  it('supplies the synthetic id when the delegate declines', async () => {
    const organizations = withRealOrganizations(async () => undefined);
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.ensureOrganization('8f21ac')).resolves.toBe('user:8f21ac');
  });

  it('treats a blank answer from the delegate as no answer', async () => {
    const organizations = withRealOrganizations(async () => '   ');
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.ensureOrganization('8f21ac')).resolves.toBe('user:8f21ac');
  });

  it('falls back when the delegate throws, instead of failing the request', async () => {
    const organizations = withRealOrganizations(async () => {
      throw new Error('organization directory unavailable');
    });
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.ensureOrganization('8f21ac')).resolves.toBe('user:8f21ac');
  });

  it('coerces a numeric organization id from the delegate', async () => {
    const organizations = withRealOrganizations(async () => 42 as unknown as string);
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.ensureOrganization('8f21ac')).resolves.toBe('42');
  });
});

describe('withSyntheticOrganizations: isOrganizationAdmin', () => {
  it('makes a user the administrator of their own personal organization', async () => {
    const wrapped = withSyntheticOrganizations(provider());
    await expect(wrapped.isOrganizationAdmin('user:8f21ac', '8f21ac')).resolves.toBe(true);
  });

  it("makes nobody the administrator of somebody else's", async () => {
    const wrapped = withSyntheticOrganizations(provider());
    await expect(wrapped.isOrganizationAdmin('user:8f21ac', 'other')).resolves.toBe(false);
  });

  it('is false for a blank user id, which resolves to no organization at all', async () => {
    const wrapped = withSyntheticOrganizations(provider());
    await expect(wrapped.isOrganizationAdmin('user:', '')).resolves.toBe(false);
  });

  it('is false for an unknown organization when there is no delegate', async () => {
    const wrapped = withSyntheticOrganizations(provider());
    await expect(wrapped.isOrganizationAdmin('org_01H8XYZ', '8f21ac')).resolves.toBe(false);
  });

  it('delegates a real organization id', async () => {
    const organizations = withRealOrganizations(
      async () => 'org_01H8XYZ',
      async (organizationId, userId) => organizationId === 'org_01H8XYZ' && userId === '8f21ac',
    );
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.isOrganizationAdmin('org_01H8XYZ', '8f21ac')).resolves.toBe(true);
    await expect(wrapped.isOrganizationAdmin('org_01H8XYZ', 'other')).resolves.toBe(false);
  });

  // A provider that answers `true` for ids it has never seen would otherwise
  // hand out administrator rights over another user's private organization.
  it('never delegates a synthetic id, even to a provider that says yes to everything', async () => {
    const organizations = withRealOrganizations(
      async () => 'org_01H8XYZ',
      async () => true,
    );
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.isOrganizationAdmin('user:someone-else', '8f21ac')).resolves.toBe(false);
    expect(organizations.isOrganizationAdmin).not.toHaveBeenCalled();
  });

  it('reads a non-boolean answer from the delegate as no', async () => {
    const organizations = withRealOrganizations(
      async () => 'org_01H8XYZ',
      async () => 'yes' as unknown as boolean,
    );
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.isOrganizationAdmin('org_01H8XYZ', '8f21ac')).resolves.toBe(false);
  });

  it('fails closed when the delegate throws', async () => {
    const organizations = withRealOrganizations(
      async () => 'org_01H8XYZ',
      async () => {
        throw new Error('role lookup unavailable');
      },
    );
    const wrapped = withSyntheticOrganizations(provider(organizations));
    await expect(wrapped.isOrganizationAdmin('org_01H8XYZ', '8f21ac')).resolves.toBe(false);
  });
});

/**
 * Every guard in `./contract`, in both directions.
 *
 * The `false` half is not filler. A wrapper implemented by copying properties
 * onto a fresh object would pass the `true` half for a plain-object fake and
 * still lose a class provider's prototype methods, and a wrapper that answered
 * `true` unconditionally would pass it too.
 */
describe('withSyntheticOrganizations: capability preservation', () => {
  const guards = [
    ['isSSOProvider', isSSOProvider, sso],
    ['isSessionProvider', isSessionProvider, session],
    ['isUserProvider', isUserProvider, user],
    ['isCredentialsProvider', isCredentialsProvider, credentials],
    ['isAuthHttpHandler', isAuthHttpHandler, httpHandler],
    ['hasAuthInit', hasAuthInit, init],
  ] as const;

  it.each(guards)('keeps %s true through the wrapper', (_name, guard, capability) => {
    const bare = provider(capability);
    expect(guard(bare)).toBe(true);
    expect(guard(withSyntheticOrganizations(bare))).toBe(true);
  });

  it.each(guards)('does not invent %s', (_name, guard) => {
    const bare = provider();
    expect(guard(bare)).toBe(false);
    expect(guard(withSyntheticOrganizations(bare))).toBe(false);
  });

  it('keeps every capability at once', () => {
    const everything = withSyntheticOrganizations(provider(sso, session, user, credentials, httpHandler, init));
    for (const [, guard] of guards) expect(guard(everything)).toBe(true);
    expect(isOrganizationsProvider(everything)).toBe(true);
  });

  it('keeps the base contract callable', async () => {
    const authenticateToken = vi.fn(async () => ({ id: '8f21ac' }));
    const wrapped = withSyntheticOrganizations(provider({ authenticateToken }));
    await expect(wrapped.authenticateToken('token', {} as never)).resolves.toEqual({ id: '8f21ac' });
    expect(authenticateToken).toHaveBeenCalledWith('token', {});
  });

  it('keeps data properties, not only methods', () => {
    const wrapped = withSyntheticOrganizations(
      provider({ name: 'my-provider', protected: ['/api/*'], public: ['/health'] }),
    );
    expect(wrapped.name).toBe('my-provider');
    expect(wrapped.protected).toEqual(['/api/*']);
    expect(wrapped.public).toEqual(['/health']);
  });

  it('reports the two organization members under reflection, not only on read', () => {
    const wrapped = withSyntheticOrganizations(provider());
    expect('ensureOrganization' in wrapped).toBe(true);
    expect(Object.keys(wrapped)).toContain('isOrganizationAdmin');
  });

  it('picks up a capability the provider grows after wrapping', () => {
    const bare = provider();
    const wrapped = withSyntheticOrganizations(bare);
    expect(isSSOProvider(wrapped)).toBe(false);
    Object.assign(bare, sso);
    expect(isSSOProvider(wrapped)).toBe(true);
  });

  it('forwards writes to the provider rather than shadowing them', () => {
    const bare = provider();
    const wrapped = withSyntheticOrganizations(bare);
    (wrapped as { name?: string }).name = 'renamed';
    expect((bare as { name?: string }).name).toBe('renamed');
  });

  it('refuses to have its organization members reassigned through the wrapper', () => {
    const wrapped = withSyntheticOrganizations(provider());
    expect(() => {
      (wrapped as { ensureOrganization: unknown }).ensureOrganization = async () => 'hijacked';
    }).toThrow(TypeError);
  });
});

/**
 * Class providers, where `this` is the thing under test.
 *
 * `IMastraAuthProvider` exists because provider classes carry `#private` and
 * `protected` members. A `#private` field is keyed on the object it was
 * installed on, so a method called with `this` set to a wrapper throws from
 * inside the provider, in a stack that names none of this package's files. This
 * is the test that would have caught it.
 */
describe('withSyntheticOrganizations: class providers', () => {
  class PrivateStateProvider {
    #calls = 0;
    name = 'class-provider';

    async authenticateToken(token: string): Promise<{ id: string } | null> {
      this.#calls += 1;
      return token === '' ? null : { id: `8f21ac-${this.#calls}` };
    }

    async authorizeUser(): Promise<boolean> {
      return true;
    }

    getLoginUrl(): string {
      return `https://idp.test/authorize?seen=${this.#calls}`;
    }

    async handleCallback(): Promise<{ user: object }> {
      return { user: {} };
    }

    calls(): number {
      return this.#calls;
    }
  }

  it('calls prototype methods with the provider as `this`, so private fields work', async () => {
    const instance = new PrivateStateProvider();
    const wrapped = withSyntheticOrganizations(instance as unknown as IMastraAuthProvider);

    await expect((wrapped as unknown as PrivateStateProvider).authenticateToken('token')).resolves.toEqual({
      id: '8f21ac-1',
    });
    expect((wrapped as unknown as PrivateStateProvider).getLoginUrl()).toBe('https://idp.test/authorize?seen=1');
    // The state landed on the provider, not on a shadow copy.
    expect(instance.calls()).toBe(1);
  });

  it('keeps prototype methods visible to the structural guards', () => {
    const wrapped = withSyntheticOrganizations(new PrivateStateProvider() as unknown as IMastraAuthProvider);
    expect(isSSOProvider(wrapped)).toBe(true);
    expect(isOrganizationsProvider(wrapped)).toBe(true);
  });

  it('keeps instanceof working', () => {
    const wrapped = withSyntheticOrganizations(new PrivateStateProvider() as unknown as IMastraAuthProvider);
    expect(wrapped).toBeInstanceOf(PrivateStateProvider);
  });
});

describe('withSyntheticOrganizations: wrapping edge cases', () => {
  it('re-wraps the original provider instead of stacking wrappers', async () => {
    const bare = provider();
    const once = withSyntheticOrganizations(bare, { prefix: 'first/' });
    const twice = withSyntheticOrganizations(once, { prefix: 'second/' });
    await expect(twice.ensureOrganization('8f21ac')).resolves.toBe('second/8f21ac');
  });

  it('is idempotent when wrapped twice with the same options', async () => {
    const bare = provider();
    const twice = withSyntheticOrganizations(withSyntheticOrganizations(bare));
    await expect(twice.ensureOrganization('8f21ac')).resolves.toBe('user:8f21ac');
    expect(isOrganizationsProvider(twice)).toBe(true);
  });

  it('keeps delegating after a re-wrap', async () => {
    const organizations = withRealOrganizations(async () => 'org_01H8XYZ');
    const twice = withSyntheticOrganizations(withSyntheticOrganizations(provider(organizations)));
    await expect(twice.ensureOrganization('8f21ac')).resolves.toBe('org_01H8XYZ');
    expect(organizations.ensureOrganization).toHaveBeenCalledTimes(1);
  });

  // A frozen provider cannot be wrapped correctly by anything: a proxy may not
  // report a value other than the pinned one. Failing here beats failing at the
  // first property read with a message about proxy invariants.
  it('refuses a provider that pins an organization member', () => {
    const bare = provider();
    Object.defineProperty(bare, 'ensureOrganization', {
      value: async () => 'pinned',
      configurable: false,
      writable: false,
    });
    expect(() => withSyntheticOrganizations(bare)).toThrow(/non-configurable own property/);
  });
});
