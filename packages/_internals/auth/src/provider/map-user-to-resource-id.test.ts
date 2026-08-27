/**
 * `mapUserToResourceId` has to be implementable the way the type says it is.
 *
 * `MastraAuthProvider` declares it as an *optional method* — `IMastraAuthProvider`
 * types it with method syntax, and every consumer duck-types it with
 * `typeof provider.mapUserToResourceId === 'function'`. The obvious way to satisfy
 * that declaration is a prototype method on the subclass. Until this fix the base
 * constructor ran `this.mapUserToResourceId = options?.mapUserToResourceId`
 * unconditionally, so a provider that did not forward the option — which is every
 * provider in this repo, they pass only `name` — got an own property holding
 * `undefined` that shadowed its own prototype method. The method was unreachable
 * and the duck-type read false, with no error anywhere.
 *
 * The three cases below are the whole contract, and they have to hold together:
 * the prototype method must survive, a supplied option must still beat it (that is
 * the documented override), and a provider with neither must still report the
 * method as absent so the optional-capability checks keep skipping honestly.
 */
import { describe, expect, it } from 'vitest';

import type { MastraAuthRequest } from '../types';
import { CompositeAuth, MastraAuthProvider } from './index';
import type { MastraAuthProviderOptions } from './index';

interface TestUser {
  id: string;
}

const USER: TestUser = { id: 'user-1' };

/** Forwards only `name`, exactly as the eleven real providers do. */
class PrototypeProvider extends MastraAuthProvider<TestUser> {
  constructor(options?: MastraAuthProviderOptions<TestUser>) {
    super({ name: options?.name ?? 'prototype-provider' });
    this.registerOptions(options);
  }

  async authenticateToken(_token: string, _request: MastraAuthRequest): Promise<TestUser | null> {
    return USER;
  }

  async authorizeUser(_user: TestUser, _request: MastraAuthRequest): Promise<boolean> {
    return true;
  }

  mapUserToResourceId(user: TestUser): string {
    return `prototype:${user.id}`;
  }
}

/** The same provider without the method, to prove absence still reads as absence. */
class BareProvider extends MastraAuthProvider<TestUser> {
  constructor(options?: MastraAuthProviderOptions<TestUser>) {
    super({ name: options?.name ?? 'bare-provider' });
    this.registerOptions(options);
  }

  async authenticateToken(_token: string, _request: MastraAuthRequest): Promise<TestUser | null> {
    return USER;
  }

  async authorizeUser(_user: TestUser, _request: MastraAuthRequest): Promise<boolean> {
    return true;
  }
}

describe('MastraAuthProvider: mapUserToResourceId is implementable on the prototype', () => {
  it('keeps a prototype method reachable when no option is supplied', () => {
    const provider = new PrototypeProvider();

    // The duck-type every consumer uses — `packages/server`'s auth helpers and the
    // conformance suite's skip condition both spell exactly this.
    expect(typeof provider.mapUserToResourceId).toBe('function');
    expect(provider.mapUserToResourceId?.(USER)).toBe('prototype:user-1');

    // No own property at all: the prototype is the only place it lives.
    expect(Object.prototype.hasOwnProperty.call(provider, 'mapUserToResourceId')).toBe(false);
  });

  it('lets a supplied option win over the prototype method', () => {
    const provider = new PrototypeProvider({
      mapUserToResourceId: user => `option:${user.id}`,
    });

    expect(typeof provider.mapUserToResourceId).toBe('function');
    expect(provider.mapUserToResourceId?.(USER)).toBe('option:user-1');
  });

  it('leaves the method absent when there is neither a prototype method nor an option', () => {
    const provider = new BareProvider();

    // Absent, so the optional-capability checks that key on this keep skipping —
    // and skip honestly, because this provider really does not implement it.
    expect(typeof provider.mapUserToResourceId).toBe('undefined');
    expect(provider.mapUserToResourceId).toBeUndefined();
  });

  it('still installs a supplied option on a provider with no prototype method', () => {
    const provider = new BareProvider({
      mapUserToResourceId: user => `option:${user.id}`,
    });

    expect(typeof provider.mapUserToResourceId).toBe('function');
    expect(provider.mapUserToResourceId?.(USER)).toBe('option:user-1');
  });

  it('does not resurrect the method on a CompositeAuth whose members lack it', () => {
    // CompositeAuth installs its own delegating implementation only when some inner
    // provider has one. It used to rely on the base assigning an own `undefined`;
    // it must stay absent now that the base assigns nothing.
    const composite = new CompositeAuth([new BareProvider() as any]);

    expect(typeof composite.mapUserToResourceId).toBe('undefined');
  });

  it('delegates through CompositeAuth to an inner prototype implementation', async () => {
    const inner = new PrototypeProvider();
    const composite = new CompositeAuth([inner as any]);

    // Reachable at all only because the inner provider's prototype method survives
    // its own constructor — this is the composite-level consequence of the fix.
    expect(typeof composite.mapUserToResourceId).toBe('function');

    const payload = await composite.authenticateToken('any-token', new Request('http://localhost/'));
    expect(composite.mapUserToResourceId?.(payload)).toBe('prototype:user-1');
  });
});
