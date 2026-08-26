/**
 * The capability descriptor and its derivation.
 *
 * Every fake below is a plain object. That is not a shortcut: the seven guards
 * in the contract are structural rather than `instanceof`, so a plain object
 * with the right methods is exactly as much of a provider as a real class is,
 * and testing through plain objects tests the thing the guards actually see.
 */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_CREDENTIALS_BASE_PATH,
  DEFAULT_PROVIDER_HINT,
  toAuthDescriptor,
  type AuthDescriptor,
} from '../capabilities.js';
import { isSessionProvider, type IMastraAuthProvider } from '../contract.js';

/** The base contract, and nothing else: a bearer-token validator. */
const bearerOnly = {
  name: 'fake',
  authenticateToken: async () => null,
  authorizeUser: async () => true,
};

function provider(...capabilities: object[]): IMastraAuthProvider {
  return Object.assign({}, bearerOnly, ...capabilities) as IMastraAuthProvider;
}

/** The three members `ISSOProvider` requires, which is what `isSSOProvider` tests. */
const sso = {
  getLoginUrl: () => 'https://idp.test/authorize',
  handleCallback: async () => ({ user: {} }),
  getLoginButtonConfig: () => ({ label: 'Sign in' }),
};

/** The two members `ICredentialsProvider` requires. */
const credentials = {
  signIn: async () => ({ user: {} }),
  signUp: async () => ({ user: {} }),
};

/** `isOrganizationsProvider` tests for both of these. */
const organizations = {
  ensureOrganization: async () => 'org-1',
  isOrganizationAdmin: async () => false,
};

/**
 * Some of `ISessionProvider`, deliberately not all of it.
 *
 * `isSessionProvider` tests all seven required members, so this composition
 * does NOT satisfy the guard - and that is the point. `features.refresh` and
 * `features.sessionRevocation` are read off their own methods rather than off
 * the guard, so a provider assembled this way still reports the two features it
 * actually has. Compose with {@link revocable} and {@link refreshable} to vary
 * them one at a time; add {@link sessionRemainder} to satisfy the guard.
 */
const partialSession = {
  createSession: async () => ({}),
  validateSession: async () => null,
};

const revocable = { destroySession: async () => {} };
const refreshable = { refreshSession: async () => null };

/** The rest of `ISessionProvider`, so `partialSession` plus these satisfies the guard. */
const sessionRemainder = {
  getSessionIdFromRequest: () => null,
  getSessionHeaders: () => ({}),
  getClearSessionHeaders: () => ({}),
};

/** All seven members `ISessionProvider` requires. */
const fullSession = { ...partialSession, ...revocable, ...refreshable, ...sessionRemainder };

/** `isAuthHttpHandler` tests for this one. */
const httpHandler = { handleAuthRequest: async () => new Response() };

describe('signIn.kind', () => {
  it('is none for a provider that cannot sign anyone in from a browser', () => {
    expect(toAuthDescriptor(provider()).signIn.kind).toBe('none');
  });

  it('is hosted for an SSO provider', () => {
    expect(toAuthDescriptor(provider(sso)).signIn.kind).toBe('hosted');
  });

  it('is credentials for a credentials provider', () => {
    expect(toAuthDescriptor(provider(credentials)).signIn.kind).toBe('credentials');
  });

  it('is both when the provider offers each', () => {
    expect(toAuthDescriptor(provider(sso, credentials)).signIn.kind).toBe('both');
  });

  it('stays none for a bearer validator that has sessions and organizations', () => {
    // The distinction the type exists to make: plenty of capability, no way for
    // a browser to start a session.
    expect(toAuthDescriptor(provider(partialSession, organizations)).signIn.kind).toBe('none');
  });

  it('needs both SSO methods, not one', () => {
    expect(toAuthDescriptor(provider({ getLoginUrl: () => 'https://idp.test' })).signIn.kind).toBe('none');
    expect(toAuthDescriptor(provider({ handleCallback: async () => ({}) })).signIn.kind).toBe('none');
  });
});

describe('signIn.providerHint', () => {
  it('defaults to generic, which is correct for any provider', () => {
    expect(toAuthDescriptor(provider(sso)).signIn.providerHint).toBe(DEFAULT_PROVIDER_HINT);
    expect(DEFAULT_PROVIDER_HINT).toBe('generic');
  });

  it('takes a host override', () => {
    expect(toAuthDescriptor(provider(sso), { providerHint: 'sso' }).signIn.providerHint).toBe('sso');
  });

  it('is always present on a descriptor this package produces', () => {
    for (const p of [provider(), provider(sso), provider(credentials), provider(sso, credentials)]) {
      expect(toAuthDescriptor(p).signIn.providerHint).toBeDefined();
    }
  });

  it('is never derived from the provider name', () => {
    const named = provider(sso, { name: 'acme-idp' });
    expect(JSON.stringify(toAuthDescriptor(named))).not.toContain('acme-idp');
  });
});

describe('signIn.label', () => {
  it('is absent unless the host supplies one, because a machine name is not display copy', () => {
    expect(toAuthDescriptor(provider(sso, { name: 'acme-idp' })).signIn.label).toBeUndefined();
  });

  it('takes a host override', () => {
    expect(toAuthDescriptor(provider(sso), { label: 'Continue with Acme' }).signIn.label).toBe('Continue with Acme');
  });
});

describe('signIn.signUpEnabled', () => {
  it('is absent when the provider has no credentials sign-in', () => {
    expect(toAuthDescriptor(provider()).signIn.signUpEnabled).toBeUndefined();
    expect(toAuthDescriptor(provider(sso)).signIn.signUpEnabled).toBeUndefined();
  });

  it('is true when the provider does not implement isSignUpEnabled, matching the documented default', () => {
    expect(toAuthDescriptor(provider(credentials)).signIn.signUpEnabled).toBe(true);
  });

  it('follows the provider when it does implement it', () => {
    expect(toAuthDescriptor(provider(credentials, { isSignUpEnabled: () => true })).signIn.signUpEnabled).toBe(true);
    expect(toAuthDescriptor(provider(credentials, { isSignUpEnabled: () => false })).signIn.signUpEnabled).toBe(false);
  });

  it('fails closed when the provider throws, because hiding a link beats showing a forbidden one', () => {
    const thrower = provider(credentials, {
      isSignUpEnabled: () => {
        throw new Error('provider is unhappy');
      },
    });
    expect(() => toAuthDescriptor(thrower)).not.toThrow();
    expect(toAuthDescriptor(thrower).signIn.signUpEnabled).toBe(false);
  });

  it('is positive polarity: true means sign-up is available', () => {
    // The wire field the SPA reads today is `signUpDisabled`, the opposite way
    // round. Both ride in one payload for a release, so this assertion is the
    // record of which way this one points.
    const disabled = toAuthDescriptor(provider(credentials, { isSignUpEnabled: () => false }));
    expect(disabled.signIn.signUpEnabled).toBe(false);
    expect(disabled.signIn).not.toHaveProperty('signUpDisabled');
  });
});

describe('signIn.credentialsBasePath', () => {
  it('is absent when the provider has no credentials sign-in', () => {
    expect(toAuthDescriptor(provider(sso)).signIn.credentialsBasePath).toBeUndefined();
  });

  it('defaults to where the Factory mounts its auth routes', () => {
    expect(toAuthDescriptor(provider(credentials)).signIn.credentialsBasePath).toBe(DEFAULT_CREDENTIALS_BASE_PATH);
    expect(DEFAULT_CREDENTIALS_BASE_PATH).toBe('/auth');
  });

  it('takes a host override, because it is a host routing fact', () => {
    expect(
      toAuthDescriptor(provider(credentials), { credentialsBasePath: '/api/auth' }).signIn.credentialsBasePath,
    ).toBe('/api/auth');
  });

  it('ignores the override when there is no credentials sign-in', () => {
    expect(
      toAuthDescriptor(provider(sso), { credentialsBasePath: '/api/auth' }).signIn.credentialsBasePath,
    ).toBeUndefined();
  });
});

describe('features.organizations', () => {
  it('follows isOrganizationsProvider', () => {
    expect(toAuthDescriptor(provider()).features.organizations).toBe(false);
    expect(toAuthDescriptor(provider(organizations)).features.organizations).toBe(true);
  });

  it('needs both organization methods', () => {
    expect(toAuthDescriptor(provider({ ensureOrganization: async () => 'org' })).features.organizations).toBe(false);
  });
});

describe('features.refresh and features.sessionRevocation', () => {
  it('are both false for a provider with no session capability', () => {
    const { features } = toAuthDescriptor(provider());
    expect(features.refresh).toBe(false);
    expect(features.sessionRevocation).toBe(false);
  });

  it('are both false for a provider that satisfies the guard but lacks the methods', () => {
    // The guard tests two of `ISessionProvider`'s seven members, so passing it
    // is not evidence that `destroySession` exists. A UI offering "sign out
    // everywhere" on the strength of the guard would call a missing method.
    const { features } = toAuthDescriptor(provider(partialSession));
    expect(features.refresh).toBe(false);
    expect(features.sessionRevocation).toBe(false);
  });

  it('are independent of each other', () => {
    expect(toAuthDescriptor(provider(partialSession, refreshable)).features).toMatchObject({
      refresh: true,
      sessionRevocation: false,
    });
    expect(toAuthDescriptor(provider(partialSession, revocable)).features).toMatchObject({
      refresh: false,
      sessionRevocation: true,
    });
  });

  it('are both true for a full session provider', () => {
    const { features } = toAuthDescriptor(provider(fullSession));
    expect(features.refresh).toBe(true);
    expect(features.sessionRevocation).toBe(true);
  });

  /**
   * Read off the methods, not off `isSessionProvider`.
   *
   * The guard requires all seven members, so gating these two on it would make
   * both exactly equal to the guard - and would report no session features at
   * all for a provider carrying six of the seven, including the ones it has.
   * A UI branches on each of these to draw a button, so each answers for the
   * method that button calls.
   */
  it('are read off the methods rather than off the session guard', () => {
    const halfway = provider(revocable, refreshable);

    expect(isSessionProvider(halfway)).toBe(false);
    expect(toAuthDescriptor(halfway).features).toMatchObject({
      refresh: true,
      sessionRevocation: true,
    });
  });

  it('are false when the methods are absent, guard or no guard', () => {
    expect(toAuthDescriptor(provider(partialSession)).features).toMatchObject({
      refresh: false,
      sessionRevocation: false,
    });
  });
});

describe('features.logout', () => {
  it('is false only when there is nothing to sign out of', () => {
    expect(toAuthDescriptor(provider()).features.logout).toBe(false);
  });

  it.each([
    ['a hosted sign-in', sso],
    ['a credentials sign-in', credentials],
    ['a server-side session', fullSession],
    ['destroySession alone, without the rest of the session interface', revocable],
    ['auth routes the provider serves itself', httpHandler],
  ])('is true given %s', (_label, capability) => {
    expect(toAuthDescriptor(provider(capability)).features.logout).toBe(true);
  });
});

describe('the descriptor as a whole', () => {
  it('describes a fully-capable provider', () => {
    const full = provider(sso, credentials, organizations, partialSession, refreshable, revocable, httpHandler, {
      isSignUpEnabled: () => false,
    });
    expect(toAuthDescriptor(full, { label: 'Continue with Acme', providerHint: 'sso' })).toEqual({
      signIn: {
        kind: 'both',
        label: 'Continue with Acme',
        providerHint: 'sso',
        signUpEnabled: false,
        credentialsBasePath: '/auth',
      },
      features: { logout: true, organizations: true, refresh: true, sessionRevocation: true },
    } satisfies AuthDescriptor);
  });

  it('describes a bearer-only provider', () => {
    expect(toAuthDescriptor(provider())).toEqual({
      signIn: { kind: 'none', providerHint: 'generic' },
      features: { logout: false, organizations: false, refresh: false, sessionRevocation: false },
    } satisfies AuthDescriptor);
  });

  it('holds the declared scope and nothing more', () => {
    // The scope boundary as an assertion: no roles, no permissions, no licence
    // gate, no telemetry. If one of those arrives, it arrives in a diff that
    // has to change this line.
    const descriptor = toAuthDescriptor(provider(sso, credentials, organizations, partialSession));
    expect(Object.keys(descriptor).sort()).toEqual(['features', 'signIn']);
    expect(Object.keys(descriptor.features).sort()).toEqual([
      'logout',
      'organizations',
      'refresh',
      'sessionRevocation',
    ]);
    expect(Object.keys(descriptor.signIn).sort()).toEqual([
      'credentialsBasePath',
      'kind',
      'providerHint',
      'signUpEnabled',
    ]);
  });

  it('survives a JSON round trip, which is how it reaches a browser', () => {
    const descriptor = toAuthDescriptor(provider(sso), { label: 'Sign in' });
    expect(JSON.parse(JSON.stringify(descriptor))).toEqual(descriptor);
  });

  it('is pure: the same provider gives the same answer', () => {
    const p = provider(sso, credentials);
    expect(toAuthDescriptor(p)).toEqual(toAuthDescriptor(p));
  });

  it('inspects the provider without calling into it', () => {
    // Only `isSignUpEnabled` is ever invoked. Anything else being called would
    // turn a page render into a network round trip, or worse.
    const exploding = provider(
      {
        getLoginUrl: () => {
          throw new Error('called');
        },
        handleCallback: () => {
          throw new Error('called');
        },
        getLoginButtonConfig: () => {
          throw new Error('called');
        },
      },
      {
        signIn: () => {
          throw new Error('called');
        },
        signUp: () => {
          throw new Error('called');
        },
      },
      {
        ensureOrganization: () => {
          throw new Error('called');
        },
        isOrganizationAdmin: () => {
          throw new Error('called');
        },
      },
      {
        createSession: () => {
          throw new Error('called');
        },
        validateSession: () => {
          throw new Error('called');
        },
        getSessionIdFromRequest: () => {
          throw new Error('called');
        },
        getSessionHeaders: () => {
          throw new Error('called');
        },
        getClearSessionHeaders: () => {
          throw new Error('called');
        },
      },
      {
        destroySession: () => {
          throw new Error('called');
        },
        refreshSession: () => {
          throw new Error('called');
        },
      },
      {
        handleAuthRequest: () => {
          throw new Error('called');
        },
      },
      {
        authenticateToken: () => {
          throw new Error('called');
        },
      },
    );
    expect(() => toAuthDescriptor(exploding)).not.toThrow();
    expect(toAuthDescriptor(exploding).signIn.kind).toBe('both');
  });
});

describe('signUpEnabled fails closed', () => {
  // The field drives whether the SPA renders a sign-up link, so a wrong `true`
  // shows sign-up on a deployment that turned it off, and nothing looks broken
  // to anyone. `isSignUpEnabled` is declared synchronous, but nothing stops a
  // provider writing `async isSignUpEnabled()`, and an async method returns a
  // Promise - which is truthy.
  const credentialsProvider = (isSignUpEnabled: unknown) =>
    ({ signIn: () => {}, signUp: () => {}, isSignUpEnabled }) as never;

  it('is true when the method is absent, which is the documented default', () => {
    expect(toAuthDescriptor({ signIn: () => {}, signUp: () => {} } as never).signIn.signUpEnabled).toBe(true);
  });

  it('is true only for a literal true', () => {
    expect(toAuthDescriptor(credentialsProvider(() => true)).signIn.signUpEnabled).toBe(true);
  });

  it.each([
    ['undefined, same as being absent', () => undefined],
    ['null, which reads as "I do not implement this" rather than "disabled"', () => null],
  ])('is true when the method returns %s', (_label, isSignUpEnabled) => {
    // The absence of an answer is not the same as a wrong answer. A provider
    // that means "sign-up is off" returns `false`; `null` and `undefined` are
    // what an optional method that is not really implemented gives back, and the
    // contract's documented default for that is `true`. Everything else has to
    // be exactly `true`.
    expect(toAuthDescriptor(credentialsProvider(isSignUpEnabled)).signIn.signUpEnabled).toBe(true);
  });

  it.each([
    ['a resolved Promise, which an async method returns', () => Promise.resolve(true)],
    ['a pending Promise', () => new Promise(() => {})],
    ['a truthy string', () => 'yes'],
    ['a truthy number', () => 1],
    ['a truthy object', () => ({})],
    ['false', () => false],
    [
      'a throw',
      () => {
        throw new Error('provider exploded');
      },
    ],
  ])('is false for %s', (_label, isSignUpEnabled) => {
    expect(toAuthDescriptor(credentialsProvider(isSignUpEnabled)).signIn.signUpEnabled).toBe(false);
  });

  it('never lets a Promise leak into the descriptor', () => {
    const descriptor = toAuthDescriptor(credentialsProvider(() => Promise.resolve(true)));
    expect(typeof descriptor.signIn.signUpEnabled).toBe('boolean');
  });

  it('does not leave a rejected Promise unhandled', async () => {
    // The descriptor judges a Promise `false` rather than awaiting it, so a
    // rejecting `async isSignUpEnabled()` would otherwise leave an unhandled
    // rejection behind - which Node makes fatal. This function is documented as
    // never throwing, and taking the process down a tick later would be a worse
    // version of throwing.
    const descriptor = toAuthDescriptor(credentialsProvider(() => Promise.reject(new Error('lookup failed'))));
    expect(descriptor.signIn.signUpEnabled).toBe(false);
    // If the rejection were unhandled, this turn of the loop is where the run
    // would fail.
    await new Promise(resolve => setTimeout(resolve, 10));
  });

  it('does not call a thenable twice while deciding', () => {
    // The Promise branch returns early, so the value is read once.
    let calls = 0;
    const descriptor = toAuthDescriptor(
      credentialsProvider(() => {
        calls += 1;
        return Promise.resolve(true);
      }),
    );
    expect(descriptor.signIn.signUpEnabled).toBe(false);
    expect(calls).toBe(1);
  });
});
