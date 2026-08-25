/**
 * The composable fake providers.
 *
 * Two things are being tested here, and only one of them is "do the fakes work".
 *
 * The first is the claim `src/testing/index.ts` makes about composition: that
 * every one of the 64 subsets of six mixins satisfies exactly the guards it
 * should, in any order of application. That is not a claim you can spot-check -
 * a mixin that quietly installed a neighbour's method would pass any three
 * hand-written cases - so the subsets are enumerated rather than written out,
 * and every permutation of every subset is applied.
 *
 * The second is the claim the conformance suite depends on: that
 * `fakeViolating(obligation)` fails that obligation *and no other*. A broken
 * fake that failed two obligations would make a conformance check go red for the
 * wrong reason and nobody would notice, because red is what the test expects.
 * So the four obligations are written as four predicates and run as a matrix:
 * every fake against every obligation.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { toAuthDescriptor } from '../capabilities.js';
import {
  hasAuthInit,
  isAuthHttpHandler,
  isCredentialsProvider,
  isOrganizationsProvider,
  isSessionProvider,
  isSSOProvider,
  isUserProvider,
} from '../contract.js';
import type { IMastraAuthProvider } from '../contract.js';
import { toAuthIdentity } from '../identity.js';
import { decodeState, encodeState, OAUTH_STATE_DELIMITER, parseStateId } from '../oauth-state.js';
import {
  AUTH_OBLIGATION_SUMMARY,
  AUTH_OBLIGATIONS,
  createCallLog,
  FAKE_COOKIE_NAME,
  FAKE_STATE_DELIMITER,
  FAKE_TOKEN,
  FAKE_TOKEN_EXPIRES_AT,
  fakeProvider,
  fakeViolating,
  fullyCapableFake,
  withCredentials,
  withHttpHandler,
  withInit,
  withOrganizations,
  withSession,
  withSSO,
} from '../testing/index.js';
import type { AuthObligation, FakeProvider, FullyCapableFake } from '../testing/index.js';

// ============================================================================
// Helpers
// ============================================================================

/** A request carrying whatever headers a case needs. */
function request(headers: Record<string, string> = {}): Request {
  return new Request('https://factory.test/api/agents', { headers });
}

/** A request carrying `token` as a cookie, under `name`. */
function withCookie(token: string, name = FAKE_COOKIE_NAME): Request {
  return request({ cookie: `${name}=${token}` });
}

/** Every subset of `items`, including the empty one. 2^n of them, in a stable order. */
function subsets<T>(items: readonly T[]): T[][] {
  return items.reduce<T[][]>((acc, item) => acc.concat(acc.map(subset => [...subset, item])), [[]]);
}

/** Every ordering of `items`. n! of them. */
function permutations<T>(items: readonly T[]): T[][] {
  if (items.length <= 1) return [[...items]];
  return items.flatMap((item, index) =>
    permutations([...items.slice(0, index), ...items.slice(index + 1)]).map(rest => [item, ...rest]),
  );
}

// ============================================================================
// The mixin table
// ============================================================================

interface MixinUnderTest {
  readonly name: string;
  readonly apply: (provider: FakeProvider) => FakeProvider;
  readonly guard: (value: unknown) => boolean;
}

/**
 * The six mixins, each paired with the guard it is supposed to satisfy.
 *
 * `isUserProvider` is deliberately absent and is asserted `false` everywhere
 * below: no mixin installs `getCurrentUser`, so a subset that started passing
 * that guard would mean a mixin had grown a method that is not its own.
 */
const MIXINS: readonly MixinUnderTest[] = [
  { name: 'withSSO', apply: provider => withSSO(provider), guard: isSSOProvider },
  { name: 'withCredentials', apply: provider => withCredentials(provider), guard: isCredentialsProvider },
  { name: 'withHttpHandler', apply: provider => withHttpHandler(provider), guard: isAuthHttpHandler },
  { name: 'withOrganizations', apply: provider => withOrganizations(provider), guard: isOrganizationsProvider },
  { name: 'withSession', apply: provider => withSession(provider), guard: isSessionProvider },
  { name: 'withInit', apply: provider => withInit(provider), guard: hasAuthInit },
];

const ALL_SUBSETS = subsets(MIXINS);

function compose(mixins: readonly MixinUnderTest[]): FakeProvider {
  return mixins.reduce<FakeProvider>((provider, mixin) => mixin.apply(provider), fakeProvider());
}

function label(mixins: readonly MixinUnderTest[]): string {
  return mixins.length === 0 ? 'fakeProvider()' : mixins.map(mixin => mixin.name).join(' + ');
}

// ============================================================================
// The obligations, as predicates
// ============================================================================

/**
 * One predicate per obligation: does this provider meet it?
 *
 * These are deliberately written the way `src/conformance/` will have to write
 * them - through the kit's own public functions, against a provider it knows
 * nothing about - so that a fake passing here is evidence the real suite will
 * pass too.
 */
const MEETS: Readonly<Record<AuthObligation, (provider: FullyCapableFake) => Promise<boolean>>> = {
  async flatId(provider) {
    const identity = toAuthIdentity(await provider.authenticateToken(FAKE_TOKEN, request()));
    return identity !== null && identity.id.length > 0;
  },

  async cookieAuth(provider) {
    // The obligation exactly: an empty bearer token means "this is a browser
    // navigation, read the cookie".
    return (await provider.authenticateToken('', withCookie(FAKE_TOKEN))) !== null;
  },

  async stateCodec(provider) {
    const state = encodeState('/workspaces/42', 'state-id');
    const loginUrl = await provider.getLoginUrl('https://factory.test/auth/callback', state);
    const echoed = new URL(loginUrl).searchParams.get('state') ?? '';
    return parseStateId(echoed) === 'state-id' && decodeState(echoed).returnTo === '/workspaces/42';
  },

  async organizationId(provider) {
    const identity = toAuthIdentity(await provider.authenticateToken(FAKE_TOKEN, request()));
    const fromIdentity = identity?.organizationId;
    if (fromIdentity !== undefined) return true;
    return (await provider.ensureOrganization(identity?.id ?? 'fake-user')) !== undefined;
  },
};

// ============================================================================
// Composition
// ============================================================================

describe('composition', () => {
  it('the base fake satisfies the contract and no capability', () => {
    const provider = fakeProvider();

    // Assignable to the position a host actually holds a provider in.
    const asProvider: IMastraAuthProvider = provider;
    expect(typeof asProvider.authenticateToken).toBe('function');
    expect(typeof asProvider.authorizeUser).toBe('function');

    expect(isSSOProvider(provider)).toBe(false);
    expect(isCredentialsProvider(provider)).toBe(false);
    expect(isAuthHttpHandler(provider)).toBe(false);
    expect(isOrganizationsProvider(provider)).toBe(false);
    expect(isSessionProvider(provider)).toBe(false);
    expect(hasAuthInit(provider)).toBe(false);
    expect(isUserProvider(provider)).toBe(false);
  });

  it('enumerates every subset of the six mixins', () => {
    expect(ALL_SUBSETS).toHaveLength(2 ** MIXINS.length);
    expect(new Set(ALL_SUBSETS.map(label)).size).toBe(ALL_SUBSETS.length);
  });

  it.each(ALL_SUBSETS.map(mixins => [label(mixins), mixins] as const))(
    'satisfies exactly the guards for %s',
    (_name, mixins) => {
      const provider = compose(mixins);
      const applied = new Set(mixins.map(mixin => mixin.name));

      for (const mixin of MIXINS) {
        expect(mixin.guard(provider), `${mixin.name}'s guard on ${label(mixins)}`).toBe(applied.has(mixin.name));
      }

      // No mixin installs `getCurrentUser`, so this guard is false for all 64.
      expect(isUserProvider(provider)).toBe(false);
    },
  );

  it('gives the same guards for every order the mixins are applied in', () => {
    const failures: string[] = [];
    let composed = 0;

    for (const subset of ALL_SUBSETS) {
      const applied = new Set(subset.map(mixin => mixin.name));
      for (const ordering of permutations(subset)) {
        composed += 1;
        const provider = compose(ordering);
        for (const mixin of MIXINS) {
          if (mixin.guard(provider) !== applied.has(mixin.name)) {
            failures.push(`${label(ordering)}: ${mixin.guard.name} disagreed`);
          }
        }
      }
    }

    // sum over k of C(6,k) * k! = 1957 distinct orderings.
    expect(composed).toBe(1957);
    expect(failures).toEqual([]);
  });

  it('never mutates the provider it was handed', () => {
    const base = fakeProvider();
    const sso = withSSO(base);
    const both = withOrganizations(sso);

    expect(isSSOProvider(base)).toBe(false);
    expect(isOrganizationsProvider(base)).toBe(false);
    expect(isOrganizationsProvider(sso)).toBe(false);
    expect(isSSOProvider(both)).toBe(true);
    expect(isOrganizationsProvider(both)).toBe(true);
    expect(both).not.toBe(sso);
  });

  it('survives being spread, because nothing on a fake is a getter or this-bound', async () => {
    const provider = { ...fullyCapableFake() };

    expect(isSSOProvider(provider)).toBe(true);
    expect(isSessionProvider(provider)).toBe(true);
    expect(await provider.authenticateToken(FAKE_TOKEN, request())).not.toBeNull();

    const { authenticateToken } = provider;
    expect(await authenticateToken(FAKE_TOKEN, request())).not.toBeNull();
  });

  it('derives the descriptor a UI would render for a partly-capable fake', () => {
    const ssoOnly = toAuthDescriptor(withSSO(fakeProvider()));
    expect(ssoOnly.signIn.kind).toBe('hosted');
    expect(ssoOnly.features.organizations).toBe(false);
    expect(ssoOnly.features.sessionRevocation).toBe(false);

    const everything = toAuthDescriptor(fullyCapableFake());
    expect(everything.signIn.kind).toBe('both');
    expect(everything.features).toEqual({
      logout: true,
      organizations: true,
      refresh: true,
      sessionRevocation: true,
    });

    // The base fake is a working provider that cannot sign anyone in.
    expect(toAuthDescriptor(fakeProvider()).signIn.kind).toBe('none');
  });

  it('answers a descriptor question without calling the provider', () => {
    const provider = withSSO(fakeProvider());
    toAuthDescriptor(provider);
    expect(provider.calls.called()).toBe(false);
  });
});

// ============================================================================
// The base contract
// ============================================================================

describe('fakeProvider', () => {
  it('authenticates a known bearer token and rejects an unknown one', async () => {
    const provider = fakeProvider({ token: 'tok-1', user: { id: 'u-1' } });

    expect(toAuthIdentity(await provider.authenticateToken('tok-1', request()))?.id).toBe('u-1');
    expect(await provider.authenticateToken('tok-2', request())).toBeNull();
    expect(await provider.authenticateToken('', request())).toBeNull();
  });

  it('reads the Cookie header under any name when the bearer token is empty', async () => {
    const provider = fakeProvider({ token: 'tok-1' });

    expect(await provider.authenticateToken('', withCookie('tok-1'))).not.toBeNull();
    expect(await provider.authenticateToken('', withCookie('tok-1', 'some_other_name'))).not.toBeNull();
    expect(await provider.authenticateToken('', request({ cookie: 'a=1; b=tok-1; c=3' }))).not.toBeNull();
    expect(await provider.authenticateToken('', withCookie('nope'))).toBeNull();
  });

  it('reads only the named cookie when one is configured', async () => {
    const provider = fakeProvider({ token: 'tok-1', cookieName: 'only_this' });

    expect(await provider.authenticateToken('', withCookie('tok-1', 'only_this'))).not.toBeNull();
    expect(await provider.authenticateToken('', withCookie('tok-1', 'not_this'))).toBeNull();
  });

  it('never accepts an empty token, however it was configured', async () => {
    const provider = fakeProvider({ token: ['', 'tok-1'] });

    expect(provider.tokens).toEqual(['tok-1']);
    expect(await provider.authenticateToken('', request())).toBeNull();
    expect(await provider.authenticateToken('', request({ cookie: 'session=' }))).toBeNull();
  });

  it('treats a request it cannot read as carrying no cookie', async () => {
    const hostile = {
      header() {
        throw new Error('this fixture explodes when read');
      },
    };

    await expect(fakeProvider().authenticateToken('', hostile)).resolves.toBeNull();
    await expect(fakeProvider().authenticateToken(FAKE_TOKEN, hostile)).resolves.not.toBeNull();
  });

  it('answers authorizeUser from its options', async () => {
    await expect(fakeProvider().authorizeUser({}, request())).resolves.toBe(true);
    await expect(fakeProvider({ authorize: false }).authorizeUser({}, request())).resolves.toBe(false);
  });

  it('maps a payload to a resource id through the real normalizer', () => {
    const provider = fakeProvider({ user: { id: 'u-1' } });

    expect(provider.mapUserToResourceId({ id: 'u-1' })).toBe('u-1');
    expect(provider.mapUserToResourceId({ sub: 'oidc-1' })).toBe('oidc-1');
    expect(provider.mapUserToResourceId({ profile: { id: 'u-1' } })).toBeUndefined();
  });

  it('carries the identity and tokens it was built with, for a test to assert against', () => {
    const provider = fakeProvider({ name: 'acme', user: { id: 'u-1', organizationId: 'org-9' }, token: 'tok-1' });

    expect(provider.name).toBe('acme');
    expect(provider.user.id).toBe('u-1');
    expect(provider.user.organizationId).toBe('org-9');
    expect(provider.tokens).toEqual(['tok-1']);
    expect(provider.violates).toBeNull();
  });
});

// ============================================================================
// The call log
// ============================================================================

describe('the call log', () => {
  it('records what was asked, in order, with the arguments it was given', async () => {
    const provider = fakeProvider();
    const req = request();

    expect(provider.calls.called()).toBe(false);
    await provider.authenticateToken(FAKE_TOKEN, req);
    await provider.authorizeUser({}, req);

    expect(provider.calls.entries().map(call => call.method)).toEqual(['authenticateToken', 'authorizeUser']);
    expect(provider.calls.count()).toBe(2);
    expect(provider.calls.count('authenticateToken')).toBe(1);
    expect(provider.calls.count('handleCallback')).toBe(0);
    expect(provider.calls.called('authorizeUser')).toBe(true);
    expect(provider.calls.called('init')).toBe(false);
    expect(provider.calls.argsFor('authenticateToken')).toEqual([[FAKE_TOKEN, req]]);
    expect(provider.calls.last()?.method).toBe('authorizeUser');
    expect(provider.calls.last('authenticateToken')?.args[0]).toBe(FAKE_TOKEN);
  });

  it('hands back a copy, so a caller cannot corrupt the history it is reading', async () => {
    const provider = fakeProvider();
    await provider.authenticateToken(FAKE_TOKEN, request());

    const snapshot = provider.calls.entries();
    await provider.authorizeUser({}, request());

    expect(snapshot).toHaveLength(1);
    expect(provider.calls.entries()).toHaveLength(2);
  });

  it('is one history shared through every mixin', async () => {
    const base = fakeProvider();
    const provider = withInit(withSSO(base));

    expect(provider.calls).toBe(base.calls);

    await provider.authenticateToken(FAKE_TOKEN, request());
    provider.getLoginButtonConfig();
    await provider.init({});

    expect(provider.calls.entries().map(call => call.method)).toEqual([
      'authenticateToken',
      'getLoginButtonConfig',
      'init',
    ]);
  });

  it('resets in place, so a reference taken earlier stays live', async () => {
    const provider = fakeProvider();
    const log = provider.calls;

    await provider.authenticateToken(FAKE_TOKEN, request());
    log.reset();

    expect(provider.calls.called()).toBe(false);
    expect(log).toBe(provider.calls);
  });

  it('accepts a hand-written double into the same history', () => {
    const log = createCallLog();
    log.record('getCurrentUser' as never, request());
    expect(log.count()).toBe(1);
  });
});

// ============================================================================
// Individual mixins
// ============================================================================

describe('withSSO', () => {
  it('carries the state through the authorization URL unchanged', async () => {
    const provider = withSSO(fakeProvider());
    const state = encodeState('/workspaces/42', 'state-id');
    const url = new URL(await provider.getLoginUrl('https://factory.test/auth/callback', state));

    expect(url.origin + url.pathname).toBe('https://fake-idp.test/authorize');
    expect(url.searchParams.get('redirect_uri')).toBe('https://factory.test/auth/callback');
    expect(url.searchParams.get('state')).toBe(state);
  });

  it('returns the fake identity and deterministic tokens from the callback', async () => {
    const provider = withSSO(fakeProvider({ user: { id: 'u-1' } }));
    const result = await provider.handleCallback('code-1', encodeState('/', 'state-id'));

    expect(result.user.id).toBe('u-1');
    expect(result.tokens.accessToken).toBe('fake-access-token');
    expect(result.tokens.expiresAt?.getTime()).toBe(FAKE_TOKEN_EXPIRES_AT);
  });

  it('installs the optional members only when asked', () => {
    const withDefaults = withSSO(fakeProvider());
    expect(typeof withDefaults.getLogoutUrl).toBe('function');
    expect(withDefaults.getLoginCookies).toBeUndefined();

    const stripped = withSSO(fakeProvider(), { logoutUrl: null });
    expect(stripped.getLogoutUrl).toBeUndefined();

    const withCookies = withSSO(fakeProvider(), { loginCookies: ['pkce=abc; Path=/'] });
    expect(withCookies.getLoginCookies?.('https://factory.test/cb', 'state')).toEqual(['pkce=abc; Path=/']);
  });

  it('takes host-supplied login button copy', () => {
    const provider = withSSO(fakeProvider(), { loginButton: { text: 'Continue' } });
    expect(provider.getLoginButtonConfig()).toEqual({ provider: 'fake', text: 'Continue' });
  });
});

describe('withCredentials', () => {
  it('signs in and hands back a cookie the same fake then authenticates', async () => {
    const provider = withCredentials(fakeProvider({ token: 'tok-1' }));
    const result = await provider.signIn('someone@example.test', 'fake-password', request());

    expect(result.user.email).toBe('someone@example.test');
    expect(result.token).toBe('tok-1');

    const cookie = result.cookies?.[0]?.split(';')[0] ?? '';
    expect(await provider.authenticateToken('', request({ cookie }))).not.toBeNull();
  });

  it('rejects the wrong password rather than resolving null', async () => {
    const provider = withCredentials(fakeProvider(), { password: 'hunter2' });

    await expect(provider.signIn('a@b.test', 'wrong', request())).rejects.toThrow(/password 'wrong'/);
    await expect(provider.signIn('a@b.test', 'hunter2', request())).resolves.toBeDefined();
  });

  it('reports sign-up the four ways the descriptor has to handle', async () => {
    expect(toAuthDescriptor(withCredentials(fakeProvider())).signIn.signUpEnabled).toBe(true);
    expect(toAuthDescriptor(withCredentials(fakeProvider(), { signUpEnabled: false })).signIn.signUpEnabled).toBe(
      false,
    );

    // Absent method: the contract's documented default is "on".
    const absent = withCredentials(fakeProvider(), { signUpEnabled: null });
    expect(absent.isSignUpEnabled).toBeUndefined();
    expect(toAuthDescriptor(absent).signIn.signUpEnabled).toBe(true);

    // A provider whose check throws fails closed.
    const throws = withCredentials(fakeProvider(), {
      signUpEnabled: () => {
        throw new Error('provider is down');
      },
    });
    expect(toAuthDescriptor(throws).signIn.signUpEnabled).toBe(false);

    await expect(
      withCredentials(fakeProvider(), { signUpEnabled: false }).signUp('a@b.test', 'fake-password', 'A', request()),
    ).rejects.toThrow(/sign-up disabled/);
  });

  it('installs the optional password-reset methods only when asked', async () => {
    expect(withCredentials(fakeProvider()).requestPasswordReset).toBeUndefined();

    const provider = withCredentials(fakeProvider(), { passwordReset: true });
    await provider.requestPasswordReset?.('a@b.test');
    await provider.resetPassword?.('reset-token', 'new-password');

    expect(provider.calls.count('requestPasswordReset')).toBe(1);
    expect(provider.calls.argsFor('resetPassword')).toEqual([['reset-token', 'new-password']]);
  });
});

describe('withHttpHandler', () => {
  it('answers 200 by default and records the request', async () => {
    const provider = withHttpHandler(fakeProvider());
    const response = await provider.handleAuthRequest(request());

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ ok: true });
    expect(provider.calls.count('handleAuthRequest')).toBe(1);
  });

  it('lets a test branch on the request', async () => {
    const provider = withHttpHandler(fakeProvider(), {
      respond: req => new Response(null, { status: new URL(req.url).pathname === '/auth/api/ok' ? 204 : 404 }),
    });

    expect((await provider.handleAuthRequest(new Request('https://factory.test/auth/api/ok'))).status).toBe(204);
    expect((await provider.handleAuthRequest(new Request('https://factory.test/nope'))).status).toBe(404);
  });
});

describe('withOrganizations', () => {
  it('is deterministic across calls', async () => {
    const provider = withOrganizations(fakeProvider({ user: { organizationId: undefined } }));

    const first = await provider.ensureOrganization('u-1');
    const second = await provider.ensureOrganization('u-1');

    expect(first).toBe('org_u-1');
    expect(second).toBe(first);
    expect(await provider.ensureOrganization('u-2')).toBe('org_u-2');
  });

  it("defaults to the fake's own organization, so identity and bootstrap agree", async () => {
    const provider = withOrganizations(fakeProvider({ user: { organizationId: 'org-9' } }));
    const identity = toAuthIdentity(await provider.authenticateToken(FAKE_TOKEN, request()));

    expect(identity?.organizationId).toBe('org-9');
    expect(await provider.ensureOrganization('u-1')).toBe('org-9');
  });

  it('answers isOrganizationAdmin from a boolean or a predicate', async () => {
    await expect(withOrganizations(fakeProvider()).isOrganizationAdmin('org-1', 'u-1')).resolves.toBe(true);

    const provider = withOrganizations(fakeProvider(), { admin: (_org, userId) => userId === 'u-1' });
    await expect(provider.isOrganizationAdmin('org-1', 'u-1')).resolves.toBe(true);
    await expect(provider.isOrganizationAdmin('org-1', 'u-2')).resolves.toBe(false);
  });
});

describe('withSession', () => {
  it('installs all seven members, not just the two the guard reads', () => {
    const provider = withSession(fakeProvider());

    for (const member of [
      'createSession',
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ] as const) {
      expect(typeof provider[member], member).toBe('function');
    }

    // The point of installing all seven: the descriptor checks these two as
    // methods precisely because the guard does not.
    expect(toAuthDescriptor(provider).features.refresh).toBe(true);
    expect(toAuthDescriptor(provider).features.sessionRevocation).toBe(true);
  });

  it('creates, validates, refreshes and destroys a session', async () => {
    let clock = 1_000;
    const provider = withSession(fakeProvider(), { ttlMs: 500, now: () => clock });

    const session = await provider.createSession('u-1', { device: 'cli' });
    expect(session.id).toBe('fake-session-1');
    expect(session.userId).toBe('u-1');
    expect(session.metadata).toEqual({ device: 'cli' });
    expect(session.expiresAt.getTime()).toBe(1_500);
    expect(provider.sessions().get('fake-session-1')).toBeDefined();

    await expect(provider.validateSession('fake-session-1')).resolves.not.toBeNull();
    await expect(provider.validateSession('nope')).resolves.toBeNull();

    clock = 1_400;
    const refreshed = await provider.refreshSession('fake-session-1');
    expect(refreshed?.expiresAt.getTime()).toBe(1_900);

    clock = 2_000;
    await expect(provider.validateSession('fake-session-1')).resolves.toBeNull();
    await expect(provider.refreshSession('fake-session-1')).resolves.toBeNull();
    expect(provider.sessions().size).toBe(0);

    const second = await provider.createSession('u-2');
    expect(second.id).toBe('fake-session-2');
    await provider.destroySession(second.id);
    expect(provider.sessions().size).toBe(0);
  });

  it('round trips a session id through its own headers', async () => {
    const provider = withSession(fakeProvider());
    const session = await provider.createSession('u-1');

    const setCookie = provider.getSessionHeaders(session)['Set-Cookie'] ?? '';
    const cookie = setCookie.split(';')[0] ?? '';

    expect(provider.getSessionIdFromRequest(request({ cookie }))).toBe(session.id);
    expect(provider.getSessionIdFromRequest(request())).toBeNull();
    expect(provider.getClearSessionHeaders()['Set-Cookie']).toContain('Max-Age=0');
  });
});

describe('withInit', () => {
  it('records the context the host handed it', async () => {
    const provider = withInit(fakeProvider());
    const ctx = { publicUrl: 'https://factory.test', allowedOrigins: ['https://app.test'] };

    await provider.init(ctx);

    expect(provider.calls.count('init')).toBe(1);
    expect(provider.calls.last('init')?.args[0]).toBe(ctx);
  });

  it('lets a provider fail fast at prepare time', async () => {
    const provider = withInit(fakeProvider(), {
      onInit: () => {
        throw new Error('DATABASE_URL is required');
      },
    });

    await expect(provider.init({})).rejects.toThrow('DATABASE_URL is required');
    expect(provider.calls.called('init')).toBe(true);
  });
});

// ============================================================================
// The four obligations
// ============================================================================

describe('the four obligations', () => {
  it('names all four, with a summary for each', () => {
    expect(AUTH_OBLIGATIONS).toEqual(['flatId', 'cookieAuth', 'stateCodec', 'organizationId']);
    expect(Object.keys(AUTH_OBLIGATION_SUMMARY).sort()).toEqual([...AUTH_OBLIGATIONS].sort());
    for (const obligation of AUTH_OBLIGATIONS) {
      expect(AUTH_OBLIGATION_SUMMARY[obligation].length).toBeGreaterThan(0);
    }
  });

  it('are all met by the fully-capable fake', async () => {
    const provider = fullyCapableFake();

    for (const obligation of AUTH_OBLIGATIONS) {
      expect(await MEETS[obligation](provider), obligation).toBe(true);
    }
  });

  it('is fully capable: every guard passes on the fake the suite must be green against', () => {
    const provider = fullyCapableFake();

    expect(isSSOProvider(provider)).toBe(true);
    expect(isCredentialsProvider(provider)).toBe(true);
    expect(isAuthHttpHandler(provider)).toBe(true);
    expect(isOrganizationsProvider(provider)).toBe(true);
    expect(isSessionProvider(provider)).toBe(true);
    expect(hasAuthInit(provider)).toBe(true);
  });

  it.each(AUTH_OBLIGATIONS)('fakeViolating(%s) fails that obligation and only that one', async violated => {
    const provider = fakeViolating(violated);

    for (const obligation of AUTH_OBLIGATIONS) {
      expect(await MEETS[obligation](provider), `${obligation} on fakeViolating('${violated}')`).toBe(
        obligation !== violated,
      );
    }
  });

  it.each(AUTH_OBLIGATIONS)('fakeViolating(%s) still declares every capability', violated => {
    const provider = fakeViolating(violated);

    // The whole point: a structural guard cannot see any of these violations.
    expect(isSSOProvider(provider)).toBe(true);
    expect(isCredentialsProvider(provider)).toBe(true);
    expect(isAuthHttpHandler(provider)).toBe(true);
    expect(isOrganizationsProvider(provider)).toBe(true);
    expect(isSessionProvider(provider)).toBe(true);
    expect(hasAuthInit(provider)).toBe(true);
    expect(toAuthDescriptor(provider).features.organizations).toBe(true);
    expect(provider.violates).toBe(violated);
  });

  it("'flatId' hides the id where the normalizer will not find it", async () => {
    const provider = fakeViolating('flatId');
    const payload = await provider.authenticateToken(FAKE_TOKEN, request());

    expect(payload).not.toBeNull();
    expect(toAuthIdentity(payload)).toBeNull();
    expect(payload).toEqual(expect.objectContaining({ profile: { id: 'fake-user' }, email: 'fake-user@example.test' }));
    expect(provider.mapUserToResourceId(payload ?? {})).toBeUndefined();
  });

  it("'cookieAuth' ignores the Cookie header but still takes a bearer token", async () => {
    const provider = fakeViolating('cookieAuth');

    expect(await provider.authenticateToken('', withCookie(FAKE_TOKEN))).toBeNull();
    expect(await provider.authenticateToken(FAKE_TOKEN, request())).not.toBeNull();
  });

  it("'stateCodec' echoes a state format this package cannot read", async () => {
    const provider = fakeViolating('stateCodec');
    const state = encodeState('/workspaces/42', 'state-id');
    const echoed =
      new URL(await provider.getLoginUrl('https://factory.test/cb', state)).searchParams.get('state') ?? '';

    expect(echoed).not.toBe(state);
    expect(parseStateId(echoed)).not.toBe('state-id');
    expect(decodeState(echoed).returnTo).toBe('/');

    // And the callback cannot read this package's format either.
    await expect(provider.handleCallback('code-1', state)).rejects.toThrow(/did not mint/);
    await expect(provider.handleCallback('code-1', echoed)).resolves.toBeDefined();
  });

  it("'organizationId' declares the capability and resolves no organization", async () => {
    const provider = fakeViolating('organizationId');
    const payload = await provider.authenticateToken(FAKE_TOKEN, request());

    expect(payload).not.toHaveProperty('organizationId');
    expect(toAuthIdentity(payload)?.organizationId).toBeUndefined();
    expect(await provider.ensureOrganization('fake-user')).toBeUndefined();

    // The explicit option does not rescue it: the violation is the point.
    const configured = fakeViolating('organizationId', { organizations: { organizationId: 'org-9' } });
    expect(await configured.ensureOrganization('fake-user')).toBeUndefined();
  });

  it('takes per-mixin options alongside the violation', async () => {
    const provider = fakeViolating('cookieAuth', {
      token: 'tok-1',
      user: { id: 'u-1' },
      credentials: { password: 'hunter2' },
      sso: { authorizationEndpoint: 'https://idp.test/oauth/authorize' },
    });

    expect(toAuthIdentity(await provider.authenticateToken('tok-1', request()))?.id).toBe('u-1');
    await expect(provider.signIn('a@b.test', 'hunter2', request())).resolves.toBeDefined();
    expect(await provider.getLoginUrl('https://factory.test/cb', 'state')).toContain(
      'https://idp.test/oauth/authorize',
    );
  });
});

// ============================================================================
// The rules src/testing/ has to keep
// ============================================================================

const TESTING_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'testing');
const SRC_DIR = path.resolve(TESTING_DIR, '..');

/** Every `from '...'` and `import('...')` specifier in a source file. */
function specifiersIn(file: string): string[] {
  const source = fs.readFileSync(file, 'utf8');
  const found = new Set<string>();
  for (const match of source.matchAll(/\bfrom\s*['"]([^'"]+)['"]/g)) found.add(match[1] ?? '');
  for (const match of source.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) found.add(match[1] ?? '');
  for (const match of source.matchAll(/\bimport\s*['"]([^'"]+)['"]/g)) found.add(match[1] ?? '');
  return [...found];
}

/**
 * `src/testing/index.ts` plus every module of this package it reaches, however
 * deeply.
 */
function testingGraph(): string[] {
  const seen = new Set<string>();
  const queue = [path.join(TESTING_DIR, 'index.ts')];

  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || seen.has(file)) continue;
    seen.add(file);

    for (const specifier of specifiersIn(file)) {
      if (!specifier.startsWith('.')) continue;
      const resolved = path.resolve(path.dirname(file), specifier.replace(/\.js$/, '.ts'));
      if (resolved.startsWith(SRC_DIR) && fs.existsSync(resolved)) queue.push(resolved);
    }
  }

  return [...seen];
}

describe('the rules src/testing/ has to keep', () => {
  it('reaches no Node builtin, so a browser fixture can load a fake', () => {
    const offenders: string[] = [];

    for (const file of testingGraph()) {
      for (const specifier of specifiersIn(file)) {
        if (specifier.startsWith('node:')) {
          offenders.push(`${path.relative(SRC_DIR, file)} imports '${specifier}'`);
        }
      }
    }

    expect(
      offenders,
      'A fake has to load from an MSW fixture as well as from a Node test runner, so nothing behind\n' +
        'src/testing/index.ts may reach a Node builtin. `../cookie.js` and `../oauth-state.js` both do -\n' +
        'that is why FAKE_STATE_DELIMITER is restated rather than imported.',
    ).toEqual([]);

    // The graph really was walked, rather than the walk returning nothing.
    expect(testingGraph().length).toBeGreaterThanOrEqual(3);
  });

  it('restates the state delimiter without letting it drift', () => {
    expect(FAKE_STATE_DELIMITER).toBe(OAUTH_STATE_DELIMITER);
  });

  it('is not re-exported from the root barrel', async () => {
    const root = await import('../index.js');
    expect(Object.keys(root)).not.toContain('fakeProvider');
    expect(Object.keys(root)).not.toContain('fullyCapableFake');
  });
});
