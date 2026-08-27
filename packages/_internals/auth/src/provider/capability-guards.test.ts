import { describe, expect, it } from 'vitest';
import type {
  IAuthHttpHandler,
  IAuthInit,
  ICredentialsProvider,
  IOrganizationsProvider,
  ISSOProvider,
  ISessionClearer,
  ISessionManager,
  ISessionProvider,
  IUserProvider,
} from '../index';
import {
  canClearSession,
  canManageSessions,
  hasAuthInit,
  isAuthHttpHandler,
  isCredentialsProvider,
  isOrganizationsProvider,
  isSSOProvider,
  isSessionProvider,
  isUserProvider,
} from './index';

/**
 * Every guard tests every required member of the interface it asserts.
 *
 * A guard's return type is a type predicate, so passing it licenses the caller
 * to reach for anything the interface requires. Four of these guards used to
 * test a subset - `isSessionProvider` read two of seven - which meant an object
 * could satisfy the guard, be narrowed to `ISessionProvider`, and throw on the
 * first call to a member nobody had checked for.
 *
 * The risk in fixing that is drift in the other direction: someone adds a
 * required member to an interface and the guard silently keeps testing the old
 * set. So the member lists below are not free-standing literals. Each is pinned
 * to its interface by `AssertSameKeys`, which fails to COMPILE - not to run -
 * if the list and the interface's required keys ever diverge. That check is why
 * this file is in the `typecheck:packages/_internals/auth` project; running it
 * without typechecking would skip the half that matters.
 */

/** The keys of `T` that a value must supply. Optional members drop out. */
type RequiredKeys<T> = { [K in keyof T]-?: object extends Pick<T, K> ? never : K }[keyof T];

/** Compiles to `true` only when `A` and `B` are the same union of keys. */
type AssertSameKeys<A extends PropertyKey, B extends PropertyKey> = [A] extends [B]
  ? [B] extends [A]
    ? true
    : { missingFromList: Exclude<B, A> }
  : { notRequiredByInterface: Exclude<A, B> };

/** One guard and the members it must test. */
interface GuardUnderTest<Members extends string> {
  readonly name: string;
  readonly guard: (value: unknown) => boolean;
  readonly required: readonly Members[];
}

/**
 * Builds a case, and pins its member list to `Iface` while doing it.
 *
 * `Members` is inferred from the array argument, so the array is the only place
 * the member names are written - there is no second copy to drift from it. The
 * `proof` argument's type is computed from that inferred union: it is `true`
 * when the list matches the interface's required keys exactly, and otherwise a
 * diagnostic object naming what is out of place, which the literal `true` at
 * every call site fails to satisfy. Add a required member to an interface and
 * the call for its guard stops compiling with `missingFromList: "theNewOne"`.
 */
function guardCase<Iface>() {
  return function <Members extends string>(
    name: string,
    guard: (value: unknown) => boolean,
    required: readonly Members[],
    proof: AssertSameKeys<Members, RequiredKeys<Iface>>,
  ): GuardUnderTest<Members> {
    void proof;
    return { name, guard, required };
  };
}

const GUARDS = [
  guardCase<ISSOProvider>()(
    'isSSOProvider',
    isSSOProvider,
    ['getLoginUrl', 'handleCallback', 'getLoginButtonConfig'],
    true,
  ),
  guardCase<ISessionProvider>()(
    'isSessionProvider',
    isSessionProvider,
    [
      'createSession',
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ],
    true,
  ),
  guardCase<IUserProvider>()('isUserProvider', isUserProvider, ['getCurrentUser', 'getUser'], true),
  guardCase<ICredentialsProvider>()('isCredentialsProvider', isCredentialsProvider, ['signIn', 'signUp'], true),
  guardCase<IOrganizationsProvider>()(
    'isOrganizationsProvider',
    isOrganizationsProvider,
    ['ensureOrganization', 'isOrganizationAdmin'],
    true,
  ),
  guardCase<IAuthHttpHandler>()('isAuthHttpHandler', isAuthHttpHandler, ['handleAuthRequest'], true),
  guardCase<IAuthInit>()('hasAuthInit', hasAuthInit, ['init'], true),
  guardCase<ISessionClearer>()('canClearSession', canClearSession, ['getClearSessionHeaders'], true),
  guardCase<ISessionManager>()(
    'canManageSessions',
    canManageSessions,
    [
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ],
    true,
  ),
] as const;

/** An object carrying exactly `members`, each a function. */
function objectWith(members: readonly string[]): Record<string, () => void> {
  return Object.fromEntries(members.map(member => [member, () => {}]));
}

describe('capability guards', () => {
  it.each(GUARDS.map(entry => [entry.name, entry] as const))(
    '%s accepts an object with every required member',
    (_name, entry) => {
      expect(entry.guard(objectWith(entry.required))).toBe(true);
    },
  );

  it.each(
    GUARDS.flatMap(entry => entry.required.map(member => [`${entry.name} without ${member}`, entry, member] as const)),
  )('%s is false', (_name, entry, member) => {
    const incomplete = objectWith(entry.required.filter(other => other !== member));
    expect(entry.guard(incomplete)).toBe(false);
  });

  it.each(GUARDS.map(entry => [entry.name, entry.guard] as const))('%s rejects non-objects', (_name, guard) => {
    for (const value of [null, undefined, 0, '', 'provider', true, Symbol('provider'), 123n]) {
      expect(guard(value)).toBe(false);
    }
  });

  it.each(GUARDS.map(entry => [entry.name, entry] as const))(
    '%s rejects an object whose members are not functions',
    (_name, entry) => {
      const notFunctions = Object.fromEntries(entry.required.map(member => [member, 'not a function']));
      expect(entry.guard(notFunctions)).toBe(false);
    },
  );

  /**
   * A guard reports on the required half only. `ISSOProvider` declares three
   * optional members and `getLogoutUrl` is the one a host is most likely to
   * feature-detect; demanding it here would reject providers the interface
   * accepts, which is the mirror-image bug of the one this file exists for.
   */
  it('does not require optional members', () => {
    expect(isSSOProvider(objectWith(['getLoginUrl', 'handleCallback', 'getLoginButtonConfig']))).toBe(true);
    expect(isUserProvider(objectWith(['getCurrentUser', 'getUser']))).toBe(true);
    expect(isCredentialsProvider(objectWith(['signIn', 'signUp']))).toBe(true);
  });

  /**
   * The guards are structural, so a plain object satisfies them. That is the
   * point - provider packages bundle their own `MastraAuthProvider` copy and
   * cannot be compared nominally across package boundaries.
   */
  /**
   * The three session guards answer in a chain, because the three interfaces
   * are one: `ISessionProvider extends ISessionManager extends ISessionClearer`.
   * A provider sitting at any rung satisfies every guard below it and none
   * above, which is the whole reason the narrower interfaces exist — asking the
   * widest question of a provider that can do most of the job answers false and
   * takes the part that works with it.
   */
  it('answers in a chain, the way the interfaces nest', () => {
    const MANAGER_MEMBERS = [
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ];

    const clearerOnly = objectWith(['getClearSessionHeaders']);
    expect([canClearSession(clearerOnly), canManageSessions(clearerOnly), isSessionProvider(clearerOnly)]).toEqual([
      true,
      false,
      false,
    ]);

    // @mastra/auth-workos: everything but minting.
    const manager = objectWith(MANAGER_MEMBERS);
    expect([canClearSession(manager), canManageSessions(manager), isSessionProvider(manager)]).toEqual([
      true,
      true,
      false,
    ]);

    const full = objectWith(['createSession', ...MANAGER_MEMBERS]);
    expect([canClearSession(full), canManageSessions(full), isSessionProvider(full)]).toEqual([true, true, true]);
  });

  /**
   * `createSession` is the only member separating the two wider guards, so it is
   * the only place they can disagree. Naming it here means a member moved
   * between the interfaces without the guards following shows up as a failure
   * rather than as two guards that quietly answer the same thing.
   */
  it('separates isSessionProvider from canManageSessions on createSession alone', () => {
    const full = objectWith([
      'createSession',
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ]);
    const { createSession: _dropped, ...withoutCreate } = full;

    expect(isSessionProvider(full)).toBe(true);
    expect(isSessionProvider(withoutCreate)).toBe(false);
    expect(canManageSessions(withoutCreate)).toBe(true);
  });

  it('narrows to a type whose required members are all callable', () => {
    const candidate: unknown = objectWith([
      'createSession',
      'validateSession',
      'destroySession',
      'refreshSession',
      'getSessionIdFromRequest',
      'getSessionHeaders',
      'getClearSessionHeaders',
    ]);

    expect(isSessionProvider(candidate)).toBe(true);
    if (isSessionProvider(candidate)) {
      // Each of these compiles because of the narrowing, and each is present
      // because the guard checked for it. Before the fix, five of the seven
      // compiled on evidence of the other two.
      for (const member of [
        candidate.createSession,
        candidate.validateSession,
        candidate.destroySession,
        candidate.refreshSession,
        candidate.getSessionIdFromRequest,
        candidate.getSessionHeaders,
        candidate.getClearSessionHeaders,
      ]) {
        expect(typeof member).toBe('function');
      }
    }
  });
});
