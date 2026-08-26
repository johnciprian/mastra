import { describe, expect, it } from 'vitest';
import type {
  IAuthHttpHandler,
  IAuthInit,
  ICredentialsProvider,
  IOrganizationsProvider,
  ISSOProvider,
  ISessionProvider,
  IUserProvider,
} from '../index';
import {
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
