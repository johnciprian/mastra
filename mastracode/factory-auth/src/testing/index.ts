/**
 * Test doubles for hosts and packages that *consume* a provider.
 *
 * `fakeProvider()` builds the base contract - `authenticateToken`,
 * `authorizeUser`, `mapUserToResourceId` - and six mixins add one optional
 * capability each. So "SSO but no organizations" is one line, and it is the line
 * that says so:
 *
 * ```ts
 * const provider = withSSO(fakeProvider());
 * expect(toAuthDescriptor(provider).features.organizations).toBe(false);
 * expect(provider.calls.called()).toBe(false); // and nothing was asked
 * ```
 *
 * HARD RULE: NOTHING UNDER `src/testing/` MAY IMPORT VITEST
 *
 * The fakes are plain objects with no runner in them, so they work from the
 * Factory's own suites, from an SPA's MSW fixtures, and from a consumer's tests
 * whatever they run. `src/__tests__/no-ee-boundary.test.ts` enforces this with a
 * fail-closed allowlist that permits `vitest` only under `src/__tests__/` and
 * `src/conformance/`; an import here fails the build rather than review.
 *
 * The same rule is why this module restates two values rather than importing
 * them. `../cookie.js` and `../oauth-state.js` both reach `node:crypto`, and a
 * fake that dragged a Node builtin into a browser bundle would stop being usable
 * from the fixtures it exists for. {@link FAKE_STATE_DELIMITER} is the one value
 * that has to agree with the kit, and `src/__tests__/testing.test.ts` pins it
 * against `OAUTH_STATE_DELIMITER` so the restatement cannot drift.
 *
 * WHAT THE MIXINS GUARANTEE
 *
 * Each returns a *new* object rather than mutating its input, so a base fake
 * stays a base fake and `isSSOProvider(fakeProvider())` is false even after some
 * other line wrapped it. Each declares its return type as `T & <the interface
 * its guard narrows to>`, so the narrowing is proved by `tsc` on this file
 * rather than asserted in a test: a mixin that stopped satisfying its interface
 * would not compile. The {@link FakeCallLog} is shared by reference through
 * every mixin, so one fake has one history no matter how it was composed.
 *
 * THE FOUR OBLIGATIONS, AND HOW TO BREAK EXACTLY ONE
 *
 * A provider can satisfy every declared interface and still not run the Factory,
 * because four requirements live outside the contract - see the README. They are
 * {@link AUTH_OBLIGATIONS}, and {@link fakeViolating} builds a fully-capable fake
 * that meets three of them and fails the fourth:
 *
 * ```ts
 * const broken = fakeViolating('cookieAuth'); // correct except for the Cookie header
 * ```
 *
 * That is the shape `src/conformance/` needs: one deliberately-broken fake per
 * obligation, with no hand-rolled provider and nothing else changed.
 *
 * Writing a provider? You want `./conformance` instead.
 */
import { getRequestHeader } from '../contract.js';
import type {
  AuthInitContext,
  IAuthHttpHandler,
  IAuthInit,
  ICredentialsProvider,
  IMastraAuthProvider,
  IOrganizationsProvider,
  ISessionProvider,
  ISSOProvider,
  IUserProvider,
  MastraAuthRequest,
} from '../contract.js';
import { toAuthIdentity } from '../identity.js';
import type { AuthIdentity } from '../identity.js';

// ============================================================================
// Types the contract does not re-export
// ============================================================================

/**
 * `src/contract.ts` re-exports the capability *interfaces* but not the payload
 * types they traffic in - `SSOLoginConfig`, `SSOCallbackResult`,
 * `CredentialsResult`, `Session` - and this package's one rule is that
 * `@mastra/core/server` has exactly one import site. So the payload types are
 * read back off the interfaces instead of imported.
 *
 * This is not a workaround with a cost: derived aliases cannot drift. If the
 * contract changes `handleCallback`'s return type, {@link FakeSSOCallbackResult}
 * changes with it and every fake below fails to compile, which is the outcome an
 * imported alias would have hidden.
 */
export type FakeSSOLoginConfig = ReturnType<ISSOProvider['getLoginButtonConfig']>;

/** What a fake's `handleCallback` resolves to. See {@link FakeSSOLoginConfig}. */
export type FakeSSOCallbackResult = Awaited<ReturnType<ISSOProvider<FakeUser>['handleCallback']>>;

/** What a fake's `signIn` and `signUp` resolve to. See {@link FakeSSOLoginConfig}. */
export type FakeCredentialsResult = Awaited<ReturnType<ICredentialsProvider<FakeUser>['signIn']>>;

/** The session record a fake's session store holds. See {@link FakeSSOLoginConfig}. */
export type FakeSession = Awaited<ReturnType<ISessionProvider['createSession']>>;

// ============================================================================
// The four obligations
// ============================================================================

/**
 * The four requirements a provider has to meet that no interface states.
 *
 * Each is a real failure the auth audit found, and each is invisible to the
 * seven structural guards: a provider can satisfy every declared interface, pass
 * every guard, and still fail one of these. That is why they are named here as
 * data rather than described in a test's prose - `./conformance` (K18) names the
 * failing obligation in its output, and {@link fakeViolating} builds the fake
 * that proves each check can actually go red.
 *
 * - `flatId` - `authenticateToken` must resolve through `toAuthIdentity` to a
 *   non-empty `id`. Every surface that persists anything keys on it.
 * - `cookieAuth` - `authenticateToken` must read the `Cookie` header when the
 *   bearer token is empty. A browser navigation sends no `Authorization` header.
 * - `stateCodec` - login and callback must agree with this package's `encodeState`
 *   and `decodeState`, so the `state` a provider echoes back still parses.
 * - `organizationId` - every identity must resolve to an organization id, from
 *   the provider itself or from `withSyntheticOrganizations`.
 */
export const AUTH_OBLIGATIONS = ['flatId', 'cookieAuth', 'stateCodec', 'organizationId'] as const;

/** One of {@link AUTH_OBLIGATIONS}. */
export type AuthObligation = (typeof AUTH_OBLIGATIONS)[number];

/**
 * One line per obligation, for a failure message that says what broke rather
 * than which assertion tripped.
 *
 * Lives beside {@link AUTH_OBLIGATIONS} so the suite that reports an obligation
 * and the fake that violates it read from the same source.
 */
export const AUTH_OBLIGATION_SUMMARY: Readonly<Record<AuthObligation, string>> = {
  flatId: 'authenticateToken must return a payload with a flat, resolvable id (id, uid or sub).',
  cookieAuth: 'authenticateToken must read the Cookie header when the bearer token is empty.',
  stateCodec: 'Login and callback must use this package’s encodeState and decodeState.',
  organizationId: 'Every identity must resolve to an organization id, from the provider or a wrapper.',
};

// ============================================================================
// Constants
// ============================================================================

/**
 * The delimiter this package's OAuth `state` codec uses.
 *
 * Restated rather than imported from `../oauth-state.js`, which reaches
 * `node:crypto` for `randomUUID` and would put a Node builtin into every bundle
 * that loads a fake. `src/__tests__/testing.test.ts` asserts this equals
 * `OAUTH_STATE_DELIMITER`, so the copy cannot silently diverge.
 */
export const FAKE_STATE_DELIMITER = '|';

/**
 * The cookie name a fake *writes*.
 *
 * A fake reads any cookie by default - see {@link FakeProviderOptions.cookieName}
 * - but it has to pick one name when it sets a cookie, and `signIn` handing back
 * a cookie the same fake's `authenticateToken` then accepts is the round trip
 * most host tests are actually exercising.
 */
export const FAKE_COOKIE_NAME = 'fake_session';

/** The bearer token {@link fakeProvider} accepts unless told otherwise. */
export const FAKE_TOKEN = 'fake-token';

/**
 * Expiry on every token and session a fake mints, in epoch milliseconds.
 *
 * A fixed far-future instant rather than `Date.now() + n`, so two runs of the
 * same test produce the same payload and a snapshot of one is stable.
 */
export const FAKE_TOKEN_EXPIRES_AT = Date.UTC(2100, 0, 1);

/** The identity {@link fakeProvider} authenticates to unless told otherwise. */
const DEFAULT_USER: FakeUser = {
  id: 'fake-user',
  email: 'fake-user@example.test',
  name: 'Fake User',
  avatarUrl: 'https://example.test/fake-user.png',
  organizationId: 'fake-org',
};

// ============================================================================
// The call log
// ============================================================================

/** One recorded call: which method, and what it was handed. */
export interface FakeCall {
  /** The method's name, as it appears on the provider. */
  readonly method: string;
  /** The arguments, in order, exactly as received. */
  readonly args: readonly unknown[];
}

/**
 * Every method a fake in this module installs.
 *
 * A closed union rather than `string`, because the interesting assertion in a
 * test is a negative one - "the descriptor says no organizations, *and* nothing
 * asked the provider" - and a negative assertion on a mistyped method name
 * passes. `calls.count('ensureOrganisation')` does not compile.
 */
export type FakeMethod =
  | 'authenticateToken'
  | 'authorizeUser'
  | 'mapUserToResourceId'
  | 'getLoginUrl'
  | 'getLoginCookies'
  | 'handleCallback'
  | 'getLoginButtonConfig'
  | 'getLogoutUrl'
  | 'signIn'
  | 'signUp'
  | 'isSignUpEnabled'
  | 'requestPasswordReset'
  | 'resetPassword'
  | 'handleAuthRequest'
  | 'getCurrentUser'
  | 'getUser'
  | 'ensureOrganization'
  | 'isOrganizationAdmin'
  | 'createSession'
  | 'validateSession'
  | 'destroySession'
  | 'refreshSession'
  | 'getSessionIdFromRequest'
  | 'getSessionHeaders'
  | 'getClearSessionHeaders'
  | 'init';

/**
 * What a fake was asked, and when.
 *
 * A fake that only answers correctly is half a test double. "The descriptor says
 * this provider has no organizations" is a claim about a pure derivation; "and
 * nothing called the provider to find out" is the claim that catches a
 * capability check that quietly probes a method instead of reading a guard.
 *
 * Every method a mixin installs records itself before doing anything, including
 * the ones that go on to throw.
 */
export interface FakeCallLog {
  /** Every call, oldest first. A fresh array each time, safe to keep. */
  entries(): readonly FakeCall[];
  /** Was `method` ever called - or, with no argument, was anything? */
  called(method?: FakeMethod): boolean;
  /** How many times `method` was called - or, with no argument, everything. */
  count(method?: FakeMethod): number;
  /** The argument list from each call of `method`, oldest first. */
  argsFor(method: FakeMethod): readonly (readonly unknown[])[];
  /** The most recent call to `method`, or the most recent call at all. */
  last(method?: FakeMethod): FakeCall | undefined;
  /** Forget everything. The log object stays the same, so held references stay live. */
  reset(): void;
  /**
   * Append a call. The mixins use this; so can a hand-written stub that wants to
   * share a fake's history.
   */
  record(method: FakeMethod, ...args: unknown[]): void;
}

/**
 * A fresh, empty log.
 *
 * Exported because a consumer assembling its own double alongside these fakes
 * should be able to put both in one history rather than correlating two.
 */
export function createCallLog(): FakeCallLog {
  let calls: FakeCall[] = [];

  // Plain closures rather than `this`-bound methods or accessors: mixins copy a
  // fake by spreading it, and a spread turns a getter into a snapshot and leaves
  // a `this`-bound method pointing at the object it came from. Closures survive
  // both, so `const { authenticateToken } = fake` also works.
  return {
    entries: () => calls.slice(),
    called: method => (method === undefined ? calls.length > 0 : calls.some(call => call.method === method)),
    count: method => (method === undefined ? calls.length : calls.filter(call => call.method === method).length),
    argsFor: method => calls.filter(call => call.method === method).map(call => call.args),
    last: method => {
      const matching = method === undefined ? calls : calls.filter(call => call.method === method);
      return matching[matching.length - 1];
    },
    reset: () => {
      calls = [];
    },
    record: (method, ...args) => {
      calls.push({ method, args });
    },
  };
}

// ============================================================================
// The base fake
// ============================================================================

/**
 * The user a fake vouches for.
 *
 * {@link AuthIdentity} itself: a fake that authenticated to some other shape
 * would be testing the normalizer rather than the host, and the one case where a
 * different shape is the point - the `flatId` obligation - is expressed by
 * {@link fakeViolating} rather than by a second user type.
 */
export type FakeUser = AuthIdentity;

/**
 * What a fake's `authenticateToken` resolves to.
 *
 * Deliberately looser than {@link FakeUser}. A provider's `authenticateToken`
 * returns whatever its vendor's token decodes to - that is the whole reason
 * `toAuthIdentity` exists - and the `flatId` fake has to be able to return a
 * payload that carries an id somewhere `toAuthIdentity` will not find it.
 */
export type FakeAuthPayload = Record<string, unknown>;

/** Options for {@link fakeProvider}. */
export interface FakeProviderOptions {
  /** `IMastraAuthProvider.name`. Defaults to `'fake'`. */
  name?: string;

  /**
   * The identity this fake authenticates to, merged over the defaults.
   *
   * Pass `{ organizationId: undefined }` to model a provider with no
   * organization concept - though if what you want is a fake that fails the
   * organization obligation while still implementing `IOrganizationsProvider`,
   * that is {@link fakeViolating}`('organizationId')`.
   */
  user?: Partial<FakeUser>;

  /**
   * Bearer tokens this fake accepts. Defaults to {@link FAKE_TOKEN}.
   *
   * Empty strings are dropped: an accepted empty token would authenticate every
   * unauthenticated request, and the `cookieAuth` obligation is precisely about
   * what happens when the token is empty.
   */
  token?: string | readonly string[];

  /**
   * Restrict the `Cookie` header search to one cookie name.
   *
   * Absent by default, so a fake accepts a known token under *any* cookie name.
   * That is the permissive direction on purpose: the obligation is that the
   * provider reads the header at all, and a host test should not have to know
   * which name this fake happens to prefer in order to exercise it.
   */
  cookieName?: string;

  /** What `authorizeUser` answers. Defaults to `true`. */
  authorize?: boolean;

  /**
   * The one obligation this fake deliberately fails. Absent means it meets all
   * four.
   *
   * Set on the base fake rather than on each mixin, because three of the four
   * obligations are not the base fake's to break - `stateCodec` lives in
   * {@link withSSO}, `organizationId` in {@link withOrganizations} - and a
   * violation configured in one place and read in another is one knob instead of
   * six. {@link fakeViolating} is the ergonomic form.
   */
  violates?: AuthObligation;
}

/**
 * The base contract, and nothing else: a fake that validates bearer tokens.
 *
 * `toAuthDescriptor` calls this `kind: 'none'`, which is a working, enforcing
 * provider that simply cannot sign anyone in from a browser - today's Supabase
 * and Firebase providers are exactly this shape. It satisfies none of the seven
 * capability guards, which is what makes it a useful starting point: every
 * capability a test sees is one the test put there.
 */
export interface FakeProvider extends IMastraAuthProvider<FakeAuthPayload> {
  /** Always set, unlike the optional `name` on the contract. */
  name: string;

  /** What was asked of this fake. See {@link FakeCallLog}. */
  calls: FakeCallLog;

  /** The identity this fake authenticates to. Read-only; set it through options. */
  user: FakeUser;

  /** The bearer tokens this fake accepts. */
  tokens: readonly string[];

  /** The obligation this fake fails, or `null` when it meets all four. */
  violates: AuthObligation | null;

  authenticateToken(token: string, request: MastraAuthRequest): Promise<FakeAuthPayload | null>;
  authorizeUser(user: FakeAuthPayload, request: MastraAuthRequest): Promise<boolean>;
  mapUserToResourceId(user: FakeAuthPayload): string | undefined;
}

/**
 * Build a provider that implements the base contract and no capability.
 *
 * ```ts
 * const provider = fakeProvider({ token: 'tok', user: { id: 'u-1' } });
 * await provider.authenticateToken('tok', request); // { id: 'u-1', ... }
 * await provider.authenticateToken('', { headers: new Headers({ cookie: 'anything=tok' }) });
 * ```
 *
 * The second call is the `cookieAuth` obligation: an empty bearer token means
 * "this is a browser navigation, read the cookie". A fake built with
 * `violates: 'cookieAuth'` resolves that call to `null` and is otherwise
 * identical.
 *
 * Requests are read through `getRequestHeader` from `../contract.js`, so a plain
 * `Request`, a Hono context request, and a bare `{ headers }` all work. A request
 * object that throws when read is treated as carrying no cookie rather than
 * propagating: a test double should not turn an odd fixture into a stack trace
 * from inside the double.
 */
export function fakeProvider(options: FakeProviderOptions = {}): FakeProvider {
  const calls = createCallLog();
  const violates = options.violates ?? null;
  const user: FakeUser = { ...DEFAULT_USER, ...options.user };
  const tokens = normalizeTokens(options.token);
  const accepted = new Set(tokens);
  const authorize = options.authorize ?? true;
  const readsCookies = violates !== 'cookieAuth';

  function payload(): FakeAuthPayload {
    const rest: FakeAuthPayload = {};
    if (user.email !== undefined) rest.email = user.email;
    if (user.name !== undefined) rest.name = user.name;
    if (user.avatarUrl !== undefined) rest.avatarUrl = user.avatarUrl;
    if (violates !== 'organizationId' && user.organizationId !== undefined) {
      rest.organizationId = user.organizationId;
    }

    // The `flatId` violation, and the only place the payload shape changes. The
    // id is present and readable by anything that knows this fake, but it is not
    // under `id`, `uid` or `sub` at the top level, so `toAuthIdentity` resolves
    // `null` - which is exactly how a real provider returning `{ data: { user } }`
    // fails today.
    if (violates === 'flatId') return { ...rest, profile: { id: user.id } };
    return { id: user.id, ...rest };
  }

  return {
    name: options.name ?? 'fake',
    calls,
    user,
    tokens,
    violates,

    async authenticateToken(token, request) {
      calls.record('authenticateToken', token, request);
      if (accepted.has(token)) return payload();
      if (!readsCookies) return null;
      return cookieValues(request, options.cookieName).some(value => accepted.has(value)) ? payload() : null;
    },

    async authorizeUser(authenticatedUser, request) {
      calls.record('authorizeUser', authenticatedUser, request);
      return authorize;
    },

    mapUserToResourceId(authenticatedUser) {
      calls.record('mapUserToResourceId', authenticatedUser);
      // Routed through the real normalizer so this answer and the `flatId`
      // obligation cannot disagree: a payload the host cannot resolve maps to no
      // resource id either.
      return toAuthIdentity(authenticatedUser)?.id;
    },
  };
}

// ============================================================================
// Mixins
// ============================================================================

/** Options for {@link withSSO}. */
export interface FakeSSOOptions {
  /** The hosted login page. Defaults to `'https://fake-idp.test/authorize'`. */
  authorizationEndpoint?: string;

  /** What `getLoginButtonConfig` answers, merged over a neutral default. */
  loginButton?: Partial<FakeSSOLoginConfig>;

  /**
   * What `getLogoutUrl` answers. Pass `null` to leave the optional method off
   * entirely, which is how you model a provider with no hosted logout.
   */
  logoutUrl?: string | null;

  /**
   * Cookies `getLoginCookies` hands back - the PKCE verifier, in a real provider.
   * Absent leaves the optional method off.
   */
  loginCookies?: readonly string[];
}

/** What {@link withSSO} adds. Satisfies `isSSOProvider`. */
export type FakeSSOCapability = ISSOProvider<FakeUser>;

/**
 * Add a hosted login: `getLoginUrl`, `handleCallback`, `getLoginButtonConfig`.
 *
 * ```ts
 * const provider = withSSO(fakeProvider());
 * isSSOProvider(provider); // true, and the type says so
 * ```
 *
 * THE `stateCodec` OBLIGATION LIVES HERE
 *
 * A conforming provider treats `state` as opaque: whatever `encodeState`
 * produced goes into the authorization URL and comes back from the identity
 * provider unchanged, so `parseStateId` and `decodeState` still read it. This
 * fake does that - `getLoginUrl` puts the value straight into the query string,
 * percent-encoded by `URLSearchParams` as any correct provider would.
 *
 * A fake built with `violates: 'stateCodec'` re-encodes `state` into a
 * querystring-shaped format of its own, which is what a provider that mints its
 * own `state` actually looks like. Two things then break, and a suite can catch
 * either: `parseStateId` on the echoed value no longer returns the id that went
 * in, and `handleCallback` rejects a `state` in this package's format because it
 * does not recognize it.
 */
export function withSSO<T extends FakeProvider>(provider: T, options: FakeSSOOptions = {}): T & FakeSSOCapability {
  const { calls, violates, user } = provider;
  const endpoint = options.authorizationEndpoint ?? 'https://fake-idp.test/authorize';
  const foreignState = violates === 'stateCodec';

  const capability: FakeSSOCapability = {
    getLoginUrl(redirectUri, state) {
      calls.record('getLoginUrl', redirectUri, state);
      const url = new URL(endpoint);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('state', foreignState ? toForeignState(state) : state);
      return url.toString();
    },

    async handleCallback(code, state) {
      calls.record('handleCallback', code, state);
      if (foreignState && !isForeignState(state)) {
        throw new Error(
          `The fake SSO provider was given a state it did not mint: '${state}'. This fake violates the ` +
            "'stateCodec' obligation, so it speaks its own state format and cannot read this package's.",
        );
      }
      return {
        user: { ...user },
        tokens: {
          accessToken: 'fake-access-token',
          refreshToken: 'fake-refresh-token',
          idToken: 'fake-id-token',
          expiresAt: new Date(FAKE_TOKEN_EXPIRES_AT),
        },
      } satisfies FakeSSOCallbackResult;
    },

    getLoginButtonConfig() {
      calls.record('getLoginButtonConfig');
      return { provider: 'fake', text: 'Sign in with the fake provider', ...options.loginButton };
    },
  };

  // Installed conditionally, because both are optional on `ISSOProvider` and a
  // fake that always has them cannot model the provider that does not.
  if (options.logoutUrl !== null) {
    const logoutUrl = options.logoutUrl ?? 'https://fake-idp.test/logout';
    capability.getLogoutUrl = (redirectUri, request) => {
      calls.record('getLogoutUrl', redirectUri, request);
      const url = new URL(logoutUrl);
      url.searchParams.set('redirect_uri', redirectUri);
      return url.toString();
    };
  }
  if (options.loginCookies !== undefined) {
    const loginCookies = [...options.loginCookies];
    capability.getLoginCookies = (redirectUri, state) => {
      calls.record('getLoginCookies', redirectUri, state);
      return loginCookies.slice();
    };
  }

  return { ...provider, ...capability };
}

/** Options for {@link withCredentials}. */
export interface FakeCredentialsOptions {
  /** The password `signIn` and `signUp` accept. Defaults to `'fake-password'`. */
  password?: string;

  /**
   * What `isSignUpEnabled()` answers.
   *
   * A function is called on every ask, so one that throws models the provider
   * whose sign-up check fails - `toAuthDescriptor` answers `false` for that, and
   * this is how you prove it. `null` leaves the optional method off entirely,
   * which the contract documents as meaning "sign-up is on".
   */
  signUpEnabled?: boolean | (() => boolean) | null;

  /** Install the optional `requestPasswordReset` and `resetPassword`. Off by default. */
  passwordReset?: boolean;
}

/** What {@link withCredentials} adds. Satisfies `isCredentialsProvider`. */
export type FakeCredentialsCapability = ICredentialsProvider<FakeUser>;

/**
 * Add an email-and-password sign-in: `signIn`, `signUp`, `isSignUpEnabled`.
 *
 * `signIn` hands back a `Set-Cookie` carrying one of the fake's own tokens under
 * {@link FAKE_COOKIE_NAME}, so a host test can complete the loop it actually
 * cares about - sign in, put the cookie on the next request, authenticate - with
 * the same fake on both ends.
 *
 * A wrong password rejects rather than resolving `null`, which is what
 * `ICredentialsProvider` documents and what a host's error path has to handle.
 */
export function withCredentials<T extends FakeProvider>(
  provider: T,
  options: FakeCredentialsOptions = {},
): T & FakeCredentialsCapability {
  const { calls, user, tokens } = provider;
  const password = options.password ?? 'fake-password';
  const token = tokens[0] ?? FAKE_TOKEN;
  // Not `?? true`: `null` is a meaningful value here - "leave the optional
  // method off" - and `??` would fold it into the default and install one.
  const signUpEnabled = options.signUpEnabled === undefined ? true : options.signUpEnabled;

  function result(overrides: Partial<FakeUser>): FakeCredentialsResult {
    return {
      user: { ...user, ...overrides },
      token,
      cookies: [`${FAKE_COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax`],
    };
  }

  function reject(method: 'signIn' | 'signUp', given: string): never {
    throw new Error(
      `The fake credentials provider rejected ${method}: password '${given}' is not the one it accepts. ` +
        'Pass the same value as the `password` option, or use the default.',
    );
  }

  const capability: FakeCredentialsCapability = {
    async signIn(email, given, request) {
      calls.record('signIn', email, given, request);
      if (given !== password) reject('signIn', given);
      return result({ email });
    },

    async signUp(email, given, name, request) {
      calls.record('signUp', email, given, name, request);
      if (given !== password) reject('signUp', given);
      if (capability.isSignUpEnabled?.() === false) {
        throw new Error('The fake credentials provider has sign-up disabled.');
      }
      return result({ email, name });
    },
  };

  if (signUpEnabled !== null) {
    capability.isSignUpEnabled = () => {
      calls.record('isSignUpEnabled');
      return typeof signUpEnabled === 'function' ? signUpEnabled() : signUpEnabled;
    };
  }
  if (options.passwordReset === true) {
    capability.requestPasswordReset = async email => {
      calls.record('requestPasswordReset', email);
    };
    capability.resetPassword = async (resetToken, newPassword) => {
      calls.record('resetPassword', resetToken, newPassword);
    };
  }

  return { ...provider, ...capability };
}

/** Options for {@link withHttpHandler}. */
export interface FakeHttpHandlerOptions {
  /**
   * What `handleAuthRequest` answers. Defaults to `200` with `{"ok":true}`.
   *
   * Called with the request, so a test can branch on the path the host mounted
   * the handler under without a second fake.
   */
  respond?: (request: Request) => Response | Promise<Response>;
}

/** What {@link withHttpHandler} adds. Satisfies `isAuthHttpHandler`. */
export type FakeHttpHandlerCapability = IAuthHttpHandler;

/**
 * Add `handleAuthRequest`, the provider that serves its own HTTP surface.
 *
 * Worth having as its own mixin because it is the one capability that changes
 * `toAuthDescriptor`'s `features.logout` without changing `signIn.kind`: a
 * provider that signs nobody in from a browser but mounts its own routes still
 * has a sign-out.
 */
export function withHttpHandler<T extends FakeProvider>(
  provider: T,
  options: FakeHttpHandlerOptions = {},
): T & FakeHttpHandlerCapability {
  const { calls } = provider;
  const respond =
    options.respond ??
    (() =>
      new Response(JSON.stringify({ ok: true }), { status: 200, headers: { 'content-type': 'application/json' } }));

  const capability: FakeHttpHandlerCapability = {
    async handleAuthRequest(request) {
      calls.record('handleAuthRequest', request);
      return respond(request);
    },
  };

  return { ...provider, ...capability };
}

/** Options for {@link withUser}. */
export interface FakeUserOptions {
  /**
   * Other users `getUser` can find, beyond the fake's own {@link FakeProvider.user}.
   *
   * Directory lookup is what `getUser` is for, and a fake with a directory of
   * exactly one user cannot tell "looked the id up" from "returned whoever is
   * signed in". Ids not in here and not the fake's own resolve to `null`, which
   * is what the interface documents for a user who does not exist.
   */
  directory?: readonly FakeUser[];
}

/** What {@link withUser} adds. Satisfies `isUserProvider`. */
export type FakeUserCapability = IUserProvider<FakeUser>;

/**
 * Add the user directory: `getCurrentUser` and `getUser`.
 *
 * ```ts
 * const provider = withUser(fakeProvider());
 * isUserProvider(provider); // true, and the type says so
 * await provider.getCurrentUser(new Request(url, { headers: { authorization: `Bearer ${FAKE_TOKEN}` } }));
 * ```
 *
 * BOTH MEMBERS, BECAUSE THE GUARD ONLY READS ONE
 *
 * `isUserProvider` tests `getCurrentUser` and nothing else, while
 * `IUserProvider` requires `getUser` as well - so the guard narrows a provider
 * that has one of the two required members to a type that promises both, and
 * `provider.getUser(id)` then typechecks and is `undefined` at runtime. This is
 * the same optimism `withSession` documents for `isSessionProvider`, and it gets
 * the same answer: install everything the interface requires, so a fake cannot
 * let a host pass a test it should fail.
 *
 * `getCurrentUser` recognizes the same credentials `authenticateToken` does -
 * the bearer token in `Authorization`, and the fake's session cookie - because
 * the two are two views of one signed-in person. A fake whose user path
 * answered somebody else, or answered somebody for a request carrying no
 * credentials at all, would be a fake modelling a defect rather than a
 * provider.
 */
export function withUser<T extends FakeProvider>(provider: T, options: FakeUserOptions = {}): T & FakeUserCapability {
  const { calls, user, tokens } = provider;
  const accepted = new Set(tokens);
  const directory = new Map<string, FakeUser>([
    [user.id, user],
    ...(options.directory ?? []).map((entry): [string, FakeUser] => [entry.id, entry]),
  ]);

  function presents(request: Request): boolean {
    let authorization: string | null;
    try {
      authorization = getRequestHeader(request, 'authorization');
    } catch {
      authorization = null;
    }
    const bearer = typeof authorization === 'string' ? authorization.replace(/^Bearer\s+/i, '') : '';
    if (bearer !== '' && accepted.has(bearer)) return true;
    return cookieValues(request).some(value => accepted.has(value));
  }

  const capability: FakeUserCapability = {
    async getCurrentUser(request) {
      calls.record('getCurrentUser', request);
      return presents(request) ? user : null;
    },

    async getUser(userId) {
      calls.record('getUser', userId);
      return directory.get(userId) ?? null;
    },
  };

  return { ...provider, ...capability };
}

/** Options for {@link withOrganizations}. */
export interface FakeOrganizationsOptions {
  /**
   * The organization id `ensureOrganization` returns, for every user.
   *
   * Defaults to the fake's own `user.organizationId`, and then to
   * `` `org_${userId}` `` - so the id a host reads off the identity and the id it
   * gets from `ensureOrganization` agree by default, which is the state a real
   * deployment is in.
   */
  organizationId?: string;

  /**
   * What `isOrganizationAdmin` answers.
   *
   * Defaults to answering `true` for the organization this fake bootstraps for
   * that user, and `false` for every other id - which is the answer a correct
   * provider gives and is not the same thing as `true`. A fake that answered
   * `true` for any id at all would model a provider handing out administrator
   * rights over an organization it has never heard of, and `organizations/is-
   * admin` exists to find exactly that.
   *
   * Pass `true` to build that provider on purpose.
   */
  admin?: boolean | ((organizationId: string, userId: string) => boolean);
}

/** What {@link withOrganizations} adds. Satisfies `isOrganizationsProvider`. */
export type FakeOrganizationsCapability = IOrganizationsProvider;

/**
 * Add `ensureOrganization` and `isOrganizationAdmin`.
 *
 * `ensureOrganization` is deterministic: the same `userId` gets the same id on
 * every call, for the lifetime of the process and across processes, because it
 * is derived rather than generated. The contract requires idempotence under
 * concurrent first logins and a fake that minted a fresh id per call would let a
 * host pass a test it should fail.
 *
 * THE `organizationId` OBLIGATION LIVES HERE
 *
 * A fake built with `violates: 'organizationId'` still satisfies
 * `isOrganizationsProvider` - the guard passes, the descriptor says
 * `organizations: true` - and `ensureOrganization` resolves `undefined`, with no
 * `organizationId` on the authenticated payload either. That is the sharp case:
 * the capability is declared and the obligation is unmet, which no structural
 * guard can tell you. The explicit `organizationId` option does not override the
 * violation; the violation is the point of that fake.
 */
export function withOrganizations<T extends FakeProvider>(
  provider: T,
  options: FakeOrganizationsOptions = {},
): T & FakeOrganizationsCapability {
  const { calls, violates, user } = provider;
  const configured = options.organizationId ?? user.organizationId;
  const bootstrapped = (userId: string): string => configured ?? `org_${userId}`;
  // Not `true`. See `admin` on the options: an id this fake never bootstrapped
  // belongs to somebody else, and the honest answer about somebody else's
  // organization is `false`.
  const admin = options.admin ?? ((organizationId: string, userId: string) => organizationId === bootstrapped(userId));

  const capability: FakeOrganizationsCapability = {
    async ensureOrganization(userId) {
      calls.record('ensureOrganization', userId);
      if (violates === 'organizationId') return undefined;
      return bootstrapped(userId);
    },

    async isOrganizationAdmin(organizationId, userId) {
      calls.record('isOrganizationAdmin', organizationId, userId);
      return typeof admin === 'function' ? admin(organizationId, userId) : admin;
    },
  };

  return { ...provider, ...capability };
}

/** Options for {@link withSession}. */
export interface FakeSessionOptions {
  /**
   * The cookie `getSessionIdFromRequest` reads and `getSessionHeaders` writes.
   * Defaults to {@link FAKE_COOKIE_NAME}.
   */
  cookieName?: string;

  /** How long a session lives, in milliseconds. Defaults to one hour. */
  ttlMs?: number;

  /**
   * The clock. Defaults to `Date.now`.
   *
   * Injectable so a test can expire a session without waiting for one: hand back
   * a value past `expiresAt` and `validateSession` answers `null`.
   */
  now?: () => number;
}

/** What {@link withSession} adds. Satisfies `isSessionProvider`. */
export type FakeSessionCapability = ISessionProvider<FakeSession> & {
  /** The live session store, for a test that wants to assert on it directly. */
  sessions(): ReadonlyMap<string, FakeSession>;
};

/**
 * Add a working in-memory session store, all seven `ISessionProvider` members.
 *
 * All seven, deliberately. `isSessionProvider` tests only `createSession` and
 * `validateSession`, so the guard is optimistic - a provider can pass it with no
 * `destroySession` at all, which is exactly why `toAuthDescriptor` checks
 * `refreshSession` and `destroySession` as methods rather than trusting the
 * guard. A fake that installed only the two the guard reads would let a host's
 * "sign out everywhere" pass against a provider that cannot do it.
 *
 * Session ids are `fake-session-1`, `fake-session-2`, ... in creation order, so
 * an assertion can name one.
 */
export function withSession<T extends FakeProvider>(
  provider: T,
  options: FakeSessionOptions = {},
): T & FakeSessionCapability {
  const { calls } = provider;
  const cookieName = options.cookieName ?? FAKE_COOKIE_NAME;
  const ttlMs = options.ttlMs ?? 60 * 60 * 1000;
  const now = options.now ?? Date.now;
  const store = new Map<string, FakeSession>();
  let issued = 0;

  /** Expired sessions are dropped on read rather than swept, as a real store would. */
  function live(sessionId: string): FakeSession | null {
    const session = store.get(sessionId);
    if (session === undefined) return null;
    if (session.expiresAt.getTime() <= now()) {
      store.delete(sessionId);
      return null;
    }
    return session;
  }

  const capability: FakeSessionCapability = {
    sessions: () => new Map(store),

    async createSession(userId, metadata) {
      calls.record('createSession', userId, metadata);
      issued += 1;
      const at = now();
      const session: FakeSession = {
        id: `fake-session-${issued}`,
        userId,
        createdAt: new Date(at),
        expiresAt: new Date(at + ttlMs),
        metadata,
      };
      store.set(session.id, session);
      return session;
    },

    async validateSession(sessionId) {
      calls.record('validateSession', sessionId);
      return live(sessionId);
    },

    async destroySession(sessionId) {
      calls.record('destroySession', sessionId);
      store.delete(sessionId);
    },

    async refreshSession(sessionId) {
      calls.record('refreshSession', sessionId);
      const session = live(sessionId);
      if (session === null) return null;
      const refreshed: FakeSession = { ...session, expiresAt: new Date(now() + ttlMs) };
      store.set(sessionId, refreshed);
      return refreshed;
    },

    getSessionIdFromRequest(request) {
      calls.record('getSessionIdFromRequest', request);
      return cookieValues(request, cookieName)[0] ?? null;
    },

    getSessionHeaders(session) {
      calls.record('getSessionHeaders', session);
      return { 'Set-Cookie': `${cookieName}=${session.id}; Path=/; HttpOnly; SameSite=Lax` };
    },

    getClearSessionHeaders() {
      calls.record('getClearSessionHeaders');
      return { 'Set-Cookie': `${cookieName}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` };
    },
  };

  return { ...provider, ...capability };
}

/** Options for {@link withInit}. */
export interface FakeInitOptions {
  /**
   * Called with the context on every `init`.
   *
   * Throw from it to model a provider that fails fast at prepare time, which is
   * what the hook is documented for and the case a host's startup path has to
   * survive.
   */
  onInit?: (ctx: AuthInitContext) => void | Promise<void>;
}

/** What {@link withInit} adds. Satisfies `hasAuthInit`. */
export type FakeInitCapability = IAuthInit;

/**
 * Add the one-time `init` hook.
 *
 * The context it was handed is in the call log - `calls.last('init')?.args[0]` -
 * which is how a test asserts that the host passed its `publicUrl` and
 * `allowedOrigins` through rather than dropping them. `calls.count('init')` is
 * how it asserts the host called it exactly once.
 */
export function withInit<T extends FakeProvider>(provider: T, options: FakeInitOptions = {}): T & FakeInitCapability {
  const { calls } = provider;

  const capability: FakeInitCapability = {
    async init(ctx) {
      calls.record('init', ctx);
      await options.onInit?.(ctx);
    },
  };

  return { ...provider, ...capability };
}

// ============================================================================
// The fully-capable fake, and the four broken ones
// ============================================================================

/** Every capability at once. What {@link fullyCapableFake} returns. */
export type FullyCapableFake = FakeProvider &
  FakeSSOCapability &
  FakeCredentialsCapability &
  FakeHttpHandlerCapability &
  FakeUserCapability &
  FakeOrganizationsCapability &
  FakeSessionCapability &
  FakeInitCapability;

/** Options for {@link fullyCapableFake} and {@link fakeViolating}. */
export interface FullyCapableFakeOptions extends FakeProviderOptions {
  /** Passed to {@link withSSO}. */
  sso?: FakeSSOOptions;
  /** Passed to {@link withCredentials}. */
  credentials?: FakeCredentialsOptions;
  /** Passed to {@link withHttpHandler}. */
  httpHandler?: FakeHttpHandlerOptions;
  /** Passed to {@link withUser}. */
  users?: FakeUserOptions;
  /** Passed to {@link withOrganizations}. */
  organizations?: FakeOrganizationsOptions;
  /** Passed to {@link withSession}. */
  session?: FakeSessionOptions;
  /** Passed to {@link withInit}. */
  init?: FakeInitOptions;
}

/**
 * Every mixin applied, every obligation met.
 *
 * The provider a conformance suite has to be green against. If a check goes red
 * here, the check is wrong - which is the half of "does this suite work" that
 * {@link fakeViolating} cannot answer.
 */
export function fullyCapableFake(options: FullyCapableFakeOptions = {}): FullyCapableFake {
  return withInit(
    withSession(
      withOrganizations(
        withUser(
          withHttpHandler(
            withCredentials(withSSO(fakeProvider(options), options.sso), options.credentials),
            options.httpHandler,
          ),
          options.users,
        ),
        options.organizations,
      ),
      options.session,
    ),
    options.init,
  );
}

/**
 * The same fake, correct except for one obligation.
 *
 * ```ts
 * const provider = fakeViolating('cookieAuth');
 * await provider.authenticateToken('', requestWithSessionCookie); // null
 * await provider.authenticateToken(FAKE_TOKEN, request); // still works
 * isSSOProvider(provider); // still true - every capability is still declared
 * ```
 *
 * This is the shape a conformance suite has to have available for each of
 * {@link AUTH_OBLIGATIONS}: a provider that passes all seven structural guards,
 * meets three of the four obligations, and fails the fourth - so a check going
 * red is evidence about that obligation and nothing else. Without it, a suite
 * that never fails and a suite that cannot fail look identical.
 *
 * What each value changes, and nothing else changes:
 *
 * - `flatId` - `authenticateToken` returns `{ profile: { id }, ... }`, so
 *   `toAuthIdentity` resolves `null`. `mapUserToResourceId` follows, because it
 *   goes through the same normalizer.
 * - `cookieAuth` - `authenticateToken` ignores the `Cookie` header, so an empty
 *   bearer token authenticates nobody however good the cookie is.
 * - `stateCodec` - `getLoginUrl` echoes `state` in a format of the provider's
 *   own, and `handleCallback` rejects a `state` in this package's format.
 * - `organizationId` - `ensureOrganization` resolves `undefined` and the
 *   authenticated payload carries no `organizationId`, while
 *   `isOrganizationsProvider` still passes.
 */
export function fakeViolating(obligation: AuthObligation, options: FullyCapableFakeOptions = {}): FullyCapableFake {
  return fullyCapableFake({ ...options, violates: obligation });
}

// ============================================================================
// Compile-time proofs
// ============================================================================

/**
 * Fails to compile unless `T` is `true`. The mechanism behind
 * {@link FakeGuardNarrowing}.
 */
type Proves<T extends true> = T;

/**
 * Proof that each mixin's return type is the interface its guard narrows to, and
 * that the base fake's is not.
 *
 * This has to live in a `.ts` file that `tsc --noEmit` reads, and a test is not
 * one: `tsconfig.json` excludes every `.test.ts`, and vitest transpiles without
 * typechecking, so a type-level assertion written in `src/__tests__/` would be
 * checked by nothing at all.
 *
 * The negative half is the load-bearing one. That `withSSO(fakeProvider())` is
 * assignable to `ISSOProvider` matters much less than that `fakeProvider()` is
 * not - if the base fake satisfied every capability interface structurally, a
 * consumer could pass "SSO but no organizations" into a position needing
 * organizations and find out at runtime, which is the whole failure this kit
 * exists to move to compile time.
 *
 * Exported because it is API: a consumer reading these lines learns what the
 * mixins promise. It has no runtime form.
 */
export type FakeGuardNarrowing = {
  sso: Proves<FakeSSOCapability extends ISSOProvider ? true : false>;
  credentials: Proves<FakeCredentialsCapability extends ICredentialsProvider ? true : false>;
  httpHandler: Proves<FakeHttpHandlerCapability extends IAuthHttpHandler ? true : false>;
  users: Proves<FakeUserCapability extends IUserProvider ? true : false>;
  organizations: Proves<FakeOrganizationsCapability extends IOrganizationsProvider ? true : false>;
  session: Proves<FakeSessionCapability extends ISessionProvider ? true : false>;
  init: Proves<FakeInitCapability extends IAuthInit ? true : false>;

  /** The base contract is satisfied, so a fake can go anywhere a provider can. */
  baseIsAProvider: Proves<FakeProvider extends IMastraAuthProvider ? true : false>;

  /** ...and no capability is, so every capability a test sees is one it added. */
  baseIsNotSSO: Proves<FakeProvider extends ISSOProvider ? false : true>;
  baseIsNotCredentials: Proves<FakeProvider extends ICredentialsProvider ? false : true>;
  baseIsNotHttpHandler: Proves<FakeProvider extends IAuthHttpHandler ? false : true>;
  baseIsNotUser: Proves<FakeProvider extends IUserProvider ? false : true>;
  baseIsNotOrganizations: Proves<FakeProvider extends IOrganizationsProvider ? false : true>;
  baseIsNotSession: Proves<FakeProvider extends ISessionProvider ? false : true>;
  baseIsNotInit: Proves<FakeProvider extends IAuthInit ? false : true>;

  /** Composition keeps both: the fully-capable fake is still the base contract. */
  fullIsAProvider: Proves<FullyCapableFake extends IMastraAuthProvider ? true : false>;
  fullIsSSO: Proves<FullyCapableFake extends ISSOProvider ? true : false>;
  fullIsCredentials: Proves<FullyCapableFake extends ICredentialsProvider ? true : false>;
  fullIsHttpHandler: Proves<FullyCapableFake extends IAuthHttpHandler ? true : false>;
  fullIsUser: Proves<FullyCapableFake extends IUserProvider ? true : false>;
  fullIsOrganizations: Proves<FullyCapableFake extends IOrganizationsProvider ? true : false>;
  fullIsSession: Proves<FullyCapableFake extends ISessionProvider ? true : false>;
  fullIsInit: Proves<FullyCapableFake extends IAuthInit ? true : false>;
};

// ============================================================================
// Internals
// ============================================================================

/** Accepted tokens, as a list, with blanks dropped. See {@link FakeProviderOptions.token}. */
function normalizeTokens(token: FakeProviderOptions['token']): readonly string[] {
  const raw = token === undefined ? [FAKE_TOKEN] : typeof token === 'string' ? [token] : [...token];
  return raw.filter(value => value.length > 0);
}

/**
 * Every cookie value in a request's `Cookie` header, optionally filtered by name.
 *
 * Never throws. The header is read through the contract's `getRequestHeader`,
 * which calls `request.header(name)` on anything that is not a `Request` - and a
 * fixture that is only `{ headers }` has no such method. A test double turning
 * that into a stack trace from inside itself would send whoever wrote the fixture
 * looking in the wrong place.
 */
function cookieValues(request: MastraAuthRequest, cookieName?: string): string[] {
  let header: string | null;
  try {
    header = getRequestHeader(request, 'cookie');
  } catch {
    return [];
  }
  if (typeof header !== 'string' || header.length === 0) return [];

  const values: string[] = [];
  for (const pair of header.split(';')) {
    const separator = pair.indexOf('=');
    if (separator === -1) continue;
    const name = pair.slice(0, separator).trim();
    const value = pair.slice(separator + 1).trim();
    if (value.length === 0) continue;
    if (cookieName !== undefined && name !== cookieName) continue;
    values.push(value);
  }
  return values;
}

/**
 * Re-encode a `state` into a format this package's codec does not read.
 *
 * A querystring rather than random noise, because that is what providers that
 * mint their own `state` actually emit, and because both halves stay legible in
 * a failure message. `parseStateId` finds no {@link FAKE_STATE_DELIMITER} in it
 * and hands back the whole string, which is not the id that went in; `decodeState`
 * finds no destination and falls back to `/`.
 */
function toForeignState(state: string): string {
  const separator = state.indexOf(FAKE_STATE_DELIMITER);
  if (separator === -1) return `state=${state}`;
  return `state=${state.slice(0, separator)}&returnTo=${state.slice(separator + 1)}`;
}

/** Did {@link toForeignState} produce this? */
function isForeignState(state: string): boolean {
  return state.startsWith('state=');
}
