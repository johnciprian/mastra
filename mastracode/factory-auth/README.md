# @mastra/factory-auth

Tools for making an auth provider work with the Mastra Factory. The package holds the provider
contract, an identity normalizer, a capability descriptor, a signed session cookie, an OAuth `state`
codec, test fakes, and a conformance suite you run in your own package's CI.

Use it when you're writing or adapting a provider. You don't need it to _use_ a provider that
already works.

This package targets the Mastra Factory. Providers that only gate `/api/*` need `@mastra/core/server`
and nothing here.

## What this isn't

- Not an auth provider. It never talks to an identity system, and it contains no vendor code.
- Not a replacement for `@mastra/core/server`. It re-exports that contract and adds the parts the
  Factory needs on top of it.
- Not enterprise code, and it can't call any. See [The EE boundary](#the-ee-boundary).
- Not role-based access control, fine-grained authorization, or licence checks. Those live in the
  enterprise packages and stay there.

## Start here

Four things decide whether a provider can run the Factory. No interface states them and nothing
stated them before this package. The conformance suite checks all four.

1. `authenticateToken` returns a payload with a flat, resolvable id — `id`, `uid` or `sub`, read in
   that order.
2. `authenticateToken` reads the `Cookie` header when the bearer token is empty. A browser
   navigation sends no `Authorization` header, so an empty token means "read the cookie".
3. Login and callback both use `encodeState` and `decodeState` from this package.
4. Every identity resolves to an organization id, from the provider or from a wrapper.

```ts
import { MastraAuthProvider, getRequestHeader } from '@mastra/factory-auth';
import type { MastraAuthRequest } from '@mastra/factory-auth';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';

type Claims = { sub: string; email?: string };

class MyOidcProvider extends MastraAuthProvider<Claims> {
  constructor(private verify: (token: string) => Promise<Claims | null>) {
    super({ name: 'my-oidc' });
  }

  async authenticateToken(token: string, request: MastraAuthRequest) {
    // 2. An empty token means a browser sent this, so look where a browser puts one.
    const cookies = getRequestHeader(request, 'cookie') ?? '';
    const bearer = token || (/(?:^|;\s*)my_session=([^;]*)/.exec(cookies)?.[1] ?? '');
    if (!bearer) return null;
    return this.verify(bearer); // 1. `sub` is one of the keys toAuthIdentity reads.
  }

  authorizeUser() {
    return true;
  }
}

// 4. Wrapping is the one-line way to satisfy the organization obligation.
export const createAuth = (verify: (token: string) => Promise<Claims | null>) =>
  withSyntheticOrganizations(new MyOidcProvider(verify));
```

Taking the verifier as an argument rather than building one inside the class is worth doing for its
own sake: it is what lets the [conformance suite](#run-the-conformance-suite) run your provider
offline, with no identity provider and no environment variables.

Then run the suite. It fails with the name of whichever obligation you missed, the call it made, and
the fix as code.

## The EE boundary

This package is Apache-2.0. Its module graph must not contain any file under an `ee/` directory, at
any depth, including through a dependency.

One import decides it. `@mastra/core/auth` is banned outright, not only `@mastra/core/auth/ee`: its
barrel re-exports `./ee`, and that module runs code as it loads. `@mastra/core/server` is safe, and
it re-exports the contract interfaces and the guards by name. Import from `@mastra/core/server`, and
only through `src/contract.ts`.

The ban is wider than the two obvious paths, because three Apache-2.0 specifiers reach enterprise
code without naming it. Measured on this tree, in the runtime graph:

Each row is that specifier walked on its own, so the numbers do not include this package's files.

| Specifier                            | Modules | Inside `ee/` |
| ------------------------------------ | ------: | -----------: |
| `@mastra/core/server`                |      19 |        **0** |
| `@mastra/core/auth`                  |      22 |       **11** |
| `@mastra/core` (root barrel)         |     713 |       **14** |
| `@mastra/auth-workos` (any provider) |       - |       **11** |

`@mastra/core` names no `ee` path anywhere, yet its graph reaches enterprise code through
`packages/core/src/tools/tool-builder/builder.ts`, which imports the runtime value
`MastraFGAPermissions` from `../../auth/ee`. Tree-shaking will not drop it. The provider packages get
there through their own FGA and RBAC providers.

Two checks enforce this:

- ESLint and oxlint `no-restricted-imports` fail on a banned specifier in this package's source. Both
  linters carry the rule, because `lint` is `oxlint . && eslint .` and lint-staged runs oxlint first.
- `src/__tests__/no-ee-boundary.test.ts` resolves the module graph and fails on any module inside an
  `ee/` directory, on any external specifier outside a fail-closed allowlist, and on any enterprise
  identifier in built output.

Lint reads source and runs without a build. The test catches what a dependency drags in, so it still
holds after a version bump. Neither is sufficient alone.

Consuming this package puts you under none of this. The boundary is a promise the package makes to
you, not a constraint it passes on — see [Stability and versioning](#stability-and-versioning). How
the two checks are kept honest is in [Contributing](#contributing).

## Run the conformance suite

You publish a provider from your own repository and want to know whether it can run the Factory.
Three lines of setup answer that, offline.

`vitest` is an **optional** peer dependency of this package, so your package manager will not install
it for you. `./conformance` is the only entry point that imports it; every other one is runner-free.

```shell
pnpm add -D @mastra/factory-auth vitest
```

Add one test file. It needs no network, no identity provider and no environment variables — the
provider your factory returns has to authenticate the `token` fixture on its own, which is the same
injected-verifier setup your unit tests already need.

```ts
// src/conformance.test.ts
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { createAuth } from './auth-provider.js';

const TOKEN = 'a-token-my-verifier-accepts';

describeAuthProvider({
  name: '@mastra/auth-my-provider',
  createProvider: () => createAuth(async token => (token === TOKEN ? { sub: 'user_123' } : null)),
  token: TOKEN,
  userId: 'user_123',
  cookieHeader: `my_session=${TOKEN}`,
});
```

Three options are required — `name`, `createProvider` and `token` — because they are the three facts
no guard can derive. Everything else defaults. Two have no default on purpose:

- **`cookieHeader`**, the header a signed-in browser sends. Required once your provider can put a
  session in a browser, which is obligation 2's gate. A suite that guessed a cookie name would report
  the guess missing as an obligation failure, and a false red looks exactly like a true one.
- **`sso.reachedTokenExchange`**, only if your token exchange does not go through global `fetch`.
  The suite replaces `fetch` to make "reached the network" observable; an SDK holding its own agent
  needs to tell it what that looks like.

You do not need it for the commoner case of a `handleCallback` that reaches the exchange and then
rethrows a flat error of its own. The suite counts calls to the stubbed `fetch` during
`handleCallback`, so it can see that the state was accepted even when nothing in the `cause` chain
says so. That check still fails — something is wrong and the suite cannot see what — but it tells
you the truth about it and asks for the one-argument fix,
`new Error('...', { cause: error })`, rather than blaming a `state` you never rejected.

Run it with vitest:

```shell
pnpm vitest run src/conformance.test.ts
```

The provider above answers with:

```
 Test Files  1 passed (1)
      Tests  8 passed | 11 skipped (19)
```

Eleven skipped is the normal shape of a first run, not a warning. Add `--reporter=verbose` to see one
`describe` per section, one `it` per check, and the reason attached to every skip:

```
 ✓ src/conformance.test.ts > auth provider conformance: @mastra/auth-my-provider > the base contract
     > implements IMastraAuthProvider
 ✓ ... > obligation 1 of 4 - flatId > authenticateToken resolves to an identity with a non-empty id
 ↓ ... > obligation 2 of 4 - cookieAuth > authenticateToken reads the Cookie header when the bearer
     token is empty [This provider cannot put a session in a browser: no hosted login, no credentials
     sign-in, no server-side sessions, and no auth routes of its own. ...]
 ✓ ... > obligation 4 of 4 - organizationId > satisfies isOrganizationsProvider, on its own or
     through the wrapper
```

**Skipped, never quietly passed.** A check is skipped only when a structural guard says the provider
does not _declare_ the capability the check is about, and the skip carries the reason, as above. It
is never skipped because a provider declared a capability and then did not deliver it.

Obligation 2 is skipped in that run, and the reason is worth reading rather than scrolling past. The
provider is a pure bearer-token validator — no hosted login, no credentials sign-in, no server-side
sessions, no auth routes — so a browser never holds a session for it and there is no cookie to read.
That is a supported shape, and the `cookieHeader` fixture goes unused until the provider grows one of
those four capabilities. The moment it does, the check applies and the fixture is required.

Obligation 4 is the exception, deliberately: it is not gated on `isOrganizationsProvider`, because
gating it there would skip the only check that notices. A provider without organizations fails it and
is told the one-line fix:

```
AssertionError: Auth conformance violation: @mastra/auth-my-provider does not meet obligation 4 of 4,
'organizationId'.

  This provider resolves no organization: isOrganizationsProvider(provider) is false.

OBSERVED
  isOrganizationsProvider(provider) is false.
    provider.ensureOrganization  is undefined
    provider.isOrganizationAdmin is undefined
  ...

WHY THIS EXISTS
  Every organization-scoped surface in the Factory writes to one column that is not nullable. ...

HOW TO FIX IT
  If your provider has no organizations, wrap it once. ...

    import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';

    export const auth = withSyntheticOrganizations(new MyProvider());
  ...
```

Every failure carries those four parts and a docs link. If you would rather run the checks from a
script, a different runner, or a CLI, `authConformanceChecks(options)` returns the same list as data
and takes no dependency on vitest to iterate. `runAuthConformanceCheck(check, provider, name)` runs
one and hands back what happened — it is the same function `describeAuthProvider` calls, so an
adapter you write behaves identically to the vitest one, known failures included.

### If your provider does PKCE

`sso/pkce-round-trip` is the one check that drives a whole flow rather than a single method, and it
is worth knowing what it asks before you see it.

A PKCE provider stashes its code verifier in a cookie on the login redirect and needs it back to
complete the token exchange. `ISSOProvider` has both halves of that: `getLoginCookies(redirectUri,
state)` returns `Set-Cookie` values on the way out, and `setCallbackCookieHeader(cookieHeader)`
receives the callback request's `Cookie` header on the way back, before `handleCallback` runs.
`handleCallback` is handed only `code` and `state`, so the read half is the only channel there is.

The check plays the browser and the identity provider. It calls `getLoginUrl`, collects what
`getLoginCookies` hands back, turns those into the `Cookie` header a browser would send, feeds it
through `setCallbackCookieHeader`, and then calls `handleCallback` with **the `state` your own
authorization URL carries** — the way a real identity provider echoes back what it was sent. If the
call reaches the token exchange, the verifier survived the trip and the check passes.

Echoing your own `state` rather than the host's is deliberate: whether the host's `state` survives
is `obligation/stateCodec/login-url`'s question, and a provider that re-encodes it would otherwise
fail here too, under a message about cookies.

Three outcomes, and the middle one is the one to read twice:

- **Skipped** when you do not implement `getLoginCookies`. You set no cookie at login, so nothing
  has to come back. A confidential client authenticating with `client_secret` is exactly that shape.
- **Passed, having asked nothing further**, when you implement `getLoginCookies` and it returns
  `undefined` or `[]` for this login. The check applied and ran; there was no cookie to hold you to.
- **Failed** when you set a cookie and either declare no `setCallbackCookieHeader`, or declare one
  and the value does not come back. Declaring both is not enough — a read half that stores nothing
  satisfies every structural guard and delivers nothing, which is the shape this check exists to
  catch.

The same cookie hand-back happens before `obligation/stateCodec/callback` too, so a correct PKCE
provider is not told it "rejected a state" about a call that threw for a missing verifier.

### If your provider implements IUserProvider

Two checks, and between them they cover a gap in the guard you are probably relying on.

`isUserProvider` tests both members `IUserProvider` requires, so a provider carrying one of them
fails the guard — and a host branching on it treats that provider as having no user directory at all,
silently losing the half it did implement. Half an interface is a defect either way: before the guard
was narrowed the cost was a run-time `auth.getUser is not a function` inside the host; now it is a
capability that quietly disappears.

That is why this section gates on carrying **either** member rather than on the guard, and why
`users/get-user` and `users/current-user` each report their own member missing as a **failure**
rather than skipping. Gating on the guard would skip exactly the provider these checks are looking
for. A provider with neither member skips, because that is a decision rather than an unfinished job.

`users/current-user` asks whether your two identity paths agree. It sends one request carrying every
credential the suite holds — the bearer token, and your `cookieHeader` if you supplied one — and
compares what `getCurrentUser` resolves against the id `authenticateToken` resolves for the same
credential. Hosts use both: enforcement goes through `authenticateToken`, and the profile on screen
comes out of `getCurrentUser`. When they disagree, somebody is shown one identity while their work is
stored under another, and nothing anywhere reports an error. It then asks a second time with a
request carrying **nothing at all**, which must not resolve a user — a `currentUser` cached on a
long-lived provider instance answers that one, and then every visitor is the last person to sign in.

Neither check demands a non-`null` answer. `null` is what the interface documents for a user who is
not found, and a provider whose directory needs a live vendor cannot answer offline: six of the nine
`IUserProvider` implementations in this repository resolve `null` from `getUser` under conformance
and pass. What is checked is that an answer you _do_ give names the person who was asked about.

### If your provider implements IOrganizationsProvider

`organizations/is-admin` is the only check in this suite whose wrong answer hands somebody rights
over another user's data, so it is worth knowing exactly what it demands and what it does not.

It asks twice. First about the organization your own `ensureOrganization` just returned, where the
requirement is only that you answer a **literal boolean** without throwing. Answering `false` there
is fine — `@mastra/auth-studio` does, on a cold cache, because it cannot know the role yet and says
no. A check that demanded `true` would turn every fail-closed provider red and teach exactly the
wrong fix.

Then it asks about `conformance-organization-nobody-created`, an id the suite invented. `true` is a
failure. Organization ids arrive from requests, which means they arrive from whoever made the
request, and a provider that answers `true` for ids it does not recognize turns "guess an
organization id" into an administrator role in it. The usual cause is not a decision to fail open —
it is a membership lookup that finds no row and falls through to a default, or a check that asks "is
this user an admin anywhere" and ignores the organization it was handed. Throwing for that id is a
failure too: `IOrganizationsProvider` says provider errors here should resolve to `false`, and a
host cannot tell a throw apart from a refusal.

If your provider has no organizations of its own, `withSyntheticOrganizations` passes this check by
construction — it answers for ids in its own namespace itself, in both directions, and never
delegates them.

## When your provider doesn't conform and ships anyway

Some defects are real and the fix isn't small. A `validateSession` that returns `null` because the
whole `ISessionProvider` half is a set of no-ops, a `getLoginUrl` that drops `state` — these have
product consequences and they don't get fixed in the PR that turned conformance on.

Once conformance runs in CI, that leaves three moves, and all three end with nobody knowing the
provider is broken: weaken the suite until it passes, leave the build red until people stop reading
it, or drop the provider from the run.

`knownFailures` is the fourth. Record the failure, name which one it is, and say why:

```ts
describeAuthProvider({
  name: '@mastra/auth-my-provider',
  createProvider: () => createAuth(verifier),
  token: TOKEN,
  userId: 'user_123',
  cookieHeader: `my_session=${TOKEN}`,
  knownFailures: [
    {
      check: 'sessions/round-trip',
      code: 'sessions/round-trip#validate-rejects-fresh-session',
      reason:
        'validateSession returns null unconditionally; the ISessionProvider members are no-ops ' +
        'kept for interface compatibility. Full diagnosis in this file’s header. Tracked in #4821.',
    },
  ],
});
```

The suite goes green, and it is visibly not the green of a clean provider. Run it and you get the
test title prefixed, a line on `stderr` that the default reporter prints with the test name attached,
and the full report as the skip note:

```
stderr | conformance.test.ts > ... > known failure: a created session validates, and names the user ...
[factory-auth conformance] KNOWN FAILURE  @mastra/auth-my-provider  sessions/round-trip#validate-rejects-fresh-session
  validateSession returns null unconditionally; the ISessionProvider members are no-ops kept for ...
```

**Every field is required, and each one is load-bearing.**

- **`check`** is the check id. An id no check has fails at registration, listing the ids that do —
  loudly, because a typo that was quietly ignored would be indistinguishable from an exemption that
  works, and a renamed check must not leave a dead entry granting cover.
- **`code`** is _which way_ that check fails. Run the check once; the red quotes the code to paste.
  A check id alone would record only _that_ a check fails — `sessions/round-trip` has five ways to
  go red, and two providers can fail it for genuinely different defects. An entry keyed on the id
  alone would silently absorb the next, unrelated regression in the same check. Codes are stable
  identifiers this package owns, so they are the thing to key on rather than the message text, which
  is patch-level here and documented as not-to-be-asserted-on.
- **`reason`** is why it isn't fixed. A pointer plus a sentence, not an essay. An exemption with no
  stated reason is how four obligations went unwritten in the first place: everybody knew why at the
  time, and the knowledge left with them.

**It is not an exclusion, because it is checked in both directions on every run.** The suite fails
if a recorded check passes, if it stops applying, or if it fails under a different code. So fixing
the defect forces the entry to be deleted in the same change, and the list cannot quietly become
fiction.

A fault in the fixtures — a `token` the provider won't accept — is reported under a `fixture/`
namespace and can never be recorded. `knownFailures` grants a _provider_ an exemption; "the token I
told the suite to use doesn't work" isn't something to be exempt from.

**One thing it does not do.** An entry records the failure a check produces, not the defect behind
it. If one underlying defect can surface under two codes depending on inputs, recording one leaves
the other uncovered — you'll see it as a `failed for a different reason` red, which is the safe
direction but is still a red you have to think about rather than a case the kit resolves for you.

## What's in the package

| Import                               | Answers                                                    | Main exports                                                                        |
| ------------------------------------ | ---------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `@mastra/factory-auth`               | The pure layer: contract, identity, capabilities.          | everything from `./contract`, `./identity` and `./capabilities`                     |
| `@mastra/factory-auth/contract`      | The same contract symbols, narrower import.                | `MastraAuthProvider`, the seven guards, `getRequestHeader`, `getWebRequest`         |
| `@mastra/factory-auth/identity`      | What is this provider's user, in one shape?                | `toAuthIdentity`, `AuthIdentity`, `IIdentityProvider`, `isIdentityProvider`         |
| `@mastra/factory-auth/capabilities`  | Which capabilities does this provider have?                | `toAuthDescriptor`, `AuthDescriptor`                                                |
| `@mastra/factory-auth/organizations` | Which organization does this identity belong to?           | `withSyntheticOrganizations`, `resolveOrganizationId`, `syntheticOrganizationId`    |
| `@mastra/factory-auth/cookie`        | How does the host mint, read and clear its session cookie? | `mintSessionCookie`, `readSessionCookie`, `clearSessionCookie`, `sessionCookieName` |
| `@mastra/factory-auth/oauth-state`   | How is the OAuth `state` parameter encoded and decoded?    | `encodeState`, `decodeState`, `parseStateId`                                        |
| `@mastra/factory-auth/testing`       | Test doubles, for code that consumes a provider.           | `fakeProvider`, `fullyCapableFake`, `fakeViolating`, six `with*` mixins             |
| `@mastra/factory-auth/conformance`   | The suite, for code that implements a provider.            | `describeAuthProvider`, `authConformanceChecks`, `runAuthConformanceCheck`          |

`./capabilities` answers **which** capabilities a provider has. The capability interfaces themselves
are in `./contract`.

`./oauth-state` is the OAuth `state` parameter: a nonce plus where to return the user after login. It
has nothing to do with `FactoryAuthState` in the web app.

The root export holds the pure layer only, so a browser bundle can import it. `./cookie` and
`./oauth-state` are server-only. `./testing` and `./conformance` are test-time and are never
re-exported from the root: `./conformance` is the one module that imports vitest, which is why vitest
is an optional peer dependency.

### What `./contract` re-exports

Everything comes from `@mastra/core/server`, and nothing in this package imports that entry point
anywhere else.

- `MastraAuthProvider` — the base class a provider extends.
- Seven capability guards: `isSSOProvider`, `isSessionProvider`, `isUserProvider`,
  `isCredentialsProvider`, `isOrganizationsProvider`, `isAuthHttpHandler`, and `hasAuthInit`. Note
  the `has` prefix on the last one, and note there is no guard for `IMastraAuthProvider` — implementing
  the base contract is a precondition, not a capability. All seven are structural, so a plain object
  with the right methods satisfies them.
- The types: `IMastraAuthProvider`, `MastraAuthProviderOptions`, `AuthInitContext`, `IAuthHttpHandler`,
  `IAuthInit`, `ICredentialsProvider`, `IOrganizationsProvider`, `ISessionProvider`, `ISSOProvider`,
  `IUserProvider`.
- Framework-neutral request primitives: `getRequestHeader`, `getWebRequest`, and the types
  `MastraAuthRequest` and `HonoRequestLike`. They come from a core module with zero imports, and they
  are how `./cookie` reads a `Cookie` header without this package depending on `hono`.

Four symbols on `@mastra/core/server` are permanently off limits here: `MastraAuthConfig`, `ApiRoute`,
`ApiRouteHandler` and `StudioConfig`. Each is defined in terms of enterprise interfaces, and core rolls
those declarations into its emitted types, so re-exporting one would copy enterprise declaration text
into this package's published type surface. `src/__tests__/contract-surface.test.ts` asserts all four
stay out, of source and of `dist/`. A host application should import them from `@mastra/core/server`
at the point of use instead.

## Stability and versioning

This package re-exports a contract it does not own. `./contract` takes every symbol from
`@mastra/core/server` by specifier, and the published `dist/contract.d.ts` re-exports them the same
way, so the types your compiler sees resolve from the `@mastra/core` you installed rather than from a
copy frozen here. That is deliberate — a provider built against your core and a host built against
ours still agree about one contract — and most of the policy below follows from it.

`@mastra/core` is a peer dependency, ranged `>=1.61.0-0 <2.0.0-0`. `vitest` is an optional peer,
needed only by `./conformance`.

**What is covered.** The nine entry points in the `exports` map and every symbol they export.
Anything reached by a deep path into `dist/` is not; the exports map is the surface.

### What each bump means

**Patch** — a defect fixed with no change to a signature or a documented value. Conformance failure
text, skip reasons, and the wording of every error message in the package are patch-level and may
change at any time. Don't assert on them.

**Minor** — new exports, a new optional field, a widened input. Three widenings have a visible edge,
so they are named rather than left to be discovered:

- `toAuthIdentity` learning a new payload shape can only turn "this token names nobody" into an
  identity, never the reverse. If you rely on a particular payload resolving to `null`, implement
  `toIdentity` and say so; shape detection is not a denial mechanism.
- `toAuthDescriptor` gaining a `features` field, because `@mastra/core/server` gained a capability
  guard. Code that switches exhaustively over the descriptor sees a new case.
- The internal layout of the signed session cookie value. Those bytes are not part of the contract —
  only `readSessionCookie` ever reads what `mintSessionCookie` produced — but changing them signs
  everybody out once, so it ships as a minor with an upgrade note rather than as a patch. The cookie
  _name_ is part of the contract; ask `sessionCookieName(site)` rather than hardcoding it.

**Major** — a removed or renamed export, a narrowed input, a changed return type, and two things that
break you without being type errors:

- **A new conformance check that a currently conforming provider can fail.** A fifth obligation, a
  new check over a declared capability, or a tightened existing check turns CI red in a repository
  this package does not own, so it is filed as a major even though no signature moved. That holds
  however narrow the gate is: `sso/pkce-round-trip` skips for every provider that sets no login
  cookie, and it still shipped as a major, because "no provider in _this_ repository goes red" is a
  fact about this repository. `users/current-user`, `users/get-user` and `organizations/is-admin`
  shipped as a major on the same reasoning, and none of the eleven providers here goes red on them
  either. Loosening a check, adding a skip gate, or rewriting a message is a patch.
- **Removing or renaming a conformance failure code.** See below: a code is a value downstream
  suites hold, and a rename turns a valid `knownFailures` entry into a registration error.
- **A change to the synthetic organization id format.** `user:${userId}` is a storage key. Changing
  the prefix or the derivation orphans every row written under the old one, and nothing reports an
  error when it happens, so it is a major and it ships with a migration note.

### Recorded known failures are part of the contract

`knownFailures` is an exemption mechanism, so what it will and will not tolerate is a promise rather
than an implementation detail. Three things about it are stable:

- **The entry shape.** `{ check, code, reason }`, all three required and all three non-empty.
  Relaxing any of them is a minor; requiring a fourth field is a major.
- **The four semantics.** A recorded check that fails as recorded is reported and does not fail the
  suite. A recorded check that passes, that stops applying, or that fails under a different code
  fails the suite. An entry naming an unknown check or an unproduceable code fails at registration.
  Any of those going quiet is a defect here, not a convenience.
- **Failure codes are values, not prose.** `sessions/round-trip#validate-rejects-fresh-session` is
  the format: a check id, a `#`, and a slug. Downstream suites hold these strings, so removing or
  renaming one is a **major** — it turns a valid entry into a registration error in a repository
  this package does not own. Adding a code is a minor, and it has a visible edge worth naming: a
  check that gains a way to go red can start failing under a code an existing entry does not record,
  which surfaces as `failed for a different reason` rather than as silence. That direction is
  deliberate. The alternative is an entry that widens to cover a defect nobody recorded.

Codes in the `fixture/` namespace are the exception to all of it: they name a fault in the calling
test file rather than in the provider, no check declares them, and an entry may never record one.

Failure _text_ stays patch-level, as above. That is exactly why entries key on a code.

### What you may build on

Two wire formats are documented and are part of the contract:

- The OAuth `state` string: an id, a `|`, and a percent-encoded `returnTo`. Only the first `|` is
  significant, so a `returnTo` containing one round trips unchanged. Encoding `/agents/42` under the
  id `abc-123` gives `abc-123|%2Fagents%2F42`.
- The synthetic organization id: the prefix `user:` followed by the provider's user id, unchanged.
  `resolveOrganizationId({ id: '8f21ac' })` is `user:8f21ac`, in every process and every deploy.

The four obligation names are stable string literals — `flatId`, `cookieAuth`, `stateCodec`,
`organizationId`. `fakeViolating('cookieAuth')` and a filter over `authConformanceChecks` both key on
them, and `AUTH_OBLIGATIONS` is their order.

### What can change under you with no release here

The types of everything `./contract` re-exports. They resolve from your installed `@mastra/core`, so
a core release that adds an optional member to `ISSOProvider` reaches you the moment you update core,
with no version of this package involved. Within core 1.x that can only be additive; core's own
semver holds that line, and this package's peer range is how it is expressed.

If `@mastra/core` moves or removes a re-exported symbol, one file changes here — `src/contract.ts` —
and the release is a major with a narrowed peer range. There is no shim. A symbol that is gone from
core is gone from `./contract`, because the alternative is this package inventing a second definition
of a contract it does not own.

### The EE boundary is part of the contract

This is the one that reads like an implementation detail, so it is written as a promise instead:
**this package's runtime module graph contains no file under an `ee/` directory, and its published
types carry no enterprise declaration.** You may build on that. It is what makes it safe to take
`@mastra/factory-auth` into an Apache-2.0 codebase, and it is the reason the package exists in its
own directory rather than as a folder in a provider.

Two consequences, and they bind releases rather than describing them:

- **The boundary is never traded for a feature.** If a symbol can only be re-exported by pulling
  enterprise code into the graph, it is not re-exported, in any bump. `MastraAuthConfig`, `ApiRoute`,
  `ApiRouteHandler` and `StudioConfig` are out permanently, not pending. Import them from
  `@mastra/core/server` at the point of use in your host, which is not under this constraint.
- **A release that has to drop a re-export to keep the boundary is a major, and the boundary wins.**
  There is no version of this package that ships with `ee/` in its graph, so "keep the export" is not
  one of the available options.

If either check that enforces the boundary goes green when it should be red, that is a release
blocker rather than a bug to schedule. The procedure for proving they still fail is in
[Contributing](#contributing).

### Before 1.0

The package is `0.x`. Breaking changes are filed as `major` changesets and carry upgrade notes, but
`0.x` does not give you semver's compatibility promise across minor versions, so read the changelog
before you bump. Nothing here is marked experimental and nothing is behind a flag: the nine entry
points are the whole published surface, and the policy above is what they are held to.

## Session cookies, and what they do not cover

`./cookie` mints and reads one signed, `HttpOnly` cookie under a name it declares. Two things about
it are worth knowing before you deploy.

**The cookie name depends on your deployment shape.** In the default configuration the name is
`__Host-mastra_factory_session`. The `__Host-` prefix makes a browser refuse to store the cookie
unless it is `Secure`, carries no `Domain`, and has `Path=/`, which means it can only have been set
by your exact host over HTTPS. That is what stops a page on a sibling subdomain from setting a
same-named cookie of its own on the shared parent domain and having the browser send both.

Setting `domain`, setting a `path` other than `/`, or setting `secure: false` for local HTTP each
make the prefix illegal, and those deployments get the plain `mastra_factory_session` instead — along
with the exposure the prefix removes. Ask `sessionCookieName(site)` rather than hardcoding either.

If the browser does send two cookies with our name that both verify to different values,
`readSessionCookie` returns `null` rather than choosing between them. Send `clearSessionCookie` when
you see that: choosing by position would hand the choice to whoever controls the header order.

**Cross-site deployments need their own CSRF defence, and this package does not ship one.** A
`crossSite: true` deployment gets `SameSite=None`, because `Lax` is not sent on a cross-site request
at all and the user would appear signed out on every call. `SameSite=None` means the browser attaches
the cookie to requests your site did not initiate, which is the condition CSRF needs.

Same-site deployments get `SameSite=Lax`, which is a meaningful defence on its own: the cookie is not
sent on a cross-site `POST`. Cross-site deployments have no such default and must add one. The usual
choices, in rough order of preference:

- Check the `Origin` header on every state-changing request against an allowlist you configure, and
  reject the request when it is absent or unrecognised. Cheapest, and enough for most APIs.
- Require a header a form post cannot set — an `Authorization` bearer token, or a custom header your
  SPA always sends. A cross-site form cannot add either, and a cross-site `fetch` that tries is
  stopped by CORS preflight.
- A double-submit or synchroniser token, if you already have somewhere to keep one.

Do this in the host, not in a provider. Nothing in this package inspects `Origin`, and a future
version that did would still not know your allowlist.

## Contributing

> Everything below is about how this package is maintained. If you are writing or integrating a
> provider, the sections above are the whole story.

Development happens in the `mastra-ai/mastra` monorepo, under `mastracode/factory-auth`.

```shell
pnpm install
pnpm turbo build --filter ./mastracode/factory-auth
pnpm --filter ./mastracode/factory-auth test
pnpm --filter ./mastracode/factory-auth lint
```

### How the boundary check is scoped

The graph is rooted at **every** `.ts` file under `src/`, not at the nine published entry points. A
file no entry point imports still ships in the repo, and rooting at the exports map left it
unwatched: a single relative import into a sibling package reaches enterprise code three hops later
while naming no banned specifier, so both linters pass it.

**A stated assumption.** The graph walker resolves workspace packages onto their TypeScript sources
and stops at anything outside the repo. `enableGlobalVirtualStore: true` means every third-party
package resolves outside the repo, so for those the walker checks nothing — what holds that line is
the fail-closed allowlist, and a reviewer adding an entry to it is accepting that they, not the
walker, have confirmed the package is free of enterprise code.

### Why the test resolves source, not built output

`packages/core/tsdown.config.ts` `alwaysBundle`s `@internal/auth`, so enterprise code is inlined into
`@mastra/core`'s `dist` and lands in shared chunks whose filenames carry no `ee` segment. A scan of
built output for `/ee` specifiers is green on `@mastra/core/auth` — the exact import this package
exists to keep out. The test resolves over source instead, through the repo's shared workspace alias
table (`scripts/workspace-source-aliases.cjs`), where `ee/` stays a literal path segment.

That is also why the test's second assertion is a fail-closed **allowlist** of external specifiers
rather than only a denylist. A denylist can be routed around; an allowlist has to be edited on
purpose, in a diff a reviewer sees.

### A type-only import is a licence problem, not a runtime one

The graph assertion skips type-only imports deliberately. `packages/core/src/server/types.ts`
type-imports three enterprise interface modules, and those edges are erased at compile time. Measured:
`packages/core/src/server/auth.ts` reaches 0 `ee/` modules at runtime and 15 with type imports
included. Without `skipTypeImports` the assertion would go red on correct code.

So an `import type { … } from '@mastra/core/auth/ee'`:

- **trips lint** — the repo uses base `no-restricted-imports`, not the typescript-eslint variant with
  `allowTypeImports`, so it fires on type imports too;
- **correctly does not trip** the runtime graph assertion, because the import carries no code;
- **does trip** the built-output assertion, which scans `dist/**/*.{js,cjs,d.ts}` for enterprise
  identifiers. Copying an enterprise declaration into a published Apache-2.0 package's type surface is
  a licence problem even when nothing executes.

If you see that combination, the checks are working. Do not "fix" the graph assertion.

The identifiers that assertion looks for are **derived** at test time from the enterprise sources
rather than typed into the test, so the set tracks enterprise code as it grows and this Apache-2.0
file carries no hand-copied roster of enterprise symbol names. Names this package declares itself are
subtracted, so a future module of ours is free to reuse a word. Sourcemaps are not scanned:
externals are peer dependencies and are never bundled, so `sourcesContent` can only hold this
package's own source.

### Re-verify the boundary

Both checks have to fail when the boundary breaks. A check nobody has watched fail isn't a check. Run
this after you change the lint rule, the graph test, or the build config.

Use `@mastra/core/auth` and `@mastra/core` as the probes, not `@mastra/core/auth/ee`. The `/ee`
subpath resolves to a real `ee/` path and goes red trivially: it would sign off a segment-matching
test that green-lights the bundled barrel, which is the failure this design exists to avoid.

**Step 0 — prerequisites.** From the repo root:

```shell
git status --porcelain          # must be empty
pnpm install
pnpm turbo build --filter ./mastracode/factory-auth
```

The graph assertion needs no build; the built-output assertion does, and vitest reports it as skipped
without one. A resolution error (`ERR_PACKAGE_PATH_NOT_EXPORTED`, `Cannot find module`) is **not** the
expected red — it means this step was skipped.

**Step 1 — add the probe.** Append to `mastracode/factory-auth/src/contract.ts`:

```ts
// EE BOUNDARY PROBE — REMOVE. See README > "Re-verify the boundary".
import { CookieSessionProvider } from '@mastra/core/auth';
void CookieSessionProvider;
```

The `void` is required. Without it `no-unused-vars` fires first and you read the wrong error, and
`eslint --fix` may delete the probe before you observe anything.

**Step 2 — lint must go red.**

```shell
pnpm --filter ./mastracode/factory-auth lint
```

The script is `oxlint . && eslint .`, so oxlint fails first and ESLint never runs. Expect a non-zero
exit and:

```
src/contract.ts:15:1: error eslint(no-restricted-imports): '@mastra/core/auth' import is restricted
from being used by a pattern. help: @mastra/core/auth loads enterprise (ee/) code through its
barrel...
```

To see ESLint's copy of the same error, run `pnpm --filter ./mastracode/factory-auth exec eslint .`
on its own. Both linters must be red; a package where only one fires has half a rule.

If lint is green, the rule is not firing. Check that the config object carrying the EE patterns has
no `ignores` key, and that it is ordered **after** the spread of `@internal/lint/eslint` — flat config
replaces rule options, it does not merge them, and the shared base ends by switching this rule off in
favour of oxlint.

One trap worth knowing before you edit the ban list: ESLint's `patterns` are gitignore-style, so a
bare `@mastra/core` in `patterns` also matches `@mastra/core/server` and rejects the one import this
package is supposed to make. oxlint treats the same entry as exact. Root barrels that must be banned
without their subpaths belong in `paths`, which is exact in both linters.

**Step 3 — the test must go red.**

```shell
pnpm --filter ./mastracode/factory-auth test
```

Expect a non-zero exit and a message starting `EE boundary violation.`, followed by the offending
module and the chain that reached it:

```
11 modules in the resolved graph are inside an ee/ directory:

  packages/_internals/auth/src/ee/index.ts
    mastracode/factory-auth/src/contract.ts
      -> packages/core/src/auth/index.ts      <- remove this import
      -> packages/_internals/auth/src/index.ts
      -> packages/_internals/auth/src/ee/index.ts
```

**Step 4 — repeat with the root barrel.** Replace the probe with:

```ts
// EE BOUNDARY PROBE (transitive) — REMOVE.
import { Mastra } from '@mastra/core';
void Mastra;
```

Both checks must go red again, and the test must report 14 modules. Lint catches this only because
`@mastra/core` is named in the ban list; the test catches it structurally. If **only** the test goes
red, the ban list has drifted — add the specifier.

**Step 5 — revert, and confirm green.**

```shell
git checkout -- mastracode/factory-auth/src/contract.ts
git status --porcelain          # must be empty again
pnpm --filter ./mastracode/factory-auth lint
pnpm --filter ./mastracode/factory-auth test
```

Both must pass. Stopping at red proves half of what is needed. Revert with `git checkout`, not by
hand and not with `eslint --fix`: it is the only revert that provably restores the original bytes. If
`git status` is not empty, the probe leaked — find it before committing.

If either check stays green, that's the bug. Fix the check before you ship anything else.

### Note on committing a probe

`.husky/pre-commit` runs lint-staged, which runs `oxlint --fix --deny-warnings` on staged `.ts` files.
Once the ban is in place a staged file importing a banned specifier cannot be committed at all. That
is the intended behaviour; it also means a probe must never be staged.
