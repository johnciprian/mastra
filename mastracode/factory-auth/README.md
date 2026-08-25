# @mastra/factory-auth

Tools for making an auth provider work with the Mastra Factory. The package holds the provider
contract, an identity normalizer, a capability descriptor, a signed session cookie, an OAuth `state`
codec, test fakes, and a conformance suite you run in your own package's CI.

Use it when you're writing or adapting a provider. You don't need it to _use_ a provider that
already works.

This package targets the Mastra Factory. Providers that only gate `/api/*` need `@mastra/core/server`
and nothing here.

> **Status: in progress.** The package layout, the exports map, both halves of the licence boundary,
> and `./contract` are in place. The remaining modules are stubs, and each one names the task that
> fills it in its file header.

## What this isn't

- Not an auth provider. It never talks to an identity system, and it contains no vendor code.
- Not a replacement for `@mastra/core/server`. It re-exports that contract and adds the parts the
  Factory needs on top of it.
- Not enterprise code, and it can't call any. See [The EE boundary](#the-ee-boundary).
- Not role-based access control, fine-grained authorization, or licence checks. Those live in the
  enterprise packages and stay there.

## Start here

Four things decide whether a provider can run the Factory. The conformance suite checks all four.

1. `authenticateToken` returns an object with a flat `id`. `uid` and `sub` work too, because
   `toAuthIdentity` normalizes them.
2. `authenticateToken` reads the `Cookie` header when the bearer token is empty. A browser
   navigation sends no `Authorization` header, so an empty token means "read the cookie".
3. Login and callback both use `encodeState` and `decodeState` from this package.
4. Every identity resolves to an organization id. Implement `IOrganizationsProvider`, or wrap the
   provider with `withSyntheticOrganizations`.

```ts
import { toAuthIdentity, isSSOProvider } from '@mastra/factory-auth';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';

export const auth = withSyntheticOrganizations(new MyOidcProvider());
```

Then run the conformance suite. It fails with the name of whichever obligation you missed.

## What's in the package

| Import                               | Answers                                                    |
| ------------------------------------ | ---------------------------------------------------------- |
| `@mastra/factory-auth`               | The pure layer: contract, identity, capabilities.          |
| `@mastra/factory-auth/contract`      | The same contract symbols, narrower import.                |
| `@mastra/factory-auth/identity`      | What is this provider's user, in one shape?                |
| `@mastra/factory-auth/capabilities`  | Which capabilities does this provider have?                |
| `@mastra/factory-auth/organizations` | Which organization does this identity belong to?           |
| `@mastra/factory-auth/cookie`        | How does the host mint, read and clear its session cookie? |
| `@mastra/factory-auth/oauth-state`   | How is the OAuth `state` parameter encoded and decoded?    |
| `@mastra/factory-auth/testing`       | Test doubles, for code that consumes a provider.           |
| `@mastra/factory-auth/conformance`   | The suite, for code that implements a provider.            |

`./capabilities` answers **which** capabilities a provider has. The capability interfaces themselves
are in `./contract`.

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

`./oauth-state` is the OAuth `state` parameter: a nonce plus where to return the user after login. It
has nothing to do with `FactoryAuthState` in the web app.

The root export holds the pure layer only, so a browser bundle can import it. `./cookie` and
`./oauth-state` are server-only. `./testing` and `./conformance` are test-time and are never
re-exported from the root: `./conformance` is the one module that imports vitest, which is why vitest
is an optional peer dependency.

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

> For contributors to this package. If you are integrating a provider, you are done — the rest of
> this file is about how the boundary is maintained.

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
