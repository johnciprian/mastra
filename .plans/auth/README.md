# Factory auth: audit, plan, and task graph

Working documents for taking the Mastra Factory auth layer from its current state
to a swappable, well-documented provider system — one that accepts generic OIDC,
Cognito, Supabase, Firebase and others without editing the SPA.

Open the `.html` files in a browser; they are self-contained (no build step, no
external assets beyond web fonts).

## Read in this order

| File | What it is |
| --- | --- |
| [`swappability-audit.html`](./swappability-audit.html) | Audit of how pluggable, compartmentalized and testable auth is today. Includes a capability matrix for all 11 `auth/*` provider packages and letter grades for five seams. |
| [`remediation-plan.html`](./remediation-plan.html) | Four-phase plan to take every seam to A−, built on a fork-owned Apache-2.0 auth kit. States the EE licence boundary precisely. |
| [`task-graph.html`](./task-graph.html) | The plan decomposed into 65 dependency-linked tasks across six lanes, with seven hard gates, the critical path, and scheduling scenarios. |
| [`tasks.json`](./tasks.json) | The same 65 tasks, machine-readable — `id`, `lane`, `size`, `deps`, `files`, `detail`, `doneWhen`. Import into a tracker or feed to a script. |

## Headline findings

- Only **2 of 11** shipped `auth/*` providers can run the Factory end to end today
  (`workos` and `studio`). `supabase` and `firebase` implement two methods each and
  are bearer-validators only.
- There are effectively **two auth contracts wearing one name**: a small, well-documented
  API gate, and a much larger undocumented surface needed to run the Factory web app.
- Four obligations a provider must satisfy appear in **no interface and no documentation**:
  a flat resolvable `id`, cookie-readable `authenticateToken`, the pipe-delimited OAuth
  `state` format, and an organization id.

## Licence boundary

All proposed work is Apache-2.0 and imports nothing from any `ee/` directory
(see `LICENSE.md` and `ee/LICENSE`). Two specifics that shape the design:

- `@mastra/core/auth` is **not** safe to import: its barrel reaches `@internal/auth`,
  which re-exports `./ee`, and `packages/core/src/auth/ee/index.ts` opens with a
  side-effecting `import './telemetry'`.
- `@mastra/core/server` **is** safe: `packages/core/src/server/auth.ts` re-exports the
  eight capability interfaces and eight guards by explicit name, and EE appears only as
  erased `import type` in `types.ts`.

The plan enforces this with an ESLint rule plus a CI test over the resolved module graph,
so the boundary is a build error rather than a code-review habit.

## Status

**30 of 65 tasks done.** Each task in `tasks.json` carries a `status` field (`done` /
`pending` / `held`) — that file is the source of truth for progress; update it when a
task merges.

| Lane | | Done |
| --- | --- | --- |
| K | Kit foundation (`mastracode/factory-auth`) | 21 / 21 ✅ |
| B | Backend seam (`mastracode/factory`) | 3 / 19 |
| U | UI seam (`factory-ui`) | 1 / 9 |
| C | Conformance and providers | 4 / 7 (C2 held) |
| D | Documentation | 1 / 6 |
| R | Release | 0 / 3 |

**`C2` is `held`:** implemented and green as a diagnosis, but deliberately unmerged. It
runs conformance against `auth/workos` and `auth/studio` and four checks fail — every one
a real provider defect (listed below). The PR gate runs `vitest --project 'unit:*'`, which
includes both packages, so merging as-is turns CI red repo-wide. It lands once the kit can
express "known-failing, tracked" via `knownFailures`.

`B18`, `B19`, `U9` and `R3` are deferred by one release and are not on the path to A−,
so 38 remain to reach the target grade.

The kit ships as `@mastra/factory-auth@0.1.0`: nine entry points, 715 tests, an enforced
Apache-2.0/EE boundary, and a `describeAuthProvider` conformance suite. See
`mastracode/factory-auth/README.md` for the package itself and its semver policy.

### Decisions that changed the plan

Measurement overruled the plan document in several places. The task entries were rewritten
to match; these are the ones that changed the shape of the work.

- **`K5` was unsound as specified.** It asserted on `/ee` path segments, but
  `packages/core/tsdown.config.ts` `alwaysBundle`s `@internal/auth`, so EE code arrives
  pre-inlined with no `ee` segment anywhere. It would have returned green on the exact
  import `K4` bans. Rebuilt around a fail-closed allowlist; re-sized S → L.
- **`K4`'s ban list was too narrow.** `@mastra/core` root reaches EE at runtime via
  `tools/tool-builder/builder.ts:17`, so `import { Mastra } from '@mastra/core'` would
  have passed the rule.
- **`K6`'s gate would have certified the broken test**, because it proved the boundary
  with `@mastra/core/auth/ee` — a specifier that resolves to a real `ee/` path and goes
  red trivially. It now uses the bundled barrel and the root.
- **Subpaths renamed**: `./state` → `./oauth-state`, `./session` → `./cookie`; directory
  `auth-kit` → `factory-auth` to match the package name.
- **`B1` did not get the kit's EE ban.** The Factory imports ~50 specifiers that reach EE
  (`@mastra/core/storage`, `/agent-controller`, `@mastra/code-sdk`, `@mastra/auth-studio`
  …), and `B7` removes only `@mastra/auth-workos`, so a zero-EE claim is unavailable to
  that package now and at the end of the plan. It got a narrower, true rule instead.
- The plan's "8 guards" is wrong throughout: `packages/core/src/server/auth.ts` exports
  **7 guards**, the `MastraAuthProvider` class, and 10 types.

### Open items not tracked as tasks

- **`isUserProvider` is never checked by the conformance suite.** One of the seven guards
  has no section, no gate and no skip — the capability is simply absent from a run. Adding
  a check is a **major** under the kit's own semver policy, so it needs scheduling.
- **`factory-auth-ee-boundary` is not a required status check.** The CI job runs, but a
  red boundary does not block a merge until someone adds it in repo settings.
- **`providerHint`'s token set** (`'generic' | 'sso' | 'oauth' | 'email'`) wants one
  confirmation before `U4` builds its icon map.
- **`auth/better-auth` defect:** `handleAuthRequest` returns a clean 503 when migrations
  fail but *throws* when the instance was never built — two shapes of "auth isn't ready",
  one 500 and one 503, on a public route.

### Provider defects found by conformance (C2)

The first run against the two providers that actually run the Factory found four real
defects. None is a small fix; each has product or data consequences, so all four are
recorded rather than patched. They are pinned as `knownFailures` in each package's
conformance test.

- **`auth/workos` — `ISessionProvider` is a no-op facade.** `validateSession` returns
  `null` unconditionally (`auth/workos/src/auth-provider.ts:712`); all seven members are
  no-ops "kept for interface compatibility". Because `isSessionProvider` tests only two
  members *for existence*, the guard reports a capability that isn't there, and
  `toAuthDescriptor` then advertises `features.sessionRevocation: true` — so a UI offers
  "sign out everywhere" against a provider that cannot. Remedies (a real session store, or
  dropping `ISessionProvider` from a published v1.6.4) are both provider decisions.
- **`auth/studio` — `getLoginUrl` drops `state`.** It extracts the `returnTo` half into
  `post_login_redirect` and discards the rest, so the id half a host compares for CSRF
  never returns. The Factory already carries a `mastra_factory_return_to` cookie as a
  workaround, which corroborates it.
- **`auth/studio` — `ensureOrganization(userId)` returns `undefined`** unless a cookie was
  previously cached for that user, so bearer/CLI users never get an org bootstrapped. The
  interface hands it only a user id, so a correct implementation must work from one.
- **`auth/studio` — `createSession(userId)` without metadata** mints an id
  `validateSession` can never accept. The host always passes `metadata.accessToken` today,
  which is why nothing noticed, but `metadata` is optional in the declared contract.

### Contract weaknesses this surfaced

- **`isSessionProvider` narrows on 2 of 7 declared members** — seen independently three
  times: building the descriptor, quantified across all seven guards by the docs stream
  (`ISSOProvider` 2/3/5, `ISessionProvider` 2/7/7, `IUserProvider` 1/2/4,
  `ICredentialsProvider` 1/2/5), and now causing a live wrong answer in `auth/workos`.
- **`mapUserToResourceId` is un-implementable as a prototype method.**
  `packages/_internals/auth/src/provider/index.ts:85` assigns
  `this.mapUserToResourceId = options?.mapUserToResourceId` unconditionally, so a provider
  that doesn't forward the option gets an own `undefined` shadowing its own prototype
  method, and the conformance check silently skips. Fix belongs in `_internals/auth`.
- **The conformance suite never exercises `IUserProvider` or `isOrganizationAdmin`.**
  Adding checks is a **major** under the kit's semver policy, so it needs scheduling.
