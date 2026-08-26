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
| [`task-graph.html`](./task-graph.html) | The plan decomposed into 65 dependency-linked tasks across six lanes, with seven hard gates, the critical path, and scheduling scenarios. Not updated with the `P` follow-ups; `tasks.json` is authoritative. |
| [`tasks.json`](./tasks.json) | 94 tasks, machine-readable — `id`, `lane`, `size`, `deps`, `files`, `detail`, `doneWhen`. The original 65, plus `P1`–`P29`: `P1`–`P18` filed by the re-grade, `P19`–`P29` filed by the work since. Import into a tracker or feed to a script. |

**Start at [Final grades](#final-grades-r2)** if you want the current state rather than the
original diagnosis. The two HTML documents describe the problem and the plan as of the
audit; they have not been rewritten, and where the code has since disproved them this
README says so.

## Headline findings

The audit's three headline claims, and how each stands at `a7909efb`:

- Only **2 of 11** shipped `auth/*` providers can run the Factory end to end
  (`workos` and `studio`). `supabase` and `firebase` implement two methods each and
  are bearer-validators only. — **Still true.** `C5` settled the two by declaring them
  unsupported-with-reason (a `FACTORY_BROWSER_SIGN_IN` export naming the reason and the
  alternative) rather than adapting them, so the count is unchanged and now honest in the
  open. The audit's own capability matrix went stale here; the current one is in
  `docs/src/content/en/reference/auth/capability-interfaces.mdx`.
- There are effectively **two auth contracts wearing one name**: a small, well-documented
  API gate, and a much larger undocumented surface needed to run the Factory web app. —
  **Largely addressed.** The larger surface is now documented, conformance-checked, and
  reachable through one import site. The exception is PKCE, which is neither declared nor
  checked and does not work.
- Four obligations a provider must satisfy appear in **no interface and no documentation**:
  a flat resolvable `id`, cookie-readable `authenticateToken`, the pipe-delimited OAuth
  `state` format, and an organization id. — **Fixed.** All four are stated as contract in
  `docs/src/content/en/docs/auth/provider-obligations.mdx` and asserted by six of the
  eighteen conformance checks.

Two of the audit's own statements were measured wrong during the work and should not be
carried forward: its "eight small interfaces / eight guards" was the origin of a persistent
"8 guards" error at a time when there were **7**, and its capability matrix predates `C5`.
`P11` has since added an eighth — `canClearSession`, narrowing to `ISessionClearer` — so
`packages/core/src/server/auth.ts` now exports 8 guards, the `MastraAuthProvider` class and
11 types. The audit was wrong when it was written and is right by accident now, which is a
reason to cite the code rather than either document.

## Licence boundary

All proposed work is Apache-2.0 and imports nothing from any `ee/` directory
(see `LICENSE.md` and `ee/LICENSE`). Two specifics that shape the design:

- `@mastra/core/auth` is **not** safe to import: its barrel reaches `@internal/auth`,
  which re-exports `./ee`, and `packages/core/src/auth/ee/index.ts` opens with a
  side-effecting `import './telemetry'`.
- `@mastra/core/server` **is** safe: `packages/core/src/server/auth.ts` re-exports the
  capability interfaces and the eight guards by explicit name, and EE appears only as
  erased `import type` in `types.ts`.

The plan enforces this with an ESLint rule plus a CI test over the resolved module graph,
so the boundary is a build error rather than a code-review habit.

## Status

**62 of 65 original tasks done**, plus **29 post-plan follow-ups** (`P1`–`P29`) filed by
the re-grade and by the work since, of which **23 are done and 6 pending**. Each task in
`tasks.json` carries a `status` field (`done` / `pending` / `held`) — that file is the
source of truth for progress; update it when a task merges.

| Lane | | Done |
| --- | --- | --- |
| K | Kit foundation (`mastracode/factory-auth`) | 21 / 21 ✅ |
| B | Backend seam (`mastracode/factory`) | 18 / 19 |
| U | UI seam (`factory-ui`) | 8 / 9 |
| C | Conformance and providers | 7 / 7 ✅ |
| D | Documentation | 6 / 6 ✅ |
| R | Release | 2 / 3 |

`B18` is **done**: `MASTRACODE_AUTH_IDENTITY_V2` now defaults **on**, with
`=false` retained as the rollback, by explicit decision to soak post-merge.

`B19`, `U9` and `R3` remain, and are gated on that soak rather than on effort. `B19`
deletes the flag and the legacy reader; `U9` drops the legacy `signUpDisabled` field from
the wire. Doing either before the soak removes the rollback the soak exists to exercise.

**The rollback is the direction that costs, not the upgrade** — measured in `B18`, and the
opposite of what the changeset originally claimed. Enabling changes nothing for a
provider-cookie deployment (WorkOS, Okta, better-auth): the host reads no cookie of its
own, so `requestAuthToken` yields `''`, which is the provider's documented signal to read
the `Cookie` header itself. Rolling *back* signs people out — a session minted by the host
under v2 lives in the host's signed cookie, and the legacy path never reads it. That hits
tokens-only providers with a session secret configured, and only them. Worth knowing
before anyone reaches for `=false` under pressure.

The kit ships as `@mastra/factory-auth@0.1.0`: nine entry points, 910 tests, an enforced
Apache-2.0/EE boundary, and a `describeAuthProvider` conformance suite. See
`mastracode/factory-auth/README.md` for the package itself and its semver policy.

### Where the plan text was wrong, and the measurement that showed it

The `P` follow-ups were written from reading the code rather than running it, and nine of
them turned out to be wrong about the defect or the fix — enough that measuring first
before touching anything is now the rule, not a precaution. Each correction is recorded in
that task's own `detail` in `tasks.json`, next to the claim it replaces.

- **`P9` does not fix WorkOS.** The task said narrowing the guards would stop `auth/workos`
  advertising `sessionRevocation` it cannot deliver, and `P18` cross-referenced it for
  that. It does not: WorkOS carries all seven `ISessionProvider` members as no-ops, so it
  passed the loose guard and passes the tight one. A structural guard cannot detect a
  no-op. Only `P18` can fix that defect.
- **`P9` breaks nothing in this repository.** The task was filed as BREAKING, and it is —
  for external providers. An AST scan over every provider class under `auth/*` showed zero
  verdicts change here, because every provider declares its interfaces with `implements`
  and the compiler had already forced the members to exist. What was breaking in theory
  was inert in practice, and knowing which mattered for the changeset.
- **`P20`'s suggested fix was a no-op.** The task proposed widening to
  `Auth<BetterAuthOptions>`. better-auth declares
  `type Auth<Options extends BetterAuthOptions = BetterAuthOptions>`, so the bare `Auth`
  already *is* `Auth<BetterAuthOptions>`; a probe with the explicit form fails identically.
  The fix is a type parameter inferred at the call site.
- **`P14`'s blocker did not exist.** The task framed dropping `@mastra/auth-workos` as a
  product decision — delete a shipped feature, or take on peer-dependency gymnastics —
  because `integrations/workos/integration.ts` imports `WorkOSAdminPortal` at top level and
  ships it. Reading what the file *uses* dissolved the dilemma: the host already injects its
  own client, and the import bought a type alias and one string constant. The feature stays
  and the dependency goes.
- **`P22` blamed the wrong mechanism.** It named `vi.mock('jose')` under `isolate: false`.
  `jose` is incidental — the leak is any module mocked in one file and imported for real by
  a sibling, and it runs in both directions, which is why the failing package differed every
  time. It also assumed isolating would cost speed; measured, it costs 0.7%.
- **`P11`'s second option would not have worked.** The task offered an optional member on
  `ISSOProvider` as an alternative to a standalone interface. `@mastra/auth-better-auth` is
  the provider the pattern exists for and it is not an `ISSOProvider`, so that route would
  have declared the member for every provider that cannot use it and none that needs it.
- **`P25` named neither real cause.** It blamed a test depending on an earlier test's mock. In
  `auth/clerk` that was close enough; in `auth/studio` the cause was a describe replacing
  `globalThis.fetch` by assignment, which `vi.restoreAllMocks()` cannot undo, so the replacement
  outlived the block and later spies inherited its call history.
- **`P26`'s first defect did not need `packages/_internals/auth`**, and its `StoredResourceScopeConfig`
  finding understated the problem: that type was never exported from any published subpath, so no
  consumer could name it at all.
- **`P18` undercounted, and one of its own reasons was wrong.** `auth/studio` carried four
  recorded failures, not three. And the reason recorded against `ensureOrganization` said
  fixing it would move which partition bearer-token users' rows land in; it does not, because
  `factoryAuthTenant` already resolves those users to the same `user:<userId>` one layer
  earlier, and `packages/server` never calls the method at all.

## Final grades (R2)

Measured against the A− exit criteria in `remediation-plan.html`, at
`a7909efb`. **One seam of five reached A−.**

| Seam | Audit | Target | **Actual** | Blocking gap |
| --- | --- | --- | --- | --- |
| Contract design | B+ | A− | **B+** | PKCE read side is declared nowhere and broken under the Factory |
| Backend seam | B− | A− | **B+** | migration is on by default; the soak has not run |
| UI seam | D+ | A− | **B** | the seam's own CI gate is never run by CI |
| Testability | B− | A− | **C+** | 2,853 host tests outside the PR gate; 6 of 11 providers conform |
| Documentation | D | A− | **A−** ✅ | reached, with two filed corrections |

The evidence for each is below. Every gap has a `P`-prefixed task in `tasks.json`; nothing
was rounded up, and nothing short was recorded as met.

### What shipped, versus what the plan set out to do

The plan set out to make five seams swappable at A−. It delivered a real, published,
Apache-2.0 kit; a conformance suite six providers run; three well-built CI gates; and a
documentation set that went from D to A− and was validated on an outside reader. That is
substantial and most of it is durable.

It did not deliver a swappable auth layer. Three things stand between here and that claim,
and none is a matter of polish:

1. **The identity migration is on by default but has not soaked.** Everything the contract
   seam added — declared identity, the `toIdentity()` escape hatch, host-owned session
   cookies — is now the default path (`B18`). `MASTRACODE_AUTH_IDENTITY_V2=false` remains
   the rollback for one release. What has not happened is the soak: no deployment has run
   this under real traffic yet, which is the whole reason the rollback is retained.
2. **The two largest test suites never run on a pull request.** `mastracode/factory` and
   `mastracode/factory-ui` are 2,853 green tests that cannot fail a merge, including the UI
   seam's own anti-regression gate.
3. **PKCE cannot complete under the Factory**, and the docs currently imply it can.

### Contract design — **B+** (target A−, not reached)

Two of the criterion's three clauses landed cleanly.

- **Declared identity: met.** `AuthIdentity` requires a non-empty `id`
  (`mastracode/factory-auth/src/identity.ts:64`), and `IIdentityProvider` / `toIdentity()`
  is the overridable escape hatch (`identity.ts:101-121`).
- **Cookie name and `state` format: met.** `SESSION_COOKIE_NAME`,
  `SESSION_COOKIE_HOST_NAME`, `sessionCookieName()` (`cookie.ts:69,88,107`);
  `OAUTH_STATE_DELIMITER`, `encodeState`, `decodeState`, `parseStateId` (`oauth-state.ts`).
- **Semver'd with a written stability policy: met.** `mastracode/factory-auth/README.md:353`
  onward — what each bump means, recorded known failures as part of the contract, what may
  change under you, and the pre-1.0 caveat.
- **PKCE read side: not met, and broken.** `ISSOProvider` declares `getLoginCookies?`
  (`packages/_internals/auth/src/index.ts:194`) and the Factory calls it
  (`mastracode/factory/src/auth.ts:1035`). The read side, `setCallbackCookieHeader`, is
  declared on **no interface**, is reached through `(auth as any)` at
  `packages/server/src/server/handlers/auth.ts:492`, and appears **zero times** in
  `mastracode/factory/src/`. A PKCE provider writes a verifier cookie it can never read
  back. → **`P5`**, **`P6`**, **`P8`**.

Held at B+ rather than A− because one of three explicitly enumerated clauses is not merely
absent but actively broken. The seam did improve on the audit's B+ — `authenticateToken`
returning `unknown` with no `id` requirement, and "no cookie contract anywhere", are both
genuinely fixed — but the improvement landed in a new package while the interfaces and
guards the criterion points at (`packages/_internals/auth`) are unchanged. Three further
weaknesses, all documented honestly and none fixed: guards narrow on fewer members than
their interfaces require (`isSessionProvider` 2 of 7, `isSSOProvider` 2 of 3 required,
`isUserProvider` 1 of 2, `isCredentialsProvider` 1 of 2 — `P9`);
`mapUserToResourceId` shadows itself (`P10`); and there is no blessed way to clear a
provider-owned session cookie (`P11`).

### Backend seam — **B** (target A−, not reached)

| Clause | Result |
| --- | --- |
| `instanceof MastraAuthWorkos` and `WORKOS_*` reach-through deleted | **met** — only comments remain |
| Org-lessness stops 403ing | **met** — `resolveOrganizationId` always yields an id; the 403 branch is gone |
| Logout revokes, and is POST | **met** — `auth.ts:1135,1165`; revocation precedes cookie clearing; GET survives one release behind a CSRF-navigation check |
| `RouteAuth` is the only identity path | **3 of 4 bypasses closed** |
| The Factory imports only the kit | **true of `src/auth.ts`, not of the package** |
| `@mastra/auth-workos` leaves the dependency list | **not met** |

- `mastracode/factory/src/storage/domains/audit/domain.ts:89` still reads
  `context.get('factoryAuthUser')` directly, and must: `RouteAuth.tenant()` returns only
  `{ orgId, userId }` (`routes/route.ts:36`), so the port cannot supply a display profile.
  Nothing enforces the port as exclusive. → **`P15`**.
- `mastracode/factory/src/factory.ts:21` imports `MastraAuthStudio` at top level and
  defaults to it. The vendor-auth lint ban is scoped to `src/auth.ts` alone
  (`eslint.config.js:176-180`). `@mastra/auth-workos` is still at `package.json:58`,
  blocked on a product decision about `WorkOSAuditIntegration`. → **`P14`**.

**Does the flag being off change this grade? Yes, and it is the reason for the grade.**

`MASTRACODE_AUTH_IDENTITY_V2` now defaults **on** (`B18`, `auth.ts:54-76`) and is documented in
`mastracode/web/.env.schema:170`. With it off, three things are true of every deployment:
identity is still the shipped shape-sniffer `legacyFactoryAuthUser`, not `toAuthIdentity`
(`auth.ts:416`); the host does not own its session cookie, so `readSessionCookie` never
runs (`auth.ts:199,261`); and `toIdentity()` — the contract's escape hatch — is never
consulted.

The audit awarded B− for, in its words, "identity is shape-sniffed". **In the default
configuration, identity is still shape-sniffed.** A migration that is written, tested and
switched off is not the same as a migration that is live: it has delivered none of the
behaviour change the criterion describes to any user, and it is one environment variable
away from delivering all of it at once, unsoaked.

**The plan's exit criteria do not account for this, and they should have.** They are
written as state-of-the-world claims — "`RouteAuth` becomes the *only* identity path",
"org-lessness stops 403ing" — with no notion of a dark launch. Worse, `tasks.json` `notes`
says `B18` ("flip the compat flag on by default and soak") is "deliberately deferred by one
release … not on the path to A−". That is the plan grading its own migration complete while
it is off. The re-grade rejects that: **`B18` is on the path to A− for this seam**. `P12`
(settle the organization fallback) used to block it, because the fallback decided which
organization's data a request could reach and the flag flipped exactly one assertion about
it. `P12` is now **settled fail-closed and done**, so nothing about org scope stands between
`B18` and the flag: the suite is identical with the flag on and off. See below.

B rather than B− because the org-lessness and logout work is real, live and unflagged, and
three of four bypasses are genuinely closed. B rather than A− because calling this A− would
tell the next person the identity migration shipped. It landed; it did not ship.

### UI seam — **B** (target A−, not reached)

Three of four clauses are met, and the work is good.

- **Sign-in renders from the descriptor: met.** `SignInPage.tsx:310-312` — `signIn.kind`
  decides which controls exist, `providerHint` decides presentation. The hint token set
  (`generic | sso | oauth | email`) is settled and documented (`capabilities.ts:95-107`).
- **Credentials form posts to a descriptor-supplied endpoint: met.** `credentialsBasePath`
  (`capabilities.ts:155`), consumed at `SignInPage.tsx:369`.
- **Unknown provider renders correctly: met.** Hint defaults to `generic`;
  `signIn.kind === 'none'` renders an explanation rather than an empty box or a
  wave-through, and says what the deployment can actually do.
- **A CI test greps `factory-ui` for provider-name literals: test met, CI not met.**

`mastracode/factory-ui/src/ui/__tests__/no-provider-literals.test.ts` is one of the better
gates in the repo: four assertions, false-green guards, a vendor-mark rule scoped to the
auth surface, and an assertion that the single `LEGACY:` exemption stays single. **CI never
runs it.** Measured: `pnpm vitest list --filesOnly --project 'unit:*' --project
'typecheck:*'` selects **zero** files under `mastracode/`, because `vitest.config.ts:30`
globs `mastracode/vitest.config.ts`, which does not exist — and no workflow runs
`factory-ui` tests. → **`P1`**.

The criterion asked for a CI test. A gate no pipeline executes is documentation. This is
the same failure class the plan itself catalogued twice — the `mastracode/` glob and
`auth/cloud`'s project name — and it landed on the plan's own deliverable.

### Testability — **C+** (target A−, not reached)

The furthest from target, and not close.

- **"Every shipped provider executes conformance in its own CI": 6 of 11.** Measured by the
  gate itself: `providers=11 with-suite=6 recorded-without=5`. `auth0`, `clerk`, `cloud`,
  `google`, `neon` have none. Green here means "six have suites and five have written
  excuses". → **`P2`**, **`P3`**.
- **`auth/cloud` has never run in the PR gate.** Its `vitest.config.ts` declares no `name`,
  so the project is `@mastra/auth-cloud` and `unit:*` never selects it — confirmed:
  `vitest list --project '@mastra/auth-cloud'` returns a real test file. → **`P2`**.
- **The suite ignores a seventh of the capability surface.** 18 checks, split 6 base / 6
  obligations / 6 capabilities. `isUserProvider` and `getCurrentUser` appear **zero times**
  in `mastracode/factory-auth/src/conformance/`; `isOrganizationAdmin` appears **once**,
  inside a failure-message string, never invoked; PKCE appears nowhere. → **`P4`**, **`P6`**.
- **Host tests: written, green, and ungated.** `mastracode/factory` is 91 files / 1,887
  tests; `mastracode/factory-ui` is 158 files / 966 tests. All pass locally. **None runs on
  a pull request.** Only `mastracode/factory-auth` runs in CI, through one job in
  `lint.yml:111` that is itself conditioned on `has_code == 'true' && github.repository ==
  'mastra-ai/mastra'` — so it skips on forks, and a skipped check cannot be required.
  → **`P1`**, **`P13`**.
- **Provider-selection tests off the 60 s boots: met** (C6).

**This is not a regression.** The CI gap predates the plan, and the plan's own conformance
gate is what surfaced it. The grade is below the audit's B− because the audit graded on
tests that exist without checking whether they run; measured, the seam was always weaker
than B−. Coverage is also still inverted in the audit's original sense — `auth0`, `clerk`,
`google`, `neon`, the likeliest drop-in targets, have no conformance at all — and a second
inversion now exists: the packages with the most tests have the least CI.

What is genuinely strong: the kit's 833 tests at 98% statements / 100% lines, the
`knownFailures` machinery that re-checks recorded failures in both directions, and three
gates built to fail closed with explicit false-green guards.

### Documentation — **A−** (target A−, **reached**)

The one seam that got there, and the biggest jump of the five.

- **Capability reference table: met.** `docs/src/content/en/reference/auth/capability-interfaces.mdx`
  — guard → interface → methods (line 17), per-interface member tables with
  required/optional (52-158), a capability matrix for all 11 providers (231), and — to its
  credit — a table at line 167 documenting the guard-narrowing weakness rather than hiding
  it.
- **Start-to-finish guide: met.** `docs/src/content/en/docs/auth/write-a-provider.mdx`, and
  D5's findings against it were fixed: `verifyJwks` is now a prominent early callout rather
  than a "next steps" link, and the token exchange posts form-encoded (line 341).
- **The four obligations promoted to documented contract: met.**
  `docs/src/content/en/docs/auth/provider-obligations.mdx` — `flatId`, `cookieAuth`,
  `stateCodec`, `organizationId`, each with what breaks, how to satisfy it, when it is
  enforced, and its conformance check names.
- **Every doc example type-checks in CI: short.** `pnpm typecheck:examples` checks 19
  examples from **3** pages; **17 in-scope pages are excluded** via `LEGACY_UNCHECKED`
  (`docs/scripts/typecheck-examples.ts:86-104`), including `custom-auth-provider.mdx` and
  `composite-auth.mdx`. The list is self-policing — a stale entry fails the run — which is
  the right design. → **`P16`**.

Two defects found and filed (**`P7`**): `capability-interfaces.mdx:252` claims Better Auth
is "the only one that runs the conformance suite in its own package" when six do; and the
`ISSOProvider` table lists `getLoginCookies` with no caveat while PKCE appears nowhere in
the auth docs, so an author who implements it builds a flow that cannot complete.

Held at A− anyway: the criterion's three substantive clauses are fully delivered, the guide
was validated on a real outside reader rather than asserted, and the fourth clause falls
short behind an exclusion list that is honest and shrinks by design. **D5's verdict still
stands** — yes for a bearer or vanilla hosted-login provider, no for a production OIDC
provider — and it stands on a code gap (PKCE), not a docs gap.

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
- The plan's "8 guards" was wrong throughout at the time: `packages/core/src/server/auth.ts`
  exported **7 guards**, the `MastraAuthProvider` class, and 10 types. `P11` has since added
  `canClearSession` and `ISessionClearer`, making it 8 and 11 — for a different reason than
  the plan gave, and after every "8 guards" claim in it had already been corrected to 7.

### Open items — now tracked

Everything that was listed here as untracked has a task as of the R2 re-grade. The
diagnoses below are kept because the task entries reference them; the task id is the thing
to follow.

- **`isUserProvider` is never checked by the conformance suite.** One of the seven guards
  has no section, no gate and no skip — the capability is simply absent from a run. Adding
  a check is a **major** under the kit's own semver policy, so it needs scheduling.
  Re-measured: `isOrganizationAdmin` is unchecked the same way. → **`P4`**
- **Neither auth CI gate is a required status check.** `auth-conformance.yml` is built to
  be requirable — no path filter, no repository condition — and needs only the repo
  setting. `factory-auth-ee-boundary` is not: `lint.yml:111` carries
  `if: needs.changes.outputs.has_code == 'true' && github.repository == 'mastra-ai/mastra'`,
  so it reports skipped on forks and on non-code PRs, and a skipped check cannot be
  required. That job is also the only thing running the kit's 833 tests in CI. → **`P13`**
- **`providerHint`'s token set** (`'generic' | 'sso' | 'oauth' | 'email'`) — **settled.**
  Documented at `capabilities.ts:95-107` with a stated rule (no token is a vendor) and
  `DEFAULT_PROVIDER_HINT = 'generic'`. `U4`'s icon map is built on it. No task needed.
- **`auth/better-auth` defect:** `handleAuthRequest` returns a clean 503 when migrations
  fail but *throws* when the instance was never built — two shapes of "auth isn't ready",
  one 500 and one 503, on a public route. Confirmed at `auth/better-auth/src/index.ts:349`
  (the 503, inside the `try`) and `:231` (the `auth` getter's throw, reached from the line
  after it, outside the `try`). → **`P17`**

Found by the re-grade and not previously listed:

- **Nothing under `mastracode/` is selected by the PR gate** — 2,853 tests across
  `factory` and `factory-ui`, including the UI seam's own anti-regression gate. → **`P1`**
- **The capability reference contains a false claim** about which providers run
  conformance, and presents `getLoginCookies` with no PKCE caveat. → **`P7`**
- **16 auth doc pages with TypeScript examples are excluded from the CI type-check.**
  → **`P16`**
- **A fourth `RouteAuth` bypass**, structural rather than an oversight: the audit domain
  needs a display profile the port cannot supply. → **`P15`**

### Provider defects found by conformance (C2)

The first run against the two providers that actually run the Factory found four real
defects. None is a small fix; each has product or data consequences, so all four are
recorded rather than patched. They are pinned as `knownFailures` in each package's
conformance test. **All four are still open at the re-grade** → **`P18`**.

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

All of these were re-measured at `a7909efb` during the R2 re-grade and every one still
holds. Each now carries a task.

- **`isSessionProvider` narrows on 2 of 7 declared members** — seen independently three
  times: building the descriptor, quantified across all seven guards by the docs stream
  (`ISSOProvider` 2/3/5, `ISessionProvider` 2/7/7, `IUserProvider` 1/2/4,
  `ICredentialsProvider` 1/2/5), and now causing a live wrong answer in `auth/workos`.
  Re-verified by counting interface members at HEAD; all four ratios are exact. → **`P9`**
- **`mapUserToResourceId` is un-implementable as a prototype method.**
  `packages/_internals/auth/src/provider/index.ts:85` assigns
  `this.mapUserToResourceId = options?.mapUserToResourceId` unconditionally, so a provider
  that doesn't forward the option gets an own `undefined` shadowing its own prototype
  method, and the conformance check silently skips. Fix belongs in `_internals/auth`.
  → **`P10`**
- **The conformance suite never exercises `IUserProvider` or `isOrganizationAdmin`.**
  Adding checks is a **major** under the kit's semver policy, so it needs scheduling.
  Re-verified: `isUserProvider` and `getCurrentUser` appear zero times in
  `src/conformance/`, and `isOrganizationAdmin` appears once, inside a failure-message
  string. → **`P4`**
- **No way to clear a provider-owned session cookie.** `ISSOProvider` has `getLogoutUrl`
  but nothing that returns clear-cookie headers, and `getClearSessionHeaders` lives on
  `ISessionProvider`, whose guard and interface demand all seven members. A hosted-login
  provider that mints its own cookie therefore has no supported way to clear it on logout.
  → **`P11`**
- **PKCE is broken under the Factory, not merely undocumented.** `getLoginCookies` (write
  side) is declared on `ISSOProvider` and is called by the Factory. `setCallbackCookieHeader`
  (read side) is **not declared on `ISSOProvider` at all** — an undeclared duck-typed hook,
  called only from `packages/server/src/server/handlers/auth.ts:492` and forwarded by
  `CompositeAuth`. It appears **zero times** in `mastracode/factory/src/`. So under the
  Factory a PKCE provider can write its verifier cookie at login and has no way to read it
  back at callback; documenting it would document something that does not work.
  `auth/supabase`'s own package comment independently gives this as its reason for
  declining a hosted login. Fix: declare the read side on `ISSOProvider` as optional, call
  it from the Factory callback, then document. The conformance suite also has no PKCE
  check, so a provider passes everything with none. → **`P5`**, **`P6`**, **`P7`**, **`P8`**
- **`auth/cloud` has never run in the PR gate.** `auth/cloud/vitest.config.ts` declares no
  `name`, so the project resolves to `@mastra/auth-cloud`, which matches neither `unit:*`
  nor `typecheck:*` in `test-suite.yml`. Same bug class as the `mastracode/vitest.config.ts`
  glob pointing at a file that does not exist — this is the second instance. Found
  prospectively by C7's reachability check. → **`P2`**

  **The re-grade found the first instance is far more expensive than "same bug class"
  suggests.** That dead glob is why nothing under `mastracode/` is in the PR gate at all:
  2,853 tests in `factory` and `factory-ui`, including the UI seam's own gate. `auth/cloud`
  costs one package's tests; the `mastracode/` glob costs the two largest suites this plan
  produced. → **`P1`**
- **Clearing a provider-owned cookie works but is unblessed.** `mastracode/factory/src/auth.ts`
  reads `getClearSessionHeaders` off the provider as `Partial<ISessionProvider>` and honours
  it without requiring the other six members — `@mastra/auth-better-auth` relies on exactly
  this. Nothing is broken; it is simply documented by no interface, which is why a fresh
  reader invented their own method for it. → **`P11`**

### Settled: the organization fallback — fail closed

**Decided, implemented, and no longer a gate on B18.** → **`P12`**, done.

`toAuthIdentity` resolved a `{ session, user }` wrapper's organization from
`session.activeOrganizationId`, **falling back to the `user` half's own `organizationId`**
when the session named none. `mastracode/factory/src/workspace.test.ts` asserted the
opposite, and it was the only assertion in 1,794 that the flag flipped.

**The fallback is removed.** A wrapper's organization now comes from the session and from
nowhere else. A session that has activated no organization resolves to no organization, and
`resolveOrganizationId` turns that into the user's private partition, `user:<id>` — the same
answer any no-org caller gets.

**Why this side won.** The `user` half's `organizationId` proves the user is a *member* of
that organization. It does not prove this session was switched into it, and a session that
never activated an organization must not reach that organization's shared data. Membership
is not activation. Reading one as the other is a data leak; the reverse is not.

**The cost, stated rather than argued away.** A user who belongs to exactly one organization
and has not switched into it sees their private partition rather than their team's. That is
confusing, and it is the same thing a signed-in user sees before picking an organization. It
is not a leak, which is why it is the side that lost the first-run argument and still won.
Providers avoid it entirely by putting the active organization on the session when they mint
it, which the [provider obligations](../../docs/src/content/en/docs/auth/provider-obligations.mdx)
page now says explicitly.

**A third implementation had already picked this side.** `resolveTenantFromRequestContext`
in `mastracode/sdk/src/agents/credential-resolver.ts` reads a wrapper's org from the session
half only, with a comment that the two parsers "cannot share code across the package
boundary, so they must agree by rule". They did not agree; they do now. The removal closed a
latent divergence rather than creating one.

**Verified both ways.** The factory suite is **1881 passed | 6 skipped** with
`MASTRACODE_AUTH_IDENTITY_V2` unset and **1881 passed | 6 skipped** with it `true` —
identical, which is the real proof the conflict is gone. The kit is at 824 (823 plus one new
assertion pinning the private-partition resolution). The conflict note in `workspace.test.ts`
was rewritten to record the decision and its reasoning, not deleted.

### Blocked, not forgotten: B7's dependency removal

B7 took `@mastra/auth-workos` out of the neutral auth module, which is its real
`doneWhen`. Removing it from `mastracode/factory/package.json` is **blocked**:
`src/integrations/workos/integration.ts` imports `WorkOSAdminPortal` at top level and it
ships — `dist/integrations/workos/integration.js` carries the runtime import, reachable
through the `"./*"` exports map. Dropping the dependency would leave an unresolvable import
in published output. Nothing in the repo imports `WorkOSAuditIntegration`, so it may be
dead code, but deleting a shipped feature is a product decision.

Consequence for the lint rule: a repo-wide `@mastra/auth-*` ban stays unavailable, because
`factory.ts:21` imports `MastraAuthStudio` and the integration imports `WorkOSAdminPortal`.
A rule scoped to `src/auth.ts` alone is true today and catches the regression that matters.
→ **`P14`**

The re-grade records this as **short of the criterion, not as done-with-a-reason.** The
backend A− criterion names the dependency removal explicitly, the reason it is blocked is a
good one, and both of those are true at once. The task is what carries the product decision
about `WorkOSAuditIntegration`.

### D5 gate result

The guide was validated by an engineer with no prior knowledge of this project, building a
generic OIDC provider from the docs alone. It reached `13 passed | 5 skipped`, zero
failures — but the exercise found the guide's own provider **does not compile** (six
`TS2339`s), that the token-exchange example posts JSON where RFC 6749 requires form
encoding, and that `verifyJwks` — the one-liner an OIDC provider most needs — is mentioned
only in a "Next steps" link at the bottom of the page, after the reader has hand-written
100 lines of WebCrypto.

Verdict: **yes-with-caveats for a bearer or vanilla hosted-login provider; no for a
production OIDC provider**, because a green conformance run tells you you are done while
PKCE and cookie cleanup are both absent and unchecked.

What held up: every numeric claim in the guide was exact, and four providers each built to
commit one mistake the docs warn about were all caught by exactly the named check.

**Re-checked at `a7909efb`.** The guide's three defects are fixed: `D4`'s
`typecheck:examples` job now compiles all 19 examples across the three new pages, so the
`TS2339`s cannot recur; the token exchange posts `application/x-www-form-urlencoded`
(`write-a-provider.mdx:341`); and `verifyJwks` is a prominent callout at line 50 rather
than a footer link. **The verdict itself stands**, and it is worth being precise about why:
it is not a documentation failure any more. PKCE (`P5`, `P6`) and cookie cleanup (`P11`)
are code gaps, and until they close, no amount of writing makes the answer yes.
