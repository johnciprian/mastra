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

Planning only — no implementation has started. The first executable step is task `K1`
in `tasks.json`.
