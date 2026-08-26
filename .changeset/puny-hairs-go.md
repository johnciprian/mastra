---
'@mastra/factory-auth': minor
---

Added `describeAuthProvider`, a drop-in conformance suite an auth provider package runs in its own CI. It asserts the contract a provider declares and the four requirements that decide whether it can actually run the Mastra Factory: a flat resolvable `id`, an `authenticateToken` that reads the `Cookie` header when the bearer token is empty, agreement with the kit's OAuth `state` codec, and an organization id.

```ts
// auth/my-provider/src/conformance.test.ts
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { MyAuthProvider } from './auth-provider.js';

describeAuthProvider({
  name: '@mastra/auth-my-provider',
  createProvider: () => new MyAuthProvider({ verify: fakeVerifier }),
  token: 'a-token-my-provider-accepts',
  userId: 'user_123',
  cookieHeader: 'my_provider_session=a-token-my-provider-accepts',
});
```

It needs no network, no identity provider and no environment variables. `vitest` is an optional peer dependency, and this is the only entry point in the package that imports it.

**What a failure tells you**

Each failure names the obligation, quotes the call the suite made and the answer it got, explains the outcome the rule prevents, and shows the fix as code. A provider that ignores the `Cookie` header is told that a browser navigation sends no `Authorization` header, that the same credential works as a bearer token, and how to fall back to the header with `getRequestHeader`.

Every failure also quotes a stable code, such as `sessions/round-trip#validate-rejects-fresh-session`. A check has several ways to go red, and the code says which one. Codes are values you can hold; failure message wording is patch-level.

**Skipped, never quietly passed**

A check is skipped only when a capability guard says the provider does not declare the capability the check is about, and the skip carries its reason. A bearer-token validator that cannot sign anyone in from a browser skips the hosted-login and cookie checks instead of failing them. The organization check is deliberately not gated that way: a provider with no organizations fails it, and `withSyntheticOrganizations` is the one-line fix.

**Recording a failure you cannot fix today**

Some conformance failures are real defects with no small fix. Without somewhere to put them the options are to weaken the suite until it passes, leave CI red until people stop reading it, or drop the provider from the run — and all three end with nobody knowing the provider is broken. `knownFailures` records the failure instead:

```ts
describeAuthProvider({
  name: '@mastra/auth-my-provider',
  createProvider: () => createAuth(verifier),
  token: TOKEN,
  knownFailures: [
    {
      check: 'sessions/round-trip',
      code: 'sessions/round-trip#validate-rejects-fresh-session',
      reason: 'validateSession returns null unconditionally. Tracked in #4821.',
    },
  ],
});
```

The suite goes green, and it is visibly not the green of a clean provider: the test title is prefixed with `known failure:`, the reason is printed where the default reporter shows it, and the original failure stays in the output.

**It cannot rot into a permanent exemption.** Every entry is checked in both directions on each run. The suite fails if a recorded check passes, if it stops applying to the provider, or if it fails for a different reason than the one recorded — so fixing the defect forces the entry to be deleted in the same change. An entry naming a check that does not exist, or a failure code that check cannot produce, fails at registration rather than being quietly ignored, and `reason` is required and non-empty.

**Running the checks outside vitest**

`authConformanceChecks` is the list of checks, and `runAuthConformanceCheck(check, provider, name)` runs one. `describeAuthProvider` is a thin adapter over them, so a script, a CLI, or another test runner enforces exactly the same rules.

**Two notes on how the suite behaves under a provider that misbehaves.** `credentials/sign-up-enabled` judges what `isSignUpEnabled` returns without awaiting it, so an `async isSignUpEnabled()` fails the check — the same judgement `toAuthDescriptor` makes, so a provider the suite passes is a provider the descriptor reads correctly. And a provider whose property read throws is reported once, by `contract/descriptor`, which is the check that explains it: the checks whose skip conditions have to read the same property skip with a pointer there instead of surfacing an error of their own.
