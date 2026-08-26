---
'@mastra/factory-auth': minor
---

Added a `knownFailures` option to `describeAuthProvider`, for a provider that ships without conforming.

Some conformance failures are real defects with no small fix. Until now that left three options — weaken the suite until it passes, leave CI red until people stop reading it, or drop the provider from the run — and all three end with nobody knowing the provider is broken. You can now record the failure instead:

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

**Conformance failures now carry stable codes.** Every failure quotes one, and shows the entry to paste if it cannot be fixed today. A check has several ways to go red, so matching on which one is what stops an entry from absorbing a second, unrelated regression in the same check. Codes are values you can hold; failure message wording stays patch-level as before.

**Fixed a misdiagnosis in the hosted-login callback check.** A `handleCallback` that reached the token exchange and rethrew a flat error with no `cause` was reported as having rejected the OAuth `state` — sometimes of a method that never reads `state`. The check now counts calls to the stubbed `fetch`, so it reports what it observed, and asks for `new Error('...', { cause: error })` rather than sending you to debug a `state` you never rejected. It still fails, so nothing that used to pass starts passing.

**Added `runAuthConformanceCheck(check, provider, name)`.** `describeAuthProvider` is now a thin adapter over it, so a script, a CLI, or another test runner walking `authConformanceChecks` enforces exactly the same rules.
