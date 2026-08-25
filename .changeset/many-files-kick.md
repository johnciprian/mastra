---
'@mastra/factory-auth': patch
---

Filled the unit-test gaps in the auth kit so every published symbol has direct coverage, and put a coverage floor behind it.

**Every check in the conformance suite is now demonstrably able to fail.** `describeAuthProvider` ships twelve checks beyond the four obligations - the base contract, hosted login, credentials, sessions, auth routes and init - and none of them had ever been observed going red. A check whose condition can never be true passes every provider silently, which is the failure the suite exists to prevent. There is now one deliberately-broken provider per failure path, asserting which check goes red and that no other one does, so a red result from your own suite is evidence about the thing it names.

**The published surface is pinned as an inventory.** A new test reads the built `.d.ts` behind each of the nine `exports` subpaths and compares it against a written list, values and types alike, and cross-checks every declared value against the runtime module. Adding, removing or renaming anything a consumer can import is now a diff on that list.

**A coverage threshold is enforced on every test run**: 100% lines and functions, 97% statements, 94% branches.

**Known limitation, unchanged by this release.** The `credentials/sign-up-enabled` check cannot fail for an `async isSignUpEnabled()`, which is the exact shape its failure text is written about - the suite awaits the return value, so a Promise resolving to `true` arrives as `true`. `toAuthDescriptor` meanwhile reports that provider as sign-up-disabled, because it reads the value without awaiting. Keep the method synchronous:

```ts
// The suite passes this, and the descriptor hides your sign-up link anyway.
async isSignUpEnabled() { return this.config.signUpEnabled; }

// Cache it at construction instead.
isSignUpEnabled() { return this.signUpEnabled; }
```
