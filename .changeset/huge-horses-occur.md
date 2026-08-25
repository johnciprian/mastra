---
'@mastra/factory-auth': patch
---

Rewrote the `@mastra/factory-auth` README around what a provider author needs on day one, and added a stability policy for the contract this package re-exports.

**Removed a false status banner.** The README said the package was in progress and that the remaining modules were stubs. All nine entry points ship.

**Conformance is a runnable section now.** It shows the real `describeAuthProvider({ name, createProvider, token, ... })` call, states that `vitest` is an _optional_ peer dependency you install yourself, and quotes a real passing run and a real failure so you know what green and red look like before you write the file.

**Added a stability policy.** What a patch, minor and major mean for this package; the two wire formats you may build on (the OAuth `state` string and the `user:` organization id); which types resolve from your installed `@mastra/core` rather than from a copy frozen here; and that a new conformance check which can fail a currently conforming provider is a major, because it turns CI red in a repository this package does not own.

**The EE boundary is stated as part of the contract, not an implementation detail.** The package's runtime module graph contains no file under an `ee/` directory and its published types carry no enterprise declaration. No release trades that for a feature: a symbol that can only be re-exported by pulling enterprise code into the graph is not re-exported, in any bump.

Every code example is checked against the built package. The maintainer content, which is how the boundary checks are scoped and the procedure for proving they still fail, moved below the integrator path instead of sitting in the middle of it.
