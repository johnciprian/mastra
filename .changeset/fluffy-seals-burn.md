---
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth': patch
'@mastra/core': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

Fixed two order-dependent test suites in the auth provider packages. Neither was failing in CI, because tests run in declaration order there, but both would have started failing the moment a test was added, moved, or reordered.

`@mastra/auth-studio`'s last describe replaced `globalThis.fetch` by assignment rather than through `vi.spyOn`, and `vi.restoreAllMocks()` cannot undo an assignment. The replacement outlived the block, so any suite running after it spied on the leftover mock and inherited its call history — a test asserting "fetch was never called" saw seven calls it never made. Its `fetch` spy also had no default implementation, so once a test's queued responses ran out the suite made real network calls; two requests were leaving the process on every run.

`@mastra/auth-clerk` reset mocks with `vi.clearAllMocks()`, which drops call history but keeps implementations. A `mockResolvedValue` set by one test answered every later test that did not set its own, so tests inherited each other's identities.

All eleven provider packages now pass with their test order shuffled, across six seeds.
