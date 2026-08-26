---
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

Fixed a flaky test suite. The provider packages ran their unit tests with a shared module registry, so a `vi.mock` of the vendor SDK in one test file could reach a sibling file that needs the real module — including each package's conformance suite, whose value depends on the SDK not being mocked.

Whichever file loaded the module first won, so about one full run in ten failed, in a different package each time. Once it surfaced as the conformance suite's security check reporting that a perfectly good provider authenticated an arbitrary token.

Each provider package now runs its unit tests isolated. Twenty consecutive full runs pass, and the sweep times the same as before to within 1%.
