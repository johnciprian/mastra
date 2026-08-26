---
'@mastra/factory-auth': patch
---

Fixed a misleading conformance failure. When a provider rejects the `token` fixture on both the bearer and the cookie path, obligation 2 no longer claims "the credential is good and the Cookie header is not being read" — a claim it had not established. It now reports the rejected token fixture, the same way every other check already did, so a provider that failed to start is not misdiagnosed as one with broken cookie parsing.
