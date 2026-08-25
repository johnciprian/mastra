---
'@mastra/factory-auth': minor
---

Added `@mastra/factory-auth`, a new Apache-2.0 package for making an auth provider work with the Mastra Software Factory.

It holds the pieces a provider and its host have to agree on and previously did not write down anywhere: the provider contract, one identity shape, a capability descriptor, a signed session cookie, and the OAuth `state` format.

```ts
import { toAuthIdentity, toAuthDescriptor, isSSOProvider } from '@mastra/factory-auth';
import { mintSessionCookie, readSessionCookie } from '@mastra/factory-auth/cookie';
import { encodeState, decodeState } from '@mastra/factory-auth/oauth-state';
```

Nine entry points are published and stable: the root, `./contract`, `./identity`, `./capabilities`, `./organizations`, `./cookie`, `./oauth-state`, `./testing` and `./conformance`. The root export holds the pure layer — types, structural guards and pure functions — so a UI can import it without reaching server code.

**The licence boundary**

The package is Apache-2.0 and must never reach code under an `ee/` directory. Two checks enforce that, and both run in CI: `no-restricted-imports` in ESLint and oxlint rejects banned specifiers in source, and a module-graph test resolves every source file over the workspace's TypeScript sources and fails on any module inside an `ee/` directory, on any external import outside a fail-closed allowlist, and on any enterprise identifier in built output.

The ban is wider than the obvious paths. `@mastra/core/server` is clean, but `@mastra/core/auth` reaches 11 enterprise modules, the `@mastra/core` root barrel reaches 14, and every `@mastra/auth-*` provider package reaches 11. Import the contract from `@mastra/core/server` instead. `mastracode/factory-auth/README.md` documents the boundary and the procedure for re-proving it.
