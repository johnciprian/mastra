---
'@mastra/factory-auth': minor
---

Added `@mastra/factory-auth`, a new Apache-2.0 package for making an auth provider work with the Mastra Software Factory.

This release is the package scaffold and the licence boundary that guards it. Eight entry points are published and stable from day one, so no later release has to move an import path:

```ts
import { toAuthIdentity, isSSOProvider } from '@mastra/factory-auth';
import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
import { mintSessionCookie } from '@mastra/factory-auth/cookie';
import { encodeState, decodeState } from '@mastra/factory-auth/oauth-state';
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
```

The modules behind those paths are stubs in this release; each one names the work that fills it.

**Why the boundary matters**

The package is Apache-2.0 and must never reach code under an `ee/` directory. Two checks enforce that, and both run in CI: `no-restricted-imports` in ESLint and oxlint rejects banned specifiers in source, and a module-graph test resolves every published entry point over source and fails on any module inside an `ee/` directory, on any external import outside a fail-closed allowlist, and on any enterprise identifier in built output.

The ban is wider than the obvious paths. `@mastra/core/server` is clean, but `@mastra/core/auth` reaches 11 enterprise modules, the `@mastra/core` root barrel reaches 14, and every `@mastra/auth-*` provider package reaches 11. Import the contract from `@mastra/core/server` instead. `mastracode/factory-auth/README.md` documents the boundary and the procedure for re-proving it.
