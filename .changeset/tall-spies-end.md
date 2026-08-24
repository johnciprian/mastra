---
'@mastra/factory-auth': minor
---

Added `@mastra/factory-auth`, a new Apache-2.0 package for making an auth provider work with the Mastra Software Factory.

**This release is the package shell, not the implementation.** Every module is empty. What ships is the public shape and the licence boundary that guards it, so the modules can be filled in later without moving a single import path.

Nine entry points are declared and stable from day one:

```jsonc
"@mastra/factory-auth"                 // the pure layer: contract, identity, capabilities
"@mastra/factory-auth/contract"        // the provider contract, re-exported from @mastra/core/server
"@mastra/factory-auth/identity"        // one identity shape across providers
"@mastra/factory-auth/capabilities"    // which capabilities a provider has
"@mastra/factory-auth/organizations"   // which organization an identity belongs to
"@mastra/factory-auth/cookie"          // the host-owned session cookie
"@mastra/factory-auth/oauth-state"     // the OAuth `state` parameter codec
"@mastra/factory-auth/testing"         // test doubles, for code that consumes a provider
"@mastra/factory-auth/conformance"     // the suite, for code that implements a provider
```

Nothing is exported from them yet, so there is no reason to install this release unless you are working on the package itself.

**Why the boundary matters**

The package is Apache-2.0 and must never reach code under an `ee/` directory. Two checks enforce that, and both run in CI: `no-restricted-imports` in ESLint and oxlint rejects banned specifiers in source, and a module-graph test resolves every source file over the workspace's TypeScript sources and fails on any module inside an `ee/` directory, on any external import outside a fail-closed allowlist, and on any enterprise identifier in built output.

The ban is wider than the obvious paths. `@mastra/core/server` is clean, but `@mastra/core/auth` reaches 11 enterprise modules, the `@mastra/core` root barrel reaches 14, and every `@mastra/auth-*` provider package reaches 11. Import the contract from `@mastra/core/server` instead. `mastracode/factory-auth/README.md` documents the boundary and the procedure for re-proving it.
