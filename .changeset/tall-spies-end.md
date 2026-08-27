---
'@mastra/factory-auth': minor
---

Added `@mastra/factory-auth`, a new Apache-2.0 package for making an auth provider work with the Mastra Software Factory.

It holds the pieces a provider and its host have to agree on and previously did not write down anywhere: the provider contract, one identity shape, a capability descriptor, a signed session cookie, the OAuth `state` format, and a conformance suite that checks a provider against all of it.

```ts
import { toAuthIdentity, toAuthDescriptor, isSSOProvider } from '@mastra/factory-auth';
import { mintSessionCookie, readSessionCookie } from '@mastra/factory-auth/cookie';
import { encodeState, decodeState } from '@mastra/factory-auth/oauth-state';
```

Nine entry points are published: the root, `./contract`, `./identity`, `./capabilities`, `./organizations`, `./cookie`, `./oauth-state`, `./testing` and `./conformance`. The root export holds the pure layer — types, structural guards and pure functions — so a UI can import it without reaching server code.

**The licence boundary**

The package is Apache-2.0 and never reaches code under an `ee/` directory. Two checks enforce that in CI: `no-restricted-imports` in ESLint and oxlint rejects banned specifiers in source, and a module-graph test resolves every source file over the workspace's TypeScript sources and fails on any module inside an `ee/` directory, on any external import outside a fail-closed allowlist, and on any enterprise identifier in built output.

The ban is wider than the obvious paths. `@mastra/core/server` is clean, but `@mastra/core/auth` reaches 11 enterprise modules, the `@mastra/core` root barrel reaches 14, and every `@mastra/auth-*` provider package reaches 11. Import the contract from `@mastra/core/server` instead.

**Versioning**

`@mastra/core` is a peer dependency ranged `>=1.61.0-0 <2.0.0-0`; `vitest` is an optional peer needed only by `./conformance`. The nine entry points and every symbol they export are the covered surface — anything reached by a deep path into `dist/` is not.

- **Patch** — a defect fixed with no change to a signature or a documented value. Conformance failure text, skip reasons and error message wording are patch-level. Don't assert on them.
- **Minor** — new exports, a new optional field, a widened input.
- **Major** — a removed or renamed export, a narrowed input, a changed return type, and a new conformance check that a currently conforming provider can fail, because that turns CI red in a repository this package does not own.

This package is `0.x`, so a minor bump does not carry semver's cross-version compatibility promise. Read the changelog before you bump. Nothing is marked experimental and nothing is behind a flag.
