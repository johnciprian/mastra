---
'@mastra/factory': patch
---

Added `@mastra/factory-auth` as a dependency of `@mastra/factory`. Nothing imports it yet; this makes the Apache-2.0 auth kit available so the Factory's identity, session and OAuth-state handling can move onto it.

**Enterprise-boundary lint rule**

The Factory now rejects three import shapes in both oxlint and ESLint, in test files as well as source:

- `@mastra/core/auth` and its subpaths
- `@internal/auth` and its subpaths
- any specifier naming an `ee/` path segment

Each of these reaches enterprise-licensed code at runtime, and the Factory makes none of them today. `@mastra/core/server` exposes the same auth interfaces and guards without reaching `ee/`, and is already the Factory's most-used core entry point.

**Why it is narrower than the kit's own ban**

`@mastra/factory` is the host application, and it legitimately depends on `@mastra/core` barrels that reach `ee/` transitively. Copying the kit's stricter ban would fail on around fifty existing imports and could only be made green by exempting each one, which would leave the rule saying nothing. So the Factory bans only the reaches it could introduce itself. The full measurement and reasoning are written out in `mastracode/factory/eslint.config.js`.
