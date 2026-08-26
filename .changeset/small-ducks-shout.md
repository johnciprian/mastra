---
'@mastra/factory': minor
---

Removed `isWorkOSAuth` and `getWorkOSProvider` from `@mastra/factory/auth`. Neither was reachable from any production path, and they were the last place the Factory's provider-neutral auth module asked which vendor was behind the provider.

**Why** Both worked by `instanceof MastraAuthWorkos`, which is the one question a provider-neutral module must not ask. It made a WorkOS import load-bearing for code paths that had nothing to do with WorkOS, and `instanceof` is unreliable in this monorepo anyway — a provider built against a second copy of its package fails the check while satisfying every interface it claims.

If you were reaching for either, ask what the provider can do instead of what it is:

```ts
// Before
if (isWorkOSAuth(provider)) {
  /* ... */
}

// After - capability guards from @mastra/core/server, or the descriptor
import { isOrganizationsProvider, isSSOProvider } from '@mastra/core/server';

if (isOrganizationsProvider(provider)) {
  /* ... */
}
```

These checks are structural, so they narrow correctly no matter which copy of a provider package built the instance.
