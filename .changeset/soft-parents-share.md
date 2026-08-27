---
'@mastra/factory': minor
---

Removed the last vendor names from the Factory's provider-neutral auth surface. The signed-in user now has one identifier, `id`, whichever provider issued it, and `@mastra/factory/auth` no longer offers a way to ask which vendor is behind a provider.

**Why** A vendor field beside the generic one meant every consumer had to decide which of the two was the real key, and different consumers answered differently. The helpers were worse: both worked by `instanceof MastraAuthWorkos`, which is the one question a provider-neutral module must not ask — and `instanceof` is unreliable in this monorepo anyway, because a provider built against a second copy of its package fails the check while satisfying every interface it claims.

**`workosId` is gone from the user shape**

```ts
// Before
const userId = user.workosId ?? user.id;

// After
const userId = user.id;
```

The resolved id does not change. Where a payload carries only `workosId`, the pre-migration reader folds it into `id` using the same precedence the old helper applied, so existing sessions keep the key their data is already stored under. Reading `user.workosId ?? user.id` also still works.

**`isWorkOSAuth` and `getWorkOSProvider` are gone**

Neither was reachable from any production path. Ask what a provider can do instead of what it is:

```ts
// Before
if (isWorkOSAuth(provider)) {
  /* ... */
}

// After — capability guards from @mastra/core/server, or the descriptor
import { isOrganizationsProvider, isSSOProvider } from '@mastra/core/server';

if (isOrganizationsProvider(provider)) {
  /* ... */
}
```

These checks are structural, so they narrow correctly no matter which copy of a provider package built the instance.

With both removed, the Factory's auth module — its gate, its routes, and both of its test suites — is built entirely on the provider contract and imports no vendor auth package. `@mastra/auth-workos` stays a dependency of `@mastra/factory` for now, because `@mastra/factory/integrations/workos/integration` still uses it for WorkOS audit-log export.
