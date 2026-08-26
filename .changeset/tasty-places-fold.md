---
'@mastra/core': patch
---

Fixed `getWebRequest` and `getRequestHeader` rejecting the request your own auth provider receives.

`@mastra/core/server` declared its own `MastraAuthRequest`/`HonoRequestLike` that had drifted from the one `MastraAuthProvider` is defined against. Passing the request from `authenticateToken`, `authorizeUser`, or the `authorizeUser` option into either helper failed with `TS2345`, even though both come from the same entry point. `getRequestHeader` also threw a `TypeError` on an Express-style request whose `headers` is a plain object.

**Before**

```typescript
import { getWebRequest } from '@mastra/core/server';
import type { MastraAuthRequest } from '@mastra/core/server';

new MyAuthProvider({
  // The annotation was required. Without it: TS2345, argument of type
  // MastraAuthRequest is not assignable to parameter of type MastraAuthRequest.
  authorizeUser: (user, request: MastraAuthRequest) => getWebRequest(request) !== undefined,
});
```

**After**

```typescript
import { getWebRequest } from '@mastra/core/server';

new MyAuthProvider({
  authorizeUser: (user, request) => getWebRequest(request) !== undefined,
});
```

`HonoRequestLike.header()` is now optional and `headers` also accepts a plain record, matching what providers are actually handed. Read headers through `getRequestHeader(request, name)` rather than calling `request.header()` directly.

Also exported `StoredResourceScopeConfig`, `StoredResourceScopeResolver`, and `StoredResourcesConfig` from `@mastra/core/server`, and gave them a user type parameter, so a stored-resource scope resolver can read the authenticated user without a cast:

```typescript
const scope: StoredResourceScopeConfig<MyUser> = {
  metadataKey: 'organizationId',
  resolve: ({ user }) => user?.organizationId,
};

new Mastra({ server: { storedResources: { scope } } });
```
