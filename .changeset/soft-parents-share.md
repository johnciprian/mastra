---
'@mastra/factory': minor
---

Removed `workosId` from the Factory's user shape. The signed-in user now has one identifier, `id`, whichever provider issued it.

**Why** The neutral type carried a vendor field beside the generic one, so every consumer had to decide which of the two was the real key — and different consumers answered differently. A vendor name in a provider-agnostic type is the sign that identity was never really abstracted.

```ts
// Before
const userId = user.workosId ?? user.id;

// After
const userId = user.id;
```

The resolved id does not change. Where a payload carries only `workosId`, the pre-migration reader folds it into `id` using the same precedence the old helper applied, so existing sessions keep the key their data is already stored under.

If you read `workosId` off `FactoryAuthUser` or off a request context's `user`, switch to `id`. Reading `user.workosId ?? user.id` already keeps working.
