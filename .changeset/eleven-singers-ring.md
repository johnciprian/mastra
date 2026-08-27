---
'@mastra/auth-workos': minor
'@mastra/factory-auth': patch
'@mastra/ai-sdk': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth': patch
'@mastra/core': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

**`authorizeUser`, `protected`, `public` and `mapUserToResourceId` can now be typed.** All four were already honoured at run time — the constructor passes its options to `registerOptions`, which binds them — but `MastraAuthWorkosOptions` did not declare them, so passing one was a compile error against an API that worked. The option type now extends `MastraAuthProviderOptions`, as the other providers do.

**`getCurrentUser` now declares what it returns.** It resolved `EEUser | null` while its body built and returned a `WorkOSUser`, so `workosId`, `organizationId` and `memberships` — the fields this provider exists to supply — were invisible to callers, who had to cast to reach them. The sibling `getUser` already declared `WorkOSUser`:

```ts
const user = await auth.getCurrentUser(request);
user?.organizationId; // was a type error, no cast needed now
```
