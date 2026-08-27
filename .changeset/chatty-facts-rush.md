---
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

`features.logout` now counts `getClearSessionHeaders`. A provider that mints its own session cookie and clears it on sign-out can log a user out, whether or not it implements the rest of `ISessionProvider` — and now that the capability guards test their interface's full required set, such a provider no longer satisfies `isSessionProvider`, so the descriptor had stopped offering a sign-out control for it.

```ts
// A hosted-login provider that owns its cookie and can clear it.
toAuthDescriptor(provider).features.logout; // was false, now true
```

`destroySession` counts the same way. Both are read as members rather than through the guard, for the same reason `refresh` and `sessionRevocation` are.
