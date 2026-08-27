---
'@mastra/core': minor
'@mastra/auth-better-auth': minor
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

**A provider can now declare that it clears its own session cookie.** `ISessionClearer` is a one-member interface — `getClearSessionHeaders()` — with a matching guard, `canClearSession`.

Until now that member existed only inside `ISessionProvider`, whose guard requires all seven of its members. A provider that mints its own cookie during a hosted login and clears it on logout has no session a host can address by id, so the other six mean nothing to it. Those providers implemented the member anyway and hosts reached for it through a structural cast that no interface described:

```ts
// Before, in the host: a convention, not a contract.
const clear = (provider as Partial<ISessionProvider>).getClearSessionHeaders;

// After: a declared capability, with a guard.
if (canClearSession(provider)) {
  headers = provider.getClearSessionHeaders();
}
```

`ISessionProvider` extends `ISessionClearer`, so every full session provider satisfies the new guard too and the member stays declared in one place. Nothing that worked before stops working.

`@mastra/auth-better-auth` — which owns its cookie and implements exactly this one member — now declares the interface instead of relying on the convention.
