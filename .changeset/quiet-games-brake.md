---
'@mastra/factory-auth': major
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

**`features.refresh` and `features.sessionRevocation` no longer depend on the session guard.** `toAuthDescriptor` used to require `isSessionProvider` before reading either method. Now that the guard tests all seven members `ISessionProvider` requires, that gate would have made both fields exactly equal to the guard — and would have reported no session features at all for a provider carrying six of the seven, including the ones it does have.

Each field names a button a UI renders and then a method that button calls, so each is now read off its own method:

```ts
// A provider with destroySession and refreshSession and nothing else.
toAuthDescriptor(provider).features;
// Before: { refresh: false, sessionRevocation: false, logout: false, ... }
// After:  { refresh: true,  sessionRevocation: true,  logout: true,  ... }
```

`features.logout` also counts `destroySession` now: a provider that can end a session can sign someone out, whether or not it satisfies the whole interface.

**Conformance catches half an interface instead of skipping it.** The user checks used to be gated on `isUserProvider`. With the tightened guard, a provider implementing `getCurrentUser` and not `getUser` fails that guard, and the section would have skipped — leaving the defect unreported and the whole capability silently absent. The gate now admits a provider carrying either member, and each check reports on its own:

- `users/get-user#not-declared` — has `getCurrentUser`, no `getUser`
- `users/current-user#not-declared` — has `getUser`, no `getCurrentUser` (new)

A provider with neither still skips, because that is a decision rather than an unfinished job.
