---
'@mastra/auth-workos': major
---

**Breaking: `MastraAuthWorkos.createSession()` is removed.** The provider now declares `ISessionManager` instead of `ISessionProvider`.

**Why** WorkOS issues a session only from an authenticated token exchange — a real credential presented by a real person — and `@workos-inc/node` has no call that mints one from a user id. `createSession(userId)` returned a record with a random id that nothing would ever accept. Its presence made `isSessionProvider` report `true`, so a host could take a branch that called it.

Everything else this provider does with sessions is unchanged and now genuinely implemented: `validateSession`, `destroySession`, `refreshSession`, `getSessionIdFromRequest`, `getSessionHeaders` and `getClearSessionHeaders`.

**What to change** If you called `createSession` on this provider, you were getting a record that could not authenticate anybody — remove the call. If you branched on `isSessionProvider`, branch on `canManageSessions` instead:

```ts
// Before
if (isSessionProvider(auth)) {
  await auth.destroySession(sessionId);
}

// After — true for this provider, and for every full session provider too
if (canManageSessions(auth)) {
  await auth.destroySession(sessionId);
}
```

`canManageSessions` is exported from `@mastra/core/server` and is satisfied by every `ISessionProvider` as well, so the swap is safe for code that handles more than one provider.
