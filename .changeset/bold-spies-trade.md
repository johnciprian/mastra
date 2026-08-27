---
'@mastra/core': minor
'@mastra/factory-auth': patch
---

**A provider can now declare that it manages sessions without being able to create one.** `ISessionManager` is `ISessionProvider` minus `createSession`, with a matching guard, `canManageSessions`.

**Why** Real identity services issue a session in exchange for a credential a person presented — a password, a code from an SSO round trip — and offer no way to conjure one from a user id. Such a provider had two options before this, and both were dishonest: declare `ISessionProvider` and stub `createSession`, which makes every guard report a capability that is not there; or declare nothing, and lose revocation, refresh and cookie handling that all work.

```ts
// Before: the member exists, so isSessionProvider is true, so a host may call it.
class MyProvider implements ISessionProvider {
  async createSession(userId: string) {
    throw new Error('cannot mint'); // or, worse, return something invented
  }
  // ...the six that actually work
}

// After: declare the half you have. canManageSessions reports it.
class MyProvider implements ISessionManager {
  // ...the six that actually work, and no createSession
}
```

The session interfaces are now a chain — `ISessionProvider extends ISessionManager extends ISessionClearer` — so a full session provider satisfies all three guards and the members stay declared in one place. Nothing that worked before stops working.

Branch on `canManageSessions` wherever a host acts on a session that already exists: sign-out, refresh, reading the session id. Reserve `isSessionProvider` for the one thing it adds.

The conformance suite in `@mastra/factory-auth` recognises the new interface by rule: a provider carrying exactly its members is whole rather than half of a bigger one, so it passes `contract/whole-capabilities` instead of failing it.
