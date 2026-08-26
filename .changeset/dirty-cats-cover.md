---
'@mastra/factory-auth': major
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
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

**Added a conformance check that fails a half-implemented capability interface.** `contract/whole-capabilities` asks every capability interface in the contract one question: does this provider carry all of the members it requires, or none of them? Some but not all is now a failure.

Every capability guard tests every member its interface requires, so a provider carrying two of `ISSOProvider`'s three members fails `isSSOProvider` — and a host branching on that guard treats it as having no hosted login at all. The methods that were written are never called, and nothing anywhere says so. Every section of this suite is gated on a guard too, so half an interface used to skip its own section and report nothing. It was the one defect the suite could not see.

```ts
// Fails now. isSSOProvider is false, so a host draws no sign-in button and calls neither method.
class MyProvider extends MastraAuthProvider {
  getLoginUrl(redirectUri: string, state: string) {
    /* ... */
  }
  async handleCallback(code: string, state: string) {
    /* ... */
  }
}

// Conforming: all three members ISSOProvider requires.
class MyProvider extends MastraAuthProvider implements ISSOProvider {
  getLoginUrl(redirectUri: string, state: string) {
    /* ... */
  }
  async handleCallback(code: string, state: string) {
    /* ... */
  }
  getLoginButtonConfig() {
    return { provider: 'my-provider', text: 'Sign in with My Provider' };
  }
}
```

**Four failure codes, one per interface it reports:** `contract/whole-capabilities#partial-sso`, `#partial-sessions`, `#partial-credentials` and `#partial-organizations`. `IAuthHttpHandler`, `IAuthInit` and `ISessionClearer` require one member each, so there is no part of them to carry. `IUserProvider` is still reported by `users/current-user` and `users/get-user`, which own one member each and can say what its absence costs; the new check names those two rather than reporting the same defect twice.

**One partial shape passes, and it passes by rule rather than by name.** `ISessionProvider` extends `ISessionClearer`, a declared one-member interface with its own guard, `canClearSession`. A provider implementing `getClearSessionHeaders` and none of the other six members is the whole of the smaller interface — which is what a provider that mints its own cookie on callback and creates no session a host can address by id wants. Any member set that is exactly a declared sub-interface's required set is treated as whole. A partial shape with no interface behind it fails however reasonable it looks: declare the interface first.

**This is a breaking change.** A new check can turn CI red in a repository this package does not own. Measured against all eleven providers here it turns none of them red — the only partial shape any of them has is `@mastra/auth-better-auth`'s `ISessionClearer`, which the check exempts — and it ships as a major anyway, because "no provider in this repository goes red" is a fact about this repository.
