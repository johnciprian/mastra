---
'@mastra/core': minor
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

**Capability guards now check every member their interface requires.** Four of the seven guards exported from `@mastra/core/server` tested only some of the members their interface declares as required. `isSessionProvider` read two of seven, `isSSOProvider` two of three, and `isUserProvider` and `isCredentialsProvider` one of two each.

Because a guard is a type predicate, passing it narrowed a provider to the full interface — so calling a member the guard never checked for compiled cleanly and threw at run time:

```ts
// Before: compiled, and threw `auth.destroySession is not a function`
// for any provider that had createSession and validateSession and no more.
if (isSessionProvider(auth)) {
  await auth.destroySession(sessionId);
}
```

Each guard now tests every required member, and no optional one. Optional members are still for the caller to feature-detect:

```ts
// Still correct, and still necessary: getLogoutUrl is optional on ISSOProvider.
if (isSSOProvider(auth) && typeof auth.getLogoutUrl === 'function') {
  redirect(await auth.getLogoutUrl(returnTo));
}
```

**This can change what a guard reports for your provider.** A provider that satisfied a guard with a subset of the required members no longer does, so a surface branching on that guard will stop offering the capability. Every provider published from this repository is unaffected — each declares its interfaces with `implements`, which already forced the members to exist — but a provider that was only ever structurally compatible may be. If yours stops passing a guard, the guard is now telling you the truth: implement the missing member, or drop the interface.

The check/required/declared counts are in the capability interfaces reference, and adding a required member to one of these interfaces now fails the build until its guard tests the new member too.
