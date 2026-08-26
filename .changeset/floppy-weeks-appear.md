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

Fixed `mapUserToResourceId` so an auth provider can implement it as an ordinary method.

`MastraAuthProvider`'s constructor assigned the `mapUserToResourceId` option unconditionally, so a provider that implemented the method but did not forward the option got an own property holding `undefined` that shadowed its own method. The method never ran, `typeof provider.mapUserToResourceId === 'function'` read false, and the server silently fell back to the user's `id` for memory resource ids. Nothing reported an error.

**Before** — the method was unreachable:

```ts
class MyAuth extends MastraAuthProvider<MyUser> {
  constructor(options?: MastraAuthProviderOptions<MyUser>) {
    super({ name: 'my-auth' });
  }

  mapUserToResourceId(user: MyUser) {
    return user.tenantId;
  }
}

typeof new MyAuth().mapUserToResourceId; // 'undefined'
```

**After** — it runs, and a supplied option still overrides it:

```ts
typeof new MyAuth().mapUserToResourceId; // 'function'

new MyAuth({ mapUserToResourceId: user => user.id }).mapUserToResourceId; // the option wins
```

**Upgrade note**

If you maintain a provider that implements `mapUserToResourceId` as a method and does not forward the option, that method starts running on upgrade. Memory resources were being keyed on the authenticated user's `id`; they will now be keyed on whatever your method returns. If the two differ, data written under the old key is not found under the new one, and nothing raises an error. Check that your method returns the same value the user's identity resolves to, or pass `mapUserToResourceId` as an option to keep the previous value.

Providers that never implemented the method are unaffected — it stays absent, exactly as before.
