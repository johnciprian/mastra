---
'@mastra/auth-okta': minor
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
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
---

**`authorizeUser`, `protected`, `public` and `mapUserToResourceId` can now be typed.** All four were already honoured at run time — the constructor passes its options to `registerOptions`, which binds them — but neither option type declared them, so passing one was a compile error against an API that worked:

```ts
new MastraAuthOkta({
  domain: 'dev-1.okta.com',
  clientId: 'c',
  authorizeUser: async user => user.email?.endsWith('@example.com') ?? false, // was error TS2353
});
```

Both option types now extend `MastraAuthProviderOptions`, as the other nine providers always have. Nothing changes at run time.
