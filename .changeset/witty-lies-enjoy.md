---
'@mastra/auth-supabase': minor
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
---

Changed how `@mastra/auth-supabase` authorizes users, and documented what it can and cannot do.

**`authorizeUser` no longer requires a `users` table**

The old default allowed only users with a truthy `isAdmin` column in a `users` table. Deployments without that exact table authenticated a user and then answered 403 to every core `/api/*` request, with nothing in the response naming the missing table. The default now allows any user the provider authenticated.

To keep the old behaviour, ask for it:

```typescript
const supabaseAuth = new MastraAuthSupabase({ requireAdminRow: true });
```

**Supabase now resolves an organization**

`ensureOrganization(userId)` returns a stable `user:${userId}`, so organization-scoped storage has something correct to write. Supabase has no organization primitive, so the id is derived rather than stored and is identical in every process and every deploy.

**It says out loud that it cannot sign you in from a browser**

`@mastra/auth-supabase` validates API tokens; it cannot take somebody from a blank browser to a signed-in session, so it cannot run the Mastra Factory's browser sign-in. Supabase's `signInWithOAuth` cannot carry the host's OAuth `state`, and its PKCE code verifier lives in the supabase-js client's storage rather than in a store shared between the login and callback requests. The decision and its reasoning are exported as `FACTORY_BROWSER_SIGN_IN` and readable from a provider instance as `provider.factoryBrowserSignIn`.

**Also**

- An empty token now returns `null` without a round trip to Supabase.
- A `client` option accepts a Supabase client you already hold, which is also what lets the provider be tested with no network and no project.
