---
'@mastra/auth-better-auth': minor
'@mastra/factory-auth': patch
'@mastra/factory': patch
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

**`new MastraAuthBetterAuth({ auth: betterAuth({ ... }) })` now type-checks.** The `auth` option was declared as the bare `Auth`, which no real instance satisfied. `betterAuth()` is generic over the exact options object it is handed, and `Auth<T>` is invariant in `T` — `AuthContext<T>` reaches `DBAdapter<T>`, whose `createSchema(options: T)` puts `T` in a contravariant position — so the inferred `Auth<{ your literal }>` was not assignable.

That call is what the README, both docs pages and the class JSDoc all show, so the documented usage failed for everyone, with a wall of `$context`/`DBAdapter` mismatch:

```ts
// Before: error TS2322 — Type 'Auth<{ database: ...; emailAndPassword: ... }>'
// is not assignable to type 'Auth'.
const provider = new MastraAuthBetterAuth({
  auth: betterAuth({
    database: { provider: 'sqlite', url: 'file:./auth.db' },
    emailAndPassword: { enabled: true },
  }),
});
```

The workaround was to hoist the literal into a `const options: BetterAuthOptions` first. That is no longer needed — the snippet above compiles as written.

The class takes a `TAuthOptions` parameter inferred from the instance you pass. You never write it, no member of the class mentions it, and it defaults to `BetterAuthOptions`, so `MastraAuthBetterAuth` on its own still means what it did and instances built from different options remain mutually assignable:

```ts
const annotated: MastraAuthBetterAuth = provider; // still fine
```

Note `Auth<BetterAuthOptions>` would not have fixed this: the bare `Auth` already is `Auth<BetterAuthOptions>`.
