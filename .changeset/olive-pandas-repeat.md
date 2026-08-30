---
'@mastra/factory': minor
---

A Factory running with auth disabled now resolves a local single-user tenant, so tenant-scoped routes serve instead of answering 401.

**Why** `auth: AUTH_DISABLED` produced an open server that refused its own operator. `factoryAuthTenant` reads the signed-in user out of the request context, so with no provider there was nobody to read and it answered `undefined` — correct for a gated route, wrong for a deployment that turned auth off on purpose. Five route modules gate on `if (!tenant) return 401` (projects, work-items, knowledge, intake, provider-credentials), which is most of what the app stores, so "no auth" meant "no app".

The substitution happens in `createFactoryRouteAuth`, the one place that already knows which case it is in because it holds the provider. The five routes are unchanged.

```ts
// Before — every tenant-scoped route 401s
new MastraFactory({ auth: AUTH_DISABLED, storage });

// After — the same config serves, as a single `local` identity
new MastraFactory({ auth: AUTH_DISABLED, storage });
```

`LOCAL_TENANT_ID` (`'local'`) is exported and is now the single definition of that sentinel; `custom-provider-source.ts` previously carried its own copy for model config, with a comment warning it "must match the custom provider routes".

**This is not a fallback for a failed sign-in.** The condition is that no provider is configured, never that a request failed to authenticate — a configured deployment still answers 401 to an anonymous caller, and a test pins that direction specifically. An auth-disabled deployment now has one identity for every caller, which suits the single-user local development it was already documented for and remains unsafe to deploy.

The GitHub and Linear feature gates drop their `auth.enabled()` requirement for the same reason. Both are configuration checks now — `isGithubFeatureEnabled` is `github !== undefined`, and Linear's is `Boolean(linear)`. Each integration still completes its own OAuth, so the provider verifies the account independently of whoever is using the Factory; GitHub additionally refuses to trust a raw `installation_id` without a verified user token, which is untouched. An auth-off server was already open on every route, so the exposure is unchanged — it is now simply usable.
