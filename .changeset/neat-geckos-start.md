---
'@mastra/factory': minor
---

Agent runs now resolve the caller through the same identity seam as HTTP routes. A run started by a user whose provider has no organizations no longer behaves differently from a request made by the same user.

**Why** Three modules — dynamic workspace resolution, rule tools, and GitHub session subscriptions — read the signed-in user out of the run context themselves instead of asking the host. They predated the seam and never picked up its organization resolution, so the same user could be recognized on a route and unrecognized inside a run.

They now go through `RouteAuth`, which gained a method for run contexts:

```ts
// A Hono request
const tenant = auth.tenant(c);

// An agent run, which never sees one
const tenant = auth.runTenant(requestContext);
```

Both answer identically, including the organization fallback, because they are one implementation behind two entry points.

If you implement `FactoryIntegration` yourself, `sessionTools` and `postToolObserver` now receive `auth` alongside `requestContext`, matching what `routes(ctx)` already provided.
