---
'@mastra/factory': minor
---

A signed-in user whose auth provider has no organizations can now use the Factory. Previously every organization-scoped route refused them with a 403.

**Why** The Factory scopes projects, work items, intake, audit and integrations by organization. A provider with no organization concept — most of them — left a user with none, and each of those route groups turned that into a 403 that looks exactly like "you are not allowed". Nothing said "your provider has no organizations", so there was nothing to act on.

Such a user now resolves to a private organization derived from their own user id:

```ts
import { resolveOrganizationId } from '@mastra/factory-auth/organizations';

resolveOrganizationId({ id: 'u_123' }); // 'user:u_123'
resolveOrganizationId({ id: 'u_123', organizationId: 'org_real' }); // 'org_real'
```

**Nobody gains access to anyone else's data.** The id is derived from the user's own, so it is unique to them and stable across processes and deploys — a private organization of one, not a shared bucket. A user who could previously reach nothing can now reach their own work.

**A declared organization always wins**, so members of a real organization are unaffected.

If you implemented the `RouteAuth` seam yourself, `tenant()` now returns `orgId` as a required string rather than an optional one, and any branch you wrote for the missing case can go.
