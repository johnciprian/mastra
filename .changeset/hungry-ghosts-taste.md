---
'@mastra/factory-auth': minor
---

Added `withSyntheticOrganizations` and `resolveOrganizationId` to `@mastra/factory-auth/organizations`, so every signed-in user resolves to an organization id even when the auth provider has no organization concept of its own.

**Why** Organization-scoped surfaces previously had to invent their own fallback or return 403 to users whose provider does not do organizations. Both helpers derive the same deterministic id from the provider's user id, so it is stable across processes and deploys, and it matches the id the Factory already writes for personal accounts.

```ts
import { withSyntheticOrganizations, resolveOrganizationId } from '@mastra/factory-auth/organizations';

// Wrap any provider. It now satisfies isOrganizationsProvider, and keeps every
// capability it already had - SSO, sessions, credentials, auth routes, init.
export const auth = withSyntheticOrganizations(new MyOidcProvider());

await auth.ensureOrganization('8f21ac'); // 'user:8f21ac', every time

// Or resolve it host-side, straight from an identity, with no provider call:
resolveOrganizationId({ id: '8f21ac' }); // 'user:8f21ac'
resolveOrganizationId({ id: '8f21ac', organizationId: 'org_01H8XYZ' }); // 'org_01H8XYZ'
```

A provider that already implements `IOrganizationsProvider` keeps its own answer. The wrapper only supplies an id for the cases where that provider returns none, turning a best-effort bootstrap into a value the host can always store.
