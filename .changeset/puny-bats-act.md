---
'@mastra/factory': patch
---

The Factory's auth module no longer depends on a vendor auth package. Its gate, its routes, and both of its test suites are built entirely on the provider contract.

**Why** The provider-neutral module still imported `@mastra/auth-workos` to build the environment-implied provider that was just removed, and both suites had to mock that package in order to test routing that has nothing to do with any vendor. A neutral module that names a vendor is only neutral by convention.

Nothing to change in your code. If you use WorkOS, keep passing it:

```ts
import { MastraAuthWorkos } from '@mastra/auth-workos';

export const factory = new MastraFactory({ auth: new MastraAuthWorkos() });
```

The package stays a dependency of `@mastra/factory` for now, because `@mastra/factory/integrations/workos/integration` still uses it for WorkOS audit-log export.
