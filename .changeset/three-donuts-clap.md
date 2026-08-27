---
'@mastra/factory': minor
'@mastra/factory-auth': patch
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

**`@mastra/auth-workos` is no longer a dependency of the Factory.** It was pulled in for one feature — the WorkOS audit-log integration — and that feature never needed the package. The host already injects its own WorkOS client; the dependency bought a type alias and one string constant.

`WorkOSAuditIntegration`'s `client` option is now typed by a small structural interface describing the two methods the integration calls, rather than by `WorkOS` itself. Existing code keeps compiling — a real `WorkOS` instance satisfies it:

```ts
import { WorkOS } from '@workos-inc/node';

new WorkOSAuditIntegration({ client: new WorkOS(apiKey), returnUrl }); // unchanged
```

The feature is unchanged and the published output has no unresolvable import.

**The vendor-provider lint ban now covers the whole package** rather than `src/auth.ts` alone, with `src/factory.ts` exempt because it still imports `MastraAuthStudio` as the default provider.
