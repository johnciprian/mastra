---
'@mastra/factory': minor
---

Made `auth` a required `MastraFactory` option that takes either a provider or the new `AUTH_DISABLED` value. Omitting it, or passing `null`, now throws from `new MastraFactory(...)` — so a deployment that never configured auth fails to boot instead of starting with a provider nobody chose. JavaScript callers passing `auth: undefined` are affected too: the check runs at construction, not through the type system.

**Why** The slot used to have three meanings. A provider was the provider, `null` meant off, and leaving it out quietly built a `MastraAuthStudio` pointed at the shared Mastra platform API. That third case is the dangerous one: a deploy that simply forgot to wire auth booted anyway, looked healthy, and deferred every identity decision to a platform its operator may never have intended to use. There are now two values, both written down at the call site.

**Migrating**

```ts
import { AUTH_DISABLED, createMastraPlatformAuth, MastraFactory } from '@mastra/factory';

// Before: omitted → implicit MastraAuthStudio
new MastraFactory({ storage });
// After: say so
new MastraFactory({ storage, auth: createMastraPlatformAuth({ publicUrl }) });

// Before: null disabled auth
new MastraFactory({ storage, auth: null });
// After
new MastraFactory({ storage, auth: AUTH_DISABLED });

// Passing a provider is unchanged
new MastraFactory({ storage, auth: new MastraAuthWorkos({ fetchMemberships: true }) });
```

**Added** `AUTH_DISABLED`, `createMastraPlatformAuth()`, `isAuthDisabled()`, and `resolveFactoryPublicUrl()`, plus the `FactoryAuthConfig`, `FactoryAuthDisabled`, and `MastraPlatformAuthOptions` types. `createMastraPlatformAuth()` builds exactly what omitting `auth` used to build, including the cookie-domain fallback derived from `publicUrl`. Use `isAuthDisabled(config.auth)` rather than comparing against the sentinel, so code that branches on "is auth on?" reads the same fact the factory does.
