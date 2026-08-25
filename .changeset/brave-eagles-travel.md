---
'@mastra/factory-auth': minor
---

`@mastra/factory-auth/contract` now re-exports the Mastra auth provider contract, so a provider author has one import path instead of hunting through `@mastra/core`.

```ts
import {
  MastraAuthProvider,
  isSSOProvider,
  isSessionProvider,
  isUserProvider,
  isCredentialsProvider,
  isOrganizationsProvider,
  isAuthHttpHandler,
  hasAuthInit,
  getRequestHeader,
} from '@mastra/factory-auth/contract';
```

The same symbols are on the root export. Alongside them are the interfaces the guards narrow to (`IMastraAuthProvider`, `ISSOProvider`, `ISessionProvider`, `IUserProvider`, `ICredentialsProvider`, `IOrganizationsProvider`, `IAuthHttpHandler`, `IAuthInit`, `AuthInitContext`, `MastraAuthProviderOptions`) and the framework-neutral request primitives `getRequestHeader`, `getWebRequest`, `MastraAuthRequest` and `HonoRequestLike`.

Two things worth knowing:

**There are seven guards, not eight.** The eighth exported value is the `MastraAuthProvider` base class. The init guard is `hasAuthInit`, not `isAuthInit`, and there is no guard for `IMastraAuthProvider` because implementing the base contract is a precondition rather than a capability. All seven are structural, so a plain object with the right methods satisfies them, and a provider built against a duplicate copy of `@mastra/core` still narrows correctly.

**Four symbols are deliberately absent.** `MastraAuthConfig`, `ApiRoute`, `ApiRouteHandler` and `StudioConfig` are exported from `@mastra/core/server` but defined in terms of enterprise interfaces, and `@mastra/core` rolls those declarations into its emitted types. Re-exporting one would copy enterprise declaration text into this Apache-2.0 package's published type surface. Import them from `@mastra/core/server` directly in your host application instead. A test asserts all four stay out of both source and built output.
