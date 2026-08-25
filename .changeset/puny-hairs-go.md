---
'@mastra/factory-auth': minor
---

Added `describeAuthProvider`, a drop-in conformance suite an auth provider package runs in its own CI. It asserts the contract a provider declares and the four requirements that decide whether it can actually run the Mastra Factory: a flat resolvable `id`, an `authenticateToken` that reads the `Cookie` header when the bearer token is empty, agreement with the kit's OAuth `state` codec, and an organization id.

**Using it**

```ts
// auth/my-provider/src/conformance.test.ts
import { describeAuthProvider } from '@mastra/factory-auth/conformance';
import { MyAuthProvider } from './auth-provider.js';

describeAuthProvider({
  name: '@mastra/auth-my-provider',
  createProvider: () => new MyAuthProvider({ verify: fakeVerifier }),
  token: 'a-token-my-provider-accepts',
  userId: 'user_123',
  cookieHeader: 'my_provider_session=a-token-my-provider-accepts',
});
```

It needs no network, no identity provider and no environment variables. `vitest` is an optional peer dependency, and this is the only entry point in the package that imports it.

**What a failure tells you**

Each failure names the obligation, quotes the call the suite made and the answer it got, explains the outcome the rule prevents, and shows the fix as code. A provider that ignores the `Cookie` header is told that a browser navigation sends no `Authorization` header, that the same credential works as a bearer token, and how to fall back to the header with `getRequestHeader`.

**Skipped, never quietly passed**

A check is skipped only when a capability guard says the provider does not declare the capability the check is about, and the skip carries its reason. A bearer-token validator that cannot sign anyone in from a browser skips the hosted-login and cookie checks instead of failing them. The organization check is deliberately not gated that way: a provider with no organizations fails it, and `withSyntheticOrganizations` is the one-line fix.

Also added `authConformanceChecks` for running the same checks outside vitest.
