---
'@mastra/factory-auth': minor
---

Added composable fake auth providers at `@mastra/factory-auth/testing`, so a test can build exactly the provider it needs in one line instead of hand-rolling one.

`fakeProvider()` gives you the base contract and nothing else. Six mixins each add one optional capability, and every combination satisfies exactly the guards it should:

```ts
import { fakeProvider, withSSO } from '@mastra/factory-auth/testing';
import { isSSOProvider, isOrganizationsProvider } from '@mastra/factory-auth';

const provider = withSSO(fakeProvider());
isSSOProvider(provider); // true - and the type says so, so a mismatch is a compile error
isOrganizationsProvider(provider); // false
```

**Fakes you can question, not just call**

Every fake carries a call log, so a test can assert what did _not_ happen as well as what did - that a capability check read a guard rather than quietly probing the provider:

```ts
toAuthDescriptor(provider);
provider.calls.called(); // false - nothing was asked
```

**Providers that are correct except for one thing**

Four requirements decide whether a provider can run the Factory and none of them are visible to a structural guard. `fakeViolating` builds a provider that declares every capability, meets three of the four, and fails the one you name:

```ts
const broken = fakeViolating('cookieAuth'); // correct, except it ignores the Cookie header
await broken.authenticateToken('', requestWithSessionCookie); // null
```

That is what lets a conformance suite prove its own checks can fail, rather than only that they pass.

No environment stubbing, no test runner: the fakes are plain objects, so they work from vitest, from an MSW fixture, or from anything else.
