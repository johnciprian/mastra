---
'@mastra/factory': minor
---

Removed the implicit WorkOS provider that the Factory built from `WORKOS_API_KEY` and `WORKOS_CLIENT_ID`. Pass an auth provider to `MastraFactory` instead.

**Why** Auth turned itself on whenever those two variables happened to be present, so a deployment could acquire an identity provider nobody had configured — and turning auth off meant removing environment variables rather than changing code. Whether a Factory is gated is now decided in one place: the `auth` slot.

```ts
// Before — auth appeared if the environment had WorkOS credentials in it
export const factory = new MastraFactory({/* ... */});

// After — the provider is named by whoever chose it
import { MastraAuthWorkos } from '@mastra/auth-workos';

export const factory = new MastraFactory({
  auth: new MastraAuthWorkos({ fetchMemberships: true }),
  /* ... */
});
```

If your Factory already passes `auth`, nothing changes: an explicit provider always took precedence.

`WORKOS_REDIRECT_URI` and the `redirectUri` option went with it. A hosted-login provider reads its own redirect configuration, and the callback URL is derived from the Factory's public origin.
