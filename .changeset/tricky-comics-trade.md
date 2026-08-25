---
'@mastra/factory-auth': minor
---

`@mastra/factory-auth/identity` now ships, so a provider that returns `{ uid }` or `{ sub }` no longer authenticates your users as nobody.

Every provider returns a different user shape, and the Factory has to store data under one key either way. `toAuthIdentity` turns any of them into a single `AuthIdentity` with a required, non-empty `id`.

```ts
import { toAuthIdentity } from '@mastra/factory-auth';

const user = await provider.authenticateToken(token, request);
const identity = toAuthIdentity(user, provider);
if (!identity) return unauthorized();

identity.id; // always a non-empty string
```

**The shapes it reads**

- Flat provider users: `{ id }`.
- Firebase `DecodedIdToken`: `{ uid }`.
- Raw OIDC claims: `{ sub }`.
- The better-auth wrapper: `{ session, user }`, with the organization taken from `session.activeOrganizationId`.

A numeric id is coerced to its decimal form, so a serial primary key behind a self-hosted provider works. A blank id counts as absent. `null` comes back only when no id can be resolved at all, which makes "this token names nobody" one checkable outcome instead of a half-built object travelling into a storage key.

Precedence is a documented rule, not an accident: `id`, then `uid`, then `sub`, and the `{ session, user }` wrapper is recognised before any of them so the id and the organization always come from the same subject.

**Mapping a shape we do not know**

A provider whose token shape you cannot change can map itself by implementing `toIdentity`, and `isIdentityProvider` is the structural guard for it.

```ts
import type { AuthIdentity, IIdentityProvider } from '@mastra/factory-auth';

class MyProvider extends MastraAuthProvider implements IIdentityProvider {
  toIdentity(raw: unknown): AuthIdentity | null {
    const claims = raw as Record<string, unknown>;
    const id = claims['https://example.com/user_id'];
    return typeof id === 'string' ? { id } : null;
  }
}
```

`toAuthIdentity` prefers your mapper when you pass the provider, and it respects a `null` from it rather than falling back to shape detection. A mapper says no for reasons only it knows, such as a service account, an unverified email, or a missing claim. Every one of those payloads still carries a `sub`, so a fallback would hand back an identity you had just refused.

**Why `id` is required**

A flat, resolvable id is one of four obligations that every Factory surface depends on and that no interface or documentation stated. Making it required moves the failure to the point that can explain it, and lets the coming conformance suite assert it.
