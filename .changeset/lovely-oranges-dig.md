---
'@mastra/factory': minor
---

The Factory resolves a signed-in user through `@mastra/factory-auth`, and it is the only path.

**What the identity path does that the previous one did not**

The Factory used to read the user id from `id` alone. A Firebase provider returns `uid` and a plain OIDC verifier returns `sub`, so both authenticated as nobody — and the request then failed somewhere unrelated with a message about missing state, which is nothing like the actual problem. Now resolving:

- `uid` (Firebase) and `sub` (OIDC claims), read after `id`
- the same keys inside a better-auth `{ session, user }` result
- numeric ids, coerced to their decimal string, so a serial primary key works
- a provider's own `toIdentity` mapper, for an id under a custom claim

A blank or whitespace-only id is treated as absent rather than used as a storage key every such user would share. A signed-in user whose provider has no organizations resolves to a private partition of their own instead of being refused by every organization-scoped route.

**What breaks, and for whom**

Nothing, for a provider that mints and reads its own session cookie — WorkOS, Okta, better-auth. Those keep every session they already had, because the Factory hands the provider an empty token and lets it read its own cookie exactly as before.

**One thing to check before you upgrade**

The user id no longer comes from `workosId`. That is a no-op for WorkOS, which sets `workosId` to the same value as `id`, unless you mapped `workosId` to a different JWT claim than the user id — in which case the key each user's data is stored under moves from the one to the other.

**Optional, and separate:** set `MASTRACODE_AUTH_SESSION_SECRET` (32+ bytes, identical on every instance) to have the Factory sign its own session cookie for tokens-only providers. Without it that branch keeps using the provider's cookie, rather than failing every login.
