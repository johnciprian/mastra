---
'@mastra/factory': minor
---

The Factory's identity and session path is now the default. `MASTRACODE_AUTH_IDENTITY_V2` remains for one release as the way back.

```shell
# Roll back to the previous identity path, for one release.
MASTRACODE_AUTH_IDENTITY_V2=false
```

**What breaks, and for whom**

Nothing, on the way in. A provider that mints and reads its own session cookie — WorkOS, Okta, better-auth — keeps every session it already had, because the Factory still hands it an empty token and lets it read its own cookie exactly as before.

The cost is on the way **back**. If your provider returns only tokens from its login callback, the Factory mints the session cookie itself, and the previous path cannot read that cookie. So setting the flag to `false` signs those people out once; they sign in again and are fine. Rolling back is still the right move if something is wrong — it is just not free, and it is worth knowing before you reach for it at 3am rather than after.

**The polarity moved with the default.** Only `0` and `false` (trimmed, case-insensitive) select the previous path. Every other value — including a typo like `flase` — leaves you on the current one. That is the same rule as before, pointed the other way: an unrecognized value must never select the non-default path, and the non-default path is the older one now.

The value is read once at startup, so a running Factory cannot change paths underneath a session that is already resolved. Restart to apply a change.

**What the current path does that the previous one did not**

The Factory used to read the user id from `id` alone. A Firebase provider returns `uid` and a plain OIDC verifier returns `sub`, so both authenticated as nobody — and the request then failed somewhere unrelated with a message about missing state, which is nothing like the actual problem. Now resolving:

- `uid` (Firebase) and `sub` (OIDC claims), read after `id`
- the same keys inside a better-auth `{ session, user }` result
- numeric ids, coerced to their decimal string, so a serial primary key works
- a provider's own `toIdentity` mapper, for an id under a custom claim

A blank or whitespace-only id is treated as absent rather than used as a storage key every such user would share. A signed-in user whose provider has no organizations resolves to a private partition of their own instead of being refused by every organization-scoped route.

**One thing to check before you upgrade**

The user id no longer comes from `workosId`. That is a no-op for WorkOS, which sets `workosId` to the same value as `id`, unless you mapped `workosId` to a different JWT claim than the user id — in which case the key each user's data is stored under moves from the one to the other.

**Optional, and separate:** set `MASTRACODE_AUTH_SESSION_SECRET` (32+ bytes, identical on every instance) to have the Factory sign its own session cookie for tokens-only providers. Without it that branch keeps using the provider's cookie, rather than failing every login.
