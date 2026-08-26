---
'@mastra/factory': minor
---

Fixed sign-in for auth providers whose token payload names the user something other than `id`. Behind `MASTRACODE_AUTH_IDENTITY_V2`, which defaults to off.

**Why** The Factory read the user id from `id` alone. A Firebase provider returns `uid`, and a plain OIDC verifier returns `sub`, so both authenticated as nobody — and the request then failed somewhere unrelated with a message about missing state, which is nothing like the actual problem.

```shell
MASTRACODE_AUTH_IDENTITY_V2=true
```

**What resolves that did not before**

- `uid` (Firebase) and `sub` (OIDC claims), read after `id`
- the same keys inside a better-auth `{ session, user }` result
- numeric ids, coerced to their decimal string, so a serial primary key works
- a provider's own `toIdentity` mapper, for an id under a custom claim

**What stops resolving, on purpose** A blank or whitespace-only id is now treated as absent rather than used as a storage key every such user would share.

**One thing to check before enabling** The user id no longer comes from `workosId`. That is a no-op for WorkOS, which sets `workosId` to the same value as `id`, unless you mapped `workosId` to a different JWT claim than the user id — in which case the key each user's data is stored under moves from the one to the other. Unset the flag and restart to go back.

Organization resolution also widens slightly: a better-auth session that names no active organization now falls back to the one on the user record instead of resolving as a personal account.
