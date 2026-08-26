---
'@mastra/factory': minor
---

Added an opt-in identity and session path, behind `MASTRACODE_AUTH_IDENTITY_V2`. It defaults to off, so nothing changes unless you set it.

```shell
MASTRACODE_AUTH_IDENTITY_V2=true
MASTRACODE_AUTH_SESSION_SECRET=<32+ bytes, identical on every instance>
```

**Why one flag** These changes decide how an auth provider's `authenticateToken` result becomes the user the Factory compares against at every ownership check. A wrong answer there does not throw — it reads as "this session belongs to somebody else", which looks like missing data rather than an auth bug. One switch is the rollback for all of it: unset the variable and restart, and the process is back on the path that shipped before. Only `1` and `true` turn it on; every other value, including a typo, leaves the shipped behaviour in place. The value is read once at startup, so a running Factory cannot change paths underneath a session that is already resolved.

**Sign-in works for providers that name the user something other than `id`**

The Factory read the user id from `id` alone. A Firebase provider returns `uid`, and a plain OIDC verifier returns `sub`, so both authenticated as nobody — and the request then failed somewhere unrelated with a message about missing state, which is nothing like the actual problem. What resolves that did not before:

- `uid` (Firebase) and `sub` (OIDC claims), read after `id`
- the same keys inside a better-auth `{ session, user }` result
- numeric ids, coerced to their decimal string, so a serial primary key works
- a provider's own `toIdentity` mapper, for an id under a custom claim

A blank or whitespace-only id is now treated as absent rather than used as a storage key every such user would share. Organization resolution widens slightly too: a better-auth session that names no active organization falls back to the one on the user record instead of resolving as a personal account.

**The Factory mints, reads and clears its own session cookie**

Providers that return only tokens from a login callback left the host to build a cookie, and the host had no cookie of its own — so the shape, the name and the protections depended on which provider you picked. The kit's cookie is signed with HMAC-SHA256 and, on any deployment that allows it, carries the `__Host-` prefix, which stops a sibling subdomain from writing a session cookie your app would then read.

A provider that already builds its own session cookie — WorkOS and Okta both do — keeps doing so untouched. Only the tokens-only branch moves to the kit. Turning the flag on without setting `MASTRACODE_AUTH_SESSION_SECRET` keeps the previous behaviour rather than failing every login, because the cookie refuses to be signed with a weak secret and there is no safe default to invent.

**Two things to check before you enable it**

- **Everyone signs in once more.** The cookie the host mints is not the cookie a provider minted, so existing sessions do not survive turning this on.
- **The user id no longer comes from `workosId`.** That is a no-op for WorkOS, which sets `workosId` to the same value as `id`, unless you mapped `workosId` to a different JWT claim than the user id — in which case the key each user's data is stored under moves from the one to the other.

Signing out clears both the provider's cookies and the host's, so a session that predates the switch is not left behind. Session revocation at sign-out is not part of this flag and applies either way.
