---
'@mastra/factory': minor
---

The Factory can now mint, read and clear its own session cookie, signed and `__Host-` prefixed, instead of leaving all three to the auth provider. Behind `MASTRACODE_AUTH_IDENTITY_V2` and off by default.

**Why** Providers that return only tokens from a login callback left the host to build a cookie, and the host had no cookie of its own — so the shape, the name and the protections depended on which provider you picked. The kit's cookie is signed with HMAC-SHA256 and, on any deployment that allows it, carries the `__Host-` prefix, which stops a sibling subdomain from writing a session cookie your app would then read.

```shell
MASTRACODE_AUTH_IDENTITY_V2=true
MASTRACODE_AUTH_SESSION_SECRET=<32+ bytes, identical on every instance>
```

**Everyone signs in once more** The cookie the host mints is not the cookie a provider minted, so existing sessions do not survive turning this on. Unset the flag and restart to go back.

**Both cookie sources still work** A provider that already builds its own session cookie — WorkOS and Okta both do — keeps doing so untouched. Only the tokens-only branch moves to the kit.

**A missing secret is not a broken sign-in** Turning the flag on without setting the secret keeps the previous behaviour rather than failing every login, because the cookie refuses to be signed with a weak secret and there is no safe default to invent.

Signing out now clears both the provider's cookies and the host's, so a session that predates the switch is not left behind.
