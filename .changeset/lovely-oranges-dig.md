---
'@mastra/factory': minor
---

Added `MASTRACODE_AUTH_IDENTITY_V2`, a compat flag for the Factory's identity, session and logout migration. It defaults to off, so nothing changes unless you set it.

**Why** Those three changes ship together, and together they are the only part of Factory auth that can break a live sign-in: they change how an auth provider's `authenticateToken` result becomes the user the Factory compares against at every ownership check. A wrong answer there does not throw — it reads as "this session belongs to somebody else", which looks like missing data rather than an auth bug. The flag is the rollback for that release.

```shell
# Opt in to the new identity path.
MASTRACODE_AUTH_IDENTITY_V2=true

# Roll back: unset it and restart. Only '1' and 'true' turn it on; every
# other value, including a typo, leaves the shipped behaviour in place.
```

The value is read once when the process starts, so a running Factory cannot change paths underneath a session that is already resolved. Restart to apply a change.
