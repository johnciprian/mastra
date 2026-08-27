---
'@mastra/factory': minor
'@mastra/factory-auth': patch
---

Removed the `MASTRACODE_AUTH_IDENTITY_V2` compatibility flag. The Factory now resolves a signed-in user one way, through `@mastra/factory-auth`, with no second path to fall back to.

**What to do**

Nothing, unless you set the variable. It no longer does anything, so delete it from your environment rather than leaving a value that reads as if it still controls something.

```shell
# Before: the way back to the pre-kit identity reader.
MASTRACODE_AUTH_IDENTITY_V2=false

# After: delete the line. There is one identity path.
```

**What you lose by not being able to go back**

Only the old reader's behaviour, which is worth restating because that is what a rollback would have restored:

- it read the user id from `id` alone, so a Firebase provider returning `uid` and a plain OIDC verifier returning `sub` authenticated as nobody
- it accepted a blank or whitespace-only id as a real id, which made one storage key that every such user shared
- it accepted `workosId` as an id key, and preferred it over `id`

Deployments that mapped `workosId` to a different JWT claim than the user id are the one group this is observable for, and that move already happened when the flag's default flipped — this release only removes the way back from it.

**Also gone:** `MASTRACODE_AUTH_SESSION_SECRET` is now the only condition for the Factory minting its own signed session cookie. Set it and the host owns the cookie; leave it unset and your provider keeps minting its own, exactly as before.
