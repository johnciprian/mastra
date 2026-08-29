---
'create-factory': minor
---

Added `MASTRACODE_AUTH_PROVIDER` to the scaffolded Factory, so a deployment names its sign-in provider instead of having one inferred from whichever credentials happen to be in the environment. Accepted values are `studio`, `workos`, `okta`, `better-auth`, `supabase`, `firebase`, and `none`.

**Why** Auth was chosen by a ladder of environment checks, and its last rung was "nothing configured, use the Mastra platform". That worked, but it meant the answer to "who signs users in here?" was spread across four variables and could change because an unrelated credential was added. The selector makes it one variable with one answer, and an unrecognized value is a startup error rather than a silent fallback — a typo like `worksos` can no longer land you on a provider you did not pick.

```bash
# Before: inferred — WorkOS appears because these two happen to be set
WORKOS_API_KEY=...
WORKOS_CLIENT_ID=...

# After: named, and the same variables still configure it
MASTRACODE_AUTH_PROVIDER=workos
WORKOS_API_KEY=...
WORKOS_CLIENT_ID=...
```

Leaving `MASTRACODE_AUTH_PROVIDER` unset keeps the previous inference exactly as it was, so existing deployments are unaffected.

**Deprecated** `MASTRACODE_AUTH_DISABLED`. It still works as an alias for `MASTRACODE_AUTH_PROVIDER=none` and warns at startup. Two notes: when both are set the selector wins and the server stays gated, because the opposite direction would open a production server on a stale flag; and the variable is now declared in `.env.schema`, so values outside `0`/`1` (for example `MASTRACODE_AUTH_DISABLED=true`) fail validation instead of being silently ignored as they were before.

**Note** `supabase` and `firebase` verify bearer tokens but cannot start a sign-in from a browser. Selecting one gives a fully gated server that browser users cannot enter, so the scaffold warns loudly at startup when you do.
