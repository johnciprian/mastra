---
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

Fixed `handleAuthRequest` returning a 500 instead of a 503 when the provider had not been initialized. In deferred instance mode the provider builds its own better-auth instance in `init()`. A request arriving before that ran reached the internal `auth` getter, which throws `MastraAuthBetterAuth is not initialized` — an uncaught error on an unauthenticated endpoint, and a stack trace for the caller.

The sibling condition, migrations failing, already answered a clean 503. Both are the same thing to the operator, so both now return the same shape:

```json
{ "error": "auth_unavailable" }
```

The not-initialized case also logs one warning rather than one per request, since the route is unauthenticated and the misconfiguration is persistent.
