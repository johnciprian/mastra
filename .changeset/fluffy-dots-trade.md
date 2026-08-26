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

Added `profile()` to the `RouteAuth` port, so the audit trail gets the acting user's display name, email and avatar from the port instead of reading `factoryAuthUser` off the Hono context directly.

`RouteAuth` is meant to be the only identity path into a route. The audit domain was the last module bypassing it, and it had to: the port answered `{ orgId, userId }` and nothing else, so a display name had nowhere to come from. A test now fails if any production module outside `src/auth.ts` reads that context variable again.
