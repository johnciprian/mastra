---
'@mastra/factory-auth': patch
'@mastra/factory': patch
'@mastra/auth-better-auth': patch
'@mastra/server': patch
'@mastra/auth-firebase': patch
'@mastra/auth-supabase': patch
'@mastra/core': patch
'@mastra/auth-google': patch
'@mastra/auth-studio': patch
'@mastra/auth-workos': patch
'@mastra/auth-auth0': patch
'@mastra/auth-clerk': patch
'@mastra/auth-cloud': patch
'@mastra/auth-neon': patch
'@mastra/auth-okta': patch
---

Fixed four defects in `MastraAuthStudio` that the auth provider conformance suite recorded.

**Sign-in now carries `state` to the callback**

`getLoginUrl` forwarded only the destination half of the host's `state` (as `post_login_redirect`) and dropped the value itself, so the id half — the half a host compares on the callback to tell its own redirect apart from one somebody else started — never came back. The whole `state` is now forwarded under the OAuth `state` parameter as well:

```ts
// Before: https://…/auth/login?product=deploy&redirect_uri=…&post_login_redirect=/agents
// After:  https://…/auth/login?product=deploy&redirect_uri=…&post_login_redirect=/agents&state=<the host's state>
```

**CLI and API-token callers now get an organization**

`ensureOrganization(userId)` answered `undefined` for any user this provider had not seen a session cookie for, so a user authenticated by bearer token never got an organization bootstrapped on any request. The cookie-backed bootstrap is unchanged; a user with no cookie now falls back to the derived `user:<userId>` organization — the same id the host already resolves for a user with no organization, so rows land in the partition they land in today. `isOrganizationAdmin` answers for those derived organizations directly: you administer your own, and nobody administers anybody else's.

**A session created without an access token now validates**

`createSession(userId)` with no `metadata` minted a random id that `validateSession` could never accept — a sign-in that did not stick. Such sessions are now recorded in-process so create, validate and destroy are one loop. Sessions created with `metadata.accessToken` (what the Mastra server and the Factory pass) are unchanged: still verified against the shared API on every call, never answered from memory.

**Failed callbacks say why**

`handleCallback` threw `Session validation failed` with no `cause` for an expired session, a clock skew and an unreachable shared API alike. The underlying failure is now attached as the error's `cause`.
