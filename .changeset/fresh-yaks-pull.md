---
'@mastra/auth-workos': minor
---

Signing out of WorkOS now really ends the session at WorkOS, and a WorkOS session can be validated and refreshed.

**Why** `MastraAuthWorkos` declared the session capability and implemented it with empty methods. `validateSession` returned `null` for sessions that were perfectly valid, `destroySession` did nothing at all, and `getSessionIdFromRequest` never found the session sitting in the request it was handed. Mastra read the declaration and told every host this provider could revoke sessions, so the one claim that matters for security was false.

**What works now**

- `destroySession(id)` calls WorkOS `revokeSession` with the session's `sid` claim. Signing out ends the session for real, not just in the browser that asked.
- `validateSession(id)` opens the encrypted cookie and refuses an expired access token instead of reporting every session as invalid.
- `refreshSession(id)` exchanges the refresh token and returns a session carrying the new cookie, so an expired-but-refreshable session no longer logs the person out.
- `getSessionIdFromRequest(request)` returns the session cookie.

The session id is the sealed cookie value, matching `@mastra/auth-studio`. Treat it as a credential: do not log it or put it in a URL.

**Also fixed** `getLogoutUrl` decoded the access token with `atob`, which rejects the `-` and `_` that Base64URL uses. Any token whose payload contained one made `getLogoutUrl` return `null`, so the browser was sent to `/` instead of WorkOS's logout page and the session was never ended there.

**One thing that still does not work** `createSession(userId)` cannot mint a session — WorkOS issues one only from an authenticated token exchange, and the SDK has no call that makes one from a user id. It returns a record nothing will accept, which is why `features.refresh` and `features.sessionRevocation` are now accurate but a create-then-validate round trip still is not.
