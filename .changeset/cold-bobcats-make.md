---
'@mastra/factory': patch
---

Factory routes now refresh an expired session instead of signing the person out, matching what `/api/*` already did.

**Why** The same auth provider behaved differently depending on which route you hit. `packages/server` refreshed an expired access token transparently on `/api/*`, so an API client stayed signed in; the Factory did not, so a browser was signed out of the Factory the moment the token expired. One session, two lifetimes, decided only by the URL.

Nothing to configure. Any provider implementing `getSessionIdFromRequest`, `refreshSession` and `getSessionHeaders` gets this automatically, and the refreshed cookie is sent back on the very request that triggered the refresh.

**Failure still means signed out** A refresh that returns nothing, throws, or produces a session that still fails to authenticate leaves the original 401 in place and sends no cookie — replacing the browser's cookie with one that is no better would sign the person out holding a fresh cookie.
