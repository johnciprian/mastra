---
'@mastra/factory': minor
---

Signing out of the Factory now revokes the session on the auth provider, not just in the browser, and `POST /auth/logout` is the route that does it.

**Why** Sign-out only cleared cookies. The session itself stayed valid on the provider, so anyone still holding the token — a copied cookie, a shared machine, a leaked log — kept access after the person believed they had signed out. Where a provider can destroy a session, the Factory now asks it to.

**`POST /auth/logout` is the documented route**

```ts
await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
```

**`GET /auth/logout` still works, for one release** A `GET` that ends a session can be triggered by any page that embeds `<img src="/auth/logout">`, which signs your visitors out without asking them. The `GET` route now runs only for real browser navigations — it checks `Sec-Fetch-Dest`, a header a page cannot set — so an embedded request redirects without touching the session. Bookmarked links and top-level navigations are unaffected.

Move any sign-out you trigger yourself to `POST`. Browsers too old to send `Sec-Fetch-Dest` still sign out over `GET`, which is the gap the route is deprecated to close.

Clearing cookies no longer depends on revocation succeeding: a provider that throws, or that cannot revoke, still ends the browser session.
