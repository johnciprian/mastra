---
'@mastra/factory': minor
---

Signing out of the Factory now revokes the session on the auth provider, not just in the browser. `POST /auth/logout` is the only route that does it, and it refuses a request that came from another site.

**Why** Sign-out only cleared cookies. The session itself stayed valid on the provider, so anyone still holding the token — a copied cookie, a shared machine, a leaked log — kept access after the person believed they had signed out. Where a provider can destroy a session, the Factory now asks it to.

**Sign-out moved from GET to POST** A URL that ends a session by being fetched is a URL any other site can put in an `<img>`, which signs your visitors out without asking them. There is no longer a `GET` route to embed — it answers 404.

```ts
// Before
window.location.assign(`${baseUrl}/auth/logout`);

// After
await fetch(`${baseUrl}/auth/logout`, { method: 'POST', credentials: 'include' });
```

For a sign-out that should still navigate the browser afterwards, submit a form instead — `location.assign` can only issue a `GET`:

```ts
const form = document.createElement('form');
form.method = 'POST';
form.action = `${baseUrl}/auth/logout`;
form.hidden = true;
document.body.appendChild(form);
form.submit();
```

**It also checks where the request came from** `SameSite=Lax` already stops a cross-site `POST` from carrying the session cookie — but only when the SPA and the API share an origin. Set `MASTRACODE_ALLOWED_ORIGINS` and the cookie becomes `SameSite=None; Secure` so your separately hosted SPA can use it, and from then on every cross-site request carries it too. CORS does not cover this: it withholds the response, not the request, and a form `POST` is never preflighted.

So `POST /auth/logout` now answers `403` unless the `Origin` is this deployment's own or one you named in `MASTRACODE_ALLOWED_ORIGINS`. A request with no browser origin headers at all — a CLI, a server-side script — is still allowed, because it carries no cookie for another site to spend.

If you host the SPA separately, make sure its origin is in `MASTRACODE_ALLOWED_ORIGINS`. It already has to be for the cookie to work at all.

Clearing cookies no longer depends on revocation succeeding: a provider that throws, or that cannot revoke, still ends the browser session.
