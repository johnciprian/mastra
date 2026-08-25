---
'@mastra/factory-auth': minor
---

**Fixed two ways an attacker could put their own session in someone else's browser.** Both needed a foothold on a sibling subdomain, which a subdomain takeover or any hosted-content subdomain gives you.

`readSessionCookie` used to return the first cookie with our name that verified. A browser sends every cookie whose name matches, so an attacker who signed in legitimately could set their own valid cookie on a shared parent domain with a longer `Path` — RFC 6265 sends longer paths first — and the victim would work inside the attacker's session with nothing to see. Two changes close it:

- **The cookie name in the default configuration is now `__Host-mastra_factory_session`.** The `__Host-` prefix makes a browser refuse to store the cookie unless it is `Secure`, carries no `Domain`, and has `Path=/`, so it can only have been set by your exact host. Setting `domain`, setting a `path` other than `/`, or setting `secure: false` for local HTTP each make the prefix illegal, and those deployments keep the plain `mastra_factory_session`. Call `sessionCookieName(site)` rather than hardcoding either.
- **Two cookies that both verify to different values are refused, not ranked.** `readSessionCookie` returns `null`, and the host should send `clearSessionCookie`.

The parser also read a cookie of ours out of another cookie's _value_. It split on `,` as well as `;`, and it unwrapped double quotes, so `theme=dark,mastra_factory_session=<attacker>` and `theme="a;mastra_factory_session=<attacker>"` both smuggled a complete signed cookie past it. It now splits on `;` only and never unwraps quotes. Repeated `Cookie` headers are joined with `"; "` by both `node:http` and undici — measured, not assumed — so nothing needed `,` in the first place.

**Upgrade note.** Existing sessions minted under the old name are not read after this change in deployments that become eligible for `__Host-`. People are signed out once and sign in again.

**Also fixed**

- `sanitizeReturnTo` percent-encodes anything outside printable ASCII. A `returnTo` of `/日本` used to survive sanitization and then throw when it reached a real `Location` header — an unauthenticated 500 on the OAuth callback, and no way to return to a non-ASCII route.
- `decodeState` and `parseStateId` guard their input type. Express's `qs` turns `?state=a&state=b` into an array and `?state[x]=y` into an object; both used to throw or return an array from a function declared to return `string | null`.
- `mintSessionCookie` and `readSessionCookie` require a secret of at least 32 bytes. A one-character secret used to mint and verify happily.
- `signUpEnabled` is `true` only for a literal `true`. An `async isSignUpEnabled()` returns a Promise, which is truthy, so a deployment with sign-up disabled could render a sign-up link.
- The signature field must be canonical base64url. Appended junk, padding and a non-canonical final character all used to verify, which left the cookie string malleable for anything downstream keyed on it.
- `path` and `domain` are rejected if they contain a character that cannot appear in a `Set-Cookie` header, and `maxAgeSeconds` must be a positive whole number — `-1` used to mint a cookie that was dead on arrival.

**Added**

- `toCookieHeader(...setCookieValues)` turns what `mintSessionCookie` returns into the `Cookie` header a browser would send back, for tests and local development.
- `SESSION_COOKIE_HOST_NAME` and `sessionCookieName(site)`.
