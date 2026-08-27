---
'@mastra/factory-auth': minor
---

`@mastra/factory-auth/cookie` gives the host its own signed session cookie, so nothing has to guess a provider's cookie name.

A host that reads one provider's cookie name by regex works for exactly that provider and fails silently for every other one, as "signed in, then immediately signed out".

```ts
import {
  sessionCookieName,
  mintSessionCookie,
  readSessionCookie,
  clearSessionCookie,
  toCookieHeader,
} from '@mastra/factory-auth/cookie';

const site = { crossSite: false };

headers.append('Set-Cookie', mintSessionCookie(token, { ...site, secret }));

const token = readSessionCookie(request, { secret }) ?? '';
const user = await provider.authenticateToken(token, request);

headers.append('Set-Cookie', clearSessionCookie(site));
```

**The name is `__Host-` prefixed wherever a browser will accept it.** `sessionCookieName(site)` returns `SESSION_COOKIE_HOST_NAME` (`__Host-mastra_factory_session`) when the prefix is legal — `Secure`, no `Domain`, `Path=/` — and `SESSION_COOKIE_NAME` (`mastra_factory_session`) otherwise. The prefix makes a browser refuse to store the cookie unless your exact host set it, which is what stops a sibling subdomain from writing a session your app would then read. Ask `sessionCookieName(site)` rather than hardcoding either name; setting `domain`, setting a `path` other than `/`, or `secure: false` for local HTTP each make the prefix illegal and select the plain name.

**A `__Host-` cookie wins outright, and ambiguity is refused rather than resolved.** A browser sends every cookie whose name matches and gives you no way to tell them apart, so picking by position hands the choice to whoever controls the order — which is how cookie tossing works. When a `__Host-` cookie is present the unprefixed name is not considered at all. If more than one candidate verifies and they carry different values, `readSessionCookie` returns `null` and the host should send `clearSessionCookie`. Signing someone out is visible and recoverable; letting them work inside someone else's session is neither.

**HMAC-SHA256 over `node:crypto`, with no new dependencies.** The signature is compared in constant time and covers the version and the expiry as well as the value, so neither can be swapped or extended, and the expiry is enforced server-side rather than trusted to the browser's `Max-Age`. The signature field must be canonical base64url, so the cookie string is not malleable for anything downstream keyed on it. Minting and reading both require a secret of at least 32 bytes.

**`SameSite` and `Secure` follow the deployment shape.** Same-site gets `SameSite=Lax; Secure` — `Lax` rather than `Strict`, because `Strict` withholds the cookie on the redirect back from a hosted login and lands the user back on the app signed out. Cross-site gets `SameSite=None; Secure`, the only combination a browser accepts; asking for a cross-site cookie with `secure: false` throws instead of minting one every browser silently drops. `path` and `domain` are rejected if they contain a character that cannot appear in a `Set-Cookie` header, and `maxAgeSeconds` must be a positive whole number.

**The `Cookie` header is parsed strictly.** Splitting on `,` as well as `;`, or unwrapping double quotes, lets a complete signed cookie ride inside another cookie's value — `theme=dark,mastra_factory_session=<attacker>` and `theme="a;mastra_factory_session=<attacker>"` are both smuggling attempts. This parser splits on `;` only and never unwraps quotes. Repeated `Cookie` headers are joined with `"; "` by both `node:http` and undici, so nothing needs `,`.

Also exported: `toCookieHeader(...setCookieValues)`, which turns what `mintSessionCookie` returns into the `Cookie` header a browser would send back, for tests and local development.
