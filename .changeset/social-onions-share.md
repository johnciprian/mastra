---
'@mastra/factory-auth': minor
---

`@mastra/factory-auth/cookie` gives the host its own signed session cookie, so nothing has to guess a provider's cookie name.

Until now the host read one provider's cookie name by regex. That works for exactly that provider and fails silently for every other one, as "signed in, then immediately signed out".

```ts
import {
  SESSION_COOKIE_NAME,
  mintSessionCookie,
  readSessionCookie,
  clearSessionCookie,
} from '@mastra/factory-auth/cookie';

headers.append('Set-Cookie', mintSessionCookie(token, { secret, crossSite: false }));

const token = readSessionCookie(request, { secret }) ?? '';
const user = await provider.authenticateToken(token, request);

headers.append('Set-Cookie', clearSessionCookie({ crossSite: false }));
```

**One declared name.** `SESSION_COOKIE_NAME` is exported, so a provider that wants to read the host session reads a constant instead of a regular expression.

**HMAC-SHA256 over `node:crypto`, with no new dependencies.** The signature is compared with a timing-safe comparison, and it covers the version and the expiry as well as the value, so neither can be swapped or extended. The expiry is enforced server-side rather than trusted to the browser's `Max-Age`.

**`SameSite` and `Secure` follow the deployment shape.** Same-site gets `SameSite=Lax; Secure` - `Lax` rather than `Strict`, because `Strict` withholds the cookie on the redirect back from a hosted login and lands the user back on the app signed out. Cross-site gets `SameSite=None; Secure`, the only combination a browser accepts. Asking for a cross-site cookie with `secure: false` throws instead of minting one every browser silently drops.

**Duplicate cookies are handled.** When a header carries the name more than once, the first value that verifies wins rather than the first that appears, so a same-named cookie set on a shared parent domain cannot lock a user out.
