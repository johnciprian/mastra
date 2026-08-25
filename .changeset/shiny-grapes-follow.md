---
'@mastra/factory-auth': minor
---

`@mastra/factory-auth/oauth-state` documents and implements the OAuth `state` format, so a provider and its host stop disagreeing about it.

The format was one of four obligations the Factory placed on providers without writing any of them down. A provider that re-encoded `state`, read it as JSON, or split it on the wrong character quietly sent every user back to `/` after login, and nobody files a bug about a redirect that merely went somewhere boring.

```ts
import { encodeState, decodeState, parseStateId } from '@mastra/factory-auth/oauth-state';

const state = encodeState('/agents/42');
// '3f2b8c1e-...-9a7d|%2Fagents%2F42'

const { id, returnTo } = decodeState(callbackQuery.state);
// { id: '3f2b8c1e-...-9a7d', returnTo: '/agents/42' }
```

**The format is now written down.** An id, a `|`, and a percent-encoded `returnTo`. Only the first `|` is significant, so a `returnTo` that itself contains one round trips unchanged.

**`decodeState` treats its input as hostile, because it is a query parameter.** It never throws and always returns a `returnTo` that is safe to redirect to: absolute URLs, protocol-relative `//evil.com`, backslash variants, control characters and malformed percent escapes all resolve to `/`. It does not check authenticity or freshness. `state` is unsigned, so use `parseStateId` to compare against a value you stored at login time if you want CSRF protection.

**A `state` this package did not mint still decodes.** Providers that generate their own get read as an opaque id with no destination, rather than failing the callback.
