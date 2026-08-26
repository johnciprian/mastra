---
'@mastra/factory': patch
---

The Factory's OAuth `state` handling now uses the shared codec from `@mastra/factory-auth/oauth-state`, so the post-login redirect survives destinations that used to lose it.

**Why** `state` is the only value that crosses the bounce to an identity provider and back, and the Factory carried its own copy of the format. A destination containing a `|` was truncated, because the old decoder had no rule about which pipe was the delimiter.

**Fixed**

- A `returnTo` containing `|` — `/search?q=a|b` — now round trips instead of silently degrading to `/`.
- A `state` that a query parser turned into an array (`?state=a&state=b`) or an object no longer reaches string methods that would throw.
- Non-ASCII destinations are percent-encoded before they reach a `Location` header, so `/日本` cannot produce an unauthenticated 500 on hosts that do not encode it for you.

**For provider authors** The Factory hands `handleCallback` the raw `state` the identity provider echoed, which is what the codec documents. `packages/server` splits it and passes only the id half. If your provider stores anything keyed on `state`, normalize with `parseStateId` so both hosts agree:

```ts
import { parseStateId } from '@mastra/factory-auth/oauth-state';

const stateStoreKey = (state: string) => parseStateId(state) ?? state;
```
