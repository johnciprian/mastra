---
'@mastra/auth-okta': patch
---

Fixed Okta sign-in failing with "Invalid or expired state parameter" on every callback under the Software Factory.

`getLoginUrl` stored its OAuth state under the id half of the `state` value while `handleCallback` looked the same value up verbatim, so the two never agreed. `mastracode/factory` passes `handleCallback` the raw `state` from the query string, which meant no hosted sign-in through the Factory could ever complete; `packages/server` splits the value first, which is why the defect stayed invisible there.

Both sides now key on `parseStateId` from `@mastra/factory-auth/oauth-state`, so either spelling of `state` resolves to the same entry and both hosts work:

```typescript
// Both of these now complete
await auth.handleCallback(code, '3f2b8c1e-...|%2Fagents%2F42'); // the Factory
await auth.handleCallback(code, '3f2b8c1e-...'); // packages/server
```

**Also in this release**

- `createSession` / `validateSession` / `destroySession` / `refreshSession` now share a real session store. They previously always resolved `null`, so a session the provider had just created did not validate and "sign out everywhere" did nothing, while the provider still advertised session revocation.
- `getLoginCookies` now takes `(redirectUri, state)` to match `ISSOProvider`. Its single parameter was named `state` but received `redirectUri`.

`getLoginUrl` and `handleCallback` had no test coverage at all, which is why this shipped. They now do, alongside the Factory auth conformance suite.
