---
'@mastra/auth-okta': minor
---

Fixed Okta sign-in failing with "Invalid or expired state parameter" on every callback under the Software Factory.

`getLoginUrl` stored its OAuth state under the id half of the `state` value while `handleCallback` looked the same value up verbatim, so the two never agreed. `mastracode/factory` passes `handleCallback` the raw `state` from the query string, which meant no hosted sign-in through the Factory could ever complete; `packages/server` splits the value first, which is why the defect stayed invisible there.

Both sides now key on `parseStateId` from `@mastra/factory-auth/oauth-state`, so either spelling of `state` resolves to the same entry and both hosts work:

```typescript
// Both of these now complete
await auth.handleCallback(code, '3f2b8c1e-...|%2Fagents%2F42'); // the Factory
await auth.handleCallback(code, '3f2b8c1e-...'); // packages/server
```

**Sessions are real, not stubs**

`createSession` / `validateSession` / `destroySession` / `refreshSession` now share a session store. They previously always resolved `null`, so a session the provider had just created did not validate and "sign out everywhere" did nothing — while `isSessionProvider` reported the capability and a UI offered the button. The store is per-process, like the OAuth state store: see the constructor warning about serverless and multi-instance deployments.

**`getLoginCookies` matches the interface**

It now takes `(redirectUri, state)`, as `ISSOProvider` declares. It previously took a single parameter named `state` that in fact received `redirectUri`, so a caller passing one positional argument was already passing the redirect URI and keeps working.

`getLoginUrl` and `handleCallback` had no test coverage at all, which is why this shipped. They now do, alongside the Factory auth conformance suite.
