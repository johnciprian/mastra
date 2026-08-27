---
'@mastra/core': minor
---

Added an optional `setCallbackCookieHeader` to `ISSOProvider`, giving PKCE-enabled SSO providers a declared way to read back the cookie they wrote at login.

`getLoginCookies` already let a provider set a cookie during the login redirect — this is where a PKCE provider stores its code verifier. But `handleCallback` receives only `code` and `state`, so there was no declared way for a host to hand the provider the callback request cookies. The read half existed only as an undeclared method some hosts reached for through a type cast, which meant a provider could write a verifier it was then unable to read.

Both halves are now on the interface:

```typescript
class MyPKCEProvider implements ISSOProvider {
  private callbackCookies: string | null = null;

  getLoginCookies(redirectUri: string, state: string) {
    return [`pkce_verifier=${this.createVerifier(state)}; Path=/; HttpOnly`];
  }

  // New: the host calls this with the callback request Cookie header,
  // before handleCallback runs.
  setCallbackCookieHeader(cookieHeader: string | null) {
    this.callbackCookies = cookieHeader;
  }

  async handleCallback(code: string, state: string) {
    const verifier = readCookie(this.callbackCookies, 'pkce_verifier');
    return this.exchangeCode(code, verifier);
  }
}
```

The member is optional, so a provider that does not implement it is unaffected.
