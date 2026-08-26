---
'@mastra/factory-auth': major
---

**Added a conformance check for the PKCE cookie round trip.** `sso/pkce-round-trip` drives the whole hosted-login flow: it mints a login URL, collects what `getLoginCookies` hands back, turns those into the `Cookie` header a browser would send, feeds it through `setCallbackCookieHeader`, and calls `handleCallback` with the `state` your own authorization URL carries. A provider that sets a cookie at login and cannot read one back now fails.

Until now the suite had no PKCE check at all, so a provider passed all eighteen checks with PKCE entirely absent or entirely broken, and a green run told the author they were done.

**This is a breaking change.** A new check can turn CI red in a repository this package does not own. It is landing now because the package has never published: there are no consumers to break yet, and the check would be a genuine breaking change the day one exists.

**When it applies**

- **Skipped** if you do not implement `getLoginCookies`. You set no cookie at login, so nothing has to come back.
- **Passes** if you implement it and it returns `undefined` or `[]`. The check ran; there was no cookie to hold you to.
- **Fails** if you set a cookie and either declare no `setCallbackCookieHeader`, or declare one and the value does not survive the trip. Declaring both is not enough: a read half that stores nothing satisfies every structural guard and delivers nothing.

```ts
class MyOidcProvider extends MastraAuthProvider implements ISSOProvider {
  private callbackCookieHeader: string | null = null;

  getLoginCookies(redirectUri: string, state: string) {
    return [`my_pkce_verifier=${this.mintVerifier(state)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600`];
  }

  // New: the read half. Hosts call it on every SSO callback, before handleCallback.
  setCallbackCookieHeader(cookieHeader: string | null) {
    this.callbackCookieHeader = cookieHeader;
  }

  async handleCallback(code: string, state: string) {
    const verifier = readCookie(this.callbackCookieHeader, 'my_pkce_verifier');
    // ... exchange `code` with `verifier`
  }
}
```

**Fixed a misdiagnosis in the state-codec check.** `obligation/stateCodec/callback` now hands the login cookies back before it calls `handleCallback`. A correct PKCE provider used to throw for a missing verifier before it read the `state` at all, and was told it had "rejected a state its own getLoginUrl was just handed" — about a call that never reached one.
