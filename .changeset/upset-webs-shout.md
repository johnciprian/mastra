---
'@mastra/factory': minor
---

`/auth/me` now returns a capability descriptor, so the sign-in screen can render from what a provider can do instead of from its name.

**Why** The screen used to branch on the provider's name, which is why an unrecognized provider got a GitHub button and a hosted-login redirect it could not complete. The descriptor answers the questions the screen actually has, so adding a provider stops meaning editing the SPA.

```jsonc
// GET /auth/me
{
  "authenticated": false,
  "user": null,
  "provider": "better-auth",
  "auth": {
    "signIn": {
      "kind": "credentials", // 'hosted' | 'credentials' | 'both' | 'none'
      "providerHint": "generic",
      "signUpEnabled": false,
      "credentialsBasePath": "/auth",
    },
    "features": { "logout": true, "organizations": false, "refresh": false, "sessionRevocation": false },
  },
}
```

**Sign-up is stated once, positively** `auth.signIn.signUpEnabled` matches the provider's own `isSignUpEnabled`, and it is the only field on the payload describing sign-up — the older negative `signUpDisabled` is gone. Treat an absent field as "not stated", whose default is enabled; the descriptor omits it entirely for providers with no credentials sign-in.

**One behaviour change** A provider whose `isSignUpEnabled` throws, or returns something that is not a boolean (an `async` implementation returns a Promise), is now treated as having sign-up off. It previously fell through as sign-up on.

`kind: 'none'` means the provider validates API tokens but cannot sign anyone in from a browser. It does not mean auth is disabled — a deployment with no provider has no descriptor at all.
