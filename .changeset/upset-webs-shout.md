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

**Two sign-up fields for one release** The payload states the same fact twice with opposite polarity: the new `auth.signIn.signUpEnabled` is positive, matching the provider's `isSignUpEnabled`, while the existing `signUpDisabled` is negative. Read the descriptor — it is authoritative, and `signUpDisabled` is removed in a later release. If you read both, mind the polarity: getting it backwards shows a sign-up link on a deployment that disabled sign-up, and nothing about that looks broken.

**One behaviour change** A provider whose `isSignUpEnabled` throws, or returns something that is not a boolean (an `async` implementation returns a Promise), is now treated as having sign-up off. It previously fell through as sign-up on.

`kind: 'none'` means the provider validates API tokens but cannot sign anyone in from a browser. It does not mean auth is disabled — a deployment with no provider has no descriptor at all.
