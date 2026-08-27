---
'@mastra/factory': minor
'@mastra/factory-auth': patch
---

`/auth/me` no longer sends the legacy `signUpDisabled` field, and the sign-in page no longer looks at the provider's name. The capability descriptor is now the only thing that decides how you sign in.

**The wire change**

```jsonc
// Before: the same fact twice, in opposite directions.
{
  "provider": "acme-auth",
  "auth": { "signIn": { "kind": "credentials", "signUpEnabled": false } },
  "signUpDisabled": true
}

// After: stated once, positively.
{
  "provider": "acme-auth",
  "auth": { "signIn": { "kind": "credentials", "signUpEnabled": false } }
}
```

If you read `/auth/me` yourself, read `auth.signIn.signUpEnabled` and treat an absent field as "not stated", whose default is enabled. Two fields of opposite polarity in one payload is a dropped `!` waiting to happen, and the failure it produces is silent: a sign-up link rendered on a deployment that deliberately disabled sign-up looks like a working page.

**The sign-in page change**

It used to fall back to a provider-name lookup when a server sent no descriptor: one name got the email/password form, one got a Mastra Platform button, and every other name fell through to a GitHub branch — so a deployment on an identity provider it had never heard of told users to "Continue with GitHub", under a GitHub logo. That lookup is gone. A response with no usable descriptor now renders one neutral hosted-login button that names no vendor.

`provider` stays on the payload. It is displayed in account settings, which answers "which system holds my identity?" — a question the descriptor deliberately cannot answer, since `providerHint` is a rendering token and not a provider name. Nothing branches on it.
