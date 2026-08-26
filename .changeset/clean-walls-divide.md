---
'@mastra/factory': patch
---

Fixed hosted logins that use PKCE bouncing users back to the sign-in page instead of signing them in.

The Factory set the cookies a provider asked for on the way out to the identity provider, but never handed the callback request cookies back. A provider that stores its PKCE code verifier in that cookie found it missing when the identity provider redirected back, failed the token exchange, and was redirected to `/auth/login` — which sent the browser straight back to the identity provider, so sign-in never completed.

The Factory now passes the callback request `Cookie` header to the provider before calling `handleCallback`, so a verifier written at login is readable at the callback. Providers that do not use cookies across the round trip are unaffected.
