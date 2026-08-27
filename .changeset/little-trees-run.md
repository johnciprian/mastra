---
'mastra': patch
---

Fixed the sign-in screen offering "Continue with GitHub" on deployments that do not use GitHub.

The screen now renders from the capability descriptor `/auth/me` reports — what the provider can _do_ — instead of from the provider's name. It previously recognized two names and sent everything else down a GitHub-branded hosted-login branch, so the only way to support a new identity provider was to edit the app.

**What you see now**

- A provider with a hosted login gets a neutral button whose icon and copy come from the descriptor's `providerHint` (`generic`, `sso`, `oauth`, `email`). Set `label` on the descriptor to supply your own copy.
- A provider with an email/password sign-in gets the credential form; one with both gets the form and the button.
- A provider that validates API tokens but cannot sign anyone in from a browser (`kind: "none"`, such as Supabase or Firebase today) now explains that and points you at your administrator, instead of rendering an empty box. This is not the same as auth being switched off, which shows no sign-in screen at all.

Deployments on a server that predates the descriptor keep rendering exactly what they render today.

**If you read the sign-up flag** The payload carries both the new positive `auth.signIn.signUpEnabled` and the legacy negative `signUpDisabled` for one release. The descriptor wins when it states the fact. Mind the polarity — reading it backwards shows a sign-up link on a deployment that disabled sign-up, and nothing about that looks broken.
