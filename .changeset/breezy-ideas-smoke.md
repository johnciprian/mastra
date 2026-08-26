---
'mastra': patch
---

Improved how the account and sign-in screens read the auth capability descriptor.

**Credentials sign-in works on any auth mount** The sign-in form used to post to a hardcoded `/auth/api/*`. It now posts below the base path the server reports, so a provider serving its own auth routes elsewhere works without changes to the app. Deployments on the default `/auth` mount are unaffected. The reported path is rejected unless it is a same-origin path, so a bad value cannot send a password to another origin.

**Log out is hidden when there is nothing to log out of** A provider that only validates API tokens has no browser session and no logout route, so the button navigated nowhere. It is now shown only when the descriptor reports a logout capability.

**The Authentication row no longer keeps a hand-written provider table** It humanizes the provider name for every provider instead of special-casing three. One visible change: a WorkOS deployment now reads "Workos".
