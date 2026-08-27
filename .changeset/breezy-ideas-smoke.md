---
'mastra': patch
---

Improved how the account and sign-in screens read the auth capability descriptor.

**A WorkOS deployment now reads "Workos" in account settings.** The Authentication row used to carry a hand-written table mapping three provider names to display copy. It now humanizes the provider name for every provider, so a new provider gets a reasonable label instead of nothing — at the cost of the "WorkOS" casing. Two of the three entries earned nothing anyway (the humanizer already produces "Mastra Studio", and `workos` differed only in capitalization), and the third mapped `better-auth` to "Email and password", which substituted a sign-in method for a provider identity. The sign-in method is now answered properly by the descriptor's `signIn.kind`.

**Credentials sign-in works on any auth mount** The sign-in form used to post to a hardcoded `/auth/api/*`. It now posts below the base path the server reports, so a provider serving its own auth routes elsewhere works without changes to the app. Deployments on the default `/auth` mount are unaffected. The reported path is rejected unless it is a same-origin path, so a bad value cannot send a password to another origin.

**Log out is hidden when there is nothing to log out of** A provider that only validates API tokens has no browser session and no logout route, so the button navigated nowhere. It is now shown only when the descriptor reports a logout capability.
