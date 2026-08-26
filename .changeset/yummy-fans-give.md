---
'@mastra/factory': patch
---

A user whose auth provider has no organizations can now open a Factory session. Opening one previously failed with an error about a missing caller identity.

**Why** The workspace layer refused any caller without an organization, and reported it as "resolved without a caller identity" — about a caller who plainly had one. That is the same misleading shape the route layer had: "you have no organization" surfacing as something that reads like "you are not allowed".

The two conditions are now separate:

- **No identity at all** still throws. That is a server-side caller — a webhook or a cron — that forgot to seed one, which is what the check was always for.
- **An identity with no organization** resolves to a private organization derived from the user id, and the ordinary ownership check decides from there.

Nothing new becomes reachable. A private organization matches only the sessions created under it, so a user still cannot open a session belonging to an organization they are not in.
