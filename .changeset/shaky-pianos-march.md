---
'@mastra/factory': minor
---

The Factory refuses a state-changing request that spends your session cookie on behalf of another site.

**Why** `SameSite=Lax` was carrying this defence, and it only holds when the SPA and the API share an origin. Setting `MASTRACODE_ALLOWED_ORIGINS` moves the session cookie to `SameSite=None; Secure` so a separately hosted SPA can use it — and from that moment every cross-site request carries it too.

CORS does not close the gap. It withholds the response from a disallowed origin; it does not stop the request. Nor does requiring a JSON body: a route reading `c.req.json()` parses the body it is given without consulting `Content-Type`, so a `text/plain` body carrying JSON is never preflighted and arrives intact. Any page on the internet could drive any mutating Factory route with a signed-in visitor's cookie attached.

**What changed** `POST`, `PUT`, `PATCH` and `DELETE` now answer `403` when the request carries a cookie, carries no `Authorization` header, and the `Origin` is neither this deployment's own nor one you named in `MASTRACODE_ALLOWED_ORIGINS`.

The test is the credential, not the route, so three kinds of caller keep working without an exemption list:

- inbound webhooks (GitHub, Slack) send no cookies and authenticate by signature
- API clients and the CLI send `Authorization`, which a cross-site page cannot set without a preflight your CORS policy has to allow first
- signed-out browsers have no session to spend

**What to check before you upgrade** If you serve the SPA from its own host, its origin must be in `MASTRACODE_ALLOWED_ORIGINS`. It already had to be for the session cookie to work at all, so no correctly configured deployment needs a change.
