---
'@mastra/auth-firebase': minor
---

Changed how `@mastra/auth-firebase` authenticates and authorizes, and documented what it can and cannot do.

**An unverifiable token no longer throws**

`authenticateToken` now returns `null` for a token it cannot verify, instead of letting the Firebase Admin SDK's rejection escape. An unverifiable token is the ordinary state of a public endpoint, and a host reads a rejection as a bug: it logged a stack trace for every anonymous request. An empty token now returns `null` without a round trip.

**`authorizeUser` no longer requires a Firestore document**

The old default allowed only users with a document at `/user_access/{uid}`. Deployments without that exact collection verified an ID token and then answered 403 to every core `/api/*` request, with nothing in the response naming the missing document. The default now allows any user the provider authenticated.

To keep the old behaviour, ask for it:

```typescript
const firebaseAuth = new MastraAuthFirebase({ requireUserAccessDocument: true });
```

**`uid` is now the user id everywhere**

Firebase calls the user id `uid`, and a host reading only `id` treated an authenticated request as anonymous at every ownership check. `mapUserToResourceId` now returns `uid`, so memory resources and everything else agree about who a request belongs to.

**Firebase now resolves an organization**

`ensureOrganization(userId)` returns a stable `user:${userId}`, so organization-scoped storage has something correct to write. Firebase has no organization primitive, so the id is derived rather than stored and is identical in every process and every deploy.

**It says out loud that it cannot sign you in from a browser**

`@mastra/auth-firebase` validates ID tokens; it cannot take somebody from a blank browser to a signed-in session, so it cannot run the Mastra Factory's browser sign-in. Firebase sign-in is client-SDK driven, so the Admin SDK has no hosted-login URL to return. Sign in with the Firebase browser SDK in your own app and send the ID token here. The decision and its reasoning are exported as `FACTORY_BROWSER_SIGN_IN` and readable from a provider instance as `provider.factoryBrowserSignIn`.

**Also**

- A `verifyIdToken` option accepts your own verifier. When supplied, no Firebase app is initialized and no credential is looked for, which is what lets the provider be tested with no network and no project.
- The `FirebaseUser` type is now exported.
