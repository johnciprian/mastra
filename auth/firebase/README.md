# @mastra/auth-firebase

A Firebase authentication integration for Mastra. It verifies Firebase ID tokens on your API,
authorizes the users it authenticates, and resolves an organization for them.

## It cannot sign you in from a browser

This is the first thing to know, because the package name suggests otherwise. `@mastra/auth-firebase`
is a **bearer-token validator**. It gates your API. It cannot take somebody from a blank browser to a
signed-in session, so it cannot run the Mastra Factory's browser sign-in flow, and this is structural
rather than a gap waiting to be filled.

- **The Admin SDK has no hosted-login URL.** Firebase sign-in is client-SDK driven — the browser SDK
  owns the redirect and the popup. The Admin SDK this package is built on exists to _verify_ ID
  tokens somebody else minted, so there is nothing for a `getLoginUrl` to return.
- **Serving the flow over Identity Toolkit REST is not a provider's job.** It would need the
  project's Web API key (a browser credential, different from the service-account credential this
  package takes) and a store carrying `accounts:createAuthUri`'s `sessionId` from the sign-in request
  to the callback request. That is per-deployment infrastructure.

**What to do instead.** Sign in with the Firebase browser SDK in your own app and send the ID token
it gives you as `Authorization: Bearer <token>` — this provider verifies it. If you need a browser
sign-in for the Factory, configure a provider that owns a server-side hosted login.

The decision, its full reasoning, and a one-line summary you can log are exported as
`FACTORY_BROWSER_SIGN_IN`, and the provider carries it as `provider.factoryBrowserSignIn`.
`src/conformance.test.ts` runs the Factory conformance suite against this package and records exactly
which checks apply, which are skipped, and why.

## Installation

```bash
npm install @mastra/auth-firebase
# or
yarn add @mastra/auth-firebase
# or
pnpm add @mastra/auth-firebase
```

## Features

- Verifies Firebase ID tokens with the Admin SDK
- Authorizes any authenticated user by default, and is replaceable
- Maps a user to a memory resource id using `uid`, which is what Firebase calls the user id
- Derives a stable personal organization id, `user:${uid}`
- Optional Firestore-backed access control
- Support for service account credentials

## Usage

```typescript
import { Mastra } from '@mastra/core/mastra';
import { MastraAuthFirebase } from '@mastra/auth-firebase';

// Initialize with default configuration
const firebaseAuth = new MastraAuthFirebase();

// Or with custom options
const firebaseAuth = new MastraAuthFirebase({
  serviceAccount: 'path/to/service-account.json',
  databaseId: 'your-database-id',
});

// Enable auth in Mastra
const mastra = new Mastra({
  ...
  server: {
    auth: firebaseAuth,
  },
});
```

## Configuration

The package can be configured through constructor options or environment variables:

### Constructor Options

- `serviceAccount`: Path to Firebase service account JSON file
- `databaseId`: Firestore database ID, read only by the optional Firestore gate below
- `verifyIdToken`: verify an ID token yourself instead of using `admin.auth().verifyIdToken`. When
  supplied, no Firebase app is initialized and no credential is looked for — which is what lets this
  provider be tested with no network and no project.
- `requireUserAccessDocument`: restore the pre-1.2 Firestore authorization gate. Off by default.

### Environment Variables

- `FIREBASE_SERVICE_ACCOUNT`: Path to Firebase service account JSON file
- `FIRESTORE_DATABASE_ID` or `FIREBASE_DATABASE_ID`: Firestore database ID

## User authorization

`authorizeUser` returns `true` for any user this provider authenticated, and `false` for a payload
that names nobody. It never throws and never touches Firestore.

**This default changed in 1.2, and the change is why it is worth reading.** Previously the method
required a document at `/user_access/{uid}` in Firestore and allowed nobody without one. That is
authorization policy resting on infrastructure the Mastra provider contract never mentions, so every
deployment without that exact collection verified an ID token and then answered 403 to every core
`/api/*` request, with nothing in the response naming the missing document.

To keep the old behaviour, ask for it:

```typescript
const firebaseAuth = new MastraAuthFirebase({ requireUserAccessDocument: true });
```

It still reads `/user_access/{uid}`, still treats the presence of a document as authorization, and
now denies rather than throws when the lookup itself fails.

Or supply your own policy, which is what most deployments should do:

```typescript
const firebaseAuth = new MastraAuthFirebase({
  authorizeUser: async user => user.email_verified === true,
});
```

## Authentication

`authenticateToken` resolves the decoded ID token, or `null`. It resolves `null` rather than
rejecting for a token it cannot verify — an unverifiable token is the ordinary state of a public
endpoint, and a host reads a rejection as a bug. An empty token resolves to `null` without a round
trip.

## Organizations

`ensureOrganization(userId)` returns `user:${userId}`. Firebase has no organization primitive — GCIP
multi-tenancy is an isolation boundary, not a membership model — so the id is derived rather than
stored: a pure function of the user id, identical in every process and every deploy, which is what
the Factory's organization-scoped storage needs. This is the same value `withSyntheticOrganizations`
from `@mastra/factory-auth/organizations` would supply; it is implemented on the provider so that
wrapping is optional rather than required.

`isOrganizationAdmin(organizationId, userId)` is true exactly when the organization is that user's.
