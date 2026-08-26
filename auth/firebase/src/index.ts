import type { MastraAuthProviderOptions } from '@internal/auth/provider';
import { MastraAuthProvider } from '@internal/auth/provider';

import admin from 'firebase-admin';
import { getFirestore } from 'firebase-admin/firestore';

/** The payload `authenticateToken` resolves to: a verified Firebase ID token. */
export type FirebaseUser = admin.auth.DecodedIdToken;

/**
 * Whether this provider can take somebody from a blank browser to a signed-in
 * session — the Mastra Factory's browser flow.
 *
 * It cannot, and that is a decision rather than an omission. The reasoning is
 * recorded here, in the package, so that a host can read it at runtime and a
 * reader can find it without the audit that produced it.
 *
 * WHY `ISSOProvider` IS NOT AVAILABLE TO THIS PACKAGE AT ALL
 *
 * Structural, not a matter of effort. Firebase sign-in is client-SDK driven: the
 * browser SDK owns the redirect and the popup. The Admin SDK this package is
 * built on exists to *verify* ID tokens somebody else minted, and it has no
 * hosted-login URL to return — so there is nothing for `getLoginUrl` to answer
 * with.
 *
 * WHY THE `IAuthHttpHandler` ROUTE WAS ALSO DECLINED
 *
 * The remaining option is to serve the flow directly over Google's Identity
 * Toolkit REST API: `accounts:createAuthUri` to mint an identity-provider URL,
 * `accounts:signInWithIdp` to complete it. Three things stop that from being
 * something this package can ship:
 *
 * 1. **It needs a credential this package does not take.** Identity Toolkit's
 *    sign-in endpoints are keyed by the project's *Web API key*, a browser
 *    credential, which is a different thing from the service-account credential
 *    `firebase-admin` is initialized with. Asking for it would mean a second,
 *    differently-scoped secret in the constructor.
 *
 * 2. **`createAuthUri` returns a `sessionId` that has to survive to the
 *    callback.** Sign-in and callback are two separate HTTP requests, and
 *    `signInWithIdp` will not complete without the `sessionId` the first one
 *    produced. Carrying it needs a shared, request-scoped store; nothing in
 *    `IAuthHttpHandler` provides one, and inventing per-deployment storage
 *    inside a provider is how a provider becomes infrastructure.
 *
 * 3. **None of it can be written or verified offline.** Every step is a live
 *    call to `identitytoolkit.googleapis.com` against a real project with a real
 *    identity provider configured. An implementation written blind would satisfy
 *    the conformance suite's structural checks and fail on the first real
 *    sign-in, which is worse than declining in writing.
 *
 * WHAT THIS PROVIDER IS INSTEAD
 *
 * A bearer-token gate, and a complete one: it verifies Firebase ID tokens,
 * resolves a flat user id, authorizes, maps a memory resource id, and resolves
 * an organization. That is a supported shape — `toAuthDescriptor` reports
 * `signIn.kind: 'none'` for it, and `src/conformance.test.ts` runs the whole
 * suite against it and records exactly which checks are skipped and why.
 *
 * @see {@link https://github.com/mastra-ai/mastra/blob/main/mastracode/factory-auth/README.md#start-here}
 */
export const FACTORY_BROWSER_SIGN_IN = {
  /** Can this provider sign somebody in from a browser? */
  supported: false,

  /** One line, for a log or an error message. The long version is above. */
  reason:
    'Firebase sign-in is client-SDK driven, so the Admin SDK this package is built on has no ' +
    'hosted-login URL to return. Serving the flow over the Identity Toolkit REST API instead would ' +
    'need the project Web API key and a store carrying `createAuthUri`’s sessionId from the login ' +
    'request to the callback request, neither of which a provider package can supply.',

  /** What somebody who wanted a browser sign-in should do. */
  alternative:
    'Sign in with the Firebase browser SDK in your own app, then send the ID token it gives you as ' +
    '`Authorization: Bearer <token>`; this provider verifies it. For a Factory browser sign-in, ' +
    'configure a provider that owns a server-side hosted login.',
} as const;

/**
 * The organization id namespace, matching `@mastra/factory-auth`'s synthetic one.
 *
 * The literal is duplicated rather than imported because `@mastra/factory-auth`
 * is a devDependency here — it is the conformance suite, not a runtime
 * dependency of a provider. `src/conformance.test.ts` asserts that what this
 * class derives is exactly what `syntheticOrganizationId` derives, so the copy
 * cannot drift silently.
 */
const SYNTHETIC_ORGANIZATION_PREFIX = 'user:';

interface MastraAuthFirebaseOptions extends MastraAuthProviderOptions<FirebaseUser> {
  databaseId?: string;
  serviceAccount?: string;

  /**
   * Verify an ID token yourself, instead of going through
   * `admin.auth().verifyIdToken`.
   *
   * Supply it in tests: injecting the verifier is what lets this provider be
   * exercised with no network, no service account and no project, which is how
   * `src/conformance.test.ts` runs. When it is set the Firebase app is not
   * initialized, so the constructor needs no credentials at all.
   *
   * Reject or resolve `null` for a token you do not accept, exactly as
   * `verifyIdToken` rejects — `authenticateToken` turns both into `null`.
   */
  verifyIdToken?: (token: string) => Promise<FirebaseUser | null>;

  /**
   * Restore the pre-1.2 authorization behaviour: allow only users with a
   * document at `/user_access/{uid}` in Firestore.
   *
   * Off by default, and the default changed deliberately. Until 1.2 this was the
   * only behaviour, and it denied every request in any deployment that did not
   * happen to have that collection — so a correctly configured Firebase project
   * verified an ID token and then answered 403 to every core `/api/*` call, with
   * nothing in the response naming the missing document. Authorization policy
   * that depends on infrastructure the contract never mentions belongs in the
   * deployment, not in a provider's default.
   *
   * Turn it on if you keep that collection and want it enforced, or supply your
   * own `authorizeUser` for anything more specific.
   */
  requireUserAccessDocument?: boolean;
}

export class MastraAuthFirebase extends MastraAuthProvider<FirebaseUser> {
  /** See {@link FACTORY_BROWSER_SIGN_IN}. Readable from a provider instance. */
  readonly factoryBrowserSignIn = FACTORY_BROWSER_SIGN_IN;

  private serviceAccount: string | undefined;
  private databaseId: string | undefined;
  private verifyIdToken: ((token: string) => Promise<FirebaseUser | null>) | undefined;
  private requireUserAccessDocument: boolean;

  constructor(options?: MastraAuthFirebaseOptions) {
    super({ name: options?.name ?? 'firebase' });

    this.serviceAccount = options?.serviceAccount ?? process.env.FIREBASE_SERVICE_ACCOUNT;
    this.databaseId = options?.databaseId ?? process.env.FIRESTORE_DATABASE_ID ?? process.env.FIREBASE_DATABASE_ID;
    this.verifyIdToken = options?.verifyIdToken;
    this.requireUserAccessDocument = options?.requireUserAccessDocument ?? false;

    // A supplied verifier replaces the Admin SDK entirely, so there is no app to
    // initialize and no credential to find. This is what makes the provider
    // constructible with no environment at all.
    if (!this.verifyIdToken && !admin.apps.length) {
      admin.initializeApp({
        credential: this.serviceAccount
          ? admin.credential.cert(this.serviceAccount)
          : admin.credential.applicationDefault(),
      });
    }

    this.registerOptions(options);
  }

  /**
   * Verify a Firebase ID token.
   *
   * Resolves `null` for anything it cannot verify, rather than rejecting. An
   * unverifiable token is the ordinary state of a public endpoint — a stale tab,
   * a bookmark, a scanner — and the contract declares `Promise<TUser | null>`, so
   * a host reads a rejection as a bug: it logs a stack trace per unauthenticated
   * request and answers 401 with nothing useful in it. The previous
   * implementation let `verifyIdToken` reject straight through.
   *
   * An empty token resolves to `null` without a round trip. The host passes the
   * empty string to mean "this request carried no bearer token", and this
   * provider reads no cookie — see {@link FACTORY_BROWSER_SIGN_IN} — so there is
   * nowhere else to look.
   */
  async authenticateToken(token: string): Promise<FirebaseUser | null> {
    if (!token) {
      return null;
    }

    try {
      const verify = this.verifyIdToken ?? ((idToken: string) => admin.auth().verifyIdToken(idToken));
      return (await verify(token)) ?? null;
    } catch {
      return null;
    }
  }

  /**
   * Authorize a user this provider authenticated.
   *
   * The default allows any payload that names somebody — which is the same
   * answer the host reaches on its own for a provider that implements no
   * authorization at all, and the answer a deployment gating `/api/*` with
   * Firebase ID tokens expects. It never throws and never touches Firestore, so
   * a transient Firestore failure cannot turn a denial into a 500.
   *
   * Set `requireUserAccessDocument` to restore the `/user_access/{uid}` lookup,
   * or pass your own `authorizeUser` for anything else.
   */
  async authorizeUser(user: FirebaseUser): Promise<boolean> {
    const uid = user?.uid;
    if (typeof uid !== 'string' || uid.trim() === '') {
      return false;
    }

    if (!this.requireUserAccessDocument) {
      return true;
    }

    try {
      const db = this.databaseId ? getFirestore(this.databaseId) : getFirestore();
      const userAccess = await db.doc(`/user_access/${uid}`).get();
      return userAccess.data() !== undefined && userAccess.data() !== null;
    } catch {
      // A lookup that failed is not an authorization. Denying is the safe
      // direction, and returning rather than throwing keeps the host answering
      // 403 instead of 500.
      return false;
    }
  }

  /**
   * The memory resource id for an authenticated user: their `uid`.
   *
   * `uid` is the field Firebase's own API names as the user id. It is also what
   * the identity normalizer resolves for a `DecodedIdToken`, so the two halves of
   * a deployment — memory resources, keyed on this, and everything else, keyed on
   * the identity — agree about who this is.
   *
   * A caller-supplied `mapUserToResourceId` option replaces this, via
   * `registerOptions`.
   */
  mapUserToResourceId(user: FirebaseUser): string | undefined {
    return user?.uid;
  }

  /**
   * The organization this user's data is stored under: `user:${uid}`.
   *
   * Firebase has no organization primitive — GCIP multi-tenancy is an isolation
   * boundary, not a membership model — so there is nothing to look up and
   * nothing to create. The id is derived: a pure function of the user id, with
   * no store behind it, so two processes agree without talking to each other,
   * and the same user gets the same organization on every call and every deploy.
   *
   * This is the same value `withSyntheticOrganizations` from
   * `@mastra/factory-auth/organizations` would supply. It is implemented here
   * rather than left to that wrapper so that a provider straight out of the box
   * satisfies `isOrganizationsProvider`, instead of resolving no organization
   * until somebody remembers to wrap it. Wrapping it anyway is harmless: the
   * wrapper delegates and only supplies an id when the delegate declines.
   */
  async ensureOrganization(userId: string): Promise<string | undefined> {
    if (typeof userId !== 'string' || userId.trim() === '') {
      return undefined;
    }
    return `${SYNTHETIC_ORGANIZATION_PREFIX}${userId}`;
  }

  /**
   * Whether this user administers this organization.
   *
   * Every organization here is one person's, so the answer is whether the
   * organization is theirs. Nobody administers somebody else's.
   */
  async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {
    return organizationId === (await this.ensureOrganization(userId));
  }
}
