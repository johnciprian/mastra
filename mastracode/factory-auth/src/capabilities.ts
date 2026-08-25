/**
 * The capability descriptor: what a provider can do, in a shape a UI can render.
 *
 * The Factory's sign-in screen currently branches on the provider's *name*. That
 * is why an unknown provider gets a GitHub logo and a "Continue with GitHub"
 * button: the screen has no other question it knows how to ask. This module is
 * the other question. `toAuthDescriptor(provider)` reduces a provider to a small
 * declared record, and the UI branches on that instead, so adding a provider
 * stops meaning editing the SPA.
 *
 * CLEAN-ROOM NOTE
 *
 * This file was written without reference to the enterprise implementation. The
 * derivation below is built from the Apache-2.0 structural guards re-exported by
 * `./contract` and from the public contract's own documentation, and no `ee/`
 * source was opened while writing it. The shape, the names and the scope are
 * this package's own: they were chosen for what the Factory's sign-in screen has
 * to decide, not by paraphrasing anything.
 *
 * SCOPE BOUNDARY
 *
 * Stated here so the record is in the file rather than in a review comment: no
 * role-based access control, no fine-grained authorization, no licence gate, no
 * telemetry. Those are enterprise concerns and they stay in the enterprise
 * packages. What is here is the minimum a browser needs in order to draw a
 * correct sign-in screen and a correct account menu.
 *
 * This module answers *which* capabilities a provider has. The capability
 * interfaces themselves are in `./contract`.
 */
import {
  isAuthHttpHandler,
  isCredentialsProvider,
  isOrganizationsProvider,
  isSessionProvider,
  isSSOProvider,
  type IMastraAuthProvider,
} from './contract.js';

/**
 * How a user can start a session in a browser.
 *
 * - `hosted` - redirect to a login page the provider owns, and come back through
 *   a callback. Anything OAuth or OIDC shaped.
 * - `credentials` - post an email and a password to this API.
 * - `both` - the provider offers each of the above, and the screen shows a form
 *   and a button.
 * - `none` - **the provider cannot sign anyone in from a browser.** See below;
 *   this is the value most likely to be misread.
 *
 * `none` DOES NOT MEAN AUTH IS OFF
 *
 * A `none` provider is a working, enabled, enforcing auth provider. It validates
 * bearer tokens on the API and it will reject an unauthenticated request. What
 * it cannot do is take somebody from a blank browser to a session, because it
 * implements neither a hosted login nor a credentials sign-in. Today's Supabase
 * and Firebase providers are exactly this.
 *
 * A deployment with auth switched off is a different state entirely, and it is
 * not represented here: there is no provider, so there is no descriptor. The
 * host reports that separately, and {@link toAuthDescriptor} is never called
 * with a placeholder to mean it.
 *
 * So a UI rendering `none` must not draw an empty sign-in box, and must not draw
 * "you're all set, come on in". It has to say that this deployment's provider
 * takes API tokens and cannot sign you in here, and point at whoever issues
 * them. Copy along these lines:
 *
 * > **Sign-in isn't available for this provider.** This deployment uses a
 * > provider that validates API tokens but can't sign you in from a browser. Ask
 * > your administrator for a token, or configure a provider that supports
 * > browser sign-in.
 *
 * A NOTE ON `both`, FOR WHOEVER EXTENDS THIS
 *
 * Four values cover what the contract can express today, because the contract
 * has exactly one hosted-login capability. The day a provider offers credentials
 * plus two different SSO buttons, this stops being an enum: it becomes a
 * credentials flag and a list of hosted options. That is a deliberate trade for
 * a smaller type now, not an oversight.
 */
export type AuthSignInKind = 'hosted' | 'credentials' | 'both' | 'none';

/**
 * A rendering token for the sign-in control. **Not a provider name.**
 *
 * This is a closed union on purpose, and the closedness is the whole feature.
 * The obvious design is a free-form string carrying the vendor - `'workos'`,
 * `'google'`, `'github'` - and it fails twice. It puts vendor names back into
 * the SPA as branch conditions, which is the coupling this whole descriptor
 * exists to remove, and the SPA gate that fails CI on provider-name literals in
 * `factory-ui/src` would reject the lookup table that such a field implies.
 *
 * So the kit declares the tokens, and each one names a *visual treatment* rather
 * than a vendor:
 *
 * - `generic` - a neutral control. The default, and the right answer whenever
 *   there is any doubt.
 * - `sso` - enterprise single sign-on: an organization's identity provider,
 *   usually reached through a work email.
 * - `oauth` - a consumer identity provider reached by redirect.
 * - `email` - an email and password form.
 *
 * A UI maps these to icons and copy in one place. Adding a vendor never touches
 * that map, because no token is a vendor.
 */
export type AuthProviderHint = 'generic' | 'sso' | 'oauth' | 'email';

/** Default {@link AuthProviderHint}: a neutral control, correct for any provider. */
export const DEFAULT_PROVIDER_HINT: AuthProviderHint = 'generic';

/** Where the Factory mounts its auth routes, and so where a credentials form posts. */
export const DEFAULT_CREDENTIALS_BASE_PATH = '/auth';

/** How a browser can start a session. */
export interface AuthSignInDescriptor {
  /** See {@link AuthSignInKind}, and read the note on `none` before rendering it. */
  kind: AuthSignInKind;

  /**
   * Display copy for the sign-in control, when the host has some.
   *
   * Host-supplied only. {@link toAuthDescriptor} never invents one from
   * `provider.name`, because a machine name is not display copy: "Continue with
   * better-auth" is worse than the generic string a UI already has. A UI must
   * therefore treat this as absent by default and fall back to its own copy.
   */
  label?: string;

  /**
   * Which visual treatment to use. See {@link AuthProviderHint}.
   *
   * Optional on the type so that a payload from an older server still parses.
   * Every descriptor this package produces sets it, defaulting to
   * {@link DEFAULT_PROVIDER_HINT}.
   */
  providerHint?: AuthProviderHint;

  /**
   * Whether new accounts can be created. Present only when `kind` includes
   * credentials.
   *
   * **Positive polarity. Read the polarity note on {@link AuthDescriptor}
   * before wiring this to a UI.**
   */
  signUpEnabled?: boolean;

  /**
   * Base path a credentials form posts to. Present only when `kind` includes
   * credentials, and defaults to {@link DEFAULT_CREDENTIALS_BASE_PATH}.
   *
   * This is a host routing fact, not a provider fact: it is where the host
   * mounted its auth routes. Override it when yours are mounted elsewhere.
   */
  credentialsBasePath?: string;
}

/**
 * What the account UI can offer once somebody is signed in.
 *
 * Every field is a plain boolean and every one is derived, so a UI can render
 * from this without probing the provider itself.
 */
export interface AuthFeatureDescriptor {
  /**
   * Whether a sign-out control makes sense, because there is something to sign
   * out of: a browser sign-in, a server-side session, or auth routes the
   * provider serves itself.
   *
   * False only for a provider with none of the three - a pure bearer-token
   * validator, where a browser never had a session to end.
   */
  logout: boolean;

  /** Whether the provider can resolve and bootstrap organization membership. */
  organizations: boolean;

  /**
   * Whether a session can be extended without a full sign-in.
   *
   * Distinct from {@link sessionRevocation}: see the note on
   * {@link toAuthDescriptor} about why these two are checked separately rather
   * than both reading "is a session provider".
   */
  refresh: boolean;

  /** Whether a session can be destroyed server-side before it expires. */
  sessionRevocation: boolean;
}

/**
 * What a provider can do, as a record a browser can render.
 *
 * ```ts
 * const descriptor = toAuthDescriptor(provider);
 * // { signIn: { kind: 'hosted', providerHint: 'generic' },
 * //   features: { logout: true, organizations: false, refresh: false, sessionRevocation: false } }
 * ```
 *
 * A `signUpEnabled` POLARITY WARNING, AND IT IS NOT DECORATIVE
 *
 * Three layers of this system express the same fact with two different
 * polarities, and one of them is about to ride alongside the other:
 *
 * - the provider method is positive: `isSignUpEnabled()`;
 * - the wire field the SPA reads today is negative: `signUpDisabled`;
 * - {@link AuthSignInDescriptor.signUpEnabled} here is positive again.
 *
 * The `/auth/me` payload carries both fields for one release, so for that
 * release a single response contains two fields of opposite polarity describing
 * the same thing. A missing `!` in the branch that reads them shows a sign-up
 * link on a deployment that deliberately disabled sign-up, and nothing about
 * that failure looks like a bug from the outside.
 *
 * Positive is the right polarity to keep - it matches the provider method, and
 * negative booleans read backwards at every call site - so the conflict is
 * resolved here in favour of `signUpEnabled` and flagged rather than hidden. A
 * consumer reading both must treat the descriptor as authoritative, and the
 * transition needs a test for a response carrying the two fields together, not
 * only for the four {@link AuthSignInKind} values.
 */
export interface AuthDescriptor {
  signIn: AuthSignInDescriptor;
  features: AuthFeatureDescriptor;
}

/**
 * The parts of a descriptor a provider cannot tell you, supplied by the host.
 *
 * Each of these is a presentation or routing decision rather than a capability,
 * so no guard can derive it and guessing would be worse than defaulting.
 */
export interface AuthDescriptorOverrides {
  /** See {@link AuthSignInDescriptor.label}. */
  label?: string;

  /** See {@link AuthSignInDescriptor.providerHint}. Defaults to {@link DEFAULT_PROVIDER_HINT}. */
  providerHint?: AuthProviderHint;

  /**
   * See {@link AuthSignInDescriptor.credentialsBasePath}. Defaults to
   * {@link DEFAULT_CREDENTIALS_BASE_PATH}, and is ignored when the provider has
   * no credentials sign-in.
   */
  credentialsBasePath?: string;
}

/**
 * Derive an {@link AuthDescriptor} from a provider.
 *
 * ```ts
 * app.get('/auth/me', c => c.json({ ...session, auth: toAuthDescriptor(provider) }));
 * ```
 *
 * Pure, synchronous, and never throws: the provider is only inspected, never
 * called, with one exception noted below. Safe to call on every request, though
 * the answer only changes when the provider does.
 *
 * Named `toAuthDescriptor` to pair with `toAuthIdentity` - same package, same
 * verb, same job of normalizing a provider-shaped thing into a declared shape -
 * and to keep `describe*` free for the conformance suite, where `describeAuthProvider`
 * registers a vitest suite and a near-identical `describeAuth` in scope would be
 * a trap.
 *
 * HOW EACH FIELD IS DERIVED
 *
 * `signIn.kind` comes from two guards: `isSSOProvider` means a hosted login
 * (`getLoginUrl` plus `handleCallback`), `isCredentialsProvider` means a
 * `signIn` method. Both, either, or neither gives the four kinds.
 *
 * `signUpEnabled` is the one place a provider method is actually invoked, and it
 * has two distinct unknowns with two different answers. A credentials provider
 * that does not implement `isSignUpEnabled` gets `true`, because the contract
 * documents that as the default. A provider whose implementation *throws* gets
 * `false`, because at that point we do not know, and hiding a sign-up link fails
 * closed while showing one fails open. A provider that returns anything other
 * than a boolean - an `async` method returning a Promise is the realistic case -
 * also gets `false`, for the same reason.
 *
 * THE RULE THIS PACKAGE FOLLOWS FOR A MISBEHAVING PROVIDER
 *
 * Fail in the direction that is safe for the caller, which is not the same
 * direction every time and is why this is worth stating once. Here, a provider
 * that misbehaves gets the restrictive answer, because the output drives what a
 * UI offers and offering too much is the harm. In `./identity`,
 * `toAuthIdentity` deliberately does the opposite and lets a provider's throw
 * propagate, because there the output decides *who someone is*, and swallowing
 * the error would resolve an authentication failure to a plausible-looking
 * identity. Same rule, opposite mechanics: never let a broken provider produce
 * an answer that grants something.
 *
 * `features.logout` asks whether anything exists to sign out of, so it takes a
 * third guard as well: `isAuthHttpHandler` means the provider mounts its own
 * auth routes and therefore has a sign-out of its own, even where the kind is
 * `none`. `features.organizations` is `isOrganizationsProvider` directly.
 *
 * `features.refresh` and `features.sessionRevocation` are checked as methods
 * rather than both being read off `isSessionProvider`, and that is not
 * belt-and-braces. `ISessionProvider` declares seven members, but the guard
 * tests two of them (`createSession`, `validateSession`). The narrowing is
 * therefore optimistic: a structurally-satisfying provider can pass the guard
 * with no `destroySession` at all, and a UI that offered "sign out everywhere"
 * on the strength of the guard alone would call a method that is not there.
 *
 * @param provider A provider. There is no descriptor for "auth is disabled" -
 * that state has no provider, and the host reports it separately.
 */
export function toAuthDescriptor(
  provider: IMastraAuthProvider,
  overrides: AuthDescriptorOverrides = {},
): AuthDescriptor {
  const hosted = isSSOProvider(provider);
  const credentials = isCredentialsProvider(provider);

  const kind: AuthSignInKind =
    hosted && credentials ? 'both' : hosted ? 'hosted' : credentials ? 'credentials' : 'none';

  const signIn: AuthSignInDescriptor = {
    kind,
    providerHint: overrides.providerHint ?? DEFAULT_PROVIDER_HINT,
  };
  if (overrides.label !== undefined) signIn.label = overrides.label;
  if (credentials) {
    signIn.signUpEnabled = readSignUpEnabled(provider);
    signIn.credentialsBasePath = overrides.credentialsBasePath ?? DEFAULT_CREDENTIALS_BASE_PATH;
  }

  let refresh = false;
  let sessionRevocation = false;
  const session = isSessionProvider(provider);
  if (session) {
    refresh = typeof provider.refreshSession === 'function';
    sessionRevocation = typeof provider.destroySession === 'function';
  }

  return {
    signIn,
    features: {
      logout: kind !== 'none' || session || isAuthHttpHandler(provider),
      organizations: isOrganizationsProvider(provider),
      refresh,
      sessionRevocation,
    },
  };
}

/**
 * Whether the provider that just satisfied `isCredentialsProvider` allows new
 * accounts. See {@link toAuthDescriptor} for why a throw answers `false` and an
 * absent method answers `true`.
 *
 * Anything that is not literally `true` or absent answers `false`, and that
 * strictness is the point rather than defensiveness. `isSignUpEnabled` is
 * declared synchronous, but nothing stops a provider writing `async
 * isSignUpEnabled()`, and an `async` method returns a Promise - which is truthy.
 * A loose check would send `signUpEnabled: true` to the SPA for a deployment
 * that had switched sign-up off, and the SPA would render a sign-up link on it.
 * Nothing would look broken to anyone, which is the failure this field's whole
 * polarity discussion is about.
 */
function readSignUpEnabled(provider: { isSignUpEnabled?: () => boolean }): boolean {
  try {
    const enabled = provider.isSignUpEnabled?.();
    // `== null` covers both an absent method and one that returned `undefined`:
    // the contract's documented default is "sign-up is on unless you say
    // otherwise". Everything else has to be exactly `true`.
    return enabled == null ? true : enabled === true;
  } catch {
    return false;
  }
}
