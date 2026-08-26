/**
 * Identity normalization.
 *
 * A provider's `authenticateToken` may return anything. Five real providers
 * return five different shapes, and the host has to store data under one key
 * either way. This module turns "anything" into {@link AuthIdentity}, and it is
 * the only place in the Factory that knows what a Firebase token or a
 * better-auth session looks like.
 *
 * Three exports, and they layer:
 *
 * - {@link AuthIdentity} - the shape the host stores and the SPA renders.
 * - {@link toAuthIdentity} - the normalizer, covering the shapes providers
 *   actually return.
 * - {@link IIdentityProvider} and {@link isIdentityProvider} - the escape hatch
 *   for a provider whose shape this module does not know, and its structural
 *   guard.
 *
 * Everything here is pure. Nothing reaches the network, `node:crypto`, or a
 * request object, which is why the root barrel can re-export it into a browser
 * bundle.
 */

/**
 * One user, in one shape, with no vendor field.
 *
 * This replaces two types. `FactoryAuthUser` carried a WorkOS-specific id
 * alongside `id`, so every consumer had to decide which one was the real key;
 * the enterprise packages carried their own user type for the same job. A
 * vendor-named field is how a provider-agnostic host ends up with a provider in
 * it, so there isn't one: whatever the provider called its identifier, it
 * arrives here as `id`.
 *
 * The enterprise type is described rather than named, deliberately. This file
 * is Apache-2.0 and its JSDoc is copied verbatim into `dist/identity.d.ts`, so
 * `src/__tests__/no-ee-boundary.test.ts` fails on an enterprise identifier
 * appearing here even in prose. That is the check working, not a false
 * positive.
 *
 * WHY `id` IS REQUIRED, AND NOT `string | undefined`
 *
 * A flat, resolvable `id` is the first of the four obligations the auth audit
 * found: every Factory surface that persists anything - agent state, credential
 * storage, run history, the `user:${userId}` tenant fallback - keys on it, and
 * before this package none of them could point at an interface that promised
 * it. The obligation was real and undocumented, which is the worst combination:
 * a provider could satisfy the declared contract in full, return
 * `{ uid: 'abc' }`, and the host would authenticate the request as nobody and
 * then fail somewhere unrelated with a message about state.
 *
 * Making the field required moves that failure to the one place that can
 * explain it. {@link toAuthIdentity} returns `null` rather than an identity with
 * a missing id, so "no id" is a single, checkable outcome instead of a
 * half-built object travelling into a storage key. `src/conformance/` (K18)
 * asserts the obligation against a real provider, and it can only do that
 * because the type states it.
 *
 * The optional fields are optional because nothing breaks without them. A
 * provider that returns no email still runs the Factory; a provider that
 * returns no id does not.
 */
export interface AuthIdentity {
  /**
   * The provider's identifier for this user, flattened.
   *
   * Non-empty. Stable across sign-ins for the same user - the host uses it as a
   * storage key, so a value that changes per session silently partitions that
   * user's data.
   */
  id: string;
  /** Primary email, when the provider exposes one. */
  email?: string;
  /** Display name, when the provider exposes one. */
  name?: string;
  /** Avatar URL, when the provider exposes one. */
  avatarUrl?: string;
  /**
   * The organization this identity is acting in.
   *
   * Absent is normal: plenty of providers have no organization concept at all.
   * `./organizations` is what turns an absent one into a deterministic value,
   * so nothing here has to invent a default.
   */
  organizationId?: string;
}

/**
 * The escape hatch: a provider maps its own payload.
 *
 * An optional capability, in the style of the seven in `./contract` - a
 * provider implements `toIdentity` or it does not, and {@link isIdentityProvider}
 * is how anything finds out. It exists for the provider whose token shape you
 * cannot change and whose shape this module does not recognize: a claim under a
 * custom namespace, an id assembled from two fields, a tenant read from
 * somewhere only that provider knows about.
 *
 * Implementing it is a statement that this provider knows its own payload
 * better than the shape detection below does. {@link toAuthIdentity} takes that
 * statement literally - see the note there on what a `null` return means.
 */
export interface IIdentityProvider {
  /**
   * Map one `authenticateToken` result onto an identity, or `null` when the
   * payload carries no identity this provider will vouch for.
   */
  toIdentity(raw: unknown): AuthIdentity | null;
}

/**
 * Does this provider map its own identities?
 *
 * Structural, never `instanceof`, matching the seven guards in `./contract`:
 * duplicate copies of `@mastra/core` in a dependency tree are common, and an
 * `instanceof` check against the wrong copy is false for an object that
 * implements the interface perfectly.
 */
export function isIdentityProvider(provider: unknown): provider is IIdentityProvider {
  return (
    provider !== null &&
    typeof provider === 'object' &&
    typeof (provider as IIdentityProvider).toIdentity === 'function'
  );
}

/**
 * The keys an id may arrive under, in the order they are read.
 *
 * PRECEDENCE, AND WHY IT IS THIS ORDER
 *
 * - `id` first. It is the field {@link AuthIdentity} declares, so a provider
 *   that already emits one has answered this question itself. Reading anything
 *   else ahead of it would override the provider's own answer with a guess.
 * - `uid` before `sub`. The only shape that carries both is Firebase's
 *   `DecodedIdToken`, where the two hold the same value and `uid` is the field
 *   Firebase's own API names as the user id; `sub` there is the underlying JWT
 *   claim it was copied from. A raw OIDC claims object has only `sub` and still
 *   resolves. So the order is observable almost nowhere, and where it is
 *   observable it picks the vendor's named field over the raw claim.
 *
 * The order is a rule rather than an accident, which matters most for the
 * ambiguous case nobody designs for: a payload carrying both `id` and `sub`
 * with different values resolves to `id`, every time, on every provider.
 */
const ID_KEYS = ['id', 'uid', 'sub'] as const;

/** Where better-auth puts the organization the session is scoped to. */
const SESSION_ORGANIZATION_KEY = 'activeOrganizationId';

/** Narrow to a plain keyed object. Arrays and functions are not payloads. */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

/**
 * Read a value that is allowed to be an identifier.
 *
 * Accepts a string, and coerces a finite `number` or a `bigint` to its decimal
 * form. Numeric ids are ordinary - a serial primary key behind a self-hosted
 * provider, a legacy directory - and rejecting one would mean the provider
 * authenticates the request and the host then 401s with nothing to debug. The
 * coercion is lossless and one-way: an id is a key, never arithmetic.
 *
 * Rejects everything else, including `NaN`, `Infinity` and booleans. Those have
 * no meaningful key form, and stringifying one would hide a provider bug behind
 * a sign-in that appears to work.
 *
 * Rejects the empty string, and a string that is only whitespace. An id is a
 * storage key, and a blank one is a key that every user shares - the exact
 * failure the required `id` exists to prevent. Blank is treated as absent, so
 * `{ id: '', sub: 'oidc-1' }` resolves to `oidc-1` rather than to `null`: the
 * provider sent an id field it never filled in, and `sub` is the value it
 * actually has. Nothing is trimmed - a rejected id is rejected, an accepted one
 * is passed through unchanged, because rewriting a key is not this function's
 * job.
 */
function asId(value: unknown): string | undefined {
  if (typeof value === 'string') return value.trim() === '' ? undefined : value;
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : undefined;
  if (typeof value === 'bigint') return String(value);
  return undefined;
}

/**
 * Read an optional display field. Strings only, and never blank.
 *
 * No coercion here, unlike {@link asId}: a numeric `name` or a boolean `email`
 * is a mis-mapped field rather than an unusual encoding, and rendering `false`
 * as a display name helps nobody. A blank string becomes `undefined` so callers
 * only have one absent value to branch on.
 */
function asText(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value : undefined;
}

/**
 * Read one object: an id under any of {@link ID_KEYS}, plus the optional display
 * fields under their own names.
 *
 * The organization is a parameter rather than a field this function reads,
 * which is deliberate. Where the organization comes from is the one thing that
 * differs between the shapes below - a flat payload declares its own, a
 * `{ session, user }` wrapper takes it from the session and from nowhere else -
 * and making it an argument puts that decision at each call site, in the open,
 * instead of behind a fallback chain in here that every caller inherits whether
 * it wanted it or not.
 */
function readFields(record: Record<string, unknown>, organizationId: string | undefined): AuthIdentity | null {
  let id: string | undefined;
  for (const key of ID_KEYS) {
    id = asId(record[key]);
    if (id !== undefined) break;
  }
  if (id === undefined) return null;

  return {
    id,
    email: asText(record.email),
    name: asText(record.name),
    avatarUrl: asText(record.avatarUrl),
    organizationId,
  };
}

/** Read a payload that declares its own organization at the top level. */
function readFlat(record: Record<string, unknown>): AuthIdentity | null {
  return readFields(record, asId(record.organizationId));
}

/**
 * Normalize whatever a provider's `authenticateToken` returned.
 *
 * Returns `null` only when no id can be resolved. That is the whole contract:
 * an identity out of this function always has a usable `id`, and a `null` always
 * means "this payload names no user", never "this payload was slightly odd".
 *
 * THE SHAPES, IN THE ORDER THEY ARE TRIED
 *
 * 1. `{ session, user }` - better-auth. Recognized when *both* halves are
 *    objects, and checked before anything else. A result carrying the wrapper
 *    and top-level identity fields is read as the wrapper: the `user` half is
 *    the authenticated subject, while the top level of that object holds session
 *    bookkeeping, including a `session.id` that is a session id and not a user
 *    id. Preferring the wrapper is what keeps the id and the organization from
 *    being read out of two different subjects.
 *
 *    The organization comes from `session.activeOrganizationId`, and from
 *    nowhere else. The session is the authenticated context: a user who belongs
 *    to three organizations is acting in exactly one of them for this request,
 *    and that is the one the session names.
 *
 *    A session that names none resolves to no organization - the `user` half's
 *    own `organizationId` is not read as a fallback. `./organizations` then
 *    turns that absence into the user's private partition, `user:${id}`, which
 *    is the same answer every no-org caller gets.
 *
 *    ACTIVATION IS NOT MEMBERSHIP, AND THE COST OF SAYING SO
 *
 *    The `user` half's `organizationId` says the user is a member of that
 *    organization. It does not say this session was switched into it, and a
 *    session that never activated an organization must not reach that
 *    organization's shared data. Reading membership as activation is the
 *    direction that leaks; this direction is not.
 *
 *    The cost is real and is accepted rather than hidden: a user who belongs to
 *    exactly one organization and has not switched into it sees their private
 *    partition instead of their team's. That is confusing, and it is what a
 *    signed-in user sees before they pick an organization. It is not a data
 *    leak, which is why it is the side that won.
 *
 *    Once the wrapper is recognized there is no fallthrough to step 2. If the
 *    `user` half names no one, the answer is `null` - reaching past it to the
 *    top level would take an id from the wrong subject, which is worse than an
 *    honest failure.
 *
 * 2. Flat - `{ id }`, `{ uid }` (Firebase `DecodedIdToken`), `{ sub }` (raw OIDC
 *    claims), and anything else that puts its identifier at the top level. See
 *    {@link ID_KEYS} for the precedence between them.
 *
 * Anything that is not a keyed object - `null`, `undefined`, a string, a number,
 * an array, a function - is `null`. There is no shape in which those name a user.
 *
 * @param raw The provider's `authenticateToken` result.
 * @param provider Optionally, the provider that produced it. When it implements
 * {@link IIdentityProvider}, its `toIdentity` replaces the shape detection
 * above - see below. Typed `unknown` so a host can pass any provider without a
 * cast; the structural guard does the narrowing.
 *
 * THE PROVIDER MAPPER WINS, INCLUDING WHEN IT SAYS `null`
 *
 * If `provider` implements `toIdentity`, it is called and its answer is the
 * answer. A `null` from it is returned as `null`; the built-in shape detection
 * does not then run as a fallback.
 *
 * That is the deliberate half of this. The alternative - fall through on `null`
 * and let shape detection have a go - is unsafe rather than merely surprising.
 * A mapper returns `null` for reasons only it knows: the payload is a service
 * account, the email is unverified, a required custom claim is missing. Every
 * one of those payloads still carries a `sub`, so a fallback would hand back an
 * identity the provider had just refused, and the refusal would be invisible.
 * Fail closed.
 *
 * It also makes the function one rule instead of two. With a mapper present,
 * `toAuthIdentity` is `provider.toIdentity`, normalized - there is no second,
 * conditional path to reason about. And the escape from that rule is trivial in
 * the direction that is safe: a mapper that wants the built-in behaviour for
 * shapes it does not handle can `return toAuthIdentity(raw)` itself, with no
 * provider argument. Delegating upward is one line; suppressing a fallthrough
 * that the kit performs on your behalf is not possible at all.
 *
 * The mapper's result is still normalized rather than trusted: it goes through
 * the same flat reader, so `id` is guaranteed non-empty and the optional fields
 * are guaranteed to be strings or absent. A mapper chooses *which* fields; it
 * does not get to break the invariant the type promises, which is the invariant
 * the conformance suite asserts. A mapper that returns something with no usable
 * id yields `null`, exactly as if it had returned `null` outright.
 *
 * A mapper that throws propagates. This function does not convert a bug in a
 * provider into an anonymous request.
 */
export function toAuthIdentity(raw: unknown, provider?: unknown): AuthIdentity | null {
  if (isIdentityProvider(provider)) {
    const mapped = asRecord(provider.toIdentity(raw));
    return mapped === undefined ? null : readFlat(mapped);
  }

  const record = asRecord(raw);
  if (record === undefined) return null;

  const session = asRecord(record.session);
  const user = asRecord(record.user);
  if (session !== undefined && user !== undefined) {
    // The session names the organization, or nothing does. The `user` half's own
    // `organizationId` is never consulted - see the note above on why activation
    // is not membership.
    return readFields(user, asId(session[SESSION_ORGANIZATION_KEY]));
  }

  return readFlat(record);
}
