/**
 * Organizations and tenancy.
 *
 * Two exports carry the work, and they answer the same question from opposite
 * ends. {@link withSyntheticOrganizations} makes a provider able to answer
 * "which organization is this user in?"; {@link resolveOrganizationId} answers
 * it for a host that has an identity in hand and no provider call to spare.
 * Both derive the same id from the same input, so a row written through one is
 * found by the other.
 *
 * WHY A WRAPPER AND NOT A `CompositeAuth` MEMBER
 *
 * The obvious way to add a capability to a provider in this codebase is to
 * compose: hand `CompositeAuth` a second provider that supplies the missing
 * piece. That does not work here, and the reason is structural rather than a
 * matter of taste.
 *
 * `CompositeAuth` is declared as
 * `class CompositeAuth extends MastraAuthProvider implements ISSOProvider<User>,
 * ISessionProvider<Session>, IUserProvider<User>`
 * (`packages/_internals/auth/src/provider/index.ts` lines 169-171). Three
 * capability interfaces, and organizations is not one of them. Reading further
 * confirms it is not an omission in the `implements` clause either: the class
 * body declares no `ensureOrganization` and no `isOrganizationAdmin` anywhere,
 * and its constructor deletes the members of the three interfaces it *does*
 * implement when no inner provider supports them, precisely so that a
 * structural guard reports the composite's real capabilities. So a composite
 * built from a provider with organizations and one without would fail
 * `isOrganizationsProvider` regardless of what went into it, because the
 * composite has no such members to find.
 *
 * A wrapper does not have that problem: it is the provider, plus two methods.
 *
 * NOTHING HERE PERSISTS ANYTHING
 *
 * A synthetic organization is a derivation, not a record. There is no table, no
 * membership list, no invitation, and no second member - it exists so that a
 * host with one storage column named `organizationId` has something correct to
 * put in it. A deployment that needs organizations people can be invited to
 * needs a provider that implements `IOrganizationsProvider` for real; this
 * module then steps aside and delegates to it.
 */
import { isOrganizationsProvider } from './contract.js';
import type { IMastraAuthProvider, IOrganizationsProvider } from './contract.js';
import type { AuthIdentity } from './identity.js';

/**
 * The prefix a synthetic organization id carries: `user:`.
 *
 * WHY THIS EXACT STRING, AND WHY IT IS NOT A FREE CHOICE
 *
 * The Factory already writes this id. `tenantOrgId` in
 * `mastracode/factory/src/routes/provider-credentials.ts` scopes model
 * credential rows under `` `user:${tenant.userId}` `` whenever the tenant has
 * no organization, and rows written that way are in deployed databases now.
 * Any other prefix - or a hash, or an opaque generated id - would resolve the
 * same user to a different partition on the day this module shipped, and every
 * credential they had stored would silently become someone else's problem to
 * find. Matching the existing string is a compatibility requirement, not a
 * stylistic one.
 *
 * The colon is doing real work as well. It namespaces the synthetic id away
 * from whatever a real provider mints, so a wrapped provider's own organization
 * ids and this module's can share one column without either being mistaken for
 * the other, and it keeps the id greppable: an operator looking at
 * `user:8f21ac` in a storage row can see both that it is synthetic and whose it
 * is, which is not true of a digest.
 */
export const SYNTHETIC_ORGANIZATION_PREFIX = 'user:';

/**
 * How a synthetic organization id is spelled.
 *
 * One option, and it is here for a single situation: a provider whose own
 * organization ids already start with `user:`, where sharing the namespace
 * would make {@link isSyntheticOrganizationId} answer `true` for a real
 * organization.
 *
 * **Changing the prefix on a running deployment is a data migration.** Every id
 * this module derives changes with it, so every row keyed on one is orphaned -
 * the data is still there and the user simply cannot see it, which is the worst
 * shape a data loss can take because nothing reports an error. Pick it once,
 * before the first sign-in, or migrate the rows.
 *
 * The prefix must be a non-empty string. An empty one is rejected rather than
 * accepted, because it would make every id its own namespace: `resolveOrganizationId`
 * would return the raw user id, and {@link isSyntheticOrganizationId} would then
 * answer `true` for every organization id in the system, including real ones.
 */
export interface SyntheticOrganizationOptions {
  /** Defaults to {@link SYNTHETIC_ORGANIZATION_PREFIX}. */
  prefix?: string;
}

/**
 * Read an id-shaped value, or `undefined`.
 *
 * The rule is `./identity`'s `asId`, deliberately: a user id that normalizes one
 * way when an identity is built and another way when its organization is derived
 * would partition that user's data against itself. Strings pass through
 * unchanged, finite numbers and bigints are coerced to their decimal form
 * (serial primary keys behind self-hosted providers are ordinary), and
 * everything else - including a blank or whitespace-only string - is absent.
 *
 * Blank is the case that matters here. `''` reaching a template would produce
 * the bare prefix, and `user:` is not one user's organization: it is an
 * organization every user with a broken id would share, which is the failure
 * this whole module exists downstream of.
 */
function asId(value: unknown): string | undefined {
  if (typeof value === 'string') return value.trim() === '' ? undefined : value;
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : undefined;
  if (typeof value === 'bigint') return String(value);
  return undefined;
}

/** Validate the configured prefix once, at the point it is first used. */
function readPrefix(options: SyntheticOrganizationOptions | undefined): string {
  const prefix = options?.prefix;
  if (prefix === undefined) return SYNTHETIC_ORGANIZATION_PREFIX;
  if (typeof prefix !== 'string' || prefix === '') {
    throw new TypeError(
      'withSyntheticOrganizations: `prefix` must be a non-empty string. ' +
        'An empty prefix makes every organization id look synthetic, including a real one. ' +
        `Omit it to use the default, '${SYNTHETIC_ORGANIZATION_PREFIX}'.`,
    );
  }
  return prefix;
}

/**
 * The personal organization id for one user: the prefix, then the user id.
 *
 * ```ts
 * syntheticOrganizationId('8f21ac'); // 'user:8f21ac'
 * ```
 *
 * WHAT THE ID IS DERIVED FROM, AND WHY IT IS THE USER ID
 *
 * The provider's user id, and nothing else. `AuthIdentity.id` is the one value
 * in this package that is already documented as stable across sign-ins for the
 * same user - the host keys storage on it, so a provider whose id changes per
 * session has a bug that partitions that user's data with or without this
 * module. Deriving from it inherits exactly that guarantee and adds no new one.
 *
 * Three alternatives, and why each is worse:
 *
 * - **A generated id.** A `randomUUID()` per user is not a derivation at all: it
 *   has to be stored somewhere to be found again, which means this module needs
 *   a table, and a wrapper that needs a table is a provider. It also fails the
 *   only property the callers need, which is that two processes computing the
 *   same user's organization agree without talking to each other.
 * - **A hash of the user id.** Stable, and pointless. The user id is already
 *   opaque to anyone reading the database, hashing it buys no secrecy that
 *   matters (the plaintext is the primary key two columns over), and it costs
 *   the thing that does matter: `user:8f21ac` tells an operator whose row this
 *   is and `user:9c1f...` does not.
 * - **A hash of the email.** Stable only until somebody changes their email
 *   address, at which point their entire history moves to a new organization and
 *   the old one becomes unreachable. Email is a mutable attribute of a user, not
 *   an identifier for one, and providers differ on case-folding it besides.
 *
 * What none of them is, and what this function is: a pure function of its
 * argument. No clock, no random source, no environment variable, no hostname,
 * no module state. Two calls in one process, two processes on one machine, and
 * two deploys three months apart all produce the same string.
 *
 * @param userId The provider's user id - `AuthIdentity.id`.
 * @returns The organization id, or `undefined` when `userId` names no user. See
 * the note on blanks in {@link asId}: absent is the honest answer, and it is the
 * answer `IOrganizationsProvider.ensureOrganization` already documents for a
 * user who stays no-org.
 */
export function syntheticOrganizationId(userId: string, options?: SyntheticOrganizationOptions): string | undefined {
  const prefix = readPrefix(options);
  const id = asId(userId);
  return id === undefined ? undefined : `${prefix}${id}`;
}

/**
 * Was this organization id derived by this module?
 *
 * For the UI question a personal organization creates: an account menu that
 * offers "invite a teammate" has to know that there is nothing to invite anyone
 * *to* yet, and this is how it finds out without a provider call.
 *
 * Answering `true` means only that the id is in the synthetic namespace - it
 * does not say whose. To ask whether an id is a particular user's personal
 * organization, compare against {@link syntheticOrganizationId} for that user;
 * that is the check {@link withSyntheticOrganizations} makes before it calls
 * anybody an administrator.
 */
export function isSyntheticOrganizationId(organizationId: string, options?: SyntheticOrganizationOptions): boolean {
  const prefix = readPrefix(options);
  return typeof organizationId === 'string' && organizationId.startsWith(prefix);
}

/**
 * The organization a host should store this identity's data under.
 *
 * ```ts
 * const identity = toAuthIdentity(await provider.authenticateToken(token, request), provider);
 * if (!identity) return c.json({ error: 'unauthorized' }, 401);
 * const organizationId = resolveOrganizationId(identity); // always a string
 * ```
 *
 * This generalizes the fallback the Factory already performs in one route.
 * `tenantOrgId` in `mastracode/factory/src/routes/provider-credentials.ts`
 * exists so that model credentials for a user with no organization are scoped to
 * that user instead of becoming server-global - a good decision, made once, in
 * the one file that happened to need it. Every other organization-scoped surface
 * has the same problem and no such line, so each one either invents its own
 * fallback or refuses the request. This function is that line, in a place the
 * other surfaces can import, so they degrade to a private organization instead
 * of returning 403 to a user whose provider simply has no organization concept.
 *
 * A NOTE ON THE NAME
 *
 * The task that specified this called it `resolveTenant`. It is named
 * `resolveOrganizationId` because that is what it returns: the contract this
 * package implements says `IOrganizationsProvider`, `ensureOrganization` and
 * `organizationId` throughout, and the word "tenant" appears nowhere in it. A
 * function whose name introduces a synonym for a concept the surrounding types
 * already name is a function every reader has to translate.
 *
 * PRECEDENCE
 *
 * A declared `organizationId` always wins. The provider - or the session inside
 * it, per `./identity` - has said which organization this request is acting in,
 * and overriding that with a derived id would move an authenticated member of a
 * real organization into a private one, where their team's data is not.
 *
 * @param identity Anything carrying an id and, optionally, an organization.
 * Accepts a partial so a host holding a `{ id, organizationId }` pair need not
 * construct a whole identity.
 * @returns Always a string. That total return type is the point: a caller that
 * has to branch on `undefined` is a caller that will write the branch that
 * 403s, which is the behaviour this replaces.
 * @throws TypeError when the identity carries neither an organization nor a
 * usable id. There is no answer in that case, and the alternatives are worse
 * than throwing: `undefined` puts the branch back, and a placeholder would be a
 * storage key shared by every caller who ever passed a broken identity. It
 * cannot happen for an identity from `toAuthIdentity`, which returns `null`
 * rather than an identity with no id.
 */
export function resolveOrganizationId(
  identity: Pick<AuthIdentity, 'id' | 'organizationId'>,
  options?: SyntheticOrganizationOptions,
): string {
  const declared = asId(identity?.organizationId);
  if (declared !== undefined) return declared;

  const synthetic = syntheticOrganizationId(identity?.id, options);
  if (synthetic === undefined) {
    throw new TypeError(
      'resolveOrganizationId: the identity has no organizationId and no usable id, so it resolves to no organization. ' +
        'Identities from toAuthIdentity always carry a non-empty id; this one was built some other way.',
    );
  }
  return synthetic;
}

/** Marks a wrapper, and holds the provider it wraps. See the re-wrap note below. */
const WRAPPED_PROVIDER = Symbol.for('mastra.factory-auth.syntheticOrganizations');

/** The two members `isOrganizationsProvider` tests for, and this wrapper supplies. */
const ORGANIZATION_MEMBERS = ['ensureOrganization', 'isOrganizationAdmin'] as const;

/** Peel off a previous wrapper so re-wrapping replaces it instead of stacking. */
function unwrap<TProvider extends IMastraAuthProvider>(provider: TProvider): TProvider {
  const inner = (provider as { [WRAPPED_PROVIDER]?: TProvider })[WRAPPED_PROVIDER];
  return inner ?? provider;
}

/**
 * Give any provider a deterministic personal organization, preserving
 * everything else it could already do.
 *
 * ```ts
 * import { withSyntheticOrganizations } from '@mastra/factory-auth/organizations';
 *
 * export const auth = withSyntheticOrganizations(new MyOidcProvider());
 * // isOrganizationsProvider(auth) === true, and so is every other guard that
 * // was true of MyOidcProvider.
 * ```
 *
 * WHEN THE PROVIDER ALREADY HAS ORGANIZATIONS: DELEGATE, NEVER OVERRIDE
 *
 * If the wrapped provider satisfies `isOrganizationsProvider`, its answer is the
 * answer. Overriding a real organization with a derived one would take a user
 * who belongs to a team and quietly file their work under a private id the team
 * cannot reach - and it would do it to the deployments that had done the most
 * work to set organizations up properly.
 *
 * The wrapper still adds something to such a provider, because the contract it
 * implements is weaker than it looks: `ensureOrganization` is documented to
 * return `undefined` when the user "genuinely stays no-org (bootstrap is
 * best-effort)". A host cannot build on best-effort - the column is not
 * nullable - so this wrapper supplies the synthetic id exactly when the
 * delegate declines to supply one. What was best-effort becomes total, and the
 * provider's own answer is never touched when it has one.
 *
 * A delegate that *throws* is treated as one that declined. That is the safe
 * direction here and it is worth saying why, because this package's other
 * modules choose the opposite: `./capabilities` swallows a provider's throw and
 * answers restrictively, `./identity` lets one propagate rather than resolve a
 * failed authentication to a plausible identity. The rule underneath all three
 * is the same - never let a broken provider produce an answer that grants
 * something - and here the output is a storage partition, not a grant. Falling
 * back yields the narrowest partition there is, one containing a single user.
 * Propagating would turn a transient outage in the provider's organization
 * lookup into a failed request on every organization-scoped surface at once.
 *
 * `isOrganizationAdmin` follows the same shape with one addition. An id in the
 * synthetic namespace is never delegated, in either direction: the user is the
 * administrator of their own personal organization and nobody is an
 * administrator of somebody else's, and both halves are decided here rather than
 * asked of a provider that has never heard of the id. Delegating would let a
 * provider that answers `true` for ids it does not recognize hand out
 * administrator rights over another user's data - a fail-open answer to a
 * question this module is better placed to answer than it is.
 *
 * WHAT "PRESERVES EVERYTHING ELSE" MEANS, AND HOW IT IS IMPLEMENTED
 *
 * A wrapper that dropped a capability would be worse than no wrapper. Dropping
 * `ISSOProvider` breaks sign-in outright; dropping `IAuthInit` means the
 * provider is never initialized and fails later, somewhere else. The obvious
 * implementations both drop things - copying the own properties of a class
 * instance leaves its prototype methods behind, and `Object.create(provider)`
 * keeps them but sends every write to a new object.
 *
 * So the wrapper is a `Proxy`. Everything except the two organization members
 * forwards to the provider, which means the provider does not have to be a class
 * instance, a plain object, or anything in particular, and a method it grows
 * later is reachable through the wrapper the moment it exists.
 *
 * Methods come back **bound to the provider**, not to the proxy, and that
 * detail is load-bearing rather than defensive. `IMastraAuthProvider` exists
 * because provider classes carry `#private` and `protected` members - the
 * interface's own documentation says so - and a `#private` field is keyed on the
 * object it was installed on. Calling such a method with `this` set to a proxy
 * throws `TypeError: Cannot read private member`, from inside the provider,
 * with a stack that points nowhere near this file. Binding to the target means
 * `this` is the real instance and nothing notices it was wrapped.
 *
 * The cost is stated rather than hidden: `wrapped.authenticateToken` is a fresh
 * bound function on each read, so it is `===` to itself only within one
 * expression. Nothing in the contract compares method identity, and the guards
 * ask `typeof`, but a test that pins a method by reference will see it.
 *
 * RE-WRAPPING
 *
 * Wrapping a wrapper re-wraps the original provider rather than stacking a
 * second proxy on the first, so the outermost options win and a provider passed
 * through twice behaves the same as one passed through once.
 *
 * @param provider Any provider. Wrapping does not mutate it, and it keeps
 * working unwrapped.
 * @param options See {@link SyntheticOrganizationOptions}, and read the
 * migration warning there before setting `prefix`.
 * @returns The provider's own type intersected with `IOrganizationsProvider`,
 * so the static type says what the runtime does: every capability that was
 * there is still there, plus one.
 * @throws TypeError when `prefix` is not a non-empty string, or when the
 * provider has pinned one of the two organization members as a non-configurable
 * own property. The second is a frozen or sealed provider, which cannot be
 * wrapped correctly by anything, and failing at wrap time reports it where it
 * can be understood instead of at the first property read.
 */
export function withSyntheticOrganizations<TProvider extends IMastraAuthProvider>(
  provider: TProvider,
  options?: SyntheticOrganizationOptions,
): TProvider & IOrganizationsProvider {
  const prefix = readPrefix(options);
  const target = unwrap(provider);

  for (const member of ORGANIZATION_MEMBERS) {
    if (Reflect.getOwnPropertyDescriptor(target, member)?.configurable === false) {
      throw new TypeError(
        `withSyntheticOrganizations: the provider pins '${member}' as a non-configurable own property, ` +
          'so it cannot be wrapped without changing what that property reports. ' +
          'This is a frozen or sealed provider; wrap it before freezing it.',
      );
    }
  }

  // Captured once. A provider that grows organization methods after being
  // wrapped is not picked up, and that is the intended reading: the capability
  // a wrapper reports must not change under a host that already asked.
  const delegate: IOrganizationsProvider | undefined = isOrganizationsProvider(target) ? target : undefined;

  async function ensureOrganization(userId: string): Promise<string | undefined> {
    if (delegate !== undefined) {
      try {
        const own = asId(await delegate.ensureOrganization(userId));
        if (own !== undefined) return own;
      } catch {
        // A declined bootstrap and a failed one are the same thing to a caller
        // that needs a column value. See the note above on why this direction.
      }
    }
    return syntheticOrganizationId(userId, { prefix });
  }

  async function isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {
    if (isSyntheticOrganizationId(organizationId, { prefix })) {
      // Never delegated, in either direction. `syntheticOrganizationId` returns
      // `undefined` for a blank user id, and `undefined === 'user:...'` is
      // false, so a broken id is not an administrator of anything.
      return organizationId === syntheticOrganizationId(userId, { prefix });
    }
    if (delegate === undefined) return false;
    try {
      // `=== true` rather than a truthiness check: the contract declares a
      // boolean, and a provider returning a non-empty string or a Promise it
      // forgot to await must not read as "yes".
      return (await delegate.isOrganizationAdmin(organizationId, userId)) === true;
    } catch {
      return false;
    }
  }

  const overrides = new Map<string | symbol, unknown>([
    ['ensureOrganization', ensureOrganization],
    ['isOrganizationAdmin', isOrganizationAdmin],
    [WRAPPED_PROVIDER, target],
  ]);

  return new Proxy(target, {
    get(t, key) {
      if (overrides.has(key)) return overrides.get(key);

      const value = Reflect.get(t, key, t);
      if (typeof value !== 'function') return value;

      // A proxy may not report a different value for a non-writable,
      // non-configurable own data property, so such a method is returned
      // unbound rather than throwing.
      const own = Reflect.getOwnPropertyDescriptor(t, key);
      if (own !== undefined && own.writable === false && own.configurable === false) return value;

      return value.bind(t);
    },

    has(t, key) {
      // A proxy may not invent keys on a non-extensible target.
      if (overrides.has(key) && Reflect.isExtensible(t)) return true;
      return Reflect.has(t, key);
    },

    ownKeys(t) {
      const keys = Reflect.ownKeys(t);
      if (!Reflect.isExtensible(t)) return keys;
      return [...keys, ...[...overrides.keys()].filter(key => !keys.includes(key))];
    },

    getOwnPropertyDescriptor(t, key) {
      if (overrides.has(key) && Reflect.isExtensible(t)) {
        return { value: overrides.get(key), writable: false, enumerable: true, configurable: true };
      }
      return Reflect.getOwnPropertyDescriptor(t, key);
    },

    // The wrapper owns these two names. Failing loudly beats accepting a write
    // that `get` would then ignore.
    set(t, key, value) {
      if (overrides.has(key)) return false;
      return Reflect.set(t, key, value, t);
    },

    defineProperty(t, key, descriptor) {
      if (overrides.has(key)) return false;
      return Reflect.defineProperty(t, key, descriptor);
    },

    deleteProperty(t, key) {
      if (overrides.has(key)) return false;
      return Reflect.deleteProperty(t, key);
    },
  }) as TProvider & IOrganizationsProvider;
}
