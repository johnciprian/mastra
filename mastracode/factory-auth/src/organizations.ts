/**
 * Organizations and tenancy.
 *
 * K15-K16 fill this in: `withSyntheticOrganizations(provider)`, a wrapper that
 * gives any provider a deterministic organization id, and the resolver that
 * turns an `AuthIdentity` into the organization the host stores data under.
 *
 * A wrapper, not a `CompositeAuth` member: `CompositeAuth` implements only
 * ISSO/ISession/IUser, so composing cannot supply organizations.
 */
export {};
