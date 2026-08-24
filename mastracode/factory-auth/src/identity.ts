/**
 * Identity normalization.
 *
 * K8-K10 fill this in: the `AuthIdentity` shape with no vendor field,
 * `toAuthIdentity(raw)` covering the flat `{ id }`, `{ uid }`, `{ sub }` and
 * `{ session, user }` claim shapes, and the `IIdentityProvider` opt-in a
 * provider can implement to override normalization.
 */
export {};
