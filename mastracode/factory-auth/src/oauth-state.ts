/**
 * The OAuth `state` parameter codec.
 *
 * K11 fills this in: `encodeState(returnTo)`, `decodeState(raw)` and
 * `parseStateId(raw)` over a documented wire format, round-tripping a `returnTo`
 * that itself contains the delimiter.
 *
 * Named `./oauth-state`, not `./state`: `FactoryAuthState` in factory-ui already
 * means "am I signed in", and `mastracode/factory/src/state-signing.ts` owns a
 * different signed `state` for integration installs. This is the OAuth spec
 * parameter: a nonce plus where to send the user after login.
 */
export {};
