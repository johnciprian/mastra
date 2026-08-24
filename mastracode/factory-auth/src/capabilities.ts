/**
 * The capability descriptor.
 *
 * K13-K14 fill this in: `AuthSignInKind`, `AuthDescriptor`, and
 * `toAuthDescriptor(provider)`, derived purely from the Apache-2.0 structural
 * guards in `./contract`.
 *
 * Scope boundary, stated so the clean-room record is in the file rather than in
 * a review comment: no role-based access control, no fine-grained
 * authorization, no licence gate, no telemetry. Those are enterprise concerns
 * and they stay in the enterprise packages.
 *
 * This module answers *which* capabilities a provider has. The capability
 * interfaces themselves are in `./contract`.
 */
export {};
