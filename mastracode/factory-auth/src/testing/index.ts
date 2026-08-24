/**
 * Test doubles for hosts and packages that *consume* a provider.
 *
 * K17 fills this in: `fakeProvider()` and the capability mixins.
 *
 * Hard rule: nothing under `src/testing/` may import vitest. The fakes are plain
 * objects, so they work from any runner - the Factory's suites, the SPA's MSW
 * fixtures, or a consumer's own tests. Only `./conformance` imports vitest.
 *
 * Writing a provider? You want `./conformance` instead.
 */
export {};
