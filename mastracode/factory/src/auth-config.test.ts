import type { IMastraAuthProvider } from '@mastra/core/server';
import { describe, expect, it } from 'vitest';
import { AUTH_DISABLED, createMastraPlatformAuth, isAuthDisabled, resolveFactoryPublicUrl } from './auth-config.js';

// Both `MASTRA_COOKIE_DOMAIN` and `MASTRA_SHARED_API_URL` feed Studio's
// cookie-domain precedence (explicit > shared-API hostname > publicUrl
// fallback), so a runner with either set would silently flip the derived
// domain. Clear both around each derivation test and restore after.
async function withCleanCookieEnv<T>(fn: () => Promise<T>): Promise<T> {
  const prevCookie = process.env.MASTRA_COOKIE_DOMAIN;
  const prevShared = process.env.MASTRA_SHARED_API_URL;
  delete process.env.MASTRA_COOKIE_DOMAIN;
  delete process.env.MASTRA_SHARED_API_URL;
  try {
    return await fn();
  } finally {
    if (prevCookie === undefined) delete process.env.MASTRA_COOKIE_DOMAIN;
    else process.env.MASTRA_COOKIE_DOMAIN = prevCookie;
    if (prevShared === undefined) delete process.env.MASTRA_SHARED_API_URL;
    else process.env.MASTRA_SHARED_API_URL = prevShared;
  }
}

/**
 * The cookie domain is not readable off the provider — it only shows up in the
 * `Set-Cookie` Studio mints for a session, so seed one and read the header.
 * `@mastra/auth-studio` has no dependencies and does no I/O at construction,
 * so these run against the real class rather than a mock.
 */
function seededSetCookie(provider: IMastraAuthProvider): string | undefined {
  const studio = provider as IMastraAuthProvider & {
    getSessionHeaders(session: { id: string; userId: string }): Record<string, string>;
  };
  return studio.getSessionHeaders({ id: 'test-token', userId: 'u_1' })['Set-Cookie'];
}

describe('AUTH_DISABLED', () => {
  it('is recognized by isAuthDisabled and cannot be mutated into looking enabled', () => {
    expect(isAuthDisabled(AUTH_DISABLED)).toBe(true);
    // Frozen: a stray assignment must not turn "auth off" into "auth on" (or
    // the reverse) for every other holder of the shared singleton.
    expect(Object.isFrozen(AUTH_DISABLED)).toBe(true);
  });

  it('does not classify a provider as disabled', () => {
    const provider = {
      authenticateToken: async () => null,
      authorizeUser: () => false,
    } as IMastraAuthProvider;
    expect(isAuthDisabled(provider)).toBe(false);
  });
});

describe('resolveFactoryPublicUrl', () => {
  it('defaults to the local Factory origin and strips trailing slashes', () => {
    expect(resolveFactoryPublicUrl(undefined)).toBe('http://localhost:4111');
    expect(resolveFactoryPublicUrl('https://app.example.com///')).toBe('https://app.example.com');
  });

  it('keeps an empty string rather than substituting the default', () => {
    // `??`, not `||` — this mirrors what `prepare()` has always done, and an
    // empty `publicUrl` is a caller mistake that should stay visible instead of
    // being quietly rewritten into localhost.
    expect(resolveFactoryPublicUrl('')).toBe('');
  });
});

describe('createMastraPlatformAuth cookie domain', () => {
  it('derives the cookie domain from publicUrl for subdomain deploys', async () => {
    // A `<sub>.mastra.cloud` deploy should mint cookies with
    // `Domain=.mastra.cloud` so the browser sends them back to sibling
    // subdomains — no `MASTRA_COOKIE_DOMAIN` env wiring required.
    await withCleanCookieEnv(async () => {
      const setCookie = seededSetCookie(createMastraPlatformAuth({ publicUrl: 'https://studio-abc.mastra.cloud' }));
      expect(setCookie).toBeDefined();
      expect(setCookie).toContain('Domain=.mastra.cloud');
    });
  });

  it('leaves the cookie host-only on localhost', async () => {
    // `publicUrl` on localhost has no parent to peel — the cookie must stay
    // host-only or the browser will silently reject it.
    await withCleanCookieEnv(async () => {
      const setCookie = seededSetCookie(createMastraPlatformAuth({ publicUrl: 'http://localhost:4111' }));
      expect(setCookie).toBeDefined();
      expect(setCookie).not.toContain('Domain=');
    });
  });

  it('leaves the cookie host-only for hosts outside the platform allowlist', async () => {
    // Public-suffix trap: a naive last-two-labels heuristic would emit
    // `Domain=.co.uk` for `foo.example.co.uk`, which every major browser
    // rejects. Custom-domain deploys must fall through to host-only cookies.
    await withCleanCookieEnv(async () => {
      const setCookie = seededSetCookie(createMastraPlatformAuth({ publicUrl: 'https://studio.example.co.uk' }));
      expect(setCookie).toBeDefined();
      expect(setCookie).not.toContain('Domain=');
    });
  });

  it('leaves the cookie host-only for numeric-labelled hostnames', async () => {
    // A leading-digit label (e.g. `3scale.example.com`) is still a valid DNS
    // host, not an IP. The derivation must not misclassify it as IPv4.
    await withCleanCookieEnv(async () => {
      const setCookie = seededSetCookie(createMastraPlatformAuth({ publicUrl: 'https://3scale.example.com' }));
      expect(setCookie).toBeDefined();
      // Not on the platform allowlist → host-only.
      expect(setCookie).not.toContain('Domain=');
    });
  });

  it('leaves the cookie host-only for literal IPv4 hosts', async () => {
    // IP-literal deploys can't share cookies across an arbitrary parent, and
    // browsers reject Domain= attributes on IP hosts entirely.
    await withCleanCookieEnv(async () => {
      const setCookie = seededSetCookie(createMastraPlatformAuth({ publicUrl: 'http://10.0.0.1:4111' }));
      expect(setCookie).toBeDefined();
      expect(setCookie).not.toContain('Domain=');
    });
  });

  it('falls back to the default publicUrl when none is passed', async () => {
    // Omitting `publicUrl` lands on `http://localhost:4111`, so host-only —
    // the same answer the factory reached when `auth` was omitted in local dev.
    await withCleanCookieEnv(async () => {
      const setCookie = seededSetCookie(createMastraPlatformAuth());
      expect(setCookie).toBeDefined();
      expect(setCookie).not.toContain('Domain=');
    });
  });
});
