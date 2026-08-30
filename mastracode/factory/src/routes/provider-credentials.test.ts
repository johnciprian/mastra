/**
 * Which credential store a request is routed to.
 *
 * There are two, and they are not interchangeable. Tenant mode reads and writes
 * DB rows scoped to (org, user). Local mode uses the file-backed `AuthStorage`
 * (`auth.json`) plus env-var fallback, and it is what an auth-off deployment
 * must use — `factory.ts` deliberately leaves the tenant credential resolver
 * unregistered when there is no provider, so every model call reads the file.
 *
 * Both helpers below used to pick between them by asking whether a tenant
 * resolved. That was a working proxy for "auth is on" only while auth-off had
 * no identity at all. It now always has one (the local single-user tenant), so
 * the proxy inverted: the settings UI began writing credentials into the tenant
 * DB while every model call kept reading `auth.json`, and a provider the user
 * had just logged into reported `oauth-user` in the UI and "Not logged in" at
 * run time.
 *
 * These tests use the REAL `createFactoryRouteAuth` rather than a double, so
 * they exercise the actual substitution. A fake whose `tenant()` returned
 * `undefined` when disabled would pass whether or not the fix exists.
 */
import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';

import { createFactoryRouteAuth } from '../auth.js';
import { listTenantCredentialsForRequest, resolveCredentialContext } from './provider-credentials.js';

/** Run `fn` with a real Hono context, and return what it produced. */
async function withContext<T>(fn: (c: never) => Promise<T>): Promise<T> {
  const app = new Hono();
  let captured: T;
  app.get('/probe', async c => {
    captured = await fn(c as never);
    return c.text('ok');
  });
  await app.request('/probe');
  return captured!;
}

describe('credential store selection with auth disabled', () => {
  const auth = () => createFactoryRouteAuth(undefined);

  it('resolves local mode, not the tenant store', async () => {
    const resolved = await withContext(c => resolveCredentialContext({ c, auth: auth(), credentials: undefined }));
    expect(resolved).toEqual({ mode: 'local' });
  });

  it('reports no tenant credentials, so callers fall back to AuthStorage', async () => {
    // `undefined` is the signal for "local mode — read auth.json"; an empty
    // array would mean "tenant mode, and this caller has no rows", which sends
    // the settings UI to the wrong store.
    const records = await withContext(c =>
      listTenantCredentialsForRequest({ c, auth: auth(), credentials: undefined }),
    );
    expect(records).toBeUndefined();
  });
});

describe('credential store selection with auth enabled', () => {
  // A provider that authenticates nobody: the caller is anonymous, which must
  // still be refused rather than silently handed the local store.
  const provider = { name: 'p', authenticateToken: async () => null, authorizeUser: async () => true } as never;

  it('refuses an anonymous caller instead of falling back to local mode', async () => {
    const resolved = await withContext(c =>
      resolveCredentialContext({ c, auth: createFactoryRouteAuth(provider), credentials: undefined }),
    );
    expect(resolved).toHaveProperty('response');
  });

  it('reports an empty tenant list rather than local mode', async () => {
    const records = await withContext(c =>
      listTenantCredentialsForRequest({ c, auth: createFactoryRouteAuth(provider), credentials: undefined }),
    );
    expect(records).toEqual([]);
  });
});
