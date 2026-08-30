import { describe, expect, it } from 'vitest';

import { fakeRouteAuth } from '../../routes/test-utils.js';
import { getGithubFeatureDiagnostics, isGithubFeatureEnabled } from './config.js';
import { GithubIntegration } from './integration.js';

describe('getGithubFeatureDiagnostics', () => {
  it('does not require integration route storage to be initialized', () => {
    const github = new GithubIntegration({
      appId: '123',
      privateKey: 'test-key',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      slug: 'test-app',
    });

    expect(
      getGithubFeatureDiagnostics({
        github,
        auth: fakeRouteAuth(),
        appDbConfigured: false,
      }),
    ).toMatchObject({
      githubAppConfigured: true,
      appDbConfigured: false,
    });
  });
});

/**
 * Whether the GitHub project feature turns on.
 *
 * It used to require `auth.enabled()`, which was right while an auth-off
 * deployment had no identity at all: installations are stored per organization,
 * and there was no organization to store them under. That is no longer true —
 * `createFactoryRouteAuth` substitutes the local single-user tenant when no
 * provider is configured, so an auth-off Factory has a stable `local` org that
 * owns its installations across restarts.
 *
 * What the gate must still refuse is a Factory with no GitHub App: that one is
 * about configuration this deployment genuinely does not have.
 */
describe('isGithubFeatureEnabled', () => {
  const github = () =>
    new GithubIntegration({
      appId: '123',
      privateKey: 'test-key',
      clientId: 'client-id',
      clientSecret: 'client-secret',
      slug: 'test-app',
    });

  it('is on for a configured App when auth is enabled', () => {
    expect(isGithubFeatureEnabled({ github: github(), auth: fakeRouteAuth({ enabled: true }) })).toBe(true);
  });

  it('is on for a configured App when auth is disabled, under the local tenant', () => {
    expect(isGithubFeatureEnabled({ github: github(), auth: fakeRouteAuth({ enabled: false }) })).toBe(true);
  });

  it('stays off when no GitHub App is configured, whatever auth is doing', () => {
    expect(isGithubFeatureEnabled({ github: undefined, auth: fakeRouteAuth({ enabled: true }) })).toBe(false);
    expect(isGithubFeatureEnabled({ github: undefined, auth: fakeRouteAuth({ enabled: false }) })).toBe(false);
  });
});
