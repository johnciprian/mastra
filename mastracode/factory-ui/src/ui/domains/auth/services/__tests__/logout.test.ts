/**
 * @vitest-environment jsdom
 *
 * A DOM, in the otherwise node-environment unit project, because what is under
 * test is a form element. The `msw:factory-ui` project is the other place with
 * a DOM, but it takes only `*.msw.test.tsx` and there is no network here to
 * mock — the whole point is that the browser performs the request, not us.
 */

/**
 * P31: sign-out is a POST, so the SPA has to submit a form to perform it.
 *
 * It used to be `window.location.assign('/auth/logout')`, which can only issue
 * a GET — and a URL that ends a session by being fetched is a URL any other
 * site can put in an `<img>`. The server no longer answers a GET there at all,
 * so this is not a style preference: `location.assign` would now navigate the
 * person to a 404 with their session intact.
 *
 * What is worth pinning is the shape of the request that replaces it (POST, at
 * the right URL) and that the form does not accumulate in the document, since
 * `submit()` starts a navigation rather than finishing one and a caller torn
 * down first would otherwise leave a node behind.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { logoutUrl, submitLogout } from '../auth';

const BASE_URL = 'https://factory.acme.com';

interface Submission {
  method: string;
  action: string;
  /** Read inside the spy: `submitLogout` detaches the form as soon as it returns. */
  connected: boolean;
}

function spyOnSubmit(): Submission[] {
  const submissions: Submission[] = [];
  vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(function (this: HTMLFormElement) {
    submissions.push({ method: this.method, action: this.action, connected: this.isConnected });
  });
  return submissions;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('submitLogout', () => {
  it('posts to the logout route', () => {
    const submissions = spyOnSubmit();

    submitLogout(BASE_URL);

    expect(submissions).toEqual([{ method: 'post', action: logoutUrl(BASE_URL), connected: true }]);
  });

  it('submits from inside the document, so the browser sends an Origin', () => {
    // A detached form does not submit at all. The server's origin check is the
    // reason this matters beyond that: a request with neither Origin nor
    // Sec-Fetch-Site is treated as a non-browser client, and the SPA's own
    // sign-out must not look like one.
    const submissions = spyOnSubmit();

    submitLogout(BASE_URL);

    expect(submissions[0]!.connected).toBe(true);
  });

  it('leaves no form behind', () => {
    const submissions = spyOnSubmit();

    submitLogout(BASE_URL);
    submitLogout(BASE_URL);

    expect(document.querySelectorAll('form')).toHaveLength(0);
    expect(submissions).toHaveLength(2);
  });

  it('leaves no form behind when submit throws', () => {
    // jsdom aside, a real browser can refuse a submission (a beforeunload veto,
    // a detached window). The node still has to go.
    vi.spyOn(HTMLFormElement.prototype, 'submit').mockImplementation(() => {
      throw new Error('navigation blocked');
    });

    expect(() => submitLogout(BASE_URL)).toThrow('navigation blocked');
    expect(document.querySelectorAll('form')).toHaveLength(0);
  });
});
