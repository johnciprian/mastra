---
'@mastra/factory-auth': major
---

**Conformance now exercises `IUserProvider` and `isOrganizationAdmin`.** Three new checks close the last two holes in the suite: one of the seven capability guards had no check at all, and half of `IOrganizationsProvider` was never called.

Until now `getCurrentUser` and `getUser` appeared nowhere in the suite, so a provider's user directory was neither passed nor skipped — it was simply absent from a run. `isOrganizationAdmin` appeared exactly once, inside a failure message, and was never invoked.

**This is a breaking change.** A new check can turn CI red in a repository this package does not own. It is landing now because the package has never published: there are no consumers to break yet, and the same checks would be a genuine breaking change the day one exists.

**`users/current-user`** — sends one request carrying every credential the suite holds and compares what `getCurrentUser` resolves against the id `authenticateToken` resolves for the same credential. Hosts use both paths: enforcement goes through `authenticateToken`, and the profile on screen comes out of `getCurrentUser`. When they disagree, somebody is shown one identity while their work is stored under another, and nothing reports an error. It then asks again with a request carrying nothing at all, which must not resolve a user.

**`users/get-user`** — fails a provider that satisfies `isUserProvider` and has no `getUser`. That guard tests `getCurrentUser` and stops, while `IUserProvider` requires both, so a host that writes `if (isUserProvider(auth)) auth.getUser(id)` compiles against a narrowed type and throws on a request:

```ts
// Passes isUserProvider today. `auth.getUser(id)` typechecks in the host and is undefined at run time.
class MyProvider extends MastraAuthProvider {
  async getCurrentUser(request: Request) {
    return this.resolve(request);
  }
}

// Conforming: both required members, and `null` is a legitimate answer for either.
class MyProvider extends MastraAuthProvider implements IUserProvider {
  async getCurrentUser(request: Request) {
    return this.resolve(request);
  }

  async getUser(userId: string) {
    return this.directory.find(userId) ?? null;
  }
}
```

Neither user check demands a non-`null` answer. `null` is what the interface documents for a user who is not found, and a directory that needs a live vendor cannot answer offline. What is checked is that an answer you do give names the person who was asked about.

**`organizations/is-admin`** — the one answer in this contract whose wrong value hands somebody rights over another user's data. It asks about your own organization, where the requirement is only a literal boolean and no throw: answering `false` is fine, and a provider that cannot reach its role store yet is right to say no. It then asks about an organization id the suite invented, where `true` is a failure. Organization ids arrive from requests, so a provider that answers `true` for ids it does not recognize turns "guess an organization id" into an administrator role in it.

```ts
async isOrganizationAdmin(organizationId: string, userId: string): Promise<boolean> {
  const membership = await this.membership(organizationId, userId);
  if (membership === undefined) return false; // Refuse by default, grant on evidence.
  return membership.role === 'admin' || membership.role === 'owner';
}
```

`withSyntheticOrganizations` passes this check by construction — it answers for ids in its own namespace itself, in both directions, and never delegates them.

**Added `withUser` to `@mastra/factory-auth/testing`**, so a provider author can build an `IUserProvider` fake. It installs both required members rather than only the one the guard reads, for the same reason `withSession` installs all seven.

**Changed what the organizations fake answers by default.** `withOrganizations(...).isOrganizationAdmin` used to answer `true` for every id. It now answers `true` only for the organization it bootstrapped for that user. Pass `admin: true` to get the old behaviour, which is a provider that hands out administrator rights over organizations it has never heard of.

None of the eleven providers in this repository goes red on any of the three.
