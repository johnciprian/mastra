---
'@mastra/auth-okta': patch
---

Typed the `getUserId` callback, so reading a field off the user no longer needs a cast.

`MastraRBACOktaOptions.getUserId` took `(user: unknown)`, which meant every caller had to cast first, including the example this package ships in its own JSDoc. `MastraRBACOkta` and its options now take a user type parameter that defaults to `OktaUser`.

**Before**

```typescript
new MastraRBACOkta({
  getUserId: (user: any) => user.metadata?.oktaUserId,
  roleMapping: { Admin: ['*'] },
});
```

**After**

```typescript
// Default: the parameter is an OktaUser.
new MastraRBACOkta({
  getUserId: user => user.oktaId,
  roleMapping: { Admin: ['*'] },
});

// Cross-provider: name the shape the other auth provider produces.
interface Auth0User extends EEUser {
  metadata?: { oktaUserId?: string };
}

new MastraRBACOkta<Auth0User>({
  getUserId: user => user.metadata?.oktaUserId ?? user.email,
  roleMapping: { Admin: ['*'] },
});
```

The type parameter defaults to `OktaUser`, so existing code that passes no type argument keeps working.
