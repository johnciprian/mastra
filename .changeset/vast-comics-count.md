---
'@mastra/auth-google': patch
---

Typed the `getUserKey` callback, so reading a field off the user no longer needs a cast.

`MastraRBACGoogleOptions.getUserKey` took `(user: unknown)`. `MastraRBACGoogle` and its options now take a user type parameter that defaults to `GoogleUser`.

**Before**

```typescript
new MastraRBACGoogle({
  getUserKey: value => (value as GoogleUser).googleId,
  roleMapping: { engineering: ['workflows:*'] },
});
```

**After**

```typescript
new MastraRBACGoogle({
  getUserKey: user => user.googleId,
  roleMapping: { engineering: ['workflows:*'] },
});
```

The type parameter defaults to `GoogleUser`, so existing code that passes no type argument keeps working.
