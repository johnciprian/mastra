import admin from 'firebase-admin';
import { getFirestore } from 'firebase-admin/firestore';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MastraAuthFirebase } from './index';
import type { FirebaseUser } from './index';

// Mock Firebase Admin
vi.mock('firebase-admin', () => ({
  default: {
    apps: [],
    initializeApp: vi.fn(),
    auth: vi.fn(() => ({
      verifyIdToken: vi.fn(),
    })),
    credential: {
      cert: vi.fn(() => 'mock-credential'),
      applicationDefault: vi.fn(() => 'mock-default-credential'),
    },
  },
}));

// Mock Firestore
vi.mock('firebase-admin/firestore', () => ({
  getFirestore: vi.fn(() => ({
    doc: vi.fn(() => ({
      get: vi.fn(),
    })),
  })),
}));

describe('MastraAuthFirebase', () => {
  const mockServiceAccount = 'mock-service-account';
  const mockDatabaseId = 'mock-database-id';
  const mockToken = 'mock-token';
  const mockUserId = 'mock-user-id';

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('initialization', () => {
    it('should initialize with provided options', () => {
      const auth = new MastraAuthFirebase({
        serviceAccount: mockServiceAccount,
        databaseId: mockDatabaseId,
      });

      expect(auth).toBeInstanceOf(MastraAuthFirebase);
      expect(admin.initializeApp).toHaveBeenCalledWith({
        credential: 'mock-credential',
      });
      expect(admin.credential.cert).toHaveBeenCalledWith(mockServiceAccount);
    });

    it('should initialize with environment variables', () => {
      process.env.FIREBASE_SERVICE_ACCOUNT = mockServiceAccount;
      process.env.FIRESTORE_DATABASE_ID = mockDatabaseId;

      const auth = new MastraAuthFirebase();

      expect(auth).toBeInstanceOf(MastraAuthFirebase);
      expect(admin.initializeApp).toHaveBeenCalledWith({
        credential: 'mock-credential',
      });
      expect(admin.credential.cert).toHaveBeenCalledWith(mockServiceAccount);

      delete process.env.FIREBASE_SERVICE_ACCOUNT;
      delete process.env.FIRESTORE_DATABASE_ID;
    });

    it('should not initialize an app when a verifier is supplied', () => {
      const auth = new MastraAuthFirebase({ verifyIdToken: async () => ({ uid: mockUserId }) as FirebaseUser });

      expect(auth).toBeInstanceOf(MastraAuthFirebase);
      // A supplied verifier replaces the Admin SDK, so the provider needs no
      // credential at all. This is what lets the conformance suite construct it.
      expect(admin.initializeApp).not.toHaveBeenCalled();
    });
  });

  describe('authenticateToken', () => {
    it('should verify and return decoded token', async () => {
      const mockDecodedToken = { uid: mockUserId };
      const mockVerifyIdToken = vi.fn().mockResolvedValue(mockDecodedToken);

      (admin.auth as any).mockReturnValue({
        verifyIdToken: mockVerifyIdToken,
      });

      const auth = new MastraAuthFirebase();
      const result = await auth.authenticateToken(mockToken);

      expect(mockVerifyIdToken).toHaveBeenCalledWith(mockToken);
      expect(result).toEqual(mockDecodedToken);
    });

    it('should resolve null rather than reject when verification fails', async () => {
      const mockVerifyIdToken = vi.fn().mockRejectedValue(new Error('Invalid token'));

      (admin.auth as any).mockReturnValue({
        verifyIdToken: mockVerifyIdToken,
      });

      const auth = new MastraAuthFirebase();

      // No `.catch()`. An unverifiable token is the ordinary state of a public
      // endpoint, and the contract declares `Promise<TUser | null>` — a host
      // reads a rejection as a bug and logs a stack trace per anonymous request.
      await expect(auth.authenticateToken(mockToken)).resolves.toBeNull();
      expect(mockVerifyIdToken).toHaveBeenCalledWith(mockToken);
    });

    it('should return null for an empty token without verifying', async () => {
      const mockVerifyIdToken = vi.fn();

      (admin.auth as any).mockReturnValue({
        verifyIdToken: mockVerifyIdToken,
      });

      const auth = new MastraAuthFirebase();

      await expect(auth.authenticateToken('')).resolves.toBeNull();
      expect(mockVerifyIdToken).not.toHaveBeenCalled();
    });
  });

  describe('authorizeUser', () => {
    const user = { uid: mockUserId } as FirebaseUser;

    it('should authorize any authenticated user by default', async () => {
      const auth = new MastraAuthFirebase();

      expect(await auth.authorizeUser(user)).toBe(true);
      // The default must not reach for infrastructure the contract never
      // mentions. Until 1.2 it did, and every deployment without a
      // `/user_access` collection verified a token and then 403d every core
      // /api/* call.
      expect(getFirestore).not.toHaveBeenCalled();
    });

    it('should refuse a payload that names nobody', async () => {
      const auth = new MastraAuthFirebase();

      expect(await auth.authorizeUser({ uid: '' } as FirebaseUser)).toBe(false);
      expect(await auth.authorizeUser(undefined as unknown as FirebaseUser)).toBe(false);
    });

    describe('with requireUserAccessDocument', () => {
      it('should return true when user has access', async () => {
        const mockUserAccessData = { someData: 'value' };
        const mockGet = vi.fn().mockResolvedValue({ data: () => mockUserAccessData });
        const mockDoc = vi.fn().mockReturnValue({ get: mockGet });

        (getFirestore as any).mockReturnValue({ doc: mockDoc });

        const auth = new MastraAuthFirebase({ requireUserAccessDocument: true });
        const result = await auth.authorizeUser(user);

        expect(mockDoc).toHaveBeenCalledWith(`/user_access/${mockUserId}`);
        expect(result).toBe(true);
      });

      it('should return false when user has no access', async () => {
        const mockGet = vi.fn().mockResolvedValue({ data: () => null });
        const mockDoc = vi.fn().mockReturnValue({ get: mockGet });

        (getFirestore as any).mockReturnValue({ doc: mockDoc });

        const auth = new MastraAuthFirebase({ requireUserAccessDocument: true });
        const result = await auth.authorizeUser(user);

        expect(mockDoc).toHaveBeenCalledWith(`/user_access/${mockUserId}`);
        expect(result).toBe(false);
      });

      it('should read the configured database', async () => {
        const mockGet = vi.fn().mockResolvedValue({ data: () => ({}) });
        const mockDoc = vi.fn().mockReturnValue({ get: mockGet });

        (getFirestore as any).mockReturnValue({ doc: mockDoc });

        const auth = new MastraAuthFirebase({ requireUserAccessDocument: true, databaseId: mockDatabaseId });
        await auth.authorizeUser(user);

        expect(getFirestore).toHaveBeenCalledWith(mockDatabaseId);
      });

      it('should return false rather than throw when the lookup blows up', async () => {
        (getFirestore as any).mockImplementation(() => {
          throw new Error('permission denied');
        });

        const auth = new MastraAuthFirebase({ requireUserAccessDocument: true });

        await expect(auth.authorizeUser(user)).resolves.toBe(false);
      });
    });
  });

  describe('organizations', () => {
    it('should derive a stable personal organization id', async () => {
      const auth = new MastraAuthFirebase();

      expect(await auth.ensureOrganization(mockUserId)).toBe(`user:${mockUserId}`);
      expect(await auth.ensureOrganization(mockUserId)).toBe(`user:${mockUserId}`);
    });

    it('should resolve no organization for a blank user id', async () => {
      const auth = new MastraAuthFirebase();

      expect(await auth.ensureOrganization('  ')).toBeUndefined();
    });
  });

  it('can be overridden with custom authorization logic', async () => {
    const firebase = new MastraAuthFirebase({
      async authorizeUser(user: any): Promise<boolean> {
        // Custom authorization logic that checks for specific permissions
        return user?.permissions?.includes('admin') ?? false;
      },
    });

    // Test with admin user
    const adminUser = { sub: 'user123', permissions: ['admin'] } as unknown as FirebaseUser;
    expect(await firebase.authorizeUser(adminUser)).toBe(true);

    // Test with non-admin user
    const regularUser = { sub: 'user456', permissions: ['read'] } as unknown as FirebaseUser;
    expect(await firebase.authorizeUser(regularUser)).toBe(false);

    // Test with user without permissions
    const noPermissionsUser = { sub: 'user789' } as unknown as FirebaseUser;
    expect(await firebase.authorizeUser(noPermissionsUser)).toBe(false);
  });
});
