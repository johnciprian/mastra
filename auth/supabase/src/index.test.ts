import { createClient } from '@supabase/supabase-js';
import type { User } from '@supabase/supabase-js';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MastraAuthSupabase } from './index';

// Mock Supabase client
vi.mock('@supabase/supabase-js', () => ({
  createClient: vi.fn(),
}));

describe('MastraAuthSupabase', () => {
  const mockSupabaseUrl = 'https://test.supabase.co';
  const mockSupabaseAnonKey = 'test-anon-key';
  const mockUser: User = {
    id: 'test-user-id',
    email: 'test@example.com',
    created_at: '',
    aud: '',
    role: '',
    app_metadata: {},
    user_metadata: {},
  };

  let authProvider: MastraAuthSupabase;
  let mockSupabaseClient: any;

  beforeEach(() => {
    // Reset environment variables
    vi.resetModules();
    process.env.SUPABASE_URL = mockSupabaseUrl;
    process.env.SUPABASE_ANON_KEY = mockSupabaseAnonKey;

    // Setup mock Supabase client
    mockSupabaseClient = {
      auth: {
        getUser: vi.fn(),
      },
      from: vi.fn().mockReturnThis(),
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      single: vi.fn(),
    };

    (createClient as any).mockReturnValue(mockSupabaseClient);
    authProvider = new MastraAuthSupabase();
  });

  describe('constructor', () => {
    it('should create instance with environment variables', () => {
      expect(createClient).toHaveBeenCalledWith(mockSupabaseUrl, mockSupabaseAnonKey);
    });

    it('should create instance with provided options', () => {
      const customUrl = 'https://custom.supabase.co';
      const customKey = 'custom-key';
      new MastraAuthSupabase({ url: customUrl, anonKey: customKey });
      expect(createClient).toHaveBeenCalledWith(customUrl, customKey);
    });

    it('should throw error when required credentials are missing', () => {
      delete process.env.SUPABASE_URL;
      delete process.env.SUPABASE_ANON_KEY;

      expect(() => new MastraAuthSupabase()).toThrow('Supabase URL and anon key are required');
    });

    it('should accept an injected client and build none of its own', () => {
      delete process.env.SUPABASE_URL;
      delete process.env.SUPABASE_ANON_KEY;
      (createClient as any).mockClear();

      const injected = { auth: { getUser: vi.fn() } } as any;
      expect(() => new MastraAuthSupabase({ client: injected })).not.toThrow();
      expect(createClient).not.toHaveBeenCalled();
    });
  });

  describe('authenticateToken', () => {
    it('should return user when token is valid', async () => {
      const mockToken = 'valid-token';
      mockSupabaseClient.auth.getUser.mockResolvedValue({
        data: { user: mockUser },
        error: null,
      });

      const result = await authProvider.authenticateToken(mockToken);
      expect(result).toEqual(mockUser);
      expect(mockSupabaseClient.auth.getUser).toHaveBeenCalledWith(mockToken);
    });

    it('should return null when token is invalid', async () => {
      const mockToken = 'invalid-token';
      mockSupabaseClient.auth.getUser.mockResolvedValue({
        data: { user: null },
        error: new Error('Invalid token'),
      });

      const result = await authProvider.authenticateToken(mockToken);
      expect(result).toBeNull();
    });

    it('should return null for an empty token without asking Supabase', async () => {
      const result = await authProvider.authenticateToken('');

      expect(result).toBeNull();
      // An empty token is the host saying "no bearer token on this request".
      // This provider reads no cookie, so there is nothing to look up.
      expect(mockSupabaseClient.auth.getUser).not.toHaveBeenCalled();
    });
  });

  describe('authorizeUser', () => {
    it('should authorize any authenticated user by default', async () => {
      const result = await authProvider.authorizeUser(mockUser);

      expect(result).toBe(true);
      // The default must not reach for infrastructure the contract never
      // mentions. Until 1.2 it did, and every deployment without a `users` table
      // authenticated a user and then 403d every core /api/* call.
      expect(mockSupabaseClient.from).not.toHaveBeenCalled();
    });

    it('should refuse a payload that names nobody', async () => {
      expect(await authProvider.authorizeUser({ ...mockUser, id: '' })).toBe(false);
      expect(await authProvider.authorizeUser(undefined as unknown as User)).toBe(false);
    });

    describe('with requireAdminRow', () => {
      let adminGated: MastraAuthSupabase;

      beforeEach(() => {
        adminGated = new MastraAuthSupabase({ requireAdminRow: true });
      });

      it('should return true for admin users', async () => {
        mockSupabaseClient.single.mockResolvedValue({
          data: { isAdmin: true },
          error: null,
        });

        const result = await adminGated.authorizeUser(mockUser);
        expect(result).toBe(true);
        expect(mockSupabaseClient.from).toHaveBeenCalledWith('users');
        expect(mockSupabaseClient.select).toHaveBeenCalledWith('isAdmin');
        expect(mockSupabaseClient.eq).toHaveBeenCalledWith('id', mockUser.id);
      });

      it('should return false for non-admin users', async () => {
        mockSupabaseClient.single.mockResolvedValue({
          data: { isAdmin: false },
          error: null,
        });

        const result = await adminGated.authorizeUser(mockUser);
        expect(result).toBe(false);
      });

      it('should return false when user data cannot be retrieved', async () => {
        mockSupabaseClient.single.mockResolvedValue({
          data: null,
          error: new Error('Database error'),
        });

        const result = await adminGated.authorizeUser(mockUser);
        expect(result).toBe(false);
      });

      it('should return false rather than throw when the lookup blows up', async () => {
        mockSupabaseClient.single.mockRejectedValue(new Error('connection refused'));

        await expect(adminGated.authorizeUser(mockUser)).resolves.toBe(false);
      });
    });
  });

  describe('organizations', () => {
    it('should derive a stable personal organization id', async () => {
      expect(await authProvider.ensureOrganization(mockUser.id)).toBe(`user:${mockUser.id}`);
      expect(await authProvider.ensureOrganization(mockUser.id)).toBe(`user:${mockUser.id}`);
    });

    it('should resolve no organization for a blank user id', async () => {
      expect(await authProvider.ensureOrganization('  ')).toBeUndefined();
    });
  });

  it('can be overridden with custom authorization logic', async () => {
    // class CustomSupabase extends MastraAuthSupabase {

    // }

    const supabase = new MastraAuthSupabase({
      async authorizeUser(user: any): Promise<boolean> {
        // Custom authorization logic that checks for specific permissions
        return user?.permissions?.includes('admin') ?? false;
      },
    });

    // Test with admin user
    const adminUser = { sub: 'user123', permissions: ['admin'] } as unknown as User;
    expect(await supabase.authorizeUser(adminUser)).toBe(true);

    // Test with non-admin user
    const regularUser = { sub: 'user456', permissions: ['read'] } as unknown as User;
    expect(await supabase.authorizeUser(regularUser)).toBe(false);

    // Test with user without permissions
    const noPermissionsUser = { sub: 'user789' } as unknown as User;
    expect(await supabase.authorizeUser(noPermissionsUser)).toBe(false);
  });
});
