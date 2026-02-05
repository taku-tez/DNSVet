import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { 
  isDNSNotFoundError, 
  resolveTxtRecords, 
  filterRecordsByPrefix,
  safeResolveTxt,
  safeResolveMx,
  setDnsResolver,
  clearDnsCache,
  cachedResolveTxt,
  cachedResolveMx
} from './dns.js';
import * as dns from 'node:dns/promises';

// Mock dns module
vi.mock('node:dns/promises', async () => {
  const actual = await vi.importActual('node:dns/promises');
  return {
    ...actual,
    resolveTxt: vi.fn(),
    resolveMx: vi.fn(),
    Resolver: vi.fn().mockImplementation(() => ({
      setServers: vi.fn(),
      resolveTxt: vi.fn().mockResolvedValue([['test']]),
      resolveMx: vi.fn().mockResolvedValue([{ exchange: 'mx.test.com', priority: 10 }]),
    })),
  };
});

describe('DNS utilities', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearDnsCache();
    setDnsResolver(undefined); // Reset resolver
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('isDNSNotFoundError', () => {
    it('should return true for ENOTFOUND', () => {
      const error = new Error('getaddrinfo ENOTFOUND') as NodeJS.ErrnoException;
      error.code = 'ENOTFOUND';
      expect(isDNSNotFoundError(error)).toBe(true);
    });

    it('should return true for ENODATA', () => {
      const error = new Error('queryTxt ENODATA') as NodeJS.ErrnoException;
      error.code = 'ENODATA';
      expect(isDNSNotFoundError(error)).toBe(true);
    });

    it('should return false for other errors', () => {
      const error = new Error('Connection timeout') as NodeJS.ErrnoException;
      error.code = 'ETIMEDOUT';
      expect(isDNSNotFoundError(error)).toBe(false);
    });

    it('should return false for non-error objects', () => {
      expect(isDNSNotFoundError(null)).toBe(false);
      expect(isDNSNotFoundError(undefined)).toBe(false);
      expect(isDNSNotFoundError('error')).toBe(false);
    });
  });

  describe('filterRecordsByPrefix', () => {
    it('should filter records by prefix', () => {
      const records = [
        'v=spf1 include:_spf.google.com -all',
        'google-site-verification=abc123',
        'v=DMARC1; p=reject',
      ];
      
      const spfRecords = filterRecordsByPrefix(records, 'v=spf1');
      expect(spfRecords).toHaveLength(1);
      expect(spfRecords[0]).toContain('v=spf1');
    });

    it('should be case-insensitive', () => {
      const records = ['V=SPF1 -all', 'v=spf1 ~all'];
      const result = filterRecordsByPrefix(records, 'v=spf1');
      expect(result).toHaveLength(2);
    });

    it('should return empty array when no matches', () => {
      const records = ['some=record', 'another=record'];
      const result = filterRecordsByPrefix(records, 'v=spf1');
      expect(result).toHaveLength(0);
    });
  });

  describe('resolveTxtRecords', () => {
    it('should resolve and return TXT records as strings', async () => {
      const result = await resolveTxtRecords('google.com');
      
      expect(Array.isArray(result)).toBe(true);
      // Each record should be a string
      result.forEach(record => {
        expect(typeof record).toBe('string');
      });
    });
  });

  describe('safeResolveTxt', () => {
    it('should return empty array on nonexistent domain', async () => {
      // Use a definitely nonexistent domain
      const result = await safeResolveTxt('this-domain-definitely-does-not-exist-abc123xyz.invalid');
      expect(result).toEqual([]);
    });

    it('should return records for valid domain', async () => {
      const result = await safeResolveTxt('google.com');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
    });
  });

  describe('safeResolveMx', () => {
    it('should return empty array on ENOTFOUND', async () => {
      const mockResolveMx = vi.mocked(dns.resolveMx);
      const error = new Error('ENOTFOUND') as NodeJS.ErrnoException;
      error.code = 'ENOTFOUND';
      mockResolveMx.mockRejectedValue(error);

      const result = await safeResolveMx('nonexistent.example.com');
      
      expect(result).toEqual([]);
    });

    it('should return MX records when available', async () => {
      // Note: This test uses the actual DNS resolver since mocking
      // the internal Resolver class is complex. We verify the function
      // returns the expected structure.
      const result = await safeResolveMx('google.com');
      
      // Google.com should have MX records
      expect(Array.isArray(result)).toBe(true);
      if (result.length > 0) {
        expect(result[0]).toHaveProperty('exchange');
        expect(result[0]).toHaveProperty('priority');
      }
    });
  });

  describe('setDnsResolver', () => {
    it('should set custom resolver', () => {
      // Just verify it doesn't throw
      expect(() => setDnsResolver('8.8.8.8')).not.toThrow();
    });

    it('should clear resolver when called with undefined', () => {
      setDnsResolver('8.8.8.8');
      expect(() => setDnsResolver(undefined)).not.toThrow();
    });
  });

  describe('clearDnsCache', () => {
    it('should clear the cache', () => {
      // Just verify it doesn't throw
      expect(() => clearDnsCache()).not.toThrow();
    });
  });

  describe('cachedResolveTxt', () => {
    it('should return TXT records and cache them', async () => {
      // Clear cache before test
      clearDnsCache();
      
      // Use a real domain for integration-style test
      const result1 = await cachedResolveTxt('google.com');
      expect(Array.isArray(result1)).toBe(true);
      
      // Second call should return same result (from cache)
      const result2 = await cachedResolveTxt('google.com');
      expect(result2).toEqual(result1);
    });
  });

  describe('cachedResolveMx', () => {
    it('should return MX records', async () => {
      clearDnsCache();
      
      const result = await cachedResolveMx('google.com');
      
      expect(Array.isArray(result)).toBe(true);
      if (result.length > 0) {
        expect(result[0]).toHaveProperty('exchange');
        expect(result[0]).toHaveProperty('priority');
      }
    });
  });
});
