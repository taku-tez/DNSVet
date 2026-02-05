import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DNSSEC_ALGORITHMS, DS_DIGEST_TYPES, DNSKEY_FLAGS, checkDNSSEC } from './dnssec.js';
import * as childProcess from 'node:child_process';
import { promisify } from 'node:util';

// Mock child_process.execFile
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual('node:child_process');
  return {
    ...actual,
    execFile: vi.fn(),
  };
});

describe('DNSSEC', () => {
  describe('Algorithm classification', () => {
    it('should classify RSAMD5 as deprecated', () => {
      expect(DNSSEC_ALGORITHMS[1].strength).toBe('deprecated');
    });

    it('should classify DSA as deprecated', () => {
      expect(DNSSEC_ALGORITHMS[3].strength).toBe('deprecated');
    });

    it('should classify RSASHA1 as weak', () => {
      expect(DNSSEC_ALGORITHMS[5].strength).toBe('weak');
    });

    it('should classify RSASHA256 as acceptable', () => {
      expect(DNSSEC_ALGORITHMS[8].strength).toBe('acceptable');
    });

    it('should classify ECDSAP256SHA256 as strong', () => {
      expect(DNSSEC_ALGORITHMS[13].strength).toBe('strong');
    });

    it('should classify ED25519 as strong', () => {
      expect(DNSSEC_ALGORITHMS[15].strength).toBe('strong');
    });
  });

  describe('DS Digest Types', () => {
    it('should classify SHA-1 as weak', () => {
      expect(DS_DIGEST_TYPES[1].strength).toBe('weak');
    });

    it('should classify SHA-256 as strong', () => {
      expect(DS_DIGEST_TYPES[2].strength).toBe('strong');
    });

    it('should classify SHA-384 as strong', () => {
      expect(DS_DIGEST_TYPES[4].strength).toBe('strong');
    });
  });

  describe('DNSKEY flags', () => {
    it('should recognize KSK flag (257)', () => {
      expect(DNSKEY_FLAGS.SEP_KEY).toBe(257);
    });

    it('should recognize ZSK flag (256)', () => {
      expect(DNSKEY_FLAGS.ZONE_KEY).toBe(256);
    });
  });

  describe('checkDNSSEC', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should detect DNSSEC enabled with valid DS and DNSKEY', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      // Mock dig for DS records
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const argsArr = args as string[];
        if (argsArr.includes('DS')) {
          // DS record: keyTag algorithm digestType digest
          const stdout = '2371 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9\n';
          if (callback) callback(null, { stdout, stderr: '' });
          return { stdout, stderr: '' } as any;
        } else if (argsArr.includes('DNSKEY')) {
          // DNSKEY record: flags protocol algorithm publicKey
          const stdout = '257 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA==\n256 3 13 6ZRWkqL+Z4r3w3XNkLCHvEjLV+PyFJLkc++tkBTH4Y+GC0Gy1BfPe2Swe8lRvFhvCMSPY1KTwLyF+q4hCCJdnA==\n';
          if (callback) callback(null, { stdout, stderr: '' });
          return { stdout, stderr: '' } as any;
        }
        if (callback) callback(null, { stdout: '', stderr: '' });
        return { stdout: '', stderr: '' } as any;
      }) as any);

      const result = await checkDNSSEC('example.com');
      
      expect(result.enabled).toBe(true);
      expect(result.ds?.found).toBe(true);
      expect(result.ds?.records.length).toBeGreaterThan(0);
      expect(result.dnskey?.found).toBe(true);
      expect(result.dnskey?.kskCount).toBe(1);
      expect(result.dnskey?.zskCount).toBe(1);
    });

    it('should detect DNSSEC not enabled when no records found', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        if (callback) callback(null, { stdout: '', stderr: '' });
        return { stdout: '', stderr: '' } as any;
      }) as any);

      const result = await checkDNSSEC('example.com');
      
      expect(result.enabled).toBe(false);
      expect(result.issues.length).toBeGreaterThan(0);
      expect(result.issues[0].message).toContain('DNSSEC is not enabled');
    });

    it('should handle dig command not found', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const error = new Error('dig not found') as NodeJS.ErrnoException;
        error.code = 'ENOENT';
        if (callback) callback(error, { stdout: '', stderr: '' });
        throw error;
      }) as any);

      const result = await checkDNSSEC('example.com');
      
      expect(result.enabled).toBe(false);
      // Should have an issue about dig not being available
      const hasDigWarning = result.issues.some(i => 
        i.message.includes('dig') || i.message.includes('DNSSEC')
      );
      expect(hasDigWarning).toBe(true);
    });

    it('should detect weak algorithms and report issues', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const argsArr = args as string[];
        if (argsArr.includes('DS')) {
          // Algorithm 5 = RSASHA1 (weak)
          const stdout = '12345 5 1 ABCDEF1234567890\n';
          if (callback) callback(null, { stdout, stderr: '' });
          return { stdout, stderr: '' } as any;
        } else if (argsArr.includes('DNSKEY')) {
          const stdout = '257 3 5 AQPJ////dGhpcyBpcyBhIHRlc3Qga2V5\n';
          if (callback) callback(null, { stdout, stderr: '' });
          return { stdout, stderr: '' } as any;
        }
        if (callback) callback(null, { stdout: '', stderr: '' });
        return { stdout: '', stderr: '' } as any;
      }) as any);

      const result = await checkDNSSEC('example.com');
      
      expect(result.enabled).toBe(true);
      // Should have issue about weak algorithm
      const hasWeakAlgoIssue = result.issues.some(i => 
        i.message.toLowerCase().includes('weak') || 
        i.message.toLowerCase().includes('rsasha1')
      );
      expect(hasWeakAlgoIssue).toBe(true);
    });

    it('should use custom resolver when provided', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      const capturedArgs: string[][] = [];
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        capturedArgs.push(args as string[]);
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        if (callback) callback(null, { stdout: '', stderr: '' });
        return { stdout: '', stderr: '' } as any;
      }) as any);

      await checkDNSSEC('example.com', { resolver: '1.1.1.1' });
      
      // Check that custom resolver was used
      const hasCustomResolver = capturedArgs.some(args => args.includes('@1.1.1.1'));
      expect(hasCustomResolver).toBe(true);
    });
  });
});
