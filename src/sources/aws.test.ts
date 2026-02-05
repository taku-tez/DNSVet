import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getRoute53Domains, assumeRole, AWSSource } from './aws.js';
import * as childProcess from 'node:child_process';

// Mock child_process.execFile
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual('node:child_process');
  return {
    ...actual,
    execFile: vi.fn(),
  };
});

describe('AWS Source', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getRoute53Domains', () => {
    it('should return domains from Route53 hosted zones', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const stdout = JSON.stringify({
          HostedZones: [
            { Name: 'example.com.', Id: '/hostedzone/Z123', Config: { PrivateZone: false } },
            { Name: 'test.com.', Id: '/hostedzone/Z456', Config: { PrivateZone: false } },
            { Name: 'private.local.', Id: '/hostedzone/Z789', Config: { PrivateZone: true } },
          ]
        });
        
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const domains = await getRoute53Domains();
      
      expect(domains).toContain('example.com');
      expect(domains).toContain('test.com');
      expect(domains).not.toContain('private.local'); // Private zones filtered
    });

    it('should throw error when AWS CLI fails', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const error = new Error('AWS CLI not configured');
        if (callback) callback(error, { stdout: '', stderr: 'error' });
        throw error;
      }) as any);

      await expect(getRoute53Domains()).rejects.toThrow();
    });

    it('should use AWS profile when specified', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      const capturedArgs: string[][] = [];
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        capturedArgs.push(args as string[]);
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const stdout = JSON.stringify({ HostedZones: [] });
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      await getRoute53Domains({ profile: 'production' });
      
      const hasProfile = capturedArgs.some(args => 
        args.includes('--profile') && args.includes('production')
      );
      expect(hasProfile).toBe(true);
    });
  });

  describe('assumeRole', () => {
    it('should assume IAM role and return credentials', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const stdout = JSON.stringify({
          Credentials: {
            AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
            SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            SessionToken: 'FwoGZXIvYXdzE...',
          }
        });
        
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const credentials = await assumeRole('arn:aws:iam::123456789012:role/DNSVetRole');
      
      expect(credentials.accessKeyId).toBe('AKIAIOSFODNN7EXAMPLE');
      expect(credentials.secretAccessKey).toBeDefined();
      expect(credentials.sessionToken).toBeDefined();
    });

    it('should throw on assume role failure', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const error = new Error('Access denied');
        if (callback) callback(error, { stdout: '', stderr: '' });
        throw error;
      }) as any);

      await expect(assumeRole('arn:aws:iam::123456789012:role/DNSVetRole'))
        .rejects.toThrow();
    });
  });

  describe('AWSSource', () => {
    it('should implement CloudSource interface', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const stdout = JSON.stringify({
          HostedZones: [
            { Name: 'example.com.', Id: '/hostedzone/Z123', Config: { PrivateZone: false } },
          ]
        });
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const source = new AWSSource();
      expect(source.name).toBe('AWS Route53');
      
      const domains = await source.getDomains();
      expect(domains).toContain('example.com');
    });
  });
});
