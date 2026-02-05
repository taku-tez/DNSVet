import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getAzureDNSDomains, listAzureSubscriptions, AzureSource } from './azure.js';
import * as childProcess from 'node:child_process';

// Mock child_process.execFile
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual('node:child_process');
  return {
    ...actual,
    execFile: vi.fn(),
  };
});

describe('Azure Source', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getAzureDNSDomains', () => {
    it('should return domains from Azure DNS zones', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const argsArr = args as string[];
        
        // Skip login calls
        if (argsArr.includes('login')) {
          if (callback) callback(null, { stdout: '', stderr: '' });
          return { stdout: '', stderr: '' } as any;
        }
        
        const stdout = JSON.stringify([
          { name: 'example.com', zoneType: 'Public' },
          { name: 'test.com', zoneType: 'Public' },
          { name: 'private.local', zoneType: 'Private' },
        ]);
        
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const domains = await getAzureDNSDomains();
      
      expect(domains).toContain('example.com');
      expect(domains).toContain('test.com');
      // Private zones should be filtered out
    });

    it('should throw error when az CLI fails', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const error = new Error('az CLI not configured');
        if (callback) callback(error, { stdout: '', stderr: 'error' });
        throw error;
      }) as any);

      await expect(getAzureDNSDomains()).rejects.toThrow();
    });

    it('should use subscription when specified', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      const capturedArgs: string[][] = [];
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        capturedArgs.push(args as string[]);
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const argsArr = args as string[];
        if (argsArr.includes('login')) {
          if (callback) callback(null, { stdout: '', stderr: '' });
          return { stdout: '', stderr: '' } as any;
        }
        
        const stdout = JSON.stringify([]);
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      await getAzureDNSDomains({ subscription: 'sub-123' });
      
      const hasSubscription = capturedArgs.some(args => 
        args.includes('--subscription') && args.includes('sub-123')
      );
      expect(hasSubscription).toBe(true);
    });
  });

  describe('listAzureSubscriptions', () => {
    it('should list accessible subscriptions', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const argsArr = args as string[];
        if (argsArr.includes('login')) {
          if (callback) callback(null, { stdout: '', stderr: '' });
          return { stdout: '', stderr: '' } as any;
        }
        
        const stdout = JSON.stringify([
          { id: 'sub-1', name: 'Subscription 1' },
          { id: 'sub-2', name: 'Subscription 2' },
        ]);
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const subscriptions = await listAzureSubscriptions();
      
      expect(subscriptions).toContain('sub-1');
      expect(subscriptions).toContain('sub-2');
    });

    it('should return empty array on error', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const error = new Error('Not authenticated');
        if (callback) callback(error, { stdout: '', stderr: '' });
        throw error;
      }) as any);

      const subscriptions = await listAzureSubscriptions();
      
      expect(subscriptions).toEqual([]);
    });
  });

  describe('AzureSource', () => {
    it('should implement CloudSource interface', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const argsArr = args as string[];
        if (argsArr.includes('login')) {
          if (callback) callback(null, { stdout: '', stderr: '' });
          return { stdout: '', stderr: '' } as any;
        }
        
        const stdout = JSON.stringify([
          { name: 'example.com', zoneType: 'Public' },
        ]);
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const source = new AzureSource();
      expect(source.name).toBe('Azure DNS');
      
      const domains = await source.getDomains();
      expect(Array.isArray(domains)).toBe(true);
    });
  });
});
