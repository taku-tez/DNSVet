import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getCloudDNSDomains, listGCPProjects, GCPSource } from './gcp.js';
import * as childProcess from 'node:child_process';

// Mock child_process.execFile
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual('node:child_process');
  return {
    ...actual,
    execFile: vi.fn(),
  };
});

describe('GCP Source', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getCloudDNSDomains', () => {
    it('should return domains from Cloud DNS zones', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        
        const stdout = JSON.stringify([
          { name: 'example-zone', dnsName: 'example.com.', visibility: 'public' },
          { name: 'test-zone', dnsName: 'test.com.', visibility: 'public' },
          { name: 'private-zone', dnsName: 'private.local.', visibility: 'private' },
        ]);
        
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const domains = await getCloudDNSDomains({ project: 'my-project' });
      
      expect(domains).toContain('example.com');
      expect(domains).toContain('test.com');
      expect(domains).not.toContain('private.local'); // Private zones filtered
    });

    it('should throw error when gcloud CLI fails', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const error = new Error('gcloud not configured');
        if (callback) callback(error, { stdout: '', stderr: 'error' });
        throw error;
      }) as any);

      await expect(getCloudDNSDomains()).rejects.toThrow();
    });

    it('should use project when specified', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      const capturedArgs: string[][] = [];
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        capturedArgs.push(args as string[]);
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const stdout = JSON.stringify([]);
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      await getCloudDNSDomains({ project: 'my-project' });
      
      // Check that project was passed in args (may be combined with other flags)
      const hasProject = capturedArgs.some(args => 
        args.some(arg => arg.includes('my-project'))
      );
      expect(hasProject).toBe(true);
    });
  });

  describe('listGCPProjects', () => {
    it('should list accessible projects', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const stdout = 'project-1\nproject-2\nproject-3\n';
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const projects = await listGCPProjects();
      
      expect(projects).toContain('project-1');
      expect(projects).toContain('project-2');
      expect(projects).toContain('project-3');
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

      const projects = await listGCPProjects();
      
      expect(projects).toEqual([]);
    });
  });

  describe('GCPSource', () => {
    it('should implement CloudSource interface', async () => {
      const mockExecFile = vi.mocked(childProcess.execFile);
      
      mockExecFile.mockImplementation(((cmd: string, args: string[], opts: unknown, callback?: Function) => {
        if (!callback && typeof opts === 'function') {
          callback = opts;
        }
        const argsArr = args as string[];
        
        if (argsArr.includes('projects')) {
          const stdout = 'test-project\n';
          if (callback) callback(null, { stdout, stderr: '' });
          return { stdout, stderr: '' } as any;
        }
        
        const stdout = JSON.stringify([
          { name: 'zone', dnsName: 'example.com.', visibility: 'public' },
        ]);
        if (callback) callback(null, { stdout, stderr: '' });
        return { stdout, stderr: '' } as any;
      }) as any);

      const source = new GCPSource();
      expect(source.name).toBe('Google Cloud DNS');
      
      const domains = await source.getDomains();
      expect(Array.isArray(domains)).toBe(true);
    });
  });
});
