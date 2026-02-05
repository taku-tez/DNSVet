import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getCloudflareDomains } from './cloudflare.js';

describe('Cloudflare source', () => {
  const originalFetch = global.fetch;

  beforeEach(() => {
    vi.stubEnv('CLOUDFLARE_API_TOKEN', '');
    vi.stubEnv('CLOUDFLARE_EMAIL', '');
    vi.stubEnv('CLOUDFLARE_API_KEY', '');
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.unstubAllEnvs();
  });

  it('throws error when no credentials configured', async () => {
    await expect(getCloudflareDomains()).rejects.toThrow('Cloudflare credentials not configured');
  });

  it('uses API token when provided', async () => {
    let capturedHeaders: Record<string, string> = {};
    
    global.fetch = vi.fn().mockImplementation(async (_url, options) => {
      capturedHeaders = options?.headers as Record<string, string>;
      return {
        ok: true,
        json: async () => ({
          result: [{ name: 'example.com', status: 'active' }],
          result_info: { total_pages: 1, page: 1 }
        })
      };
    }) as typeof fetch;

    await getCloudflareDomains({ apiToken: 'test-token' });
    
    expect(capturedHeaders['Authorization']).toBe('Bearer test-token');
  });

  it('uses email + API key when token not provided', async () => {
    let capturedHeaders: Record<string, string> = {};
    
    global.fetch = vi.fn().mockImplementation(async (_url, options) => {
      capturedHeaders = options?.headers as Record<string, string>;
      return {
        ok: true,
        json: async () => ({
          result: [{ name: 'example.com', status: 'active' }],
          result_info: { total_pages: 1, page: 1 }
        })
      };
    }) as typeof fetch;

    await getCloudflareDomains({ email: 'test@example.com', apiKey: 'test-key' });
    
    expect(capturedHeaders['X-Auth-Email']).toBe('test@example.com');
    expect(capturedHeaders['X-Auth-Key']).toBe('test-key');
  });

  it('handles pagination correctly', async () => {
    let pageRequests = 0;
    
    global.fetch = vi.fn().mockImplementation(async (url) => {
      pageRequests++;
      const urlObj = new URL(url);
      const page = parseInt(urlObj.searchParams.get('page') || '1', 10);
      
      return {
        ok: true,
        json: async () => ({
          result: [{ name: `domain${page}.com`, status: 'active' }],
          result_info: { total_pages: 3, page }
        })
      };
    }) as typeof fetch;

    const domains = await getCloudflareDomains({ apiToken: 'test-token' });
    
    expect(pageRequests).toBe(3);
    expect(domains).toEqual(['domain1.com', 'domain2.com', 'domain3.com']);
  });

  it('filters out inactive zones', async () => {
    global.fetch = vi.fn().mockImplementation(async () => ({
      ok: true,
      json: async () => ({
        result: [
          { name: 'active.com', status: 'active' },
          { name: 'pending.com', status: 'pending' },
          { name: 'deactivated.com', status: 'deactivated' },
        ],
        result_info: { total_pages: 1, page: 1 }
      })
    })) as typeof fetch;

    const domains = await getCloudflareDomains({ apiToken: 'test-token' });
    
    expect(domains).toEqual(['active.com']);
  });

  it('throws error on API error response', async () => {
    global.fetch = vi.fn().mockImplementation(async () => ({
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      json: async () => ({
        errors: [{ message: 'Invalid API token' }]
      })
    })) as typeof fetch;

    await expect(getCloudflareDomains({ apiToken: 'bad-token' }))
      .rejects.toThrow('Cloudflare API error: Invalid API token');
  });
});
