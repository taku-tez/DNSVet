import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { analyzeDomain, analyzeMultiple } from './analyzer.js';
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
      resolveTxt: vi.fn(),
      resolveMx: vi.fn(),
    })),
  };
});

// Mock fetch for MTA-STS/TLS-RPT/BIMI
vi.stubGlobal('fetch', vi.fn());

// Mock child_process for DNSSEC
vi.mock('node:child_process', async () => {
  const actual = await vi.importActual('node:child_process');
  return {
    ...actual,
    execFile: vi.fn((cmd, args, opts, callback) => {
      if (typeof opts === 'function') {
        callback = opts;
      }
      if (callback) callback(null, { stdout: '', stderr: '' });
    }),
  };
});

describe('analyzeDomain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    
    // Setup default mocks
    const mockResolveTxt = vi.mocked(dns.resolveTxt);
    const mockResolveMx = vi.mocked(dns.resolveMx);
    const mockFetch = vi.mocked(fetch);

    // Default: return empty for all DNS queries
    mockResolveTxt.mockResolvedValue([]);
    mockResolveMx.mockResolvedValue([]);
    
    // Default: fetch fails (no MTA-STS/BIMI)
    mockFetch.mockRejectedValue(new Error('Not found'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should return low grade for domain with no records', async () => {
    // Use a definitely nonexistent domain to test no-records scenario
    const result = await analyzeDomain('this-domain-definitely-does-not-exist-xyz123.invalid');
    
    expect(result.domain).toBe('this-domain-definitely-does-not-exist-xyz123.invalid');
    expect(result.spf.found).toBe(false);
    expect(result.dkim.found).toBe(false);
    expect(result.dmarc.found).toBe(false);
  });

  it('should return invalid domain error for bad input', async () => {
    const result = await analyzeDomain('not a domain');
    
    expect(result.grade).toBe('F');
    expect(result.score).toBe(0);
    expect(result.error).toContain('Invalid domain');
  });

  it('should normalize domain with trailing dot', async () => {
    const result = await analyzeDomain('example.com.');
    
    expect(result.domain).toBe('example.com');
  });

  it('should normalize domain with uppercase', async () => {
    const result = await analyzeDomain('EXAMPLE.COM');
    
    expect(result.domain).toBe('example.com');
  });

  it('should detect SPF record', async () => {
    const mockResolveTxt = vi.mocked(dns.resolveTxt);
    mockResolveTxt.mockImplementation(async (domain: string) => {
      if (domain === 'example.com') {
        return [['v=spf1 include:_spf.google.com -all']];
      }
      return [];
    });

    const result = await analyzeDomain('example.com');
    
    expect(result.spf.found).toBe(true);
    expect(result.spf.mechanism).toBe('-all');
  });

  it('should detect DKIM record', async () => {
    const mockResolveTxt = vi.mocked(dns.resolveTxt);
    mockResolveTxt.mockImplementation(async (domain: string) => {
      if (domain.includes('._domainkey.')) {
        return [['v=DKIM1; k=rsa; p=MIGfMA0GCSq...']];
      }
      return [];
    });

    const result = await analyzeDomain('example.com');
    
    expect(result.dkim.found).toBe(true);
    expect(result.dkim.selectors.length).toBeGreaterThan(0);
  });

  it('should detect DMARC record', async () => {
    const mockResolveTxt = vi.mocked(dns.resolveTxt);
    mockResolveTxt.mockImplementation(async (domain: string) => {
      if (domain === '_dmarc.example.com') {
        return [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']];
      }
      return [];
    });

    const result = await analyzeDomain('example.com');
    
    expect(result.dmarc.found).toBe(true);
    expect(result.dmarc.policy).toBe('reject');
  });

  it('should detect MX records', async () => {
    const mockResolveMx = vi.mocked(dns.resolveMx);
    mockResolveMx.mockResolvedValue([
      { exchange: 'aspmx.l.google.com', priority: 1 },
      { exchange: 'alt1.aspmx.l.google.com', priority: 5 },
    ]);

    const result = await analyzeDomain('example.com');
    
    expect(result.mx.found).toBe(true);
    expect(result.mx.records.length).toBeGreaterThanOrEqual(1);
  });

  it('should skip checks when --skip option is used', async () => {
    const result = await analyzeDomain('example.com', {
      checks: { bimi: false, dnssec: false }
    });
    
    // BIMI and DNSSEC should be skipped
    expect(result.bimi?.skipped).toBe(true);
    expect(result.bimi?.found).toBe(false);
    expect(result.dnssec?.skipped).toBe(true);
    expect(result.dnssec?.enabled).toBe(false);
  });

  it('should use custom resolver when specified', async () => {
    const result = await analyzeDomain('example.com', {
      resolver: '1.1.1.1'
    });
    
    // Should complete without error
    expect(result.domain).toBe('example.com');
  });

  it('should calculate correct grade for well-configured domain', async () => {
    const mockResolveTxt = vi.mocked(dns.resolveTxt);
    const mockResolveMx = vi.mocked(dns.resolveMx);

    mockResolveTxt.mockImplementation(async (domain: string) => {
      if (domain === 'example.com') {
        return [['v=spf1 include:_spf.google.com -all']];
      }
      if (domain === '_dmarc.example.com') {
        return [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']];
      }
      if (domain.includes('._domainkey.')) {
        return [['v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC...']];
      }
      return [];
    });

    mockResolveMx.mockResolvedValue([
      { exchange: 'aspmx.l.google.com', priority: 1 },
    ]);

    const result = await analyzeDomain('example.com');
    
    expect(result.spf.found).toBe(true);
    expect(result.dkim.found).toBe(true);
    expect(result.dmarc.found).toBe(true);
    expect(result.mx.found).toBe(true);
    // Should be at least grade C with these settings
    expect(['A', 'B', 'C']).toContain(result.grade);
  });

  it('should include timestamp in result', async () => {
    const result = await analyzeDomain('example.com');
    
    expect(result.timestamp).toBeDefined();
    expect(new Date(result.timestamp).getTime()).not.toBeNaN();
  });
});

describe('analyzeMultiple', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    
    const mockResolveTxt = vi.mocked(dns.resolveTxt);
    const mockResolveMx = vi.mocked(dns.resolveMx);
    const mockFetch = vi.mocked(fetch);

    mockResolveTxt.mockResolvedValue([]);
    mockResolveMx.mockResolvedValue([]);
    mockFetch.mockRejectedValue(new Error('Not found'));
  });

  it('should analyze multiple domains', async () => {
    const results = await analyzeMultiple(['example.com', 'test.com']);
    
    expect(results.length).toBe(2);
    expect(results[0].domain).toBe('example.com');
    expect(results[1].domain).toBe('test.com');
  });

  it('should respect concurrency option', async () => {
    const domains = ['a.com', 'b.com', 'c.com', 'd.com', 'e.com'];
    const results = await analyzeMultiple(domains, { concurrency: 2 });
    
    expect(results.length).toBe(5);
  });

  it('should handle empty domain list', async () => {
    const results = await analyzeMultiple([]);
    
    expect(results).toEqual([]);
  });

  it('should filter out invalid domains', async () => {
    const results = await analyzeMultiple(['example.com', '', 'test.com']);
    
    // Empty string should be filtered or result in error
    expect(results.length).toBeGreaterThanOrEqual(2);
  });
});

  it('should not penalize or recommend skipped checks (--only spf)', async () => {
    const result = await analyzeDomain('example.com', {
      checks: { spf: true, dkim: false, dmarc: false, mx: false, bimi: false, mtaSts: false, tlsRpt: false, arc: false, dnssec: false }
    });
    
    // Skipped checks should have skipped: true
    expect(result.dkim.skipped).toBe(true);
    expect(result.dmarc.skipped).toBe(true);
    expect(result.mx.skipped).toBe(true);
    
    // Recommendations should NOT include DMARC/DKIM/MX suggestions
    const recText = result.recommendations.join('\n');
    expect(recText).not.toContain('DMARC');
    expect(recText).not.toContain('DKIM');
    expect(recText).not.toContain('MTA-STS');
    expect(recText).not.toContain('TLS-RPT');
    expect(recText).not.toContain('DNSSEC');
  });
