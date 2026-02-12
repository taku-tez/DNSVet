import { describe, it, expect, vi, beforeEach } from 'vitest';
import { checkWhois, clearRDAPCache } from './whois.js';

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

const MOCK_BOOTSTRAP = {
  services: [
    [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
    [['jp'], ['https://jprs.rdap.jp/']],
  ],
};

function mockRDAPResponse(overrides: Record<string, unknown> = {}) {
  return {
    ldhName: 'example.com',
    status: ['clientTransferProhibited', 'clientDeleteProhibited'],
    events: [
      { eventAction: 'registration', eventDate: '2020-01-01T00:00:00Z' },
      { eventAction: 'last changed', eventDate: '2025-06-01T00:00:00Z' },
      { eventAction: 'expiration', eventDate: '2027-01-01T00:00:00Z' },
    ],
    entities: [
      {
        roles: ['registrar'],
        vcardArray: ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
      },
    ],
    nameservers: [
      { ldhName: 'ns1.example.com' },
      { ldhName: 'ns2.example.com' },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  clearRDAPCache();
});

describe('checkWhois', () => {
  it('should return domain registration info', async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_BOOTSTRAP) }) // bootstrap
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(mockRDAPResponse()) }); // RDAP query

    const result = await checkWhois('example.com');

    expect(result.found).toBe(true);
    expect(result.registrar).toBe('Example Registrar');
    expect(result.createdDate).toBe('2020-01-01T00:00:00Z');
    expect(result.expiryDate).toBe('2027-01-01T00:00:00Z');
    expect(result.daysUntilExpiry).toBeGreaterThan(0);
    expect(result.eppStatus).toContain('clientTransferProhibited');
    expect(result.nameServers).toEqual(['ns1.example.com', 'ns2.example.com']);
  });

  it('should detect expired domain', async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_BOOTSTRAP) })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRDAPResponse({
          events: [
            { eventAction: 'expiration', eventDate: '2020-01-01T00:00:00Z' },
          ],
        })),
      });

    const result = await checkWhois('example.com');
    expect(result.issues.some(i => i.severity === 'critical' && i.message.includes('expired'))).toBe(true);
  });

  it('should warn about missing transfer lock', async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_BOOTSTRAP) })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRDAPResponse({
          status: ['active'],
        })),
      });

    const result = await checkWhois('example.com');
    expect(result.issues.some(i => i.message.includes('transfer lock'))).toBe(true);
  });

  it('should handle RDAP unavailable', async () => {
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_BOOTSTRAP) });
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

    const result = await checkWhois('example.com');
    expect(result.found).toBe(false);
  });

  it('should detect domain near expiry (30 days)', async () => {
    const nearExpiry = new Date();
    nearExpiry.setDate(nearExpiry.getDate() + 15);
    
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_BOOTSTRAP) })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRDAPResponse({
          events: [
            { eventAction: 'expiration', eventDate: nearExpiry.toISOString() },
          ],
        })),
      });

    const result = await checkWhois('example.com');
    expect(result.issues.some(i => i.severity === 'high' && i.message.includes('days'))).toBe(true);
  });

  it('should detect pendingDelete status', async () => {
    mockFetch
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(MOCK_BOOTSTRAP) })
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockRDAPResponse({
          status: ['pendingDelete'],
        })),
      });

    const result = await checkWhois('example.com');
    expect(result.issues.some(i => i.severity === 'critical' && i.message.includes('pendingDelete'))).toBe(true);
  });
});
