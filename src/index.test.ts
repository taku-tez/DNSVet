import { describe, it, expect } from 'vitest';
import * as dnsvet from './index.js';

describe('Public API exports', () => {
  it('should export all check functions', () => {
    expect(typeof dnsvet.checkSPF).toBe('function');
    expect(typeof dnsvet.checkDKIM).toBe('function');
    expect(typeof dnsvet.checkDMARC).toBe('function');
    expect(typeof dnsvet.checkMX).toBe('function');
    expect(typeof dnsvet.checkBIMI).toBe('function');
    expect(typeof dnsvet.checkMTASTS).toBe('function');
    expect(typeof dnsvet.checkTLSRPT).toBe('function');
    expect(typeof dnsvet.checkARCReadiness).toBe('function');
    expect(typeof dnsvet.checkDNSSEC).toBe('function');
  });

  it('should export analyzer functions', () => {
    expect(typeof dnsvet.analyzeDomain).toBe('function');
    expect(typeof dnsvet.analyzeMultiple).toBe('function');
  });

  it('should export source functions', () => {
    expect(typeof dnsvet.getRoute53Domains).toBe('function');
    expect(typeof dnsvet.getCloudDNSDomains).toBe('function');
    expect(typeof dnsvet.getAzureDNSDomains).toBe('function');
    expect(typeof dnsvet.getCloudflareDomains).toBe('function');
  });
});
