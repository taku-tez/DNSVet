/**
 * Domain WHOIS/RDAP checker
 * 
 * Uses RDAP (RFC 7482/7483) for structured domain registration data.
 * Checks domain expiry, EPP status, and registration info.
 */

import type { WhoisResult, Issue } from '../types.js';

/** RDAP bootstrap: resolve the authoritative RDAP server for a TLD */
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/** Cache for RDAP server URLs by TLD */
const rdapServerCache = new Map<string, string>();

/** Clear RDAP server cache (for testing) */
export function clearRDAPCache(): void {
  rdapServerCache.clear();
}

/** Warning thresholds for domain expiry (days) */
const EXPIRY_CRITICAL_DAYS = 7;
const EXPIRY_HIGH_DAYS = 30;
const EXPIRY_MEDIUM_DAYS = 90;

/** Known EPP status codes and their security implications */
const PROTECTIVE_STATUSES = new Set([
  'clientTransferProhibited',
  'serverTransferProhibited',
  'clientDeleteProhibited',
  'serverDeleteProhibited',
  'clientUpdateProhibited',
  'serverUpdateProhibited',
]);

interface RDAPEvent {
  eventAction: string;
  eventDate: string;
}

interface RDAPEntity {
  vcardArray?: [string, Array<[string, Record<string, unknown>, string, string]>];
  roles?: string[];
}

interface RDAPResponse {
  handle?: string;
  ldhName?: string;
  status?: string[];
  events?: RDAPEvent[];
  entities?: RDAPEntity[];
  nameservers?: Array<{ ldhName?: string }>;
  port43?: string;
  links?: Array<{ rel?: string; href?: string }>;
}

/**
 * Get RDAP server URL for a given TLD from IANA bootstrap
 */
async function getRDAPServer(tld: string): Promise<string | undefined> {
  if (rdapServerCache.has(tld)) {
    return rdapServerCache.get(tld);
  }

  try {
    const res = await fetch(RDAP_BOOTSTRAP_URL, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return undefined;

    const data = await res.json() as { services: Array<[string[], string[]]> };
    
    for (const [tlds, urls] of data.services) {
      const serverUrl = urls[0];
      for (const t of tlds) {
        rdapServerCache.set(t.toLowerCase(), serverUrl);
      }
    }

    return rdapServerCache.get(tld);
  } catch {
    return undefined;
  }
}

/**
 * Query RDAP for domain registration data
 */
async function queryRDAP(domain: string, timeout = 10000): Promise<RDAPResponse | undefined> {
  // Extract TLD
  const parts = domain.split('.');
  // Try progressively longer TLD matches (e.g., co.jp before jp)
  for (let i = 1; i < parts.length; i++) {
    const tld = parts.slice(i).join('.');
    const serverUrl = await getRDAPServer(tld);
    if (serverUrl) {
      try {
        const url = `${serverUrl.replace(/\/$/, '')}/domain/${domain}`;
        const res = await fetch(url, {
          signal: AbortSignal.timeout(timeout),
          headers: { 'Accept': 'application/rdap+json' },
        });
        if (res.ok) {
          return await res.json() as RDAPResponse;
        }
      } catch {
        // Try next TLD match
      }
    }
  }
  return undefined;
}

/**
 * Extract date from RDAP events by action type
 */
function getEventDate(events: RDAPEvent[] | undefined, action: string): string | undefined {
  const event = events?.find(e => e.eventAction === action);
  return event?.eventDate;
}

/**
 * Calculate days until a date
 */
function daysUntil(dateStr: string): number {
  const target = new Date(dateStr);
  const now = new Date();
  return Math.floor((target.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
}

/**
 * Extract registrar name from RDAP entities
 */
function getRegistrar(entities: RDAPEntity[] | undefined): string | undefined {
  const registrar = entities?.find(e => e.roles?.includes('registrar'));
  if (!registrar?.vcardArray) return undefined;
  
  const vcard = registrar.vcardArray[1];
  const fn = vcard?.find(v => v[0] === 'fn');
  return fn?.[3] as string | undefined;
}

/**
 * Check domain WHOIS/RDAP information
 */
export async function checkWhois(domain: string, options: { timeout?: number } = {}): Promise<WhoisResult> {
  const timeout = options.timeout || 10000;
  const issues: Issue[] = [];

  const rdap = await queryRDAP(domain, timeout);
  
  if (!rdap) {
    return {
      found: false,
      issues: [{
        severity: 'info',
        message: 'RDAP data not available for this domain',
        recommendation: 'WHOIS/RDAP data may not be available for all TLDs',
      }],
    };
  }

  const createdDate = getEventDate(rdap.events, 'registration');
  const updatedDate = getEventDate(rdap.events, 'last changed');
  const expiryDate = getEventDate(rdap.events, 'expiration');
  const registrar = getRegistrar(rdap.entities);
  const eppStatus = rdap.status;
  const nameServers = rdap.nameservers?.map(ns => ns.ldhName?.toLowerCase() || '').filter(Boolean);

  // Check domain expiry
  let daysUntilExpiry: number | undefined;
  if (expiryDate) {
    daysUntilExpiry = daysUntil(expiryDate);

    if (daysUntilExpiry < 0) {
      issues.push({
        severity: 'critical',
        message: `Domain has expired (${expiryDate})`,
        recommendation: 'Renew the domain immediately to prevent loss and potential takeover',
      });
    } else if (daysUntilExpiry <= EXPIRY_CRITICAL_DAYS) {
      issues.push({
        severity: 'critical',
        message: `Domain expires in ${daysUntilExpiry} days (${expiryDate})`,
        recommendation: 'Renew the domain immediately and enable auto-renewal',
      });
    } else if (daysUntilExpiry <= EXPIRY_HIGH_DAYS) {
      issues.push({
        severity: 'high',
        message: `Domain expires in ${daysUntilExpiry} days (${expiryDate})`,
        recommendation: 'Renew the domain soon and verify auto-renewal is enabled',
      });
    } else if (daysUntilExpiry <= EXPIRY_MEDIUM_DAYS) {
      issues.push({
        severity: 'medium',
        message: `Domain expires in ${daysUntilExpiry} days (${expiryDate})`,
        recommendation: 'Verify auto-renewal is enabled to prevent accidental expiry',
      });
    }
  }

  // Check EPP status for security
  if (eppStatus && eppStatus.length > 0) {
    const hasTransferLock = eppStatus.some(s => 
      s === 'clientTransferProhibited' || s === 'serverTransferProhibited'
    );
    const hasDeleteLock = eppStatus.some(s =>
      s === 'clientDeleteProhibited' || s === 'serverDeleteProhibited'  
    );

    if (!hasTransferLock) {
      issues.push({
        severity: 'medium',
        message: 'Domain transfer lock is not enabled',
        recommendation: 'Enable registrar lock (clientTransferProhibited) to prevent unauthorized domain transfers',
      });
    }

    if (!hasDeleteLock) {
      issues.push({
        severity: 'low',
        message: 'Domain delete protection is not enabled',
        recommendation: 'Enable delete protection (clientDeleteProhibited) to prevent accidental deletion',
      });
    }

    // Check for redemption/pending delete status
    if (eppStatus.some(s => s === 'redemptionPeriod' || s === 'pendingDelete')) {
      issues.push({
        severity: 'critical',
        message: `Domain is in ${eppStatus.find(s => s === 'redemptionPeriod' || s === 'pendingDelete')} status`,
        recommendation: 'Contact your registrar immediately to recover the domain',
      });
    }
  }

  return {
    found: true,
    registrar,
    createdDate,
    updatedDate,
    expiryDate,
    daysUntilExpiry,
    eppStatus,
    nameServers,
    issues,
  };
}
