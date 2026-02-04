/**
 * DMARC (Domain-based Message Authentication, Reporting & Conformance) checker
 */

import dns from 'node:dns/promises';
import type { DMARCResult, Issue } from '../types.js';

export async function checkDMARC(domain: string): Promise<DMARCResult> {
  const issues: Issue[] = [];
  const dmarcDomain = `_dmarc.${domain}`;

  try {
    const txtRecords = await dns.resolveTxt(dmarcDomain);
    const dmarcRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=dmarc1'));

    if (dmarcRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No DMARC record found',
          recommendation: 'Add a DMARC record to specify email authentication policy'
        }]
      };
    }

    if (dmarcRecords.length > 1) {
      issues.push({
        severity: 'high',
        message: `Multiple DMARC records found (${dmarcRecords.length})`,
        recommendation: 'Only one DMARC record should exist'
      });
    }

    const record = dmarcRecords[0];
    const policy = extractPolicy(record);
    const subdomainPolicy = extractSubdomainPolicy(record);
    const rua = extractReportingAddresses(record, 'rua');
    const ruf = extractReportingAddresses(record, 'ruf');
    const pct = extractPercentage(record);

    // Check policy strength
    if (!policy) {
      issues.push({
        severity: 'critical',
        message: 'DMARC record has no policy (p=) specified',
        recommendation: 'Add a policy: p=reject for maximum protection'
      });
    } else if (policy === 'none') {
      issues.push({
        severity: 'high',
        message: 'DMARC policy is "none" - no enforcement',
        recommendation: 'Change to p=quarantine or p=reject after monitoring'
      });
    } else if (policy === 'quarantine') {
      issues.push({
        severity: 'medium',
        message: 'DMARC policy is "quarantine" - consider upgrading',
        recommendation: 'Change to p=reject for maximum protection when ready'
      });
    }

    // Check subdomain policy
    if (policy === 'reject' && subdomainPolicy && subdomainPolicy !== 'reject') {
      issues.push({
        severity: 'medium',
        message: `Subdomain policy (sp=${subdomainPolicy}) is weaker than main policy`,
        recommendation: 'Consider setting sp=reject as well'
      });
    }

    // Check reporting
    const reportingEnabled = rua.length > 0 || ruf.length > 0;
    if (!reportingEnabled) {
      issues.push({
        severity: 'medium',
        message: 'No DMARC reporting configured',
        recommendation: 'Add rua= to receive aggregate reports'
      });
    }

    // Check percentage
    if (pct !== undefined && pct < 100) {
      issues.push({
        severity: 'low',
        message: `DMARC policy applies to only ${pct}% of messages`,
        recommendation: 'Consider increasing pct to 100 after testing'
      });
    }

    return {
      found: true,
      record,
      policy,
      subdomainPolicy,
      reportingEnabled,
      rua,
      ruf,
      pct,
      issues
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No DMARC record found',
          recommendation: 'Add a DMARC record to specify email authentication policy'
        }]
      };
    }
    throw err;
  }
}

function extractPolicy(record: string): 'none' | 'quarantine' | 'reject' | undefined {
  const match = record.match(/;\s*p=([^;\s]+)/i);
  if (!match) return undefined;
  
  const policy = match[1].toLowerCase();
  if (policy === 'none' || policy === 'quarantine' || policy === 'reject') {
    return policy;
  }
  return undefined;
}

function extractSubdomainPolicy(record: string): 'none' | 'quarantine' | 'reject' | undefined {
  const match = record.match(/;\s*sp=([^;\s]+)/i);
  if (!match) return undefined;
  
  const policy = match[1].toLowerCase();
  if (policy === 'none' || policy === 'quarantine' || policy === 'reject') {
    return policy;
  }
  return undefined;
}

function extractReportingAddresses(record: string, tag: 'rua' | 'ruf'): string[] {
  const regex = new RegExp(`${tag}=([^;]+)`, 'i');
  const match = record.match(regex);
  if (!match) return [];

  return match[1]
    .split(',')
    .map(addr => addr.trim())
    .filter(addr => addr.length > 0);
}

function extractPercentage(record: string): number | undefined {
  const match = record.match(/;\s*pct=(\d+)/i);
  if (!match) return undefined;
  
  const pct = parseInt(match[1], 10);
  if (pct >= 0 && pct <= 100) {
    return pct;
  }
  return undefined;
}
