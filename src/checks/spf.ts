/**
 * SPF (Sender Policy Framework) checker
 */

import dns from 'node:dns/promises';
import type { SPFResult, Issue } from '../types.js';

const MAX_DNS_LOOKUPS = 10;

export async function checkSPF(domain: string): Promise<SPFResult> {
  const issues: Issue[] = [];
  
  try {
    const txtRecords = await dns.resolveTxt(domain);
    const spfRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=spf1'));

    if (spfRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No SPF record found',
          recommendation: 'Add an SPF record to prevent email spoofing'
        }]
      };
    }

    if (spfRecords.length > 1) {
      issues.push({
        severity: 'high',
        message: `Multiple SPF records found (${spfRecords.length})`,
        recommendation: 'Only one SPF record should exist per domain'
      });
    }

    const record = spfRecords[0];
    const mechanism = extractMechanism(record);
    const includes = extractIncludes(record);
    const lookupCount = countDNSLookups(record);

    // Check mechanism strength
    if (mechanism === '+all') {
      issues.push({
        severity: 'critical',
        message: 'SPF uses +all (pass all) - effectively no protection',
        recommendation: 'Change to -all (hardfail) for maximum protection'
      });
    } else if (mechanism === '?all') {
      issues.push({
        severity: 'high',
        message: 'SPF uses ?all (neutral) - weak protection',
        recommendation: 'Change to -all (hardfail) for maximum protection'
      });
    } else if (mechanism === '~all') {
      issues.push({
        severity: 'medium',
        message: 'SPF uses ~all (softfail) - consider using hardfail',
        recommendation: 'Change to -all (hardfail) when ready for stricter enforcement'
      });
    } else if (mechanism === '-all') {
      // Good!
    } else {
      issues.push({
        severity: 'high',
        message: 'SPF record has no all mechanism',
        recommendation: 'Add -all at the end of your SPF record'
      });
    }

    // Check DNS lookup count
    if (lookupCount > MAX_DNS_LOOKUPS) {
      issues.push({
        severity: 'high',
        message: `SPF record exceeds DNS lookup limit (${lookupCount}/${MAX_DNS_LOOKUPS})`,
        recommendation: 'Reduce the number of include/redirect mechanisms'
      });
    } else if (lookupCount > 7) {
      issues.push({
        severity: 'medium',
        message: `SPF record is close to DNS lookup limit (${lookupCount}/${MAX_DNS_LOOKUPS})`,
        recommendation: 'Consider flattening SPF record to avoid future issues'
      });
    }

    // Check for deprecated ptr mechanism
    if (record.toLowerCase().includes(' ptr')) {
      issues.push({
        severity: 'medium',
        message: 'SPF record uses deprecated ptr mechanism',
        recommendation: 'Replace ptr with explicit IP ranges or include statements'
      });
    }

    return {
      found: true,
      record,
      mechanism,
      lookupCount,
      includes,
      issues
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'critical',
          message: 'No SPF record found',
          recommendation: 'Add an SPF record to prevent email spoofing'
        }]
      };
    }
    throw err;
  }
}

function extractMechanism(record: string): string | undefined {
  const match = record.match(/([+\-~?]?)all\b/i);
  if (match) {
    const qualifier = match[1] || '+'; // Default is +
    return `${qualifier}all`;
  }
  return undefined;
}

function extractIncludes(record: string): string[] {
  const includes: string[] = [];
  const regex = /include:([^\s]+)/gi;
  let match;
  while ((match = regex.exec(record)) !== null) {
    includes.push(match[1]);
  }
  return includes;
}

function countDNSLookups(record: string): number {
  // Mechanisms that require DNS lookups: include, a, mx, ptr, exists, redirect
  const lookupMechanisms = ['include:', 'a:', 'a ', 'mx:', 'mx ', 'ptr:', 'ptr ', 'exists:', 'redirect='];
  let count = 0;

  const lower = record.toLowerCase();
  for (const mech of lookupMechanisms) {
    const regex = new RegExp(mech.trim().replace(':', ':'), 'gi');
    const matches = lower.match(regex);
    if (matches) {
      count += matches.length;
    }
  }

  // Also count implicit a and mx (without domain specified)
  if (/\sa\s|^a\s|\sa$/i.test(record)) count++;
  if (/\smx\s|^mx\s|\smx$/i.test(record)) count++;

  return count;
}
