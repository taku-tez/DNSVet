/**
 * TLS-RPT (SMTP TLS Reporting) checker
 * 
 * TLS-RPT enables receiving reports about TLS connectivity issues
 * when other mail servers try to send email to your domain.
 */

import dns from 'node:dns/promises';
import type { Issue } from '../types.js';

export interface TLSRPTResult {
  found: boolean;
  record?: string;
  version?: string;
  rua?: string[];
  issues: Issue[];
}

export async function checkTLSRPT(domain: string): Promise<TLSRPTResult> {
  const issues: Issue[] = [];
  const tlsrptDomain = `_smtp._tls.${domain}`;

  try {
    const txtRecords = await dns.resolveTxt(tlsrptDomain);
    const tlsrptRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=tlsrpt'));

    if (tlsrptRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'low',
          message: 'No TLS-RPT record found',
          recommendation: 'Add TLS-RPT to receive reports about TLS connection failures'
        }]
      };
    }

    if (tlsrptRecords.length > 1) {
      issues.push({
        severity: 'medium',
        message: `Multiple TLS-RPT records found (${tlsrptRecords.length})`,
        recommendation: 'Only one TLS-RPT record should exist'
      });
    }

    const record = tlsrptRecords[0];
    const version = extractTag(record, 'v');
    const rua = extractReportingAddresses(record);

    // Check reporting addresses
    if (rua.length === 0) {
      issues.push({
        severity: 'high',
        message: 'TLS-RPT record has no reporting addresses (rua=)',
        recommendation: 'Add rua= tag with mailto: or https: reporting endpoints'
      });
    } else {
      // Validate addresses
      for (const addr of rua) {
        if (!addr.startsWith('mailto:') && !addr.startsWith('https://')) {
          issues.push({
            severity: 'medium',
            message: `Invalid TLS-RPT reporting address: ${addr}`,
            recommendation: 'Use mailto: or https: scheme for reporting addresses'
          });
        }
      }
    }

    return {
      found: true,
      record,
      version,
      rua,
      issues
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'low',
          message: 'No TLS-RPT record found',
          recommendation: 'Add TLS-RPT to receive reports about TLS connection failures'
        }]
      };
    }
    throw err;
  }
}

function extractTag(record: string, tag: string): string | undefined {
  const regex = new RegExp(`${tag}=([^;\\s]+)`, 'i');
  const match = record.match(regex);
  return match ? match[1] : undefined;
}

function extractReportingAddresses(record: string): string[] {
  const match = record.match(/rua=([^;]+)/i);
  if (!match) return [];

  return match[1]
    .split(',')
    .map(addr => addr.trim())
    .filter(addr => addr.length > 0);
}
