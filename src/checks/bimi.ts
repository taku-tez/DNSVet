/**
 * BIMI (Brand Indicators for Message Identification) checker
 * 
 * BIMI allows brands to display their logo in email clients.
 * Requires valid DMARC with p=quarantine or p=reject.
 */

import dns from 'node:dns/promises';
import type { Issue } from '../types.js';

export interface BIMIResult {
  found: boolean;
  record?: string;
  version?: string;
  logoUrl?: string;
  certificateUrl?: string;
  issues: Issue[];
}

export async function checkBIMI(domain: string): Promise<BIMIResult> {
  const issues: Issue[] = [];
  const bimiDomain = `default._bimi.${domain}`;

  try {
    const txtRecords = await dns.resolveTxt(bimiDomain);
    const bimiRecords = txtRecords
      .map(r => r.join(''))
      .filter(r => r.toLowerCase().startsWith('v=bimi1'));

    if (bimiRecords.length === 0) {
      return {
        found: false,
        issues: [{
          severity: 'info',
          message: 'No BIMI record found',
          recommendation: 'Consider adding BIMI to display your brand logo in email clients'
        }]
      };
    }

    if (bimiRecords.length > 1) {
      issues.push({
        severity: 'medium',
        message: `Multiple BIMI records found (${bimiRecords.length})`,
        recommendation: 'Only one BIMI record should exist'
      });
    }

    const record = bimiRecords[0];
    const version = extractTag(record, 'v');
    const logoUrl = extractTag(record, 'l');
    const certificateUrl = extractTag(record, 'a');

    // Check logo URL
    if (!logoUrl) {
      issues.push({
        severity: 'high',
        message: 'BIMI record missing logo URL (l=)',
        recommendation: 'Add l= tag with URL to your SVG logo'
      });
    } else if (!logoUrl.startsWith('https://')) {
      issues.push({
        severity: 'high',
        message: 'BIMI logo URL must use HTTPS',
        recommendation: 'Update logo URL to use HTTPS'
      });
    } else if (!logoUrl.endsWith('.svg')) {
      issues.push({
        severity: 'medium',
        message: 'BIMI logo should be SVG Tiny PS format',
        recommendation: 'Use SVG Tiny PS format for maximum compatibility'
      });
    }

    // Check VMC certificate (optional but recommended)
    if (!certificateUrl) {
      issues.push({
        severity: 'low',
        message: 'No VMC (Verified Mark Certificate) specified',
        recommendation: 'Consider obtaining a VMC for broader email client support'
      });
    }

    return {
      found: true,
      record,
      version,
      logoUrl,
      certificateUrl,
      issues
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        issues: [{
          severity: 'info',
          message: 'No BIMI record found',
          recommendation: 'Consider adding BIMI to display your brand logo in email clients'
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
