/**
 * MX (Mail Exchange) record checker
 */

import dns from 'node:dns/promises';
import type { MXResult, MXRecord, Issue } from '../types.js';

export async function checkMX(domain: string): Promise<MXResult> {
  const issues: Issue[] = [];

  try {
    const mxRecords = await dns.resolveMx(domain);

    if (mxRecords.length === 0) {
      return {
        found: false,
        records: [],
        issues: [{
          severity: 'info',
          message: 'No MX records found',
          recommendation: 'Add MX records if this domain should receive email'
        }]
      };
    }

    // Sort by priority
    const records: MXRecord[] = mxRecords
      .sort((a, b) => a.priority - b.priority)
      .map(r => ({
        exchange: r.exchange,
        priority: r.priority
      }));

    // Check for single point of failure
    if (records.length === 1) {
      issues.push({
        severity: 'low',
        message: 'Only one MX record - no redundancy',
        recommendation: 'Consider adding backup MX servers'
      });
    }

    // Check for null MX (RFC 7505)
    const hasNullMX = records.some(r => r.exchange === '.' || r.exchange === '');
    if (hasNullMX) {
      issues.push({
        severity: 'info',
        message: 'Null MX record present - domain explicitly does not receive mail',
        recommendation: 'This is intentional if the domain should not receive email'
      });
    }

    // Check priority distribution
    const priorities = records.map(r => r.priority);
    const allSamePriority = priorities.every(p => p === priorities[0]);
    if (records.length > 1 && allSamePriority) {
      issues.push({
        severity: 'info',
        message: 'All MX records have same priority - round-robin delivery',
        recommendation: 'Consider different priorities for primary/backup servers'
      });
    }

    // Identify email provider
    const provider = identifyEmailProvider(records);
    if (provider) {
      issues.push({
        severity: 'info',
        message: `Email provider detected: ${provider}`
      });
    }

    return {
      found: true,
      records,
      issues
    };
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOTFOUND' ||
        (err as NodeJS.ErrnoException).code === 'ENODATA') {
      return {
        found: false,
        records: [],
        issues: [{
          severity: 'info',
          message: 'No MX records found',
          recommendation: 'Add MX records if this domain should receive email'
        }]
      };
    }
    throw err;
  }
}

function identifyEmailProvider(records: MXRecord[]): string | undefined {
  const exchanges = records.map(r => r.exchange.toLowerCase());
  
  const providers: Array<{ pattern: RegExp; name: string }> = [
    { pattern: /google\.com$|googlemail\.com$/i, name: 'Google Workspace' },
    { pattern: /outlook\.com$|protection\.outlook\.com$/i, name: 'Microsoft 365' },
    { pattern: /pphosted\.com$/i, name: 'Proofpoint' },
    { pattern: /mimecast\.com$/i, name: 'Mimecast' },
    { pattern: /barracuda(networks)?\.com$/i, name: 'Barracuda' },
    { pattern: /messagelabs\.com$/i, name: 'Symantec/Broadcom' },
    { pattern: /zoho\.com$/i, name: 'Zoho Mail' },
    { pattern: /yahoodns\.net$/i, name: 'Yahoo Mail' },
    { pattern: /secureserver\.net$/i, name: 'GoDaddy' },
    { pattern: /emailsrvr\.com$/i, name: 'Rackspace' },
    { pattern: /amazonaws\.com$/i, name: 'Amazon SES' },
    { pattern: /mailgun\.org$/i, name: 'Mailgun' },
    { pattern: /sendgrid\.net$/i, name: 'SendGrid' },
    { pattern: /postmarkapp\.com$/i, name: 'Postmark' },
    { pattern: /mx\.icloud\.com$/i, name: 'Apple iCloud' },
    { pattern: /fastmail\.com$/i, name: 'Fastmail' },
  ];

  for (const { pattern, name } of providers) {
    if (exchanges.some(ex => pattern.test(ex))) {
      return name;
    }
  }

  return undefined;
}
