/**
 * DNS utility functions
 * Common DNS operations and error handling
 */

import dns from 'node:dns/promises';

/**
 * Check if error is a DNS "not found" error
 */
export function isDNSNotFoundError(err: unknown): boolean {
  const error = err as NodeJS.ErrnoException;
  return error.code === 'ENOTFOUND' || error.code === 'ENODATA';
}

/**
 * Resolve TXT records with common error handling
 */
export async function resolveTxtRecords(domain: string): Promise<string[]> {
  const txtRecords = await dns.resolveTxt(domain);
  return txtRecords.map(r => r.join(''));
}

/**
 * Filter TXT records by prefix
 */
export function filterRecordsByPrefix(records: string[], prefix: string): string[] {
  return records.filter(r => r.toLowerCase().startsWith(prefix.toLowerCase()));
}

/**
 * Resolve TXT records filtered by prefix (common pattern)
 */
export async function resolvePrefixedTxtRecords(
  domain: string, 
  prefix: string
): Promise<string[]> {
  const records = await resolveTxtRecords(domain);
  return filterRecordsByPrefix(records, prefix);
}

/**
 * Safe DNS resolution with not-found handling
 * Returns empty array if domain/record not found
 */
export async function safeResolveTxt(domain: string): Promise<string[]> {
  try {
    return await resolveTxtRecords(domain);
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return [];
    }
    throw err;
  }
}

/**
 * MX record type
 */
export interface MxRecord {
  exchange: string;
  priority: number;
}

/**
 * Safe MX resolution with not-found handling
 */
export async function safeResolveMx(domain: string): Promise<MxRecord[]> {
  try {
    return await dns.resolveMx(domain);
  } catch (err) {
    if (isDNSNotFoundError(err)) {
      return [];
    }
    throw err;
  }
}

export { dns };
