/**
 * Domain email security analyzer
 */

import { checkSPF, checkDKIM, checkDMARC, checkMX, checkBIMI, checkMTASTS, checkTLSRPT, checkARCReadiness } from '../checks/index.js';
import { calculateGrade, generateRecommendations } from './scorer.js';
import type { DomainResult, ScanOptions } from '../types.js';
import { COMMON_DKIM_SELECTORS } from '../types.js';

export async function analyzeDomain(
  domain: string, 
  options: ScanOptions = {}
): Promise<DomainResult> {
  const startTime = Date.now();
  
  // Normalize domain
  domain = domain.toLowerCase().trim();
  if (domain.startsWith('http://') || domain.startsWith('https://')) {
    domain = new URL(domain).hostname;
  }
  // Remove trailing dot if present
  domain = domain.replace(/\.$/, '');

  try {
    // Run all checks in parallel
    const dkimSelectors = options.dkimSelectors || COMMON_DKIM_SELECTORS;
    
    const [spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt] = await Promise.all([
      checkSPF(domain),
      checkDKIM(domain, dkimSelectors),
      checkDMARC(domain),
      checkMX(domain),
      checkBIMI(domain),
      checkMTASTS(domain),
      checkTLSRPT(domain),
    ]);

    // ARC readiness is derived from other checks
    const arc = checkARCReadiness(spf, dkim, dmarc);

    const { grade, score } = calculateGrade(spf, dkim, dmarc, mx);
    const recommendations = generateRecommendations(spf, dkim, dmarc, mx);

    return {
      domain,
      grade,
      score,
      timestamp: new Date().toISOString(),
      spf,
      dkim,
      dmarc,
      mx,
      bimi,
      mtaSts,
      tlsRpt,
      arc,
      recommendations,
    };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    return {
      domain,
      grade: 'F',
      score: 0,
      timestamp: new Date().toISOString(),
      spf: { found: false, issues: [] },
      dkim: { found: false, selectors: [], issues: [] },
      dmarc: { found: false, issues: [] },
      mx: { found: false, records: [], issues: [] },
      recommendations: [],
      error,
    };
  }
}

export async function analyzeMultiple(
  domains: string[],
  options: ScanOptions = {}
): Promise<DomainResult[]> {
  const concurrency = options.concurrency || 5;
  const results: DomainResult[] = [];

  // Process in batches
  for (let i = 0; i < domains.length; i += concurrency) {
    const batch = domains.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(domain => analyzeDomain(domain, options))
    );
    results.push(...batchResults);
  }

  return results;
}
