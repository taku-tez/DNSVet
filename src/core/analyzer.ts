/**
 * Domain email security analyzer
 */

import { checkSPF, checkDKIM, checkDMARC, checkMX, checkBIMI, checkMTASTS, checkTLSRPT, checkARCReadiness, checkDNSSEC, checkWhois } from '../checks/index.js';
import { calculateGrade, generateRecommendations } from './scorer.js';
import type { DomainResult, ScanOptions, SPFResult, DKIMResult, DMARCResult, MXResult, BIMIResult, MTASTSResult, TLSRPTResult, DNSSECResult, WhoisResult } from '../types.js';
import { COMMON_DKIM_SELECTORS, normalizeDomain } from '../types.js';
import { isValidDomain, setDnsResolver, clearDnsCache } from '../utils/index.js';

/**
 * Create a failed result for a check that errored
 */
function createFailedResult<T extends { found: boolean; issues: Array<{ severity: string; message: string; recommendation?: string }> }>(
  checkName: string, 
  error: string, 
  defaults: Omit<T, 'found' | 'issues'>
): T {
  return {
    found: false,
    issues: [{
      severity: 'high' as const,
      message: `${checkName} check failed: ${error}`,
      recommendation: 'Check DNS configuration and try again'
    }],
    ...defaults
  } as T;
}

export async function analyzeDomain(
  domain: string, 
  options: ScanOptions = {}
): Promise<DomainResult> {
  // Normalize domain using shared function
  domain = normalizeDomain(domain);

  // Set custom DNS resolver if specified
  setDnsResolver(options.resolver);

  // Validate domain format
  if (!isValidDomain(domain)) {
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
      error: `Invalid domain format: "${domain}"`,
    };
  }

  // Run all checks in parallel with optional timeout using allSettled
  // Fall back to default selectors if not specified or empty array
  const dkimSelectors = options.dkimSelectors?.length ? options.dkimSelectors : COMMON_DKIM_SELECTORS;
  const timeout = options.timeout || 10000;
  
  /**
   * Wrap a promise with timeout. On timeout, the promise is rejected but
   * the underlying operation may continue (DNS queries cannot be cancelled).
   * HTTP requests (MTA-STS/TLS-RPT) use AbortSignal internally for true cancellation.
   * Promise.allSettled handles rejections gracefully without losing other results.
   */
  const wrapWithTimeout = async <T>(promise: Promise<T>, name: string): Promise<T> => {
    let timeoutId: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => reject(new Error(`${name} check timed out`)), timeout);
    });
    
    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      clearTimeout(timeoutId!);
    }
  };

  // Check toggle defaults (all enabled unless explicitly disabled)
  const checks = options.checks || {};
  const isEnabled = (check: keyof typeof checks): boolean => checks[check] !== false;

  // Build check promises (skip disabled checks)
  const checkPromises = [
    isEnabled('spf') ? wrapWithTimeout(checkSPF(domain), 'SPF') : Promise.resolve({ found: false, skipped: true, issues: [] } as SPFResult),
    isEnabled('dkim') ? wrapWithTimeout(checkDKIM(domain, dkimSelectors), 'DKIM') : Promise.resolve({ found: false, skipped: true, selectors: [], issues: [] } as DKIMResult),
    isEnabled('dmarc') ? wrapWithTimeout(checkDMARC(domain), 'DMARC') : Promise.resolve({ found: false, skipped: true, issues: [] } as DMARCResult),
    isEnabled('mx') ? wrapWithTimeout(checkMX(domain), 'MX') : Promise.resolve({ found: false, skipped: true, records: [], issues: [] } as MXResult),
    isEnabled('bimi') ? wrapWithTimeout(checkBIMI(domain), 'BIMI') : Promise.resolve({ found: false, skipped: true, issues: [] } as BIMIResult),
    isEnabled('mtaSts') ? wrapWithTimeout(checkMTASTS(domain, { timeout }), 'MTA-STS') : Promise.resolve({ found: false, skipped: true, issues: [] } as MTASTSResult),
    isEnabled('tlsRpt') ? wrapWithTimeout(checkTLSRPT(domain, { verifyEndpoints: options.verifyTlsRptEndpoints, timeout }), 'TLS-RPT') : Promise.resolve({ found: false, skipped: true, issues: [] } as TLSRPTResult),
    isEnabled('dnssec') ? wrapWithTimeout(checkDNSSEC(domain, { resolver: options.resolver }), 'DNSSEC') : Promise.resolve({ enabled: false, skipped: true, issues: [] } as DNSSECResult),
    isEnabled('whois') ? wrapWithTimeout(checkWhois(domain, { timeout }), 'WHOIS') : Promise.resolve({ found: false, skipped: true, issues: [] } as WhoisResult),
  ] as const;

  // Use Promise.allSettled to handle individual failures gracefully
  const [spfResult, dkimResult, dmarcResult, mxResult, bimiResult, mtaStsResult, tlsRptResult, dnssecResult, whoisResult] = await Promise.allSettled(checkPromises);

  // Extract results, creating failed results for rejected promises
  const spf: SPFResult = spfResult.status === 'fulfilled' 
    ? spfResult.value 
    : createFailedResult<SPFResult>('SPF', spfResult.reason?.message || 'Unknown error', {});

  const dkim: DKIMResult = dkimResult.status === 'fulfilled'
    ? dkimResult.value
    : createFailedResult<DKIMResult>('DKIM', dkimResult.reason?.message || 'Unknown error', { selectors: [] });

  const dmarc: DMARCResult = dmarcResult.status === 'fulfilled'
    ? dmarcResult.value
    : createFailedResult<DMARCResult>('DMARC', dmarcResult.reason?.message || 'Unknown error', {});

  const mx: MXResult = mxResult.status === 'fulfilled'
    ? mxResult.value
    : createFailedResult<MXResult>('MX', mxResult.reason?.message || 'Unknown error', { records: [] });

  const bimi: BIMIResult | undefined = bimiResult.status === 'fulfilled'
    ? bimiResult.value ?? undefined
    : bimiResult.reason ? createFailedResult<BIMIResult>('BIMI', bimiResult.reason?.message || 'Unknown error', {}) : undefined;

  const mtaSts: MTASTSResult | undefined = mtaStsResult.status === 'fulfilled'
    ? mtaStsResult.value ?? undefined
    : mtaStsResult.reason ? createFailedResult<MTASTSResult>('MTA-STS', mtaStsResult.reason?.message || 'Unknown error', {}) : undefined;

  const tlsRpt: TLSRPTResult | undefined = tlsRptResult.status === 'fulfilled'
    ? tlsRptResult.value ?? undefined
    : tlsRptResult.reason ? createFailedResult<TLSRPTResult>('TLS-RPT', tlsRptResult.reason?.message || 'Unknown error', {}) : undefined;

  // DNSSEC result (uses different structure, handle separately)
  const dnssec: DNSSECResult | undefined = dnssecResult.status === 'fulfilled'
    ? dnssecResult.value
    : { enabled: false, issues: [{ severity: 'high' as const, message: `DNSSEC check failed: ${dnssecResult.reason?.message || 'Unknown error'}` }] };

  // WHOIS/RDAP result
  const whois: WhoisResult | undefined = whoisResult.status === 'fulfilled'
    ? whoisResult.value
    : { found: false, issues: [{ severity: 'info' as const, message: `WHOIS check failed: ${whoisResult.reason?.message || 'Unknown error'}` }] };

  // ARC readiness is derived from SPF/DKIM/DMARC — skip if any prerequisite is disabled
  const arcSkipped = !isEnabled('arc') || !isEnabled('spf') || !isEnabled('dkim') || !isEnabled('dmarc');
  const arc = arcSkipped 
    ? { ready: false, canSign: false, canValidate: false, skipped: true, issues: [] }
    : checkARCReadiness(spf, dkim, dmarc);

  // BIMI prerequisite check: requires DMARC quarantine or reject
  if (bimi?.found) {
    if (!dmarc.found) {
      bimi.issues.push({
        severity: 'high',
        message: 'BIMI requires DMARC to be configured',
        recommendation: 'Add a DMARC record with p=quarantine or p=reject'
      });
    } else if (dmarc.policy === 'none' || !dmarc.policy) {
      bimi.issues.push({
        severity: 'high',
        message: 'BIMI requires DMARC policy of quarantine or reject',
        recommendation: 'Upgrade DMARC policy from none to quarantine or reject'
      });
    }
  }

  // MTA-STS / MX consistency check
  if (mtaSts?.found && mtaSts.policy?.mx && mtaSts.policy.mx.length > 0 && mx.found) {
    const mtaStsMxPatterns = mtaSts.policy.mx;
    const mxHosts = mx.records.map(r => r.exchange.toLowerCase().replace(/\.$/, ''));
    
    for (const mxHost of mxHosts) {
      const matched = mtaStsMxPatterns.some(pattern => {
        const p = pattern.toLowerCase();
        if (p.startsWith('*.')) {
          // Wildcard: *.example.com matches mail.example.com
          const suffix = p.slice(1); // .example.com
          return mxHost.endsWith(suffix) || mxHost === p.slice(2);
        }
        return mxHost === p;
      });
      
      if (!matched) {
        mtaSts.issues.push({
          severity: 'high',
          message: `MX host "${mxHost}" not covered by MTA-STS policy`,
          recommendation: `Add "mx: ${mxHost}" or appropriate wildcard to MTA-STS policy`
        });
      }
    }
  }

  const { grade, score } = calculateGrade(spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt, arc, dnssec);
  const recommendations = generateRecommendations(spf, dkim, dmarc, mx, bimi, mtaSts, tlsRpt, arc, dnssec);

  // Append WHOIS recommendations from issues
  if (whois && !whois.skipped && whois.issues.length > 0) {
    for (const issue of whois.issues) {
      if (issue.recommendation && issue.severity !== 'info') {
        const icon = issue.severity === 'critical' ? '🚨' : issue.severity === 'high' ? '⚠️' : '💡';
        const label = issue.severity === 'critical' ? '[緊急]' : issue.severity === 'high' ? '[重要]' : '[推奨]';
        recommendations.push(`${icon} ${label} ${issue.recommendation}`);
      }
    }
  }

  // Collect any check-level errors for the error field (including advanced checks)
  const errors: string[] = [];
  if (spfResult.status === 'rejected') errors.push(`SPF: ${spfResult.reason?.message}`);
  if (dkimResult.status === 'rejected') errors.push(`DKIM: ${dkimResult.reason?.message}`);
  if (dmarcResult.status === 'rejected') errors.push(`DMARC: ${dmarcResult.reason?.message}`);
  if (mxResult.status === 'rejected') errors.push(`MX: ${mxResult.reason?.message}`);
  if (bimiResult.status === 'rejected') errors.push(`BIMI: ${bimiResult.reason?.message}`);
  if (mtaStsResult.status === 'rejected') errors.push(`MTA-STS: ${mtaStsResult.reason?.message}`);
  if (tlsRptResult.status === 'rejected') errors.push(`TLS-RPT: ${tlsRptResult.reason?.message}`);
  if (dnssecResult.status === 'rejected') errors.push(`DNSSEC: ${dnssecResult.reason?.message}`);
  if (whoisResult.status === 'rejected') errors.push(`WHOIS: ${whoisResult.reason?.message}`);

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
    dnssec,
    whois,
    recommendations,
    ...(errors.length > 0 ? { error: errors.join('; ') } : {}),
  };
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
    clearDnsCache();
    const batchResults = await Promise.all(
      batch.map(domain => analyzeDomain(domain, options))
    );
    results.push(...batchResults);
  }

  return results;
}
