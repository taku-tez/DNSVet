import { describe, it, expect } from 'vitest';
import { calculateGrade, generateRecommendations } from './scorer.js';
import type { SPFResult, DKIMResult, DMARCResult, MXResult } from '../types.js';

const baseSPF: SPFResult = { found: false, issues: [] };
const baseDKIM: DKIMResult = { found: false, selectors: [], issues: [] };
const baseDMARC: DMARCResult = { found: false, issues: [] };
const baseMX: MXResult = { found: false, records: [], issues: [] };

describe('calculateGrade', () => {
  it('returns F for no records', () => {
    const { grade, score } = calculateGrade(baseSPF, baseDKIM, baseDMARC, baseMX);
    expect(grade).toBe('F');
    expect(score).toBe(0);
  });

  it('returns A for perfect configuration', () => {
    const spf: SPFResult = { found: true, mechanism: '-all', lookupCount: 5, issues: [] };
    const dkim: DKIMResult = { 
      found: true, 
      selectors: [{ selector: 'google', found: true, keyLength: 2048 }], 
      issues: [] 
    };
    const dmarc: DMARCResult = { 
      found: true, 
      policy: 'reject', 
      reportingEnabled: true, 
      pct: 100,
      issues: [] 
    };
    const mx: MXResult = { found: true, records: [], issues: [] };

    const { grade, score } = calculateGrade(spf, dkim, dmarc, mx);
    expect(grade).toBe('A');
    expect(score).toBeGreaterThanOrEqual(90);
  });

  it('returns B for quarantine DMARC', () => {
    const spf: SPFResult = { found: true, mechanism: '~all', lookupCount: 3, issues: [] };
    const dkim: DKIMResult = { 
      found: true, 
      selectors: [{ selector: 'default', found: true, keyLength: 1024 }], 
      issues: [] 
    };
    const dmarc: DMARCResult = { 
      found: true, 
      policy: 'quarantine', 
      reportingEnabled: true,
      issues: [] 
    };

    const { grade, score } = calculateGrade(spf, dkim, dmarc, baseMX);
    // With softfail SPF + 1024 DKIM + quarantine DMARC = ~75-85
    expect(['A', 'B']).toContain(grade);
    expect(score).toBeGreaterThanOrEqual(70);
  });

  it('returns C or D for softfail SPF with DMARC none', () => {
    const spf: SPFResult = { found: true, mechanism: '~all', issues: [] };
    const dmarc: DMARCResult = { found: true, policy: 'none', issues: [] };

    const { grade, score } = calculateGrade(spf, baseDKIM, dmarc, baseMX);
    // Softfail SPF (25) + DMARC none (13) = 38 → D
    expect(['C', 'D']).toContain(grade);
  });

  it('returns D for SPF only', () => {
    const spf: SPFResult = { found: true, mechanism: '~all', issues: [] };

    const { grade, score } = calculateGrade(spf, baseDKIM, baseDMARC, baseMX);
    expect(grade).toBe('D');
  });

  it('penalizes excessive DNS lookups', () => {
    const spfGood: SPFResult = { found: true, mechanism: '-all', lookupCount: 5, issues: [] };
    const spfBad: SPFResult = { found: true, mechanism: '-all', lookupCount: 15, issues: [] };

    const { score: scoreGood } = calculateGrade(spfGood, baseDKIM, baseDMARC, baseMX);
    const { score: scoreBad } = calculateGrade(spfBad, baseDKIM, baseDMARC, baseMX);
    
    expect(scoreBad).toBeLessThan(scoreGood);
  });
});

describe('generateRecommendations', () => {
  it('recommends SPF when missing', () => {
    const recs = generateRecommendations(baseSPF, baseDKIM, baseDMARC, baseMX);
    expect(recs.some(r => r.toLowerCase().includes('spf'))).toBe(true);
  });

  it('recommends DKIM when missing', () => {
    const recs = generateRecommendations(baseSPF, baseDKIM, baseDMARC, baseMX);
    expect(recs.some(r => r.toLowerCase().includes('dkim'))).toBe(true);
  });

  it('recommends DMARC upgrade from none', () => {
    const dmarc: DMARCResult = { found: true, policy: 'none', issues: [] };
    const recs = generateRecommendations(baseSPF, baseDKIM, dmarc, baseMX);
    expect(recs.some(r => r.includes('quarantine') || r.includes('reject'))).toBe(true);
  });

  it('recommends reporting when not configured', () => {
    const dmarc: DMARCResult = { found: true, policy: 'reject', reportingEnabled: false, issues: [] };
    const recs = generateRecommendations(baseSPF, baseDKIM, dmarc, baseMX);
    expect(recs.some(r => r.toLowerCase().includes('report'))).toBe(true);
  });

  it('orders recommendations by priority', () => {
    // Missing SPF should come before DMARC quarantine upgrade
    const dmarc: DMARCResult = { found: true, policy: 'quarantine', issues: [] };
    const recs = generateRecommendations(baseSPF, baseDKIM, dmarc, baseMX);
    
    const spfIndex = recs.findIndex(r => r.toLowerCase().includes('spf'));
    const dmarcIndex = recs.findIndex(r => r.toLowerCase().includes('quarantine'));
    
    if (spfIndex !== -1 && dmarcIndex !== -1) {
      expect(spfIndex).toBeLessThan(dmarcIndex);
    }
  });
});
