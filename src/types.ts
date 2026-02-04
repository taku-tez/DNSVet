/**
 * MailVet - Email Security Configuration Scanner
 * Type definitions
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';
export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info' | 'error';

export interface Issue {
  severity: Severity;
  message: string;
  recommendation?: string;
}

export interface SPFResult {
  found: boolean;
  record?: string;
  mechanism?: string; // -all, ~all, ?all, +all
  lookupCount?: number;
  includes?: string[];
  issues: Issue[];
}

export interface DKIMSelector {
  selector: string;
  found: boolean;
  keyType?: string;
  keyLength?: number;
  record?: string;
}

export interface DKIMResult {
  found: boolean;
  selectors: DKIMSelector[];
  issues: Issue[];
}

export interface DMARCResult {
  found: boolean;
  record?: string;
  policy?: 'none' | 'quarantine' | 'reject';
  subdomainPolicy?: 'none' | 'quarantine' | 'reject';
  reportingEnabled?: boolean;
  rua?: string[];
  ruf?: string[];
  pct?: number;
  issues: Issue[];
}

export interface MXRecord {
  exchange: string;
  priority: number;
}

export interface MXResult {
  found: boolean;
  records: MXRecord[];
  issues: Issue[];
}

export interface DomainResult {
  domain: string;
  grade: Grade;
  score: number;
  timestamp: string;
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  mx: MXResult;
  recommendations: string[];
  error?: string;
}

export interface ScanOptions {
  domain?: string;
  file?: string;
  stdin?: boolean;
  aws?: boolean;
  awsProfile?: string;
  gcp?: boolean;
  gcpProject?: string;
  azure?: boolean;
  azureSubscription?: string;
  cloudflare?: boolean;
  json?: boolean;
  verbose?: boolean;
  dkimSelectors?: string[];
  timeout?: number;
  concurrency?: number;
}

export interface CloudSource {
  name: string;
  getDomains(): Promise<string[]>;
}

// Common DKIM selectors used by popular email providers
export const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1', // Microsoft 365
  'selector2', // Microsoft 365
  'k1',
  'k2',
  's1',
  's2',
  'dkim',
  'mail',
  'email',
  'smtp',
  'mandrill',
  'mailchimp',
  'amazonses',
  'ses',
  'sendgrid',
  'sg',
  'postmark',
  'pm',
  'mailgun',
  'mg',
  'sparkpost',
  'zendesk',
  'zendesk1',
  'zendesk2',
] as const;
