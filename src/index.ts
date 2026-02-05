/**
 * MailVet - Email security configuration scanner
 */

export { analyzeDomain, analyzeMultiple } from './core/index.js';
export { checkSPF, checkDKIM, checkDMARC, checkMX } from './checks/index.js';
export { 
  AWSSource, 
  GCPSource, 
  AzureSource, 
  CloudflareSource,
  getRoute53Domains,
  getCloudDNSDomains,
  getCloudDNSDomainsOrg,
  getAzureDNSDomains,
  getCloudflareDomains,
} from './sources/index.js';
export * from './types.js';
