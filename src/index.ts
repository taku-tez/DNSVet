/**
 * MailVet - Email security configuration scanner
 */

export { analyzeDomain, analyzeMultiple } from './core/index.js';
export { checkSPF, checkDKIM, checkDMARC, checkMX } from './checks/index.js';
export * from './types.js';
