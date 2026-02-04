/**
 * AWS Route53 domain source
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execAsync = promisify(exec);

export interface AWSOptions {
  profile?: string;
  region?: string;
}

export class AWSSource implements CloudSource {
  name = 'AWS Route53';
  private options: AWSOptions;

  constructor(options: AWSOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getRoute53Domains(this.options);
  }
}

/**
 * Get all domains from AWS Route53 hosted zones
 */
export async function getRoute53Domains(options: AWSOptions = {}): Promise<string[]> {
  const profileArg = options.profile ? `--profile ${options.profile}` : '';
  const regionArg = options.region ? `--region ${options.region}` : '';

  try {
    // List all hosted zones
    const { stdout } = await execAsync(
      `aws route53 list-hosted-zones ${profileArg} ${regionArg} --output json`
    );

    const data = JSON.parse(stdout);
    const zones: Array<{ Name: string; Id: string; Config?: { PrivateZone?: boolean } }> = 
      data.HostedZones || [];

    // Filter out private zones and extract domain names
    const domains = zones
      .filter(zone => !zone.Config?.PrivateZone)
      .map(zone => zone.Name.replace(/\.$/, '')); // Remove trailing dot

    return domains;
  } catch (err) {
    const error = err as Error & { stderr?: string };
    if (error.stderr?.includes('Unable to locate credentials')) {
      throw new Error('AWS credentials not configured. Run "aws configure" or set AWS_PROFILE');
    }
    if (error.stderr?.includes('could not be found')) {
      throw new Error('AWS CLI not found. Install with: pip install awscli');
    }
    throw new Error(`Failed to list Route53 zones: ${error.message}`);
  }
}

/**
 * Get domains from a specific hosted zone
 */
export async function getRoute53ZoneDomains(
  zoneId: string, 
  options: AWSOptions = {}
): Promise<string[]> {
  const profileArg = options.profile ? `--profile ${options.profile}` : '';
  const regionArg = options.region ? `--region ${options.region}` : '';

  try {
    const { stdout } = await execAsync(
      `aws route53 list-resource-record-sets --hosted-zone-id ${zoneId} ${profileArg} ${regionArg} --output json`
    );

    const data = JSON.parse(stdout);
    const records: Array<{ Name: string; Type: string }> = data.ResourceRecordSets || [];

    // Get unique domain names (excluding subdomains for now)
    const domains = new Set<string>();
    for (const record of records) {
      if (record.Type === 'SOA' || record.Type === 'NS') {
        const domain = record.Name.replace(/\.$/, '');
        domains.add(domain);
      }
    }

    return Array.from(domains);
  } catch (err) {
    throw new Error(`Failed to list zone records: ${(err as Error).message}`);
  }
}
