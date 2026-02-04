/**
 * Google Cloud DNS domain source
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execAsync = promisify(exec);

export interface GCPOptions {
  project?: string;
  account?: string;
}

export class GCPSource implements CloudSource {
  name = 'Google Cloud DNS';
  private options: GCPOptions;

  constructor(options: GCPOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getCloudDNSDomains(this.options);
  }
}

/**
 * Get all domains from Google Cloud DNS managed zones
 */
export async function getCloudDNSDomains(options: GCPOptions = {}): Promise<string[]> {
  const projectArg = options.project ? `--project=${options.project}` : '';
  const accountArg = options.account ? `--account=${options.account}` : '';

  try {
    // List all managed zones
    const { stdout } = await execAsync(
      `gcloud dns managed-zones list ${projectArg} ${accountArg} --format=json`
    );

    const zones: Array<{ 
      name: string; 
      dnsName: string; 
      visibility?: string;
    }> = JSON.parse(stdout) || [];

    // Filter out private zones and extract domain names
    const domains = zones
      .filter(zone => zone.visibility !== 'private')
      .map(zone => zone.dnsName.replace(/\.$/, '')); // Remove trailing dot

    return domains;
  } catch (err) {
    const error = err as Error & { stderr?: string };
    if (error.stderr?.includes('not logged in') || error.stderr?.includes('credentials')) {
      throw new Error('GCP credentials not configured. Run "gcloud auth login"');
    }
    if (error.stderr?.includes('not found') || error.stderr?.includes('command not found')) {
      throw new Error('gcloud CLI not found. Install from: https://cloud.google.com/sdk/install');
    }
    if (error.stderr?.includes('project')) {
      throw new Error('GCP project not set. Use --gcp-project or run "gcloud config set project PROJECT_ID"');
    }
    throw new Error(`Failed to list Cloud DNS zones: ${error.message}`);
  }
}

/**
 * Get all projects with Cloud DNS enabled
 */
export async function listGCPProjects(): Promise<string[]> {
  try {
    const { stdout } = await execAsync(
      `gcloud projects list --format="value(projectId)"`
    );

    return stdout.trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Get domains from multiple GCP projects
 */
export async function getCloudDNSDomainsMultiProject(
  projects?: string[]
): Promise<string[]> {
  const projectList = projects || await listGCPProjects();
  const allDomains: string[] = [];

  for (const project of projectList) {
    try {
      const domains = await getCloudDNSDomains({ project });
      allDomains.push(...domains);
    } catch {
      // Skip projects without Cloud DNS or access
    }
  }

  return [...new Set(allDomains)]; // Deduplicate
}
