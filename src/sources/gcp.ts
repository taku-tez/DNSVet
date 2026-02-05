/**
 * Google Cloud DNS domain source
 * 
 * Authentication methods (in order of precedence):
 * 1. Service account key file (--gcp-key-file or GOOGLE_APPLICATION_CREDENTIALS)
 * 2. gcloud auth (gcloud auth login / gcloud auth application-default login)
 * 3. Compute Engine default service account
 * 4. Workload Identity (GKE)
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execAsync = promisify(exec);

export interface GCPOptions {
  project?: string;
  account?: string;
  keyFile?: string;
  impersonateServiceAccount?: string;
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
 * Build CLI arguments and environment for GCP commands
 */
function buildGCPConfig(options: GCPOptions): { args: string; env: Record<string, string> } {
  const args: string[] = [];
  const env: Record<string, string> = {};

  if (options.project) {
    args.push(`--project=${options.project}`);
  }
  if (options.account) {
    args.push(`--account=${options.account}`);
  }
  if (options.impersonateServiceAccount) {
    args.push(`--impersonate-service-account=${options.impersonateServiceAccount}`);
  }
  if (options.keyFile) {
    env.GOOGLE_APPLICATION_CREDENTIALS = options.keyFile;
  }

  return { args: args.join(' '), env };
}

/**
 * Get all domains from Google Cloud DNS managed zones
 */
export async function getCloudDNSDomains(options: GCPOptions = {}): Promise<string[]> {
  const { args, env } = buildGCPConfig(options);

  try {
    // List all managed zones
    const { stdout } = await execAsync(
      `gcloud dns managed-zones list ${args} --format=json`,
      { env: { ...process.env, ...env } }
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
 * Get all projects accessible to the current user/service account
 */
export async function listGCPProjects(options: GCPOptions = {}): Promise<string[]> {
  const { args, env } = buildGCPConfig(options);

  try {
    const { stdout } = await execAsync(
      `gcloud projects list ${args} --format="value(projectId)"`,
      { env: { ...process.env, ...env } }
    );

    return stdout.trim().split('\n').filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Get all projects in an organization
 */
export async function listOrgProjects(
  orgId: string,
  options: GCPOptions = {}
): Promise<string[]> {
  const { args, env } = buildGCPConfig(options);

  try {
    const { stdout } = await execAsync(
      `gcloud projects list --filter="parent.id=${orgId}" ${args} --format="value(projectId)"`,
      { env: { ...process.env, ...env } }
    );

    return stdout.trim().split('\n').filter(Boolean);
  } catch (err) {
    // Fallback to listing all accessible projects
    console.error(`Could not list org projects, falling back to accessible projects`);
    return listGCPProjects(options);
  }
}

export interface OrgScanResult {
  domains: string[];
  scannedProjects: number;
  skippedProjects: number;
  projectsWithZones: string[];
}

/**
 * Get domains from all projects in an organization (parallel scan)
 * 
 * Strategy: Skip DNS API check and directly try to list zones.
 * This is faster than checking API status for each project.
 */
export async function getCloudDNSDomainsOrg(
  options: GCPOptions & { 
    orgId?: string; 
    concurrency?: number;
    verbose?: boolean;
  } = {}
): Promise<OrgScanResult> {
  const concurrency = options.concurrency || 50; // High concurrency for large orgs
  const verbose = options.verbose || false;

  // Get all projects
  let projects: string[];
  if (options.orgId) {
    if (verbose) console.error(`Listing projects in org ${options.orgId}...`);
    projects = await listOrgProjects(options.orgId, options);
  } else {
    if (verbose) console.error(`Listing all accessible projects...`);
    projects = await listGCPProjects(options);
  }

  if (verbose) console.error(`Found ${projects.length} projects, scanning for DNS zones...`);

  // Directly scan all projects (faster than checking API first)
  const allDomains: string[] = [];
  const projectsWithZones: string[] = [];
  let scanned = 0;
  let skipped = 0;

  for (let i = 0; i < projects.length; i += concurrency) {
    const batch = projects.slice(i, i + concurrency);
    
    if (verbose && i > 0) {
      console.error(`  Progress: ${i}/${projects.length} projects...`);
    }

    const results = await Promise.allSettled(
      batch.map(async (project) => {
        try {
          const domains = await getCloudDNSDomainsWithTimeout({ ...options, project }, 3000);
          return { project, domains, error: null };
        } catch (err) {
          return { project, domains: [] as string[], error: err };
        }
      })
    );

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const { project, domains, error } = result.value;
        if (!error && domains.length > 0) {
          allDomains.push(...domains);
          projectsWithZones.push(project);
          scanned++;
          if (verbose) {
            console.error(`  ✓ ${project}: ${domains.length} zones`);
          }
        } else if (!error) {
          scanned++;
        } else {
          skipped++;
        }
      } else {
        skipped++;
      }
    }
  }

  if (verbose) {
    console.error(`Scan complete: ${projectsWithZones.length} projects with zones, ${skipped} skipped`);
  }

  return {
    domains: [...new Set(allDomains)],
    scannedProjects: scanned,
    skippedProjects: skipped,
    projectsWithZones,
  };
}

/**
 * Get Cloud DNS domains with timeout
 */
async function getCloudDNSDomainsWithTimeout(
  options: GCPOptions,
  timeoutMs: number
): Promise<string[]> {
  const { args, env } = buildGCPConfig(options);

  try {
    const { stdout } = await execAsync(
      `gcloud dns managed-zones list ${args} --format=json`,
      { env: { ...process.env, ...env }, timeout: timeoutMs }
    );

    const zones: Array<{ 
      name: string; 
      dnsName: string; 
      visibility?: string;
    }> = JSON.parse(stdout) || [];

    return zones
      .filter(zone => zone.visibility !== 'private')
      .map(zone => zone.dnsName.replace(/\.$/, ''));
  } catch (err) {
    const error = err as Error & { stderr?: string; killed?: boolean };
    // Silently skip API not enabled, permission denied, or timeout
    if (error.stderr?.includes('not enabled') ||
        error.stderr?.includes('PERMISSION_DENIED') ||
        error.stderr?.includes('does not have') ||
        error.killed) {
      return [];
    }
    throw err;
  }
}

/**
 * Get domains from multiple GCP projects (legacy function)
 */
export async function getCloudDNSDomainsMultiProject(
  projects?: string[],
  options: GCPOptions = {}
): Promise<string[]> {
  const projectList = projects || await listGCPProjects(options);
  const allDomains: string[] = [];

  for (const project of projectList) {
    try {
      const domains = await getCloudDNSDomains({ ...options, project });
      allDomains.push(...domains);
    } catch {
      // Skip projects without Cloud DNS or access
    }
  }

  return [...new Set(allDomains)]; // Deduplicate
}
