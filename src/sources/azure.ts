/**
 * Azure DNS domain source
 */

import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { CloudSource } from '../types.js';

const execAsync = promisify(exec);

export interface AzureOptions {
  subscription?: string;
  resourceGroup?: string;
}

export class AzureSource implements CloudSource {
  name = 'Azure DNS';
  private options: AzureOptions;

  constructor(options: AzureOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getAzureDNSDomains(this.options);
  }
}

/**
 * Get all domains from Azure DNS zones
 */
export async function getAzureDNSDomains(options: AzureOptions = {}): Promise<string[]> {
  const subscriptionArg = options.subscription ? `--subscription "${options.subscription}"` : '';
  const rgArg = options.resourceGroup ? `-g "${options.resourceGroup}"` : '';

  try {
    // List all DNS zones
    const { stdout } = await execAsync(
      `az network dns zone list ${subscriptionArg} ${rgArg} --output json`
    );

    const zones: Array<{ 
      name: string; 
      zoneType?: string;
    }> = JSON.parse(stdout) || [];

    // Filter public zones only
    const domains = zones
      .filter(zone => zone.zoneType !== 'Private')
      .map(zone => zone.name);

    return domains;
  } catch (err) {
    const error = err as Error & { stderr?: string };
    if (error.stderr?.includes('login') || error.stderr?.includes('credentials')) {
      throw new Error('Azure credentials not configured. Run "az login"');
    }
    if (error.stderr?.includes('not found') || error.stderr?.includes('command not found')) {
      throw new Error('Azure CLI not found. Install from: https://docs.microsoft.com/cli/azure/install-azure-cli');
    }
    if (error.stderr?.includes('subscription')) {
      throw new Error('Azure subscription not set. Use --azure-subscription or run "az account set -s SUBSCRIPTION_ID"');
    }
    throw new Error(`Failed to list Azure DNS zones: ${error.message}`);
  }
}

/**
 * List Azure subscriptions
 */
export async function listAzureSubscriptions(): Promise<Array<{ id: string; name: string }>> {
  try {
    const { stdout } = await execAsync(
      `az account list --output json`
    );

    const subscriptions: Array<{ id: string; name: string }> = JSON.parse(stdout) || [];
    return subscriptions;
  } catch {
    return [];
  }
}

/**
 * Get domains from all Azure subscriptions
 */
export async function getAzureDNSDomainsMultiSubscription(
  subscriptions?: string[]
): Promise<string[]> {
  const subList = subscriptions || (await listAzureSubscriptions()).map(s => s.id);
  const allDomains: string[] = [];

  for (const subscription of subList) {
    try {
      const domains = await getAzureDNSDomains({ subscription });
      allDomains.push(...domains);
    } catch {
      // Skip subscriptions without DNS zones or access
    }
  }

  return [...new Set(allDomains)]; // Deduplicate
}
