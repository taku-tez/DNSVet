/**
 * Cloudflare DNS domain source
 * 
 * Authentication methods (in order of precedence):
 * 1. API Token (recommended): --cloudflare-token or CLOUDFLARE_API_TOKEN
 * 2. Global API Key: --cloudflare-email + --cloudflare-key 
 *    or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY
 * 
 * API Token is recommended as it supports fine-grained permissions.
 * Create at: https://dash.cloudflare.com/profile/api-tokens
 * Required permission: Zone.Zone:Read
 */

import type { CloudSource } from '../types.js';

const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1000;

/**
 * Fetch with retry for rate limits (429) and server errors (5xx)
 */
async function fetchWithRetry(url: string, options: RequestInit): Promise<Response> {
  let lastError: Error | null = null;
  
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(url, options);
      
      // Success or client error (4xx except 429) - don't retry
      if (response.ok || (response.status >= 400 && response.status < 500 && response.status !== 429)) {
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          const errorMsg = (errorData as { errors?: Array<{ message: string }> })?.errors?.[0]?.message || response.statusText;
          throw new Error(`Cloudflare API error: ${errorMsg}`);
        }
        return response;
      }
      
      // Rate limited - respect Retry-After header
      if (response.status === 429) {
        const retryAfter = response.headers.get('Retry-After');
        const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : INITIAL_BACKOFF_MS * Math.pow(2, attempt);
        await sleep(waitMs);
        continue;
      }
      
      // Server error (5xx) - exponential backoff
      if (response.status >= 500) {
        await sleep(INITIAL_BACKOFF_MS * Math.pow(2, attempt));
        continue;
      }
      
    } catch (err) {
      lastError = err as Error;
      // Network error - retry with backoff
      if (attempt < MAX_RETRIES - 1) {
        await sleep(INITIAL_BACKOFF_MS * Math.pow(2, attempt));
        continue;
      }
    }
  }
  
  throw lastError || new Error('Max retries exceeded');
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export interface CloudflareOptions {
  /** API Token (recommended) */
  apiToken?: string;
  /** Email for Global API Key auth */
  email?: string;
  /** Global API Key */
  apiKey?: string;
  /** Filter by account ID */
  accountId?: string;
}

export class CloudflareSource implements CloudSource {
  name = 'Cloudflare';
  private options: CloudflareOptions;

  constructor(options: CloudflareOptions = {}) {
    this.options = options;
  }

  async getDomains(): Promise<string[]> {
    return getCloudflareDomains(this.options);
  }
}

/**
 * Get all domains from Cloudflare zones
 */
export async function getCloudflareDomains(options: CloudflareOptions = {}): Promise<string[]> {
  const apiToken = options.apiToken || process.env.CLOUDFLARE_API_TOKEN;
  const email = options.email || process.env.CLOUDFLARE_EMAIL;
  const apiKey = options.apiKey || process.env.CLOUDFLARE_API_KEY;

  if (!apiToken && !(email && apiKey)) {
    throw new Error(
      'Cloudflare credentials not configured. Set CLOUDFLARE_API_TOKEN or (CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY)'
    );
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (apiToken) {
    headers['Authorization'] = `Bearer ${apiToken}`;
  } else {
    headers['X-Auth-Email'] = email!;
    headers['X-Auth-Key'] = apiKey!;
  }

  const allDomains: string[] = [];
  let page = 1;
  const perPage = 50;

  // Build query params
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
  });
  if (options.accountId) {
    params.set('account.id', options.accountId);
  }

  try {
    while (true) {
      params.set('page', String(page));
      const response = await fetchWithRetry(
        `https://api.cloudflare.com/client/v4/zones?${params}`,
        { headers }
      );

      const data = await response.json() as {
        result: Array<{ name: string; status: string }>;
        result_info: { total_pages: number; page: number };
      };

      // Extract active zone names
      const domains = data.result
        .filter(zone => zone.status === 'active')
        .map(zone => zone.name);

      allDomains.push(...domains);

      // Check if more pages
      if (page >= data.result_info.total_pages) {
        break;
      }
      page++;
    }

    return allDomains;
  } catch (err) {
    if (err instanceof Error && err.message.includes('Cloudflare API error')) {
      throw err;
    }
    throw new Error(`Failed to fetch Cloudflare zones: ${(err as Error).message}`);
  }
}

/**
 * Get zone details including DNS records count
 */
export async function getCloudflareZoneDetails(
  zoneId: string,
  options: CloudflareOptions = {}
): Promise<{
  name: string;
  status: string;
  nameServers: string[];
}> {
  const apiToken = options.apiToken || process.env.CLOUDFLARE_API_TOKEN;
  const email = options.email || process.env.CLOUDFLARE_EMAIL;
  const apiKey = options.apiKey || process.env.CLOUDFLARE_API_KEY;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  if (apiToken) {
    headers['Authorization'] = `Bearer ${apiToken}`;
  } else {
    headers['X-Auth-Email'] = email!;
    headers['X-Auth-Key'] = apiKey!;
  }

  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}`,
    { headers }
  );

  if (!response.ok) {
    throw new Error(`Failed to get zone details: ${response.statusText}`);
  }

  const data = await response.json() as {
    result: {
      name: string;
      status: string;
      name_servers: string[];
    };
  };

  return {
    name: data.result.name,
    status: data.result.status,
    nameServers: data.result.name_servers,
  };
}
