#!/usr/bin/env node

/**
 * MailVet CLI - Email security configuration scanner
 */

import { Command } from 'commander';
import fs from 'node:fs/promises';
import readline from 'node:readline';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeDomain, analyzeMultiple } from './core/index.js';
import { formatResult, formatSummary } from './output.js';
import type { DomainResult, ScanOptions } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'package.json'), 'utf-8'));

const program = new Command();

program
  .name('mailvet')
  .description('Email security configuration scanner - SPF/DKIM/DMARC/MX validation')
  .version(pkg.version);

program
  .command('check <domain>')
  .description('Check email security configuration for a single domain')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed information')
  .option('--selectors <selectors>', 'Custom DKIM selectors (comma-separated)')
  .action(async (domain: string, options) => {
    const scanOptions: ScanOptions = {
      dkimSelectors: options.selectors?.split(','),
      verbose: options.verbose,
    };

    const result = await analyzeDomain(domain, scanOptions);

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatResult(result, options.verbose));
    }

    process.exit(result.grade === 'F' ? 1 : 0);
  });

program
  .command('scan')
  .description('Scan multiple domains')
  .option('-f, --file <path>', 'Read domains from file')
  .option('--stdin', 'Read domains from stdin')
  .option('-o, --output <path>', 'Write results to file')
  .option('--json', 'Output as JSON')
  .option('-c, --concurrency <n>', 'Concurrent checks', '5')
  .option('--selectors <selectors>', 'Custom DKIM selectors (comma-separated)')
  .action(async (options) => {
    let domains: string[] = [];

    if (options.file) {
      const content = await fs.readFile(options.file, 'utf-8');
      domains = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
    } else if (options.stdin) {
      domains = await readStdin();
    } else {
      console.error('Error: Specify --file or --stdin');
      process.exit(1);
    }

    if (domains.length === 0) {
      console.error('Error: No domains to scan');
      process.exit(1);
    }

    console.error(`Scanning ${domains.length} domains...`);

    const scanOptions: ScanOptions = {
      concurrency: parseInt(options.concurrency, 10),
      dkimSelectors: options.selectors?.split(','),
    };

    const results = await analyzeMultiple(domains, scanOptions);

    if (options.json || options.output) {
      const output = JSON.stringify(results, null, 2);
      if (options.output) {
        await fs.writeFile(options.output, output);
        console.error(`Results written to ${options.output}`);
      } else {
        console.log(output);
      }
    } else {
      // Print summary
      console.log(formatSummary(results));
    }

    const hasFailures = results.some(r => r.grade === 'F');
    process.exit(hasFailures ? 1 : 0);
  });

// Default action: check single domain
program
  .argument('[domain]')
  .option('--json', 'Output as JSON')
  .option('-v, --verbose', 'Show detailed information')
  .action(async (domain: string | undefined, options) => {
    if (!domain) {
      program.help();
      return;
    }

    const result = await analyzeDomain(domain);

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatResult(result, options.verbose));
    }

    process.exit(result.grade === 'F' ? 1 : 0);
  });

async function readStdin(): Promise<string[]> {
  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  const domains: string[] = [];
  for await (const line of rl) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      domains.push(trimmed);
    }
  }
  return domains;
}

program.parse();
