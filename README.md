# MailVet 📧

Email security configuration scanner - validates SPF, DKIM, DMARC, and MX records.

## Features

- **SPF Validation**: Check sender policy framework configuration
- **DKIM Detection**: Scan common DKIM selectors and validate key strength
- **DMARC Analysis**: Verify policy, reporting, and subdomain settings
- **MX Inspection**: Identify mail servers and email providers
- **Grading System**: A-F grades based on security configuration
- **Recommendations**: Actionable suggestions to improve email security

## Installation

```bash
npm install -g mailvet
```

## Usage

### Single Domain Check

```bash
# Basic check
mailvet check example.com

# JSON output
mailvet check example.com --json

# Verbose mode
mailvet check example.com --verbose

# Custom DKIM selectors
mailvet check example.com --selectors google,selector1,custom
```

### Bulk Scanning

```bash
# From file
mailvet scan -f domains.txt

# From stdin
cat domains.txt | mailvet scan --stdin

# Output to file
mailvet scan -f domains.txt -o results.json --json

# Control concurrency
mailvet scan -f domains.txt -c 10
```

### Integration with DNS Providers

Coming soon:
- `--aws` - Scan all Route53 hosted zones
- `--gcp` - Scan Google Cloud DNS zones
- `--azure` - Scan Azure DNS zones
- `--cloudflare` - Scan Cloudflare zones

## Output Example

```
📧 example.com - Grade: B (82/100)

SPF     ✅ Found
        Record: v=spf1 include:_spf.google.com ~all
        ⚠️ Mechanism: ~all
        ✅ DNS lookups: 4/10

DKIM    ✅ Found
        ✅ google._domainkey (2048-bit)
        ✅ selector1._domainkey (2048-bit)

DMARC   ✅ Found
        Record: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com
        ⚠️ Policy: p=quarantine
        ✅ Reporting: enabled

MX      ✅ Found
        ✅ aspmx.l.google.com (pri: 1)
        ℹ️ Email provider detected: Google Workspace

Recommendations:
  1. Consider changing SPF from ~all (softfail) to -all (hardfail)
  2. Consider upgrading DMARC policy from quarantine to reject
```

## Grading Criteria

| Grade | Score | Requirements |
|-------|-------|--------------|
| **A** | 90-100 | SPF (-all) + DKIM (2048-bit) + DMARC (reject) |
| **B** | 75-89 | SPF + DKIM + DMARC (quarantine) |
| **C** | 50-74 | SPF + DMARC (any policy) |
| **D** | 25-49 | SPF only |
| **F** | 0-24 | Missing critical records |

## Checks Performed

### SPF
- Record existence
- Mechanism strength (-all > ~all > ?all > +all)
- DNS lookup count (max 10)
- Deprecated mechanisms (ptr)
- Multiple record detection

### DKIM
- Common selector detection (google, selector1, default, etc.)
- Key length validation (≥2048-bit recommended)
- Multiple selector support

### DMARC
- Record existence
- Policy strength (reject > quarantine > none)
- Subdomain policy (sp=)
- Reporting configuration (rua/ruf)
- Percentage coverage (pct=)

### MX
- Record existence
- Priority configuration
- Redundancy check
- Email provider identification

## Programmatic Usage

```typescript
import { analyzeDomain, analyzeMultiple } from 'mailvet';

// Single domain
const result = await analyzeDomain('example.com');
console.log(result.grade); // 'A', 'B', 'C', 'D', or 'F'
console.log(result.score); // 0-100
console.log(result.recommendations);

// Multiple domains
const results = await analyzeMultiple([
  'example.com',
  'test.org'
], { concurrency: 5 });
```

## Exit Codes

- `0` - All domains have grade D or better
- `1` - At least one domain has grade F

## Related Projects

Part of the **xxVet** security tool series:
- [AgentVet](https://github.com/taku-tez/agentvet) - AI Agent Security Scanner
- [PermitVet](https://github.com/taku-tez/PermitVet) - Cloud IAM Scanner
- [SubVet](https://github.com/taku-tez/SubVet) - Subdomain Takeover Scanner
- [ReachVet](https://github.com/taku-tez/ReachVet) - Supply Chain Reachability

## License

MIT
