# Cyber Toolkit

A modular, browser-only toolkit for quick security lookups. Paste an IP, domain, URL, email address or file hash and it works out what it is, then runs every tool that applies. No accounts, no API keys, no build step.

Status: **v0.1**, private, not published.

## Run locally

```bash
cd cyber-toolkit
python3 -m http.server 8000
# open http://localhost:8000
```

ES modules need a web server; opening `index.html` from disk will not work.

## Tools (V1)

| Tool | Accepts | Data source (all CORS-enabled, keyless) |
| --- | --- | --- |
| Smart input | anything | Local detection of IPv4/IPv6, domain (incl. Unicode → punycode), URL, email, MD5/SHA-1/SHA-256. Re-fangs `hxxp://`, `[.]`, `[@]`. |
| IP lookup | IP (and a URL's IP host) | RDAP via `rdap.org` (redirects to ARIN/RIPE/APNIC/LACNIC/AFRINIC); reverse DNS (PTR) via DoH. Private/reserved ranges are recognised and not looked up. |
| Domain lookup | domain, URL host, email domain | RDAP via `rdap.org` (e.g. Verisign for .com). Age in days with amber pill under 90 days and rose under 30, expiry, registrar, nameservers, status, DNSSEC. |
| DNS & email security | domain | DNS-over-HTTPS: `dns.google/resolve`, falling back to `cloudflare-dns.com/dns-query`. A/AAAA/MX/NS/TXT; SPF and DMARC analysis and an A–F grade. |
| Certificates | domain | Certificate Transparency via SSLMate Cert Spotter (`api.certspotter.com/v1/issuances`), crt.sh as a deep link. |
| Reputation | IP, domain, URL, hash | Deep links (new tab) to VirusTotal, AbuseIPDB, Shodan, URLScan, Cisco Talos, AlienVault OTX, MalwareBazaar. |

### CORS notes (checked Oct 2026 with headless Chrome, `tests/cors-probe.js`)

- `rdap.org` → ARIN / APNIC / Verisign: OK. Do **not** URL-encode IPv6 colons (rdap.org returns 400).
- `dns.google` and `cloudflare-dns.com` (`ct=application/dns-json`): OK.
- `api.certspotter.com`: OK. Free tier is rate-limited per hour; lists unexpired certificates, first 100 per query.
- `crt.sh` JSON: **failed** (HTTP 502, no CORS header, "Failed to fetch"). It is disabled (`TRY_CRTSH` in `modules/certificates.js`) and kept as a deep link.
- Reputation sites block iframes (X-Frame-Options / frame-ancestors), so they are links, not embeds.
- Some country-code registries (e.g. .au) do not publish RDAP; the domain tool then links to ICANN Lookup.

## Adding a tool

1. Create `modules/my-tool.js`:

```js
import { factCard, factGrid } from '../js/ui.js';
export default {
  id: 'my-tool', name: 'My tool', icon: 'hash',      // icon = key in js/icons.js (Lucide)
  accepts: ['domain'],                                 // 'ip' | 'domain' | 'url' | 'hash'
  summary: 'One line for the home screen.',
  source: 'Where the data comes from',
  async render(q, { body, setStatus }) {
    setStatus('low', 'Looks fine');                    // 'low' | 'unknown' | 'caution' | 'high'
    body.append(factGrid(factCard({ label: 'Thing', figure: 42 })));
  },
};
```

2. Add one import and one entry in `js/registry.js`.

`q` is the parsed input: `{ type, value, ip?, domain?, url?, email?, hashType? }`. Use helpers in `js/ui.js` (safe DOM builder, cards, tables, pills, callouts) and `js/net.js` (`fetchJson` with timeout and caching, `doh`, `rdap`). Never use `innerHTML` with external data.

## Style

Adapted from Ajith's **Soft Indigo Desk** brief: periwinkle canvas, rounded shell, indigo sidebar rail, white cards with soft shadows, pill controls, Plus Jakarta Sans, tabular numerals, Lucide outline icons, persisted dark mode switch at the bottom of the rail (compact in the toolbar on mobile), reduced-motion support.

Adaptations for a security tool:

- **Status colours mean risk**: teal = low/clean, slate = unknown/no score, amber = caution (domain under 90 days, missing DMARC, `p=none`, `?all`), rose = high risk (domain under 30 days, `+all`, suspended or expired domain).
- **Sidebar items are tool modules**; on mobile they become a chip row. The hero search pill is the smart input.
- **Monospace for raw values only** (IPs, hashes, DNS records, JSON) so they can be compared character by character. It uses the system mono stack, not a second web font.
- In dark mode, text on the light indigo fill is dark (`--on-primary`) for contrast.
- Market-direction colours (indigo up / coral down) and charts are not used yet.

## Tests

```bash
npm i playwright            # anywhere; point NODE_PATH at it
python3 -m http.server 8811 &
node tests/smoke.js --shots   # all sample lookups, bad input, tool filter, dark mode, mobile; no console errors
node tests/cors-probe.js      # each data source fetched from a browser page
```

Uses the system Chrome (`PW_CHANNEL=chrome`). Screenshots go to `screenshots/`.

## Roadmap

- **V2**: live reputation scores (AbuseIPDB, VirusTotal, etc.) combined into one risk score, through a small private backend (e.g. a Cloudflare Worker) so API keys never reach the browser.
- **Later**: email header analyser, breach check via k-anonymity (HIBP range API), hash and Base64 tools, password strength meter, CVE / vulnerability feed.
