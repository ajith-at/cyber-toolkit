# Cyber Toolkit

**Live: https://u51.org/toolkit/**

A small, modular, open-source toolkit for quick security lookups that runs entirely in your browser. Paste an IP address, domain, URL, email address or file hash. It works out what you pasted and runs every tool that applies:

- **IP lookup**: owner, network range, country and abuse contact (RDAP), plus reverse DNS.
- **Domain lookup**: registrar, created and expiry dates, domain age (flagged when under 90 days), nameservers, registry status and DNSSEC.
- **DNS & email security**: A, AAAA, MX, NS and TXT records, with SPF and DMARC analysis and an A–F grade.
- **Certificates**: current TLS certificates from Certificate Transparency logs, and the subdomains they reveal.
- **Reputation**: one-click links to VirusTotal, AbuseIPDB, Shodan, URLScan, Cisco Talos, AlienVault OTX and MalwareBazaar.

Standalone tools work on pasted text, files or a password instead of the smart input:

- **Email headers**: paste raw headers to see the delivery path (hops in order, with the delay between them), SPF, DKIM and DMARC results, From / Reply-To / Return-Path / Sender mismatches, misleading display names, and the originating IP. Each IP and domain links into IP lookup, Domain lookup, DNS & email security and Reputation.
- **Extract indicators**: paste an alert email, threat report or chat message to pull out every IPv4/IPv6 address, domain, URL, email address and MD5 / SHA-1 / SHA-256 hash, including defanged ones (`hxxp`, `[.]`, `(.)`, `[@]`). Duplicates are removed and results are grouped by type with a count. Copy the list plain (as written), defanged for safe sharing, or refanged, and "Check" any indicator in the smart input. File names (`report.pdf`) and version numbers (`v2.4.1.9`) are ignored.
- **Hash & encode**: MD5, SHA-1, SHA-256, SHA-384 and SHA-512 of text or a file; Base64, Base64URL, URL, hex and HTML entity encoding and decoding; defang and refang. A hash can be sent straight to Reputation.
- **Password breach check**: whether a password appears in Have I Been Pwned's Pwned Passwords data. Only the first 5 characters of its SHA-1 hash are sent (k-anonymity), with response padding; the password never leaves the browser and is never stored or put in the URL.

The smart input understands IPv4/IPv6, domains (including Unicode), URLs, emails and MD5/SHA-1/SHA-256 hashes. It also restores "defanged" indicators such as `hxxps://example[.]com`.

It is a static site: plain HTML, CSS and JavaScript ES modules. There is no build step, no framework, no backend, no tracking and no API keys.

## Privacy

- Everything runs in your browser. There is no server of ours in the middle, no analytics and no cookies. The only thing saved locally is your light or dark mode choice (`localStorage`).
- Lookups go **directly from your browser** to these public services:

  | Service | Used for | What it receives |
  | --- | --- | --- |
  | [rdap.org](https://rdap.org) → the regional internet registry or domain registry it redirects to (e.g. ARIN, APNIC, RIPE, Verisign) | IP and domain registration data | The IP or domain |
  | [Google Public DNS](https://developers.google.com/speed/public-dns/docs/doh/json) (`dns.google`), with [Cloudflare DNS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) as a fallback | DNS records, reverse DNS, SPF and DMARC | The domain, or the reverse name of the IP |
  | [SSLMate Cert Spotter](https://sslmate.com/certspotter/api/) (`api.certspotter.com`) | Certificate Transparency | The registered domain |
  | [Have I Been Pwned Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) (`api.pwnedpasswords.com`) | Password breach check | The first 5 hex characters of the password's SHA-1 hash, never the password |
  | [Google Fonts](https://fonts.google.com) | The Plus Jakarta Sans font | A normal font request (no indicator) |

- Text, headers and files in the standalone tools (Email headers, Extract indicators, Hash & encode) are processed in the browser and never leave it.
- File hashes and full URLs are **not** sent anywhere unless you click a reputation link.
- Reputation links open the third-party site in a new tab, which sends the indicator to that site. Don't paste confidential URLs or internal hostnames if that matters to you.
- Requests are made with `referrerPolicy: no-referrer` and without credentials. A Content Security Policy limits scripts to the site itself.

## Run it locally

```bash
git clone https://github.com/ajith-at/cyber-toolkit
cd cyber-toolkit
python3 -m http.server 8000
# open http://localhost:8000
```

Any static file server works. ES modules don't load from `file://`, so opening `index.html` directly won't work.

## Project layout

```
index.html          app shell (sidebar, toolbar, smart input)
css/tokens.css      colour tokens for light and dark mode
css/app.css         layout and components
js/app.js           routing (#q=...&tool=...), rendering, theme switch
js/detect.js        smart input detection and normalisation
js/registry.js      the list of tool modules
js/net.js           fetch with timeout and caching, DNS-over-HTTPS, RDAP helpers
js/ui.js            safe DOM builder, cards, tables, pills, callouts
js/icons.js         Lucide outline icons (ISC)
js/md5.js           MD5 for Hash & encode (WebCrypto has no MD5)
js/ioc.js           defang / refang and indicator extraction (shared by Extract indicators and Hash & encode)
js/tlds.js          IANA top-level domain list snapshot, used to tell domains from file names
modules/*.js        one file per tool
tests/              Playwright smoke test, per-module tests and CORS probe
deploy-u51.sh       maintainer script that publishes to u51.org/toolkit/
```

## Adding a module

A tool is one file plus one line in the registry.

1. Create `modules/my-tool.js`:

```js
import { factCard, factGrid, detailsTable, mono } from '../js/ui.js';
import { fetchJson } from '../js/net.js';

export default {
  id: 'my-tool',                 // unique slug, used in the URL: #q=example.com&tool=my-tool
  name: 'My tool',               // sidebar label
  icon: 'hash',                  // a key in js/icons.js (Lucide outline icon)
  accepts: ['domain'],           // any of 'ip' | 'domain' | 'url' | 'hash'
  summary: 'One line shown on the home screen.',
  source: 'Where the data comes from',

  async render(q, { body, setStatus }) {
    // q = { type, value, display, ip?, domain?, url?, email?, hashType?, refanged }
    const data = await fetchJson(`https://api.example.org/lookup/${encodeURIComponent(q.domain)}`);
    setStatus('low', 'Looks fine');            // 'low' | 'unknown' | 'caution' | 'high'
    body.append(
      factGrid(factCard({ label: 'Score', figure: data.score, status: 'low' })),
      detailsTable('Details', [['Domain', mono(q.domain)], ['Score', String(data.score)]]),
    );
  },
};
```

2. Register it in `js/registry.js`:

```js
import myTool from '../modules/my-tool.js';
export const MODULES = [ /* ...existing */ myTool ];
```

**Standalone tools** (pasted text or files rather than the smart input) set `accepts: []`, list `inputs` for the home screen (e.g. `['Text', 'File']`) and provide `panel(body, { go })` instead of `render`. The panel is built once and kept while you switch tools; `go(value, toolId)` opens a lookup, e.g. `go(sha256, 'reputation')`. See `modules/encoding.js`.

**How routing works:** a URL also provides its host's `ip` or `domain`, and an email provides its `domain`. A module runs when any of its `accepts` values is present in the parsed input.

**Module rules:**

- Use the endpoints of keyless services that send `Access-Control-Allow-Origin` headers. Check them with `tests/cors-probe.js`.
- Never put an API key in the code. Keyed services belong in a future backend proxy.
- Build DOM with the helpers in `js/ui.js`, which use `textContent`. Never pass external data to `innerHTML`.
- Handle failure: catch errors, call `setStatus('unknown', ...)` and show `errorCallout(...)` with a link to the provider's website. A thrown error is caught by the app, but a helpful message is better.
- Status colours mean risk: teal = low, slate = unknown, amber = caution, rose = high risk.

## Style

The visual style is adapted from the "Soft Indigo Desk" dashboard brief. It uses a periwinkle canvas and a rounded shell, an indigo sidebar, white cards with soft shadows and pill controls. Text is set in Plus Jakarta Sans with tabular numerals, and icons are Lucide outlines. Light and dark tokens swap together, and the layout respects reduced-motion settings. Monospace is used only for raw values (IPs, hashes, DNS records, JSON).

## Tests

```bash
npm i playwright                  # any folder; point NODE_PATH at its node_modules
python3 -m http.server 8811 &
node tests/smoke.js               # or: node tests/smoke.js https://u51.org/toolkit/
node tests/smoke.js --shots       # also writes screenshots/
node tests/breach-check.js        # Password breach check: only a 5-character prefix is sent, nothing stored
node tests/encoding.js            # Hash & encode: known-answer tests, UI and no-network check
node tests/email-headers.js       # Email headers: Gmail, Microsoft 365 and spoofed samples (tests/fixtures/)
node tests/ioc-extract.js         # Extract indicators: normal, defanged and tricky fixtures, defang/refang round trips, copy, UI
node tests/cors-probe.js          # fetches every data source from a browser page
node tests/reputation-links.js    # reputation link formats (offline)
```

The tests use the installed Chrome (`PW_CHANNEL=chrome` by default; set `PW_CHANNEL=chromium` to use Playwright's own build). The smoke test covers sample IPs, domains, a URL, an email, a hash, defanged input, a private IP, bad input, the tool filter, dark mode and a mobile viewport. It fails on any console error.

## Known limits

- The `crt.sh` JSON API was unreachable from browsers (HTTP 502 without CORS) when this was built, so certificates come from Cert Spotter. Cert Spotter has a free hourly limit and lists unexpired certificates only (the first 100). crt.sh stays as a link (set `TRY_CRTSH` in `modules/certificates.js` to try it again).
- Some country-code registries (for example `.de`) don't publish RDAP. The domain tool then links to ICANN Lookup ([#9](https://github.com/ajith-at/cyber-toolkit/issues/9)).
- Registrable domains are guessed without the full Public Suffix List.
- There are no reputation scores yet, only links (see the roadmap).

## Roadmap

- Live reputation scores (AbuseIPDB, VirusTotal and others) combined into one risk score, through a small optional backend (e.g. a Cloudflare Worker) so API keys never reach the browser.
- Breach check via k-anonymity (only a hash prefix leaves the browser).
- A password strength meter.
- CVE / vulnerability feed.

## Backlog

Planned work, known limits and ideas are tracked as [GitHub Issues](https://github.com/ajith-at/cyber-toolkit/issues):

- [High priority](https://github.com/ajith-at/cyber-toolkit/issues?q=is%3Aopen+label%3Apriority%3Ahigh)
- [New modules](https://github.com/ajith-at/cyber-toolkit/issues?q=is%3Aopen+label%3Anew-module)
- [Good first issues](https://github.com/ajith-at/cyber-toolkit/issues?q=is%3Aopen+label%3A%22good+first+issue%22)
- [Ideas that need investigation](https://github.com/ajith-at/cyber-toolkit/issues?q=is%3Aopen+label%3Aidea)

Have a feature request or found a bug? [Open an issue](https://github.com/ajith-at/cyber-toolkit/issues/new).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE) © 2026 Ajith Thamarakshan. Icons from [Lucide](https://lucide.dev) (ISC).
