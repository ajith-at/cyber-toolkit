// Checks each data source from a real browser page (CORS applies), using the same sample indicators as the app.
// Usage: python3 -m http.server 8811 &  then  node tests/cors-probe.js
const { chromium } = require('playwright');
const BASE = process.argv[2] || 'http://localhost:8811/';
const ENDPOINTS = [
  ['RDAP IP (rdap.org -> ARIN) 8.8.8.8', 'https://rdap.org/ip/8.8.8.8', { accept: 'application/rdap+json' }],
  ['RDAP IP (rdap.org -> APNIC) 1.1.1.1', 'https://rdap.org/ip/1.1.1.1', { accept: 'application/rdap+json' }],
  ['RDAP IPv6 (rdap.org -> ARIN)', 'https://rdap.org/ip/2606:4700:4700::1111', { accept: 'application/rdap+json' }],
  ['RDAP domain (rdap.org -> Verisign) example.com', 'https://rdap.org/domain/example.com', { accept: 'application/rdap+json' }],
  ['RDAP domain google.com', 'https://rdap.org/domain/google.com', { accept: 'application/rdap+json' }],
  ['DoH Google A', 'https://dns.google/resolve?name=example.com&type=A', {}],
  ['DoH Google PTR 8.8.8.8', 'https://dns.google/resolve?name=8.8.8.8.in-addr.arpa&type=PTR', {}],
  ['DoH Cloudflare TXT', 'https://cloudflare-dns.com/dns-query?name=google.com&type=TXT&ct=application/dns-json', { accept: 'application/dns-json' }],
  ['Cert Spotter example.com', 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names&expand=issuer', {}],
  ['crt.sh JSON example.com', 'https://crt.sh/?q=example.com&output=json&exclude=expired&deduplicate=Y', {}],
];
(async () => {
  const b = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  const p = await b.newPage();
  await p.goto(BASE);
  for (const [name, url, headers] of ENDPOINTS) {
    const r = await p.evaluate(async ({ url, headers }) => {
      const t = performance.now();
      try {
        const res = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
        const body = await res.text();
        return { ok: res.ok, status: res.status, ms: Math.round(performance.now() - t), bytes: body.length };
      } catch (e) { return { ok: false, error: `${e.name}: ${e.message}`, ms: Math.round(performance.now() - t) }; }
    }, { url, headers });
    console.log(`${r.ok ? 'OK  ' : 'FAIL'} ${name.padEnd(48)} ${r.status ?? ''} ${r.error ?? ''} ${r.ms}ms ${r.bytes ?? ''}`);
  }
  await b.close();
})();
