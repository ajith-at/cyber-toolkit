// Reputation link formats (see the verification note in modules/reputation.js). Offline: checks the generated URLs only.
// Usage: python3 -m http.server 8811 &   then   node tests/reputation-links.js [baseUrl]
const { chromium } = require('playwright');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHA = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

const EXPECT = {
  ip: {
    VirusTotal: 'https://www.virustotal.com/gui/ip-address/8.8.8.8',
    AbuseIPDB: 'https://www.abuseipdb.com/check/8.8.8.8',
    Shodan: 'https://www.shodan.io/host/8.8.8.8',
    URLScan: 'https://urlscan.io/search/#page.ip%3A%228.8.8.8%22',
    'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search=8.8.8.8',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/ip/8.8.8.8',
  },
  domain: {
    VirusTotal: 'https://www.virustotal.com/gui/domain/www.example.com',
    AbuseIPDB: 'https://www.abuseipdb.com/check/www.example.com',
    Shodan: 'https://www.shodan.io/domain/example.com',
    URLScan: 'https://urlscan.io/search/#page.domain%3A%22www.example.com%22',
    'Cisco Talos': 'https://talosintelligence.com/reputation_center/lookup?search=www.example.com',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/hostname/www.example.com',
  },
  url: {
    VirusTotal: 'https://www.virustotal.com/gui/search/https%253A%252F%252Fexample.com%252Flogin',
    URLScan: 'https://urlscan.io/search/#page.url%3A%22https%3A%2F%2Fexample.com%2Flogin%22',
    'AlienVault OTX': 'https://otx.alienvault.com/indicator/url/https%3A%2F%2Fexample.com%2Flogin',
  },
  hash: {
    VirusTotal: `https://www.virustotal.com/gui/file/${SHA}`,
    'Cisco Talos': `https://talosintelligence.com/talos_file_reputation?s=${SHA}`,
    'AlienVault OTX': `https://otx.alienvault.com/indicator/file/${SHA}`,
    MalwareBazaar: `https://bazaar.abuse.ch/browse.php?search=sha256%3A${SHA}`,
  },
};

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  const page = await browser.newPage();
  await page.goto(BASE);
  const got = await page.evaluate(async (SHA) => {
    const { PROVIDERS } = await import('./modules/reputation.js');
    const inputs = { ip: ['8.8.8.8', {}], domain: ['www.example.com', {}], url: ['https://example.com/login', {}], hash: [SHA, { hashType: 'SHA-256' }] };
    const out = {};
    for (const [kind, [v, q]] of Object.entries(inputs)) out[kind] = Object.fromEntries(PROVIDERS.map((p) => [p.name, p[kind]?.(v, q) || null]).filter(([, h]) => h));
    return out;
  }, SHA);
  let fails = 0;
  for (const kind of Object.keys(EXPECT)) {
    for (const [name, href] of Object.entries(EXPECT[kind])) if (got[kind][name] !== href) { fails++; console.log(`FAIL: ${kind} ${name}: ${got[kind][name]} (want ${href})`); }
    for (const name of Object.keys(got[kind])) if (!(name in EXPECT[kind])) { fails++; console.log(`FAIL: unexpected ${kind} link for ${name}`); }
  }
  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : 'ok: reputation link formats\n\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
