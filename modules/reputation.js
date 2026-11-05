// Reputation panel: one-click links to well-known threat-intel services, opened in a new tab.
// Most of these sites refuse to be embedded (X-Frame-Options / CSP frame-ancestors), so links are used instead of iframes.
import { el, iconEl, mono, extLink } from '../js/ui.js';
import { guessRegistrable } from '../js/net.js';

// Link formats re-checked on 6 Nov 2026 in a normal Chromium on the box (no sign-in) for OTX and MalwareBazaar (#10):
//   VirusTotal  ip, domain, file, url (double-encoded search redirects to /gui/url/<id>)        works (earlier)
//   AbuseIPDB   /check/<ip|domain>: a domain resolves to its IP's report                            works (earlier; bot check blocks scripts)
//   Talos       reputation_center/lookup?search=<ip|domain>, talos_file_reputation?s=<sha256>       works (earlier)
//   URLScan     search/#page.ip:"..." and page.url:"..." work; /domain/<d> needs a login, so domains use page.domain:"..."
//   Shodan      /host/<ip> works; hostname: search filters need a login, so domains use /domain/<registrable domain>
//   OTX         /indicator/{ip|domain|hostname|file}/… PASS; /indicator/url/<raw-url> PASS — do NOT
//               percent-encode the whole URL (encodeURIComponent made OTX show "Invalid url (https%3A%2F%2F…)")
//   MalwareBazaar  SHA-256 uses /sample/<sha256>/; MD5/SHA-1 keep browse.php?search=md5:… / sha1:…
//               Automated/box browsers still hit a one-time /verify-ua/ checkbox before the page; links are for humans

const e = encodeURIComponent;

export const PROVIDERS = [
  {
    name: 'VirusTotal', what: 'Verdicts from 70+ antivirus and URL scanners.',
    ip: (v) => `https://www.virustotal.com/gui/ip-address/${e(v)}`,
    domain: (v) => `https://www.virustotal.com/gui/domain/${e(v)}`,
    url: (v) => `https://www.virustotal.com/gui/search/${e(e(v))}`,
    hash: (v) => `https://www.virustotal.com/gui/file/${e(v)}`,
  },
  {
    name: 'AbuseIPDB', what: 'Community abuse reports and confidence score.',
    ip: (v) => `https://www.abuseipdb.com/check/${e(v)}`,
    domain: (v) => `https://www.abuseipdb.com/check/${e(v)}`,
  },
  {
    name: 'Shodan', what: 'Open ports and services on a host, or DNS records for a domain.',
    ip: (v) => `https://www.shodan.io/host/${e(v)}`,
    domain: (v) => `https://www.shodan.io/domain/${e(guessRegistrable(v))}`,
  },
  {
    name: 'URLScan', what: 'Screenshots and page behaviour from past scans.',
    ip: (v) => `https://urlscan.io/search/#${e(`page.ip:"${v}"`)}`,
    domain: (v) => `https://urlscan.io/search/#${e(`page.domain:"${v}"`)}`,
    url: (v) => `https://urlscan.io/search/#${e(`page.url:"${v}"`)}`,
  },
  {
    name: 'Cisco Talos', what: 'Email and web reputation from Cisco.',
    ip: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${e(v)}`,
    domain: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${e(v)}`,
    hash: (v, q) => (q.hashType === 'SHA-256' ? `https://talosintelligence.com/talos_file_reputation?s=${e(v)}` : null),
  },
  {
    name: 'AlienVault OTX', what: 'Open threat-intel pulses that mention it.',
    ip: (v) => `https://otx.alienvault.com/indicator/ip/${e(v)}`,
    domain: (v) => `https://otx.alienvault.com/indicator/${v.split('.').length > 2 ? 'hostname' : 'domain'}/${e(v)}`,
    url: (v) => `https://otx.alienvault.com/indicator/url/${v}`,
    hash: (v) => `https://otx.alienvault.com/indicator/file/${e(v)}`,
  },
  {
    name: 'MalwareBazaar', what: 'Malware samples shared by abuse.ch.',
    hash: (v, q) => {
      if (q.hashType === 'SHA-256') return `https://bazaar.abuse.ch/sample/${v}/`;
      const prefix = { MD5: 'md5', 'SHA-1': 'sha1' }[q.hashType];
      return prefix ? `https://bazaar.abuse.ch/browse.php?search=${e(`${prefix}:${v}`)}` : null;
    },
  },
];

function targets(q) {
  const t = [];
  if (q.type === 'url') t.push(['url', q.url, 'Link']);
  if (q.ip) t.push(['ip', q.ip, 'IP address']);
  if (q.domain) t.push(['domain', q.domain, q.type === 'email' ? 'Email domain' : 'Domain']);
  if (q.type === 'hash') t.push(['hash', q.value, `${q.hashType} hash`]);
  return t;
}

export default {
  id: 'reputation',
  name: 'Reputation',
  icon: 'radar',
  accepts: ['ip', 'domain', 'url', 'hash'],
  summary: 'One-click checks on VirusTotal, AbuseIPDB, Shodan, URLScan, Cisco Talos and AlienVault OTX.',
  source: 'Links open in a new tab',

  async render(q, { body, setStatus }) {
    setStatus('unknown', 'Check externally');
    const facts = [];
    for (const [kind, value, label] of targets(q)) {
      const links = PROVIDERS.map((p) => [p, p[kind]?.(value, q)]).filter(([, href]) => href);
      const cards = links.map(([p, href]) =>
        el('article', { class: 'card provider' },
          el('div', { class: 'provider-top' }, el('h4', {}, p.name), iconEl('external-link', 16)),
          el('p', { class: 'caption' }, p.what),
          extLink(href, `Open in ${p.name}`, { button: true })));
      body.append(el('div', { class: 'subhead' }, el('span', { class: 'label' }, label), mono(value)), el('div', { class: 'provider-grid' }, cards));
      for (const [p, href] of links) facts.push([`${p.name} (${label.toLowerCase()})`, href]);
    }
    body.append(el('p', { class: 'note' }, 'Opening a link sends the indicator to that service. Avoid pasting confidential URLs or internal hostnames.'));
    return { facts };
  },
};
