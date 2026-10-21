// Reputation panel: one-click links to well-known threat-intel services, opened in a new tab.
// Most of these sites refuse to be embedded (X-Frame-Options / CSP frame-ancestors), so links are used instead of iframes.
import { el, iconEl, mono, extLink } from '../js/ui.js';

const e = encodeURIComponent;

const PROVIDERS = [
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
    name: 'Shodan', what: 'Open ports, services and banners seen on the host.',
    ip: (v) => `https://www.shodan.io/host/${e(v)}`,
    domain: (v) => `https://www.shodan.io/search?query=${e(`hostname:${v}`)}`,
  },
  {
    name: 'URLScan', what: 'Screenshots and page behaviour from past scans.',
    ip: (v) => `https://urlscan.io/search/#${e(`page.ip:"${v}"`)}`,
    domain: (v) => `https://urlscan.io/domain/${e(v)}`,
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
    url: (v) => `https://otx.alienvault.com/indicator/url/${e(v)}`,
    hash: (v) => `https://otx.alienvault.com/indicator/file/${e(v)}`,
  },
  {
    name: 'MalwareBazaar', what: 'Malware samples shared by abuse.ch.',
    hash: (v, q) => `https://bazaar.abuse.ch/browse.php?search=${e(`${{ MD5: 'md5', 'SHA-1': 'sha1', 'SHA-256': 'sha256' }[q.hashType]}:${v}`)}`,
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
    for (const [kind, value, label] of targets(q)) {
      const cards = PROVIDERS.map((p) => [p, p[kind]?.(value, q)]).filter(([, href]) => href).map(([p, href]) =>
        el('article', { class: 'card provider' },
          el('div', { class: 'provider-top' }, el('h4', {}, p.name), iconEl('external-link', 16)),
          el('p', { class: 'caption' }, p.what),
          extLink(href, `Open in ${p.name}`, { button: true })));
      body.append(el('div', { class: 'subhead' }, el('span', { class: 'label' }, label), mono(value)), el('div', { class: 'provider-grid' }, cards));
    }
    body.append(el('p', { class: 'note' }, 'Opening a link sends the indicator to that service. Avoid pasting confidential URLs or internal hostnames.'));
  },
};
