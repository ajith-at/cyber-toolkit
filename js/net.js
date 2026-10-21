// Network helpers shared by every module. Browser-only, no API keys.
// All endpoints used here were checked to send CORS headers (Access-Control-Allow-Origin: *).

export class NetError extends Error {
  constructor(kind, message, status) { super(message); this.kind = kind; this.status = status; }
}

const cache = new Map();

/** GET JSON with a timeout. Identical requests share one in-flight promise (modules reuse each other's lookups). */
export function fetchJson(url, { timeout = 15000, headers = {}, cacheable = true } = {}) {
  const key = url + JSON.stringify(headers);
  if (cacheable && cache.has(key)) return cache.get(key);
  const p = (async () => {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), timeout);
    let res;
    try {
      res = await fetch(url, { headers, signal: ctl.signal, referrerPolicy: 'no-referrer', credentials: 'omit' });
    } catch (e) {
      if (e.name === 'AbortError') throw new NetError('timeout', 'The service took too long to answer.');
      throw new NetError('network', 'The service could not be reached. Check your connection or try again later.');
    } finally { clearTimeout(t); }
    if (!res.ok) throw new NetError('http', `The service answered with HTTP ${res.status}.`, res.status);
    try { return await res.json(); } catch { throw new NetError('parse', 'The service sent something that was not JSON.'); }
  })();
  if (cacheable) {
    cache.set(key, p);
    p.catch(() => cache.delete(key)); // let failures be retried
  }
  return p;
}

// ---------- DNS over HTTPS ----------
export const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
const RCODE = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };

/** Resolve a record via Google Public DNS JSON API, falling back to Cloudflare. */
export async function doh(name, type) {
  const qs = `name=${encodeURIComponent(name)}&type=${type}`;
  let data, provider;
  try {
    data = await fetchJson(`https://dns.google/resolve?${qs}`, { timeout: 8000 });
    provider = 'Google Public DNS';
  } catch {
    data = await fetchJson(`https://cloudflare-dns.com/dns-query?${qs}&ct=application/dns-json`, { timeout: 8000, headers: { accept: 'application/dns-json' } });
    provider = 'Cloudflare DNS';
  }
  const want = DNS_TYPES[type];
  const answers = (data.Answer || []).filter((a) => a.type === want).map((a) => ({ ...a, data: type === 'TXT' ? unquoteTxt(a.data) : a.data }));
  return { rcode: RCODE[data.Status] || String(data.Status), nx: data.Status === 3, answers, provider, dnssec: !!data.AD };
}

function unquoteTxt(s) {
  // "v=spf1 ..." "more" -> v=spf1 ...more
  const parts = s.match(/"((?:[^"\\]|\\.)*)"/g);
  return parts ? parts.map((p) => p.slice(1, -1).replace(/\\"/g, '"')).join('') : s;
}

export function reverseName(ip) {
  if (ip.includes(':')) {
    // expand IPv6
    const [head, tail = ''] = ip.split('::');
    const h = head ? head.split(':') : [];
    const t = tail ? tail.split(':') : [];
    const full = [...h, ...Array(8 - h.length - t.length).fill('0'), ...t].map((g) => g.padStart(4, '0')).join('');
    return `${full.split('').reverse().join('.')}.ip6.arpa`;
  }
  return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
}

// ---------- RDAP ----------
const RDAP_HEADERS = { accept: 'application/rdap+json, application/json' };

/** RDAP via the rdap.org bootstrap redirector, which 302s to the right RIR / registry server. */
export function rdap(kind, value) {
  // value is already validated by detect.js (IP or LDH domain), so no escaping is needed; encoding ':' breaks IPv6.
  return fetchJson(`https://rdap.org/${kind}/${kind === 'ip' ? value : encodeURIComponent(value)}`, { headers: RDAP_HEADERS, timeout: 15000 });
}

// Second-level labels that are usually public suffixes under a country-code TLD (example.com.au, example.co.uk).
const SLD = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'id', 'asn', 'or', 'ne', 'go', 'gob', 'mil', 'nic', 'ltd', 'plc', 'me', 'nom', 'sch']);

/** Best guess at the registrable domain without the full Public Suffix List. */
export function guessRegistrable(host) {
  const l = host.split('.');
  if (l.length <= 2) return host;
  const n = l[l.length - 1].length === 2 && SLD.has(l[l.length - 2]) ? 3 : 2;
  return l.slice(-n).join('.');
}

/** Domain RDAP: try the guessed registrable domain first (avoids noisy 404s), then walk up the labels. */
export async function rdapDomain(host) {
  const labels = host.split('.');
  const guess = guessRegistrable(host);
  const tries = [guess, ...labels.map((_, i) => labels.slice(i).join('.')).filter((n) => n.includes('.') && n !== guess)];
  let lastErr;
  for (const name of tries) {
    try { return { name, data: await rdap('domain', name) }; } catch (e) {
      lastErr = e;
      if (!(e.kind === 'http' && e.status === 404)) throw e;
    }
  }
  throw lastErr;
}

export function vcard(entity) {
  const out = {};
  const props = entity?.vcardArray?.[1] || [];
  for (const [k, , , v] of props) {
    if (k === 'fn') out.name = v;
    if (k === 'org' && !out.org) out.org = Array.isArray(v) ? v.join(' ') : v;
    if (k === 'email' && !out.email) out.email = v;
    if (k === 'tel' && !out.tel) out.tel = String(v).replace(/^tel:/, '');
    if (k === 'adr' && !out.address) {
      const label = props.find((p) => p[0] === 'adr')?.[1]?.label;
      const parts = Array.isArray(v) ? v.flat().filter(Boolean) : [v].filter(Boolean);
      out.address = label ? label.split('\n').join(', ') : parts.join(', ') || null;
      out.country = (Array.isArray(v) && v[6]) || (label ? label.trim().split('\n').pop() : null);
    }
  }
  return out;
}

/** Depth-first list of entities (RDAP nests abuse contacts inside registrants). */
export function allEntities(obj, acc = []) {
  for (const e of obj?.entities || []) { acc.push(e); allEntities(e, acc); }
  return acc;
}

export function entityByRole(obj, role) {
  return allEntities(obj).find((e) => (e.roles || []).includes(role));
}

export function eventDate(obj, action) {
  const ev = (obj?.events || []).find((e) => e.eventAction === action);
  return ev ? new Date(ev.eventDate) : null;
}
