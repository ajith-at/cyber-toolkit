// Indicator (IOC) helpers: defang / refang and extraction from free text. Pure functions, no DOM, no network.
// Shared by Hash & encode and Extract indicators, and written so a future "Decode & Analyse" card (#36) can reuse them.
import { isIPv4, isIPv6, isDomain, HASHES } from './detect.js';
import { TLDS } from './tlds.js';

// ---------- defang / refang ----------
// Fang tokens commonly used when sharing indicators, and what they stand for.
const FANG = /\bh(?:xx|\*\*)p(s?)(\[:\/\/\]|\[?:\]?\/\/)|\bfxp(\[:\/\/\]|\[?:\]?\/\/)|\[\s*\.\s*\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\}|\[@\]|\(@\)|\[at\]|\[:\]|\[:\/\/\]/gi;
function fangValue(m, s, sep) {
  const l = m.toLowerCase();
  if (sep !== undefined) return `http${s}://`;
  if (l.startsWith('fxp')) return 'ftp://';
  if (l === '[://]') return '://';
  if (/@|at\]/.test(l)) return '@';
  if (l === '[:]') return ':';
  return '.';
}

/** Undo defanging anywhere in a block of text: hxxp(s)://, fxp://, [.], (.), {.}, [dot], [@], [at], [:], [://]. */
export function refang(s) {
  return s.replace(FANG, (m, s1, sep) => fangValue(m, s1, sep));
}

const INDICATOR = /\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62})\b/gi;
/** Defang every link, IP and domain-like name in a block of text so it is safe to share (not clickable). */
export function defang(s) {
  return s.replace(/\bhttp(s?):\/\//gi, 'hxxp$1://').replace(/\bftp:\/\//gi, 'fxp://').replace(INDICATOR, (m) => m.replace(/\./g, '[.]'));
}

/** Defang one normalised indicator of a known type. refang(defangIndicator(v, t)) === v. */
export function defangIndicator(value, type) {
  const dots = (x) => x.replace(/\./g, '[.]');
  switch (type) {
    case 'url': {
      const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(value);
      if (!m) return value;
      const scheme = m[1].toLowerCase() === 'ftp' ? 'fxp' : m[1].replace(/^http/i, 'hxxp');
      return `${scheme}://${m[2].startsWith('[') ? m[2] : dots(m[2])}${m[3]}`;
    }
    case 'domain': case 'ipv4': return dots(value);
    case 'ipv6': return value.replace(/:/g, '[:]');
    case 'email': { const at = value.lastIndexOf('@'); return `${value.slice(0, at)}[@]${dots(value.slice(at + 1))}`; }
    default: return value;
  }
}

/** refang() that also maps each output character back to the original text, so we can quote indicators as written. */
function refangMapped(text) {
  let out = '';
  const start = [];
  const end = [];
  let last = 0;
  const push = (str, s, e) => { for (let i = 0; i < str.length; i++) { start.push(s); end.push(e); } out += str; };
  for (const m of text.matchAll(FANG)) {
    for (let i = last; i < m.index; i++) push(text[i], i, i + 1);
    push(fangValue(m[0], m[1], m[2]), m.index, m.index + m[0].length);
    last = m.index + m[0].length;
  }
  for (let i = last; i < text.length; i++) push(text[i], i, i + 1);
  return { out, orig: (s, e) => text.slice(start[s], end[e - 1]) };
}

// ---------- extraction ----------
// Real TLDs that are also common file extensions. A two-label name ending in one (README.md, setup.py, photos.zip)
// is treated as a file name unless it was written defanged (evil[.]zip), which only happens to indicators.
export const FILE_LIKE_TLDS = new Set(['zip', 'mov', 'md', 'py', 'sh', 'rs', 'pl', 'so', 'ps', 'pub', 'cab', 'run', 'java', 'tf', 'mp']);

export const IOC_TYPES = [
  { id: 'url', label: 'URLs', one: 'URL' },
  { id: 'domain', label: 'Domains', one: 'domain' },
  { id: 'ip', label: 'IP addresses', one: 'IP address' },
  { id: 'email', label: 'Email addresses', one: 'email address' },
  { id: 'hash', label: 'File hashes', one: 'file hash' },
];

// Special-use names (RFC 6761, RFC 7686, .internal) that are not in the IANA root list but do appear in reports.
const SPECIAL_TLDS = new Set(['onion', 'example', 'test', 'invalid', 'localhost', 'local', 'internal']);

export const MAX_INPUT = 1_000_000;

const URL_RE = /\b(?:https?|ftp):\/\/(?:\[[0-9a-f:.]+\](?::\d{1,5})?|[^\s<>"'`{}|\\^[\]/?#]+)(?:[/?#][^\s<>"'`{}|\\^]*)?/gi;
const EMAIL_RE = /(?<![\w.%+-])[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9_%+-])?@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?![\w-]|\.[a-z0-9])/gi;
const IPV6_RE = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?![\w:]|\.\d)/gi;
const IPV4_RE = /(?<![\w.-])(?:\d{1,3}\.){3}\d{1,3}(?![\w-]|\.\d)/g;
const HASH_RE = /(?<![a-z0-9_-])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-z0-9_-])/gi;
const DOMAIN_RE = /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})(?![\w-]|\.[a-z0-9])/gi;
const VERSION_BEFORE = /(?:\bv|\bver\.?|\bversion|\bbuild|\brelease)\s*$/i;

/** A domain with a real TLD that does not look like a file name. */
export function isLikelyDomain(d, defanged = false) {
  const h = d.toLowerCase().replace(/\.$/, '');
  if (!isDomain(h)) return false;
  const labels = h.split('.');
  const tld = labels[labels.length - 1];
  if (!TLDS.has(tld) && !SPECIAL_TLDS.has(tld)) return false;
  if (!defanged && labels.length === 2 && FILE_LIKE_TLDS.has(tld)) return false;
  return true;
}

// Code such as System.IO or DateTime.Now: a capitalised last label in a name that is not all upper case.
const looksLikeCode = (w) => /[A-Z]/.test(w.slice(w.lastIndexOf('.') + 1)) && w !== w.toUpperCase();

function trimUrl(u) {
  let s = u.replace(/[.,;:!?'"*]+$/, '');
  // Drop a closing bracket that belongs to the surrounding text, e.g. "(see https://example.com/a)".
  for (const [o, c] of [['(', ')'], ['[', ']'], ['{', '}']]) {
    while (s.endsWith(c) && s.split(o).length < s.split(c).length) s = s.slice(0, -1).replace(/[.,;:!?'"*]+$/, '');
  }
  return s;
}

/**
 * Pulls indicators out of free text. Defanged forms are restored first.
 * Returns { items: [{ type, value, written, defanged, ...extra }], counts: { url, domain, ip, email, hash }, total, truncated }.
 * value is the normalised, live form; written is how it first appeared in the text.
 * Domains also include the hosts of extracted URLs and email addresses.
 */
export function extractIocs(input) {
  const truncated = input.length > MAX_INPUT;
  const text = truncated ? input.slice(0, MAX_INPUT) : input;
  const { out: r, orig } = refangMapped(text);
  const chars = r.split('');
  const mask = (i, n) => { for (let k = i; k < i + n; k++) chars[k] = ' '; };
  const masked = () => chars.join('');
  const seen = new Map();
  const add = (type, value, pos, written, extra = {}) => {
    const key = `${type}|${value}`;
    if (seen.has(key)) { seen.get(key).count++; return; }
    seen.set(key, { type, value, written, defanged: refang(written) !== written, pos, count: 1, ...extra });
  };
  const isFanged = (w) => refang(w) !== w;

  // URLs
  for (const m of r.matchAll(URL_RE)) {
    const raw = trimUrl(m[0]);
    let u;
    try { u = new URL(raw); } catch { continue; }
    const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const written = orig(m.index, m.index + raw.length);
    if (!(isIPv4(host) || isIPv6(host) || isLikelyDomain(host, isFanged(written)))) continue;
    mask(m.index, raw.length);
    add('url', u.href, m.index, written);
    if (isIPv4(host) || isIPv6(host)) add('ip', host, m.index, isFanged(written) ? defangIndicator(host, isIPv4(host) ? 'ipv4' : 'ipv6') : host, { version: isIPv4(host) ? 4 : 6, fromUrl: true });
    else add('domain', host, m.index, isFanged(written) ? defangIndicator(host, 'domain') : host, { fromUrl: true });
  }

  // Email addresses
  for (const m of masked().matchAll(EMAIL_RE)) {
    const written = orig(m.index, m.index + m[0].length);
    const v = m[0].toLowerCase();
    const domain = v.slice(v.lastIndexOf('@') + 1);
    if (!isLikelyDomain(domain, isFanged(written))) continue;
    mask(m.index, m[0].length);
    add('email', v, m.index, written);
    add('domain', domain, m.index, isFanged(written) ? defangIndicator(domain, 'domain') : domain, { fromEmail: true });
  }

  // IPv6 (before IPv4 so ::ffff:192.0.2.1 stays whole)
  for (const m of masked().matchAll(IPV6_RE)) {
    const s = m[0];
    const groups = s.split(':').filter(Boolean).length;
    // Need "::" or eight groups, and at least three groups, to avoid times (10:30:00), MACs and C++ (a::b).
    if (groups < 3 || !(s.includes('::') || groups >= 7) || !isIPv6(s) || /^\d{1,2}(:\d{2}){1,2}$/.test(s)) continue;
    const v = new URL(`http://[${s}]/`).hostname.slice(1, -1);
    mask(m.index, s.length);
    add('ip', v, m.index, orig(m.index, m.index + s.length), { version: 6 });
  }

  // IPv4 (skip version strings such as "v1.2.3.4" or "version 10.0.0.1")
  for (const m of masked().matchAll(IPV4_RE)) {
    if (!isIPv4(m[0]) || VERSION_BEFORE.test(r.slice(Math.max(0, m.index - 12), m.index))) continue;
    mask(m.index, m[0].length);
    add('ip', m[0], m.index, orig(m.index, m.index + m[0].length), { version: 4 });
  }

  // File hashes (MD5, SHA-1, SHA-256), exact lengths only, so longer hex runs (SHA-512, keys) are not split.
  for (const m of masked().matchAll(HASH_RE)) {
    const v = m[0].toLowerCase();
    if (/^\d+$/.test(v) || /^(.)\1+$/.test(v)) continue; // long numbers and 000…/fff… padding
    mask(m.index, v.length);
    add('hash', v, m.index, m[0], { hashType: HASHES[v.length] });
  }

  // Domains
  for (const m of masked().matchAll(DOMAIN_RE)) {
    const written = orig(m.index, m.index + m[0].length);
    if (!isLikelyDomain(m[0], isFanged(written)) || looksLikeCode(written)) continue;
    add('domain', m[0].toLowerCase().replace(/\.$/, ''), m.index, written);
  }

  const items = [...seen.values()].sort((a, b) => IOC_TYPES.findIndex((t) => t.id === a.type) - IOC_TYPES.findIndex((t) => t.id === b.type) || a.pos - b.pos);
  const counts = Object.fromEntries(IOC_TYPES.map((t) => [t.id, items.filter((i) => i.type === t.id).length]));
  return { items, counts, total: items.length, truncated };
}

/** Formats a list of extracted items, one per line, as written in the text, defanged, or refanged (live). */
export function formatIocs(items, mode = 'refanged') {
  return items.map((i) => {
    if (mode === 'written') return i.written;
    if (mode === 'defanged') return defangIndicator(i.value, i.type === 'ip' ? `ipv${i.version}` : i.type);
    return i.value;
  }).join('\n');
}
