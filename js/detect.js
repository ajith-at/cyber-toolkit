// Smart input: works out what was pasted and normalises it.
// Returns { type, value, display, host?, domain?, ip?, url?, email?, hashType?, refanged } or { type: 'invalid', reason }.

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HEX = /^[a-f0-9]+$/i;
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i;
const EMAIL = /^[^\s@<>()[\]\\,;:"]+@([^\s@]+)$/;

/** Undo common "defanging" used when sharing indicators: hxxp, [.], (.), [@], [:]. */
export function refang(s) {
  return s
    .replace(/^hxxp(s?):\/\//i, 'http$1://')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.')
    .replace(/\[@\]|\[at\]/gi, '@')
    .replace(/\[:\]/g, ':');
}

export function isIPv4(s) { return IPV4.test(s); }

export function isIPv6(s) {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
  try { new URL(`http://[${s}]/`); return true; } catch { return false; }
}

/** Converts a hostname (incl. Unicode) to lower-case punycode, or null if invalid. */
export function toAsciiHost(s) {
  try {
    const h = new URL(`http://${s}/`).hostname;
    return h.replace(/\.$/, '');
  } catch { return null; }
}

export function isDomain(s) {
  if (!s || s.length > 253 || !s.includes('.')) return false;
  const labels = s.split('.');
  const tld = labels[labels.length - 1];
  if (!/^(xn--[a-z0-9-]+|[a-z]{2,63})$/i.test(tld)) return false;
  return labels.every((l) => LABEL.test(l));
}

/** Private, loopback, link-local, CGNAT, documentation and other non-routable ranges. */
export function ipScope(ip) {
  if (isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private (RFC 1918)';
    if (a === 127) return 'loopback';
    if (a === 169 && b === 254) return 'link-local';
    if (a === 100 && b >= 64 && b <= 127) return 'carrier-grade NAT';
    if (a === 0 || a >= 224) return a >= 240 || a === 0 ? 'reserved' : 'multicast';
    if ((a === 192 && b === 0 && ip.startsWith('192.0.2.')) || ip.startsWith('198.51.100.') || ip.startsWith('203.0.113.')) return 'documentation';
    return null;
  }
  const l = ip.toLowerCase();
  if (l === '::1') return 'loopback';
  if (l === '::') return 'unspecified';
  if (/^f[cd]/.test(l)) return 'unique local';
  if (/^fe[89ab]/.test(l)) return 'link-local';
  if (/^ff/.test(l)) return 'multicast';
  if (l.startsWith('2001:db8')) return 'documentation';
  return null;
}

export const HASHES = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256' };

export function detect(raw) {
  const input = (raw || '').trim();
  if (!input) return { type: 'invalid', reason: 'Type or paste an IP address, domain, URL, email or file hash.' };
  if (input.length > 2048) return { type: 'invalid', reason: 'That is too long to be an indicator.' };
  const s = refang(input);
  const refanged = s !== input;

  // Hash
  if (HEX.test(s) && HASHES[s.length]) {
    const v = s.toLowerCase();
    return { type: 'hash', value: v, display: v, hashType: HASHES[s.length], refanged };
  }

  // Bracketed IPv6 like [2001:db8::1]
  const unbr = s.replace(/^\[(.+)\]$/, '$1');
  if (isIPv4(unbr)) return { type: 'ip', value: unbr, display: unbr, ip: unbr, version: 4, refanged };
  if (isIPv6(unbr)) {
    const v = new URL(`http://[${unbr}]/`).hostname.slice(1, -1);
    return { type: 'ip', value: v, display: v, ip: v, version: 6, refanged };
  }

  // URL (explicit scheme, or host followed by a path / query)
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) || /^[^\s/@]+\.[^\s/@]+[/?#]/.test(s)) {
    let u;
    try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `http://${s}`); } catch { u = null; }
    if (!u || !/^(https?|ftp):$/.test(u.protocol) || !u.hostname) {
      return { type: 'invalid', reason: 'That looks like a link, but it could not be read. Only http, https and ftp links are supported.' };
    }
    const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const base = { type: 'url', value: u.href, display: u.href, url: u.href, host, refanged };
    if (isIPv4(host) || isIPv6(host)) return { ...base, ip: host };
    if (isDomain(host)) return { ...base, domain: host };
    return { type: 'invalid', reason: `The link's host "${host}" is not a valid domain or IP.` };
  }

  // Email
  const em = EMAIL.exec(s);
  if (em) {
    const host = toAsciiHost(em[1]);
    if (host && isDomain(host)) {
      const v = `${s.slice(0, s.lastIndexOf('@'))}@${host}`.toLowerCase();
      return { type: 'email', value: v, display: v, email: v, domain: host, refanged };
    }
    return { type: 'invalid', reason: 'That looks like an email address, but the part after @ is not a valid domain.' };
  }

  // Domain (allow Unicode, convert to punycode)
  if (!/[\s/@]/.test(s)) {
    const host = toAsciiHost(s);
    if (host && isDomain(host)) return { type: 'domain', value: host, display: host, domain: host, refanged };
  }

  if (HEX.test(s)) return { type: 'invalid', reason: `That looks like a hex string of ${s.length} characters. File hashes are 32 (MD5), 40 (SHA-1) or 64 (SHA-256).` };
  return { type: 'invalid', reason: 'Not recognised. Try an IP (8.8.8.8), a domain (example.com), a URL, an email address, or an MD5/SHA-1/SHA-256 hash.' };
}

export const TYPE_LABEL = { ip: 'IP address', domain: 'Domain', url: 'URL', email: 'Email', hash: 'File hash' };
