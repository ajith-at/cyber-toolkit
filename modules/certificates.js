// Certificates: Certificate Transparency logs.
// Data comes from SSLMate Cert Spotter's free, keyless API (CORS-enabled, fast). crt.sh's JSON endpoint was tested
// first but returned HTTP 502 without CORS headers during the build (Oct 2026), which also puts errors in the browser
// console, so it is off by default and used as a deep link instead. Flip TRY_CRTSH to true to try it first again.
import { fetchJson, guessRegistrable } from '../js/net.js';
import { el, factCard, factGrid, listTable, mono, fmtDate, daysBetween, fmtNum, extLink, callout } from '../js/ui.js';

const TRY_CRTSH = false;
const CRT_TIMEOUT = 6000;

function fromCrtSh(rows, domain) {
  return rows.map((r) => ({
    id: String(r.id),
    names: String(r.name_value || '').split('\n').map((s) => s.trim().toLowerCase()).filter(Boolean),
    issuer: (/O=([^,]+)/.exec(r.issuer_name || '') || [])[1] || r.issuer_name,
    notBefore: new Date(r.not_before + 'Z'),
    notAfter: new Date(r.not_after + 'Z'),
    link: `https://crt.sh/?id=${r.id}`,
    domain,
  }));
}

function fromCertSpotter(rows, domain) {
  return rows.map((r) => ({
    id: r.cert_sha256 || r.id,
    names: (r.dns_names || []).map((s) => s.toLowerCase()),
    issuer: r.issuer?.friendly_name || (/O=([^,]+)/.exec(r.issuer?.name || '') || [])[1] || '—',
    notBefore: new Date(r.not_before),
    notAfter: new Date(r.not_after),
    revoked: r.revoked,
    link: r.cert_sha256 ? `https://crt.sh/?q=${r.cert_sha256}` : null,
    domain,
  }));
}

export default {
  id: 'certificates',
  name: 'Certificates',
  icon: 'file-badge',
  accepts: ['domain'],
  summary: 'TLS certificates from public Certificate Transparency logs, and the subdomains they reveal.',
  source: 'Certificate Transparency logs via Cert Spotter',

  async render(q, { body, setStatus }) {
    const domain = guessRegistrable(q.domain);
    const crtUrl = `https://crt.sh/?q=${encodeURIComponent(domain)}`;
    const csP = fetchJson(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`, { timeout: 15000 })
      .then((r) => ({ src: 'Cert Spotter', more: r.length >= 100, certs: fromCertSpotter(r, domain) }));
    csP.catch(() => {});

    let res = null;
    let crtErr = null;
    if (TRY_CRTSH) {
      try {
        const r = await fetchJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired&deduplicate=Y`, { timeout: CRT_TIMEOUT });
        res = { src: 'crt.sh', more: false, certs: fromCrtSh(r, domain) };
      } catch (e) { crtErr = e; }
    }
    if (!res) { try { res = await csP; } catch (e) { res = null; if (e.kind === 'http' && e.status === 429) crtErr = e; } }

    const links = el('div', { class: 'link-row' }, extLink(crtUrl, 'Open on crt.sh', { button: true }), extLink(`https://sslmate.com/certspotter/`, 'About Cert Spotter', { button: true }));
    if (!res) {
      setStatus('unknown', 'Unavailable');
      body.append(callout('unknown', 'Certificate logs could not be reached', crtErr?.status === 429 ? 'Cert Spotter\'s free hourly limit was reached. Try again later, or search crt.sh directly.' : 'Cert Spotter did not answer from the browser. Use the link to search crt.sh directly.', links));
      return;
    }

    const certs = res.certs.sort((a, b) => b.notBefore - a.notBefore);
    const now = new Date();
    const valid = certs.filter((c) => c.notAfter > now && c.notBefore <= now);
    const subs = [...new Set(certs.flatMap((c) => c.names).map((n) => n.replace(/^\*\./, '')).filter((n) => n === domain || n.endsWith(`.${domain}`)))].sort();
    const latest = certs[0];
    const soonest = valid.map((c) => c.notAfter).sort((a, b) => a - b)[0];
    const issuers = [...new Set(certs.map((c) => c.issuer))];

    setStatus(certs.length ? (valid.length ? 'low' : 'caution') : 'unknown', certs.length ? (valid.length ? 'Valid certs' : 'None valid') : 'None found');

    if (domain !== q.domain) body.append(el('p', { class: 'note' }, 'Showing certificates for ', mono(domain), ' and all its subdomains.'));
    if (!certs.length) {
      body.append(callout('unknown', 'No current certificates found', `No unexpired certificates for ${domain} were found in the logs. The site may not use HTTPS, or may use a certificate for a different name.`, links));
      return;
    }

    body.append(factGrid(
      factCard({ label: 'Certificates', figure: `${fmtNum(certs.length)}${res.more ? '+' : ''}`, caption: `Unexpired, from ${res.src}${res.more ? ' (first 100 shown)' : ''}` }),
      factCard({ label: 'Subdomains seen', figure: fmtNum(subs.length), caption: subs.length ? 'Names listed on the certificates' : null }),
      factCard({ label: 'Latest issued', figure: latest ? fmtNum(daysBetween(latest.notBefore)) : '—', unit: 'days ago', caption: latest ? `${latest.issuer}, ${fmtDate(latest.notBefore)}` : null }),
      factCard({ label: 'Next expiry', figure: soonest ? fmtNum(-daysBetween(soonest)) : '—', unit: soonest ? 'days' : null, status: soonest ? (-daysBetween(soonest) < 7 ? 'caution' : 'low') : 'unknown', statusText: soonest ? (-daysBetween(soonest) < 7 ? 'Expiring' : 'OK') : 'None valid', caption: `${issuers.length} issuer${issuers.length === 1 ? '' : 's'}: ${issuers.slice(0, 3).join(', ')}${issuers.length > 3 ? '…' : ''}` }),
    ));

    const shown = subs.slice(0, 60);
    body.append(el('article', { class: 'card table-card' },
      el('h3', { class: 'card-title' }, 'Discovered subdomains'),
      el('div', { class: 'chip-cloud' }, shown.map((s) => el('span', { class: 'chip-static mono' }, s))),
      subs.length > shown.length ? el('p', { class: 'caption' }, `+${subs.length - shown.length} more on crt.sh`) : null));

    const rows = certs.slice(0, 25).map((c) => ({
      issued: fmtDate(c.notBefore),
      expires: fmtDate(c.notAfter),
      issuer: c.issuer,
      names: el('span', {}, mono(c.names[0] || '—'), c.names.length > 1 ? el('span', { class: 'muted' }, ` +${c.names.length - 1}`) : null),
      id: c.link ? el('a', { href: c.link, target: '_blank', rel: 'noopener noreferrer', class: 'mono' }, String(c.id).slice(0, 12) + '…') : mono(String(c.id)),
    }));
    body.append(listTable(`Most recent certificates (${rows.length} of ${fmtNum(certs.length)})`,
      [{ key: 'issued', label: 'Issued' }, { key: 'expires', label: 'Expires' }, { key: 'issuer', label: 'Issuer' }, { key: 'names', label: 'Names' }, { key: 'id', label: 'Certificate' }],
      rows, el('div', { class: 'card-foot' }, links)));
  },
};
