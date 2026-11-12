// Open ports and known CVEs: Shodan InternetDB (internetdb.shodan.io). No key; sends Access-Control-Allow-Origin: *.
// IPv4 only. A 404 {"detail":"No information available"} means Shodan has not seen the IP, which is not an error.
// CVEs are then ranked by FIRST EPSS (api.first.org, no key, CORS open). Only CVE IDs are sent there, never the IP.
import { el, factCard, factGrid, detailsTable, rawJson, callout, extLink, list, fmtNum } from '../js/ui.js';
import { ipScope, isIPv4 } from '../js/detect.js';
import { NetError } from '../js/net.js';

const API = 'https://internetdb.shodan.io/';
const RISKY_TAGS = ['compromised', 'malware', 'eol-product', 'eol-os', 'c2', 'honeypot'];
const CVE_SHOWN = 24;
const EPSS_API = 'https://api.first.org/data/v1/epss';
const EPSS_BATCH = 100;
export const EPSS_HIGH = 0.5;

/** Fetch one IPv4 record. Returns null when InternetDB has nothing on the IP. Throws NetError otherwise. */
export async function internetDb(ip) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 15000);
  let res;
  try {
    res = await fetch(API + ip, { signal: ctl.signal, referrerPolicy: 'no-referrer', credentials: 'omit' });
  } catch (e) {
    if (e.name === 'AbortError') throw new NetError('timeout', 'Shodan InternetDB took too long to answer.');
    throw new NetError('network', 'Shodan InternetDB could not be reached. Check your connection or try again later.');
  } finally { clearTimeout(t); }
  if (res.status === 404) return null;
  if (!res.ok) throw new NetError('http', `Shodan InternetDB answered with HTTP ${res.status}.`, res.status);
  try { return await res.json(); } catch { throw new NetError('parse', 'Shodan InternetDB sent something that was not JSON.'); }
}

/** Pure summary of an InternetDB record (null = nothing seen). */
export function assessInternetDb(d) {
  if (!d) return { status: 'unknown', text: 'Nothing seen', ports: [], vulns: [], tags: [], hostnames: [], cpes: [], risky: [] };
  const arr = (v) => (Array.isArray(v) ? v.map(String) : []);
  const ports = arr(d.ports).map(Number).filter((p) => Number.isInteger(p) && p >= 0 && p <= 65535).sort((a, b) => a - b);
  // Newest CVEs first (by year, then number).
  const key = (c) => { const m = /^CVE-(\d{4})-(\d+)$/i.exec(c); return m ? [Number(m[1]), Number(m[2])] : [0, 0]; };
  const vulns = [...new Set(arr(d.vulns).filter((c) => /^CVE-\d{4}-\d{4,}$/i.test(c)).map((c) => c.toUpperCase()))]
    .sort((a, b) => { const [ya, na] = key(a); const [yb, nb] = key(b); return yb - ya || nb - na; });
  const tags = arr(d.tags);
  const risky = tags.filter((t) => RISKY_TAGS.includes(t.toLowerCase()));
  let status = 'unknown', text = 'No CVEs listed';
  if (vulns.length) { status = 'caution'; text = `${vulns.length} CVE${vulns.length === 1 ? '' : 's'}`; }
  else if (risky.length) { status = 'caution'; text = `Tagged ${risky[0]}`; }
  return { status, text, ports, vulns, tags, hostnames: arr(d.hostnames), cpes: arr(d.cpes), risky };
}

/** Fetch EPSS scores for a list of CVE IDs (batched, 100 per call). Returns Map cve -> { epss, percentile, date }. Throws NetError. */
export async function epssScores(cves) {
  const out = new Map();
  for (let i = 0; i < cves.length; i += EPSS_BATCH) {
    const batch = cves.slice(i, i + EPSS_BATCH);
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 15000);
    let res;
    try {
      res = await fetch(`${EPSS_API}?cve=${batch.map(encodeURIComponent).join(',')}&limit=${EPSS_BATCH}`, { signal: ctl.signal, referrerPolicy: 'no-referrer', credentials: 'omit' });
    } catch (e) {
      if (e.name === 'AbortError') throw new NetError('timeout', 'FIRST EPSS took too long to answer.');
      throw new NetError('network', 'FIRST EPSS could not be reached.');
    } finally { clearTimeout(t); }
    if (!res.ok) throw new NetError('http', `FIRST EPSS answered with HTTP ${res.status}.`, res.status);
    let j;
    try { j = await res.json(); } catch { throw new NetError('parse', 'FIRST EPSS sent something that was not JSON.'); }
    for (const r of Array.isArray(j?.data) ? j.data : []) {
      const cve = String(r?.cve || '').toUpperCase();
      const epss = Number(r?.epss), percentile = Number(r?.percentile);
      if (/^CVE-\d{4}-\d{4,}$/.test(cve) && Number.isFinite(epss) && epss >= 0 && epss <= 1) {
        out.set(cve, { epss, percentile: Number.isFinite(percentile) ? percentile : null, date: typeof r.date === 'string' ? r.date : null });
      }
    }
  }
  return out;
}

/** Pure: order CVEs by EPSS (highest first); CVEs without a score keep their order after the scored ones. */
export function rankByEpss(vulns, scores) {
  const scored = vulns.filter((c) => scores.has(c)).sort((a, b) => scores.get(b).epss - scores.get(a).epss);
  const unscored = vulns.filter((c) => !scores.has(c));
  const top = scored[0] ? { cve: scored[0], ...scores.get(scored[0]) } : null;
  const date = scored.map((c) => scores.get(c).date).filter(Boolean).sort().pop() || null;
  return { order: [...scored, ...unscored], top, date, scoredCount: scored.length, high: scored.filter((c) => scores.get(c).epss >= EPSS_HIGH) };
}

export const fmtPct = (p) => (p >= 0.1 ? (p * 100).toFixed(1) : p >= 0.001 ? (p * 100).toFixed(2) : '<0.1') + '%';

const chips = (items, monoItems = true) => (items.length ? el('div', { class: 'chip-cloud' }, items.map((s) => el('span', { class: `chip-static${monoItems ? ' mono' : ''}` }, s))) : null);
const nvd = (c, scores) => {
  const link = extLink(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c)}`, c);
  const s = scores?.get(c);
  if (!s) return link;
  return el('span', { class: `cve-item${s.epss >= EPSS_HIGH ? ' cve-hot' : ''}` }, link,
    el('span', { class: 'epss', title: `EPSS ${s.epss}${s.percentile != null ? `, percentile ${s.percentile}` : ''}` }, fmtPct(s.epss)));
};

export default {
  id: 'open-ports',
  name: 'Open ports & CVEs',
  icon: 'network',
  accepts: ['ip'],
  summary: 'Open ports, detected software, tags and known CVEs Shodan has seen on a public IPv4 address (InternetDB), with CVEs ranked by FIRST EPSS exploit likelihood.',
  source: 'Shodan InternetDB · free for non-commercial use, updated weekly · CVE ranking by FIRST EPSS',

  async render(q, { body, setStatus }) {
    const ip = q.ip;
    const shodan = `https://www.shodan.io/host/${encodeURIComponent(ip)}`;
    const scope = ipScope(ip);
    if (scope || !isIPv4(ip)) {
      setStatus('unknown', 'Not available');
      body.append(callout('unknown', 'Not available for this address', scope
        ? `${ip} is a ${scope} address, so internet scanners cannot see it. Nothing was sent.`
        : 'Shodan InternetDB only covers IPv4 addresses. Nothing was sent.'));
      return { facts: [['IP address', ip], ['Open ports (InternetDB)', 'Not available']] };
    }

    let d;
    try { d = await internetDb(ip); } catch (err) {
      setStatus('unknown', 'Unavailable');
      body.append(callout('unknown', 'Lookup unavailable', err.message, el('p', { class: 'caption' }, extLink(shodan, 'Open the IP on Shodan'))));
      return { facts: [['IP address', ip], ['Open ports (InternetDB)', 'Unavailable']] };
    }

    const a = assessInternetDb(d);
    if (!d) {
      setStatus(a.status, a.text);
      body.append(callout('unknown', 'Nothing seen', 'Shodan has no record of open ports on this IP. That usually means nothing answered its scans recently; it does not prove the host is safe.', el('p', { class: 'caption' }, extLink(shodan, 'Open the IP on Shodan'))));
      return { facts: [['IP address', ip], ['Open ports (InternetDB)', 'Nothing seen']] };
    }

    // Rank CVEs by EPSS; if EPSS is unreachable keep the newest-first list.
    let scores = null, rank = null, epssErr = null;
    if (a.vulns.length) {
      try { scores = await epssScores(a.vulns); rank = rankByEpss(a.vulns, scores); } catch (err) { epssErr = err.message; }
    }
    const vulns = rank ? rank.order : a.vulns;
    if (rank?.high.length) setStatus('high', `${a.vulns.length} CVE${a.vulns.length === 1 ? '' : 's'} · EPSS ${fmtPct(rank.top.epss)}`);
    else setStatus(a.status, a.text);

    body.append(factGrid(
      factCard({ label: 'Open ports', figure: fmtNum(a.ports.length), caption: a.ports.length ? a.ports.slice(0, 8).join(', ') + (a.ports.length > 8 ? ', …' : '') : 'No open ports seen.' }),
      factCard({ label: 'Known CVEs', figure: fmtNum(a.vulns.length), status: a.vulns.length ? 'caution' : null, statusText: a.vulns.length ? 'Check' : null, caption: a.vulns.length ? 'Matched from software versions; may include CVEs that are already patched.' : 'None matched to the detected software.' }),
      factCard({ label: 'Tags', figure: a.tags.length ? a.tags.join(', ') : 'None', small: true, status: a.risky.length ? 'caution' : null, statusText: a.risky.length ? 'Check' : null, caption: a.risky.length ? `${a.risky.join(', ')} is worth a closer look.` : null }),
      a.vulns.length ? factCard({ label: 'Highest EPSS', figure: rank?.top ? fmtPct(rank.top.epss) : '—',
        status: rank?.high.length ? 'high' : null, statusText: rank?.high.length ? 'Likely target' : null,
        caption: rank?.top ? `${rank.top.cve}: chance of exploitation in the next 30 days${rank.date ? ` (scored ${rank.date})` : ''}. Still unverified, since InternetDB matches by version.`
          : epssErr ? `EPSS unavailable: ${epssErr}` : 'No EPSS scores for these CVEs.' }) : null,
      factCard({ label: 'Hostnames', figure: a.hostnames[0] || 'None', mono: !!a.hostnames[0], small: true, caption: a.hostnames.length > 1 ? `+${a.hostnames.length - 1} more` : null }),
    ));

    const shown = vulns.slice(0, CVE_SHOWN);
    const rest = vulns.slice(CVE_SHOWN);
    body.append(detailsTable('Ports, software and CVEs', [
      ['Open ports', chips(a.ports.map(String))],
      ['Software (CPE)', list(a.cpes, true)],
      ['Tags', chips(a.tags, false)],
      ['Hostnames', list(a.hostnames, true)],
      [rank ? 'Known CVEs (by EPSS)' : 'Known CVEs', vulns.length ? el('div', {},
        el('div', { class: 'chip-cloud cve-list' }, shown.map((c) => nvd(c, scores))),
        rest.length ? el('details', { class: 'raw' }, el('summary', {}, `Show ${rest.length} more`), el('div', { class: 'chip-cloud cve-list' }, rest.map((c) => nvd(c, scores)))) : null) : null],
    ], el('div', { class: 'card-foot' },
      el('p', { class: 'caption' }, 'InternetDB lists CVEs by matching software versions, so some may be unverified or already patched. Data is refreshed about weekly.'),
      el('p', { class: 'caption' }, rank ? `Percentages are FIRST EPSS scores: the estimated chance each CVE is exploited in the wild in the next 30 days${rank.date ? `, scored ${rank.date}` : ''}. Only the CVE IDs were sent to api.first.org.`
        : epssErr ? `CVEs are shown newest first because EPSS ranking was unavailable (${epssErr}).` : null),
      rawJson('View raw InternetDB response', d), extLink(shodan, 'Open on Shodan'))));

    return {
      facts: [
        ['IP address', ip], ['Open ports', a.ports.map(String)], ['Known CVEs', vulns.length ? `${vulns.length}: ${vulns.map((c) => (scores?.has(c) ? `${c} (EPSS ${fmtPct(scores.get(c).epss)})` : c)).join(', ')}` : 'None'],
        ['Tags', a.tags], ['Hostnames', a.hostnames], ['Software (CPE)', a.cpes],
      ],
      raw: d,
    };
  },
};
