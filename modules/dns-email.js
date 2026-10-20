// DNS & email security: A/AAAA/MX/NS/TXT records and an SPF + DMARC grade, all via DNS-over-HTTPS.
import { doh, guessRegistrable } from '../js/net.js';
import { el, factCard, factGrid, listTable, detailsTable, mono, fmtNum, callout, errorCallout, worst, extLink } from '../js/ui.js';

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT'];

export function analyseSpf(txts) {
  const spf = txts.filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!spf.length) return { status: 'caution', word: 'Missing', note: 'No SPF record, so anyone can claim to send mail from this domain.' };
  if (spf.length > 1) return { status: 'caution', word: 'Invalid', record: spf.join('  |  '), note: 'More than one SPF record. Receivers treat that as an error (permerror).' };
  const rec = spf[0];
  const lookups = (rec.match(/\b(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)/gi) || []).length;
  const all = /([+~?-]?)all\b/i.exec(rec);
  const q = all ? (all[1] || '+') : null;
  let r;
  if (q === '+') r = { status: 'high', word: 'Allows anyone', note: '"+all" lets every server on the internet send as this domain.' };
  else if (q === '?') r = { status: 'caution', word: 'Neutral', note: '"?all" gives no protection against spoofing.' };
  else if (q === '~') r = { status: 'low', word: 'Soft fail', note: '"~all" marks unlisted senders as suspicious.' };
  else if (q === '-') r = { status: 'low', word: 'Hard fail', note: '"-all" rejects unlisted senders. Strongest setting.' };
  else if (/redirect=/i.test(rec)) r = { status: 'low', word: 'Redirect', note: 'Policy is delegated to another domain with redirect=.' };
  else r = { status: 'caution', word: 'No "all"', note: 'The record does not end with an "all" rule, so unlisted senders are not handled.' };
  if (lookups > 10) r = { ...r, status: worst(r.status, 'caution'), note: `${r.note} It also uses ${lookups} DNS lookups (the limit is 10).` };
  return { ...r, record: rec, lookups };
}

export function analyseDmarc(txts) {
  const recs = txts.filter((t) => /^v=DMARC1/i.test(t));
  if (!recs.length) return { status: 'caution', word: 'Missing', note: 'No DMARC record, so receivers have no instruction for mail that fails SPF/DKIM.' };
  const rec = recs[0];
  const tag = (k) => (new RegExp(`(?:^|;)\\s*${k}\\s*=\\s*([^;]+)`, 'i').exec(rec) || [])[1]?.trim();
  const p = (tag('p') || '').toLowerCase();
  const pct = tag('pct');
  const rua = tag('rua');
  let r;
  if (p === 'reject') r = { status: 'low', word: 'Reject', note: 'Spoofed mail is rejected.' };
  else if (p === 'quarantine') r = { status: 'low', word: 'Quarantine', note: 'Spoofed mail goes to spam.' };
  else if (p === 'none') r = { status: 'caution', word: 'Monitor only', note: '"p=none" only reports; spoofed mail is still delivered.' };
  else r = { status: 'caution', word: 'Invalid', note: 'The record has no valid p= policy.' };
  if (pct && Number(pct) < 100 && r.status === 'low') r = { ...r, note: `${r.note} Applied to ${pct}% of mail only.` };
  return { ...r, record: rec, policy: p, pct, rua };
}

function grade(spf, dmarc, hasMx) {
  if (spf.status === 'high') return { g: 'F', status: 'high' };
  const spfOk = spf.status === 'low';
  const dm = dmarc.status === 'low';
  if (spfOk && dm) return { g: 'A', status: 'low' };
  if (spfOk && dmarc.word === 'Monitor only') return { g: 'B', status: 'caution' };
  if (spfOk || dm || dmarc.word === 'Monitor only') return { g: 'C', status: 'caution' };
  return { g: hasMx ? 'F' : 'D', status: hasMx ? 'high' : 'caution' };
}

async function findDmarc(host) {
  // Check the exact host first, then parent domains (DMARC organisational-domain fallback, approximated without the PSL).
  const labels = host.split('.');
  for (let i = 0; i <= labels.length - 2; i++) {
    const d = labels.slice(i).join('.');
    const r = await doh(`_dmarc.${d}`, 'TXT');
    const txt = r.answers.map((a) => a.data);
    if (txt.some((t) => /^v=DMARC1/i.test(t))) return { at: d, txt };
  }
  return { at: host, txt: [] };
}

export default {
  id: 'dns-email',
  name: 'DNS & email security',
  icon: 'mail-check',
  accepts: ['domain'],
  summary: 'A, AAAA, MX, NS and TXT records, with a simple SPF and DMARC grade for email spoofing protection.',
  source: 'DNS-over-HTTPS (Google Public DNS, Cloudflare fallback)',

  async render(q, { body, setStatus }) {
    const host = q.domain;
    // Web hosts such as www.example.com rarely send mail, so SPF/DMARC/MX are graded on the parent domain.
    const mailDomain = guessRegistrable(host);
    let results, dmarcRes, mailRes;
    try {
      results = await Promise.all(TYPES.map((t) => doh(host, t)));
      mailRes = mailDomain === host ? null : await Promise.all([doh(mailDomain, 'MX'), doh(mailDomain, 'TXT')]);
      dmarcRes = await findDmarc(mailDomain);
    } catch (e) {
      setStatus('unknown', 'Unavailable');
      body.append(errorCallout(e, `https://dns.google/query?name=${encodeURIComponent(host)}`, 'Open in Google Public DNS'));
      return;
    }
    const by = Object.fromEntries(TYPES.map((t, i) => [t, results[i]]));
    if (by.A.nx) {
      setStatus('caution', 'Does not exist');
      body.append(callout('caution', `${host} does not exist in DNS`, 'The name returned NXDOMAIN. It may be unregistered, expired or mistyped.'));
      return;
    }
    const mailMx = mailRes ? mailRes[0] : by.MX;
    const txts = (mailRes ? mailRes[1] : by.TXT).answers.map((a) => a.data);
    const mx = mailMx.answers.map((a) => { const [pr, ex] = a.data.split(/\s+/); return { pr: Number(pr), ex: (ex || '').replace(/\.$/, '') }; }).sort((a, b) => a.pr - b.pr);
    const spf = analyseSpf(txts);
    const dmarc = analyseDmarc(dmarcRes.txt);
    const nullMx = mx.length === 1 && (mx[0].ex === '' || mx[0].ex === '.');
    const gr = grade(spf, dmarc, mx.length > 0 && !nullMx);
    setStatus(gr.status, `Email grade ${gr.g}`);
    if (mailRes) body.append(el('p', { class: 'note' }, 'Email checks (SPF, DMARC, MX) use the parent domain ', mono(mailDomain), '. The DNS records table is for ', mono(host), '.'));

    body.append(factGrid(
      factCard({ label: 'Email security grade', status: gr.status, figure: gr.g, caption: 'Based on SPF and DMARC. DKIM needs a selector, so it is not graded.' }),
      factCard({ label: 'SPF', status: spf.status, statusText: spf.word, figure: spf.record ? 'Present' : 'None', small: true, caption: spf.note }),
      factCard({ label: 'DMARC', status: dmarc.status, statusText: dmarc.word, figure: dmarc.record ? (dmarc.policy ? `p=${dmarc.policy}` : 'Present') : 'None', small: true, caption: dmarc.note }),
      factCard({ label: 'Mail servers', figure: fmtNum(nullMx ? 0 : mx.length), caption: nullMx ? 'Null MX: this domain says it never receives mail.' : mx[0] ? `Primary ${mx[0].ex}` : 'No MX records; the domain does not receive mail.' }),
    ));

    const rows = [];
    for (const t of TYPES) for (const a of by[t].answers) rows.push({ type: t, value: mono(a.data), ttl: fmtNum(a.TTL) });
    body.append(listTable('DNS records', [{ key: 'type', label: 'Type' }, { key: 'value', label: 'Value' }, { key: 'ttl', label: 'TTL (s)', num: true }], rows,
      el('div', { class: 'card-foot' }, el('span', { class: 'caption' }, `Resolved by ${by.A.provider}${by.A.dnssec ? ' · DNSSEC validated' : ''}`), extLink(`https://dns.google/query?name=${encodeURIComponent(host)}`, 'Open in Google Public DNS'))));

    body.append(detailsTable('Email authentication', [
      ['Mail domain', mono(mailDomain)],
      ['SPF record', spf.record ? mono(spf.record) : null, {}],
      ['SPF DNS lookups', spf.lookups != null ? `${spf.lookups} of 10` : null],
      ['DMARC record', dmarc.record ? mono(dmarc.record) : null],
      ['DMARC found at', dmarc.record ? mono(`_dmarc.${dmarcRes.at}`) : null],
      ['DMARC reports (rua)', dmarc.rua ? mono(dmarc.rua) : null],
    ]));
  },
};
