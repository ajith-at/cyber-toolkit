// DNS & email security: A/AAAA/MX/NS/TXT records, an SPF + DMARC grade, and the newer mail protections
// (MTA-STS, TLS-RPT, BIMI, best-effort DKIM selectors), all via DNS-over-HTTPS.
import { doh, guessRegistrable } from '../js/net.js';
import { el, pill, factCard, factGrid, listTable, detailsTable, mono, fmtNum, callout, errorCallout, worst, extLink } from '../js/ui.js';

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

const tagOf = (rec, k) => (new RegExp(`(?:^|;)\\s*${k}\\s*=\\s*([^;]*)`, 'i').exec(rec) || [])[1]?.trim();

/** MTA-STS: _mta-sts.<domain> TXT "v=STSv1; id=...". The policy file has no CORS headers, so it is linked, not fetched. */
export function analyseMtaSts(txts, domain) {
  const policyUrl = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  const recs = txts.filter((t) => /^v=STSv1/i.test(t));
  if (!recs.length) return { present: false, status: 'unknown', word: 'Missing', policyUrl, note: 'No MTA-STS record, so sending servers may fall back to unencrypted delivery if TLS is stripped.' };
  if (recs.length > 1) return { present: false, status: 'caution', word: 'Invalid', record: recs.join('  |  '), policyUrl, note: 'More than one MTA-STS record. Senders ignore the policy when there is more than one.' };
  const id = tagOf(recs[0], 'id');
  if (!id) return { present: false, status: 'caution', word: 'Invalid', record: recs[0], policyUrl, note: 'The record has no id= tag, so senders ignore it.' };
  return { present: true, status: 'low', word: 'Present', record: recs[0], id, policyUrl, note: 'Senders are asked to require TLS. The mode (enforce or testing) is in the policy file.' };
}

/** TLS-RPT: _smtp._tls.<domain> TXT "v=TLSRPTv1; rua=...". */
export function analyseTlsRpt(txts) {
  const recs = txts.filter((t) => /^v=TLSRPTv1/i.test(t));
  if (!recs.length) return { present: false, status: 'unknown', word: 'Missing', note: 'No TLS-RPT record, so the domain gets no reports about failed encrypted deliveries.' };
  const rua = tagOf(recs[0], 'rua');
  if (!rua) return { present: false, status: 'caution', word: 'Invalid', record: recs[0], note: 'The record has no rua= address, so no reports can be sent.' };
  return { present: true, status: 'low', word: 'Present', record: recs[0], rua, note: 'Mail servers send daily reports about TLS delivery problems.' };
}

/** BIMI: default._bimi.<domain> TXT "v=BIMI1; l=<logo>; a=<VMC/CMC>". */
export function analyseBimi(txts) {
  const recs = txts.filter((t) => /^v=BIMI1/i.test(t));
  if (!recs.length) return { present: false, status: 'unknown', word: 'Missing', note: 'No BIMI record, so mail apps show no brand logo. This is optional.' };
  const rec = recs[0];
  const logo = tagOf(rec, 'l') || '';
  const cert = tagOf(rec, 'a') || '';
  if (!logo) return { present: false, status: 'unknown', word: 'Declined', record: rec, note: 'An empty BIMI record: the domain says it does not publish a logo.' };
  const safe = (u) => (/^https:\/\//i.test(u) ? u : null);
  return { present: true, status: 'low', word: 'Present', record: rec, logo: safe(logo), cert: safe(cert),
    note: cert ? 'Publishes a brand logo with a mark certificate (VMC or CMC), which Gmail and Apple Mail need.' : 'Publishes a brand logo but no mark certificate, so Gmail and Apple Mail will not show it.' };
}

// Common DKIM selectors to try. Capped at 8 lookups; selectors can be any name, so this is best effort.
export const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'default', 'k1', 's1', 's2', 'dkim'];

/** DKIM: results is [{ selector, txts }]. Only records that look like DKIM keys count (wildcard TXT records are ignored). */
export function analyseDkim(results) {
  const found = [];
  for (const { selector, txts } of results) {
    const rec = txts.find((t) => /^v=DKIM1/i.test(t) || /(?:^|;)\s*p=/i.test(t));
    if (!rec) continue;
    const p = tagOf(rec, 'p');
    found.push({ selector, record: rec, keyType: (tagOf(rec, 'k') || 'rsa').toLowerCase(), revoked: p === '' || p == null });
  }
  const live = found.filter((f) => !f.revoked);
  if (live.length) return { present: true, status: 'low', word: 'Found', found, note: `Found a DKIM key at ${live.map((f) => f.selector).join(', ')}. Other selectors may also exist.` };
  if (found.length) return { present: false, status: 'unknown', word: 'Revoked only', found, note: 'Only revoked (empty) keys were found at the common selectors. DKIM may still use another selector.' };
  return { present: false, status: 'unknown', word: 'Not found', found, note: 'None of the common selectors publish a key. That does not mean DKIM is off; it may use another selector.' };
}

/** Bonus only: MTA-STS plus TLS-RPT adds a "+" to an A, B or C grade. Missing them never lowers the grade. */
export function withBonus(g, mtaSts, tlsRpt) {
  return mtaSts?.present && tlsRpt?.present && ['A', 'B', 'C'].includes(g.g) ? { ...g, g: `${g.g}+`, bonus: true } : g;
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

/** The newer protections. Each lookup fails on its own, so one slow resolver answer never hides the rest. */
async function newerChecks(domain) {
  const txt = async (name) => (await doh(name, 'TXT')).answers.map((a) => a.data);
  const [mta, tls, bimi, ...dkim] = await Promise.allSettled([
    txt(`_mta-sts.${domain}`), txt(`_smtp._tls.${domain}`), txt(`default._bimi.${domain}`),
    ...DKIM_SELECTORS.map((sel) => txt(`${sel}._domainkey.${domain}`)),
  ]);
  const val = (r, fn) => (r.status === 'fulfilled' ? fn(r.value) : { failed: true, status: 'unknown', word: 'Not checked', note: 'The DNS lookup failed. Try again later.' });
  const dkimOk = dkim.map((r, i) => ({ selector: DKIM_SELECTORS[i], txts: r.status === 'fulfilled' ? r.value : [] }));
  const dkimRes = analyseDkim(dkimOk);
  const dkimFailed = dkim.filter((r) => r.status === 'rejected').length;
  if (dkimFailed) dkimRes.note += ` ${dkimFailed} of ${DKIM_SELECTORS.length} lookups failed.`;
  return { mtaSts: val(mta, (t) => analyseMtaSts(t, domain)), tlsRpt: val(tls, analyseTlsRpt), bimi: val(bimi, analyseBimi), dkim: dkimRes };
}

export default {
  id: 'dns-email',
  name: 'DNS & email security',
  icon: 'mail-check',
  accepts: ['domain'],
  summary: 'A, AAAA, MX, NS and TXT records, an SPF and DMARC grade for spoofing protection, plus MTA-STS, TLS-RPT, BIMI and common DKIM selectors.',
  source: 'DNS-over-HTTPS (Google Public DNS, Cloudflare fallback)',

  async render(q, { body, setStatus }) {
    const host = q.domain;
    // Web hosts such as www.example.com rarely send mail, so SPF/DMARC/MX are graded on the parent domain.
    const mailDomain = guessRegistrable(host);
    let results, dmarcRes, mailRes, extra;
    try {
      const extraP = newerChecks(mailDomain);
      results = await Promise.all(TYPES.map((t) => doh(host, t)));
      mailRes = mailDomain === host ? null : await Promise.all([doh(mailDomain, 'MX'), doh(mailDomain, 'TXT')]);
      dmarcRes = await findDmarc(mailDomain);
      extra = await extraP;
    } catch (e) {
      setStatus('unknown', 'Unavailable');
      body.append(errorCallout(e, `https://dns.google/query?name=${encodeURIComponent(host)}`, 'Open in Google Public DNS'));
      return { facts: [['Host', host], ['DNS', 'Unavailable']] };
    }
    const by = Object.fromEntries(TYPES.map((t, i) => [t, results[i]]));
    if (by.A.nx) {
      setStatus('caution', 'Does not exist');
      body.append(callout('caution', `${host} does not exist in DNS`, 'The name returned NXDOMAIN. It may be unregistered, expired or mistyped.'));
      return { facts: [['Host', host], ['DNS', 'Does not exist (NXDOMAIN)']] };
    }
    const mailMx = mailRes ? mailRes[0] : by.MX;
    const txts = (mailRes ? mailRes[1] : by.TXT).answers.map((a) => a.data);
    const mx = mailMx.answers.map((a) => { const [pr, ex] = a.data.split(/\s+/); return { pr: Number(pr), ex: (ex || '').replace(/\.$/, '') }; }).sort((a, b) => a.pr - b.pr);
    const spf = analyseSpf(txts);
    const dmarc = analyseDmarc(dmarcRes.txt);
    const nullMx = mx.length === 1 && (mx[0].ex === '' || mx[0].ex === '.');
    const gr = withBonus(grade(spf, dmarc, mx.length > 0 && !nullMx), extra.mtaSts, extra.tlsRpt);
    setStatus(gr.status, `Email grade ${gr.g}`);
    if (mailRes) body.append(el('p', { class: 'note' }, 'Email checks (SPF, DMARC, MX and the newer protections) use the parent domain ', mono(mailDomain), '. The DNS records table is for ', mono(host), '.'));

    body.append(factGrid(
      factCard({ label: 'Email security grade', status: gr.status, figure: gr.g, caption: gr.bonus ? 'Based on SPF and DMARC, with a bonus "+" for MTA-STS and TLS-RPT.' : 'Based on SPF and DMARC. MTA-STS plus TLS-RPT adds a bonus "+"; DKIM is not graded.' }),
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

    const { mtaSts, tlsRpt, bimi, dkim } = extra;
    const dkimRec = dkim.found.length ? el('ul', { class: 'plain' }, dkim.found.map((f) => el('li', {}, mono(`${f.selector}._domainkey`), f.revoked ? ' · revoked (empty key)' : ` · ${f.keyType} key`))) : null;
    const row = (label, r, ...more) => [label, el('div', { class: 'check-cell' }, pill(r.status, r.word), el('p', { class: 'caption' }, r.note), r.record ? el('div', { class: 'mono rec' }, r.record) : null, ...more)];
    body.append(detailsTable('Newer mail protections', [
      row('MTA-STS', mtaSts, mtaSts.present ? el('div', {}, extLink(mtaSts.policyUrl, 'View policy file')) : null),
      row('TLS-RPT', tlsRpt),
      row('BIMI', bimi, bimi.logo ? el('div', {}, extLink(bimi.logo, 'View logo')) : null),
      row('DKIM (best effort)', dkim, dkimRec),
    ], el('div', { class: 'card-foot' }, el('span', { class: 'caption' }, `DKIM tries ${DKIM_SELECTORS.length} common selectors: ${DKIM_SELECTORS.join(', ')}. Missing MTA-STS, TLS-RPT or BIMI never lowers the grade.`))));

    const recs = (t) => by[t].answers.map((a) => a.data);
    const fact = (r, extraText) => `${r.word}${r.record ? `: ${r.record}` : ''}${extraText || ''}`;
    return {
      facts: [
        ['Email security grade', gr.g], ['Mail domain', mailDomain], ['SPF', `${spf.word}${spf.record ? `: ${spf.record}` : ''}`],
        ['DMARC', `${dmarc.word}${dmarc.record ? `: ${dmarc.record}` : ''}`],
        ['Mail servers (MX)', nullMx ? 'Null MX (receives no mail)' : mx.map((m) => `${m.pr} ${m.ex}`)],
        ['MTA-STS', fact(mtaSts)], ['TLS-RPT', fact(tlsRpt)], ['BIMI', fact(bimi)],
        ['DKIM (common selectors)', dkim.found.length ? dkim.found.map((f) => `${f.selector}${f.revoked ? ' (revoked)' : ` (${f.keyType})`}`) : `${dkim.word} (best effort, ${DKIM_SELECTORS.length} selectors tried)`],
        ['A', recs('A')], ['AAAA', recs('AAAA')], ['NS', recs('NS')], ['DNSSEC validated', by.A.dnssec ? 'Yes' : 'No'],
      ],
    };
  },
};
