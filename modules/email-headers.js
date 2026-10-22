// Email header analyser. Parses pasted raw headers in the browser; nothing is sent anywhere.
import { el, iconEl, pill, callout, mono, listTable, detailsTable } from '../js/ui.js';
import { isIPv4, isIPv6, ipScope, isDomain } from '../js/detect.js';
import { guessRegistrable } from '../js/net.js';

// ---------- parsing ----------
/** Raw header block -> [{ name, value }] in original order (top = newest). Folded lines are joined. */
export function parseHeaders(raw) {
  const lines = String(raw || '').replace(/\r\n?/g, '\n').replace(/^\s*\n/, '').split('\n');
  const out = [];
  for (const line of lines) {
    if (line.trim() === '') { if (out.length) break; continue; } // blank line ends the header block
    if (/^[ \t]/.test(line) && out.length) { out[out.length - 1].value += ` ${line.trim()}`; continue; }
    const m = /^([!-9;-~]+):\s?(.*)$/.exec(line);
    if (m) out.push({ name: m[1], value: m[2].trim() });
    else if (out.length) out[out.length - 1].value += ` ${line.trim()}`;
  }
  return out;
}

const all = (hs, name) => hs.filter((h) => h.name.toLowerCase() === name.toLowerCase()).map((h) => h.value);
const first = (hs, name) => all(hs, name)[0] ?? null;
const stripComments = (s) => s.replace(/\((?:[^()\\]|\\.)*\)/g, ' ');

function cleanIp(s) {
  const v = s.replace(/^\[|\]$/g, '').replace(/^IPv6:/i, '');
  return isIPv4(v) || isIPv6(v) ? v.toLowerCase() : null;
}

export function parseDate(s) {
  if (!s) return null;
  const t = Date.parse(s.replace(/\([^)]*\)/g, '').replace(/\s+/g, ' ').trim());
  return Number.isNaN(t) ? null : new Date(t);
}

/** One Received header -> { from, fromIp, by, with, date, ips }. */
export function parseReceived(v) {
  const semi = v.lastIndexOf(';');
  const date = semi >= 0 ? parseDate(v.slice(semi + 1)) : null;
  const body = semi >= 0 ? v.slice(0, semi) : v;
  const part = (kw) => {
    const m = new RegExp(`(?:^|\\s)${kw}\\s+(.+?)(?=\\s+(?:from|by|via|with|id|for)\\s|$)`, 'i').exec(body);
    return m ? m[1].trim() : null;
  };
  const fromRaw = part('from');
  const ips = [...body.matchAll(/\[(?:IPv6:)?([0-9a-f:.]+)\]|\(([0-9a-f:.]{7,})\)|\b(\d{1,3}(?:\.\d{1,3}){3})\b/gi)]
    .map((m) => cleanIp(m[1] || m[2] || m[3])).filter(Boolean);
  const fromIps = fromRaw ? [...fromRaw.matchAll(/\[(?:IPv6:)?([0-9a-f:.]+)\]|\(([0-9a-f:.]{7,})\)|\b(\d{1,3}(?:\.\d{1,3}){3})\b/gi)].map((m) => cleanIp(m[1] || m[2] || m[3])).filter(Boolean) : [];
  const host = (s) => (s ? s.split(/\s+/)[0].replace(/[()[\]]/g, '').replace(/\.$/, '') : null);
  const withRaw = part('with');
  return {
    from: host(fromRaw),
    fromIp: fromIps.find((ip) => !ipScope(ip)) || fromIps[fromIps.length - 1] || null,
    by: host(part('by')),
    with: withRaw ? withRaw.split(/\s+/)[0] : null,
    date,
    ips: [...new Set(ips)],
    raw: v,
  };
}

/** Hops in delivery order (oldest first) with the delay from the previous hop in seconds. */
export function receivedChain(hs) {
  const hops = all(hs, 'Received').map(parseReceived).reverse();
  let prev = null;
  for (const h of hops) {
    h.delay = h.date && prev ? Math.round((h.date - prev) / 1000) : null;
    if (h.date) prev = h.date;
  }
  return hops;
}

const RESULT_KEYS = ['spf', 'dkim', 'dmarc', 'arc', 'compauth'];

/** Authentication-Results value -> { server, spf, dkim, dmarc, ... , props } (first result per method). */
export function parseAuthResults(v) {
  const text = stripComments(v);
  const serverMatch = /^\s*(?:i=\d+;\s*)?([^\s;=]+)(?:\s+\d+)?\s*;/.exec(text);
  const out = { server: serverMatch && !/=/.test(serverMatch[1]) ? serverMatch[1] : null, props: {} };
  for (const m of text.matchAll(/\b(spf|dkim|dmarc|arc|compauth)\s*=\s*([a-z]+)([^;]*)/gi)) {
    const k = m[1].toLowerCase();
    if (out[k]) continue;
    out[k] = m[2].toLowerCase();
    for (const p of m[3].matchAll(/\b((?:header|smtp)\.[a-z]+|action|reason)=("?)([^\s";]+)\2/gi)) out.props[`${k}.${p[1].toLowerCase()}`] = p[3];
  }
  return out;
}

/** Display name and address from a From/Reply-To/Sender/Return-Path value. */
export function parseAddress(v) {
  if (!v) return null;
  const angle = /<([^<>]*)>/.exec(v);
  const addr = (angle ? angle[1] : (/[^\s<>"(),;]+@[^\s<>"(),;]+/.exec(v) || [''])[0]).trim().toLowerCase();
  const name = angle ? v.slice(0, angle.index).trim().replace(/^"|"$/g, '').trim() : '';
  const domain = addr.includes('@') ? addr.split('@').pop().replace(/\.$/, '') : null;
  return { raw: v, name, address: addr || null, domain: domain && isDomain(domain) ? domain : null };
}

const RANK = { pass: 'low', none: 'unknown', neutral: 'caution', softfail: 'caution', temperror: 'caution', policy: 'caution', fail: 'high', permerror: 'high', hardfail: 'high' };
export const resultStatus = (r) => (r ? RANK[r] || 'unknown' : 'unknown');

/** Full analysis of a header block. */
export function analyse(raw) {
  const hs = parseHeaders(raw);
  if (!hs.length) return null;
  const hops = receivedChain(hs);

  // Use the topmost Authentication-Results (added by the receiving server); ARC results are from earlier hops.
  const ar = all(hs, 'Authentication-Results').map(parseAuthResults);
  const arc = all(hs, 'ARC-Authentication-Results').map(parseAuthResults);
  const auth = { ...(ar[0] || { props: {} }) };
  const spfHeader = first(hs, 'Received-SPF');
  if (!auth.spf && spfHeader) auth.spf = (/^\s*([a-z]+)/i.exec(spfHeader) || [])[1]?.toLowerCase() || null;
  if (!auth.dkim && !ar.length && first(hs, 'DKIM-Signature')) auth.dkimSigned = true;

  const addrs = Object.fromEntries(['From', 'Reply-To', 'Return-Path', 'Sender'].map((n) => [n, parseAddress(first(hs, n))]));
  const fromDom = addrs.From?.domain;
  const org = (d) => (d ? guessRegistrable(d) : null);
  const mismatches = [];
  for (const n of ['Reply-To', 'Return-Path', 'Sender']) {
    const a = addrs[n];
    if (a?.domain && fromDom && org(a.domain) !== org(fromDom)) mismatches.push({ header: n, domain: a.domain, fromDomain: fromDom });
  }
  const nameEmail = addrs.From?.name && /[^\s<>"()]+@[^\s<>"()]+/.exec(addrs.From.name);
  const displaySpoof = nameEmail && addrs.From.address && nameEmail[0].toLowerCase().replace(/[()]/g, '') !== addrs.From.address ? nameEmail[0].replace(/[()]/g, '') : null;

  // Originating IP: X-Originating-IP / X-Sender-IP, else the first public IP in the oldest hop that has one.
  const xo = ['X-Originating-IP', 'X-Sender-IP', 'X-Source-IP'].map((n) => first(hs, n)).filter(Boolean).map((v) => cleanIp(v.trim())).find(Boolean) || null;
  const firstPublicHop = hops.find((h) => h.fromIp && !ipScope(h.fromIp));
  const origin = xo || firstPublicHop?.fromIp || null;

  const ips = [...new Set([origin, ...hops.map((h) => h.fromIp)].filter((ip) => ip && !ipScope(ip)))];
  const domains = [...new Set([
    ...Object.values(addrs).map((a) => a?.domain),
    auth.props['dkim.header.d'], auth.props['dkim.header.i']?.replace(/^.*@/, ''),
    (auth.props['spf.smtp.mailfrom'] || '').replace(/^.*@/, ''),
  ].filter((d) => d && isDomain(d)).map((d) => d.toLowerCase()))];

  const dates = hops.map((h) => h.date).filter(Boolean);
  const transit = dates.length > 1 ? Math.round((dates[dates.length - 1] - dates[0]) / 1000) : null;

  return {
    headers: hs, hops, auth, arc, addrs, mismatches, displaySpoof, origin, ips, domains, transit,
    subject: first(hs, 'Subject'), date: first(hs, 'Date'), messageId: first(hs, 'Message-ID'), to: first(hs, 'To'),
  };
}

/** Overall verdict: high when DMARC/SPF/DKIM fail, caution on mismatches or soft results. */
export function verdict(a) {
  const s = ['spf', 'dkim', 'dmarc'].map((k) => resultStatus(a.auth[k]));
  if (a.auth.dmarc === 'fail' || s.includes('high')) return 'high';
  if (a.mismatches.length || a.displaySpoof || s.includes('caution')) return 'caution';
  if (a.auth.dmarc === 'pass' || (a.auth.spf === 'pass' && a.auth.dkim === 'pass')) return 'low';
  return 'unknown';
}

// ---------- formatting ----------
export function fmtDelay(sec) {
  if (sec == null) return null;
  const sign = sec < 0 ? '−' : '+';
  let s = Math.abs(sec);
  if (s < 60) return `${sign}${s} s`;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  return `${sign}${h ? `${h} h ` : ''}${m} min${!h && s ? ` ${s} s` : ''}`;
}
const fmtUtc = (d) => (d ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : null);

const SAMPLE = `Received: by 2002:a05:6214:1c8a::1 with SMTP id gc10csp22; Wed, 21 Oct 2026 09:41:52 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=none;
       spf=softfail (domain of billing@paypa1-secure.top does not designate 45.33.32.156 as permitted sender) smtp.mailfrom=billing@paypa1-secure.top;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=paypal.com
Return-Path: <billing@paypa1-secure.top>
Received: from mail.paypa1-secure.top (li982-156.members.linode.com. [45.33.32.156])
        by mx.google.com with ESMTP id a1b2c3.11
        for <sam@example.com>; Wed, 21 Oct 2026 09:41:51 -0700 (PDT)
Received: from [192.168.10.23] (unknown [102.89.32.11])
        by mail.paypa1-secure.top (Postfix) with ESMTPSA id 7F2C1A0042
        for <sam@example.com>; Wed, 21 Oct 2026 16:38:40 +0000 (UTC)
From: "PayPal Service (service@paypal.com)" <service@paypal.com>
Reply-To: account-review@protonmail.com
To: sam@example.com
Subject: Your account has been limited
Date: Wed, 21 Oct 2026 16:38:39 +0000
Message-ID: <20261021163839.7F2C1A0042@mail.paypa1-secure.top>`;

// ---------- UI ----------
function renderResult(a, go) {
  const v = verdict(a);
  const nodes = [];
  const titles = { high: 'Authentication failed', caution: 'Check the sender carefully', low: 'Authentication passed', unknown: 'No authentication results' };
  const reasons = [];
  if (a.auth.dmarc === 'fail') reasons.push('DMARC failed: the From domain did not authorise this message.');
  if (a.auth.spf && resultStatus(a.auth.spf) !== 'low' && a.auth.spf !== 'none') reasons.push(`SPF ${a.auth.spf}.`);
  if (a.auth.dkim && resultStatus(a.auth.dkim) === 'high') reasons.push('DKIM signature failed.');
  for (const m of a.mismatches) reasons.push(`${m.header} domain ${m.domain} differs from From domain ${m.fromDomain}.`);
  if (a.displaySpoof) reasons.push(`The display name shows ${a.displaySpoof}, but the real address is ${a.addrs.From.address}.`);
  if (v === 'low' && !reasons.length) reasons.push('No red flags in the headers. Headers alone cannot prove a message is safe.');
  if (v === 'unknown' && !reasons.length) reasons.push('No Authentication-Results header was found. Copy the full headers from your mail client.');
  nodes.push(callout(v, titles[v], null, el('ul', { class: 'reasons' }, reasons.map((r) => el('li', { class: 'caption' }, r)))));

  // authentication pills
  const authCard = (k, label) => {
    const r = a.auth[k];
    const st = resultStatus(r);
    const detail = { spf: a.auth.props['spf.smtp.mailfrom'], dkim: a.auth.props['dkim.header.d'] || a.auth.props['dkim.header.i'], dmarc: a.auth.props['dmarc.header.from'] }[k];
    return el('article', { class: 'card fact', 'data-auth': k },
      el('div', { class: 'fact-top' }, el('span', { class: 'label' }, label), pill(st, r ? r.toUpperCase().replace(/^(.)(.*)$/, (x, f, rest) => f + rest.toLowerCase()) : 'None')),
      el('p', { class: 'caption' }, detail ? mono(detail) : (k === 'dkim' && a.auth.dkimSigned ? 'Signed, but no verification result in the headers.' : 'No result in the headers.')));
  };
  nodes.push(el('div', { class: 'fact-grid' }, authCard('spf', 'SPF'), authCard('dkim', 'DKIM'), authCard('dmarc', 'DMARC')));

  // addresses
  const addrRows = ['From', 'Reply-To', 'Return-Path', 'Sender'].filter((n) => a.addrs[n]).map((n) => {
    const ad = a.addrs[n];
    const mm = a.mismatches.find((m) => m.header === n);
    return [n, el('span', { class: 'addr-cell' }, ad.name ? `${ad.name} ` : null, ad.address ? mono(`<${ad.address}>`) : mono(ad.raw), mm ? pill('caution', 'Different domain') : null, n === 'From' && a.displaySpoof ? pill('caution', 'Misleading display name') : null)];
  });
  nodes.push(detailsTable('Sender', [...addrRows, ['To', a.to], ['Subject', a.subject], ['Date', a.date], ['Message-ID', a.messageId ? mono(a.messageId) : null]]));

  // hops
  const rows = a.hops.map((h, i) => ({
    n: String(i + 1),
    from: el('span', {}, h.from ? mono(h.from) : el('span', { class: 'muted' }, '—'), h.fromIp ? el('span', { class: 'caption hop-ip' }, ' ', mono(h.fromIp), ipScope(h.fromIp) ? ` (${ipScope(h.fromIp)})` : '') : null),
    by: h.by ? mono(h.by) : null,
    with: h.with,
    time: fmtUtc(h.date),
    delay: h.delay == null ? null : el('span', { class: h.delay < 0 || h.delay > 3600 ? 'delay-warn' : '' }, fmtDelay(h.delay), h.delay < 0 ? ' (clock skew)' : ''),
  }));
  nodes.push(listTable(`Delivery path (${a.hops.length} hop${a.hops.length === 1 ? '' : 's'}, oldest first)`, [
    { key: 'n', label: '#' }, { key: 'from', label: 'From' }, { key: 'by', label: 'By' }, { key: 'with', label: 'With' }, { key: 'time', label: 'Time (UTC)' }, { key: 'delay', label: 'Delay', num: true },
  ], rows, a.transit != null ? el('p', { class: 'caption hop-total' }, `Total time in transit: ${fmtDelay(a.transit).replace(/^\+/, '')}`) : null));

  // indicators
  const btn = (label, icon, v2, tool) => el('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => go(v2, tool) }, iconEl(icon, 16), label);
  const indRows = [
    ...a.ips.map((ip) => ({ kind: ip === a.origin ? 'Originating IP' : 'IP', value: mono(ip), actions: el('div', { class: 'row-actions' }, btn('IP lookup', 'server', ip, 'ip-lookup'), btn('Reputation', 'radar', ip, 'reputation')) })),
    ...a.domains.map((d) => ({ kind: 'Domain', value: mono(d), actions: el('div', { class: 'row-actions' }, btn('Domain lookup', 'globe', d, 'domain-lookup'), btn('DNS & email', 'mail-check', d, 'dns-email'), btn('Reputation', 'radar', d, 'reputation')) })),
  ];
  nodes.push(listTable('IPs and domains', [{ key: 'kind', label: 'Type' }, { key: 'value', label: 'Value' }, { key: 'actions', label: 'Check', num: true }], indRows));

  if (a.arc.length) {
    nodes.push(listTable('ARC results from earlier hops', [{ key: 'server', label: 'Server' }, { key: 'spf', label: 'SPF' }, { key: 'dkim', label: 'DKIM' }, { key: 'dmarc', label: 'DMARC' }],
      a.arc.map((r) => ({ server: r.server ? mono(r.server) : null, spf: r.spf ? pill(resultStatus(r.spf), r.spf) : null, dkim: r.dkim ? pill(resultStatus(r.dkim), r.dkim) : null, dmarc: r.dmarc ? pill(resultStatus(r.dmarc), r.dmarc) : null }))));
  }
  return { status: v, nodes };
}

export default {
  id: 'email-headers',
  name: 'Email headers',
  icon: 'mail-search',
  accepts: [],
  inputs: ['Raw headers'],
  summary: 'Paste raw email headers: delivery path with delays, SPF, DKIM and DMARC results, sender mismatches, and the IPs and domains involved.',
  source: 'Parsed in your browser. Header content never leaves it.',

  panel(body, { go }) {
    const input = el('textarea', { id: 'eh-input', class: 'textbox mono', rows: '10', spellcheck: 'false', autocapitalize: 'off', placeholder: 'Received: from …\nAuthentication-Results: …\nFrom: …' });
    const out = el('div', { class: 'section-stack eh-out', 'aria-live': 'polite' });
    const run = () => {
      const a = analyse(input.value);
      if (!a) { out.replaceChildren(callout('unknown', 'No headers found', 'Paste the full header block, starting with lines like Received: or Delivered-To:.')); return; }
      if (!a.hops.length && !a.addrs.From && !a.auth.spf) { out.replaceChildren(callout('unknown', 'Not recognised as email headers', 'Expected header lines such as Received:, Authentication-Results: and From:.')); return; }
      out.replaceChildren(...renderResult(a, go).nodes);
    };
    body.append(
      el('article', { class: 'card enc-card' },
        el('label', { class: 'card-title', for: 'eh-input' }, 'Raw headers'),
        input,
        el('div', { class: 'link-row' },
          el('button', { type: 'button', class: 'btn btn-primary', id: 'eh-go', onclick: run }, iconEl('scan-search', 18), 'Analyse'),
          el('button', { type: 'button', class: 'btn btn-secondary', id: 'eh-sample', onclick: () => { input.value = SAMPLE; run(); } }, 'Load example'),
          el('button', { type: 'button', class: 'btn btn-secondary', onclick: () => { input.value = ''; out.replaceChildren(); input.focus(); } }, 'Clear'))),
      out,
    );
  },
};
