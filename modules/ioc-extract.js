// Extract indicators: pull IPs, domains, URLs, email addresses and file hashes out of pasted text, with defang / refang.
// Everything runs in the browser. Pasted text is only ever rendered with textContent.
import { el, iconEl, copyButton, callout, listTable, mono, pill, announce } from '../js/ui.js';
import { ipScope } from '../js/detect.js';
import { extractIocs, formatIocs, defangIndicator, IOC_TYPES, MAX_INPUT } from '../js/ioc.js';

const MAX_ROWS = 500; // per group on screen; copying always includes everything

const SAMPLE = `Subject: [SOC] Phishing campaign targeting payroll staff

Users received a lure from payroll-update[@]account-verify[.]example linking to
hxxps://login.account-verify[.]example/sso/start?session=8841 and a fallback at
hxxp://198.51.100[.]23/invoice.php (see also https://www.example.com/blog/phishing-guide).

The dropper (invoice_2026.zip, 1.2 MB) calls back to cdn-update[.]example[.]net on 203.0.113.77:443
and over IPv6 to 2001:db8:4f2a::17. Second stage beacons every 60s to 203.0.113.77 again.

Hashes:
  MD5     44d88612fea8a8f36de82e1278abb02f
  SHA-1   3395856ce81f2b7382dee72602f798b642f14140
  SHA-256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

Seen on hosts running agent v2.4.1.9 (build 10.0.19041.1). Notes in README.md and report.pdf.
Report to soc@example.org by 10:30:00 AEDT.`;

const typeKey = (i) => (i.type === 'ip' ? `ipv${i.version}` : i.type);

function note(i) {
  const bits = [];
  if (i.defanged) bits.push(el('span', { class: 'chip-static' }, 'Defanged in text'));
  if (i.type === 'hash') bits.push(el('span', { class: 'chip-static' }, i.hashType));
  if (i.type === 'ip') {
    bits.push(el('span', { class: 'chip-static' }, `IPv${i.version}`));
    const scope = ipScope(i.value);
    if (scope) bits.push(pill('unknown', scope));
  }
  if (i.fromUrl) bits.push(el('span', { class: 'chip-static' }, 'From a URL'));
  if (i.fromEmail) bits.push(el('span', { class: 'chip-static' }, 'From an email'));
  if (i.count > 1) bits.push(el('span', { class: 'chip-static' }, `×${i.count}`));
  return bits.length ? el('div', { class: 'pill-row ioc-notes' }, bits) : null;
}

function groupCard(t, items, go) {
  const rows = items.slice(0, MAX_ROWS).map((i) => ({
    value: el('div', { class: 'ioc-cell' }, mono(i.value), note(i)),
    actions: el('div', { class: 'row-actions' },
      el('button', { type: 'button', class: 'btn btn-secondary btn-sm', 'data-check': i.value, 'aria-label': `Check ${i.value}`, onclick: () => go(i.value) }, iconEl('search', 16), 'Check'),
      i.type === 'hash' ? copyButton(() => i.value, `Copy ${i.value}`) : copyButton(() => defangIndicator(i.value, typeKey(i)), `Copy ${i.value} defanged`, 'Copy defanged')),
  }));
  const foot = el('div', { class: 'card-foot' },
    el('p', { class: 'caption' }, items.length > MAX_ROWS ? `Showing the first ${MAX_ROWS} of ${items.length.toLocaleString('en-AU')}. Copy includes them all.` : ''),
    el('div', { class: 'link-row' },
      copyButton(() => formatIocs(items, 'refanged'), `Copy all ${t.label}`, 'Copy all'),
      t.id === 'hash' ? null : copyButton(() => formatIocs(items, 'defanged'), `Copy all ${t.label} defanged`, 'Copy all defanged')));
  const card = listTable(`${t.label} (${items.length})`, [{ key: 'value', label: 'Value' }, { key: 'actions', label: 'Actions', num: true }], rows, foot);
  card.dataset.group = t.id;
  card.querySelector('table').classList.add('ind-table', 'ioc-table');
  return card;
}

export function renderIocs(res, go) {
  if (!res.total) {
    return [callout('unknown', 'No indicators found', 'Nothing in the text looks like an IP address, domain, URL, email address or MD5 / SHA-1 / SHA-256 hash. File names (report.pdf) and version numbers (v2.0) are ignored on purpose.')];
  }
  const fanged = res.items.filter((i) => i.defanged).length;
  const summary = el('article', { class: 'card ioc-summary', 'aria-live': 'polite' },
    el('div', { class: 'fact-top' },
      el('h3', { class: 'card-title' }, `Found ${res.total} indicator${res.total === 1 ? '' : 's'}`),
      fanged ? pill('unknown', `${fanged} defanged in text`) : null),
    el('div', { class: 'pill-row' }, IOC_TYPES.filter((t) => res.counts[t.id]).map((t) => el('a', { href: `#ioc-${t.id}`, class: 'chip chip-soft', 'data-count': t.id, onclick: (e) => { e.preventDefault(); document.querySelector(`[data-group="${t.id}"]`)?.scrollIntoView({ block: 'start' }); } }, `${t.label} `, el('strong', {}, String(res.counts[t.id]))))),
    el('p', { class: 'caption' }, 'Duplicates are removed. Domains include the hosts of URLs and email addresses. Copy gives one indicator per line.'),
    res.truncated ? el('p', { class: 'caption' }, `Only the first ${MAX_INPUT.toLocaleString('en-AU')} characters were read.`) : null,
    el('div', { class: 'link-row' },
      copyButton(() => formatIocs(res.items, 'written'), 'Copy all as plain text, as written in the paste', 'Copy plain'),
      copyButton(() => formatIocs(res.items, 'defanged'), 'Copy all defanged, safe to share', 'Copy defanged'),
      copyButton(() => formatIocs(res.items, 'refanged'), 'Copy all refanged, live form', 'Copy refanged')));
  return [summary, ...IOC_TYPES.filter((t) => res.counts[t.id]).map((t) => groupCard(t, res.items.filter((i) => i.type === t.id), go))];
}

export default {
  id: 'ioc-extract',
  name: 'Extract indicators',
  icon: 'scan-text',
  accepts: [],
  inputs: ['Text'],
  summary: 'Paste an alert, report or chat message to pull out every IP, domain, URL, email and file hash, including defanged ones. Copy them plain, defanged or refanged.',
  source: 'Runs in your browser. Nothing is sent anywhere.',

  panel(body, { go }) {
    const input = el('textarea', { id: 'ioc-input', class: 'textbox mono', rows: '10', spellcheck: 'false', autocapitalize: 'off', placeholder: 'Paste an alert email, threat report or chat message. Defanged indicators such as hxxps://evil[.]example are fine.' });
    const out = el('div', { class: 'section-stack ioc-out' });
    const run = () => {
      out.replaceChildren(...renderIocs(extractIocs(input.value), go));
      announce(out.querySelector('.card-title, .callout-title')?.textContent || '');
    };
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); run(); } });
    input.addEventListener('paste', () => setTimeout(run, 0));
    body.append(
      el('article', { class: 'card enc-card' },
        el('label', { class: 'card-title', for: 'ioc-input' }, 'Text'),
        input,
        el('div', { class: 'link-row' },
          el('button', { type: 'button', class: 'btn btn-primary', id: 'ioc-go', onclick: run }, iconEl('scan-text', 18), 'Extract'),
          el('button', { type: 'button', class: 'btn btn-secondary', id: 'ioc-sample', onclick: () => { input.value = SAMPLE; run(); } }, 'Load example'),
          el('button', { type: 'button', class: 'btn btn-secondary', id: 'ioc-clear', onclick: () => { input.value = ''; out.replaceChildren(); input.focus(); } }, 'Clear'))),
      out,
    );
  },
};
