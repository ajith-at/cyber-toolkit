// Tiny, XSS-safe DOM helpers shared by modules. Text always goes in via textContent.
import { icon } from './icons.js';

export function el(tag, props = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'html') n.innerHTML = v; // only ever used with our own static icon markup
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : v);
  }
  append(n, children);
  return n;
}

function append(n, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export const iconEl = (name, size = 18, cls = '') => el('span', { class: 'icon-wrap', html: icon(name, size, cls) });

// ---------- status ----------
// Risk mapping of the template's status colours.
export const STATUS = {
  low: { cls: 'teal', word: 'Low risk' },
  unknown: { cls: 'slate', word: 'Unknown' },
  caution: { cls: 'amber', word: 'Caution' },
  high: { cls: 'rose', word: 'High risk' },
};
const ORDER = ['low', 'unknown', 'caution', 'high'];
export const worst = (...s) => s.filter(Boolean).reduce((a, b) => (ORDER.indexOf(b) > ORDER.indexOf(a) ? b : a), 'low');

export function pill(status = 'unknown', text) {
  const s = STATUS[status] || STATUS.unknown;
  return el('span', { class: `pill pill-${s.cls}`, 'data-status': status }, el('span', { class: 'dot', 'aria-hidden': 'true' }), text || s.word);
}

export function dot(status, text) {
  const s = STATUS[status] || STATUS.unknown;
  return el('span', { class: `dotline dot-${s.cls}` }, el('span', { class: 'dot', 'aria-hidden': 'true' }), text);
}

// ---------- cards ----------
export function factCard({ label, status, statusText, figure, unit, caption, mono = false, small = false }) {
  return el('article', { class: 'card fact' },
    el('div', { class: 'fact-top' }, el('span', { class: 'label' }, label), status ? pill(status, statusText) : null),
    el('div', { class: `figure${mono ? ' mono' : ''}${small ? ' figure-sm' : ''}` }, figure ?? '—', unit ? el('span', { class: 'unit' }, unit) : null),
    caption ? el('p', { class: 'caption' }, caption) : null,
  );
}

export const factGrid = (...cards) => el('div', { class: 'fact-grid' }, cards);

/** rows: [label, value, opts?] where value can be string, Node, array; opts.mono for raw values. */
export function detailsTable(title, rows, foot) {
  const body = rows.filter(Boolean).map(([k, v, o = {}]) => el('tr', {},
    el('th', { scope: 'row' }, k),
    el('td', { class: o.mono ? 'mono' : '' }, isEmpty(v) ? el('span', { class: 'muted' }, '—') : v)));
  return el('article', { class: 'card table-card' },
    title ? el('h3', { class: 'card-title' }, title) : null,
    el('div', { class: 'table-scroll' }, el('table', { class: 'kv' }, el('tbody', {}, body))),
    foot || null);
}

/** Simple column table: cols [{key,label,mono,num}], rows of objects. */
export function listTable(title, cols, rows, foot) {
  return el('article', { class: 'card table-card' },
    title ? el('h3', { class: 'card-title' }, title) : null,
    el('div', { class: 'table-scroll' }, el('table', { class: 'grid' },
      el('thead', {}, el('tr', {}, cols.map((c) => el('th', { scope: 'col', class: c.num ? 'num' : '' }, c.label)))),
      el('tbody', {}, rows.length ? rows.map((r) => el('tr', {}, cols.map((c) => el('td', { class: [c.mono && 'mono', c.num && 'num'].filter(Boolean).join(' ') }, isEmpty(r[c.key]) ? el('span', { class: 'muted' }, '—') : r[c.key]))))
        : el('tr', {}, el('td', { colspan: cols.length, class: 'muted' }, 'No records.'))))),
    foot || null);
}

const isEmpty = (v) => v == null || v === '' || (Array.isArray(v) && v.length === 0);

export function callout(status, title, text, ...extra) {
  const s = STATUS[status] || STATUS.unknown;
  return el('div', { class: `card callout callout-${s.cls}`, role: status === 'high' || status === 'caution' ? 'status' : null },
    el('div', {}, el('p', { class: 'callout-title' }, title), text ? el('p', { class: 'caption' }, text) : null, extra));
}

export function extLink(href, text, { button = false } = {}) {
  return el('a', { href, target: '_blank', rel: 'noopener noreferrer', class: button ? 'btn btn-secondary' : 'ext' },
    text, el('span', { class: 'icon-wrap', html: icon('external-link', 14) }), el('span', { class: 'sr-only' }, ' (opens in a new tab)'));
}

export function rawJson(label, obj) {
  return el('details', { class: 'raw' }, el('summary', {}, label), el('pre', { class: 'mono' }, JSON.stringify(obj, null, 2)));
}

export const mono = (t) => el('span', { class: 'mono' }, t);
export const list = (items, monoItems = false) => (items && items.length ? el('ul', { class: 'plain' }, items.map((i) => el('li', { class: monoItems ? 'mono' : '' }, i))) : null);

// ---------- formatting ----------
export const fmtDate = (d) => (d && !isNaN(d) ? d.toLocaleDateString('en-AU', { day: 'numeric', month: 'short', year: 'numeric' }) : null);
export const daysBetween = (a, b = new Date()) => Math.floor((b - a) / 86400000);
export const fmtNum = (n) => (n == null ? '—' : Number(n).toLocaleString('en-AU'));

export function loading(text = 'Looking up…') {
  return el('div', { class: 'loading', role: 'status' }, el('span', { class: 'spinner', html: icon('loader-circle', 18) }), text);
}

export function errorCallout(err, fallbackHref, fallbackText) {
  const msg = err?.message || 'Something went wrong.';
  return callout('unknown', 'Lookup unavailable', msg, fallbackHref ? el('p', { class: 'caption' }, extLink(fallbackHref, fallbackText || 'Open the lookup on the provider site')) : null);
}
