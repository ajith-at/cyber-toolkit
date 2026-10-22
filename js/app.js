import { MODULES, modulesFor } from './registry.js';
import { detect, TYPE_LABEL } from './detect.js';
import { icon } from './icons.js';
import { el, pill, callout, mono, worst, loading, iconEl, errorCallout } from './ui.js';

const SAMPLES = ['8.8.8.8', '1.1.1.1', 'example.com', 'google.com', 'security@google.com',
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'];

const $ = (s) => document.querySelector(s);
const state = { raw: '', q: null, tool: 'all' };
const sectionCache = new Map(); // `${query}|${moduleId}` -> { section, status }
const panelCache = new Map(); // standalone tool id -> section (keeps typed input while switching tools)

// ---------- static icons ----------
document.querySelectorAll('[data-icon]').forEach((n) => { n.innerHTML = icon(n.dataset.icon, n.classList.contains('search-go') ? 20 : 18); });

// ---------- theme ----------
function applyTheme(t, persist) {
  document.documentElement.setAttribute('data-theme', t);
  if (persist) try { localStorage.setItem('ctk-theme', t); } catch { /* storage blocked */ }
  document.querySelectorAll('[data-theme-toggle]').forEach((b) => {
    b.setAttribute('aria-checked', String(t === 'dark'));
    b.querySelector('.switch-icon').innerHTML = icon(t === 'dark' ? 'moon' : 'sun', 18);
  });
}
document.querySelectorAll('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
  applyTheme(document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark', true);
}));
applyTheme(document.documentElement.getAttribute('data-theme') || 'light', false);

// ---------- navigation ----------
const views = [{ id: 'all', name: 'All tools', icon: 'layout-grid' }, ...MODULES];

function buildNav() {
  const nav = $('#nav');
  const chips = $('#chips');
  for (const v of views) {
    nav.append(el('li', {}, el('a', { href: '#', class: 'nav-item', 'data-tool': v.id, onclick: (e) => { e.preventDefault(); go(state.raw, v.id); } },
      iconEl(v.icon, 18), el('span', {}, v.name))));
    chips.append(el('button', { type: 'button', class: 'chip', role: 'tab', 'data-tool': v.id, onclick: () => go(state.raw, v.id) }, iconEl(v.icon, 16), v.name));
  }
  const samples = $('#samples');
  for (const s of SAMPLES) samples.append(el('button', { type: 'button', class: 'chip chip-sample', title: s, onclick: () => go(s, state.tool) }, s.length > 20 ? `${s.slice(0, 10)}…${s.slice(-6)}` : s));
}

function markActive() {
  document.querySelectorAll('[data-tool]').forEach((n) => {
    const on = n.dataset.tool === state.tool;
    n.classList.toggle('active', on);
    if (n.classList.contains('chip')) n.setAttribute('aria-selected', String(on));
    else if (on) n.setAttribute('aria-current', 'page'); else n.removeAttribute('aria-current');
  });
  const v = views.find((x) => x.id === state.tool) || views[0];
  $('#view-title').textContent = v.name;
  $('#view-caption').textContent = v.id === 'all' ? '' : v.summary;
}

// ---------- routing via the URL hash: #q=<value>&tool=<id> ----------
function go(raw, tool) {
  const p = new URLSearchParams();
  if (raw) p.set('q', raw);
  if (tool && tool !== 'all') p.set('tool', tool);
  const h = p.toString();
  if (`#${h}` === location.hash || (!h && !location.hash)) route();
  else location.hash = h;
}

function route() {
  const p = new URLSearchParams(location.hash.slice(1));
  state.raw = p.get('q') || '';
  state.tool = views.some((v) => v.id === p.get('tool')) ? p.get('tool') : 'all';
  $('#q').value = state.raw;
  markActive();
  render();
}

// ---------- rendering ----------
function render() {
  const out = $('#results');
  out.replaceChildren();
  out.dataset.q = state.raw;
  const standalone = MODULES.find((m) => m.id === state.tool && m.panel);
  $('.hero').hidden = !!standalone;
  if (standalone) { out.append(panelSection(standalone)); return; }
  if (!state.raw) { out.append(home()); return; }

  const q = detect(state.raw);
  state.q = q;
  if (q.type === 'invalid') {
    out.append(callout('caution', 'Not something we can check', q.reason));
    out.append(home());
    return;
  }

  const mods = modulesFor(q);
  const shown = state.tool === 'all' ? mods : mods.filter((m) => m.id === state.tool);
  const overview = summaryCard(q, mods, shown);
  out.append(overview.node);

  if (state.tool !== 'all' && !shown.length) {
    const m = MODULES.find((x) => x.id === state.tool);
    out.append(callout('unknown', `${m.name} does not apply to a ${TYPE_LABEL[q.type].toLowerCase()}`, `It works with: ${m.accepts.map((a) => ({ ip: 'IP addresses', domain: 'domains (also from links and emails)', url: 'links', hash: 'file hashes' })[a]).join(', ')}.`,
      el('div', { class: 'link-row' }, el('button', { type: 'button', class: 'btn btn-secondary', onclick: () => go(state.raw, 'all') }, 'Show all results'))));
  }

  for (const m of shown) out.append(moduleSection(q, m, overview.update));
  overview.update();
}

// The status covers the tools on screen: every applicable tool, or only the selected one when a tool filter is set.
function summaryCard(q, mods, shown = mods) {
  const filtered = state.tool !== 'all';
  const statusSlot = el('span', {}, pill('unknown', 'Checking…'));
  const statusLabel = filtered ? (MODULES.find((m) => m.id === state.tool)?.name || 'Status') : 'Overall';
  const node = el('section', { class: 'card summary', 'aria-label': 'Input summary' },
    el('div', { class: 'summary-main' },
      el('div', { class: 'summary-id' },
        el('span', { class: 'type-badge' }, iconEl({ ip: 'server', domain: 'globe', url: 'link', email: 'at-sign', hash: 'fingerprint' }[q.type], 18), TYPE_LABEL[q.type]),
        el('p', { class: 'summary-value mono' }, q.display),
        q.hashType ? el('p', { class: 'caption' }, `${q.hashType} hash`) : null,
        q.type === 'url' || q.type === 'email' ? el('p', { class: 'caption' }, 'Checking host ', mono(q.ip || q.domain)) : null,
        q.refanged ? el('p', { class: 'caption' }, 'Defanged input was restored (hxxp, [.] and similar).') : null),
      el('div', { class: 'summary-status' }, el('span', { class: 'label' }, statusLabel), statusSlot)),
    el('div', { class: 'summary-tools' }, mods.map((m) => el('a', { href: `#${new URLSearchParams({ q: state.raw, ...(m.id === 'all' ? {} : { tool: m.id }) })}`, class: 'chip chip-soft' }, iconEl(m.icon, 14), m.name))));
  const update = () => {
    if (!shown.length) { statusSlot.replaceChildren(pill('unknown', 'Not checked')); return; }
    const done = shown.map((m) => sectionCache.get(`${q.value}|${m.id}`)).filter((c) => c && c.status);
    if (done.length < shown.length) { statusSlot.replaceChildren(pill('unknown', filtered ? 'Checking…' : `Checking ${done.length}/${shown.length}`)); return; }
    const scored = done.map((c) => c.status).filter((s) => s !== 'unknown');
    const w = scored.length ? worst(...scored) : 'unknown';
    statusSlot.replaceChildren(pill(w, w === 'low' ? 'No red flags' : undefined));
  };
  return { node, update };
}

function moduleSection(q, m, onDone) {
  const key = `${q.value}|${m.id}`;
  const cached = sectionCache.get(key);
  if (cached) { if (cached.status) queueMicrotask(onDone); else cached.listeners.push(onDone); return cached.section; }

  const statusSlot = el('span', { class: 'section-status' }, pill('unknown', 'Checking…'));
  const body = el('div', { class: 'section-body' }, loading());
  const section = el('section', { class: 'module', id: `mod-${m.id}`, 'aria-labelledby': `h-${m.id}`, 'aria-busy': 'true' },
    el('header', { class: 'module-head' },
      el('span', { class: 'module-icon' }, iconEl(m.icon, 20)),
      el('div', { class: 'module-titles' }, el('h2', { id: `h-${m.id}` }, m.name), el('p', { class: 'caption' }, m.source)),
      statusSlot),
    body);
  const entry = { section, status: null, listeners: [onDone] };
  sectionCache.set(key, entry);

  let status = 'unknown';
  let text;
  const setStatus = (s, t) => { status = s; text = t; };
  const target = el('div', { class: 'section-stack' });
  Promise.resolve()
    .then(() => m.render(q, { body: target, setStatus }))
    .catch((err) => {
      console.warn(`[${m.id}]`, err);
      status = 'unknown'; text = 'Error';
      target.append(errorCallout({ message: 'This tool hit an unexpected problem. The other tools are unaffected.' }));
    })
    .finally(() => {
      body.replaceChildren(target);
      statusSlot.replaceChildren(pill(status, text));
      section.setAttribute('aria-busy', 'false');
      entry.status = status;
      entry.listeners.splice(0).forEach((f) => f());
    });
  return section;
}

function panelSection(m) {
  if (panelCache.has(m.id)) return panelCache.get(m.id);
  const body = el('div', { class: 'section-stack' });
  const section = el('section', { class: 'module', id: `mod-${m.id}`, 'aria-labelledby': `h-${m.id}` },
    el('header', { class: 'module-head' },
      el('span', { class: 'module-icon' }, iconEl(m.icon, 20)),
      el('div', { class: 'module-titles' }, el('h2', { id: `h-${m.id}` }, m.name), el('p', { class: 'caption' }, m.source))),
    body);
  m.panel(body, { go: (v, tool) => { $('#q').value = v; go(v, tool); } });
  panelCache.set(m.id, section);
  return section;
}

function home() {
  return el('section', { class: 'home', 'aria-label': 'Available tools' },
    el('div', { class: 'tool-grid' }, MODULES.map((m) => el('article', { class: 'card tool-card' },
      el('div', { class: 'tool-top' }, el('span', { class: 'module-icon' }, iconEl(m.icon, 20)), el('h3', {}, m.name)),
      el('p', { class: 'caption' }, m.summary),
      el('div', { class: 'tool-foot' },
        el('div', { class: 'pill-row' }, (m.inputs || m.accepts.map((a) => ({ ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash' })[a])).map((a) => el('span', { class: 'chip-static' }, a))),
        m.panel ? el('a', { href: `#tool=${m.id}`, class: 'ext' }, 'Open', iconEl('arrow-right', 14)) : null)))));
}

// ---------- boot ----------
buildNav();
$('#search').addEventListener('submit', (e) => {
  e.preventDefault();
  const v = $('#q').value.trim();
  if (!v) { $('#q').focus(); return; }
  // Pressing Check again re-runs the lookups for that input.
  const q = detect(v);
  if (q.value) for (const k of [...sectionCache.keys()]) if (k.startsWith(`${q.value}|`)) sectionCache.delete(k);
  go(v, state.tool);
});
window.addEventListener('hashchange', route);
route();
