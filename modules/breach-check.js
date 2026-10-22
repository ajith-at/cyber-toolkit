// Password breach check with Have I Been Pwned's Pwned Passwords range API (k-anonymity).
// The password is hashed with SHA-1 in the browser; only the first 5 hex characters of the hash are sent.
// The password is never put in the URL, storage, history or the console.
import { el, iconEl, factCard, callout, fmtNum } from '../js/ui.js';

const API = 'https://api.pwnedpasswords.com/range/';

export async function sha1Hex(text) {
  const d = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/** Count for `suffix` in a range response ("SUFFIX:COUNT" lines). Padding lines have a count of 0. */
export function countIn(body, suffix) {
  for (const line of body.split('\n')) {
    const [s, n] = line.trim().split(':');
    if (s === suffix) return Number(n) || 0;
  }
  return 0;
}

/** Returns { count, prefix }. Throws on network or HTTP errors. */
export async function pwnedCount(password) {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), 15000);
  let res;
  try {
    res = await fetch(API + prefix, { headers: { 'Add-Padding': 'true' }, signal: ctl.signal, referrerPolicy: 'no-referrer', credentials: 'omit', cache: 'no-store' });
  } finally { clearTimeout(t); }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return { count: countIn(await res.text(), hash.slice(5)), prefix };
}

export default {
  id: 'breach-check',
  name: 'Password breach check',
  icon: 'key-round',
  accepts: [],
  inputs: ['Password'],
  summary: 'Check whether a password appears in known data breaches. Only a 5-character hash prefix is sent (k-anonymity).',
  source: 'Have I Been Pwned · Pwned Passwords',

  panel(body) {
    const input = el('input', { id: 'bc-input', type: 'password', class: 'pw-input', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', 'aria-describedby': 'bc-how' });
    const toggle = el('button', { type: 'button', class: 'pw-toggle', 'aria-label': 'Show password', 'aria-pressed': 'false', onclick: () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      toggle.setAttribute('aria-pressed', String(show));
      toggle.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      toggle.replaceChildren(iconEl(show ? 'eye-off' : 'eye', 18));
    } }, iconEl('eye', 18));
    const out = el('div', { class: 'section-stack bc-out', 'aria-live': 'polite' });
    const go = el('button', { type: 'submit', class: 'btn btn-primary', id: 'bc-go' }, iconEl('search', 18), 'Check');

    const form = el('form', { class: 'card bc-card', autocomplete: 'off', onsubmit: async (ev) => {
      ev.preventDefault();
      const pw = input.value;
      if (!pw) { input.focus(); return; }
      go.disabled = true;
      out.replaceChildren(el('div', { class: 'loading', role: 'status' }, 'Checking…'));
      try {
        const { count } = await pwnedCount(pw);
        out.replaceChildren(count
          ? el('div', { class: 'fact-grid' }, factCard({ label: 'Seen in breaches', status: 'high', statusText: 'Breached', figure: fmtNum(count), unit: count === 1 ? 'time' : 'times', caption: 'This password is in known breach data. Do not use it anywhere; change it wherever it is used.' }))
          : el('div', { class: 'fact-grid' }, factCard({ label: 'Seen in breaches', status: 'low', statusText: 'Not found', figure: '0', unit: 'times', caption: 'Not in the Pwned Passwords data set. That does not make it strong; use a long, unique password for every site.' })));
      } catch {
        out.replaceChildren(callout('unknown', 'Check unavailable', 'Have I Been Pwned could not be reached. Check your connection or try again later.'));
      } finally { go.disabled = false; }
    } },
    el('label', { class: 'card-title', for: 'bc-input' }, 'Password'),
    el('div', { class: 'pw-row' }, el('div', { class: 'pw-field' }, input, toggle), go),
    el('p', { class: 'caption', id: 'bc-how' }, 'The password is hashed (SHA-1) in your browser. Only the first 5 characters of the hash are sent to api.pwnedpasswords.com, which returns every breached hash starting with them; the match is made here.'));

    // Leaving the tool clears the password and result.
    window.addEventListener('hashchange', () => {
      if (!new URLSearchParams(location.hash.slice(1)).get('tool')?.startsWith('breach-check')) {
        input.value = ''; input.type = 'password'; toggle.setAttribute('aria-pressed', 'false'); toggle.setAttribute('aria-label', 'Show password'); toggle.replaceChildren(iconEl('eye', 18)); out.replaceChildren();
      }
    });

    body.append(form, out);
  },
};
