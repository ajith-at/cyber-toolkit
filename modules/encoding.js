// Hash, Base64 and encoding tools. Everything runs in the browser: no network requests, nothing uploaded.
import { el, iconEl, copyButton, announce, loading } from '../js/ui.js';
import { md5 } from '../js/md5.js';
import { HASHES } from '../js/detect.js';

const enc = new TextEncoder();
const utf8 = (bytes) => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

export class EncodingError extends Error {}

// ---------- hashing ----------
export const ALGORITHMS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];

/** Hashes bytes with every algorithm. Returns [[name, hex], ...]. */
export async function hashAll(bytes) {
  const out = [['MD5', md5(bytes)]];
  for (const a of ALGORITHMS.slice(1)) out.push([a, toHex(new Uint8Array(await crypto.subtle.digest(a, bytes)))]);
  return out;
}

// ---------- Base64 ----------
function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

export const base64Encode = (s) => bytesToB64(enc.encode(s));
export const base64UrlEncode = (s) => base64Encode(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Base64 or Base64URL (either alphabet, padding optional, whitespace ignored) to bytes. */
export function base64ToBytes(s) {
  let t = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!t) throw new EncodingError('Nothing to decode.');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(t)) throw new EncodingError('Not valid Base64: it contains characters outside A–Z, a–z, 0–9, + / (or - _ for Base64URL) and = padding.');
  t = t.replace(/=+$/, '');
  if (t.length % 4 === 1) throw new EncodingError('Not valid Base64: the length is wrong, so some characters are missing or extra.');
  t += '='.repeat((4 - (t.length % 4)) % 4);
  const bin = atob(t);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// ---------- hex ----------
export const hexEncode = (s) => toHex(enc.encode(s));
export function hexToBytes(s) {
  const t = s.replace(/0x/gi, '').replace(/[\s:,-]/g, '');
  if (!t) throw new EncodingError('Nothing to decode.');
  if (!/^[0-9a-f]*$/i.test(t)) throw new EncodingError('Not valid hex: only 0–9 and a–f are allowed (spaces, colons and 0x are ignored).');
  if (t.length % 2) throw new EncodingError('Not valid hex: it has an odd number of digits.');
  return Uint8Array.from(t.match(/../g), (h) => parseInt(h, 16));
}

// ---------- URL ----------
export const urlEncode = (s) => encodeURIComponent(s);
export function urlDecode(s) {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { throw new EncodingError('Not valid URL encoding: a % is not followed by a valid UTF-8 sequence.'); }
}

// ---------- HTML entities ----------
const NAMED = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', copy: '©', reg: '®', hellip: '…', ndash: '–', mdash: '—', lsquo: '‘', rsquo: '’', ldquo: '“', rdquo: '”' };
export const htmlEncode = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
export function htmlDecode(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1].toLowerCase() === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
    }
    return NAMED[e.toLowerCase()] ?? m;
  });
}

// ---------- defang / refang ----------
const INDICATOR = /\b(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z][a-z0-9-]{1,62})\b/gi;
export function defang(s) {
  return s.replace(/\bhttp(s?):\/\//gi, 'hxxp$1://').replace(/\bftp:\/\//gi, 'fxp://').replace(INDICATOR, (m) => m.replace(/\./g, '[.]'));
}
export function refang(s) {
  return s.replace(/\bhxxp(s?):\/\//gi, 'http$1://').replace(/\bfxp:\/\//gi, 'ftp://')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.').replace(/\[@\]|\[at\]/gi, '@').replace(/\[:\]/g, ':');
}

/** Bytes to text when they are UTF-8, otherwise hex (flagged). */
function bytesOut(bytes) {
  try { return { text: utf8(bytes) }; } catch { return { text: toHex(bytes), note: 'The decoded bytes are not UTF-8 text, so they are shown as hex.' }; }
}

export const OPS = {
  'b64-enc': { label: 'Base64', title: 'Base64 encoded', run: (s) => ({ text: base64Encode(s) }) },
  'b64url-enc': { label: 'Base64URL', title: 'Base64URL encoded', run: (s) => ({ text: base64UrlEncode(s) }) },
  'url-enc': { label: 'URL', title: 'URL encoded', run: (s) => ({ text: urlEncode(s) }) },
  'hex-enc': { label: 'Hex', title: 'Hex encoded', run: (s) => ({ text: hexEncode(s) }) },
  'html-enc': { label: 'HTML entities', title: 'HTML entities encoded', run: (s) => ({ text: htmlEncode(s) }) },
  defang: { label: 'Defang', title: 'Defanged', run: (s) => ({ text: defang(s) }) },
  'b64-dec': { label: 'Base64', title: 'Base64 decoded', run: (s) => bytesOut(base64ToBytes(s)) },
  'url-dec': { label: 'URL', title: 'URL decoded', run: (s) => ({ text: urlDecode(s) }) },
  'hex-dec': { label: 'Hex', title: 'Hex decoded', run: (s) => bytesOut(hexToBytes(s)) },
  'html-dec': { label: 'HTML entities', title: 'HTML entities decoded', run: (s) => ({ text: htmlDecode(s) }) },
  refang: { label: 'Refang', title: 'Refanged', run: (s) => ({ text: refang(s) }) },
};
const ENCODE = ['b64-enc', 'b64url-enc', 'url-enc', 'hex-enc', 'html-enc', 'defang'];
const DECODE = ['b64-dec', 'url-dec', 'hex-dec', 'html-dec', 'refang'];

/** Best guess at how a string is encoded, or null. Only suggests when decoding gives readable text. */
export function guessEncoding(s) {
  const t = s.trim();
  if (t.length < 4) return null;
  const readable = (x) => /^[\P{C}\s]*$/u.test(x) && x.trim().length > 0;
  if (/%[0-9a-f]{2}/i.test(t) && !/\s/.test(t)) {
    try { if (urlDecode(t) !== t) return 'url-dec'; } catch { /* not URL encoding */ }
  }
  if (/^(?:[0-9a-f]{2})+$/i.test(t) && t.length >= 8 && !HASHES[t.length]) {
    try { if (readable(utf8(hexToBytes(t)))) return 'hex-dec'; } catch { /* not hex text */ }
  }
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(t.replace(/\s+/g, '')) && t.length >= 8 && /[A-Z]/.test(t) && /[a-z0-9+/=_-]/.test(t)) {
    try { if (readable(utf8(base64ToBytes(t)))) return 'b64-dec'; } catch { /* not Base64 text */ }
  }
  if (/\bhxxps?:\/\/|\[\.\]/i.test(t)) return 'refang';
  return null;
}

// ---------- UI ----------
function hashTable(rows, go) {
  return el('div', { class: 'table-scroll' }, el('table', { class: 'grid hash-table' },
    el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Algorithm'), el('th', { scope: 'col' }, 'Hash'), el('th', { scope: 'col' }, el('span', { class: 'sr-only' }, 'Actions')))),
    el('tbody', {}, rows.map(([a, h]) => el('tr', { 'data-alg': a },
      el('td', { class: 'label' }, a),
      el('td', { class: 'mono' }, h),
      el('td', { class: 'row-actions' },
        copyButton(() => h, `Copy ${a} hash`),
        Object.values(HASHES).includes(a) ? el('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => go(h, 'reputation') }, iconEl('radar', 16), 'Reputation') : null))))));
}

export default {
  id: 'encoding',
  name: 'Hash & encode',
  icon: 'binary',
  accepts: [],
  inputs: ['Text', 'File'],
  summary: 'Hash text or a file (MD5, SHA-1, SHA-256, SHA-384, SHA-512), Base64, URL, hex and HTML encoding, defang and refang.',
  source: 'Runs in your browser. Nothing is uploaded.',

  panel(body, { go }) {
    const input = el('textarea', { id: 'enc-input', class: 'textbox mono', rows: '6', spellcheck: 'false', autocapitalize: 'off', placeholder: 'Text to hash, encode or decode' });
    const hint = el('div', { class: 'enc-hint', 'aria-live': 'polite' });
    const out = el('div', { class: 'enc-out' });

    const show = (node) => { out.replaceChildren(node); };
    const result = (title, text, note) => {
      const pre = el('pre', { class: 'mono out-box', tabindex: '0', 'aria-label': title }, text);
      show(el('article', { class: 'card', 'aria-live': 'polite' },
        el('h3', { class: 'card-title' }, title),
        pre,
        note ? el('p', { class: 'caption' }, note) : null,
        el('div', { class: 'link-row' },
          copyButton(() => text, `Copy ${title.toLowerCase()} result`),
          el('button', { type: 'button', class: 'btn btn-secondary btn-sm', onclick: () => { input.value = text; input.dispatchEvent(new Event('input')); input.focus(); announce('Result moved to the input'); } }, iconEl('arrow-right', 16), 'Use as input'))));
    };
    const error = (title, msg) => show(el('div', { class: 'card callout callout-rose', role: 'alert' }, el('div', {}, el('p', { class: 'callout-title' }, title), el('p', { class: 'caption' }, msg))));

    const runOp = (id) => {
      const op = OPS[id];
      try {
        const r = op.run(input.value);
        result(op.title, r.text, r.note);
      } catch (e) {
        if (!(e instanceof EncodingError) && !(e instanceof DOMException)) throw e;
        error(`Could not decode ${op.label}`, e instanceof EncodingError ? e.message : 'Not valid Base64.');
      }
    };

    const hashText = async () => {
      const rows = await hashAll(enc.encode(input.value));
      show(el('article', { class: 'card', 'aria-live': 'polite' }, el('h3', { class: 'card-title' }, 'Text hashes'),
        el('p', { class: 'caption' }, `${enc.encode(input.value).length.toLocaleString('en-AU')} bytes, UTF-8`), hashTable(rows, go)));
    };

    const fileInput = el('input', { type: 'file', id: 'enc-file', class: 'sr-only', onchange: async () => {
      const f = fileInput.files[0];
      if (!f) return;
      show(loading(`Hashing ${f.name}…`));
      try {
        const rows = await hashAll(new Uint8Array(await f.arrayBuffer()));
        show(el('article', { class: 'card', 'aria-live': 'polite' }, el('h3', { class: 'card-title' }, 'File hashes'),
          el('p', { class: 'caption' }, el('span', { class: 'mono' }, f.name), ` · ${f.size.toLocaleString('en-AU')} bytes`), hashTable(rows, go)));
      } catch {
        error('Could not read the file', 'The browser could not read that file. Very large files may not fit in memory.');
      }
      fileInput.value = '';
    } });

    input.addEventListener('input', () => {
      const g = guessEncoding(input.value);
      hint.replaceChildren(g ? el('span', { class: 'caption' }, `Looks like ${g === 'refang' ? 'defanged indicators' : OPS[g].label}`) : '',
        g ? el('button', { type: 'button', class: 'chip chip-soft', 'data-op': g, onclick: () => runOp(g) }, iconEl('arrow-right', 14), OPS[g].label === 'Refang' ? 'Refang' : `Decode ${OPS[g].label}`) : '');
    });

    const group = (label, ids, verb) => el('div', { class: 'op-group', role: 'group', 'aria-label': label },
      el('span', { class: 'label' }, label),
      el('div', { class: 'op-row' }, ids.map((id) => el('button', { type: 'button', class: 'chip chip-soft', 'data-op': id, 'aria-label': `${verb} ${OPS[id].label}`.replace(/^(Encode|Decode) (Defang|Refang)$/, '$2'), onclick: () => runOp(id) }, OPS[id].label))));

    body.append(
      el('article', { class: 'card enc-card' },
        el('label', { class: 'card-title', for: 'enc-input' }, 'Text'),
        input,
        hint,
        el('div', { class: 'op-groups' },
          el('div', { class: 'op-group', role: 'group', 'aria-label': 'Hash' }, el('span', { class: 'label' }, 'Hash'),
            el('div', { class: 'op-row' }, el('button', { type: 'button', class: 'chip chip-soft', id: 'enc-hash', onclick: hashText }, iconEl('fingerprint', 14), 'Hash text'))),
          group('Encode', ENCODE, 'Encode'),
          group('Decode', DECODE, 'Decode'))),
      el('article', { class: 'card file-card' },
        el('div', {}, el('h3', { class: 'card-title' }, 'File'), el('p', { class: 'caption' }, 'The file is hashed in your browser and never uploaded.')),
        el('label', { class: 'btn btn-secondary', for: 'enc-file' }, iconEl('file-search', 18), 'Choose a file', fileInput)),
      out,
    );
  },
};
