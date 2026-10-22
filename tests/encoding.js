// Hash & encode module: known-answer tests, UI checks and a no-network check, in headless Chrome.
// Usage: python3 -m http.server 8811 &   then   node tests/encoding.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const crypto = require('crypto');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'screenshots');

const TEXTS = ['', 'abc', 'The quick brown fox jumps over the lazy dog', 'Ünïcödé ✓ 日本語 🙂 മലയാളം', 'a'.repeat(1000)];
const node = {
  hash: (alg, s) => crypto.createHash(alg).update(Buffer.from(s, 'utf8')).digest('hex'),
  b64: (s) => Buffer.from(s, 'utf8').toString('base64'),
  b64url: (s) => Buffer.from(s, 'utf8').toString('base64url'),
  hex: (s) => Buffer.from(s, 'utf8').toString('hex'),
};
// RFC 1321 appendix A.5 test suite
const MD5_RFC = { '': 'd41d8cd98f00b204e9800998ecf8427e', a: '0cc175b9c0f1b6a831c399e269772661', abc: '900150983cd24fb0d6963f7d28e17f72', 'message digest': 'f96b697d7cb7938d525a2f31aaf161d0', abcdefghijklmnopqrstuvwxyz: 'c3fcd3d76192e4007dfb496cca67e13b', ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789: 'd174ab98d277d9f5a5611c2c9f419d9f', '12345678901234567890123456789012345678901234567890123456789012345678901234567890': '57edf4a22be3c955ac49da2e2107b67a' };

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };
  const eq = (name, got, want) => { if (got !== want) fail(`${name}: got ${JSON.stringify(got)?.slice(0, 120)}, want ${JSON.stringify(want)?.slice(0, 120)}`); };

  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light', permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') errs.push(`console: ${m.text()}`); });
  await page.goto(`${BASE}#tool=encoding`);
  await page.waitForSelector('#enc-input');

  // ---- known-answer tests against Node's crypto / Buffer ----
  const got = await page.evaluate(async (texts) => {
    const m = await import('./modules/encoding.js');
    const out = [];
    for (const t of texts) {
      const bytes = new TextEncoder().encode(t);
      const roundB64 = t ? new TextDecoder().decode(m.base64ToBytes(m.base64Encode(t))) : '';
      const roundUrl = t ? new TextDecoder().decode(m.base64ToBytes(m.base64UrlEncode(t))) : '';
      const roundHex = t ? new TextDecoder().decode(m.hexToBytes(m.hexEncode(t))) : '';
      out.push({ t, hashes: Object.fromEntries(await m.hashAll(bytes)), b64: m.base64Encode(t), b64url: m.base64UrlEncode(t), hex: m.hexEncode(t), roundB64, roundUrl, roundHex, url: m.urlDecode(m.urlEncode(t)), html: m.htmlDecode(m.htmlEncode(t)) });
    }
    return { out };
  }, TEXTS);
  for (const r of got.out) {
    const label = JSON.stringify(r.t.slice(0, 20));
    for (const [alg, n] of [['MD5', 'md5'], ['SHA-1', 'sha1'], ['SHA-256', 'sha256'], ['SHA-384', 'sha384'], ['SHA-512', 'sha512']]) eq(`${alg} ${label}`, r.hashes[alg], node.hash(n, r.t));
    eq(`base64 ${label}`, r.b64, node.b64(r.t));
    eq(`base64url ${label}`, r.b64url, node.b64url(r.t));
    eq(`hex ${label}`, r.hex, node.hex(r.t));
    for (const k of ['roundB64', 'roundUrl', 'roundHex', 'url', 'html']) eq(`${k} round-trip ${label}`, r[k], r.t);
  }
  const rfc = await page.evaluate(async (v) => { const { md5 } = await import('./js/md5.js'); return Object.fromEntries(Object.keys(v).map((k) => [k, md5(new TextEncoder().encode(k))])); }, MD5_RFC);
  for (const [k, v] of Object.entries(MD5_RFC)) eq(`MD5 RFC 1321 ${JSON.stringify(k.slice(0, 12))}`, rfc[k], v);
  const fixed = await page.evaluate(async () => {
    const m = await import('./modules/encoding.js');
    const tryErr = (f) => { try { f(); return null; } catch (e) { return e instanceof m.EncodingError; } };
    return {
      b64dec: new TextDecoder().decode(m.base64ToBytes('SGVsbG8sIOS4lueVjCE=')),
      b64nopad: new TextDecoder().decode(m.base64ToBytes('SGVsbG8')),
      b64urlDec: new TextDecoder().decode(m.base64ToBytes('_-8')),
      badB64: tryErr(() => m.base64ToBytes('abc$def')),
      badB64Len: tryErr(() => m.base64ToBytes('abcde')),
      badHex: tryErr(() => m.hexToBytes('abc')),
      badUrl: tryErr(() => m.urlDecode('%E0%A4%A')),
      url: m.urlEncode('a b&c=d/é'),
      urlPlus: m.urlDecode('a+b%26c'),
      html: m.htmlEncode('<a href="x">\'&\'</a>'),
      htmlDec: m.htmlDecode('&lt;b&gt; &amp;amp; &#39; &#x1F642; &unknown;'),
      defang: m.defang('Visit https://evil.example.com/a.php or 203.0.113.5 now. ok'),
      refang: m.refang('hxxps://evil[.]example[.]com/a.php user[@]example(.)org 203[.]0[.]113[.]5'),
      guessB64: m.guessEncoding('SGVsbG8gd29ybGQ='), guessUrl: m.guessEncoding('a%20b%2Fc'), guessHex: m.guessEncoding('68656c6c6f20776f726c64'), guessFang: m.guessEncoding('evil[.]com'), guessPlain: m.guessEncoding('hello world'), guessHash: m.guessEncoding('d41d8cd98f00b204e9800998ecf8427e'),
    };
  });
  eq('b64 decode UTF-8', fixed.b64dec, 'Hello, 世界!');
  eq('b64 decode without padding', fixed.b64nopad, 'Hello');
  eq('b64url decode', fixed.b64urlDec, Buffer.from('_-8', 'base64url').toString('utf8'));
  for (const k of ['badB64', 'badB64Len', 'badHex', 'badUrl']) eq(`${k} throws EncodingError`, fixed[k], true);
  eq('url encode', fixed.url, encodeURIComponent('a b&c=d/é'));
  eq('url decode +', fixed.urlPlus, 'a b&c');
  eq('html encode', fixed.html, '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;');
  eq('html decode', fixed.htmlDec, "<b> &amp; ' 🙂 &unknown;");
  eq('defang', fixed.defang, 'Visit hxxps://evil[.]example[.]com/a[.]php or 203[.]0[.]113[.]5 now. ok');
  eq('refang', fixed.refang, 'https://evil.example.com/a.php user@example.org 203.0.113.5');
  eq('guess base64', fixed.guessB64, 'b64-dec');
  eq('guess url', fixed.guessUrl, 'url-dec');
  eq('guess hex', fixed.guessHex, 'hex-dec');
  eq('guess defanged', fixed.guessFang, 'refang');
  eq('guess plain text', fixed.guessPlain, null);
  eq('guess leaves hashes alone', fixed.guessHash, null);
  console.log('ok: known-answer tests (hashes, Base64/Base64URL, hex, URL, HTML, defang/refang, detection)');

  // ---- UI: no network requests while using the tool ----
  const requests = [];
  page.on('request', (r) => requests.push(r.url()));
  const sample = 'Ünïcödé ✓ 🙂';
  await page.fill('#enc-input', sample);
  await page.click('#enc-hash');
  await page.waitForSelector('.hash-table tr[data-alg="SHA-256"]');
  eq('UI SHA-256', await page.textContent('.hash-table tr[data-alg="SHA-256"] td.mono'), node.hash('sha256', sample));
  eq('UI MD5', await page.textContent('.hash-table tr[data-alg="MD5"] td.mono'), node.hash('md5', sample));
  if (await page.$('.hash-table tr[data-alg="SHA-512"] button:has-text("Reputation")')) fail('SHA-512 should not offer a reputation link');
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'encoding-desktop-light.png') });

  // copy + screen-reader announcement
  await page.click('.hash-table tr[data-alg="SHA-256"] button[aria-label="Copy SHA-256 hash"]');
  await page.waitForFunction(() => [...document.querySelectorAll('[aria-live="polite"][role="status"]')].some((n) => /Copied/.test(n.textContent)));
  eq('clipboard', await page.evaluate(() => navigator.clipboard.readText()), node.hash('sha256', sample));
  console.log('ok: copy button copies and announces');

  // encode / decode via buttons, Unicode round trip
  await page.click('[data-op="b64-enc"]');
  eq('UI base64', await page.textContent('.out-box'), node.b64(sample));
  await page.click('button:has-text("Use as input")');
  if (!(await page.$('.enc-hint [data-op="b64-dec"]'))) fail('Base64 not auto-detected');
  await page.click('.enc-hint [data-op="b64-dec"]');
  eq('UI base64 round-trip', await page.textContent('.out-box'), sample);

  // invalid Base64 error
  await page.fill('#enc-input', 'not*base64');
  await page.click('[data-op="b64-dec"]');
  const errText = await page.textContent('.enc-out [role="alert"]').catch(() => '');
  if (!/Not valid Base64/.test(errText)) fail(`invalid Base64 error missing: ${errText}`);

  // file hash (File API, nothing uploaded)
  const fileBytes = crypto.randomBytes(300000);
  await page.setInputFiles('#enc-file', { name: 'sample.bin', mimeType: 'application/octet-stream', buffer: fileBytes });
  await page.waitForSelector('.enc-out .hash-table');
  eq('file SHA-256', await page.textContent('.hash-table tr[data-alg="SHA-256"] td.mono'), crypto.createHash('sha256').update(fileBytes).digest('hex'));
  eq('file MD5', await page.textContent('.hash-table tr[data-alg="MD5"] td.mono'), crypto.createHash('md5').update(fileBytes).digest('hex'));
  eq('file SHA-1', await page.textContent('.hash-table tr[data-alg="SHA-1"] td.mono'), crypto.createHash('sha1').update(fileBytes).digest('hex'));
  if (requests.length) fail(`network requests while using the tool:\n  ${requests.join('\n  ')}`);
  else console.log('ok: no network requests while hashing, encoding and decoding');

  // send a hash to Reputation
  await page.click('.hash-table tr[data-alg="SHA-256"] button:has-text("Reputation")');
  await page.waitForSelector('#mod-reputation');
  if (!/tool=reputation/.test(page.url())) fail('reputation hand-off');
  console.log('ok: hash opens Reputation');

  // dark
  await page.goto(`${BASE}#tool=encoding`);
  await page.click('.switch-rail');
  await page.fill('#enc-input', 'https://example.com/login?u=a b');
  await page.click('[data-op="defang"]');
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'encoding-desktop-dark.png') });
  await page.click('.switch-rail');
  const ov = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  if (ov) fail('desktop horizontal overflow');
  if (errs.length) fail(`desktop console errors:\n  ${errs.join('\n  ')}`);
  await ctx.close();

  // ---- mobile ----
  const mctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'light' });
  const m = await mctx.newPage();
  const merrs = [];
  m.on('pageerror', (e) => merrs.push(`pageerror: ${e.message}`));
  m.on('console', (x) => { if (x.type() === 'error') merrs.push(`console: ${x.text()}`); });
  await m.goto(`${BASE}#tool=encoding`);
  await m.fill('#enc-input', 'hello');
  await m.click('#enc-hash');
  await m.waitForSelector('.hash-table');
  const mob = await m.evaluate(() => ({
    overflow: document.documentElement.scrollWidth > window.innerWidth,
    hero: getComputedStyle(document.querySelector('.hero')).display,
    small: [...document.querySelectorAll('#mod-encoding button, #mod-encoding label.btn, .chips .chip')].filter((e) => e.offsetParent && e.getBoundingClientRect().height < 44).map((e) => e.textContent.trim()),
  }));
  if (mob.overflow) fail('mobile: horizontal overflow');
  if (mob.hero !== 'none') fail('mobile: search hero should be hidden on a standalone tool');
  if (mob.small.length) fail(`mobile: tap targets <44px: ${mob.small.join(', ')}`);
  console.log('ok: mobile layout', JSON.stringify(mob));
  if (SHOTS) await m.screenshot({ path: path.join(shotDir, 'encoding-mobile-light.png'), fullPage: true });
  if (merrs.length) fail(`mobile console errors:\n  ${merrs.join('\n  ')}`);
  await mctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
