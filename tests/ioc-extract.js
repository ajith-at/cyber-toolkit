// Extract indicators module: extraction fixtures (normal, defanged, tricky), defang/refang round trips,
// UI checks (copy, Check, XSS-safe rendering), light, dark and mobile, no console errors, no network.
// Usage: python3 -m http.server 8811 &   then   node tests/ioc-extract.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'docs', 'screenshots');
const fixture = (n) => fs.readFileSync(path.join(__dirname, 'fixtures', `ioc-${n}.txt`), 'utf8');

const EXPECT = {
  normal: {
    url: ['https://download.update-check.example.net/v2/agent.exe?id=771', 'http://203.0.113.45:8080/gate.php', 'ftp://files.example.com/pub/payload.bin', 'http://[2001:db8::42]:8443/beacon', 'https://www.example.org/advisories/orchid-7'],
    domain: ['cert.example.org', 'download.update-check.example.net', 'files.example.com', 'update-check.example.net', 'telemetry.example.co.uk', 'example.com', 'example.org', 'www.example.org'],
    ip: ['203.0.113.45', '198.51.100.7', '2001:db8:85a3::8a2e:370:7334', '2001:db8::42'],
    email: ['alerts@cert.example.org', 'abuse@example.com', 'soc.team@example.org'],
    hash: ['d41d8cd98f00b204e9800998ecf8427e', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],
  },
  defanged: {
    url: ['https://login-microsoftonline.example.com/common/oauth2?client=abc', 'http://198.51.100.99/drop/stage2.ps1', 'https://short.example.net/x7', 'ftp://archive.example.org/a.zip'],
    domain: ['login-microsoftonline.example.com', 'short.example.net', 'archive.example.org', 'c2.bad-actor.example', 'invoice-portal.example', 'evil.zip'],
    ip: ['198.51.100.99', '192.0.2.10', '2001:db8::bad'],
    email: ['billing@invoice-portal.example', 'refunds@invoice-portal.example'],
    hash: [],
  },
  // Version numbers, file names, code, times, MACs, GUIDs, SHA-512, long numbers and bad IPs must not match.
  tricky: { url: [], domain: [], ip: ['1.2.3.4'], email: [], hash: [] },
};

// Small cases: [text, type, expected values]
const CASES = [
  ['v2.0 and 1.2.3.4.5', 'ip', []],
  ['version 10.0.0.1, but 10.0.0.1 alone counts', 'ip', ['10.0.0.1']],
  ['hash: ' + 'ab'.repeat(64), 'hash', []],
  ['two hashes 44D88612FEA8A8F36DE82E1278ABB02F 44d88612fea8a8f36de82e1278abb02f', 'hash', ['44d88612fea8a8f36de82e1278abb02f']],
  ['(see https://example.com/a_(b)) and https://example.net/x.', 'url', ['https://example.com/a_(b)', 'https://example.net/x']],
  ['Visit Example.COM. Then EXAMPLE.com', 'domain', ['example.com']],
  ['System.IO and Console.WriteLine', 'domain', []],
  ['::ffff:192.0.2.1 and fe80::1%eth0', 'ip', ['192.0.2.1']],
  ['photos.zip vs photos[.]zip vs cdn.photos.zip', 'domain', ['photos.zip', 'cdn.photos.zip']],
  ['onion: abcdefghijklmnop.onion', 'domain', ['abcdefghijklmnop.onion']],
];

const ROUND = [
  ['https://evil.example.com/a.php?x=1', 'url'], ['http://[2001:db8::1]:8080/x', 'url'], ['ftp://1.2.3.4/x', 'url'],
  ['a.b.example.co.uk', 'domain'], ['203.0.113.5', 'ipv4'], ['2001:db8::1', 'ipv6'], ['first.last+tag@mail.example.org', 'email'],
  ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'hash'],
];

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };
  const same = (name, got, want) => { if (JSON.stringify(got) !== JSON.stringify(want)) fail(`${name}:\n    got  ${JSON.stringify(got)}\n    want ${JSON.stringify(want)}`); };

  async function open(opts) {
    const ctx = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'], ...opts });
    const page = await ctx.newPage();
    const errs = [];
    const foreign = [];
    page.on('pageerror', (e) => errs.push(`pageerror: ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') errs.push(`console: ${m.text()}`); });
    page.on('dialog', (d) => { errs.push(`dialog: ${d.message()}`); d.dismiss(); });
    page.on('request', (r) => { const u = r.url(); if (!u.startsWith(BASE) && !/fonts\.(googleapis|gstatic)\.com/.test(u)) foreign.push(u); });
    await page.goto(`${BASE}#tool=ioc-extract`);
    await page.waitForSelector('#ioc-input');
    return { ctx, page, errs, foreign };
  }

  // ---- extraction and round trips, in the page (the real ES modules) ----
  const d = await open({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  const got = await d.page.evaluate(async ({ texts, cases, round }) => {
    const m = await import('./js/ioc.js');
    const by = (r, t) => r.items.filter((i) => i.type === t).map((i) => i.value);
    const fx = Object.fromEntries(Object.entries(texts).map(([k, t]) => { const r = m.extractIocs(t); return [k, { url: by(r, 'url'), domain: by(r, 'domain'), ip: by(r, 'ip'), email: by(r, 'email'), hash: by(r, 'hash'), total: r.total, counts: r.counts, fanged: r.items.filter((i) => i.defanged).length }]; }));
    const cs = cases.map(([t, type]) => by(m.extractIocs(t), type));
    const rt = round.map(([v, t]) => ({ v, d: m.defangIndicator(v, t), back: m.refang(m.defangIndicator(v, t)) }));
    // A defanged copy of a fixture, extracted again, must give the same indicators.
    const r1 = m.extractIocs(texts.normal);
    const r2 = m.extractIocs(m.formatIocs(r1.items, 'defanged'));
    const r3 = m.extractIocs(m.formatIocs(r1.items, 'written'));
    const enc = await import('./modules/encoding.js');
    return { fx, cs, rt, reDefanged: r2.items.map((i) => `${i.type}|${i.value}`).sort(), orig: r1.items.map((i) => `${i.type}|${i.value}`).sort(), reWritten: r3.items.map((i) => `${i.type}|${i.value}`).sort(),
      shared: enc.refang === m.refang && enc.defang === m.defang, written: r1.items.find((i) => i.type === 'email' && i.value.startsWith('soc')).written };
  }, { texts: { normal: fixture('normal'), defanged: fixture('defanged'), tricky: fixture('tricky') }, cases: CASES, round: ROUND });

  for (const [k, want] of Object.entries(EXPECT)) for (const [t, v] of Object.entries(want)) same(`fixture ${k} ${t}`, got.fx[k][t], v);
  same('defanged fixture: every indicator flagged as defanged in text (except URL hosts written live)', got.fx.defanged.fanged, got.fx.defanged.total);
  CASES.forEach(([t, type, want], i) => same(`case ${JSON.stringify(t.slice(0, 40))}`, got.cs[i], want));
  for (const r of got.rt) { if (r.back !== r.v) fail(`round trip ${r.v} -> ${r.d} -> ${r.back}`); if (r.d === r.v && !/^[a-f0-9]+$/.test(r.v)) fail(`not defanged: ${r.v}`); }
  same('defanged copy re-extracts to the same set', got.reDefanged, got.orig);
  same('plain (as written) copy re-extracts to the same set', got.reWritten, got.orig);
  if (!got.shared) fail('Hash & encode should reuse defang/refang from js/ioc.js');
  same('as written keeps original case', got.written, 'Soc.Team@Example.ORG');
  console.log('ok: fixtures', Object.entries(got.fx).map(([k, v]) => `${k}=${v.total}`).join(' '), `| ${CASES.length} cases | ${ROUND.length} round trips`);

  // ---- UI: sample, groups, copy, XSS-safe ----
  const p = d.page;
  await p.click('#ioc-sample');
  await p.waitForSelector('.ioc-summary');
  const ui = await p.evaluate(() => ({
    title: document.querySelector('.ioc-summary .card-title').textContent,
    groups: [...document.querySelectorAll('[data-group]')].map((g) => g.dataset.group),
    rows: document.querySelectorAll('.ioc-table tbody tr').length,
    checks: document.querySelectorAll('[data-check]').length,
  }));
  same('sample groups', ui.groups, ['url', 'domain', 'ip', 'email', 'hash']);
  if (ui.rows !== ui.checks || ui.rows < 10) fail(`sample rows ${ui.rows}, checks ${ui.checks}`);
  console.log('ok: sample', JSON.stringify(ui));
  if (SHOTS) {
    await p.screenshot({ path: path.join(shotDir, 'pr31-ioc-light.png') });
    // The main column scrolls inside the shell, so grow the viewport to capture every group.
    const full = await p.evaluate(() => document.querySelector('.content').scrollHeight + 120);
    await p.setViewportSize({ width: 1440, height: full });
    await p.screenshot({ path: path.join(shotDir, 'pr31-ioc-light-full.png') });
    await p.setViewportSize({ width: 1440, height: 900 });
  }

  const copy = async (sel) => { await p.click(sel); await p.waitForTimeout(80); return p.evaluate(() => navigator.clipboard.readText()); };
  const plain = await copy('.ioc-summary button[aria-label^="Copy all as plain"]');
  const defangedOut = await copy('.ioc-summary button[aria-label^="Copy all defanged"]');
  const refanged = await copy('.ioc-summary button[aria-label^="Copy all refanged"]');
  if (!plain.includes('hxxps://login.account-verify[.]example/sso/start?session=8841')) fail('plain copy should keep the defanged form as written');
  if (/https?:\/\//.test(defangedOut) || !defangedOut.includes('hxxps://login[.]account-verify[.]example/sso/start?session=8841')) fail(`defanged copy not safe:\n${defangedOut}`);
  if (/hxxp|\[\.\]|\[@\]/.test(refanged) || !refanged.includes('https://login.account-verify.example/sso/start?session=8841')) fail(`refanged copy not live:\n${refanged}`);
  if (plain.split('\n').length !== refanged.split('\n').length) fail('copy formats have different line counts');
  const groupCopy = await copy('[data-group="hash"] button[aria-label="Copy all File hashes"]');
  same('hash group copy', groupCopy.split('\n').length, 3);
  console.log('ok: copy plain / defanged / refanged and per group');

  // XSS: pasted markup is shown as text only
  await p.fill('#ioc-input', fixture('tricky'));
  await p.click('#ioc-go');
  const xss = await p.evaluate(() => ({ img: !!document.querySelector('#mod-ioc-extract img, #results script'), flag: window.__xss || 0, ips: [...document.querySelectorAll('[data-check]')].map((b) => b.dataset.check) }));
  if (xss.img || xss.flag) fail('pasted markup was rendered');
  same('tricky UI', xss.ips, ['1.2.3.4']);
  await p.fill('#ioc-input', 'nothing here, just v1.0 and report.pdf');
  await p.click('#ioc-go');
  if (!/No indicators found/.test(await p.textContent('.ioc-out'))) fail('empty result message missing');
  console.log('ok: XSS-safe, tricky input, empty result');

  // Dark mode
  await p.click('#ioc-sample');
  await p.click('.switch-rail');
  if (await p.getAttribute('html', 'data-theme') !== 'dark') fail('dark mode did not switch');
  if (SHOTS) { await p.waitForTimeout(500); await p.screenshot({ path: path.join(shotDir, 'pr31-ioc-dark.png') }); }
  const ov = await p.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  if (ov) fail('desktop horizontal overflow');
  await p.click('.switch-rail');

  // Check opens the smart input
  await p.click('[data-group="domain"] [data-check]');
  await p.waitForSelector('.summary');
  const h = await p.evaluate(() => ({ hash: decodeURIComponent(location.hash), q: document.querySelector('#q').value, hero: !document.querySelector('.hero').hidden }));
  if (!h.hash.includes('q=account-verify.example') || h.q !== 'account-verify.example' || !h.hero) fail(`Check did not open the smart input: ${JSON.stringify(h)}`);
  await p.goBack();
  await p.waitForSelector('.ioc-summary');
  console.log('ok: Check opens the smart input, back keeps results', JSON.stringify(h));
  await p.unroute('**/*').catch(() => {});
  const domainErrs = d.errs.filter((e) => !/rdap|dns\.google|cloudflare-dns|certspotter|http 4/.test(e));
  if (domainErrs.length) fail(`desktop console errors:\n  ${domainErrs.join('\n  ')}`);
  const preCheck = d.foreign.filter((u) => !/rdap|dns\.google|cloudflare-dns|certspotter/.test(u));
  if (preCheck.length) fail(`unexpected network requests: ${preCheck.join(', ')}`);
  await d.ctx.close();

  // Extraction itself sends nothing anywhere
  {
    const n = await open({ viewport: { width: 1280, height: 800 } });
    await n.page.fill('#ioc-input', fixture('normal') + fixture('defanged'));
    await n.page.click('#ioc-go');
    await n.page.waitForTimeout(300);
    if (n.foreign.length) fail(`extraction made network requests: ${n.foreign.join(', ')}`);
    if (n.errs.length) fail(`console errors:\n  ${n.errs.join('\n  ')}`);
    console.log('ok: no network requests while extracting');
    await n.ctx.close();
  }

  // ---- mobile, light and dark ----
  for (const scheme of ['light', 'dark']) {
    const m = await open({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: scheme });
    await m.page.click('#ioc-sample');
    await m.page.waitForSelector('.ioc-summary');
    const mob = await m.page.evaluate(() => ({
      theme: document.documentElement.getAttribute('data-theme'),
      overflow: document.documentElement.scrollWidth > window.innerWidth,
      hero: getComputedStyle(document.querySelector('.hero')).display,
      small: [...document.querySelectorAll('#mod-ioc-extract button, #mod-ioc-extract a.chip, .chips .chip')].filter((e) => e.offsetParent && e.getBoundingClientRect().height < 44).map((e) => e.textContent.trim()),
    }));
    if (mob.theme !== scheme) fail(`mobile: theme ${mob.theme}, want ${scheme}`);
    if (mob.overflow) fail(`mobile ${scheme}: horizontal overflow`);
    if (mob.hero !== 'none') fail(`mobile ${scheme}: search hero should be hidden`);
    if (mob.small.length) fail(`mobile ${scheme}: tap targets <44px: ${mob.small.join(', ')}`);
    console.log(`ok: mobile ${scheme}`, JSON.stringify(mob));
    if (SHOTS) {
      await m.page.evaluate(() => document.querySelector('.ioc-summary').scrollIntoView({ block: 'start' }));
      await m.page.screenshot({ path: path.join(shotDir, `pr31-ioc-mobile-${scheme}.png`) });
    }
    if (m.errs.length) fail(`mobile ${scheme} console errors:\n  ${m.errs.join('\n  ')}`);
    await m.ctx.close();
  }

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
