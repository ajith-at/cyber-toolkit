// Email header analyser: parser tests on Gmail, Microsoft 365 and spoofed samples, UI, no-network check.
// Usage: python3 -m http.server 8811 &   then   node tests/email-headers.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'screenshots');
const fx = (n) => fs.readFileSync(path.join(__dirname, 'fixtures', `headers-${n}.txt`), 'utf8');
const FIX = { gmail: fx('gmail'), outlook: fx('outlook'), spoofed: fx('spoofed') };

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };
  const eq = (name, got, want) => { if (JSON.stringify(got) !== JSON.stringify(want)) fail(`${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`); };

  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', (e) => errs.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { if (m.type() === 'error') errs.push(`console: ${m.text()}`); });
  await page.goto(`${BASE}#tool=email-headers`);
  await page.waitForSelector('#eh-input');

  // ---- parser ----
  const r = await page.evaluate(async (FIX) => {
    const m = await import('./modules/email-headers.js');
    const sum = (a) => ({
      verdict: m.verdict(a), spf: a.auth.spf, dkim: a.auth.dkim, dmarc: a.auth.dmarc, origin: a.origin, transit: a.transit,
      hops: a.hops.map((h) => [h.from, h.fromIp, h.by, h.date && h.date.toISOString(), h.delay]),
      mismatches: a.mismatches.map((x) => `${x.header}:${x.domain}`), displaySpoof: a.displaySpoof, domains: a.domains, ips: a.ips, arc: a.arc.length,
    });
    const folded = m.parseHeaders('Subject: line one\r\n  continues here\r\n\tand here\r\nFrom: a@b.com\r\n\r\nbody text: not a header');
    return {
      gmail: sum(m.analyse(FIX.gmail)), outlook: sum(m.analyse(FIX.outlook)), spoofed: sum(m.analyse(FIX.spoofed)),
      folded,
      display: m.analyse('From: "support@bank.example (Support)" <x@evil.example>\nReply-To: x@evil.example').displaySpoof,
      sameOrg: m.analyse('From: a@mail.example.com.au\nReturn-Path: <bounce@bounces.example.com.au>').mismatches.length,
      skew: m.receivedChain(m.parseHeaders('Received: from b by c; Wed, 21 Oct 2026 10:00:00 +0000\nReceived: from a by b; Wed, 21 Oct 2026 10:00:30 +0000')).map((h) => h.delay),
      delays: [m.fmtDelay(5), m.fmtDelay(64), m.fmtDelay(3725), m.fmtDelay(-3)],
      none: m.analyse(''),
    };
  }, FIX);

  // Gmail (github.com notification)
  eq('gmail verdict', r.gmail.verdict, 'low');
  eq('gmail spf/dkim/dmarc', [r.gmail.spf, r.gmail.dkim, r.gmail.dmarc], ['pass', 'pass', 'pass']);
  eq('gmail origin', r.gmail.origin, '192.30.252.201');
  eq('gmail hop order', r.gmail.hops.map((h) => h[2]), ['smtp.github.com', 'mx.google.com', '2002:a05:7300:5b0e:b0:1a2:3c4d:5e6f']);
  eq('gmail delays', r.gmail.hops.map((h) => h[4]), [null, 2, 1]);
  eq('gmail private first hop', r.gmail.hops[0][1], '10.56.112.27');
  eq('gmail ips', r.gmail.ips, ['192.30.252.201']);
  eq('gmail domains', r.gmail.domains, ['github.com']);
  eq('gmail mismatches', r.gmail.mismatches, []);
  eq('gmail arc', r.gmail.arc, 1);
  // Microsoft 365
  eq('outlook verdict', r.outlook.verdict, 'low');
  eq('outlook spf/dkim/dmarc', [r.outlook.spf, r.outlook.dkim, r.outlook.dmarc], ['pass', 'pass', 'pass']);
  eq('outlook origin (X-Originating-IP)', r.outlook.origin, '2001:8003:1c2b:4d00:89ab:cdef:1234:5678');
  eq('outlook hops', r.outlook.hops.length, 5);
  eq('outlook first hop', r.outlook.hops[0][0], 'KL1PR0601MB4321.apcprd06.prod.outlook.com');
  eq('outlook edge hop IP', r.outlook.hops[1][1], '40.107.215.88');
  eq('outlook folded date', r.outlook.hops[3][3], '2026-10-21T02:30:11.000Z');
  eq('outlook transit', r.outlook.transit, 5);
  eq('outlook domains', r.outlook.domains, ['contoso.com.au']);
  // Spoofed
  eq('spoofed verdict', r.spoofed.verdict, 'high');
  eq('spoofed spf/dkim/dmarc', [r.spoofed.spf, r.spoofed.dkim, r.spoofed.dmarc], ['softfail', 'none', 'fail']);
  eq('spoofed origin', r.spoofed.origin, '102.89.32.11');
  eq('spoofed mismatches', r.spoofed.mismatches, ['Reply-To:protonmail.com', 'Return-Path:paypa1-secure.top']);
  eq('spoofed delays', r.spoofed.hops.map((h) => h[4]), [null, 191, 1]);
  eq('spoofed ips', r.spoofed.ips, ['102.89.32.11', '45.33.32.156']);
  // edge cases
  eq('folded header', r.folded, [{ name: 'Subject', value: 'line one continues here and here' }, { name: 'From', value: 'a@b.com' }]);
  eq('display-name spoof', r.display, 'support@bank.example');
  eq('same organisation is not a mismatch', r.sameOrg, 0);
  eq('negative delay (clock skew)', r.skew, [null, -30]);
  eq('delay format', r.delays, ['+5 s', '+1 min 4 s', '+1 h 2 min', '−3 s']);
  eq('empty input', r.none, null);
  console.log('ok: parser (Gmail, Microsoft 365, spoofed, folding, mismatches, delays)');

  // ---- UI, with no network requests while analysing ----
  const requests = [];
  page.on('request', (q) => requests.push(q.url()));
  await page.fill('#eh-input', FIX.gmail);
  await page.click('#eh-go');
  await page.waitForSelector('[data-auth="dmarc"]');
  eq('UI gmail pills', await page.$$eval('[data-auth] .pill', (p) => p.map((x) => x.dataset.status)), ['low', 'low', 'low']);
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'email-headers-gmail.png') });
  await page.fill('#eh-input', FIX.outlook);
  await page.click('#eh-go');
  await page.waitForFunction(() => /5 hops/.test(document.querySelector('.eh-out').textContent));
  await page.fill('#eh-input', FIX.spoofed);
  await page.click('#eh-go');
  await page.waitForFunction(() => /Authentication failed/.test(document.querySelector('.eh-out').textContent));
  eq('UI spoofed pills', await page.$$eval('[data-auth] .pill', (p) => p.map((x) => x.dataset.status)), ['caution', 'unknown', 'high']);
  eq('UI mismatch pills', await page.$$eval('.addr-cell .pill[data-status="caution"]', (p) => p.length), 2);
  if (requests.length) fail(`network requests while analysing:\n  ${requests.join('\n  ')}`);
  else console.log('ok: UI pills and mismatches; no network requests while analysing');
  if (SHOTS) {
    const h = await page.evaluate(() => document.querySelector('.content').scrollHeight + 140);
    await page.setViewportSize({ width: 1440, height: h });
    await page.screenshot({ path: path.join(shotDir, 'email-headers-spoofed.png') });
    await page.setViewportSize({ width: 1440, height: 900 });
  }

  // not-headers input
  await page.fill('#eh-input', 'hello there, this is just a sentence');
  await page.click('#eh-go');
  if (!/No headers found|Not recognised/.test(await page.textContent('.eh-out'))) fail('non-header input message');

  // extracted IP opens IP lookup; input kept when coming back
  await page.click('#eh-sample');
  await page.click('.eh-out button:has-text("IP lookup")');
  await page.waitForSelector('#mod-ip-lookup');
  if (!/q=102\.89\.32\.11/.test(page.url()) || !/tool=ip-lookup/.test(page.url())) fail(`IP hand-off url ${page.url()}`);
  await page.goBack();
  await page.waitForSelector('#eh-input');
  if (!(await page.inputValue('#eh-input')).includes('paypa1-secure.top')) fail('input not kept after switching tools');
  console.log('ok: IP hand-off to IP lookup, input kept');

  // dark
  await page.click('.switch-rail');
  await page.waitForTimeout(200);
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'email-headers-dark.png') });
  await page.click('.switch-rail');
  if (await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth)) fail('desktop horizontal overflow');
  if (errs.length) fail(`desktop console errors:\n  ${errs.join('\n  ')}`);
  await ctx.close();

  // ---- mobile ----
  const mctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'light' });
  const m = await mctx.newPage();
  const merrs = [];
  m.on('pageerror', (e) => merrs.push(`pageerror: ${e.message}`));
  m.on('console', (x) => { if (x.type() === 'error') merrs.push(`console: ${x.text()}`); });
  await m.goto(`${BASE}#tool=email-headers`);
  await m.click('#eh-sample');
  await m.waitForSelector('[data-auth="dmarc"]');
  const mob = await m.evaluate(() => ({
    overflow: document.documentElement.scrollWidth > 390, // innerWidth grows with over-wide content on mobile
    small: [...document.querySelectorAll('#mod-email-headers button, .chips .chip')].filter((e) => e.offsetParent && e.getBoundingClientRect().height < 44).map((e) => e.textContent.trim()),
  }));
  if (mob.overflow) fail('mobile: horizontal overflow');
  if (mob.small.length) fail(`mobile: tap targets <44px: ${mob.small.join(', ')}`);
  console.log('ok: mobile layout', JSON.stringify(mob));
  if (SHOTS) await m.screenshot({ path: path.join(shotDir, 'email-headers-mobile.png'), fullPage: true });
  if (merrs.length) fail(`mobile console errors:\n  ${merrs.join('\n  ')}`);
  await mctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
