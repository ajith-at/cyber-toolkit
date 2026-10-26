// End-to-end smoke test in headless Chrome. Usage:
//   python3 -m http.server 8811 &   then   node tests/smoke.js [baseUrl] [--shots]
// Needs the `playwright` npm package (any folder on NODE_PATH) and Chrome/Chromium.
const { chromium } = require('playwright');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const path = require('path');
const shotDir = path.join(__dirname, '..', 'screenshots');

const SAMPLES = [
  { q: '8.8.8.8', expect: ['ip-lookup', 'reputation'], text: ['Google'] },
  { q: '1.1.1.1', expect: ['ip-lookup', 'reputation'], text: ['APNIC'] },
  { q: '2606:4700:4700::1111', expect: ['ip-lookup', 'reputation'], text: ['Cloudflare'] },
  { q: 'example.com', expect: ['domain-lookup', 'dns-email', 'certificates', 'reputation'], text: ['Domain age'] },
  { q: 'google.com', expect: ['domain-lookup', 'dns-email', 'certificates', 'reputation'], text: ['MarkMonitor'] },
  { q: 'https://www.google.com/search?q=test', expect: ['domain-lookup', 'dns-email', 'certificates', 'reputation'], text: ['google.com'] },
  { q: 'security@google.com', expect: ['domain-lookup', 'dns-email', 'certificates', 'reputation'], text: ['Email security grade'] },
  { q: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', expect: ['reputation'], text: ['MalwareBazaar'] },
  { q: 'hxxps://example[.]com/login', expect: ['domain-lookup', 'reputation'], text: ['Defanged'] },
  { q: '192.168.1.1', expect: ['ip-lookup'], text: ['private'] },
];
const BAD = ['hello world', '256.1.1.1', 'abc123', 'javascript:alert(1)', '<img src=x onerror=alert(1)>'];

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };

  async function newPage(opts) {
    const ctx = await browser.newContext(opts);
    const page = await ctx.newPage();
    const errs = [];
    page.on('pageerror', (e) => errs.push(`pageerror: ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') errs.push(`console: ${m.text()}`); });
    page.on('response', (r) => { if (r.status() >= 400) errs.push(`http ${r.status()}: ${r.url()}`); });
    page.on('dialog', (d) => { errs.push(`dialog: ${d.message()}`); d.dismiss(); });
    return { ctx, page, errs };
  }

  async function check(page, q) {
    await page.fill('#q', q);
    await page.click('.search-go');
    await page.waitForFunction((q) => document.querySelector('#results').dataset.q === q, q);
    await page.waitForSelector('.summary');
    await page.waitForFunction(() => document.querySelectorAll('section.module').length > 0 && ![...document.querySelectorAll('section.module')].some((s) => s.getAttribute('aria-busy') === 'true'), null, { timeout: 45000 });
    return page.evaluate(() => ({
      mods: [...document.querySelectorAll('section.module')].map((s) => ({ id: s.id.replace('mod-', ''), status: s.querySelector('.section-status .pill')?.dataset.status, text: s.querySelector('.section-status').textContent, unavailable: /Lookup unavailable|could not be reached|unexpected problem/.test(s.textContent) })),
      overall: document.querySelector('.summary-status').textContent,
      body: document.querySelector('#results').innerText,
    }));
  }

  // ---- desktop light ----
  const d = await newPage({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  await d.page.goto(BASE);
  await d.page.evaluate(() => localStorage.clear());
  await d.page.reload();
  if (await d.page.getAttribute('html', 'data-theme') !== 'light') fail('default theme should follow OS (light)');

  // Podcast link: visible in the sidebar, same tab, points at the u51.org home page.
  {
    const pod = await d.page.evaluate(() => {
      const a = document.querySelector('.rail-links a[data-podcast-link]');
      return a && { href: a.getAttribute('href'), target: a.getAttribute('target'), visible: !!a.offsetParent, text: a.textContent.trim() };
    });
    if (!pod) fail('desktop: podcast link missing from sidebar');
    else {
      if (pod.href !== 'https://u51.org/') fail(`podcast link href ${pod.href}`);
      if (pod.target) fail('podcast link should open in the same tab');
      if (!pod.visible) fail('desktop: podcast link not visible');
      console.log('ok: podcast link in sidebar', JSON.stringify(pod));
    }
  }

  for (const s of SAMPLES) {
    const r = await check(d.page, s.q);
    const ids = r.mods.map((m) => m.id);
    for (const e of s.expect) if (!ids.includes(e)) fail(`${s.q}: missing module ${e}`);
    for (const m of r.mods) if (m.unavailable) fail(`${s.q}: ${m.id} unavailable`);
    for (const t of s.text) if (!r.body.toLowerCase().includes(t.toLowerCase())) fail(`${s.q}: expected text "${t}"`);
    if (SHOTS && s.q === '8.8.8.8') await d.page.screenshot({ path: path.join(shotDir, 'desktop-light-ip.png') });
    console.log(`ok: ${s.q.slice(0, 40).padEnd(40)} overall=${r.overall.padEnd(16)} ${r.mods.map((m) => `${m.id}:${m.text}`).join(' | ')}`);
    if (SHOTS && s.q === 'example.com') {
      await d.page.evaluate(() => document.querySelector('.main').scrollTo(0, 0));
      await d.page.screenshot({ path: path.join(shotDir, 'desktop-light-domain.png') });
      // The main column scrolls inside the shell, so grow the viewport to capture every section.
      const h = await d.page.evaluate(() => document.querySelector('.content').scrollHeight + 120);
      await d.page.setViewportSize({ width: 1440, height: h });
      await d.page.screenshot({ path: path.join(shotDir, 'desktop-light-domain-full.png') });
      await d.page.setViewportSize({ width: 1440, height: 900 });
    }
  }

  // Caution path: a mocked RDAP record for a 45-day-old domain must show the amber "New domain" pill.
  await d.page.route('https://rdap.org/domain/brandnew-example.com', (route) => route.fulfill({
    status: 200, headers: { 'access-control-allow-origin': '*', 'content-type': 'application/rdap+json' },
    body: JSON.stringify({ objectClassName: 'domain', ldhName: 'BRANDNEW-EXAMPLE.COM', status: ['active'],
      events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 45 * 864e5).toISOString() }, { eventAction: 'expiration', eventDate: new Date(Date.now() + 320 * 864e5).toISOString() }] }),
  }));
  {
    const r = await check(d.page, 'brandnew-example.com');
    const dl = r.mods.find((x) => x.id === 'domain-lookup');
    if (dl?.status !== 'caution') fail(`new domain should be caution, got ${dl?.status}`);
    if (!/New domain/.test(r.body)) fail('new domain pill missing');
    console.log('ok: <90-day domain shows caution', r.mods.map((m) => `${m.id}:${m.text}`).join(' | '));
    if (SHOTS) await d.page.screenshot({ path: path.join(shotDir, 'desktop-light-new-domain-caution.png') });
  }

  for (const b of BAD) {
    await d.page.fill('#q', b);
    await d.page.click('.search-go');
    await d.page.waitForFunction((q) => document.querySelector('#results').dataset.q === q.trim(), b);
    await d.page.waitForSelector('.callout');
    const t = await d.page.textContent('#results');
    if (!/Not something we can check/.test(t)) fail(`bad input not handled: ${b}`);
    if (await d.page.$('#results img')) fail('HTML injection rendered');
  }
  console.log('ok: bad input handled for', BAD.length, 'cases');

  // Extract indicators (standalone): the example yields every indicator group.
  {
    await d.page.goto(`${BASE}#tool=ioc-extract`);
    await d.page.click('#ioc-sample');
    const groups = await d.page.$$eval('[data-group]', (g) => g.map((x) => x.dataset.group).join(','));
    if (groups !== 'url,domain,ip,email,hash') fail(`ioc-extract groups: ${groups}`);
    console.log('ok: extract indicators example', groups);
    await d.page.goto(BASE);
  }

  // tool filter + not-applicable message
  await d.page.goto(`${BASE}#q=8.8.8.8&tool=dns-email`);
  await d.page.waitForSelector('.callout');
  if (!/does not apply/.test(await d.page.textContent('#results'))) fail('tool filter n/a message');
  await d.page.goto(`${BASE}#q=example.com&tool=domain-lookup`);
  await d.page.waitForFunction(() => document.querySelector('#mod-domain-lookup')?.getAttribute('aria-busy') === 'false', null, { timeout: 30000 });
  if ((await d.page.$$('section.module')).length !== 1) fail('tool filter should show one module');
  // The summary status covers only the selected tool, so it must finish (issue #27).
  try {
    await d.page.waitForFunction(() => !/Checking/.test(document.querySelector('.summary-status .pill')?.textContent || 'Checking'), null, { timeout: 10000 });
  } catch { fail(`tool filter: summary status stuck on "${await d.page.textContent('.summary-status .pill')}"`); }
  console.log('ok: tool filter');

  // ---- dark mode toggle persists ----
  await d.page.goto(`${BASE}#q=google.com`);
  await d.page.click('.switch-rail');
  if (await d.page.getAttribute('html', 'data-theme') !== 'dark') fail('toggle to dark');
  await d.page.reload();
  if (await d.page.getAttribute('html', 'data-theme') !== 'dark') fail('dark not persisted');
  await d.page.waitForFunction(() => document.querySelectorAll('section.module').length && ![...document.querySelectorAll('section.module')].some((s) => s.getAttribute('aria-busy') === 'true'), null, { timeout: 45000 });
  console.log('ok: dark mode persisted');
  if (SHOTS) { await d.page.waitForTimeout(400); await d.page.screenshot({ path: path.join(shotDir, "desktop-dark.png") }); }
  await d.page.click('.switch-rail');

  // horizontal overflow check
  const ov = await d.page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
  if (ov) fail('desktop horizontal overflow');

  if (d.errs.length) fail(`desktop console errors:\n  ${d.errs.join('\n  ')}`);
  await d.ctx.close();

  // ---- mobile ----
  const m = await newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'light' });
  await m.page.goto(BASE);
  await m.page.evaluate(() => localStorage.clear());
  await m.page.goto(`${BASE}#q=example.com`);
  await m.page.waitForFunction(() => document.querySelectorAll('section.module').length && ![...document.querySelectorAll('section.module')].some((s) => s.getAttribute('aria-busy') === 'true'), null, { timeout: 45000 });
  const mob = await m.page.evaluate(() => {
    const vis = (s) => { const e = document.querySelector(s); return !!e && getComputedStyle(e).display !== 'none'; };
    const small = [...document.querySelectorAll('.chips .chip, .search-go, .switch-compact, .podcast-compact, .chip-sample, .btn')].filter((e) => e.offsetParent && e.getBoundingClientRect().height < 44).map((e) => e.className);
    const pod = document.querySelector('.podcast-compact');
    return { rail: vis('.rail'), chips: vis('.chips'), compact: vis('.switch-compact'), podcast: vis('.podcast-compact') && pod.getAttribute('href') === 'https://u51.org/' && !pod.target, overflow: document.documentElement.scrollWidth > window.innerWidth, small };
  });
  if (mob.rail) fail('mobile: sidebar should hide');
  if (!mob.chips) fail('mobile: chips row missing');
  if (!mob.compact) fail('mobile: compact theme switch missing');
  if (!mob.podcast) fail('mobile: podcast link missing from toolbar');
  if (mob.overflow) fail('mobile: horizontal overflow');
  if (mob.small.length) fail(`mobile: tap targets <44px: ${[...new Set(mob.small)].join(', ')}`);
  console.log('ok: mobile layout', JSON.stringify(mob));
  // A phone's layout viewport grows to fit over-wide content (innerWidth grows with it), so also compare the page
  // width with the device width.
  const pageWidth = await m.page.evaluate(() => document.documentElement.scrollWidth);
  if (pageWidth > 390) fail(`mobile: page is ${pageWidth}px wide on a 390px screen`);
  if (SHOTS) {
    await m.page.waitForTimeout(300);
    await m.page.screenshot({ path: path.join(shotDir, 'mobile-light.png') });
    await m.page.click(".switch-compact");
    await m.page.waitForTimeout(500);
    await m.page.screenshot({ path: path.join(shotDir, 'mobile-dark.png') });
  }
  if (m.errs.length) fail(`mobile console errors:\n  ${m.errs.join('\n  ')}`);
  await m.ctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
