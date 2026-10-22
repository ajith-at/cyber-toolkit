// Summary status with a tool filter: it must cover only the tool on screen and reach a final status (issue #27).
// Usage: python3 -m http.server 8811 &   then   node tests/status-filter.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'docs', 'screenshots');

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
    return { ctx, page, errs };
  }

  const settled = (page) => page.waitForFunction(() => {
    const p = document.querySelector('.summary-status .pill');
    return p && !/Checking/.test(p.textContent) && ![...document.querySelectorAll('section.module')].some((s) => s.getAttribute('aria-busy') === 'true');
  }, null, { timeout: 45000 });
  const summary = (page) => page.evaluate(() => ({
    label: document.querySelector('.summary-status .label').textContent,
    status: document.querySelector('.summary-status .pill').dataset.status,
    text: document.querySelector('.summary-status .pill').textContent,
    sections: [...document.querySelectorAll('section.module')].map((s) => ({ id: s.id.replace('mod-', ''), status: s.querySelector('.section-status .pill')?.dataset.status })),
    chips: document.querySelectorAll('.summary-tools .chip').length,
  }));

  // ---- desktop light ----
  const d = await newPage({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  await d.page.goto(BASE);
  await d.page.evaluate(() => localStorage.clear());

  // Filtered view on a fresh load: only one tool runs, so the status must finish once it does.
  for (const [q, tool, label] of [['www.example.com', 'reputation', 'Reputation'], ['8.8.8.8', 'ip-lookup', 'IP lookup'], ['example.com', 'certificates', 'Certificates']]) {
    await d.page.goto(`${BASE}#q=${encodeURIComponent(q)}&tool=${tool}`);
    await d.page.reload();
    await d.page.waitForSelector('.summary');
    try { await settled(d.page); } catch { fail(`${q} / ${tool}: status never finished`); continue; }
    const s = await summary(d.page);
    if (s.sections.length !== 1 || s.sections[0].id !== tool) fail(`${q} / ${tool}: expected one section, got ${JSON.stringify(s.sections)}`);
    if (s.label !== label) fail(`${q} / ${tool}: label "${s.label}", expected "${label}"`);
    const expect = s.sections[0].status === 'unknown' ? 'unknown' : s.sections[0].status;
    if (s.status !== expect) fail(`${q} / ${tool}: summary ${s.status} does not match the tool's ${s.sections[0].status}`);
    if (q !== '8.8.8.8' && s.chips < 2) fail(`${q} / ${tool}: chips for all applicable tools should stay`);
    console.log(`ok: ${q} tool=${tool} -> ${s.label}: ${s.text} (${s.chips} chips)`);
    if (SHOTS && tool === 'reputation') await d.page.screenshot({ path: path.join(shotDir, 'pr27-filter-light.png') });
  }

  // Tool that does not apply: no endless "Checking".
  await d.page.goto(`${BASE}#q=8.8.8.8&tool=dns-email`);
  await d.page.waitForSelector('.callout');
  {
    const s = await summary(d.page);
    if (/Checking/.test(s.text)) fail(`n/a tool: status stuck on "${s.text}"`);
    console.log(`ok: tool that does not apply -> ${s.label}: ${s.text}`);
  }

  // All tools view unchanged: label "Overall", counts every tool, reaches a final status.
  await d.page.goto(`${BASE}#q=example.com`);
  await d.page.waitForSelector('.summary');
  {
    const first = await d.page.textContent('.summary-status .pill');
    try { await settled(d.page); } catch { fail('all tools: status never finished'); }
    const s = await summary(d.page);
    if (s.label !== 'Overall') fail(`all tools: label "${s.label}"`);
    if (s.sections.length < 4) fail(`all tools: ${s.sections.length} sections`);
    console.log(`ok: all tools -> ${s.label}: ${s.text} (first shown: ${first.trim()}, ${s.sections.length} tools)`);
  }

  // Switching from a filtered view back to all tools on the same input resumes counting from the cache.
  await d.page.goto(`${BASE}#q=google.com&tool=domain-lookup`);
  await settled(d.page);
  await d.page.click('.nav-item[data-tool="all"]');
  await d.page.waitForSelector('.summary');
  try { await settled(d.page); console.log(`ok: filtered -> all tools -> Overall: ${(await summary(d.page)).text}`); } catch { fail('filtered -> all: status never finished'); }

  // dark
  await d.page.click('.switch-rail');
  await d.page.goto(`${BASE}#q=${encodeURIComponent('www.example.com')}&tool=reputation`);
  await settled(d.page);
  if (await d.page.getAttribute('html', 'data-theme') !== 'dark') fail('dark mode');
  if (SHOTS) { await d.page.waitForTimeout(300); await d.page.screenshot({ path: path.join(shotDir, 'pr27-filter-dark.png') }); }
  console.log('ok: dark mode');
  await d.page.click('.switch-rail');
  if (d.errs.length) fail(`desktop console errors:\n  ${d.errs.join('\n  ')}`);
  await d.ctx.close();

  // ---- mobile ----
  const m = await newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'light' });
  await m.page.goto(BASE);
  await m.page.evaluate(() => localStorage.clear());
  await m.page.goto(`${BASE}#q=${encodeURIComponent('www.example.com')}&tool=reputation`);
  await m.page.waitForSelector('.summary');
  try { await settled(m.page); } catch { fail('mobile: status never finished'); }
  const ms = await summary(m.page);
  const width = await m.page.evaluate(() => document.documentElement.scrollWidth);
  if (width > 390) fail(`mobile: page is ${width}px wide`);
  console.log(`ok: mobile -> ${ms.label}: ${ms.text}, width ${width}`);
  if (SHOTS) {
    await m.page.screenshot({ path: path.join(shotDir, 'pr27-filter-mobile-light.png') });
    await m.page.click('.switch-compact');
    await m.page.waitForTimeout(400);
    await m.page.screenshot({ path: path.join(shotDir, 'pr27-filter-mobile-dark.png') });
  }
  if (m.errs.length) fail(`mobile console errors:\n  ${m.errs.join('\n  ')}`);
  await m.ctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
