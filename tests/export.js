// Copy as Markdown / Download JSON (issue #13): unit checks on js/export.js, then the summary-card buttons in
// headless Chrome (clipboard text, downloaded file, screen-reader announcement), light, dark and mobile, no console errors.
// Usage: python3 -m http.server 8811 &   then   node tests/export.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'docs', 'screenshots');

(async () => {
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };

  // ---- unit: pure export functions ----
  const ex = await import(path.join(__dirname, '..', 'js', 'export.js'));
  const at = new Date('2026-10-30T00:00:00Z');
  const sample = {
    input: 'evil|site.example', type: 'Domain', overall: { status: 'caution', text: null }, at,
    results: [
      { id: 'a', name: 'Domain lookup', status: 'caution', statusText: 'New domain', facts: [['Registrar', 'Pipe | Co'], ['Nameservers', ['ns1.x', 'ns2.x']], ['Empty', null], ['Blank', []]], raw: { big: true } },
      { id: 'b', name: 'Certificates', status: null, facts: undefined },
    ],
  };
  const md = ex.toMarkdown(sample);
  if (!md.includes('## Cyber Toolkit: evil\\|site.example')) fail('markdown: heading should escape the pipe');
  if (!md.includes('| Registrar | `Pipe \\| Co` |')) fail('markdown: table value should be inline code and escape the pipe');
  if (!md.includes('| Nameservers | `ns1.x, ns2.x` |')) fail('markdown: arrays should become a comma list inside code');
  if (md.includes('Empty') || md.includes('Blank')) fail('markdown: empty facts should be dropped');
  if (!md.includes('Status: Caution (New domain)')) fail('markdown: status line');
  if (!md.includes('Status: Still checking')) fail('markdown: pending tool');
  if (!md.includes('- **Checked:** 2026-10-30T00:00:00Z')) fail('markdown: timestamp');
  const js = JSON.parse(ex.toJson(sample));
  if (js.input !== 'evil|site.example' || js.checkedAt !== '2026-10-30T00:00:00.000Z' || js.overall.status !== 'caution') fail('json: header fields');
  if (js.results[0].facts.Nameservers !== 'ns1.x, ns2.x' || 'Empty' in js.results[0].facts) fail('json: facts');
  if ('raw' in js.results[0]) fail('json: raw should be left out by default');
  if (!JSON.parse(ex.toJson({ ...sample, includeRaw: true })).results[0].raw) fail('json: includeRaw');
  if (js.results[1].status !== 'checking') fail('json: pending tool status');
  if (ex.fileName('https://Example.com/a b?c', at) !== 'cyber-toolkit-https-example.com-a-b-c-2026-10-30.json') fail(`fileName: ${ex.fileName('https://Example.com/a b?c', at)}`);
  console.log(fails ? 'unit checks had failures' : 'ok: unit checks');

  // ---- browser ----
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  async function newPage(opts) {
    const ctx = await browser.newContext({ acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'], ...opts });
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
  const clip = (page) => page.evaluate(() => navigator.clipboard.readText());

  const d = await newPage({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  await d.page.goto(BASE);
  await d.page.evaluate(() => localStorage.clear());

  const CASES = [
    { q: 'example.com', tools: ['Domain lookup', 'DNS & email security', 'Certificates', 'Reputation'], facts: ['Registrar', 'Email security grade', 'VirusTotal (domain)'] },
    { q: '8.8.8.8', tools: ['IP lookup', 'Reputation'], facts: ['Owner', 'Google', 'AbuseIPDB (ip address)'] },
    { q: '192.168.1.1', tools: ['IP lookup', 'Reputation'], facts: ['Scope', 'private'] },
    { q: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', tools: ['Reputation'], facts: ['MalwareBazaar'] },
  ];
  for (const c of CASES) {
    await d.page.goto(`${BASE}#q=${encodeURIComponent(c.q)}`);
    await d.page.waitForSelector('.summary-export');
    try { await settled(d.page); } catch { fail(`${c.q}: never settled`); continue; }
    await d.page.click('.summary-export button[aria-label="Copy results as Markdown"]');
    await d.page.waitForTimeout(200);
    const text = await clip(d.page);
    for (const t of c.tools) if (!text.includes(`### ${t.replace(/&/g, '&')}`)) fail(`${c.q}: markdown missing section ${t}`);
    for (const f of c.facts) if (!text.includes(f)) fail(`${c.q}: markdown missing "${f}"`);
    if (!/\| Fact \| Value \|/.test(text)) fail(`${c.q}: markdown has no table`);
    const btn = (await d.page.textContent('.summary-export button[aria-label="Copy results as Markdown"]')).trim();
    if (btn !== 'Copied') fail(`${c.q}: button says "${btn}"`);
    await d.page.waitForTimeout(150);
    const live = await d.page.evaluate(() => [...document.querySelectorAll('[aria-live="polite"]')].map((n) => n.textContent).join('|'));
    if (!live.includes('Copied to clipboard')) fail(`${c.q}: no screen-reader announcement (${live})`);

    const [dl] = await Promise.all([d.page.waitForEvent('download'), d.page.click('.summary-export button[aria-label="Download results as JSON"]')]);
    const file = await dl.path();
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!/^cyber-toolkit-.*\d{4}-\d{2}-\d{2}\.json$/.test(dl.suggestedFilename())) fail(`${c.q}: file name ${dl.suggestedFilename()}`);
    if (j.input !== c.q || !j.checkedAt || !j.overall?.status) fail(`${c.q}: json header ${JSON.stringify({ input: j.input, overall: j.overall })}`);
    if (j.results.map((r) => r.name).join() !== c.tools.join()) fail(`${c.q}: json tools ${j.results.map((r) => r.name)}`);
    if (j.results.some((r) => r.status === 'checking' || !Object.keys(r.facts).length)) fail(`${c.q}: json has a tool with no facts`);
    console.log(`ok: ${c.q} -> markdown ${text.split('\n').length} lines, json ${j.results.length} tools (${j.overall.status})`);
    if (SHOTS && c.q === 'example.com') {
      await d.page.screenshot({ path: path.join(shotDir, 'pr13-export-light.png') });
      fs.writeFileSync(path.join(shotDir, 'pr13-example.md'), text);
    }
  }

  // Filtered view exports only the tool on screen.
  await d.page.goto(`${BASE}#q=example.com&tool=dns-email`);
  await settled(d.page);
  await d.page.click('.summary-export button[aria-label="Copy results as Markdown"]');
  await d.page.waitForTimeout(200);
  { const t = await clip(d.page); if (!t.includes('### DNS & email security') || t.includes('### Reputation')) fail('filtered: should export only the shown tool'); else console.log('ok: filtered view exports only the shown tool'); }

  // A tool that does not apply: no export buttons.
  await d.page.goto(`${BASE}#q=8.8.8.8&tool=dns-email`);
  await d.page.waitForSelector('.summary');
  if (await d.page.$('.summary-export')) fail('n/a tool: export row should be hidden'); else console.log('ok: no export row when no tool applies');

  // dark
  await d.page.click('.switch-rail');
  await d.page.goto(`${BASE}#q=example.com`);
  await settled(d.page);
  if (await d.page.getAttribute('html', 'data-theme') !== 'dark') fail('dark mode');
  if (SHOTS) { await d.page.waitForTimeout(300); await d.page.screenshot({ path: path.join(shotDir, 'pr13-export-dark.png') }); }
  console.log('ok: dark mode');
  await d.page.click('.switch-rail');
  if (d.errs.length) fail(`desktop console errors:\n  ${d.errs.join('\n  ')}`);
  await d.ctx.close();

  // mobile
  const m = await newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: 'light' });
  await m.page.goto(BASE);
  await m.page.evaluate(() => localStorage.clear());
  await m.page.goto(`${BASE}#q=8.8.8.8`);
  await m.page.waitForSelector('.summary-export');
  try { await settled(m.page); } catch { fail('mobile: never settled'); }
  const sizes = await m.page.$$eval('.summary-export button', (bs) => bs.map((b) => b.getBoundingClientRect().height));
  if (sizes.some((h) => h < 44)) fail(`mobile: buttons too small for touch (${sizes})`);
  const width = await m.page.evaluate(() => document.documentElement.scrollWidth);
  if (width > 390) fail(`mobile: page is ${width}px wide`);
  console.log(`ok: mobile, buttons ${sizes.join('/')}px tall, width ${width}`);
  if (SHOTS) {
    await m.page.screenshot({ path: path.join(shotDir, 'pr13-export-mobile-light.png') });
    await m.page.click('.switch-compact');
    await m.page.waitForTimeout(400);
    await m.page.screenshot({ path: path.join(shotDir, 'pr13-export-mobile-dark.png') });
  }
  if (m.errs.length) fail(`mobile console errors:\n  ${m.errs.join('\n  ')}`);
  await m.ctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
