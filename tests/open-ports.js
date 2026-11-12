// Open ports & CVEs (Shodan InternetDB): mocked found / nothing seen / error, a live check, IPv6 and private (no request),
// light, dark and mobile. Usage: python3 -m http.server 8811 &  then  node tests/open-ports.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'screenshots');
const API = 'https://internetdb.shodan.io/**';
const EPSS = 'https://api.first.org/data/v1/epss**';
const epssBody = (hot) => JSON.stringify({ data: FOUND.vulns.map((c, i) => ({ cve: c, epss: String(hot && i === 7 ? 0.9731 : (i + 1) / 1000), percentile: '0.5', date: '2026-11-12' })) });
const CORS = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
const FOUND = { ip: '45.33.32.156', ports: [22, 80, 123, 9929], hostnames: ['scanme.nmap.org'], tags: ['cloud', 'eol-product'],
  cpes: ['cpe:/a:apache:http_server:2.4.7', 'cpe:/a:openbsd:openssh:6.6.1p1'],
  vulns: Array.from({ length: 30 }, (_, i) => `CVE-20${10 + (i % 15)}-${1000 + i}`) };

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };

  async function open(opts) {
    const ctx = await browser.newContext(opts);
    const page = await ctx.newPage();
    const errs = []; const reqs = [];
    page.on('pageerror', (e) => errs.push(e.message));
    page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
    page.on('request', (r) => { if (r.url().startsWith('https://internetdb.shodan.io/') || r.url().startsWith('https://api.first.org/')) reqs.push(r.url()); });
    return { ctx, page, errs, reqs };
  }
  async function look(page, q) {
    await page.goto(`${BASE}#q=${encodeURIComponent(q)}&tool=open-ports`);
    await page.waitForSelector('#mod-open-ports');
    await page.waitForFunction(() => document.querySelector('#mod-open-ports').getAttribute('aria-busy') !== 'true', null, { timeout: 30000 });
    return page.evaluate(() => {
      const s = document.querySelector('#mod-open-ports');
      return { status: s.querySelector('.section-status .pill')?.dataset.status, pill: s.querySelector('.section-status').textContent.trim(), text: s.innerText, first: s.querySelector('.cve-list a')?.textContent.trim(), cves: s.querySelectorAll('.cve-list a').length, ext: [...s.querySelectorAll('.cve-list a')].every((a) => a.target === '_blank' && /noopener/.test(a.rel) && a.href.startsWith('https://nvd.nist.gov/vuln/detail/CVE-')) };
    });
  }

  const d = await open({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  let respond = () => ({ status: 200, headers: CORS, body: JSON.stringify(FOUND) });
  await d.page.route(API, (route) => route.fulfill(respond()));
  let epss = () => ({ status: 200, headers: CORS, body: epssBody(false) });
  await d.page.route(EPSS, (route) => route.fulfill(epss()));

  let r = await look(d.page, '45.33.32.156');
  if (r.status !== 'caution' || !/30 CVEs/.test(r.pill)) fail(`found: status ${r.status} "${r.pill}"`);
  for (const [k, re] of [["first", /^CVE-2024-1029/.test(r.first)], ["label", /Known CVEs \(by EPSS\)/i.test(r.text)], ["pct", /3\.00%/.test(r.text)], ["date", /scored 2026-11-12/.test(r.text)]]) if (!re) fail(`EPSS low: ${k}`);
  console.log('ok: CVEs ranked by EPSS (low scores keep Caution)', r.first);

  epss = () => ({ status: 200, headers: CORS, body: epssBody(true) });
  r = await look(d.page, '203.0.114.21');
  if (r.status !== 'high' || !/EPSS 97\.3%/.test(r.pill) || !/^CVE-2017-1007/.test(r.first) || !/Likely target/.test(r.text)) fail(`EPSS high: ${r.status} "${r.pill}" first ${r.first}`);
  if (SHOTS) await d.page.screenshot({ path: path.join(shotDir, 'open-ports-epss-light.png'), fullPage: true });
  console.log('ok: EPSS >= 50% raises status to High', r.pill);

  epss = () => ({ status: 503, headers: CORS, body: 'busy' });
  r = await look(d.page, '203.0.114.22');
  if (r.status !== 'caution' || !/^CVE-2024-1029/.test(r.first) || !/EPSS ranking was unavailable/.test(r.text) || r.cves !== 30) fail(`EPSS down: ${r.status} first ${r.first}`);
  console.log('ok: EPSS outage falls back to newest-first list');
  epss = () => ({ status: 200, headers: CORS, body: epssBody(true) });
  for (const t of ['9929', 'scanme.nmap.org', 'eol-product', 'apache:http_server', 'Show 6 more']) if (!r.text.includes(t)) fail(`found: missing "${t}"`);
  if (r.cves !== 30 || !r.ext) fail(`found: ${r.cves} CVE links, safe external links ${r.ext}`);
  if (SHOTS) await d.page.screenshot({ path: path.join(shotDir, 'open-ports-light.png'), fullPage: true });
  console.log('ok: mocked record shows ports, software, tags, hostnames and NVD-linked CVEs', r.pill);

  // Markdown export carries the facts
  const exp = await d.page.evaluate(() => document.querySelector('#results').innerText);
  if (!/Open ports/.test(exp)) fail('export / results missing Open ports');

  respond = () => ({ status: 404, headers: CORS, body: '{"detail":"No information available"}' });
  r = await look(d.page, '203.0.114.9');
  if (r.status !== 'unknown' || !/Nothing seen/.test(r.text)) fail(`404: ${r.status} ${r.pill}`);
  console.log('ok: 404 is "Nothing seen", not an error');

  respond = () => ({ status: 503, headers: CORS, body: 'busy' });
  r = await look(d.page, '203.0.114.10');
  if (!/Lookup unavailable/.test(r.text) || !/HTTP 503/.test(r.text)) fail(`503: ${r.text.slice(0, 120)}`);
  console.log('ok: HTTP errors show "Lookup unavailable" with a Shodan link');

  const before = d.reqs.length;
  r = await look(d.page, '2606:4700:4700::1111');
  if (!/only covers IPv4/.test(r.text)) fail('IPv6 message');
  r = await look(d.page, '192.168.1.1');
  if (!/private/.test(r.text)) fail('private message');
  if (d.reqs.length !== before) fail(`IPv6/private made ${d.reqs.length - before} request(s)`);
  console.log('ok: IPv6 and private addresses are "Not available" with no request');

  // live
  await d.page.unroute(API);
  await d.page.unroute(EPSS);
  r = await look(d.page, '8.8.8.8');
  if (!/53/.test(r.text) || /Lookup unavailable/.test(r.text)) fail(`live 8.8.8.8: ${r.pill} ${r.text.slice(0, 160)}`);
  else console.log('ok: live InternetDB for 8.8.8.8', r.pill);

  // dark
  await d.page.route(API, (route) => route.fulfill({ status: 200, headers: CORS, body: JSON.stringify(FOUND) }));
  await d.page.route(EPSS, (route) => route.fulfill({ status: 200, headers: CORS, body: epssBody(true) }));
  await look(d.page, '45.33.32.156');
  await d.page.click('.switch-rail');
  if (await d.page.getAttribute('html', 'data-theme') !== 'dark') fail('dark mode did not switch');
  if (SHOTS) await d.page.screenshot({ path: path.join(shotDir, 'open-ports-dark.png'), fullPage: true });
  // The deliberate 404 and 503 responses are logged by the browser; those are expected.
  const errs = d.errs.filter((e) => !/status of (404|503)/.test(e));
  if (errs.length) fail(`desktop console errors:\n  ${errs.join('\n  ')}`);
  await d.ctx.close();

  for (const scheme of ['light', 'dark']) {
    const m = await open({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: scheme });
    await m.page.route(API, (route) => route.fulfill({ status: 200, headers: CORS, body: JSON.stringify(FOUND) }));
    await m.page.route(EPSS, (route) => route.fulfill({ status: 200, headers: CORS, body: epssBody(true) }));
    await look(m.page, '45.33.32.156');
    const w = await m.page.evaluate(() => document.documentElement.scrollWidth);
    if (w > 390) fail(`mobile ${scheme}: page is ${w}px wide`);
    if (SHOTS) await m.page.screenshot({ path: path.join(shotDir, `open-ports-mobile-${scheme}.png`), fullPage: true });
    if (m.errs.length) fail(`mobile ${scheme} console errors:\n  ${m.errs.join('\n  ')}`);
    console.log(`ok: mobile ${scheme} layout (${w}px)`);
    await m.ctx.close();
  }

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
