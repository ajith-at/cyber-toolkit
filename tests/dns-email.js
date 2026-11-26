// DNS & email security, newer mail protections (MTA-STS, TLS-RPT, BIMI, DKIM selectors): mocked DoH answers for a
// well-configured and a bare domain, a partial DoH outage, export, live google.com / example.com, light, dark and mobile.
// Usage: python3 -m http.server 8811 &  then  node tests/dns-email.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'docs', 'screenshots');
const CORS = { 'access-control-allow-origin': '*', 'content-type': 'application/json' };
const TYPE = { A: 1, NS: 2, MX: 15, TXT: 16, AAAA: 28 };

// A fully configured mock domain plus a bare one (no mail protections at all).
const ZONE = {
  'good.test': { A: ['192.0.2.10'], MX: ['10 mx.good.test.'], NS: ['ns1.good.test.'], TXT: ['v=spf1 include:_spf.good.test -all'] },
  '_dmarc.good.test': { TXT: ['v=DMARC1; p=reject; rua=mailto:d@good.test'] },
  '_mta-sts.good.test': { TXT: ['v=STSv1; id=20261127T000000;'] },
  '_smtp._tls.good.test': { TXT: ['v=TLSRPTv1; rua=mailto:tls@good.test'] },
  'default._bimi.good.test': { TXT: ['v=BIMI1; l=https://good.test/logo.svg; a=https://good.test/vmc.pem'] },
  'selector1._domainkey.good.test': { TXT: ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA'] },
  'k1._domainkey.good.test': { TXT: ['v=DKIM1; p='] },
  'bare.test': { A: ['192.0.2.20'], MX: ['10 mx.bare.test.'], TXT: ['v=spf1 ~all'] },
  'flaky.test': { A: ['192.0.2.30'], TXT: ['v=spf1 -all'] },
  '_dmarc.flaky.test': { TXT: ['v=DMARC1; p=quarantine'] },
  '_smtp._tls.flaky.test': { TXT: ['v=TLSRPTv1; rua=mailto:x@flaky.test'] },
};
const FAIL = new Set(['_mta-sts.flaky.test', 'google._domainkey.flaky.test']); // simulate resolver failures (both providers)

function answer(url) {
  const u = new URL(url);
  const name = u.searchParams.get('name');
  const type = u.searchParams.get('type');
  if (FAIL.has(name)) return { status: 503, headers: CORS, body: 'busy' };
  const rec = ZONE[name];
  const data = (rec && rec[type]) || [];
  const zoneKnown = rec || Object.keys(ZONE).some((k) => k.endsWith(`.${name}`));
  return { status: 200, headers: CORS, body: JSON.stringify({ Status: zoneKnown ? 0 : 3, AD: false,
    Answer: data.map((d) => ({ name, type: TYPE[type], TTL: 300, data: type === 'TXT' ? `"${d}"` : d })) }) };
}

// The app shell scrolls inside .main, so grow the viewport to the content height for a full-length shot.
async function tallShot(page, file, width) {
  await page.waitForTimeout(300);
  const h = await page.evaluate(() => Math.max(document.querySelector('.main')?.scrollHeight || 0, document.body.scrollHeight));
  const vp = page.viewportSize();
  await page.setViewportSize({ width: width || vp.width, height: Math.max(vp.height, h + 40) });
  await page.screenshot({ path: path.join(shotDir, file), fullPage: true });
  await page.setViewportSize(vp);
}

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };

  async function open(opts, mock = true) {
    const ctx = await browser.newContext(opts);
    const page = await ctx.newPage();
    const errs = []; const dns = [];
    page.on('pageerror', (e) => errs.push(e.message));
    page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
    page.on('request', (r) => { if (/dns\.google|cloudflare-dns/.test(r.url())) dns.push(new URL(r.url()).searchParams.get('name')); });
    if (mock) {
      for (const pat of ['https://dns.google/resolve**', 'https://cloudflare-dns.com/dns-query**']) await page.route(pat, (route) => route.fulfill(answer(route.request().url())));
      await page.route(/^https:\/\/(rdap\.org|crt\.sh|api\.certspotter|.*urlhaus|.*threatfox).*/, (route) => route.abort());
    }
    return { ctx, page, errs, dns };
  }
  async function look(page, q) {
    await page.goto(`${BASE}#q=${encodeURIComponent(q)}&tool=dns-email`);
    await page.waitForSelector('#mod-dns-email');
    await page.waitForFunction(() => document.querySelector('#mod-dns-email').getAttribute('aria-busy') !== 'true', null, { timeout: 45000 });
    return page.evaluate(() => {
      const s = document.querySelector('#mod-dns-email');
      const rows = {};
      const card = [...s.querySelectorAll('.card-title')].find((h) => h.textContent === 'Newer mail protections')?.closest('article');
      for (const tr of card ? card.querySelectorAll('tbody tr') : []) rows[tr.cells[0].textContent] = { status: tr.cells[1].querySelector('.pill')?.dataset.status, word: tr.cells[1].querySelector('.pill')?.textContent.trim(), text: tr.cells[1].textContent };
      const links = card ? [...card.querySelectorAll('a')].map((a) => ({ href: a.href, safe: a.target === '_blank' && /noopener/.test(a.rel) })) : [];
      return { pill: s.querySelector('.section-status').textContent.trim(), grade: s.querySelector('.fact .figure')?.textContent, rows, links, text: s.innerText, hasCard: !!card };
    });
  }

  const d = await open({ viewport: { width: 1440, height: 900 }, colorScheme: 'light', acceptDownloads: true, permissions: ['clipboard-read', 'clipboard-write'] });
  let r = await look(d.page, 'good.test');
  if (r.grade !== 'A+') fail(`good: grade ${r.grade}`);
  for (const [k, w] of [['MTA-STS', 'Present'], ['TLS-RPT', 'Present'], ['BIMI', 'Present'], ['DKIM (best effort)', 'Found']]) if (r.rows[k]?.word !== w || r.rows[k]?.status !== 'low') fail(`good: ${k} ${JSON.stringify(r.rows[k])}`);
  if (!/selector1\._domainkey · rsa key/.test(r.rows['DKIM (best effort)']?.text) || !/k1\._domainkey · revoked/.test(r.rows['DKIM (best effort)']?.text)) fail(`good: DKIM detail ${r.rows['DKIM (best effort)']?.text}`);
  if (!r.links.some((l) => l.href === 'https://mta-sts.good.test/.well-known/mta-sts.txt') || !r.links.every((l) => l.safe)) fail(`good: links ${JSON.stringify(r.links)}`);
  const dkimQ = d.dns.filter((n) => /\._domainkey\.good\.test$/.test(n));
  if (new Set(dkimQ).size > 8) fail(`good: ${new Set(dkimQ).size} DKIM selectors queried (cap is 8)`);
  if (!/best effort/i.test(r.text)) fail('good: DKIM not labelled best effort');
  if (SHOTS) await tallShot(d.page, 'email-security-light.png');
  console.log('ok: well-configured domain shows all four Present/Found, grade', r.grade, `(${new Set(dkimQ).size} DKIM lookups)`);

  // Export includes the new facts
  await d.page.click('.summary-export button[aria-label="Copy results as Markdown"]');
  await d.page.waitForTimeout(300);
  const clip = await d.page.evaluate(() => navigator.clipboard.readText());
  for (const t of ['| MTA-STS | `Present: v=STSv1', '| TLS-RPT | `Present', '| BIMI | `Present', '| DKIM (common selectors) | `selector1 (rsa)']) if (!clip.includes(t)) fail(`markdown missing "${t}" in:\n${clip}`);
  const [dl] = await Promise.all([d.page.waitForEvent('download'), d.page.click('.summary-export button[aria-label="Download results as JSON"]')]);
  const json = JSON.parse(require('fs').readFileSync(await dl.path(), 'utf8'));
  const de = json.results.find((x) => x.id === 'dns-email');
  if (!de || !/^Present/.test(de.facts['MTA-STS']) || !/^Present/.test(de.facts['TLS-RPT']) || !/selector1 \(rsa\)/.test(de.facts['DKIM (common selectors)'])) fail(`json facts ${JSON.stringify(de?.facts)}`);
  console.log('ok: Copy as Markdown and Download JSON include MTA-STS, TLS-RPT, BIMI and DKIM');

  r = await look(d.page, 'bare.test');
  if (r.grade !== 'C') fail(`bare: grade ${r.grade} (missing extras must not lower it)`);
  for (const [k, w] of [['MTA-STS', 'Missing'], ['TLS-RPT', 'Missing'], ['BIMI', 'Missing'], ['DKIM (best effort)', 'Not found']]) if (r.rows[k]?.word !== w || r.rows[k]?.status !== 'unknown') fail(`bare: ${k} ${JSON.stringify(r.rows[k])}`);
  if (!/does not mean DKIM is off/.test(r.rows['DKIM (best effort)']?.text)) fail('bare: DKIM caveat missing');
  console.log('ok: bare domain shows Missing / Not found in slate, grade unchanged', r.grade);

  r = await look(d.page, 'flaky.test');
  if (r.rows['MTA-STS']?.word !== 'Not checked' || r.rows['TLS-RPT']?.word !== 'Present' || !/1 of 8 lookups failed/.test(r.rows['DKIM (best effort)']?.text)) fail(`flaky: ${JSON.stringify(r.rows)}`);
  if (r.grade !== 'A') fail(`flaky: grade ${r.grade}`);
  console.log('ok: a failed lookup shows "Not checked" and the rest still render');

  await d.page.click('.switch-rail');
  if (await d.page.getAttribute('html', 'data-theme') !== 'dark') fail('dark mode did not switch');
  r = await look(d.page, 'good.test');
  if (SHOTS) await tallShot(d.page, 'email-security-dark.png');
  const errs = d.errs.filter((e) => !/status of (503)/.test(e) && !/ERR_FAILED/.test(e));
  if (errs.length) fail(`desktop console errors:\n  ${errs.join('\n  ')}`);
  console.log('ok: dark mode');
  await d.ctx.close();

  for (const scheme of ['light', 'dark']) {
    const m = await open({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true, colorScheme: scheme });
    await look(m.page, 'good.test');
    const w = await m.page.evaluate(() => document.documentElement.scrollWidth);
    if (w > 390) fail(`mobile ${scheme}: page is ${w}px wide`);
    if (SHOTS) await tallShot(m.page, `email-security-mobile-${scheme}.png`);
    const me = m.errs.filter((e) => !/ERR_FAILED/.test(e));
    if (me.length) fail(`mobile ${scheme} console errors:\n  ${me.join('\n  ')}`);
    console.log(`ok: mobile ${scheme} layout (${w}px)`);
    await m.ctx.close();
  }

  // live
  const l = await open({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' }, false);
  r = await look(l.page, 'google.com');
  if (r.rows['MTA-STS']?.word !== 'Present' || r.rows['TLS-RPT']?.word !== 'Present' || !/^A\+?$|^[BC]\+?$/.test(r.grade || '')) fail(`live google.com: ${r.grade} ${JSON.stringify(r.rows)}`);
  else console.log('ok: live google.com', r.grade, Object.entries(r.rows).map(([k, v]) => `${k}=${v.word}`).join(', '));
  r = await look(l.page, 'example.com');
  if (!r.hasCard || r.rows['MTA-STS']?.word !== 'Missing') fail(`live example.com: ${r.grade} ${JSON.stringify(r.rows)}`);
  else console.log('ok: live example.com', r.grade, Object.entries(r.rows).map(([k, v]) => `${k}=${v.word}`).join(', '));
  if (l.errs.length) fail(`live console errors:\n  ${l.errs.join('\n  ')}`);
  await l.ctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
