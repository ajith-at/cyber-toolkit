// Password breach check: only a 5-character SHA-1 prefix is sent, padding is requested, nothing is stored.
// Usage: python3 -m http.server 8811 &   then   node tests/breach-check.js [baseUrl] [--shots]
const { chromium } = require('playwright');
const crypto = require('crypto');
const path = require('path');
const BASE = process.argv.find((a) => a.startsWith('http')) || 'http://localhost:8811/';
const SHOTS = process.argv.includes('--shots');
const shotDir = path.join(__dirname, '..', 'screenshots');
const sha1 = (s) => crypto.createHash('sha1').update(s, 'utf8').digest('hex').toUpperCase();

(async () => {
  const browser = await chromium.launch({ channel: process.env.PW_CHANNEL || 'chrome' });
  let fails = 0;
  const fail = (m) => { fails++; console.log('FAIL:', m); };

  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light' });
  const page = await ctx.newPage();
  const errs = [];
  const logs = [];
  page.on('pageerror', (e) => errs.push(`pageerror: ${e.message}`));
  page.on('console', (m) => { logs.push(m.text()); if (m.type() === 'error') errs.push(`console: ${m.text()}`); });
  await page.goto(`${BASE}#tool=breach-check`);
  await page.waitForSelector('#bc-input');

  // field attributes
  const attrs = await page.$eval('#bc-input', (i) => ({ type: i.type, ac: i.getAttribute('autocomplete'), name: i.name }));
  if (attrs.type !== 'password' || attrs.ac !== 'off' || attrs.name) fail(`password field attributes ${JSON.stringify(attrs)}`);
  await page.click('.pw-toggle');
  if ((await page.$eval('#bc-input', (i) => i.type)) !== 'text') fail('show toggle');
  await page.click('.pw-toggle');
  if ((await page.$eval('#bc-input', (i) => i.type)) !== 'password') fail('hide toggle');

  // Mocked range API: record every request.
  const secret = 'correct horse battery staple ✓';
  const h = sha1(secret);
  const requests = [];
  page.on('request', (r) => { if (!r.url().startsWith(BASE)) requests.push({ url: r.url(), headers: r.headers(), post: r.postData() }); });
  let respond = (suffix) => `${'0'.repeat(35)}:0\r\n${suffix}:4242\r\nABCDEF0123456789ABCDEF0123456789ABC:0\r\n`;
  await page.route('https://api.pwnedpasswords.com/range/**', (route) => route.fulfill({ status: 200, headers: { 'access-control-allow-origin': '*', 'content-type': 'text/plain' }, body: respond(h.slice(5)) }));

  await page.fill('#bc-input', secret);
  await page.press('#bc-input', 'Enter');
  await page.waitForSelector('.bc-out .fact');
  const found = await page.textContent('.bc-out');
  if (!/4,242/.test(found) || !/Breached/.test(found)) fail(`found result: ${found}`);
  if (await page.$eval('.bc-out .pill', (p) => p.dataset.status) !== 'high') fail('found should be rose/high');
  if (requests.length !== 1) fail(`expected exactly 1 external request, got ${requests.length}`);
  else {
    const r = requests[0];
    if (r.url !== `https://api.pwnedpasswords.com/range/${h.slice(0, 5)}`) fail(`request url ${r.url}`);
    if (r.headers['add-padding'] !== 'true') fail('Add-Padding header missing');
    if (r.post) fail('request has a body');
    if (r.url.includes(h.slice(5, 12)) || JSON.stringify(r).includes(encodeURIComponent(secret).slice(0, 10))) fail('more than the prefix was sent');
  }
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'breach-found.png') });

  // padding entries (count 0) must not count as found
  respond = () => `${'0'.repeat(35)}:0\r\n`;
  await page.fill('#bc-input', 'another-unique-passphrase-9f8e7d');
  await page.click('#bc-go');
  await page.waitForFunction(() => /Not found/.test(document.querySelector('.bc-out').textContent));
  if (await page.$eval('.bc-out .pill', (p) => p.dataset.status) !== 'low') fail('not found should be teal/low');
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'breach-not-found.png') });

  // network failure
  await page.unroute('https://api.pwnedpasswords.com/range/**');
  await page.route('https://api.pwnedpasswords.com/range/**', (route) => route.abort());
  const before = errs.length;
  await page.click('#bc-go');
  await page.waitForFunction(() => /Check unavailable/.test(document.querySelector('.bc-out').textContent));
  // The browser logs the deliberately failed request; that one is expected.
  errs.splice(before, errs.length - before, ...errs.slice(before).filter((x) => !/ERR_FAILED/.test(x)));
  console.log('ok: only the 5-character prefix is sent with Add-Padding; found / not found / error states');

  // never stored or put in the URL / history / console
  const leaks = await page.evaluate((s) => ({ url: location.href.includes(s) || decodeURIComponent(location.href).includes(s), ls: JSON.stringify({ ...localStorage }).includes(s), ss: JSON.stringify({ ...sessionStorage }).includes(s), hist: history.length }), secret);
  if (leaks.url || leaks.ls || leaks.ss) fail(`password leaked: ${JSON.stringify(leaks)}`);
  if (logs.some((l) => l.includes(secret) || l.includes(h))) fail('password or hash logged to the console');
  // leaving the tool clears the field
  await page.click('.nav-item[data-tool="all"]');
  await page.click('.nav-item[data-tool="breach-check"]');
  if (await page.inputValue('#bc-input')) fail('password not cleared after leaving the tool');
  console.log('ok: not in URL, storage or console; cleared when leaving the tool');

  // live check against the real API with a well-known breached password
  await page.unroute('https://api.pwnedpasswords.com/range/**');
  await page.fill('#bc-input', 'password');
  await page.click('#bc-go');
  await page.waitForFunction(() => /Breached|Not found|unavailable/.test(document.querySelector('.bc-out').textContent), null, { timeout: 20000 });
  const live = await page.textContent('.bc-out');
  if (!/Breached/.test(live)) fail(`live check for "password" should be breached: ${live}`);
  else console.log('ok: live Pwned Passwords check (CORS preflight with Add-Padding works)');

  // dark
  await page.click('.switch-rail');
  if (SHOTS) await page.screenshot({ path: path.join(shotDir, 'breach-dark.png') });
  await page.click('.switch-rail');
  if (errs.length) fail(`desktop console errors:\n  ${errs.join('\n  ')}`);
  await ctx.close();

  // mobile
  const mctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, isMobile: true, hasTouch: true });
  const m = await mctx.newPage();
  const merrs = [];
  m.on('pageerror', (e) => merrs.push(e.message));
  m.on('console', (x) => { if (x.type() === 'error') merrs.push(x.text()); });
  await m.route('https://api.pwnedpasswords.com/range/**', (route) => route.fulfill({ status: 200, headers: { 'access-control-allow-origin': '*' }, body: `${sha1('hunter2').slice(5)}:31337\r\n` }));
  await m.goto(`${BASE}#tool=breach-check`);
  await m.fill('#bc-input', 'hunter2');
  await m.click('#bc-go');
  await m.waitForSelector('.bc-out .fact');
  const mob = await m.evaluate(() => ({
    width: document.documentElement.scrollWidth,
    small: [...document.querySelectorAll('#mod-breach-check button')].filter((e) => e.offsetParent && e.getBoundingClientRect().height < 44).map((e) => e.className),
  }));
  if (mob.width > 390) fail(`mobile: page is ${mob.width}px wide`);
  if (mob.small.length) fail(`mobile: tap targets <44px: ${mob.small.join(', ')}`);
  console.log('ok: mobile layout', JSON.stringify(mob));
  if (SHOTS) await m.screenshot({ path: path.join(shotDir, 'breach-mobile.png') });
  if (merrs.length) fail(`mobile console errors:\n  ${merrs.join('\n  ')}`);
  await mctx.close();

  await browser.close();
  console.log(fails ? `\n${fails} FAILURE(S)` : '\nALL PASSED');
  process.exit(fails ? 1 : 0);
})();
