import test from 'node:test';
import assert from 'node:assert/strict';
import { detect, refang } from '../js/detect.js';
import { reverseName } from '../js/net.js';
import { analyseSpf, analyseDmarc, analyseMtaSts, analyseTlsRpt, analyseBimi, analyseDkim, withBonus, DKIM_SELECTORS } from '../modules/dns-email.js';

test('pure input and DNS helpers never access the network', async (t) => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected network request'); });

  await t.test('detect normalises IPv4 and IPv6 forms', () => {
    for (const [input, value, version] of [
      ['192.0.2.1', '192.0.2.1', 4],
      ['::1', '::1', 6],
      ['::', '::', 6],
      ['[2001:DB8::1]', '2001:db8::1', 6],
      ['2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1', 6],
      ['::ffff:192.0.2.1', '::ffff:c000:201', 6],
    ]) {
      const result = detect(input);
      assert.equal(result.type, 'ip', input);
      assert.equal(result.value, value, input);
      assert.equal(result.version, version, input);
    }
    for (const input of ['256.1.1.1', '2001::db8::1', '2001:db8:zz::1']) {
      assert.equal(detect(input).type, 'invalid', input);
    }
  });

  await t.test('detect handles Unicode domains and defanged indicators', () => {
    for (const [input, type, value] of [
      ['  EXAMPLE.COM.  ', 'domain', 'example.com'],
      ['bücher.example', 'domain', 'xn--bcher-kva.example'],
      ['USER@BÜCHER.EXAMPLE', 'email', 'user@xn--bcher-kva.example'],
      ['hxxps://example[.]com/login', 'url', 'https://example.com/login'],
      ['user[@]example[.]com', 'email', 'user@example.com'],
      ['192[.]0[.]2[.]1', 'ip', '192.0.2.1'],
    ]) {
      const result = detect(input);
      assert.equal(result.type, type, input);
      assert.equal(result.value, value, input);
    }
    assert.equal(detect('hxxps://example[.]com').refanged, true);
    assert.equal(detect('example.com').refanged, false);
    for (const input of ['', 'hello world', 'javascript:alert(1)', 'x'.repeat(2049)]) {
      assert.equal(detect(input).type, 'invalid', input);
    }
  });

  await t.test('detect accepts only supported hexadecimal hash lengths', () => {
    for (const [length, hashType] of [[32, 'MD5'], [40, 'SHA-1'], [64, 'SHA-256']]) {
      const result = detect('A'.repeat(length));
      assert.equal(result.type, 'hash');
      assert.equal(result.hashType, hashType);
      assert.equal(result.value, 'a'.repeat(length));
    }
    for (const length of [31, 33, 39, 41, 63, 65]) {
      assert.equal(detect('a'.repeat(length)).type, 'invalid', String(length));
    }
    assert.equal(detect('g'.repeat(32)).type, 'invalid');
  });

  await t.test('refang restores supported delimiters without changing ordinary input', () => {
    for (const [input, expected] of [
      ['hxxp://example[.]com', 'http://example.com'],
      ['hxxps://example(.)com', 'https://example.com'],
      ['example{.}com', 'example.com'],
      ['example[DOT]com', 'example.com'],
      ['user[at]example[.]com', 'user@example.com'],
      ['https[:]//example.com', 'https://example.com'],
      ['https://example.com/path', 'https://example.com/path'],
    ]) assert.equal(refang(input), expected);
  });

  await t.test('SPF distinguishes missing, duplicate, permissive and delegated policies', () => {
    assert.equal(analyseSpf([]).word, 'Missing');
    assert.equal(analyseSpf(['unrelated TXT']).word, 'Missing');
    assert.equal(analyseSpf(['v=spf10 -all']).word, 'Missing');
    assert.equal(analyseSpf(['v=spf1 -all', 'v=spf1 ~all']).word, 'Invalid');
    for (const [record, word, status] of [
      ['v=spf1 +all', 'Allows anyone', 'high'],
      ['v=spf1 all', 'Allows anyone', 'high'],
      ['v=spf1 ?all', 'Neutral', 'caution'],
      ['v=spf1 ~all', 'Soft fail', 'low'],
      ['v=spf1 -all', 'Hard fail', 'low'],
      ['v=spf1 redirect=example.com', 'Redirect', 'low'],
      ['v=spf1 ip4:192.0.2.0/24', 'No "all"', 'caution'],
    ]) {
      const result = analyseSpf([record]);
      assert.equal(result.word, word, record);
      assert.equal(result.status, status, record);
      assert.equal(result.record, record);
    }
    for (const count of [10, 11]) {
      const record = `v=spf1 ${Array.from({length: count}, (_, i) => `include:mail${i}.example.com`).join(' ')} -all`;
      const result = analyseSpf([record]);
      assert.equal(result.lookups, count);
      assert.equal(result.status, count === 10 ? 'low' : 'caution');
      assert.equal(result.note.includes('limit is 10'), count > 10);
    }
    assert.equal(analyseSpf(['v=spf1 redirect=example.com']).lookups, 1);
  });

  await t.test('DMARC parses policy, reporting and partial enforcement', () => {
    assert.equal(analyseDmarc([]).word, 'Missing');
    assert.equal(analyseDmarc(['unrelated TXT']).word, 'Missing');
    for (const [policy, word, status] of [
      ['reject', 'Reject', 'low'], ['quarantine', 'Quarantine', 'low'], ['none', 'Monitor only', 'caution'],
    ]) {
      const result = analyseDmarc([`v=DMARC1; p=${policy}; rua=mailto:reports@example.com`]);
      assert.equal(result.word, word);
      assert.equal(result.status, status);
      assert.equal(result.policy, policy);
      assert.equal(result.rua, 'mailto:reports@example.com');
    }
    for (const record of ['v=DMARC1', 'v=DMARC1; p=unknown']) {
      assert.equal(analyseDmarc([record]).word, 'Invalid');
    }
    for (const pct of ['0', '25', '100']) {
      const result = analyseDmarc([`v=DMARC1; p=reject; pct=${pct}`]);
      assert.equal(result.pct, pct);
      assert.equal(result.note.includes(`Applied to ${pct}%`), pct !== '100');
    }
    assert.equal(analyseDmarc(['v=DMARC1; P = REJECT ; pct = 25']).policy, 'reject');
  });

  await t.test('reverse DNS expands compressed IPv6 and reverses every nibble', () => {
    assert.equal(reverseName('192.0.2.1'), '1.2.0.192.in-addr.arpa');
    assert.equal(reverseName('::'), `${Array(32).fill('0').join('.')}.ip6.arpa`);
    assert.equal(reverseName('::1'), `1.${Array(31).fill('0').join('.')}.ip6.arpa`);
    const expected = '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa';
    assert.equal(reverseName('2001:db8::1'), expected);
    assert.equal(reverseName('2001:db8:0:0:0:0:0:1'), expected);
    assert.equal(reverseName(detect('::ffff:192.0.2.1').value),
      '1.0.2.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa');
  });
  assert.equal(globalThis.fetch.mock.callCount(), 0);
});

test('InternetDB assessment (open ports and CVEs)', async () => {
  const { assessInternetDb } = await import('../modules/open-ports.js');
  const none = assessInternetDb(null);
  assert.equal(none.status, 'unknown');
  assert.equal(none.text, 'Nothing seen');
  const clean = assessInternetDb({ ports: [443, 53], tags: ['pqc'], vulns: [], hostnames: ['dns.google'], cpes: [] });
  assert.deepEqual(clean.ports, [53, 443]);
  assert.equal(clean.status, 'unknown');
  assert.equal(clean.text, 'No CVEs listed');
  const vuln = assessInternetDb({ ports: [22, 80, 99999, 'x'], vulns: ['CVE-2014-0226', 'cve-2024-38475', 'CVE-2024-38475', 'not-a-cve'], tags: [] });
  assert.deepEqual(vuln.ports, [22, 80]);
  assert.deepEqual(vuln.vulns, ['CVE-2024-38475', 'CVE-2014-0226']);
  assert.equal(vuln.status, 'caution');
  assert.equal(vuln.text, '2 CVEs');
  const eol = assessInternetDb({ ports: [80], vulns: [], tags: ['eol-product'] });
  assert.equal(eol.status, 'caution');
  assert.equal(eol.text, 'Tagged eol-product');
});

test('EPSS ranking for InternetDB CVEs', async () => {
  const { epssScores, rankByEpss, fmtPct } = await import('../modules/open-ports.js');
  const saved = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (u) => { urls.push(String(u)); return new Response(JSON.stringify({ data: [
    { cve: 'CVE-2024-38475', epss: '0.943', percentile: '0.999', date: '2026-11-12' },
    { cve: 'CVE-2014-0226', epss: '0.02', percentile: '0.8', date: '2026-11-12' },
    { cve: 'bogus', epss: '0.9' }, { cve: 'CVE-2020-0001', epss: '7' },
  ] }), { status: 200 }); };
  try {
    const cves = Array.from({ length: 150 }, (_, i) => `CVE-2020-${1000 + i}`).concat(['CVE-2024-38475', 'CVE-2014-0226']);
    const scores = await epssScores(cves);
    assert.equal(urls.length, 2, 'batched into 100 per call');
    assert.ok(urls[0].startsWith('https://api.first.org/data/v1/epss?cve=CVE-2020-1000,'));
    assert.equal(scores.size, 2);
    const r = rankByEpss(['CVE-2025-1', 'CVE-2014-0226', 'CVE-2024-38475'], scores);
    assert.deepEqual(r.order, ['CVE-2024-38475', 'CVE-2014-0226', 'CVE-2025-1']);
    assert.equal(r.top.cve, 'CVE-2024-38475');
    assert.equal(r.date, '2026-11-12');
    assert.deepEqual(r.high, ['CVE-2024-38475']);
    assert.equal(fmtPct(0.943), '94.3%');
    assert.equal(fmtPct(0.0123), '1.23%');
    assert.equal(fmtPct(0.00001), '<0.1%');
    globalThis.fetch = async () => new Response('busy', { status: 503 });
    await assert.rejects(epssScores(['CVE-2024-38475']), /HTTP 503/);
  } finally { globalThis.fetch = saved; }
});

test('CVE IDs are detected and normalised', () => {
  for (const s of ['CVE-2021-44228', 'cve-2021-44228', ' Cve-2021-44228 ', 'CVE\u20112021\u201144228']) {
    const q = detect(s);
    assert.equal(q.type, 'cve', s);
    assert.equal(q.value, 'CVE-2021-44228');
  }
  assert.equal(detect('CVE-2024-123456').value, 'CVE-2024-123456');
  assert.notEqual(detect('CVE-2021-123').type, 'cve', 'needs at least 4 digits');
  assert.notEqual(detect('CVE-21-44228').type, 'cve');
});

test('CVE record parsing and status (CIRCL Vulnerability-Lookup)', async () => {
  const { parseCve, assessCve, severityOf } = await import('../modules/cve-lookup.js');
  const { readFile } = await import('node:fs/promises');
  const rec = JSON.parse(await readFile(new URL('./fixtures/cve-2021-44228.json', import.meta.url), 'utf8'));
  const c = parseCve(rec);
  assert.equal(c.id, 'CVE-2021-44228');
  assert.equal(c.state, 'PUBLISHED');
  assert.equal(c.assigner, 'apache');
  assert.match(c.description, /JNDI/);
  assert.equal(c.cvss.score, 10);
  assert.equal(c.cvss.version, '3.1');
  assert.equal(c.cvss.severity, 'CRITICAL');
  assert.equal(c.textRating, 'CRITICAL');
  assert.equal(c.kev.dateAdded, '2021-12-10');
  assert.equal(c.exploitation, 'active');
  assert.ok(c.cwes.some((w) => /CWE-502/.test(w)));
  assert.deepEqual(c.affected, ['Apache Software Foundation · Apache Log4j2']);
  assert.ok(c.refs.length > 5 && c.refs.every((r) => /^https?:/.test(r.url)));
  assert.equal(new Set(c.refs.map((r) => r.url)).size, c.refs.length, 'references are de-duplicated');
  assert.deepEqual(assessCve(c, null), { status: 'high', text: 'Known exploited' });

  const plain = parseCve({ cveMetadata: { cveId: 'CVE-2025-0001', state: 'PUBLISHED' }, containers: { cna: {
    descriptions: [{ lang: 'en', value: 'A bug.' }],
    metrics: [{ cvssV3_1: { baseScore: 7.5, baseSeverity: 'HIGH' } }, { cvssV4_0: { baseScore: 8.7 } }],
    references: [{ url: 'javascript:alert(1)' }, { url: 'https://example.com/a', tags: [] }, { url: 'https://vendor.example/adv', tags: ['vendor-advisory'] }],
  } } });
  assert.equal(plain.cvss.version, '4.0', 'newest CVSS version wins');
  assert.equal(plain.cvss.severity, 'HIGH', 'severity derived from score when missing');
  assert.deepEqual(plain.refs.map((r) => r.url), ['https://vendor.example/adv', 'https://example.com/a'], 'unsafe links dropped, advisories first');
  assert.equal(plain.kev, null);
  assert.deepEqual(assessCve(plain, null), { status: 'caution', text: 'CVSS 8.7' });
  assert.deepEqual(assessCve(plain, { epss: 0.62 }), { status: 'high', text: 'EPSS 62.0%' });
  assert.deepEqual(assessCve(parseCve({ cveMetadata: { cveId: 'CVE-2025-0002', state: 'PUBLISHED' }, containers: { cna: {} } }), null), { status: 'unknown', text: 'Not scored' });

  const rej = parseCve({ cveMetadata: { cveId: 'CVE-2023-9999', state: 'REJECTED' }, containers: { cna: { rejectedReasons: [{ lang: 'en', value: 'Duplicate of CVE-2023-1.' }] } } });
  assert.equal(rej.rejectedReason, 'Duplicate of CVE-2023-1.');
  assert.equal(assessCve(rej, null).text, 'Rejected');
  assert.equal(severityOf(9.8), 'CRITICAL');
  assert.equal(severityOf(4), 'MEDIUM');
});

test('CVE lookup treats an empty answer as not found', async () => {
  const { cveRecord } = await import('../modules/cve-lookup.js');
  const saved = globalThis.fetch;
  const urls = [];
  try {
    globalThis.fetch = async (u) => { urls.push(String(u)); return new Response('{}', { status: 200 }); };
    assert.equal(await cveRecord('CVE-2099-99999'), null);
    assert.equal(urls[0], 'https://vulnerability.circl.lu/api/vulnerability/CVE-2099-99999');
    globalThis.fetch = async () => new Response('nope', { status: 404 });
    assert.equal(await cveRecord('CVE-2099-99999'), null);
    globalThis.fetch = async () => new Response('busy', { status: 502 });
    await assert.rejects(cveRecord('CVE-2021-44228'), /HTTP 502/);
  } finally { globalThis.fetch = saved; }
});

test('Newer mail protections: MTA-STS, TLS-RPT, BIMI, DKIM and the bonus grade', (t) => {
  t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected network request'); });

  // MTA-STS
  assert.equal(analyseMtaSts([], 'example.com').word, 'Missing');
  assert.equal(analyseMtaSts([], 'example.com').status, 'unknown');
  const m = analyseMtaSts(['v=STSv1; id=20210803T010101;'], 'google.com');
  assert.equal(m.present, true);
  assert.equal(m.id, '20210803T010101');
  assert.equal(m.policyUrl, 'https://mta-sts.google.com/.well-known/mta-sts.txt');
  assert.equal(analyseMtaSts(['v=STSv1;'], 'x.com').word, 'Invalid');
  assert.equal(analyseMtaSts(['v=STSv1; id=1', 'v=STSv1; id=2'], 'x.com').word, 'Invalid');

  // TLS-RPT
  assert.equal(analyseTlsRpt(['v=spf1 -all']).word, 'Missing');
  const r = analyseTlsRpt(['v=TLSRPTv1;rua=mailto:sts-reports@google.com']);
  assert.equal(r.present, true);
  assert.equal(r.rua, 'mailto:sts-reports@google.com');
  assert.equal(analyseTlsRpt(['v=TLSRPTv1;']).word, 'Invalid');

  // BIMI
  assert.equal(analyseBimi([]).word, 'Missing');
  assert.equal(analyseBimi(['v=BIMI1; l=; a=; lps=x']).word, 'Declined');
  const b = analyseBimi(['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem']);
  assert.equal(b.present, true);
  assert.equal(b.logo, 'https://example.com/logo.svg');
  assert.match(b.note, /mark certificate/);
  const noCert = analyseBimi(['v=BIMI1; l=https://example.com/logo.svg']);
  assert.equal(noCert.cert, null);
  assert.match(noCert.note, /no mark certificate/);
  assert.equal(analyseBimi(['v=BIMI1; l=javascript:alert(1)']).logo, null, 'unsafe logo URLs are dropped');

  // DKIM
  assert.ok(DKIM_SELECTORS.length <= 8);
  assert.equal(analyseDkim([]).word, 'Not found');
  const d = analyseDkim([
    { selector: 'google', txts: [] },
    { selector: 'selector1', txts: ['v=DKIM1; k=rsa; p=MIIBIjANBg'] },
    { selector: 'k1', txts: ['v=DKIM1; k=ed25519; p='] },
    { selector: 's1', txts: ['v=spf1 include:_spf.example.com ~all'] }, // wildcard TXT is ignored
  ]);
  assert.equal(d.word, 'Found');
  assert.deepEqual(d.found.map((f) => [f.selector, f.keyType, f.revoked]), [['selector1', 'rsa', false], ['k1', 'ed25519', true]]);
  assert.equal(analyseDkim([{ selector: 'k1', txts: ['v=DKIM1; p='] }]).word, 'Revoked only');

  // Bonus grade: only a "+", never a downgrade
  const yes = { present: true }; const no = { present: false };
  assert.equal(withBonus({ g: 'A', status: 'low' }, yes, yes).g, 'A+');
  assert.equal(withBonus({ g: 'B', status: 'caution' }, yes, yes).g, 'B+');
  assert.equal(withBonus({ g: 'A', status: 'low' }, yes, no).g, 'A');
  assert.equal(withBonus({ g: 'F', status: 'high' }, yes, yes).g, 'F');
  assert.equal(withBonus({ g: 'A', status: 'low' }, { failed: true }, yes).g, 'A');
});
