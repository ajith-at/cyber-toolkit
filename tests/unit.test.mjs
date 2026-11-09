import test from 'node:test';
import assert from 'node:assert/strict';
import { detect, refang } from '../js/detect.js';
import { reverseName } from '../js/net.js';
import { analyseSpf, analyseDmarc } from '../modules/dns-email.js';

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
