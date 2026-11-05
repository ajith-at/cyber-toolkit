import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mdCell, toMarkdown } from '../js/export.js';

test('Markdown export wraps table values in inline code', () => {
  assert.equal(mdCell('www.evil.example'), '`www.evil.example`');
  assert.equal(mdCell('https://evil.example/phish'), '`https://evil.example/phish`');
  assert.equal(mdCell('_spoof_ ~~ok~~'), '`_spoof_ ~~ok~~`');
  assert.equal(mdCell('&#60;script&#62;'), '`&#60;script&#62;`');
  assert.equal(mdCell('Pipe | Co'), '`Pipe \\| Co`');
  assert.equal(mdCell('no `break` out'), '``no `break` out``');
  assert.equal(mdCell('`lead'), '`` `lead ``');
  assert.equal(mdCell('trail`'), '`` trail` ``');
  assert.equal(mdCell('a```b'), '````a```b````');

  const md = toMarkdown({
    input: 'evil|site.example',
    type: 'Domain',
    overall: { status: 'caution', text: null },
    at: new Date('2026-10-30T00:00:00Z'),
    results: [{
      id: 'dns',
      name: 'DNS & email security',
      status: 'caution',
      statusText: 'New domain',
      facts: [['TXT', '_spoof_ ~~ok~~ https://evil.example www.evil.example'], ['Nameservers', ['ns1.x', 'ns2.x']]],
    }],
  });
  assert.match(md, /## Cyber Toolkit: evil\\\|site\.example/);
  assert.match(md, /### DNS & email security/);
  assert.match(md, /Status: Caution \(New domain\)/);
  assert.match(md, /\| TXT \| `_spoof_ ~~ok~~ https:\/\/evil\.example www\.evil\.example` \|/);
  assert.match(md, /\| Nameservers \| `ns1\.x, ns2\.x` \|/);
  assert.doesNotMatch(md, /\| TXT \| _spoof_/);
});

test('frame-buster is external and connect-src stays https:', () => {
  const html = fs.readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /<script src="js\/frame-buster\.js"><\/script>/);
  assert.match(html, /connect-src https:/);
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  const js = fs.readFileSync(new URL('../js/frame-buster.js', import.meta.url), 'utf8');
  assert.match(js, /window\.top/);
  assert.match(js, /frame-ancestors/);
  assert.match(js, /X-Frame-Options/);
});
