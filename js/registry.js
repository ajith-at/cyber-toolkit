// Module registry. To add a tool: create modules/<id>.js exporting the module object, then add one line below.
//
// Module contract:
//   id       unique slug, used in the URL (#q=...&tool=<id>)
//   name     sidebar label
//   icon     a key from js/icons.js (Lucide outline icon)
//   accepts  which targets it understands: 'ip' | 'domain' | 'url' | 'hash'
//            (a URL also yields its host's ip/domain; an email yields its domain)
//   summary  one line for the home screen
//   source   data source caption shown on the result section
//   render(q, { body, setStatus }) async; append result cards to body; setStatus('low'|'unknown'|'caution'|'high', text)
//
// Standalone tools that work on pasted text or files instead of the smart input use accepts: [] and provide:
//   inputs   labels for the home screen, e.g. ['Text', 'File']
//   panel(body, { go })  build the tool UI once into body; go(value, toolId) opens a lookup in another tool

import ipLookup from '../modules/ip-lookup.js';
import domainLookup from '../modules/domain-lookup.js';
import dnsEmail from '../modules/dns-email.js';
import certificates from '../modules/certificates.js';
import reputation from '../modules/reputation.js';
import encoding from '../modules/encoding.js';

export const MODULES = [
  ipLookup,
  domainLookup,
  dnsEmail,
  certificates,
  reputation,
  encoding,
];

/** Targets a parsed query provides. */
export function targetsOf(q) {
  const t = new Set();
  if (q.ip) t.add('ip');
  if (q.domain) t.add('domain');
  if (q.type === 'url') t.add('url');
  if (q.type === 'hash') t.add('hash');
  return t;
}

export function modulesFor(q) {
  const t = targetsOf(q);
  return MODULES.filter((m) => m.accepts.some((a) => t.has(a)));
}
