// IP lookup: RDAP ownership (via rdap.org -> ARIN/RIPE/APNIC/LACNIC/AFRINIC) + reverse DNS via DoH.
import { rdap, doh, reverseName, vcard, entityByRole, allEntities, eventDate } from '../js/net.js';
import { el, factCard, factGrid, detailsTable, rawJson, mono, fmtDate, errorCallout, callout, extLink, list } from '../js/ui.js';
import { ipScope } from '../js/detect.js';

export default {
  id: 'ip-lookup',
  name: 'IP lookup',
  icon: 'server',
  accepts: ['ip'],
  summary: 'Who owns an IP: organisation, network range, country and abuse contact (RDAP), plus reverse DNS.',
  source: 'RDAP via rdap.org · reverse DNS via DNS-over-HTTPS',

  async render(q, { body, setStatus }) {
    const ip = q.ip;
    const scope = ipScope(ip);
    if (scope) {
      setStatus('unknown', 'Not public');
      body.append(callout('unknown', `${ip} is a ${scope} address`, 'It is not routed on the public internet, so there is no public owner or reputation to look up. If it appears in logs, look at your own network.'));
      return;
    }

    const [r, ptr] = await Promise.allSettled([rdap('ip', ip), doh(reverseName(ip), 'PTR')]);
    const names = ptr.status === 'fulfilled' ? ptr.value.answers.map((a) => a.data.replace(/\.$/, '')) : [];

    if (r.status === 'rejected') {
      setStatus('unknown', 'Unavailable');
      body.append(errorCallout(r.reason, `https://client.rdap.org/?type=ip&object=${encodeURIComponent(ip)}`, 'Try the RDAP web client'));
      if (names.length) body.append(detailsTable('Reverse DNS', [['PTR', list(names, true)]]));
      return;
    }

    const d = r.value;
    const registrant = entityByRole(d, 'registrant') || allEntities(d)[0];
    const reg = vcard(registrant);
    const abuseEnt = entityByRole(d, 'abuse');
    const abuse = vcard(abuseEnt);
    const cidrs = (d.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
    const range = d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : null;
    const registered = eventDate(d, 'registration');
    const changed = eventDate(d, 'last changed');
    const server = (d.port43 || (d.links || []).find((l) => l.rel === 'self')?.href || '').replace(/^https?:\/\/([^/]+).*$/, '$1');
    const org = reg.org || reg.name || d.name || '—';
    const country = d.country || reg.country || null;

    // There is no reputation score without an API key (planned for V2), so status stays "Unknown" unless something stands out.
    setStatus('unknown', 'No score (V1)');

    body.append(factGrid(
      factCard({ label: 'Owner', figure: org, small: true, caption: d.name && d.name !== org ? `Network name ${d.name}` : (registrant?.handle ? `Handle ${registrant.handle}` : null) }),
      factCard({ label: 'Network', figure: cidrs[0] || range || '—', mono: true, small: true, caption: cidrs.length > 1 ? `${cidrs.length} prefixes` : (d.type || null) }),
      factCard({ label: 'Country', figure: country || '—', small: !!country && country.length > 3, caption: country ? 'Registered country of the network owner. The server itself can be elsewhere.' : 'Not listed in the registry record.' }),
      factCard({ label: 'Reverse DNS', figure: names[0] || 'None', mono: !!names[0], small: true, status: names.length ? 'low' : 'unknown', statusText: names.length ? 'Has PTR' : 'No PTR', caption: names.length > 1 ? `+${names.length - 1} more` : (names.length ? null : 'Many servers have no reverse name; that alone is not suspicious.') }),
    ));

    body.append(detailsTable('Registration details', [
      ['IP address', mono(ip)],
      ['Network range', range ? mono(range) : null],
      ['CIDR', list(cidrs, true)],
      ['Network name', d.name],
      ['Handle', d.handle ? mono(d.handle) : null],
      ['Organisation', org],
      ['Address', reg.address],
      ['Country', country],
      ['Abuse contact', abuse.email ? el('a', { href: `mailto:${abuse.email}` }, abuse.email) : null],
      ['Abuse phone', abuse.tel],
      ['Registered', fmtDate(registered)],
      ['Last changed', fmtDate(changed)],
      ['Allocation type', d.type],
      ['Reverse DNS (PTR)', list(names, true)],
      ['RDAP server', server || null],
    ], el('div', { class: 'card-foot' }, rawJson('View raw RDAP response', d), extLink(`https://client.rdap.org/?type=ip&object=${encodeURIComponent(ip)}`, 'Open in RDAP client'))));
  },
};
