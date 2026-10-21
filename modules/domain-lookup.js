// Domain lookup: registry RDAP (via rdap.org bootstrap) for registrar, dates, nameservers and status.
import { rdapDomain, vcard, entityByRole, eventDate } from '../js/net.js';
import { el, factCard, factGrid, detailsTable, rawJson, mono, fmtDate, daysBetween, fmtNum, errorCallout, callout, extLink, list, pill, worst } from '../js/ui.js';

const BAD_STATUS = ['client hold', 'server hold', 'redemption period', 'pending delete', 'inactive'];

export default {
  id: 'domain-lookup',
  name: 'Domain lookup',
  icon: 'globe',
  accepts: ['domain'],
  summary: 'Registrar, created and expiry dates, domain age, nameservers and registry status (RDAP).',
  source: 'RDAP via rdap.org',

  async render(q, { body, setStatus }) {
    let res;
    try { res = await rdapDomain(q.domain); } catch (e) {
      setStatus('unknown', 'Unavailable');
      const msg = e.kind === 'http' && e.status === 404
        ? 'No RDAP record was found. The domain may not exist, or its registry does not publish RDAP (for example .de).'
        : e.message;
      body.append(errorCallout({ message: msg }, `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(q.domain)}`, 'Look it up on ICANN Lookup'));
      return;
    }
    const { name, data: d } = res;
    const created = eventDate(d, 'registration');
    const expires = eventDate(d, 'expiration');
    const changed = eventDate(d, 'last changed');
    const regEnt = entityByRole(d, 'registrar');
    const registrar = vcard(regEnt);
    const ianaId = regEnt?.publicIds?.find((p) => /iana/i.test(p.type))?.identifier;
    const abuse = vcard(entityByRole(regEnt || d, 'abuse'));
    const ns = (d.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()).filter(Boolean);
    const status = d.status || [];
    const signed = d.secureDNS?.delegationSigned;

    const age = created ? daysBetween(created) : null;
    const toExpiry = expires ? -daysBetween(expires) : null;

    const ageStatus = age == null ? 'unknown' : age < 30 ? 'high' : age < 90 ? 'caution' : 'low';
    const ageText = age == null ? 'Unknown' : age < 30 ? 'Very new' : age < 90 ? 'New domain' : 'Established';
    const expStatus = toExpiry == null ? 'unknown' : toExpiry < 0 ? 'high' : toExpiry < 30 ? 'caution' : 'low';
    const badStatus = status.filter((s) => BAD_STATUS.includes(s.toLowerCase()));
    const statStatus = badStatus.length ? 'high' : status.length ? 'low' : 'unknown';

    setStatus(worst(ageStatus === 'unknown' ? 'low' : ageStatus, expStatus === 'unknown' ? 'low' : expStatus, badStatus.length ? 'high' : 'low'));

    if (name !== q.domain) body.append(el('p', { class: 'note' }, `Registration data is held for the parent domain `, mono(name), ` (looked up from ${q.domain}).`));
    if (ageStatus === 'caution' || ageStatus === 'high') {
      body.append(callout(ageStatus, `Registered ${fmtNum(age)} days ago`, 'Brand-new domains are a common sign of phishing and scam sites. Treat links and attachments with extra care.'));
    }
    if (badStatus.length) body.append(callout('high', `Registry status: ${badStatus.join(', ')}`, 'The registry has suspended or is deleting this domain.'));

    body.append(factGrid(
      factCard({ label: 'Domain age', status: ageStatus, statusText: ageText, figure: age == null ? '—' : fmtNum(age), unit: age == null ? null : 'days', caption: created ? `Created ${fmtDate(created)}` : 'No creation date in the record.' }),
      factCard({ label: 'Expires in', status: expStatus, statusText: toExpiry == null ? 'Unknown' : toExpiry < 0 ? 'Expired' : toExpiry < 30 ? 'Soon' : 'OK', figure: toExpiry == null ? '—' : fmtNum(toExpiry), unit: toExpiry == null ? null : 'days', caption: expires ? `On ${fmtDate(expires)}` : 'No expiry date in the record.' }),
      factCard({ label: 'Registrar', figure: registrar.name || '—', small: true, caption: ianaId ? `IANA ID ${ianaId}` : null }),
      factCard({ label: 'Nameservers', figure: fmtNum(ns.length), status: signed ? 'low' : 'unknown', statusText: signed ? 'DNSSEC on' : 'No DNSSEC', caption: ns[0] ? ns[0] : null }),
    ));

    body.append(detailsTable('Registration details', [
      ['Domain', mono(name.toLowerCase())],
      ['Registrar', registrar.name],
      ['IANA ID', ianaId],
      ['Registrar abuse', abuse.email ? el('a', { href: `mailto:${abuse.email}` }, abuse.email) : null],
      ['Created', fmtDate(created)],
      ['Last changed', fmtDate(changed)],
      ['Expires', fmtDate(expires)],
      ['Status', status.length ? el('div', { class: 'pill-row' }, status.map((s) => pill(BAD_STATUS.includes(s.toLowerCase()) ? 'high' : 'unknown', s))) : null],
      ['DNSSEC', signed == null ? null : signed ? 'Signed' : 'Not signed'],
      ['Nameservers', list(ns, true)],
    ], el('div', { class: 'card-foot' }, rawJson('View raw RDAP response', d), extLink(`https://lookup.icann.org/en/lookup?name=${encodeURIComponent(name)}`, 'Open on ICANN Lookup'))));
  },
};
