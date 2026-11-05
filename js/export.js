// Export lookup results as Markdown (for tickets, GitHub, Jira, Notion) or JSON. Pure functions, no DOM.
//
// A result is { id, name, status, statusText, facts: [[label, value], ...], raw? } where status is
// 'low' | 'unknown' | 'caution' | 'high', or null while the tool is still checking.

const WORD = { low: 'Low risk', unknown: 'Unknown', caution: 'Caution', high: 'High risk' };

export function statusWord(status, text) {
  if (!status) return 'Still checking';
  const w = WORD[status] || WORD.unknown;
  return text && text !== w ? `${w} (${text})` : w;
}

/** Plain text for one fact value: arrays become comma lists, empty values become null. */
export function plain(v) {
  if (v == null) return null;
  if (Array.isArray(v)) { const a = v.map(plain).filter(Boolean); return a.length ? a.join(', ') : null; }
  const s = String(v).replace(/\s+/g, ' ').trim();
  return s || null;
}

/** Escape text for a Markdown heading or list line. Backslashes, pipes and markup characters are escaped. */
function mdText(v) {
  return String(v).replace(/[\\`*[\]<>|]/g, (c) => `\\${c}`);
}

/**
 * Table value as inline code. The fence is one backtick longer than the longest
 * run in the value, so domain-controlled TXT or RDAP text cannot close the span
 * and then autolink or spoof italics or strikethrough in GitHub or Slack.
 * Pipes are escaped because GFM splits table cells before it parses code spans.
 */
export function mdCell(v) {
  const s = String(v).replace(/\|/g, '\\|');
  let longest = 0;
  for (const run of s.match(/`+/g) || []) {
    if (run.length > longest) longest = run.length;
  }
  const fence = '`'.repeat(longest + 1);
  // A leading or trailing backtick would merge with the fence. Pad both sides;
  // CommonMark then strips one space from each end.
  const pad = s.startsWith('`') || s.endsWith('`') ? ' ' : '';
  return `${fence}${pad}${s}${pad}${fence}`;
}

export function normalise(results) {
  return results.map((r) => ({
    id: r.id,
    name: r.name,
    status: r.status || 'checking',
    statusText: r.statusText || null,
    facts: (r.facts || []).map(([k, v]) => [String(k), plain(v)]).filter(([, v]) => v != null),
    ...(r.raw !== undefined ? { raw: r.raw } : {}),
  }));
}

/** JSON export: the input, when it was checked, the overall status, and each tool's status and facts. */
export function toJson({ input, type, overall, at = new Date(), results, includeRaw = false }) {
  const tools = normalise(results).map((r) => {
    const o = { ...r, facts: Object.fromEntries(r.facts) };
    if (!includeRaw) delete o.raw;
    return o;
  });
  return JSON.stringify({ tool: 'Cyber Toolkit', input, type, checkedAt: at.toISOString(), overall: overall || null, results: tools }, null, 2);
}

/** Markdown export: a heading and summary line, then a two-column table of key facts per tool. */
export function toMarkdown({ input, type, overall, at = new Date(), results }) {
  const out = [`## Cyber Toolkit: ${mdText(input)}`, ''];
  out.push(`- **Type:** ${mdText(type)}`);
  if (overall) out.push(`- **Overall:** ${mdText(statusWord(overall.status, overall.text))}`);
  out.push(`- **Checked:** ${at.toISOString().replace(/\.\d+Z$/, 'Z')}`, '');
  for (const r of normalise(results)) {
    out.push(`### ${mdText(r.name)}`, '', `Status: ${mdText(statusWord(r.status === 'checking' ? null : r.status, r.statusText))}`, '');
    if (r.facts.length) {
      out.push('| Fact | Value |', '| --- | --- |');
      for (const [k, v] of r.facts) out.push(`| ${mdText(k)} | ${mdCell(v)} |`);
      out.push('');
    }
  }
  return `${out.join('\n').trimEnd()}\n`;
}

/** File name for a download, e.g. cyber-toolkit-example.com-2026-10-30.json */
export function fileName(input, at = new Date(), ext = 'json') {
  const slug = String(input).toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'lookup';
  return `cyber-toolkit-${slug}-${at.toISOString().slice(0, 10)}.${ext}`;
}
