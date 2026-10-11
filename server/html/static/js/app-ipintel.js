// RemotePower — Threat intel page: attacking addresses with their AbuseIPDB /
// SniffCat reputation, reports and timed blocks, plus the provider settings.
//
// Lazy, page-scoped module (see _LAZY_PAGE_MODULES in app.js). api() resolves
// rather than throwing on 4xx, so outcomes are read from the body. Addresses
// and device ids ride data-ip / data-dev attributes read by a delegated
// listener, never data-arg (which turns numeric-looking strings into numbers).

let _ipiData = null;
let _ipiAdmin = false;
let _ipiWired = false;
const _ipiOpen = new Set();

// What the logs showed. The class ids and the wording match threat_evidence.CLASSES on
// the server (tests/test_v720_ipintel_page.py keeps the two in step), and every phrase
// is put in a span of its own so the language engine can translate it.
const _IPI_CLASS = {
  ssh_brute: 'SSH brute force', login_brute: 'login brute force', sqli: 'SQL injection',
  xss: 'cross-site scripting', traversal: 'path traversal', rce: 'remote code execution attempts',
  probe: 'probing for exposed files and admin pages', scanner: 'vulnerability scanning',
  flood: 'request flooding', bad_bot: 'unwanted web crawling',
  waf: 'requests blocked by a web application firewall', mail_brute: 'mail login brute force',
  ftp_brute: 'FTP brute force', service_brute: 'service login brute force', port_scan: 'port scanning',
  canary: 'using a credential planted in a decoy file', decoy_login: 'signing in to a decoy service',
  ddos: 'HTTP request flooding',
};
const _IPI_SOURCE = {
  web: 'Web server log', err: 'Web server error log', waf: 'WAF audit log',
  f2b: 'fail2ban log', cs: 'CrowdSec alerts', fw: 'Firewall log',
  cf: 'Cloudflare firewall events', trap: 'Edge honeypot',
};
// The edge feeds (Cloudflare's firewall events and the honeypot's log): what each is
// called, how its state reads, why a line was set aside, and what a connection test
// tried. The keys match what edge_intel_handlers.py and edge_evidence.py send
// (tests/test_v730_edge_page.py derives both sides and compares them).
const _IPI_FEED = {
  cf: 'Cloudflare firewall events', trap: 'Edge honeypot',
};
const _IPI_FEED_STATE = {
  ok: 'Reading', no_access: 'No permission', refused: 'Refused by Cloudflare', error: 'Error',
  no_account: 'Needs an account id', no_zones: 'No zones found',
  off: 'Off', waiting: 'Waiting for the first read',
};
const _IPI_FEED_STATE_CLASS = {
  ok: 'c-green', no_access: 'c-red', refused: 'c-red', error: 'c-red', no_account: 'c-amber',
  no_zones: 'c-amber', off: 'hint', waiting: 'hint',
};
const _IPI_ASIDE = {
  not_a_refusal: 'challenges and log-only actions',
  not_an_attack_source: 'country, network and security-level rules',
  list_rule: 'a rule that also blocks an IP list',
  not_public: 'private or invalid addresses',
  cloudflare_address: "Cloudflare's own addresses",
  own_or_shared_address: 'your own or shared addresses',
  not_evidence: 'lines the honeypot logs only to be read',
};
const _IPI_CHECK = {
  zones: 'Zones', firewall: 'Firewall events', rules: 'Custom rules', trap: 'Honeypot log',
};
const _IPI_CHECK_STATE = {
  ok: 'Works', no_access: 'The token cannot read this', refused: 'Cloudflare refused this read',
  error: 'Failed', skipped: 'Skipped',
};
// The edge blocklist: the Cloudflare IP list RemotePower keeps up to date. The states and
// the reasons match what edge_blocklist_handlers.py and edge_blocklist.py send
// (tests/test_v730_edge_blocklist_page.py derives both sides and compares them).
const _IPI_LIST_STATE = {
  ok: 'Up to date', preview: 'Preview', held: 'Held', needs_adopt: 'Needs to be taken over',
  needs_setup: 'Needs setup', pending: 'Being applied', error: 'Error', waiting: 'Waiting for the first sync',
};
const _IPI_LIST_STATE_CLASS = {
  ok: 'c-green', preview: 'c-accent', held: 'c-amber', needs_adopt: 'c-amber', needs_setup: 'c-amber',
  pending: 'c-amber', error: 'c-red', waiting: 'hint',
};
const _IPI_LIST_SRC = {
  always: 'Your own entries', own: 'Found by RemotePower', abuseipdb: 'AbuseIPDB', sniffcat: 'SniffCat',
};
// The other fixed words the status prints, in one table so the language gate reads one place.
const _IPI_LIST_WORD = {
  off: 'Off', list: 'List', missing: 'Does not exist yet', managed: 'Managed by RemotePower',
  foreign: 'Not created by RemotePower', current: 'In the list now', should: 'Should hold',
  added: 'Added', removed: 'Removed', room: 'Room in the account', trimmed: 'Left out for lack of room',
  protected: 'Left out as protected', from: 'In the list from', addresses: 'addresses',
  copy: 'saved copy', downloaded: 'downloaded', sync_anyway: 'Sync anyway', entries: 'entries',
  token_prefix: 'The token cannot edit lists:', preview_failed: 'Preview failed', sync_failed: 'Sync failed',
};
const _IPI_LIST_DIALOG = {
  adopt: {
    title: 'Take over this list',
    message: 'A list with this name exists and RemotePower did not create it. Syncing replaces everything in it with what your sources say, and marks it as managed by RemotePower. Stop any other tool that updates it first, or the two will keep undoing each other.',
    confirm: 'Take over and sync',
  },
  force: {
    title: 'Sync anyway',
    message: 'RemotePower held this sync because it would empty or halve the list, or because a source did not answer. Syncing anyway replaces the list with what the sources say now.',
    confirm: 'Sync anyway',
  },
  token: {
    title: 'Remove token',
    message: 'RemotePower stops updating the list until you add a token again. The list in Cloudflare is left as it is.',
    confirm: 'Remove',
  },
};
// A ban by hand (v7.3.0): one address, at the edge and on hosts. The fixed words are a
// table so the language gate reads one place (tests/test_v730_edge_ban_page.py).
const _IPI_BAN_WORD = {
  in_list: 'in the edge blocklist', edge_ban: 'banned at the edge', edge_wait: 'edge ban waiting for the next sync',
  edge_label: 'At the edge:', hosts_label: 'On hosts:',
  edge_in: 'it is in the list', edge_later: 'it goes in the list at the next sync',
  edge_applying: 'Cloudflare is applying the change',
  edge_adopt: 'it goes in once the list has been taken over',
  host_queued: 'queued', host_approval: 'waiting for approval', host_extended: 'already blocked, time extended',
  host_skipped: 'skipped: not a Linux agent you can reach',
  host_deferred: 'not reached in time: ban again to continue',
  seen_by: 'Hosts that saw it', of_hosts: 'Linux hosts in all',
  off_note: 'Turn on the Edge blocklist under Security → Threat intel → Edge blocklist to ban at the edge.',
  operator_note: 'Only the platform operator can ban at the edge.',
  choose: 'Choose at least one place.', could_not: 'Could not ban this address', unbanned: 'Unbanned',
};
const _IPI_BAN_DIALOG = {
  unban: {
    title: 'Unban this address',
    message: 'Lift the ban at the edge and every block RemotePower made on hosts for this address?',
    confirm: 'Unban',
  },
};
const _IPI_EDGE_DIALOG = {
  token: {
    title: 'Remove token',
    message: 'RemotePower stops reading Cloudflare until you add a token again. Nothing in Cloudflare changes.',
    confirm: 'Remove',
  },
};
const _IPI_LIST_WHY = [
  'Add a Cloudflare token that can edit lists.',
  'Add the Cloudflare account id under Edge sources.',
  'The list name may use lower-case letters, digits and underscores.',
  'A list with this name exists and is not an IP list.',
  'A list with this name exists and RemotePower did not create it.',
  "Cloudflare's list limit is reached. Delete a list you no longer use, or give the name of an existing list.",
  'Cloudflare is still working on the last change.',
  'Cloudflare is still applying the change.',
  'Cloudflare did not finish the change in an hour.',
  'Cloudflare could not apply the change.',
  'Cloudflare did not answer.',
  'A source did not answer and has no recent copy.',
  'No source is switched on, so nothing would be left in the list.',
  'Nothing would be left in the list.',
  'The list would shrink by more than half.',
];
const _IPI_STATE = {
  ok: 'Reading', idle: 'Quiet', missing: 'File missing', denied: 'No permission',
  unparsed: 'Not understood', unsupported: 'Cannot be read', error: 'Error',
};
const _IPI_STATE_CLASS = {
  ok: 'c-green', idle: 'hint', missing: 'c-amber', denied: 'c-red',
  unparsed: 'c-amber', unsupported: 'c-amber', error: 'c-red',
};
const _IPI_FMT = {
  combined: 'Standard', custom: "From the server's config", json: 'JSON',
  generic: 'Guessed', native: 'ModSecurity native',
};

function _ipiScoreClass(s) {
  if (s == null) return 'hint';
  return s >= 90 ? 'c-red' : s >= 50 ? 'c-amber' : 'c-green';
}

function _ipiWire() {
  if (_ipiWired) return;
  _ipiWired = true;
  const att = document.getElementById('ipintel-att-tbody');
  if (att) att.addEventListener('click', (ev) => {
    const t = ev.target.closest('button[data-ipi-toggle]');
    if (t) {
      const ip = t.dataset.ipiToggle;
      if (_ipiOpen.has(ip)) _ipiOpen.delete(ip); else _ipiOpen.add(ip);
      _ipiRenderAttackers();
      return;
    }
    const ban = ev.target.closest('button[data-ipi-ban]');
    if (ban) { openIpIntelBan(ban.dataset.ipiBan); return; }
    const unban = ev.target.closest('button[data-ipi-unban]');
    if (unban) { unbanIpIntel(unban.dataset.ipiUnban); return; }
    const b = ev.target.closest('button[data-ip][data-dev]');
    if (b) blockIpIntel(b.dataset.dev, b.dataset.ip);
  });
  const blk = document.getElementById('ipintel-blk-tbody');
  if (blk) blk.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-ip][data-dev]');
    if (b) unblockIpIntel(b.dataset.dev, b.dataset.ip);
  });
  const f = document.getElementById('ipintel-filter');
  if (f) f.addEventListener('input', () => _ipiRenderAttackers());
}

async function loadIpIntel() {
  tableCtl.wireSortOnly('ipintel-att-thead', 'ipintel-att', () => _ipiRenderAttackers());
  tableCtl.wireSortOnly('ipintel-blk-thead', 'ipintel-blk', () => _ipiRenderBlocks());
  tableCtl.wireSortOnly('ipintel-src-thead', 'ipintel-src', () => _ipiRenderSources());
  tableCtl.wireSortOnly('ipintel-edge-thead', 'ipintel-edge', () => _ipiRenderEdge());
  _ipiWire();
  const d = await api('GET', '/ip-intel').catch(() => null);
  _ipiData = (d && !d.error) ? d : {attackers: [], blocks: [], sensors: [], settings: {}};
  _ipiAdmin = !!_ipiData.is_admin;
  document.getElementById('ipintel-settings-card').hidden = !_ipiAdmin;
  document.getElementById('ipintel-sensor-card').hidden = !_ipiAdmin;
  document.getElementById('ipintel-limits-card').hidden = !_ipiAdmin;
  document.getElementById('ipintel-lookup-card').hidden = !_ipiAdmin;
  // The edge feeds belong to the instance: only the operator is sent their state.
  const edge = !!(_ipiAdmin && _ipiData.edge);
  document.getElementById('ipintel-edge-card').hidden = !edge;
  document.getElementById('ipintel-edge-status-card').hidden = !edge;
  // The list RemotePower keeps in Cloudflare belongs to the instance as well.
  document.getElementById('ipintel-edgelist-card').hidden = !(_ipiAdmin && _ipiData.edge_list);
  if (_ipiAdmin) _ipiFillSettings(_ipiData.settings || {}, _ipiData.budget || {});
  _ipiRenderAttackers();
  _ipiRenderBlocks();
  _ipiRenderSources();
  _ipiRenderEdge();
  _ipiRenderEdgeList();
}

function _ipiFillSettings(s, budget) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  const chk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
  chk('ipintel-lookup', s.lookup_enabled);
  chk('ipintel-report', s.report_enabled);
  chk('ipintel-block', s.block_enabled);
  chk('ipintel-sensor', s.sensor_enabled);
  set('ipintel-sensor-paths', (s.sensor_paths || []).join('\n'));
  set('ipintel-min-score', s.block_min_score ?? 90);
  set('ipintel-ttl', s.block_ttl_hours ?? 24);
  set('ipintel-max-hour', s.block_max_per_hour ?? 20);
  set('ipintel-report-min', s.report_min_count ?? 10);
  set('ipintel-lookup-budget', s.daily_lookup_budget ?? 900);
  set('ipintel-report-budget', s.daily_report_budget ?? 900);
  set('ipintel-cache-hours', s.cache_hours ?? 24);
  set('ipintel-comment', s.report_comment || '');
  set('ipintel-never', (s.never_block || []).join('\n'));
  chk('ipintel-edge', s.edge_enabled);
  chk('ipintel-edge-cf', s.edge_cf_events);
  chk('ipintel-edge-trap', s.edge_trap);
  chk('ipintel-edge-lists', s.edge_count_list_rules);
  set('ipintel-edge-account', s.edge_account_id || '');
  set('ipintel-edge-zones', (s.edge_zone_ids || []).join('\n'));
  set('ipintel-edge-workers', (s.edge_workers || []).join('\n'));
  set('ipintel-edge-minutes', s.edge_poll_minutes ?? 10);
  set('ipintel-edge-report-after', s.edge_report_after ?? 1);
  const et = document.getElementById('ipintel-edge-token');
  if (et) { et.value = ''; et.placeholder = s.edge_token_set ? '••••••••  (saved — leave blank to keep)' : ''; }
  const ec = document.getElementById('ipintel-edge-clear');
  if (ec) ec.hidden = !s.edge_token_set;
  chk('ipintel-edgelist', s.edgelist_enabled);
  set('ipintel-edgelist-name', s.edgelist_name || '');
  chk('ipintel-edgelist-own', s.edgelist_own);
  chk('ipintel-edgelist-abuseipdb', s.edgelist_abuseipdb);
  chk('ipintel-edgelist-sniffcat', s.edgelist_sniffcat);
  set('ipintel-edgelist-own-score', s.edgelist_own_score ?? 75);
  set('ipintel-edgelist-own-days', s.edgelist_own_days ?? 14);
  set('ipintel-edgelist-abuseipdb-conf', s.edgelist_abuseipdb_conf ?? 75);
  set('ipintel-edgelist-abuseipdb-limit', s.edgelist_abuseipdb_limit ?? 8000);
  set('ipintel-edgelist-sniffcat-conf', s.edgelist_sniffcat_conf ?? 80);
  set('ipintel-edgelist-sniffcat-limit', s.edgelist_sniffcat_limit ?? 2000);
  set('ipintel-edgelist-hours', s.edgelist_hours ?? 6);
  set('ipintel-edgelist-max', s.edgelist_max ?? 10000);
  set('ipintel-edgelist-always', (s.edgelist_always || []).join('\n'));
  const lt = document.getElementById('ipintel-edgelist-token');
  if (lt) { lt.value = ''; lt.placeholder = s.edge_list_token_set ? '••••••••  (saved — leave blank to keep)' : ''; }
  const lc = document.getElementById('ipintel-edgelist-clear');
  if (lc) lc.hidden = !s.edge_list_token_set;
  for (const [p, isSet] of [['abuseipdb', s.abuseipdb_key_set], ['sniffcat', s.sniffcat_key_set]]) {
    const el = document.getElementById(`ipintel-${p}-key`);
    if (el) { el.value = ''; el.placeholder = isSet ? '••••••••  (saved — leave blank to keep)' : ''; }
  }
  const b = document.getElementById('ipintel-budget');
  if (b) {
    const cap = s.daily_lookup_budget ?? 900;
    const rcap = s.daily_report_budget ?? 900;
    b.textContent = `Lookups today: AbuseIPDB ${budget.abuseipdb || 0} / ${cap}, SniffCat ${budget.sniffcat || 0} / ${cap}. ` +
      `Reports today: AbuseIPDB ${budget['report:abuseipdb'] || 0} / ${rcap}, SniffCat ${budget['report:sniffcat'] || 0} / ${rcap}`;
  }
}

// Why an address was not blocked, from the hosts that saw it. The edge's own reason (it
// never reached a host) counts only when no host saw the address; otherwise it would
// hide the reason that applies to the host, and say there is no host when there is one.
function _ipiNotBlockedReason(a, edgeHolds) {
  const withWhy = (a.devices || []).filter(d => d.not_blocked);
  const hosts = withWhy.filter(d => !String(d.device_id || '').startsWith('edge:'));
  if (edgeHolds) return (hosts[0] || {}).not_blocked || '';   // the edge is where it is blocked
  return (hosts[0] || withWhy[0] || {}).not_blocked || '';
}

// What the edge does with an address: 'listed' (the list holds it), 'banned' (a ban by
// hand is in the list) or 'waiting' (a ban by hand the list does not hold yet). The page
// trusts a stamp only while the blocklist is on; a stamp outlives a list that was switched off.
function _ipiEdgeState(a) {
  const el = (_ipiData || {}).edge_list;
  const listed = !!(a.in_list && el && el.enabled);
  if (a.edge_ban) return listed ? 'banned' : 'waiting';
  return listed ? 'listed' : '';
}

function _ipiStatus(a) {
  const parts = [];
  for (const p of Object.keys(a.reported || {})) parts.push(`reported to ${p === 'abuseipdb' ? 'AbuseIPDB' : 'SniffCat'}`);
  const edge = _ipiEdgeState(a);
  if (edge) parts.push(_IPI_BAN_WORD[{listed: 'in_list', banned: 'edge_ban', waiting: 'edge_wait'}[edge]]);
  const blocked = new Set((_ipiData.blocks || []).filter(b => b.ip === a.ip).map(b => b.device_id));
  if (blocked.size) parts.push(`blocked on ${blocked.size}`);
  const why = _ipiNotBlockedReason(a, edge === 'listed' || edge === 'banned');
  if (!blocked.size && why) parts.push(`not blocked: ${why}`);
  const errs = Object.entries(a.errors || {}).filter(([, e]) => e);
  if (errs.length) parts.push(errs.map(([p, e]) => `${p}: ${e}`).join(', '));
  return parts.join(' · ');
}

// The status cell for display. _ipiStatus() above is the plain string the table sorts
// on; this is the same sentence with every fixed phrase in a span of its own, because
// the language engine translates whole text nodes and a joined sentence is not one.
// The reasons come from ip_intel.py and ip_intel_handlers.py in English; anything this
// does not recognise (a provider's own error text) is shown unchanged.
function _ipiPhrase(text) { return `<span>${escHtml(text)}</span>`; }
function _ipiReason(why) {
  const score = /^score (\d+) is below (\d+)$/.exec(why);
  if (score) return `${_ipiPhrase('score below threshold')} (${score[1]} &lt; ${score[2]})`;
  const rep = /^not reported: (.+)$/.exec(why);
  if (rep) {
    const few = /^(\d+) of (\d+) attempts so far$/.exec(rep[1]);
    if (few) return `${_ipiPhrase('not reported:')} ${few[1]} / ${few[2]} ${_ipiPhrase('attempts so far')}`;
    const refs = /^(\d+) of (\d+) (WAF|Cloudflare) refusals so far$/.exec(rep[1]);
    if (refs) {
      const what = refs[3] === 'WAF' ? _ipiPhrase('WAF refusals so far') : _ipiPhrase('Cloudflare refusals so far');
      return `${_ipiPhrase('not reported:')} ${refs[1]} / ${refs[2]} ${what}`;
    }
    return `${_ipiPhrase('not reported:')} ${_ipiPhrase(rep[1])}`;
  }
  return _ipiPhrase(why);
}
function _ipiStatusHtml(a) {
  const parts = [];
  for (const p of Object.keys(a.reported || {})) {
    parts.push(`${_ipiPhrase('reported to')} ${escHtml(p === 'abuseipdb' ? 'AbuseIPDB' : 'SniffCat')}`);
  }
  const edge = _ipiEdgeState(a);
  if (edge) parts.push(_ipiPhrase(_IPI_BAN_WORD[{listed: 'in_list', banned: 'edge_ban', waiting: 'edge_wait'}[edge]]));
  const blocked = new Set((_ipiData.blocks || []).filter(b => b.ip === a.ip).map(b => b.device_id));
  if (blocked.size) parts.push(`${_ipiPhrase('blocked on')} ${blocked.size}`);
  const why = _ipiNotBlockedReason(a, edge === 'listed' || edge === 'banned');
  if (!blocked.size && why) parts.push(`${_ipiPhrase('not blocked:')} ${_ipiReason(why)}`);
  const errs = Object.entries(a.errors || {}).filter(([, e]) => e);
  if (errs.length) parts.push(errs.map(([p, e]) => `${escHtml(p)}: ${_ipiReason(e)}`).join(', '));
  return parts.join(' · ');
}

function _ipiClassName(id) { return _IPI_CLASS[id] || String(id); }

// Plain text for filtering: what the logs showed, in the words the page uses.
function _ipiEvidenceText(a) {
  const e = a.evidence;
  if (!e) return '';
  return [(e.classes || []).map(c => _ipiClassName(c.id)).join(' '), (e.jails || []).join(' '),
    (e.cves || []).join(' '), (e.rules || []).join(' ')].join(' ');
}

function _ipiEvidenceWeight(a) {
  const e = a.evidence;
  return e ? (e.classes || []).reduce((n, c) => n + (c.n || 0), 0) : 0;
}

function _ipiEvidenceHtml(a) {
  const e = a.evidence;
  if (!e) return '<span class="hint">—</span>';
  const chips = (e.classes || []).slice(0, 3).map(c =>
    `<span class="ipi-chip">${_ipiPhrase(_ipiClassName(c.id))} <span class="hint">×${escHtml(String(c.n))}</span></span>`).join('');
  const notes = [];
  if (e.confirmed) {
    const who = e.confirmed === 'the edge honeypot' ? _ipiPhrase('the edge honeypot') : escHtml(e.confirmed);
    notes.push(`${_ipiPhrase('confirmed by')} ${who}`);
  }
  if (e.ans) notes.push(`<span class="c-amber">${_ipiPhrase('answered')} ${escHtml(String(e.ans))}</span>`);
  const open = _ipiOpen.has(a.ip);
  return `${chips}${notes.length ? `<div class="hint fs-11">${notes.join(' · ')}</div>` : ''}` +
    `<button class="btn-icon" data-ipi-toggle="${escAttr(a.ip)}" aria-expanded="${open}">${_ipiPhrase(open ? 'Hide details' : 'Details')}</button>`;
}

function _ipiProviderName(p) { return p === 'abuseipdb' ? 'AbuseIPDB' : p === 'sniffcat' ? 'SniffCat' : String(p); }

// The detail row: where the address was seen, which rules fired, and exactly what was sent
// to each service. Everything dynamic is escaped; the comment is public text RemotePower
// built from fixed phrases and numbers, shown as sent.
function _ipiDetailHtml(a) {
  const e = a.evidence || {};
  const facts = [];
  const seen = (e.sources || []).map(s =>
    `${_ipiPhrase(_IPI_SOURCE[s.id] || s.id)}${s.n ? ' ×' + escHtml(String(s.n)) : ''}`);
  if (e.ans) seen.push(`${_ipiPhrase('answered')} ${escHtml(String(e.ans))}`);
  if (e.blk) seen.push(`${_ipiPhrase('refused')} ${escHtml(String(e.blk))}`);
  if (seen.length) facts.push([_ipiPhrase('Seen in'), seen.join(' · ')]);
  const ids = [].concat(e.rules || [], e.cves || [], e.jails || []).map(x => `<code>${escHtml(x)}</code>`);
  if (ids.length) facts.push([_ipiPhrase('Rules'), ids.join(' ')]);
  for (const r of a.report_log || []) {
    const body = r.error
      ? `<span class="c-red">${_ipiReason(r.error)}</span>`
      : `${_ipiPhrase('categories')} ${escHtml((r.cats || []).join(', '))} · ${escHtml(timeAgo(r.at))}`;
    facts.push([`${_ipiPhrase('reported to')} ${escHtml(_ipiProviderName(r.prov))}`,
      `${body}<code class="ipi-comment">${escHtml(r.comment || '')}</code>`]);
  }
  return `<dl class="ipi-facts">${facts.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
}

function _ipiRenderAttackers() {
  const tb = document.getElementById('ipintel-att-tbody');
  if (!tb || !_ipiData) return;
  const q = ((document.getElementById('ipintel-filter') || {}).value || '').trim().toLowerCase();
  let rows = _ipiData.attackers || [];
  if (q) rows = rows.filter(a => `${a.ip} ${a.country} ${a.isp} ${(a.devices || []).map(d => d.name).join(' ')} ${_ipiEvidenceText(a)}`
    .toLowerCase().includes(q));
  rows = tableCtl.sortRows('ipintel-att', rows, a => ({
    ip: a.ip, score: a.score ?? -1, reports: a.reports || 0, country: a.country || '',
    isp: a.isp || '', hosts: (a.devices || []).length, evidence: _ipiEvidenceWeight(a),
    last_seen: a.last_seen || 0, status: _ipiStatus(a),
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="10" class="hint">${escHtml('No attackers recorded yet.')}</td></tr>`;
    return;
  }
  const blocked = new Set((_ipiData.blocks || []).map(b => `${b.device_id}|${b.ip}`));
  tb.innerHTML = rows.map(a => {
    const hosts = (a.devices || []).map(d =>
      `${escHtml(d.name)} <span class="hint">(${escHtml(String(d.count || 0))})</span>`).join(', ');
    const target = (a.devices || []).find(d => !String(d.device_id).startsWith('edge:')
      && !blocked.has(`${d.device_id}|${a.ip}`));
    const btn = target
      ? `<button class="btn-icon" data-ip="${escAttr(a.ip)}" data-dev="${escAttr(target.device_id)}" aria-label="Block on host"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg> Block</button>`
      : '';
    const icon = d => `<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`;
    const shield = '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>';
    const banBtn = `<button class="btn-icon" data-ipi-ban="${escAttr(a.ip)}" aria-label="Ban">${icon(shield + '<path d="m4.243 5.21 14.39 12.472"/>')} Ban</button>`;
    // Unban only where there is something to lift: a ban at the edge, or a block on a host.
    const liftable = a.edge_ban || (_ipiData.blocks || []).some(b => b.ip === a.ip);
    const unbanBtn = liftable
      ? `<button class="btn-icon" data-ipi-unban="${escAttr(a.ip)}" aria-label="Unban">${icon(shield + '<path d="m9 12 2 2 4-4"/>')} Unban</button>`
      : '';
    const score = a.score == null ? '—' : String(a.score);
    return `<tr>
      <td class="ff-mono">${escHtml(a.ip)}</td>
      <td class="${_ipiScoreClass(a.score)}">${escHtml(score)}</td>
      <td>${escHtml(String(a.reports || 0))}</td>
      <td>${escHtml(a.country || '')}</td>
      <td>${escHtml(a.isp || '')}</td>
      <td>${hosts}</td>
      <td>${_ipiEvidenceHtml(a)}</td>
      <td>${escHtml(timeAgo(a.last_seen))}</td>
      <td class="hint fs-11">${_ipiStatusHtml(a)}</td>
      <td><div class="ipi-actions">${btn}${banBtn}${unbanBtn}</div></td>
    </tr>${_ipiOpen.has(a.ip) ? `<tr class="ipi-detail"><td colspan="10">${_ipiDetailHtml(a)}</td></tr>` : ''}`;
  }).join('');
}

function _ipiRenderSources() {
  const tb = document.getElementById('ipintel-src-tbody');
  const notes = document.getElementById('ipintel-src-notes');
  if (!tb || !_ipiData) return;
  let rows = [];
  for (const h of _ipiData.sensors || []) {
    for (const s of h.sources || []) rows.push(Object.assign({host: h.name, at: h.at}, s));
  }
  rows = tableCtl.sortRows('ipintel-src', rows, r => ({
    host: r.host || '', kind: r.kind || '', path: r.path || '', fmt: r.fmt || '',
    lines: r.lines || 0, parsed: r.lines ? (r.parsed || 0) / r.lines : 1, events: r.events || 0,
    at: r.at || 0, state: r.state || '',
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="9" class="hint">${escHtml(_ipiData.sensor_enabled
      ? 'No host has reported its logs yet. Agents pick the setting up on their next heartbeat.'
      : 'The log sensor is off. An administrator can turn it on under Log sensor.')}</td></tr>`;
  } else {
    tb.innerHTML = rows.map(r => `<tr>
      <td>${escHtml(r.host)}</td>
      <td>${_ipiPhrase(_IPI_SOURCE[r.kind] || r.kind)}</td>
      <td class="ff-mono fs-11">${escHtml(r.path)}</td>
      <td>${r.fmt ? _ipiPhrase(_IPI_FMT[r.fmt] || r.fmt) : ''}</td>
      <td>${escHtml(String(r.lines || 0))}</td>
      <td>${escHtml(String(r.parsed || 0))}</td>
      <td>${escHtml(String(r.events || 0))}</td>
      <td>${escHtml(timeAgo(r.at))}</td>
      <td class="${_IPI_STATE_CLASS[r.state] || 'hint'}">${_ipiPhrase(_IPI_STATE[r.state] || r.state || '')}</td>
    </tr>`).join('');
  }
  if (!notes) return;
  const out = [];
  let behindCloudflare = false;
  for (const h of _ipiData.sensors || []) {
    const cf = (h.ignored || {}).cloudflare;
    if (cf) {
      behindCloudflare = true;
      out.push(`<p class="hint">${escHtml(h.name)}: ${_ipiPhrase('requests from Cloudflare addresses were ignored')} (${escHtml(String(cf))})</p>`);
    }
    if (h.throttled) {
      out.push(`<p class="hint">${escHtml(h.name)}: ${_ipiPhrase('over the hourly limit, some addresses were skipped')} (${escHtml(String(h.throttled))})</p>`);
    }
  }
  // Said once, after the hosts it applies to, not once for each.
  if (behindCloudflare) {
    out.push(`<p class="hint">${_ipiPhrase("Your web server is logging Cloudflare, not the visitor. Restore the visitor's address (nginx real_ip_header, Apache mod_remoteip) and they will be counted.")}</p>`);
  }
  notes.innerHTML = out.join('');
}

function _ipiRenderBlocks() {
  const tb = document.getElementById('ipintel-blk-tbody');
  if (!tb || !_ipiData) return;
  const rows = tableCtl.sortRows('ipintel-blk', _ipiData.blocks || [], b => ({
    ip: b.ip, name: b.name || '', score: b.score ?? -1, by: b.by || '',
    at: b.at || 0, until: b.until || 0,
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="7" class="hint">${escHtml('No active blocks.')}</td></tr>`;
    return;
  }
  const now = Date.now() / 1000;
  tb.innerHTML = rows.map(b => {
    const left = Math.max(0, (b.until || 0) - now);
    return `<tr>
      <td class="ff-mono">${escHtml(b.ip)}</td>
      <td>${escHtml(b.name || b.device_id)}</td>
      <td>${escHtml(b.score == null ? '—' : String(b.score))}</td>
      <td>${escHtml(b.by === 'auto' ? 'automatic' : (b.by || ''))}</td>
      <td>${escHtml(timeAgo(b.at))}</td>
      <td>${escHtml(left < 60 ? '< 1m' : _fmtDuration(left))}</td>
      <td><button class="btn-icon" data-ip="${escAttr(b.ip)}" data-dev="${escAttr(b.device_id)}" aria-label="Lift block"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg> Unblock</button></td>
    </tr>`;
  }).join('');
}

// The edge feeds' last turn: what each read, what it counted and what it set aside, and
// why. Every word is from a fixed table; the one free-text field is Cloudflare's own
// error sentence, escaped.
function _ipiRenderEdge() {
  const tb = document.getElementById('ipintel-edge-tbody');
  const notes = document.getElementById('ipintel-edge-notes');
  if (!tb || !_ipiData || !_ipiData.edge) return;
  const e = _ipiData.edge;
  const rows = ['cf', 'trap'].map(feed => {
    const f = e[feed] || {};
    const aside = Object.entries(f.ignored || {}).filter(([, n]) => n);
    return {feed, f, key: !e.enabled ? 'off' : (f.state || 'waiting'), aside,
      asideN: aside.reduce((n, [, c]) => n + c, 0)};
  });
  const sorted = tableCtl.sortRows('ipintel-edge', rows, r => ({
    feed: _IPI_FEED[r.feed], state: _IPI_FEED_STATE[r.key] || r.key, at: r.f.at || 0,
    read: r.f.rows ?? r.f.hits ?? 0, kept: r.f.kept || 0, aside: r.asideN,
  }));
  tb.innerHTML = sorted.map(r => {
    const f = r.f;
    const on = e.enabled && f.state;
    const asideHtml = r.aside.map(([k, n]) => `${_ipiPhrase(_IPI_ASIDE[k] || k)} ×${escHtml(String(n))}`).join(', ');
    return `<tr>
      <td>${_ipiPhrase(_IPI_FEED[r.feed])}${(f.zones || []).length ? `<div class="hint fs-11">${(f.zones || []).slice(0, 6).map(z => escHtml(z.name)).join(', ')}</div>` : ''}</td>
      <td class="${_IPI_FEED_STATE_CLASS[r.key] || 'hint'}">${_ipiPhrase(_IPI_FEED_STATE[r.key] || r.key)}${f.error ? `<div class="hint fs-11">${escHtml(f.error)}</div>` : ''}${r.key === 'ok' && f.mode && f.mode !== 'groups' ? `<div class="hint fs-11">${_ipiPhrase('Cloudflare refused the grouped view, so the events are read one at a time.')}</div>` : ''}</td>
      <td>${on && f.at ? escHtml(timeAgo(f.at)) : ''}</td>
      <td>${escHtml(String(f.rows ?? f.hits ?? 0))}</td>
      <td>${escHtml(String(f.kept || 0))}</td>
      <td class="hint fs-11">${asideHtml}</td>
    </tr>`;
  }).join('');
  if (!notes) return;
  const out = [];
  if (e.cf && e.cf.rules_unreadable) {
    out.push(`<p class="hint">${_ipiPhrase('Rules could not be read, so a rule that also blocks an IP list cannot be told apart.')}</p>`);
  }
  for (const feed of ['cf', 'trap']) {
    if ((e[feed] || {}).truncated) {
      out.push(`<p class="hint">${_ipiPhrase(_IPI_FEED[feed])}: ${_ipiPhrase('More events than one read can hold; some were not counted.')}</p>`);
    }
  }
  notes.innerHTML = out.join('');
}

// The newer of the last sync and the last preview: a preview is what a sync would do, so
// it is shown until something real happens after it.
function _ipiListCurrent(el) {
  const last = el.last || {}, pre = el.preview || {};
  return (pre.at || 0) > (last.at || 0) ? pre : last;
}

function _ipiListNeedsAdopt(el) {
  const cur = _ipiListCurrent(el);
  return !!(cur.needs_adopt || cur.state === 'needs_adopt');
}

function _ipiListSrc(k) {
  const name = _IPI_LIST_SRC[k] || k;
  return (k === 'abuseipdb' || k === 'sniffcat') ? escHtml(name) : _ipiPhrase(name);
}

// A reason from the server. One of them ends in Cloudflare's own sentence, which is
// shown escaped after the fixed words.
function _ipiListWhy(why) {
  const pre = _IPI_LIST_WORD.token_prefix;
  const text = String(why);
  if (text.startsWith(pre + ' ')) return `${_ipiPhrase(pre)} ${escHtml(text.slice(pre.length + 1))}`;
  return _ipiPhrase(text);
}

// The list's last turn. Every fixed phrase is a span of its own; the free text is a
// provider's or Cloudflare's own sentence, escaped.
function _ipiRenderEdgeList() {
  const box = document.getElementById('ipintel-edgelist-status');
  const el = _ipiData && _ipiData.edge_list;
  if (!box || !el) return;
  const W = _IPI_LIST_WORD;
  const cur = _ipiListCurrent(el);
  const fact = (label, v) => `${_ipiPhrase(label)} ${escHtml(String(v ?? 0))}`;
  const out = [];
  if (!cur.state) {
    out.push(`<div class="hint">${_ipiPhrase(el.enabled ? _IPI_LIST_STATE.waiting : W.off)}</div>`);
    box.innerHTML = out.join('');
    return;
  }
  const st = cur.state;
  out.push(`<div><span class="${_IPI_LIST_STATE_CLASS[st] || 'hint'}">${_ipiPhrase(_IPI_LIST_STATE[st] || st)}</span>` +
    `${cur.at ? ` · ${escHtml(timeAgo(cur.at))}` : ''}${cur.why ? ` · ${_ipiListWhy(cur.why)}` : ''}</div>`);
  if (cur.needs_adopt && st !== 'needs_adopt') {
    out.push(`<div class="hint">${_ipiPhrase(_IPI_LIST_WHY[4])}</div>`);
  }
  const l = cur.list || {};
  if (l.name) {
    const who = !l.exists ? W.missing : l.managed ? W.managed : W.foreign;
    out.push(`<div class="hint fs-11">${_ipiPhrase(W.list)} <code>${escHtml(l.name)}</code> · ${_ipiPhrase(who)}` +
      `${l.exists && l.items != null ? ` · ${escHtml(String(l.items))} ${_ipiPhrase(W.entries)}` : ''}</div>`);
  }
  if (cur.size != null) {
    out.push(`<div class="hint fs-11">${[fact(W.current, cur.current), fact(W.should, cur.size),
      fact(W.added, cur.added), fact(W.removed, cur.removed)].join(' · ')}</div>`);
    const room = [fact(W.room, cur.capacity)];
    if (cur.trimmed) room.push(fact(W.trimmed, cur.trimmed));
    if ((cur.dropped || {}).protected) room.push(fact(W.protected, cur.dropped.protected));
    out.push(`<div class="hint fs-11">${room.join(' · ')}</div>`);
    const kept = cur.kept || {};
    out.push(`<div class="hint fs-11">${_ipiPhrase(W.from)}: ` +
      ['always', 'own', 'abuseipdb', 'sniffcat'].map(k => `${_ipiListSrc(k)} ${escHtml(String(kept[k] || 0))}`).join(' · ') + '</div>');
  }
  for (const [k, s] of Object.entries(cur.sources || {})) {
    out.push(`<div class="hint fs-11">${_ipiListSrc(k)}: ${escHtml(String(s.n || 0))} ${_ipiPhrase(W.addresses)}` +
      `${s.at ? ` · ${escHtml(timeAgo(s.at))}` : ''} · ${_ipiPhrase(s.from === 'copy' ? W.copy : W.downloaded)}` +
      `${s.error ? ` · ${escHtml(s.error)}` : ''}</div>`);
  }
  for (const [k, e] of Object.entries(cur.failed || {})) {
    out.push(`<div class="hint fs-11"><span class="c-red">${_ipiListSrc(k)}</span>: ${escHtml(String(e))}</div>`);
  }
  for (const [label, rows, sign] of [[W.added, cur.added_sample, '+'], [W.removed, cur.removed_sample, '\u2212']]) {
    if (rows && rows.length) {
      out.push(`<div class="hint fs-11 mt-8">${_ipiPhrase(label)}</div>` +
        `<div class="ff-mono fs-11">${rows.map(x => `${sign} ${escHtml(String(x))}`).join('<br>')}</div>`);
    }
  }
  if (st === 'held' && cur.can_force) {
    out.push(`<div class="mt-8"><button class="btn-icon" data-action="syncIpIntelListForce">` +
      `<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg> ` +
      `${_ipiPhrase(W.sync_anyway)}</button></div>`);
  }
  box.innerHTML = out.join('');
}

async function previewIpIntelList() {
  const box = document.getElementById('ipintel-edgelist-status');
  if (!box || !_ipiData || !_ipiData.edge_list) return;
  box.textContent = '…';
  const r = await api('POST', '/ip-intel/edge-list/preview', {}).catch(() => null);
  if (!r || r.error) { box.textContent = (r && r.error) || _IPI_LIST_WORD.preview_failed; return; }
  _ipiData.edge_list.preview = r.result;
  _ipiRenderEdgeList();
}

async function _ipiSyncList(opts) {
  const box = document.getElementById('ipintel-edgelist-status');
  if (!box || !_ipiData || !_ipiData.edge_list) return;
  box.textContent = '…';
  const r = await api('POST', '/ip-intel/edge-list/sync', opts).catch(() => null);
  if (!r || r.error) { box.textContent = (r && r.error) || _IPI_LIST_WORD.sync_failed; return; }
  _ipiData.edge_list.last = r.result;
  _ipiData.edge_list.pending = !!r.result.op;
  _ipiRenderEdgeList();
  // The page did not know the list was not ours when the button was pressed. The server
  // left it alone and said so, so ask now: one press is enough.
  if (r.result.state === 'needs_adopt' && !opts.adopt && await _ipiConfirmAdopt()) {
    await _ipiSyncList(Object.assign({}, opts, {adopt: true}));
  }
}

// The take-over question, asked before a sync replaces a list RemotePower did not create.
async function _ipiConfirmAdopt() {
  const d = _IPI_LIST_DIALOG.adopt;
  return uiConfirm({title: d.title, message: d.message, confirmText: d.confirm, danger: true});
}

async function syncIpIntelList() {
  const el = (_ipiData || {}).edge_list || {};
  const adopt = _ipiListNeedsAdopt(el);
  if (adopt && !(await _ipiConfirmAdopt())) return;
  await _ipiSyncList(adopt ? {adopt: true} : {});
}

async function syncIpIntelListForce() {
  const d = _IPI_LIST_DIALOG.force;
  const ok = await uiConfirm({title: d.title, message: d.message, confirmText: d.confirm, danger: true});
  if (!ok) return;
  const el = (_ipiData || {}).edge_list || {};
  await _ipiSyncList({force: true, adopt: _ipiListNeedsAdopt(el)});
}

async function clearIpIntelEdgeToken() {
  const d = _IPI_EDGE_DIALOG.token;
  const ok = await uiConfirm({title: d.title, message: d.message, confirmText: d.confirm, danger: true});
  if (!ok) return;
  const r = await api('POST', '/ip-intel/settings', {clear_edge_token: true}).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not save', 'error'); return; }
  toast('Saved', 'success');
  loadIpIntel();
}

async function clearIpIntelListToken() {
  const d = _IPI_LIST_DIALOG.token;
  const ok = await uiConfirm({title: d.title, message: d.message, confirmText: d.confirm, danger: true});
  if (!ok) return;
  const r = await api('POST', '/ip-intel/settings', {clear_edge_list_token: true}).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not save', 'error'); return; }
  toast('Saved', 'success');
  loadIpIntel();
}

async function testIpIntelEdge() {
  const out = document.getElementById('ipintel-edge-test');
  if (!out) return;
  out.textContent = '…';
  const body = {};
  const tok = document.getElementById('ipintel-edge-token').value.trim();
  const acct = document.getElementById('ipintel-edge-account').value.trim();
  if (tok) body.token = tok;
  if (acct) body.account_id = acct;
  const r = await api('POST', '/ip-intel/edge-test', body).catch(() => null);
  if (!r || r.error) { out.textContent = (r && r.error) || 'Test failed'; return; }
  const lines = [];
  for (const [k, c] of Object.entries(r.checks || {})) {
    const cls = c.state === 'ok' ? 'c-green' : c.state === 'skipped' ? 'hint' : 'c-red';
    let more = '';
    if (k === 'zones' && c.state === 'ok') {
      more = ` · ${escHtml(String(c.n))} ${_ipiPhrase('zones')}${(c.names || []).length ? ': ' + (c.names || []).map(escHtml).join(', ') : ''}`;
    } else if (k === 'rules' && c.state === 'ok') {
      more = (c.rules || []).map(x =>
        `<div class="hint fs-11"><code>${escHtml(x.id)}</code> ${escHtml(x.d || '')}${x.k ? ` — ${_ipiPhrase('also blocks an IP list')}` : ''}</div>`).join('');
    } else if (k === 'firewall' && c.state === 'ok' && c.mode && c.mode !== 'groups') {
      more = ` · ${_ipiPhrase('Cloudflare refused the grouped view, so the events are read one at a time.')}`;
    } else if (c.error && c.state !== 'ok') {
      more = ` · ${escHtml(c.error)}`;
    }
    lines.push(`<div><span class="${cls}">${_ipiPhrase(_IPI_CHECK_STATE[c.state] || c.state)}</span> ` +
      `${_ipiPhrase(_IPI_CHECK[k] || k)}${more}</div>`);
  }
  out.innerHTML = lines.join('');
}

async function saveIpIntelSettings() {
  const v = id => document.getElementById(id);
  const body = {
    lookup_enabled: v('ipintel-lookup').checked,
    report_enabled: v('ipintel-report').checked,
    block_enabled: v('ipintel-block').checked,
    sensor_enabled: v('ipintel-sensor').checked,
    sensor_paths: v('ipintel-sensor-paths').value,
    block_min_score: v('ipintel-min-score').value,
    block_ttl_hours: v('ipintel-ttl').value,
    block_max_per_hour: v('ipintel-max-hour').value,
    report_min_count: v('ipintel-report-min').value,
    daily_lookup_budget: v('ipintel-lookup-budget').value,
    daily_report_budget: v('ipintel-report-budget').value,
    cache_hours: v('ipintel-cache-hours').value,
    report_comment: v('ipintel-comment').value,
    never_block: v('ipintel-never').value,
  };
  // Keys are write-only: only send one the admin actually typed.
  const ak = v('ipintel-abuseipdb-key').value.trim();
  const sk = v('ipintel-sniffcat-key').value.trim();
  if (ak) body.abuseipdb_api_key = ak;
  if (sk) body.sniffcat_api_key = sk;
  if (v('ipintel-edge')) {
    Object.assign(body, {
      edge_enabled: v('ipintel-edge').checked,
      edge_cf_events: v('ipintel-edge-cf').checked,
      edge_trap: v('ipintel-edge-trap').checked,
      edge_count_list_rules: v('ipintel-edge-lists').checked,
      edge_account_id: v('ipintel-edge-account').value.trim(),
      edge_zone_ids: v('ipintel-edge-zones').value,
      edge_workers: v('ipintel-edge-workers').value,
      edge_poll_minutes: v('ipintel-edge-minutes').value,
      edge_report_after: v('ipintel-edge-report-after').value,
    });
    const et = v('ipintel-edge-token').value.trim();
    if (et) body.edge_cloudflare_token = et;
  }
  if (v('ipintel-edgelist')) {
    Object.assign(body, {
      edgelist_enabled: v('ipintel-edgelist').checked,
      edgelist_name: v('ipintel-edgelist-name').value.trim(),
      edgelist_own: v('ipintel-edgelist-own').checked,
      edgelist_abuseipdb: v('ipintel-edgelist-abuseipdb').checked,
      edgelist_sniffcat: v('ipintel-edgelist-sniffcat').checked,
      edgelist_own_score: v('ipintel-edgelist-own-score').value,
      edgelist_own_days: v('ipintel-edgelist-own-days').value,
      edgelist_abuseipdb_conf: v('ipintel-edgelist-abuseipdb-conf').value,
      edgelist_abuseipdb_limit: v('ipintel-edgelist-abuseipdb-limit').value,
      edgelist_sniffcat_conf: v('ipintel-edgelist-sniffcat-conf').value,
      edgelist_sniffcat_limit: v('ipintel-edgelist-sniffcat-limit').value,
      edgelist_hours: v('ipintel-edgelist-hours').value,
      edgelist_max: v('ipintel-edgelist-max').value,
      edgelist_always: v('ipintel-edgelist-always').value,
    });
    const lt = v('ipintel-edgelist-token').value.trim();
    if (lt) body.edge_list_token = lt;
  }
  if (body.block_enabled && !(_ipiData.settings || {}).block_enabled) {
    const ok = await uiConfirm({title: 'Turn on auto-block', message: 'Hosts will drop traffic from addresses that reach the score you set, for the hours you set. Your fleet, your allow-list and recent RemotePower logins are never blocked. Continue?', confirmText: 'Turn on'});
    if (!ok) return;
  }
  const r = await api('POST', '/ip-intel/settings', body).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not save', 'error'); return; }
  toast('Saved', 'success');
  loadIpIntel();
}

async function lookupIpIntel() {
  const ip = document.getElementById('ipintel-lookup-ip').value.trim();
  const out = document.getElementById('ipintel-lookup-result');
  if (!ip) return;
  out.textContent = '…';
  const r = await api('POST', '/ip-intel/lookup', {ip}).catch(() => null);
  if (!r || r.error) { out.textContent = (r && r.error) || 'Lookup failed'; return; }
  const v = r.verdict || {};
  const lines = [];
  lines.push(`${r.ip}: score ${v.score == null ? '—' : v.score}, ${v.reports || 0} reports`);
  if (v.country || v.isp) lines.push([v.country, v.isp, v.usage].filter(Boolean).join(' · '));
  for (const [p, x] of Object.entries(v.providers || {})) lines.push(`${p}: ${x.score} (${x.reports || 0})`);
  for (const [p, e] of Object.entries(r.errors || {})) if (e) lines.push(`${p}: ${e}`);
  out.innerHTML = lines.map(l => `<div>${escHtml(l)}</div>`).join('');
}

let _ipiBanIp = '';

// Open the ban dialog for one address. The edge half is offered only when the operator has
// the blocklist on with a token (the page sends `edge_list` to the operator alone); the host
// half defaults to the hosts that saw the address, or to nothing when none did.
function openIpIntelBan(ip) {
  const a = ((_ipiData || {}).attackers || []).find(x => x.ip === ip);
  if (!a) return;
  _ipiBanIp = ip;
  const B = _IPI_BAN_WORD, $ = id => document.getElementById(id);
  const el = _ipiData.edge_list;
  const ready = !!(el && el.enabled && el.token_set);
  const seen = (a.devices || []).filter(d => !String(d.device_id).startsWith('edge:')).length;
  $('ipintel-ban-ip').textContent = ip;
  const edge = $('ipintel-ban-edge');
  edge.disabled = !ready;
  edge.checked = ready;
  $('ipintel-ban-edge-note').innerHTML = ready ? '' : _ipiPhrase(el ? B.off_note : B.operator_note);
  $('ipintel-ban-hosts').checked = seen > 0;
  const which = $('ipintel-ban-which');
  which.value = seen > 0 ? 'seen' : 'all';
  which.querySelector('option[value="seen"]').disabled = seen === 0;
  $('ipintel-ban-counts').innerHTML = `${_ipiPhrase(B.seen_by)}: ${seen} · ${_ipiPhrase(B.of_hosts)}: ${_ipiData.ban_hosts || 0}`;
  const want = String(((_ipiData.settings || {}).block_ttl_hours) || 24);
  const hours = $('ipintel-ban-hours');
  hours.value = [...hours.options].some(o => o.value === want) ? want : '24';
  $('ipintel-ban-result').innerHTML = '';
  openModal('ipintel-ban-modal');
}

function closeIpIntelBan() { closeModal('ipintel-ban-modal'); }

// What a ban did, in the dialog: the edge half in a word, the hosts half as counts, and a
// host that refused by name with its own reason (escaped; it is free text).
function _ipiBanResultHtml(d) {
  const B = _IPI_BAN_WORD, out = [];
  if (d.edge) {
    const s = d.edge.state;
    const bad = s === 'held' || s === 'error' || s === 'needs_setup';
    const word = s === 'ok' ? B.edge_in : s === 'pending' ? B.edge_applying : s === 'needs_adopt' ? B.edge_adopt : B.edge_later;
    const cls = s === 'ok' ? 'c-green' : bad ? 'c-amber' : 'hint';
    const text = bad && d.edge.why ? _ipiListWhy(d.edge.why) : _ipiPhrase(word);
    out.push(`<div>${_ipiPhrase(B.edge_label)} <span class="${cls}">${text}</span></div>`);
  }
  if (d.hosts) {
    const h = d.hosts, bits = [];
    for (const [n, word] of [[h.queued, B.host_queued], [h.approval, B.host_approval],
                             [h.extended, B.host_extended], [h.skipped, B.host_skipped],
                             [h.deferred, B.host_deferred]]) {
      if (n) bits.push(`${escHtml(String(n))} ${_ipiPhrase(word)}`);
    }
    out.push(`<div>${_ipiPhrase(B.hosts_label)} ${bits.join(' · ') || '0'}</div>`);
    for (const f of h.failed || []) {
      out.push(`<div class="hint fs-11"><span class="c-red">${escHtml(f.name)}</span>: ${escHtml(f.error)}</div>`);
    }
  }
  return out.join('');
}

async function applyIpIntelBan() {
  const $ = id => document.getElementById(id);
  const out = $('ipintel-ban-result');
  const edge = $('ipintel-ban-edge').checked && !$('ipintel-ban-edge').disabled;
  const hosts = $('ipintel-ban-hosts').checked;
  if (!edge && !hosts) { out.innerHTML = _ipiPhrase(_IPI_BAN_WORD.choose); return; }
  const body = {ip: _ipiBanIp, hours: Number($('ipintel-ban-hours').value)};
  if (edge) body.edge = true;
  if (hosts) body.hosts = $('ipintel-ban-which').value;
  out.textContent = '…';
  const r = await api('POST', '/ip-intel/ban', body).catch(() => null);
  if (!r || r.error) { out.textContent = (r && r.error) || _IPI_BAN_WORD.could_not; return; }
  out.innerHTML = _ipiBanResultHtml(r);
  loadIpIntel();
}

async function unbanIpIntel(ip) {
  const d = _IPI_BAN_DIALOG.unban;
  const ok = await uiConfirm({title: d.title, message: d.message, confirmText: d.confirm, danger: true});
  if (!ok) return;
  const body = {ip, hosts: 'all'};
  if ((_ipiData || {}).edge_list) body.edge = true;
  const r = await api('POST', '/ip-intel/unban', body).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not save', 'error'); return; }
  toast(_IPI_BAN_WORD.unbanned, 'success');
  loadIpIntel();
}

async function blockIpIntel(devId, ip) {
  const ok = await uiConfirm({title: 'Block address', message: 'Block this address on the host it attacked? The block lifts itself after the configured number of hours.', confirmText: 'Block', danger: true});
  if (!ok) return;
  const r = await api('POST', '/ip-intel/block', {device_id: devId, ip}).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not block', 'error'); return; }
  toast(r.approval_required ? 'Waiting for a second admin to approve' : 'Block queued', 'success');
  loadIpIntel();
}

async function unblockIpIntel(devId, ip) {
  const r = await api('POST', '/ip-intel/unblock', {device_id: devId, ip}).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not unblock', 'error'); return; }
  toast('Unblock queued', 'success');
  loadIpIntel();
}
