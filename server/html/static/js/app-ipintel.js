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

function _ipiScoreClass(s) {
  if (s == null) return 'hint';
  return s >= 90 ? 'c-red' : s >= 50 ? 'c-amber' : 'c-green';
}

function _ipiWire() {
  if (_ipiWired) return;
  _ipiWired = true;
  const att = document.getElementById('ipintel-att-tbody');
  if (att) att.addEventListener('click', (ev) => {
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
  _ipiWire();
  const d = await api('GET', '/ip-intel').catch(() => null);
  _ipiData = (d && !d.error) ? d : {attackers: [], blocks: [], settings: {}};
  _ipiAdmin = !!_ipiData.is_admin;
  document.getElementById('ipintel-settings-card').hidden = !_ipiAdmin;
  document.getElementById('ipintel-lookup-card').hidden = !_ipiAdmin;
  if (_ipiAdmin) _ipiFillSettings(_ipiData.settings || {}, _ipiData.budget || {});
  _ipiRenderAttackers();
  _ipiRenderBlocks();
}

function _ipiFillSettings(s, budget) {
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  const chk = (id, v) => { const el = document.getElementById(id); if (el) el.checked = !!v; };
  chk('ipintel-lookup', s.lookup_enabled);
  chk('ipintel-report', s.report_enabled);
  chk('ipintel-block', s.block_enabled);
  set('ipintel-min-score', s.block_min_score ?? 90);
  set('ipintel-ttl', s.block_ttl_hours ?? 24);
  set('ipintel-max-hour', s.block_max_per_hour ?? 20);
  set('ipintel-report-min', s.report_min_count ?? 10);
  set('ipintel-never', (s.never_block || []).join('\n'));
  for (const [p, isSet] of [['abuseipdb', s.abuseipdb_key_set], ['sniffcat', s.sniffcat_key_set]]) {
    const el = document.getElementById(`ipintel-${p}-key`);
    if (el) { el.value = ''; el.placeholder = isSet ? '••••••••  (saved — leave blank to keep)' : ''; }
  }
  const b = document.getElementById('ipintel-budget');
  if (b) {
    const cap = s.daily_lookup_budget ?? 900;
    b.textContent = `Lookups today: AbuseIPDB ${budget.abuseipdb || 0} / ${cap}, SniffCat ${budget.sniffcat || 0} / ${cap}`;
  }
}

function _ipiStatus(a) {
  const parts = [];
  for (const p of Object.keys(a.reported || {})) parts.push(`reported to ${p === 'abuseipdb' ? 'AbuseIPDB' : 'SniffCat'}`);
  const blocked = new Set((_ipiData.blocks || []).filter(b => b.ip === a.ip).map(b => b.device_id));
  if (blocked.size) parts.push(`blocked on ${blocked.size}`);
  const why = (a.devices || []).map(d => d.not_blocked).filter(Boolean);
  if (!blocked.size && why.length) parts.push(`not blocked: ${why[0]}`);
  const errs = Object.entries(a.errors || {}).filter(([, e]) => e);
  if (errs.length) parts.push(errs.map(([p, e]) => `${p}: ${e}`).join(', '));
  return parts.join(' · ');
}

function _ipiRenderAttackers() {
  const tb = document.getElementById('ipintel-att-tbody');
  if (!tb || !_ipiData) return;
  const q = ((document.getElementById('ipintel-filter') || {}).value || '').trim().toLowerCase();
  let rows = _ipiData.attackers || [];
  if (q) rows = rows.filter(a => `${a.ip} ${a.country} ${a.isp} ${(a.devices || []).map(d => d.name).join(' ')}`
    .toLowerCase().includes(q));
  rows = tableCtl.sortRows('ipintel-att', rows, a => ({
    ip: a.ip, score: a.score ?? -1, reports: a.reports || 0, country: a.country || '',
    isp: a.isp || '', hosts: (a.devices || []).length, last_seen: a.last_seen || 0,
    status: _ipiStatus(a),
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="9" class="hint">${escHtml('No attackers recorded yet.')}</td></tr>`;
    return;
  }
  const blocked = new Set((_ipiData.blocks || []).map(b => `${b.device_id}|${b.ip}`));
  tb.innerHTML = rows.map(a => {
    const hosts = (a.devices || []).map(d =>
      `${escHtml(d.name)} <span class="hint">(${escHtml(String(d.count || 0))})</span>`).join(', ');
    const target = (a.devices || []).find(d => !blocked.has(`${d.device_id}|${a.ip}`));
    const btn = target
      ? `<button class="btn-icon" data-ip="${escAttr(a.ip)}" data-dev="${escAttr(target.device_id)}" aria-label="Block on host"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg> Block</button>`
      : '';
    const score = a.score == null ? '—' : String(a.score);
    return `<tr>
      <td class="ff-mono">${escHtml(a.ip)}</td>
      <td class="${_ipiScoreClass(a.score)}">${escHtml(score)}</td>
      <td>${escHtml(String(a.reports || 0))}</td>
      <td>${escHtml(a.country || '')}</td>
      <td>${escHtml(a.isp || '')}</td>
      <td>${hosts}</td>
      <td>${escHtml(timeAgo(a.last_seen))}</td>
      <td class="hint fs-11">${escHtml(_ipiStatus(a))}</td>
      <td>${btn}</td>
    </tr>`;
  }).join('');
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

async function saveIpIntelSettings() {
  const v = id => document.getElementById(id);
  const body = {
    lookup_enabled: v('ipintel-lookup').checked,
    report_enabled: v('ipintel-report').checked,
    block_enabled: v('ipintel-block').checked,
    block_min_score: v('ipintel-min-score').value,
    block_ttl_hours: v('ipintel-ttl').value,
    block_max_per_hour: v('ipintel-max-hour').value,
    report_min_count: v('ipintel-report-min').value,
    never_block: v('ipintel-never').value,
  };
  // Keys are write-only: only send one the admin actually typed.
  const ak = v('ipintel-abuseipdb-key').value.trim();
  const sk = v('ipintel-sniffcat-key').value.trim();
  if (ak) body.abuseipdb_api_key = ak;
  if (sk) body.sniffcat_api_key = sk;
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
