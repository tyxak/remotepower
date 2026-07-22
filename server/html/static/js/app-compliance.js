// ══════════════════════════════════════════════════════════════════════════════
//  CIS-style configuration baseline (compliance)
//  Split out of app.js (v3.13.0). Classic script — shares the global scope with
//  app.js (loaded first); calls core helpers (api, escHtml, toast, openModal, …)
//  at runtime. Not a module — do not wrap in an IIFE.
// ══════════════════════════════════════════════════════════════════════════════

// ── v3.4.2: CIS-style configuration baseline ───────────────────────────────
let _cisDisabled = new Set();

async function loadComplianceBaseline() {
  const body = document.getElementById('cis-baseline-body');
  if (!body) return;
  const r = await api('GET', '/compliance/baseline').catch(() => null);
  if (!r || !Array.isArray(r.checks)) { _errorState(body, loadComplianceBaseline, {msg: 'Failed to load baseline.'}); return; }
  _cisDisabled = new Set(r.disabled || []);
  const scoreEl = document.getElementById('cis-score');
  if (scoreEl) {
    const s = r.score;
    scoreEl.textContent = s != null ? s + '%' : 'no data';
    scoreEl.className = 'ro-badge ' + (s == null ? '' : s >= 80 ? 'rs-done' : s >= 50 ? 'rs-paused' : 'rs-failed');
  }
  // Trend sparkline (last ~30 daily samples)
  const trend = document.getElementById('cis-trend');
  if (trend) trend.innerHTML = _cisSparkline(r.history || []);
  // Per-check table — every available check, with an enable/disable toggle.
  const byId = {}; (r.checks || []).forEach(c => { byId[c.id] = c; });
  const _sevRank = { high: 3, medium: 2, low: 1 };
  const rowObjs = (r.available_checks || []).map(ac => {
    const c = byId[ac.id] || { pass: 0, fail: 0, na: 0, failing: [] };
    return { id: ac.id, title: ac.title, severity: ac.severity,
             pass: c.pass || 0, fail: c.fail || 0, na: c.na || 0,
             failing: c.failing || [], on: !_cisDisabled.has(ac.id) };
  });
  const sorted = tableCtl.sortRows('cis_baseline', rowObjs, r => ({
    check: r.title, severity: _sevRank[r.severity] || 0,
    pass: r.pass, fail: r.fail, na: r.na,
  }));
  const rows = sorted.map(c => {
    const failing = (c.failing || []).slice(0, 8).join(', ');
    return `<tr class="${c.on ? '' : 'o-50'}">
      <td><label class="click-row-6"><input type="checkbox" data-change="toggleCisCheck" data-change-arg="${escAttr(c.id)}" ${c.on ? 'checked' : ''}><span>${escHtml(c.title)}</span></label></td>
      <td><span class="sev-pill sev-${c.severity === 'high' ? 'critical' : c.severity === 'medium' ? 'medium' : 'low'}">${escHtml(c.severity)}</span></td>
      <td class="c-green">${c.pass}</td>
      <td class="c-red">${c.fail}</td>
      <td class="c-muted">${c.na}</td>
      <td class="fs-11 c-muted">${escHtml(failing)}${(c.failing || []).length > 8 ? '…' : ''}</td>
    </tr>`;
  }).join('');
  // v3.14.0 #31: one-click remediation for failing, fixable checks. Each Fix
  // runs through the existing queue/approval/audit pipeline and only on hosts
  // where the operator has enabled remediation in device settings.
  const titleById = {}; (r.available_checks || []).forEach(c => { titleById[c.id] = c.title; });
  const remRows = [];
  for (const d of (r.devices || [])) {
    for (const cid of (d.remediable || [])) {
      remRows.push({ device: d.name, device_id: d.device_id, check: cid,
                     title: titleById[cid] || cid, enabled: d.remediation_enabled });
    }
  }
  let remHtml = '';
  if (remRows.length) {
    const remSorted = tableCtl.sortRows('cis_remediation', remRows,
      x => ({ device: x.device, check: x.title }));
    remHtml = `<div class="section-title mt-24">Remediation</div>
      <div class="page-subtitle">One-click fixes for failing checks. Each is queued through your existing approval + audit pipeline (a reboot still needs 4-eyes when that's on), and only on hosts where you've turned on <em>Automatic remediation</em> in device settings.</div>
      <div class="table-card"><table><thead id="cis-rem-thead"><tr><th data-col="device">Device</th><th data-col="check">Failing check</th><th>Action</th></tr></thead><tbody>` +
      remSorted.map(x => `<tr>
        <td>${escHtml(x.device)}</td>
        <td>${escHtml(x.title)}</td>
        <td>${x.enabled
          ? `<button class="btn-icon" data-action="remediateCheck" data-arg="${escAttr(x.device_id)}|${escAttr(x.check)}">Fix</button>`
          : `<span class="hint">remediation off for this host</span>`}</td>
      </tr>`).join('') + `</tbody></table></div>`;
  }
  body.innerHTML = `<div class="fs-12 c-muted mb-6">${r.devices_evaluated} device(s) evaluated.</div>
    <div class="table-card"><table><thead id="cis-baseline-thead"><tr><th data-col="check">Check</th><th data-col="severity">Severity</th><th data-col="pass">Pass</th><th data-col="fail">Fail</th><th data-col="na">N/A</th><th>Failing hosts</th></tr></thead><tbody>${rows}</tbody></table></div>${remHtml}`;
  tableCtl.wireSortOnly('cis-baseline-thead', 'cis_baseline', loadComplianceBaseline);
  if (remRows.length) tableCtl.wireSortOnly('cis-rem-thead', 'cis_remediation', loadComplianceBaseline);
}

// v3.14.0 #31: queue a remediation. arg is "<device_id>|<check_id>".
async function remediateCheck(arg) {
  const [device_id, check_id] = String(arg).split('|');
  const r = await api('POST', '/compliance/remediate', { device_id, check_id }).catch(() => null);
  if (r?.approval_required) toast('Fix parked — a second admin must approve it', 'info');
  else if (r?.ok) toast('Fix queued', 'success');
  else { toast(r?.error || 'Failed to queue fix', 'error'); return; }
  loadComplianceBaseline();
}

function _cisSparkline(hist) {
  if (!hist.length) return '<span class="c-muted fs-14">No trend yet — a daily sample is recorded automatically.</span>';
  const pts = hist.map(h => h.score).filter(s => typeof s === 'number');
  if (!pts.length) return '';
  const max = 100, min = 0, w = 4, h = 28;
  const bars = pts.slice(-40).map(s => {
    const ph = Math.max(2, Math.round((s - min) / (max - min) * h));
    const col = s >= 80 ? 'var(--green)' : s >= 50 ? 'var(--amber)' : 'var(--red)';
    return `<span class="cis-spark-bar" data-h="${ph}" data-bg="${col}" title="${s}%"></span>`;
  }).join('');
  return `<div class="cis-spark" data-barw="${w}">${bars}</div>`;
}

async function toggleCisCheck(id, checked) {
  if (checked) _cisDisabled.delete(id); else _cisDisabled.add(id);
  const r = await api('POST', '/config', { compliance_baseline: { disabled: Array.from(_cisDisabled) } }).catch(() => null);
  if (r?.ok) loadComplianceBaseline();
  else toast(r?.error || 'Failed to update baseline', 'error');
}

// v3.4.2: OpenSCAP deep scans
async function loadScap() {
  const out = document.getElementById('scap-body');
  if (!out) return;
  const r = await api('GET', '/scap').catch(() => null);
  if (!r) { out.innerHTML = '<div class="c-red">Failed to load OpenSCAP results.</div>'; return; }
  const sel = document.getElementById('scap-profile');
  if (sel) {
    // Always refresh: r.profiles is the union actually supported across the
    // fleet once agents have reported (e.g. the ANSSI profiles on Debian),
    // falling back to the built-in superset before the first scan. Preserve the
    // operator's current selection across refreshes.
    const prev = sel.value;
    const profs = (r.profiles && r.profiles.length) ? r.profiles : ['cis'];
    sel.innerHTML = profs.map(p => {
      // 'standard' on the Debian SSG selects no rules — label it so nobody picks
      // it expecting a score.
      const note = p === 'standard' ? ' (minimal — often 0 rules)' : '';
      return `<option value="${escAttr(p)}">${escHtml(p + note)}</option>`;
    }).join('');
    if (prev && profs.includes(prev)) sel.value = prev;
    sel.dataset.filled = '1';
  }
  onScapTargetChange();   // fill the group/tag/device target dropdown
  const avg = document.getElementById('scap-avg');
  if (avg) {
    avg.textContent = r.avg_score != null ? `avg ${r.avg_score}%` : 'no scans';
    avg.className = 'ro-badge ' + (r.avg_score == null ? '' : r.avg_score >= 80 ? 'rs-done' : r.avg_score >= 50 ? 'rs-paused' : 'rs-failed');
  }
  // v3.4.2: cache the rows and render from cache so a sort-header click
  // re-renders locally instead of re-fetching /scap (the old rerender callback
  // was loadScap, which double-fetched and reset the profile dropdown selection
  // mid-interaction).
  _scapLastDevices = r.devices || [];
  _renderScapTable();
}

let _scapLastDevices = [];
function _renderScapTable() {
  const out = document.getElementById('scap-body');
  if (!out) return;
  const devices = _scapLastDevices || [];
  if (!devices.length) { out.innerHTML = '<div class="empty-state">No scans yet. Pick a profile and click <strong>Run scan</strong>.</div>'; return; }
  const sorted = tableCtl.sortRows('scap', devices.slice(), d => ({
    device: d.name,
    score: (d.score == null ? -1 : d.score),
    pass: d.pass || 0, fail: d.fail || 0,
    when: d.ts || 0,
  }));
  const reportCell = (d) => d.has_report
    ? `<button class="btn-icon" data-action="downloadScapReport" data-arg="${escAttr(d.device_id)}" data-arg2="${escAttr(d.name)}" title="Open the full OpenSCAP HTML report">Report</button>`
    : '<span class="hint">—</span>';
  const rows = sorted.map(d => {
    if (!d.available) {
      return `<tr><td>${escHtml(d.name)}</td><td colspan="4" class="c-muted fs-12">not available — ${escHtml(d.reason || 'oscap/SCAP content missing')}</td><td class="fs-11 c-muted">${escHtml(timeAgo(d.ts))}</td><td>${reportCell(d)}</td></tr>`;
    }
    const sc = d.score == null ? '—' : d.score + '%';
    const scCls = d.score == null ? '' : d.score >= 80 ? 'c-green' : d.score >= 50 ? 'c-amber' : 'c-red';
    const top = (d.failed_top || []).slice(0, 6).map(f => escHtml(f.id)).join(', ');
    return `<tr><td>${escHtml(d.name)}</td><td class="${scCls} fw-500">${sc}</td><td class="c-green">${d.pass || 0}</td><td class="c-red">${d.fail || 0}</td><td class="fs-11 c-muted">${escHtml(d.profile || '')} · ${escHtml(d.datastream || '')}<div>${top}${(d.failed_top || []).length > 6 ? '…' : ''}</div></td><td class="fs-11 c-muted">${escHtml(timeAgo(d.ts))}</td><td>${reportCell(d)}</td></tr>`;
  }).join('');
  out.innerHTML = `<div class="table-card"><table><thead id="scap-thead"><tr><th data-col="device">Device</th><th data-col="score">Score</th><th data-col="pass">Pass</th><th data-col="fail">Fail</th><th>Profile / top failures</th><th data-col="when">When</th><th>Report</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  tableCtl.wireSortOnly('scap-thead', 'scap', _renderScapTable);
}

// Open the full OpenSCAP/usg HTML report in a new tab. The endpoint needs the
// X-Token header (a plain link can't send it), so fetch it and stream into the
// tab via a blob URL — same pattern as the posture report.
async function downloadScapReport(devId, name) {
  const w = window.open('', '_blank');
  if (!w) { toast('Allow pop-ups to open the report', 'error'); return; }
  let resp;
  try {
    resp = await fetch('/api/scap/' + encodeURIComponent(devId) + '/report',
                       { headers: { 'X-Token': getToken() } });
  } catch (_) { resp = null; }
  if (!resp || !resp.ok) {
    try { w.close(); } catch (_) {}
    toast('No report available' + (resp ? ' (' + resp.status + ')' : ''), 'error');
    return;
  }
  const blobUrl = URL.createObjectURL(await resp.blob());
  w.location.replace(blobUrl);
  setTimeout(() => { try { URL.revokeObjectURL(blobUrl); } catch (_) {} }, 60000);
}

// v3.4.2: shared target resolver for fleet actions (scan, install). Returns the
// body fragment _resolve_targets understands. `all` expands to the visible
// device ids client-side.
async function _fleetTargetBody(type, value) {
  if (type === 'group') return { group: value };
  if (type === 'tag') return { tag: value };
  if (type === 'device') return { device_ids: [value] };
  const devs = await api('GET', '/devices?slim=1').catch(() => []);
  return { device_ids: (Array.isArray(devs) ? devs : []).map(d => d.id).filter(Boolean) };
}
// Distinct groups / tags / devices across the fleet, for the target dropdowns.
// Cached for the session so opening the install / scan forms is instant.
let _fleetTargetsCache = null;
async function _fleetTargets() {
  if (_fleetTargetsCache) return _fleetTargetsCache;
  const devs = await api('GET', '/devices?slim=1').catch(() => []);
  const list = Array.isArray(devs) ? devs : [];
  const groups = new Set(), tags = new Set();
  list.forEach(d => {
    if (d.group) groups.add(d.group);
    (d.tags || []).forEach(t => t && tags.add(t));
  });
  _fleetTargetsCache = {
    groups: [...groups].sort(),
    tags: [...tags].sort(),
    devices: list.map(d => ({ id: d.id, name: d.name || d.id }))
                 .sort((a, b) => a.name.localeCompare(b.name)),
  };
  return _fleetTargetsCache;
}
// Populate a target-value <select> based on the chosen type. The select is
// hidden for 'all'. Falls back to a free-text prompt only if there are no
// options (so you can't blindly install on a group/tag that doesn't exist).
// v3.14.0: hide/show a select that may have been turned into a device-combo —
// then the visible element is the .dev-combo wrapper, not the native <select>.
function _comboToggleHidden(el, hidden) {
  if (!el) return;
  (el.closest('.dev-combo') || el).classList.toggle('d-none', hidden);
}

async function _fillTargetSelect(typeSel, valueSel) {
  const t = document.getElementById(typeSel).value;
  const el = document.getElementById(valueSel);
  if (!el) return;
  _comboToggleHidden(el, t === 'all');
  if (t === 'all') { el.innerHTML = ''; return; }
  const tg = await _fleetTargets();
  let opts = [];
  if (t === 'group') opts = tg.groups.map(g => [g, g]);
  else if (t === 'tag') opts = tg.tags.map(g => [g, g]);
  else if (t === 'device') opts = tg.devices.map(d => [d.id, d.name]);
  // v5.0.1: build <option>s with the DOM API (new Option sets text via
  // textContent — no innerHTML round-trip), clearing codeql js/xss-through-dom.
  el.replaceChildren();
  if (opts.length) opts.forEach(([v, label]) => el.add(new Option(String(label), String(v))));
  else el.add(new Option(`(no ${t}s defined)`, ''));
  // v3.14.0: make every target value-picker a searchable device-combo (works
  // for group/tag too — it's just a searchable single-select). Idempotent.
  el.classList.add('device-combo');
  if (typeof enhanceDeviceCombos === 'function') enhanceDeviceCombos(el.parentNode || document);
  const wrap = el.closest('.dev-combo');
  if (wrap) {
    const inp = wrap.querySelector('.dev-combo-input');
    if (inp && document.activeElement !== inp) {
      const o = el.options[el.selectedIndex] || el.options[0];
      inp.value = o ? o.text : '';
    }
  }
}
function onScapTargetChange() { _fillTargetSelect('scap-target-type', 'scap-target-value'); }
function onInstallTargetChange() { _fillTargetSelect('install-target-type', 'install-target-value'); }

async function runScapScan() {
  const profile = document.getElementById('scap-profile').value || 'cis';
  const type = document.getElementById('scap-target-type').value;
  const value = document.getElementById('scap-target-value').value.trim();
  if (type !== 'all' && !value) { toast('Select a ' + type, 'error'); return; }
  const scapScope = type === 'all' ? 'the ENTIRE fleet' : `${type} "${value}"`;
  if (!await uiConfirm(`Run the OpenSCAP "${profile}" scan on ${scapScope}? Each host runs oscap in the background; results arrive on the next heartbeat.`)) return;
  const body = await _fleetTargetBody(type, value);
  if (!(body.device_ids || body.group || body.tag) || (body.device_ids && !body.device_ids.length)) { toast('No matching devices', 'error'); return; }
  body.profile = profile;
  const r = await api('POST', '/scap/scan', body).catch(() => null);
  if (r?.ok) toast(`OpenSCAP scan queued on ${r.queued} host(s) — results arrive on next heartbeat`, 'success');
  else toast(r?.error || 'Failed to queue scan', 'error');
}

async function runInstall() {
  const pkgs = document.getElementById('install-pkgs').value.trim();
  if (!pkgs) { toast('Enter one or more package names', 'error', {transient: true}); return; }
  const type = document.getElementById('install-target-type').value;
  const value = document.getElementById('install-target-value').value.trim();
  if (type !== 'all' && !value) { toast('Enter a ' + type, 'error'); return; }
  const scopeLabel = type === 'all' ? 'the ENTIRE fleet' : `${type} "${value}"`;
  if (!await uiConfirm(`Install "${pkgs}" on ${scopeLabel}?`)) return;
  const body = await _fleetTargetBody(type, value);
  if (body.device_ids && !body.device_ids.length) { toast('No matching devices', 'error'); return; }
  body.packages = pkgs;
  const r = await api('POST', '/install', body).catch(() => null);
  if (r?.ok) toast(`Install queued for ${r.packages.join(', ')} on ${r.queued} host(s) — follow progress on Rollouts → Recent jobs`, 'success');
  else toast(r?.error || 'Failed to queue install', 'error');
}

async function runUninstall() {
  const pkgs = document.getElementById('install-pkgs').value.trim();
  if (!pkgs) { toast('Enter one or more package names to remove', 'error', {transient: true}); return; }
  const type = document.getElementById('install-target-type').value;
  const value = document.getElementById('install-target-value').value.trim();
  if (type !== 'all' && !value) { toast('Select a ' + type, 'error'); return; }
  const scopeLabel = type === 'all' ? 'the ENTIRE fleet' : `${type} "${value}"`;
  if (!await uiConfirm(`Uninstall "${pkgs}" from ${scopeLabel}? This removes the package(s) via the host's package manager.`)) return;
  const body = await _fleetTargetBody(type, value);
  if (body.device_ids && !body.device_ids.length) { toast('No matching devices', 'error'); return; }
  body.packages = pkgs;
  const r = await api('POST', '/uninstall', body).catch(() => null);
  if (r?.ok) toast(`Uninstall queued for ${r.packages.join(', ')} on ${r.queued} host(s) — follow progress on Rollouts → Recent jobs`, 'success');
  else toast(r?.error || 'Failed to queue uninstall', 'error');
}

// v3.14.0 (#39): pin/unpin packages so a fleet upgrade-all skips them.
async function _runHold(hold) {
  const pkgs = document.getElementById('install-pkgs').value.trim();
  if (!pkgs) { toast('Enter one or more package names', 'error', {transient: true}); return; }
  const type = document.getElementById('install-target-type').value;
  const value = document.getElementById('install-target-value').value.trim();
  if (type !== 'all' && !value) { toast('Select a ' + type, 'error'); return; }
  const scopeLabel = type === 'all' ? 'the ENTIRE fleet' : `${type} "${value}"`;
  const verb = hold ? 'Hold' : 'Unhold';
  if (!await uiConfirm(`${verb} "${pkgs}" on ${scopeLabel}?`)) return;
  const body = await _fleetTargetBody(type, value);
  if (body.device_ids && !body.device_ids.length) { toast('No matching devices', 'error'); return; }
  body.packages = pkgs;
  const r = await api('POST', hold ? '/packages/hold' : '/packages/unhold', body).catch(() => null);
  if (r?.ok) toast(`${verb} queued for ${r.packages.join(', ')} on ${r.queued} host(s) — follow progress on Rollouts → Recent jobs`, 'success');
  else toast(r?.error || `Failed to queue ${verb.toLowerCase()}`, 'error');
}
function runHold() { _runHold(true); }
function runUnhold() { _runHold(false); }

// v3.4.2: one-time install from the Rollouts page — target one device or a tag.
async function openInstallModal() {
  document.getElementById('oti-pkgs').value = '';
  document.getElementById('oti-target-type').value = 'device';
  _fleetTargetsCache = null;   // refresh so newly-added devices/groups/tags show
  const sel = document.getElementById('oti-device');
  const tg = await _fleetTargets();
  sel.innerHTML = tg.devices.map(d =>
    `<option value="${escAttr(d.id)}">${escHtml(d.name)}</option>`).join('') || '<option value="">(no devices)</option>';
  onOtiTargetChange();
  openModal('one-time-install-modal');
}
function onOtiTargetChange() {
  const t = document.getElementById('oti-target-type').value;
  // v3.14.0: hide the COMBO wrapper, not just the (visually-hidden) native select.
  _comboToggleHidden(document.getElementById('oti-device'), t !== 'device');
  _comboToggleHidden(document.getElementById('oti-target-value'), t === 'device');
  if (t !== 'device') _fillTargetSelect('oti-target-type', 'oti-target-value');
}
async function runOneTimeInstall() {
  const pkgs = document.getElementById('oti-pkgs').value.trim();
  if (!pkgs) { toast('Enter one or more package names', 'error', {transient: true}); return; }
  const type = document.getElementById('oti-target-type').value;
  let body, scope;
  if (type === 'device') {
    const id = document.getElementById('oti-device').value;
    if (!id) { toast('Pick a device', 'error', {transient: true}); return; }
    body = { device_ids: [id] };
    scope = 'this device';
  } else {
    const val = document.getElementById('oti-target-value').value.trim();
    if (!val) { toast('Enter a ' + type, 'error'); return; }
    body = type === 'tag' ? { tag: val } : { group: val };
    scope = `${type} "${val}"`;
  }
  if (!await uiConfirm(`Install "${pkgs}" now on ${scope}?`)) return;
  body.packages = pkgs;
  const r = await api('POST', '/install', body).catch(() => null);
  if (r?.ok) {
    toast(`Install queued for ${r.packages.join(', ')} on ${r.queued} host(s) — follow it below`, 'success');
    closeModal('one-time-install-modal');
    if (r.job_id) _batchExpanded.add(r.job_id);   // auto-expand so the user sees per-host progress
    loadBatchJobs();
  } else toast(r?.error || 'Failed to queue install', 'error');
}

