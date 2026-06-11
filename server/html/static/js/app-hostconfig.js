// ══════════════════════════════════════════════════════════════════════════════
//  Custom monitoring scripts + host configuration management
//  Split out of app.js (v3.13.0). Classic script — shares the global scope with
//  app.js (loaded first); calls core helpers (api, escHtml, toast, openModal, …)
//  at runtime. Not a module — do not wrap in an IIFE.
// ══════════════════════════════════════════════════════════════════════════════

// ─── v2.5.0: Custom Monitoring Scripts ────────────────────────────────────────

let _csData = null;       // {results: [...], scripts: [...]} from server
let _csDevices = null;    // device list for the device picker

// Called by showPage('custom-scripts', ...)
function loadCustomScripts() {
  renderCustomScriptsLoading();
  Promise.all([
    api('GET', '/custom-scripts/results'),
    api('GET', '/devices'),
  ]).then(([resultsData, devicesData]) => {
    if (!resultsData) return;
    _csData = resultsData;
    _csDevices = devicesData ? (devicesData.devices || devicesData) : [];
    renderCustomScriptsPage();
  }).catch(() => {
    const tbody = document.getElementById('cs-results-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="isl-597">Failed to load. Refresh to retry.</td></tr>';
  });
}

function renderCustomScriptsLoading() {
  const tbody = document.getElementById('cs-results-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="empty-state-sm">Loading…</td></tr>';
}

function renderCustomScriptsPage() {
  if (!_csData) return;
  const filterText = (document.getElementById('cs-filter')?.value || '').toLowerCase();
  const statusFilter = document.getElementById('cs-status-filter')?.value || 'all';

  let rows = _csData.results || [];
  if (filterText) {
    rows = rows.filter(r =>
      r.script_name.toLowerCase().includes(filterText) ||
      r.device_name.toLowerCase().includes(filterText) ||
      (r.group || '').toLowerCase().includes(filterText) ||
      (r.output || '').toLowerCase().includes(filterText)
    );
  }
  if (statusFilter === 'fail') rows = rows.filter(r => !r.ok);
  if (statusFilter === 'ok')   rows = rows.filter(r => r.ok);

  tableCtl.wireSortOnly('cs-results-thead', 'cs_results', renderCustomScriptsPage);
  rows = tableCtl.sortRows('cs_results', rows, (r) => ({
    script_name: (r.script_name || '').toLowerCase(),
    device_name: (r.device_name || '').toLowerCase(),
    group:       (r.group || '').toLowerCase(),
    ok:          r.ok ? 1 : 0,
    output:      (r.output || '').toLowerCase(),
    ran_at:      r.ran_at || 0,
    duration_ms: r.duration_ms || 0,
  }));

  // Stats
  const allRows = _csData.results || [];
  const failing = allRows.filter(r => !r.ok).length;
  const allOk   = allRows.filter(r => r.ok).length;
  const scripts  = _csData.scripts || [];

  document.getElementById('cs-stat-total').textContent   = scripts.length;
  document.getElementById('cs-stat-running').textContent = allRows.length;
  document.getElementById('cs-stat-fail').textContent    = failing;
  document.getElementById('cs-stat-ok').textContent      = allOk;

  const tbody = document.getElementById('cs-results-tbody');
  if (!tbody) return;

  // Also show scripts that have never run (no results yet) — always visible and deletable
  const allScripts = _csData.scripts || [];
  const scriptIdsWithResults = new Set(rows.map(r => r.script_id));
  const noResultRows = allScripts
    .filter(s => s.id && !scriptIdsWithResults.has(s.id))
    .filter(s => {
      const n = s.name || '';
      return !filterText || n.toLowerCase().includes(filterText);
    })
    .filter(() => statusFilter === 'all');

  const noResultHtml = noResultRows.map(s => {
    const sid = escAttr(s.id);   // safe: IDs are cs_hexhex, no special chars
    return `<tr class="isl-598">
      <td class="fw-500">${escHtml(s.name)}</td>
      <td colspan="5" class="isl-599">No results yet — waiting for next run cycle</td>
      <td></td>
      <td class="nowrap">
        <button class="btn-icon isl-600"
            data-action="openCustomScriptModal" data-arg="${sid}" >Edit</button>
        <button class="btn-icon isl-601"
            data-action="csDeleteScript" data-arg="${sid}" >Delete</button>
      </td>
    </tr>`;
  }).join('');

  if (!rows.length && !noResultRows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">${
      filterText || statusFilter !== 'all' ? 'No results match the filter.' : 'No custom script results yet. Assign a script to a device and wait one run cycle (5 min).'
    }</td></tr>`;
    return;
  }

  tbody.innerHTML = noResultHtml + rows.map(r => {
    const statusBadge = r.ok
      ? '<span class="c-green-bold">● OK</span>'
      : '<span class="c-red-bold">● FAIL</span>';
    const output = (r.output || '').trim();
    const outputSnippet = output.length > 80
      ? escHtml(output.slice(0, 80)) + '<span class="c-muted">…</span>'
      : escHtml(output || '—');
    const ranAt = r.ran_at ? new Date(r.ran_at * 1000).toLocaleString() : '—';
    const dur   = r.duration_ms ? `${r.duration_ms} ms` : '—';
    const changedAgo = r.changed_at
      ? `<span title="Status changed ${new Date(r.changed_at*1000).toLocaleString()}" class="isl-602">changed ${_reltime(r.changed_at)}</span>`
      : '';
    return `<tr>
      <td class="fw-500">${escHtml(r.script_name)}</td>
      <td>${escHtml(r.device_name)}</td>
      <td class="hint">${r.group ? `<span class="group-badge">${escHtml(r.group)}</span>` : '—'}</td>
      <td class="ta-center">${statusBadge}<br>${changedAgo}</td>
      <td
          data-action-btn="_csOutputFromStore" data-store-key="${_storeEvtData([r.script_name, r.device_name, output])}"
          title="Click for full output" class="isl-603">${outputSnippet}</td>
      <td class="meta-sm-nm">${ranAt}</td>
      <td class="isl-604">${dur}</td>
      <td class="nowrap">
        <button class="btn-icon isl-600"
            data-action="openCustomScriptModal" data-arg="${escAttr(r.script_id)}" >Edit</button>
        <button class="btn-icon isl-601"
            data-action="csDeleteScript" data-arg="${escAttr(r.script_id)}" >Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function renderCsDefinitions() { /* cards removed — table is the only view */ }

function openCsOutput(scriptName, deviceName, output) {
  document.getElementById('cs-output-title').textContent = `${scriptName} — ${deviceName}`;
  document.getElementById('cs-output-body').textContent = output || '(no output)';
  openModal('cs-output-modal');
}

// ── Script create / edit modal ─────────────────────────────────────────────

async function openCustomScriptModal(scriptId) {
  // Reset modal
  document.getElementById('cs-modal-title').textContent = scriptId ? 'Edit script' : 'New script';
  document.getElementById('cs-modal-id').value   = scriptId || '';
  document.getElementById('cs-modal-name').value  = '';
  document.getElementById('cs-modal-desc').value  = '';
  document.getElementById('cs-modal-body').value  = '';
  document.getElementById('cs-ai-prompt').value   = '';
  document.getElementById('cs-ai-status').textContent = '';
  document.getElementById('cs-modal-delete-btn').style.display = scriptId ? 'block' : 'none';

  // If editing, fetch the script body (list view omits it)
  if (scriptId) {
    const s = await api('GET', `/custom-scripts/${scriptId}`);
    if (s) {
      document.getElementById('cs-modal-name').value = s.name || '';
      document.getElementById('cs-modal-desc').value = s.description || '';
      document.getElementById('cs-modal-body').value = s.body || '';
    }
  }

  // Build device picker
  await _buildCsDevicePicker(scriptId);

  openModal('custom-script-modal');
}

async function _buildCsDevicePicker(scriptId) {
  const container = document.getElementById('cs-device-picker');
  if (!container) return;
  container.innerHTML = '<span class="hint">Loading devices…</span>';

  // Get assigned_devices for this script (if editing) — always fetch so
  // we don't need _csData to be loaded first.
  let assigned = [];
  if (scriptId) {
    try {
      const full = await api('GET', `/custom-scripts/${scriptId}`);
      if (full) assigned = full.assigned_devices || [];
    } catch (_) {}
  }

  // Use cached device list if available; otherwise fetch fresh.
  let devs = _csDevices;
  if (!devs || !devs.length) {
    try {
      const fetched = await api('GET', '/devices');
      devs = Array.isArray(fetched) ? fetched : (fetched && fetched.devices) ? fetched.devices : [];
      if (devs.length) _csDevices = devs; // cache for next time
    } catch (_) {
      devs = [];
    }
  }

  const agentDevs = (devs || []).filter(d => !d.agentless);
  if (!agentDevs.length) {
    container.innerHTML = '<span class="hint">No devices enrolled.</span>';
    return;
  }

  container.innerHTML = agentDevs.map(d => {
    const devId  = d.device_id || d.id;
    const checked = assigned.includes(devId) ? 'checked' : '';
    const grp = d.group || '';
    // data-search carries name+group lowercased so the filter is one cheap
    // substring test per row (no re-reading the DOM text each keystroke).
    const hay = ((d.name || devId) + ' ' + grp).toLowerCase();
    return `<label class="isl-605 cs-device-row" data-search="${escAttr(hay)}">
      <input type="checkbox" class="cs-device-cb isl-606" value="${escAttr(devId)}" ${checked}>
      ${escHtml(d.name || devId)}
      ${grp ? `<span class="group-badge fs-10">${escHtml(grp)}</span>` : ''}
    </label>`;
  }).join('');

  // Wire the search box + live count (idempotent — reset value, (re)bind).
  const search = document.getElementById('cs-device-search');
  if (search) {
    search.value = '';
    search.oninput = _filterCsDevices;
  }
  container.onchange = _updateCsDeviceCount; // keep count live on box toggles
  _updateCsDeviceCount();
}

// Filter the assign-devices list by name/group as the operator types, and
// keep the "N of M selected" count live. Hidden rows stay checked — filtering
// is a view, not a deselect.
function _filterCsDevices() {
  const search = document.getElementById('cs-device-search');
  const q = (search ? search.value : '').trim().toLowerCase();
  document.querySelectorAll('#cs-device-picker .cs-device-row').forEach(row => {
    const hit = !q || (row.dataset.search || '').includes(q);
    row.classList.toggle('d-none', !hit);
  });
  _updateCsDeviceCount();
}

function _updateCsDeviceCount() {
  const el = document.getElementById('cs-device-count');
  if (!el) return;
  const all = document.querySelectorAll('#cs-device-picker .cs-device-cb');
  const sel = document.querySelectorAll('#cs-device-picker .cs-device-cb:checked').length;
  const vis = document.querySelectorAll('#cs-device-picker .cs-device-row:not(.d-none)').length;
  const filtered = vis !== all.length;
  el.textContent = `${sel} of ${all.length} selected` + (filtered ? ` · ${vis} shown` : '');
}

// Select-all / Clear act on the *visible* (filtered) rows only — so you can
// search "web", Select all, search "db", Select all, etc.
function csDeviceSelectAll() {
  document.querySelectorAll('#cs-device-picker .cs-device-row:not(.d-none) .cs-device-cb')
    .forEach(cb => { cb.checked = true; });
  _updateCsDeviceCount();
}
function csDeviceClear() {
  document.querySelectorAll('#cs-device-picker .cs-device-row:not(.d-none) .cs-device-cb')
    .forEach(cb => { cb.checked = false; });
  _updateCsDeviceCount();
}
window.csDeviceSelectAll = csDeviceSelectAll;
window.csDeviceClear = csDeviceClear;

async function saveCustomScript() {
  const sid   = document.getElementById('cs-modal-id').value;
  const name  = document.getElementById('cs-modal-name').value.trim();
  const desc  = document.getElementById('cs-modal-desc').value.trim();
  const body  = document.getElementById('cs-modal-body').value.trim();
  const assigned = [...document.querySelectorAll('.cs-device-cb:checked')].map(cb => cb.value);

  if (!name) { toast('Script name is required', 'error'); return; }
  if (!body) { toast('Script body is required', 'error'); return; }

  const payload = { name, description: desc, body, assigned_devices: assigned };
  let result;
  if (sid) {
    result = await api('PUT', `/custom-scripts/${sid}`, payload);
  } else {
    result = await api('POST', '/custom-scripts', payload);
  }
  if (!result) return;
  closeModal('custom-script-modal');
  toast(sid ? 'Script updated' : 'Script created', 'success');
  loadCustomScripts();
}

async function deleteCustomScript() {
  const sid  = document.getElementById('cs-modal-id').value;
  const name = document.getElementById('cs-modal-name').value;
  if (!sid) return;
  if (!confirm(`Delete script "${name}"? This removes it from all devices.`)) return;
  const r = await api('DELETE', `/custom-scripts/${sid}`);
  if (!r) return;
  closeModal('custom-script-modal');
  toast('Script deleted', 'success');
  loadCustomScripts();
}

// Standalone delete — called from table row buttons. Looks up name from cache.
async function csDeleteScript(sid) {
  const script = (_csData && _csData.scripts || []).find(s => s.id === sid);
  const name   = script ? script.name : sid;
  if (!confirm(`Delete script "${name}"? This removes it from all devices.`)) return;
  const r = await api('DELETE', `/custom-scripts/${sid}`);
  if (!r) return;
  toast('Script deleted', 'success');
  loadCustomScripts();
}

// ── AI generation ──────────────────────────────────────────────────────────

async function csGenerateWithAI() {
  const prompt = document.getElementById('cs-ai-prompt').value.trim();
  if (!prompt) { toast('Describe what the script should check', 'error'); return; }

  const btn    = document.getElementById('cs-ai-btn');
  const status = document.getElementById('cs-ai-status');
  btn.disabled = true;
  status.textContent = 'Generating…';
  status.style.color = 'var(--accent)';

  try {
    const resp = await api('POST', '/ai/chat', {
      system:     'generate_script',
      messages:   [{ role: 'user', content:
        `Write a bash monitoring script for RemotePower custom script checks.\n\n` +
        `Monitoring contract (MUST follow):\n` +
        `- Exit code 0 = OK (check passed)\n` +
        `- Exit code non-zero = FAIL (check failed)\n` +
        `- Runs as root on the agent host\n` +
        `- Hard timeout: 30 seconds — finish well within that\n` +
        `- stdout + stderr are merged and captured (max 4 KB shown)\n` +
        `- Print one clear status line so the operator knows what happened\n\n` +
        `Task: ${prompt}\n\n` +
        `Return ONLY the bash script. No markdown, no explanation, no code fences.`
      }],
      max_tokens: 1500,
      context:    'custom_script_generate',
    });
    if (!resp) throw new Error('No response');
    const text = (resp.text || resp.content || '').trim();
    if (!text) throw new Error('Empty response from AI');

    // Strip markdown code fences if the model wrapped despite instructions
    const cleaned = text.replace(/^```(?:bash|sh)?\n?/m, '').replace(/\n?```$/m, '').trim();
    document.getElementById('cs-modal-body').value = cleaned;
    status.textContent = '✓ Script generated — review before saving';
    status.style.color = 'var(--green)';
  } catch (e) {
    status.textContent = `✗ ${e.message || 'AI generation failed'}`;
    status.style.color = 'var(--red)';
  } finally {
    btn.disabled = false;
  }
}

function _reltime(ts) {
  if (!ts) return '';
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

// ─── v2.6.0: Host Configuration Management ────────────────────────────────────

let _hcData    = null;   // {desired, current, drift, desired_at, current_collected_at}
let _hcDevId   = null;
let _hcDevName = null;
const HC_TEXT_SECTIONS    = ['repos','netplan','nmcli','resolv_conf','hosts','sudoers','motd','logrotate','cron'];
const HC_SPECIAL_SECTIONS = ['services','users','groups'];

// ── Open modal ─────────────────────────────────────────────────────────────

async function openHostConfigModal(devId, devName) {
  _hcDevId   = devId;
  _hcDevName = devName;
  document.getElementById('hc-device-name').textContent = devName;
  document.getElementById('hc-device-id').value         = devId;

  hcShowTab('repos', document.querySelector('.hc-tab'));
  _hcData = null;
  _hcClearAll();
  openModal('host-config-modal');

  const data = await api('GET', `/devices/${devId}/host-config`);
  if (!data) return;
  _hcData = data;

  // v3.4.0: reflect the per-device enforce opt-in + its warning banner.
  const applyCb = document.getElementById('hc-apply-enabled');
  if (applyCb) { applyCb.checked = !!data.apply_enabled; _hcToggleApplyWarn(); }
  const enfCb = document.getElementById('hc-enforce-drift');
  if (enfCb) enfCb.checked = !!data.enforce;

  const desired = data.desired || {};
  const current = data.current || {};

  // For each section: use desired if set, otherwise fall back to current
  // so the editor is always pre-filled if we have any data at all.
  const merged = {};
  const ALL_SECTIONS = ['repos','netplan','nmcli','resolv_conf','hosts',
                        'sudoers','motd','logrotate','cron','services','users','groups'];
  ALL_SECTIONS.forEach(s => {
    const d = desired[s];
    const c = current[s];
    const hasDesired = d !== undefined && d !== null &&
                       (Array.isArray(d) ? d.length > 0 : d !== '');
    merged[s] = hasDesired ? d : (c !== undefined ? c : d);
  });
  _hcPopulateAll(merged);
  _hcShowDrift(data.drift || {});

  // Show a subtle info note if we're showing current (no desired saved yet)
  const hasAnyDesired = Object.keys(desired).length > 0;
  if (!hasAnyDesired && Object.keys(current).length > 0) {
    const ts = data.current_collected_at
      ? new Date(data.current_collected_at * 1000).toLocaleString()
      : 'unknown time';
    const infoBanner = document.getElementById('hc-info-banner');
    if (infoBanner) {
      infoBanner.style.display = 'block';
      document.getElementById('hc-info-ts').textContent = ts;
    }
  }
}

function _hcClearAll() {
  HC_TEXT_SECTIONS.forEach(s => {
    const el = document.getElementById(`hc-text-${s}`);
    if (el) el.value = '';
    const d = document.getElementById(`hc-drift-${s}`);
    if (d) d.textContent = '';
  });
  document.getElementById('hc-text-services').value = '';
  document.getElementById('hc-drift-services').textContent = '';
  document.getElementById('hc-users-list').innerHTML = '';
  document.getElementById('hc-drift-users').textContent = '';
  document.getElementById('hc-groups-list').innerHTML = '';
  document.getElementById('hc-drift-groups').textContent = '';
  document.getElementById('hc-drift-banner').style.display = 'none';
  const infoBanner = document.getElementById('hc-info-banner');
  if (infoBanner) infoBanner.style.display = 'none';
}

function _hcPopulateAll(desired) {
  HC_TEXT_SECTIONS.forEach(s => {
    const el = document.getElementById(`hc-text-${s}`);
    if (el) el.value = desired[s] || '';
  });
  // Services: list → textarea (one per line)
  const svcEl = document.getElementById('hc-text-services');
  if (svcEl) svcEl.value = (desired.services || []).join('\n');
  // Users
  _hcRenderUsers(desired.users || []);
  // Groups
  _hcRenderGroups(desired.groups || []);
}

function _hcShowDrift(drift) {
  const sections = drift.sections || [];
  const banner   = document.getElementById('hc-drift-banner');
  if (sections.length) {
    banner.style.display = 'block';
    document.getElementById('hc-drift-sections').textContent = sections.join(', ');
    sections.forEach(s => {
      const el = document.getElementById(`hc-drift-${s}`);
      if (el) el.textContent = 'drift detected';
    });
  } else {
    banner.style.display = 'none';
  }
}

// ── Tab switching ──────────────────────────────────────────────────────────

function hcShowTab(section, btn) {
  document.querySelectorAll('.hc-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.hc-panel').forEach(p => p.style.display = 'none');
  if (btn) btn.classList.add('active');
  const panel = document.getElementById(`hc-panel-${section}`);
  // CSP L1 fallout: hc-panel-* (except the default) have `d-none`
  // in markup so they're hidden on initial paint. `style.display = ''`
  // would only clear the inline attribute; the d-none class would
  // keep the panel hidden. Use explicit 'block' to beat the class.
  if (panel) panel.style.display = 'block';
}

// ── Fetch current from agent ───────────────────────────────────────────────

async function hcFetchCurrent(section) {
  if (!_hcDevId) return;
  const data = await api('GET', `/devices/${_hcDevId}/host-config/current`);
  if (!data) return;
  const current = data.current || {};
  const val = current[section];
  if (val === undefined || val === null) {
    toast(`No current ${section} data yet — agent reports every 15 min`, 'info');
    return;
  }
  // Populate the appropriate editor
  if (HC_TEXT_SECTIONS.includes(section)) {
    document.getElementById(`hc-text-${section}`).value =
      typeof val === 'string' ? val : JSON.stringify(val, null, 2);
  } else if (section === 'services') {
    document.getElementById('hc-text-services').value =
      Array.isArray(val) ? val.join('\n') : '';
  } else if (section === 'users') {
    _hcRenderUsers(Array.isArray(val) ? val : []);
  } else if (section === 'groups') {
    _hcRenderGroups(Array.isArray(val) ? val : []);
  }
  const ts = data.current_collected_at
    ? new Date(data.current_collected_at * 1000).toLocaleTimeString()
    : 'unknown time';
  toast(`Loaded current ${section} from agent (collected ${ts})`, 'success');
}

// ── Users editor ───────────────────────────────────────────────────────────

function _hcRenderUsers(users) {
  const container = document.getElementById('hc-users-list');
  if (!container) return;
  container.innerHTML = '';
  (users || []).forEach((u, i) => {
    container.appendChild(_hcUserCard(u, i));
  });
}

function _hcUserCard(u, i) {
  const div = document.createElement('div');
  div.className = 'hc-user-card';
  div.dataset.idx = i;
  div.style.cssText = 'background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;position:relative';
  div.innerHTML = `
    <button data-action="hcRemoveUser" data-arg="${i}" title="Remove user" class="isl-607">×</button>
    <div class="isl-608">
      <div><label class="isl-609">Username</label>
        <input class="form-input fs-12" value="${escAttr(u.name||'')}" data-field="name"></div>
      <div><label class="isl-609">Shell</label>
        <input class="form-input fs-12" value="${escAttr(u.shell||'/bin/bash')}" data-field="shell"></div>
    </div>
    <div class="isl-610"><label class="isl-609">Groups (comma-separated)</label>
      <input class="form-input fs-12" value="${escAttr((u.groups||[]).join(', '))}" data-field="groups"></div>
    <div><label class="isl-609">authorized_keys</label>
      <textarea class="form-textarea isl-611" data-field="authorized_keys">${escHtml(u.authorized_keys||'')}</textarea></div>`;
  return div;
}

function hcAddUser() {
  const container = document.getElementById('hc-users-list');
  const idx = container.querySelectorAll('.hc-user-card').length;
  container.appendChild(_hcUserCard({name:'',shell:'/bin/bash',groups:[],authorized_keys:''}, idx));
}

function hcRemoveUser(idx) {
  const cards = document.querySelectorAll('.hc-user-card');
  if (cards[idx]) cards[idx].remove();
  // Re-index remaining cards. After CSP L1, the remove button uses
  // data-action="hcRemoveUser" data-arg="${i}" instead of an inline
  // onclick, so re-indexing means updating the dataset arg, not the
  // attribute.
  document.querySelectorAll('.hc-user-card').forEach((c, i) => {
    c.dataset.idx = i;
    const btn = c.querySelector('button[data-action="hcRemoveUser"]');
    if (btn) btn.dataset.arg = i;
  });
}

function hcUserField(idx, el) {
  // Live update handled at save time — no-op here, just for symmetry
}

function _hcCollectUsers() {
  const users = [];
  document.querySelectorAll('.hc-user-card').forEach(card => {
    const get = (field) => {
      const el = card.querySelector(`[data-field="${field}"]`);
      return el ? el.value : '';
    };
    const name = get('name').trim();
    if (!name) return;
    const groupsRaw = get('groups').split(',').map(g => g.trim()).filter(Boolean);
    users.push({
      name,
      shell:           get('shell').trim() || '/bin/bash',
      groups:          groupsRaw,
      authorized_keys: get('authorized_keys'),
    });
  });
  return users;
}

// ── Groups editor ──────────────────────────────────────────────────────────

function _hcRenderGroups(groups) {
  const container = document.getElementById('hc-groups-list');
  if (!container) return;
  container.innerHTML = '';
  (groups || []).forEach((g, i) => container.appendChild(_hcGroupRow(g, i)));
}

function _hcGroupRow(g, i) {
  const div = document.createElement('div');
  div.className = 'hc-group-row';
  div.style.cssText = 'display:flex;gap:10px;align-items:center';
  div.innerHTML = `
    <input class="form-input isl-612" placeholder="groupname"
           value="${escAttr(g.name||'')}" data-field="name">
    <input class="form-input isl-613" placeholder="GID (opt)"
           value="${g.gid !== null && g.gid !== undefined ? g.gid : ''}" data-field="gid" type="number">
    <button data-remove-closest=".hc-group-row" class="isl-614">×</button>`;
  return div;
}

function hcAddGroup() {
  const container = document.getElementById('hc-groups-list');
  container.appendChild(_hcGroupRow({name:'', gid: null}, container.children.length));
}

function _hcCollectGroups() {
  const groups = [];
  document.querySelectorAll('.hc-group-row').forEach(row => {
    const name = row.querySelector('[data-field="name"]').value.trim();
    if (!name) return;
    const gidRaw = row.querySelector('[data-field="gid"]').value;
    groups.push({ name, gid: gidRaw ? parseInt(gidRaw) : null });
  });
  return groups;
}

// ── Save ───────────────────────────────────────────────────────────────────

async function saveHostConfig() {
  if (!_hcDevId) return;
  const desired = {};

  HC_TEXT_SECTIONS.forEach(s => {
    const el = document.getElementById(`hc-text-${s}`);
    if (el && el.value.trim()) desired[s] = el.value;
  });

  // Services: textarea → list
  const svcEl = document.getElementById('hc-text-services');
  if (svcEl && svcEl.value.trim()) {
    desired.services = svcEl.value.split('\n').map(l => l.trim()).filter(Boolean);
  }

  const users = _hcCollectUsers();
  if (users.length) desired.users = users;

  const groups = _hcCollectGroups();
  if (groups.length) desired.groups = groups;

  // v3.4.0: carry the enforce opt-in. The server only pushes the config for
  // the agent to APPLY when this is on; otherwise it's a drift-monitoring
  // baseline only.
  const enforce = !!document.getElementById('hc-apply-enabled')?.checked;
  desired.apply_enabled = enforce;
  // v3.7.0: corrective enforcement — re-apply only when drift is detected.
  desired.enforce = !!document.getElementById('hc-enforce-drift')?.checked;

  const r = await api('PUT', `/devices/${_hcDevId}/host-config`, desired);
  if (!r) return;
  closeModal('host-config-modal');
  toast(enforce
    ? 'Host config saved — enforcement ON, agent will apply it on next poll (~60s).'
    : 'Host config saved as a drift baseline (monitor only — not applied).', 'success');
}

// Show/hide the enforcement warning as the operator toggles it.
function _hcToggleApplyWarn() {
  const on = !!document.getElementById('hc-apply-enabled')?.checked;
  const warn = document.getElementById('hc-apply-warn');
  if (warn) warn.classList.toggle('d-none', !on);
}

// Trigger agent to collect and send all current config sections via exec command
async function hcFetchAllCurrent() {
  if (!_hcDevId) return;
  const btn = document.getElementById('hc-fetch-all-btn');
  btn.disabled = true;
  btn.textContent = 'Requesting…';
  // Queue command via the standard exec endpoint
  const r = await api('POST', '/exec', {
    device_id: _hcDevId,
    cmd: 'remotepower-agent send_current_configs',
  });
  if (!r || !r.ok) {
    toast(r?.error || 'Failed to queue command', 'error');
    btn.disabled = false;
    btn.textContent = 'Collect all current';
    return;
  }
  btn.textContent = 'Queued — refreshing in 75s…';
  toast('Command queued — agent will collect and send config in ~60s', 'success');
  // After one full poll cycle the agent should have run and sent back the data
  setTimeout(async () => {
    const data = await api('GET', `/devices/${_hcDevId}/host-config`);
    if (data) {
      _hcData = data;
      // Populate from current data (what the agent just collected)
      const current = data.current || {};
      if (Object.keys(current).length > 0) {
        _hcPopulateAll(current);
        toast('Current config loaded — review and click Save to apply as desired', 'success');
      } else {
        _hcPopulateAll(data.desired || {});
        toast('Current config loaded from agent', 'success');
      }
      _hcShowDrift(data.drift || {});
    }
    btn.disabled = false;
    btn.textContent = 'Collect all current';
  }, 75000);
}

