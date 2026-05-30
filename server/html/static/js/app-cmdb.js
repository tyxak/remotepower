// Split out of app.js (v3.4.0 modularisation). Plain classic script —
// shares the global scope with app.js; loaded right after it in index.html.
// No bundler / no ES modules. Functions here are called from app.js and vice
// versa; page init is DOMContentLoaded-deferred so load order is not sensitive.

// ── v1.9.0: CMDB ─────────────────────────────────────────────────────────────
// All state is per-tab; the derived vault key is held in a single closure
// variable and zeroed on logout/page reload.
let _cmdbVaultKey   = null;     // hex string when unlocked
let _cmdbVaultMeta  = null;     // {configured, ...}
let _cmdbAssetCache = null;     // last full list response
let _cmdbCurrent    = null;     // {device_id, ...} — asset currently in the modal
let _cmdbSearchTimer = null;

// Send the vault key on every CMDB credential request that needs it.
async function cmdbApi(method, path, body, sendKey) {
  const opts = {method, headers: {'X-Token': getToken()}};
  if (sendKey && _cmdbVaultKey) opts.headers['X-RP-Vault-Key'] = _cmdbVaultKey;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) {
    // Could be auth expiry OR vault locked — only auth-401 should log out.
    let payload = null;
    try { payload = await r.clone().json(); } catch (e) {}
    if (payload && payload.code === 'vault_locked') {
      _cmdbVaultKey = null;
      cmdbRenderVaultBar();
      alert('Vault is locked — please unlock and retry.');
      return null;
    }
    doLogout();
    return null;
  }
  let data;
  try { data = await r.json(); } catch (e) { data = null; }
  return {ok: r.ok, status: r.status, data};
}

function enterCMDB() {
  cmdbRefreshVaultStatus().then(() => cmdbReloadList());
  cmdbLoadServerFunctions();
}

async function cmdbRefreshVaultStatus() {
  const res = await cmdbApi('GET', '/cmdb/vault/status');
  if (!res || !res.data) return;
  _cmdbVaultMeta = res.data;
  cmdbRenderVaultBar();
}

function cmdbRenderVaultBar() {
  const stateEl  = document.getElementById('cmdb-vault-state');
  const iconEl   = document.getElementById('cmdb-vault-icon');
  const actionEl = document.getElementById('cmdb-vault-action');
  const lockEl   = document.getElementById('cmdb-vault-lock');
  const rotateEl = document.getElementById('cmdb-vault-rotate');
  if (!_cmdbVaultMeta) {
    stateEl.textContent = 'Vault status unknown';
    return;
  }
  if (!_cmdbVaultMeta.configured) {
    iconEl.innerHTML = _icon('settings', 16);
    stateEl.textContent = 'Vault not yet configured. Set a passphrase to start storing credentials.';
    actionEl.style.display = 'inline-block';
    actionEl.textContent = 'Set up vault';
    actionEl.onclick = cmdbOpenSetupModal;
    rotateEl.style.display = 'none';
    lockEl.style.display = 'none';
    return;
  }
  if (_cmdbVaultKey) {
    iconEl.innerHTML = _icon('unlock', 16);
    stateEl.textContent = 'Vault unlocked. Credential operations enabled in this tab only.';
    actionEl.style.display = 'none';
    rotateEl.style.display = 'inline-block';
    lockEl.style.display = 'inline-block';
  } else {
    iconEl.innerHTML = _icon('lock', 16);
    stateEl.textContent = 'Vault is configured but locked. Unlock to manage credentials.';
    actionEl.style.display = 'inline-block';
    actionEl.textContent = 'Unlock vault';
    actionEl.onclick = cmdbOpenUnlockModal;
    rotateEl.style.display = 'none';
    lockEl.style.display = 'none';
  }
}

function cmdbVaultAction() { /* dispatch through actionEl.onclick — no-op fallback */ }
function cmdbOpenSetupModal() {
  document.getElementById('cmdb-vault-setup-pw').value  = '';
  document.getElementById('cmdb-vault-setup-pw2').value = '';
  openModal('cmdb-vault-setup-modal');
  setTimeout(() => document.getElementById('cmdb-vault-setup-pw').focus(), 50);
}
function cmdbOpenUnlockModal() {
  document.getElementById('cmdb-vault-unlock-pw').value = '';
  openModal('cmdb-vault-unlock-modal');
  setTimeout(() => document.getElementById('cmdb-vault-unlock-pw').focus(), 50);
}
function cmdbOpenRotateModal() {
  document.getElementById('cmdb-vault-rotate-old').value  = '';
  document.getElementById('cmdb-vault-rotate-new').value  = '';
  document.getElementById('cmdb-vault-rotate-new2').value = '';
  openModal('cmdb-vault-rotate-modal');
}

async function cmdbVaultSetup() {
  const pw  = document.getElementById('cmdb-vault-setup-pw').value;
  const pw2 = document.getElementById('cmdb-vault-setup-pw2').value;
  if (pw !== pw2) { alert('Passphrases do not match.'); return; }
  const res = await cmdbApi('POST', '/cmdb/vault/setup', {passphrase: pw});
  if (!res) return;
  if (!res.ok) { alert('Vault setup failed: ' + (res.data && res.data.error || res.status)); return; }
  _cmdbVaultKey = res.data.key;
  closeModal('cmdb-vault-setup-modal');
  await cmdbRefreshVaultStatus();
  cmdbRenderVaultBar();
}

async function cmdbVaultUnlock() {
  const pw = document.getElementById('cmdb-vault-unlock-pw').value;
  const res = await cmdbApi('POST', '/cmdb/vault/unlock', {passphrase: pw});
  if (!res) return;
  if (!res.ok) { alert('Unlock failed: ' + (res.data && res.data.error || res.status)); return; }
  _cmdbVaultKey = res.data.key;
  closeModal('cmdb-vault-unlock-modal');
  cmdbRenderVaultBar();
  // If a credentials tab is open, reload it now
  if (_cmdbCurrent) cmdbLoadCreds(_cmdbCurrent.device_id);
}

async function cmdbVaultRotate() {
  const oldPw = document.getElementById('cmdb-vault-rotate-old').value;
  const newPw = document.getElementById('cmdb-vault-rotate-new').value;
  const new2  = document.getElementById('cmdb-vault-rotate-new2').value;
  if (newPw !== new2) { alert('New passphrases do not match.'); return; }
  const res = await cmdbApi('POST', '/cmdb/vault/change',
    {old_passphrase: oldPw, new_passphrase: newPw});
  if (!res) return;
  if (!res.ok) { alert('Rotation failed: ' + (res.data && res.data.error || res.status)); return; }
  _cmdbVaultKey = res.data.key;
  closeModal('cmdb-vault-rotate-modal');
  alert('Passphrase rotated. ' + res.data.rotated + ' credential(s) re-encrypted.');
  cmdbRenderVaultBar();
}

function cmdbLockVault() {
  _cmdbVaultKey = null;
  cmdbRenderVaultBar();
}

// ── Asset list / search ──────────────────────────────────────────────────────

function cmdbDebounceSearch() {
  clearTimeout(_cmdbSearchTimer);
  _cmdbSearchTimer = setTimeout(cmdbReloadList, 200);
}

async function cmdbReloadList() {
  const q  = encodeURIComponent(document.getElementById('cmdb-search').value || '');
  const fn = encodeURIComponent(document.getElementById('cmdb-func-filter').value || '');
  const res = await cmdbApi('GET', `/cmdb?q=${q}&function=${fn}`);
  if (!res || !res.ok) return;
  _cmdbAssetCache = res.data;
  cmdbRenderTable(res.data);
}

function cmdbRenderTable(rows) {
  const tbody = document.getElementById('cmdb-tbody');
  // v3.2.1: sortable
  tableCtl.wireSortOnly('cmdb-thead', 'cmdb', () => cmdbRenderTable(_cmdbAssetCache || rows));
  rows = tableCtl.sortRows('cmdb', rows || [], (r) => ({
    name:            (r.name || '').toLowerCase(),
    asset_id:        r.asset_id || '',
    server_function: r.server_function || '',
    os:              r.os || '',
    ip:              r.ip || '',
    hypervisor_url:  r.hypervisor_url || '',
    docs_count:      r.has_documentation ? 1 : 0,
    creds_count:     r.credential_count || 0,
  }));
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No matching assets.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const hyp = r.hypervisor_url
      ? `<a href="${_cmdbEsc(r.hypervisor_url)}" target="_blank" rel="noopener" class="c-accent-12">open ↗</a>`
      : '<span class="hint">—</span>';
    const fn = r.server_function
      ? `<span class="tag-pill">${_cmdbEsc(r.server_function)}</span>`
      : '<span class="hint">—</span>';
    // v3.3.0: clicking the Name cell opens the asset (same as the Open
    // button). The button stays in the actions column for discoverability.
    return `<tr>
      <td class="fw-500 pointer" data-action="cmdbOpenAsset" data-arg="${_cmdbEsc(r.device_id)}">${osIcon(r.os, 14)} ${_cmdbEsc(r.name)}</td>
      <td class="mono-12">${_cmdbEsc(r.asset_id) || '<span class="c-muted">—</span>'}</td>
      <td>${fn}</td>
      <td class="hint">${_cmdbEsc(r.os) || '—'}</td>
      <td class="mono-12">${_cmdbEsc(r.ip) || '—'}</td>
      <td>${hyp}</td>
      <td class="ta-center">${r.has_documentation ? '<span class="c-green">●</span>' : '<span class="c-muted">○</span>'}</td>
      <td class="isl-430">${r.credential_count}</td>
      <td><button class="btn-icon" data-action="cmdbOpenAsset" data-arg="${_cmdbEsc(r.device_id)}" >Open</button></td>
    </tr>`;
  }).join('');
}

async function cmdbLoadServerFunctions() {
  const res = await cmdbApi('GET', '/cmdb/server-functions');
  if (!res || !res.ok) return;
  const list = res.data || [];
  const dl = document.getElementById('cmdb-func-datalist');
  dl.innerHTML = list.map(v => `<option value="${_cmdbEsc(v)}">`).join('');
  const sel = document.getElementById('cmdb-func-filter');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All functions</option>' +
    list.map(v => `<option value="${_cmdbEsc(v)}">${_cmdbEsc(v)}</option>`).join('');
  sel.value = cur;
}

// ── Asset detail modal ───────────────────────────────────────────────────────

async function cmdbOpenAsset(deviceId) {
  const res = await cmdbApi('GET', '/cmdb/' + encodeURIComponent(deviceId));
  if (!res || !res.ok) { alert('Failed to load asset.'); return; }
  _cmdbCurrent = res.data;
  document.getElementById('cmdb-asset-title').textContent = res.data.name + ' — CMDB';
  document.getElementById('cmdb-asset-deviceid').value = deviceId;
  document.getElementById('cmdb-asset-id').value         = res.data.asset_id || '';
  document.getElementById('cmdb-asset-function').value   = res.data.server_function || '';
  document.getElementById('cmdb-asset-vlan').value       = res.data.vlan || '';
  document.getElementById('cmdb-asset-hypervisor').value = res.data.hypervisor_url || '';
  document.getElementById('cmdb-asset-ssh-port').value   = res.data.ssh_port || 22;
  document.getElementById('cmdb-asset-hostname').textContent = res.data.hostname || '—';
  document.getElementById('cmdb-asset-os').textContent       = res.data.os || '—';
  document.getElementById('cmdb-asset-ip').textContent       = res.data.ip || '—';
  document.getElementById('cmdb-asset-mac').textContent      = res.data.mac || '—';
  document.getElementById('cmdb-asset-group').textContent    = res.data.group || '—';
  // v2.0: render the docs list. Server returns docs[] migrated from the
  // legacy single 'documentation' field if needed.
  cmdbRenderDocs(res.data.docs || []);
  cmdbSwitchTab('props');
  openModal('cmdb-asset-modal');
}

function cmdbSwitchTab(tab) {
  document.querySelectorAll('.cmdb-tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  document.getElementById('cmdb-tab-props').style.display = tab === 'props' ? 'block' : 'none';
  document.getElementById('cmdb-tab-docs').style.display  = tab === 'docs'  ? 'block' : 'none';
  document.getElementById('cmdb-tab-creds').style.display = tab === 'creds' ? 'block' : 'none';
  const snmpPane = document.getElementById('cmdb-tab-snmp');
  if (snmpPane) snmpPane.style.display = tab === 'snmp' ? 'block' : 'none';
  if (tab === 'creds') cmdbLoadCreds(_cmdbCurrent ? _cmdbCurrent.device_id : null);
  if (tab === 'snmp')  cmdbLoadSnmp(_cmdbCurrent ? _cmdbCurrent.device_id : null);
}

// v3.2.0 (B5): SNMP config + latest poll for the asset modal
async function cmdbLoadSnmp(deviceId) {
  if (!deviceId) return;
  try {
    const r = await api('GET', `/devices/${encodeURIComponent(deviceId)}/snmp`);
    if (!r) return;
    const cfg = r.config || {};
    document.getElementById('cmdb-snmp-enabled').checked = !!cfg.enabled;
    document.getElementById('cmdb-snmp-port').value = cfg.port || 161;
    document.getElementById('cmdb-snmp-community').value = '';
    document.getElementById('cmdb-snmp-community').placeholder =
      cfg.has_community ? `(keep current — preview: ${cfg.community_preview || '…'})` : 'public';
    _renderCmdbSnmpData(r.data);
  } catch (e) {
    toast('Failed to load SNMP config', 'error');
  }
}

function _renderCmdbSnmpData(data) {
  const el = document.getElementById('cmdb-snmp-data');
  if (!el) return;
  if (!data || (!data.last_ok && !data.last_error)) {
    el.innerHTML = '<span class="c-muted">No data yet — save the config and click "Poll now".</span>';
    return;
  }
  if (data.last_error && !data.last_ok) {
    el.innerHTML = `<div class="sev-pill sev-critical">poll failed</div> <code>${_escapeHtml(data.last_error)}</code>`;
    return;
  }
  const upDays = data.sysUpTime ? Math.floor(data.sysUpTime / 100 / 86400) : '?';
  el.innerHTML =
    `<div><strong>Last successful poll:</strong> ${_formatTs(data.last_ok)}</div>` +
    `<div><strong>sysDescr:</strong> ${_escapeHtml(data.sysDescr || '—')}</div>` +
    `<div><strong>sysName:</strong> ${_escapeHtml(data.sysName || '—')}</div>` +
    `<div><strong>sysLocation:</strong> ${_escapeHtml(data.sysLocation || '—')}</div>` +
    `<div><strong>sysContact:</strong> ${_escapeHtml(data.sysContact || '—')}</div>` +
    `<div><strong>sysObjectID:</strong> <code>${_escapeHtml(data.sysObjectID || '—')}</code></div>` +
    `<div><strong>sysUpTime:</strong> ${data.sysUpTime || '?'} (≈ ${upDays}d)</div>` +
    (data.last_error ? `<div class="c-muted mt-12"><em>Note: most recent error — ${_escapeHtml(data.last_error)}</em></div>` : '');
}

async function saveCmdbSnmp() {
  const deviceId = document.getElementById('cmdb-asset-deviceid').value;
  if (!deviceId) return;
  const enabled = document.getElementById('cmdb-snmp-enabled').checked;
  const portRaw = document.getElementById('cmdb-snmp-port').value;
  const comm = document.getElementById('cmdb-snmp-community').value;

  // Client-side validation — server validates too, but a clear message
  // before the round trip is much friendlier than a 400 toast.
  const port = parseInt(portRaw, 10) || 161;
  if (port < 1 || port > 65535) {
    _showSnmpInlineError('UDP port must be 1..65535.');
    return;
  }
  if (enabled) {
    // If enabling for the first time, community is required. We can't tell
    // from the client whether one already exists; rely on the server's
    // explicit error if it's missing (returns 400 with a clear message).
    if (comm && /\s/.test(comm)) {
      _showSnmpInlineError('Community string cannot contain whitespace.');
      return;
    }
  }
  const body = { enabled, port };
  if (comm) body.community = comm;
  _showSnmpInlineNotice('Saving…');
  const r = await api('PATCH', `/devices/${encodeURIComponent(deviceId)}/snmp`, body);
  if (r && r.ok) {
    toast('SNMP config saved', 'success');
    _showSnmpInlineNotice('Config saved.', 'success');
    document.getElementById('cmdb-snmp-community').value = '';
    cmdbLoadSnmp(deviceId);
  } else {
    _showSnmpInlineError((r && r.error) || 'Save failed');
  }
}

async function pollCmdbSnmp() {
  const deviceId = document.getElementById('cmdb-asset-deviceid').value;
  if (!deviceId) return;
  const enabled = document.getElementById('cmdb-snmp-enabled').checked;
  if (!enabled) {
    _showSnmpInlineError('SNMP is disabled on this device. Tick "Enable SNMP polling" and Save first.');
    return;
  }
  // Disable the button + show in-progress so the user knows we're working
  const btn = document.querySelector('[data-action="pollCmdbSnmp"]');
  const prevText = btn ? btn.textContent : 'Poll now';
  if (btn) { btn.disabled = true; btn.textContent = 'Polling…'; }
  _showSnmpInlineNotice('Polling SNMP target (up to 4 s)…');
  try {
    const r = await api('POST', `/devices/${encodeURIComponent(deviceId)}/snmp/poll`, {});
    if (r && r.ok) {
      _renderCmdbSnmpData(r.data);
      if (r.data && r.data.last_ok) {
        toast('Polled OK — see Latest poll below', 'success');
        _showSnmpInlineNotice(`Last successful poll: ${_formatTs(r.data.last_ok)}`, 'success');
      } else {
        toast('Poll failed — see error below', 'error');
        _showSnmpInlineError(r.data && r.data.last_error ? r.data.last_error
                                                          : 'Unknown error');
      }
    } else {
      const msg = (r && r.error) || 'Poll request failed';
      toast(msg, 'error');
      _showSnmpInlineError(msg);
    }
  } catch (e) {
    _showSnmpInlineError(`Network error: ${e && e.message ? e.message : e}`);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = prevText; }
  }
}

function _showSnmpInlineError(msg) {
  const el = document.getElementById('cmdb-snmp-data');
  if (!el) return;
  el.innerHTML = `<div class="sev-pill sev-critical">error</div> <span>${_escapeHtml(msg)}</span>`;
}
function _showSnmpInlineNotice(msg, kind) {
  const el = document.getElementById('cmdb-snmp-data');
  if (!el) return;
  const pillCls = kind === 'success' ? 'sev-pill sev-success' : 'sev-pill sev-medium';
  el.innerHTML = `<div class="${pillCls}">${kind || 'info'}</div> <span>${_escapeHtml(msg)}</span>`;
}

// ── v2.0: multi-doc list ─────────────────────────────────────────────────────
//
// _cmdbCurrent.docs holds the canonical list. cmdbRenderDocs() repaints the
// .cmdb-docs-list container; per-doc add/edit/delete operations mutate the
// list in place after a successful API response, then re-render. We don't
// re-fetch the whole asset for each change — the modal stays open and
// responsive.

function cmdbRenderDocs(docs) {
  const list  = document.getElementById('cmdb-docs-list');
  const empty = document.getElementById('cmdb-docs-empty');
  if (!docs || docs.length === 0) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  // Each doc is a <details> card so the body collapses by default —
  // an asset with 10 docs shouldn't take 10 screens of vertical space.
  // The first doc is open by default (most common case is "show me
  // the runbook" without a click).
  list.innerHTML = docs.map((doc, idx) => {
    const created = doc.created_at ? new Date(doc.created_at * 1000).toISOString().split('T')[0] : '';
    const updated = doc.updated_at ? new Date(doc.updated_at * 1000).toISOString().split('T')[0] : '';
    const meta = (created === updated || !created)
      ? (updated ? `updated ${updated}` : '')
      : `created ${created}, updated ${updated}`;
    return `<details class="cmdb-doc-card isl-431" ${idx === 0 ? 'open' : ''}>
      <summary class="isl-432">
        <span class="meta-sm-nm">▸</span>
        <span class="isl-433">${cmdbEscHtml(doc.title || '(untitled)')}</span>
        <span class="hint">${meta}</span>
        <button class="btn-icon isl-434" data-stop-prop="1" data-prevent-default="1" data-action="cmdbDocEditOpen" data-arg="${doc.id}" >Edit</button>
        <button class="btn-icon isl-435" data-stop-prop="1" data-prevent-default="1" data-action="cmdbDocDelete" data-arg="${doc.id}" >Delete</button>
      </summary>
      <div class="isl-436">
        ${cmdbRenderMarkdown(doc.body || '')}
      </div>
    </details>`;
  }).join('');
}

function cmdbEscHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function cmdbDocAddOpen() {
  document.getElementById('cmdb-doc-modal-mode').value = 'add';
  document.getElementById('cmdb-doc-modal-docid').value = '';
  document.getElementById('cmdb-doc-modal-deviceid').value =
    _cmdbCurrent ? _cmdbCurrent.device_id : '';
  document.getElementById('cmdb-doc-modal-title').textContent = 'Add document';
  document.getElementById('cmdb-doc-modal-title-input').value = '';
  document.getElementById('cmdb-doc-modal-body').value = '';
  cmdbDocModalSwitch('edit');
  openModal('cmdb-doc-edit-modal');
  setTimeout(() => document.getElementById('cmdb-doc-modal-title-input').focus(), 60);
}

function cmdbDocEditOpen(docId) {
  if (!_cmdbCurrent) return;
  const doc = (_cmdbCurrent.docs || []).find(d => d.id === docId);
  if (!doc) return;
  document.getElementById('cmdb-doc-modal-mode').value = 'edit';
  document.getElementById('cmdb-doc-modal-docid').value = docId;
  document.getElementById('cmdb-doc-modal-deviceid').value = _cmdbCurrent.device_id;
  document.getElementById('cmdb-doc-modal-title').textContent = 'Edit document';
  document.getElementById('cmdb-doc-modal-title-input').value = doc.title || '';
  document.getElementById('cmdb-doc-modal-body').value = doc.body || '';
  cmdbDocModalSwitch('edit');
  openModal('cmdb-doc-edit-modal');
}

function cmdbDocModalSwitch(mode) {
  const ta = document.getElementById('cmdb-doc-modal-body');
  const pv = document.getElementById('cmdb-doc-modal-preview');
  document.getElementById('cmdb-doc-modal-edit-btn').classList.toggle('active', mode === 'edit');
  document.getElementById('cmdb-doc-modal-preview-btn').classList.toggle('active', mode === 'preview');
  if (mode === 'edit') {
    ta.style.display = 'block';
    pv.style.display = 'none';
  } else {
    ta.style.display = 'none';
    pv.style.display = 'block';
    pv.innerHTML = cmdbRenderMarkdown(ta.value || '');
  }
}

async function cmdbDocSave() {
  const mode    = document.getElementById('cmdb-doc-modal-mode').value;
  const devId   = document.getElementById('cmdb-doc-modal-deviceid').value;
  const docId   = document.getElementById('cmdb-doc-modal-docid').value;
  const title   = document.getElementById('cmdb-doc-modal-title-input').value.trim();
  const body    = document.getElementById('cmdb-doc-modal-body').value;

  if (!title) {
    alert('Title is required.');
    return;
  }
  let res;
  if (mode === 'add') {
    res = await cmdbApi('POST', `/cmdb/${encodeURIComponent(devId)}/docs`,
                        { title, body });
  } else {
    res = await cmdbApi('PUT',
                        `/cmdb/${encodeURIComponent(devId)}/docs/${encodeURIComponent(docId)}`,
                        { title, body });
  }
  if (!res) return;
  if (!res.ok) {
    alert('Save failed: ' + (res.data && res.data.error || res.status));
    return;
  }
  // Update _cmdbCurrent.docs in place — promotes legacy doc id if the
  // server changed it (the 'legacy' → real-id swap during edit).
  const newDoc = res.data;
  if (mode === 'add') {
    if (!_cmdbCurrent.docs) _cmdbCurrent.docs = [];
    _cmdbCurrent.docs.push(newDoc);
  } else {
    const idx = _cmdbCurrent.docs.findIndex(d => d.id === docId);
    if (idx >= 0) _cmdbCurrent.docs[idx] = newDoc;
  }
  cmdbRenderDocs(_cmdbCurrent.docs);
  closeModal('cmdb-doc-edit-modal');
  // Refresh the list view's "has docs" indicator on the next list refresh
  cmdbReloadList();
}

async function cmdbDocDelete(docId) {
  if (!_cmdbCurrent) return;
  const doc = (_cmdbCurrent.docs || []).find(d => d.id === docId);
  if (!doc) return;
  if (!confirm(`Delete document "${doc.title}"?`)) return;
  const res = await cmdbApi('DELETE',
    `/cmdb/${encodeURIComponent(_cmdbCurrent.device_id)}/docs/${encodeURIComponent(docId)}`);
  if (!res) return;
  if (!res.ok) {
    alert('Delete failed: ' + (res.data && res.data.error || res.status));
    return;
  }
  _cmdbCurrent.docs = (_cmdbCurrent.docs || []).filter(d => d.id !== docId);
  cmdbRenderDocs(_cmdbCurrent.docs);
  cmdbReloadList();
}

// Tiny Markdown renderer — headings, bold, italic, code, links, lists.
// Deliberately conservative: anything not matched stays as escaped text.
function cmdbRenderMarkdown(src) {
  if (!src) return '<div class="c-muted">No content.</div>';
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const lines = src.split('\n');
  const out = [];
  let inCode = false, inList = false;
  for (let raw of lines) {
    if (raw.startsWith('```')) {
      if (inCode) { out.push('</code></pre>'); inCode = false; }
      else        { out.push('<pre class="isl-437"><code>'); inCode = true; }
      continue;
    }
    if (inCode) { out.push(esc(raw)); continue; }
    if (/^- /.test(raw)) {
      if (!inList) { out.push('<ul class="isl-438">'); inList = true; }
      out.push('<li>' + cmdbInlineMd(esc(raw.slice(2))) + '</li>');
      continue;
    } else if (inList) { out.push('</ul>'); inList = false; }

    if (/^### /.test(raw))      out.push('<h4 class="isl-439">' + cmdbInlineMd(esc(raw.slice(4))) + '</h4>');
    else if (/^## /.test(raw))  out.push('<h3 class="isl-440">' + cmdbInlineMd(esc(raw.slice(3))) + '</h3>');
    else if (/^# /.test(raw))   out.push('<h2 class="isl-441">' + cmdbInlineMd(esc(raw.slice(2))) + '</h2>');
    else if (raw.trim() === '') out.push('<br>');
    else out.push('<div>' + cmdbInlineMd(esc(raw)) + '</div>');
  }
  if (inList) out.push('</ul>');
  if (inCode) out.push('</code></pre>');
  return out.join('\n');
}

function cmdbInlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, '<code class="isl-442">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,
             '<a href="$2" target="_blank" rel="noopener" class="c-accent">$1</a>');
}

async function cmdbAssetSave() {
  const deviceId = document.getElementById('cmdb-asset-deviceid').value;
  // v2.0: docs are managed via their own CRUD endpoints (cmdbDocSave /
  // cmdbDocDelete), not bundled into this asset PUT. The legacy
  // 'documentation' field is no longer sent — server-side back-compat
  // still accepts it, so old clients keep working, but new clients
  // route doc edits through the dedicated endpoints which support
  // multiple titled docs per asset.
  const body = {
    asset_id:        document.getElementById('cmdb-asset-id').value.trim(),
    server_function: document.getElementById('cmdb-asset-function').value.trim(),
    vlan:            document.getElementById('cmdb-asset-vlan').value.trim(),
    hypervisor_url:  document.getElementById('cmdb-asset-hypervisor').value.trim(),
    ssh_port:        parseInt(document.getElementById('cmdb-asset-ssh-port').value, 10) || 22,
  };
  const res = await cmdbApi('PUT', '/cmdb/' + encodeURIComponent(deviceId), body);
  if (!res) return;
  if (!res.ok) { alert('Save failed: ' + (res.data && res.data.error || res.status)); return; }
  closeModal('cmdb-asset-modal');
  cmdbReloadList();
  cmdbLoadServerFunctions();
}

// ── Credentials sub-tab ──────────────────────────────────────────────────────

async function cmdbLoadCreds(deviceId) {
  if (!deviceId) return;
  const warn = document.getElementById('cmdb-creds-locked-warning');
  const addBtn = document.getElementById('cmdb-creds-add-btn');
  const locked = !_cmdbVaultKey;
  warn.style.display = (locked && _cmdbVaultMeta && _cmdbVaultMeta.configured) ? 'block' : 'none';
  addBtn.disabled = locked;
  addBtn.style.opacity = locked ? '0.5' : '1';

  const res = await cmdbApi('GET', '/cmdb/' + encodeURIComponent(deviceId) + '/credentials');
  if (!res || !res.ok) return;
  const creds = (res.data && res.data.credentials) || [];
  const list = document.getElementById('cmdb-creds-list');
  if (creds.length === 0) {
    list.innerHTML = '<div class="isl-232">No credentials yet.</div>';
    return;
  }
  list.innerHTML = creds.map(c => {
    const note = c.note ? `<div class="isl-69">${_cmdbEsc(c.note)}</div>` : '';
    // v1.10.0: per-credential SSH link. Builds ssh://user@host:port for the
    // anchor + plain `ssh user@host -p port` for the copy button. Host comes
    // from the current asset's hostname (preferred) falling back to its IP.
    // The ssh:// URI deliberately omits the password — the password lives in
    // the reveal modal where it belongs, not in browser history.
    const sshHost = (_cmdbCurrent && (_cmdbCurrent.hostname || _cmdbCurrent.ip)) || '';
    const sshPort = (_cmdbCurrent && _cmdbCurrent.ssh_port) || 22;
    const sshUser = c.username || '';
    let sshButtons = '';
    if (sshHost && sshUser) {
      const portFrag = sshPort && sshPort !== 22 ? `:${sshPort}` : '';
      const sshUri = `ssh://${encodeURIComponent(sshUser)}@${sshHost}${portFrag}`;
      const sshCmd = sshPort && sshPort !== 22
        ? `ssh ${sshUser}@${sshHost} -p ${sshPort}`
        : `ssh ${sshUser}@${sshHost}`;
      sshButtons =
        `<a class="btn-icon isl-443" href="${_cmdbEsc(sshUri)}" title="Open ssh:// link in your default handler">SSH</a>
         <button class="btn-icon" title="Copy: ${_cmdbEsc(sshCmd)}" data-action="cmdbSshCopy" data-arg="${_cmdbEsc(sshCmd)}" >Copy</button>`;
    }
    return `<div class="isl-444">
      <div class="isl-445">
        <div class="fw-600">${_cmdbEsc(c.label)}</div>
        <div class="isl-328">user: ${_cmdbEsc(c.username) || '—'}</div>
        ${note}
      </div>
      <div class="isl-446">
        ${sshButtons}
        <button class="btn-icon" ${locked ? 'disabled' : ''} data-action="cmdbCredReveal" data-arg="${_cmdbEsc(deviceId)}" data-arg2="${_cmdbEsc(c.id)}" >Reveal</button>
        <button class="btn-icon" ${locked ? 'disabled' : ''} data-action="cmdbCredEditOpen" data-arg="${_cmdbEsc(deviceId)}" data-arg2="${_cmdbEsc(c.id)}" data-arg3="${_cmdbEsc(c.label)}" data-arg4="${_cmdbEsc(c.username)}" data-arg5="${_cmdbEsc(c.note || '')}">Edit</button>
        <button class="btn-icon c-red" data-action="cmdbCredDelete" data-arg="${_cmdbEsc(deviceId)}" data-arg2="${_cmdbEsc(c.id)}" >Delete</button>
      </div>
    </div>`;
  }).join('');
}

function cmdbSshCopy(cmd) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(
      () => toast && toast('SSH command copied', 'success'),
      () => alert('Copy failed — your browser may block clipboard access on http://')
    );
  } else {
    const ta = document.createElement('textarea');
    ta.value = cmd; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); if (typeof toast === 'function') toast('SSH command copied', 'success'); }
    catch (e) { alert('Copy failed.'); }
    document.body.removeChild(ta);
  }
}

function cmdbCredAddOpen() {
  if (!_cmdbVaultKey) { alert('Unlock the vault first.'); return; }
  if (!_cmdbCurrent)  return;
  document.getElementById('cmdb-cred-modal-mode').value = 'add';
  document.getElementById('cmdb-cred-modal-deviceid').value = _cmdbCurrent.device_id;
  document.getElementById('cmdb-cred-modal-credid').value = '';
  document.getElementById('cmdb-cred-modal-title').textContent = 'Add credential';
  document.getElementById('cmdb-cred-label').value    = '';
  document.getElementById('cmdb-cred-username').value = '';
  document.getElementById('cmdb-cred-password').value = '';
  document.getElementById('cmdb-cred-note').value     = '';
  openModal('cmdb-cred-add-modal');
}

function cmdbCredEditOpen(deviceId, credId, label, username, note) {
  if (!_cmdbVaultKey) { alert('Unlock the vault first.'); return; }
  document.getElementById('cmdb-cred-modal-mode').value = 'edit';
  document.getElementById('cmdb-cred-modal-deviceid').value = deviceId;
  document.getElementById('cmdb-cred-modal-credid').value = credId;
  document.getElementById('cmdb-cred-modal-title').textContent = 'Edit credential';
  document.getElementById('cmdb-cred-label').value    = label || '';
  document.getElementById('cmdb-cred-username').value = username || '';
  document.getElementById('cmdb-cred-password').value = '';
  document.getElementById('cmdb-cred-password').placeholder = '(leave empty to keep current)';
  document.getElementById('cmdb-cred-note').value     = note || '';
  openModal('cmdb-cred-add-modal');
}

async function cmdbCredSave() {
  const mode     = document.getElementById('cmdb-cred-modal-mode').value;
  const deviceId = document.getElementById('cmdb-cred-modal-deviceid').value;
  const credId   = document.getElementById('cmdb-cred-modal-credid').value;
  const body = {
    label:    document.getElementById('cmdb-cred-label').value.trim(),
    username: document.getElementById('cmdb-cred-username').value,
    note:     document.getElementById('cmdb-cred-note').value,
  };
  const pw = document.getElementById('cmdb-cred-password').value;
  if (mode === 'add') {
    if (!pw) { alert('Password required.'); return; }
    body.password = pw;
    const res = await cmdbApi('POST',
      '/cmdb/' + encodeURIComponent(deviceId) + '/credentials',
      body, true);
    if (!res || !res.ok) { alert('Save failed: ' + (res && res.data && res.data.error || '?')); return; }
  } else {
    if (pw) body.password = pw;
    const res = await cmdbApi('PUT',
      '/cmdb/' + encodeURIComponent(deviceId) + '/credentials/' + encodeURIComponent(credId),
      body, !!pw);
    if (!res || !res.ok) { alert('Save failed: ' + (res && res.data && res.data.error || '?')); return; }
  }
  closeModal('cmdb-cred-add-modal');
  cmdbLoadCreds(deviceId);
  cmdbReloadList();
}

async function cmdbCredDelete(deviceId, credId) {
  if (!confirm('Delete this credential? The encrypted password will be permanently removed.')) return;
  const res = await cmdbApi('DELETE',
    '/cmdb/' + encodeURIComponent(deviceId) + '/credentials/' + encodeURIComponent(credId));
  if (!res || !res.ok) { alert('Delete failed.'); return; }
  cmdbLoadCreds(deviceId);
  cmdbReloadList();
}

async function cmdbCredReveal(deviceId, credId) {
  if (!_cmdbVaultKey) { alert('Unlock the vault first.'); return; }
  const res = await cmdbApi('POST',
    '/cmdb/' + encodeURIComponent(deviceId) + '/credentials/' + encodeURIComponent(credId) + '/reveal',
    null, true);
  if (!res || !res.ok) {
    alert('Reveal failed: ' + (res && res.data && res.data.error || '?'));
    return;
  }
  document.getElementById('cmdb-cred-reveal-label').textContent    = res.data.label || '—';
  document.getElementById('cmdb-cred-reveal-username').textContent = res.data.username || '—';
  document.getElementById('cmdb-cred-reveal-password').textContent = res.data.password || '';
  const noteWrap = document.getElementById('cmdb-cred-reveal-note-wrap');
  if (res.data.note) {
    noteWrap.style.display = 'block';
    document.getElementById('cmdb-cred-reveal-note').textContent = res.data.note;
  } else {
    noteWrap.style.display = 'none';
  }
  openModal('cmdb-cred-reveal-modal');
}

function cmdbCredRevealClose() {
  // Wipe DOM nodes so the plaintext doesn't linger in the markup.
  document.getElementById('cmdb-cred-reveal-label').textContent    = '—';
  document.getElementById('cmdb-cred-reveal-username').textContent = '—';
  document.getElementById('cmdb-cred-reveal-password').textContent = '—';
  document.getElementById('cmdb-cred-reveal-note').textContent     = '—';
  closeModal('cmdb-cred-reveal-modal');
}

function cmdbCredCopy(elId) {
  const el = document.getElementById(elId);
  const txt = el && el.textContent;
  if (!txt || txt === '—') return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt);
  } else {
    // Fallback for older browsers / non-HTTPS dev environments
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }
}
