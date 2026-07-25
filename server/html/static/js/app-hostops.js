// app-hostops.js — page module extracted from app.js (buildless classic script; all
// symbols stay global, same as the rest of the client JS).
// Three sibling host-operation pages that share only the device
// picker: App catalog, Cron/timers, and the File manager.

// ── v5.1.0: app catalog (one-click compose deploy) ──────────────────────────
let _catalogDev = null, _catalogApps = [];

async function loadCatalog() {
  if (!_catalogApps.length) {
    try { const r = await api('GET', '/app-catalog'); _catalogApps = r.apps || []; }
    catch (e) { /* render handles empty */ }
  }
  _renderCatalog();
}

async function _renderCatalogDeviceResults(term) {
  const box = document.getElementById('catalog-device-results');
  if (!box) return;
  const devs = await _scanDeviceList();
  const q = (term || '').toLowerCase().trim();
  let matches = devs;
  if (q) matches = devs.filter(d =>
    (d.name || '').toLowerCase().includes(q) || (d.ip || '').toLowerCase().includes(q) ||
    (d.group || '').toLowerCase().includes(q) || (d.tags || []).some(t => (t || '').toLowerCase().includes(q)));
  matches = matches.slice(0, 25);
  box.innerHTML = matches.length
    ? matches.map(d =>
        `<div class="pointer mb-8" data-action="pickCatalogDevice" data-arg="${escAttr(d.id)}" data-arg2="${escAttr(d.name || d.id)}"><strong>${escHtml(d.name || d.id)}</strong>${d.ip ? ` <span class="hint">${escHtml(d.ip)}</span>` : ''}</div>`).join('')
    : '<div class="empty-state">No matching devices.</div>';
  box.classList.remove('hidden');
}

function pickCatalogDevice(id, name) {
  // Keep the id an opaque string — the data-action dispatcher coerces all-numeric
  // args to Number, which would then miss the string-keyed devices store on deploy.
  _catalogDev = { id: String(id), name };
  document.getElementById('catalog-device-results').classList.add('hidden');
  document.getElementById('catalog-device-search').value = name;
  const cur = document.getElementById('catalog-device-current');
  if (cur) cur.textContent = 'Target: ' + name;
  _renderCatalog();
}
// v6.0.1: the table's "Pick a host" button focuses the target-host search so the
// picker is one obvious click away (it lives in a separate card above the table).
function focusCatalogHostSearch() {
  const s = document.getElementById('catalog-device-search');
  if (!s) return;
  s.scrollIntoView({ behavior: 'smooth', block: 'center' });
  s.focus();
}

function filterCatalog() { _renderCatalog(); }

function _renderCatalog() {
  const isAdmin = !!(_meCache && _meCache.admin);
  const addBtn = document.getElementById('catalog-add-btn');
  if (addBtn) addBtn.classList.toggle('hidden', !isAdmin);
  const box = document.getElementById('catalog-grid');
  if (!box) return;
  if (!_catalogApps.length) { box.innerHTML = '<div class="hint">No apps in the catalog.</div>'; return; }
  const q = (document.getElementById('catalog-filter')?.value || '').toLowerCase().trim();
  const apps = q
    ? _catalogApps.filter(a => (`${a.name || ''} ${a.category || ''} ${a.description || ''}`).toLowerCase().includes(q))
    : _catalogApps;
  if (!apps.length) { box.innerHTML = '<div class="empty-state">No apps match your search.</div>'; return; }
  // v6.0.1 (item 4): render the catalog as a proper, full-width table instead of
  // a stack of cramped cards in a small scroll box — far more apps visible at once.
  const sorted = tableCtl.sortRows('catalog', apps.slice(), a => ({
    name: (a.name || '').toLowerCase(),
    category: (a.category || '').toLowerCase(),
    port: a.port || 0,
  }));
  const rows = sorted.map(a => {
    const dep = _catalogDev
      ? `<button class="btn-primary btn-sm" data-action="catalogDeploy" data-arg="${escAttr(a.id)}" title="Deploy to ${escAttr(_catalogDev.name)}">Deploy</button>`
      : `<button class="btn-icon btn-sm" data-action="focusCatalogHostSearch" title="Choose a target host above">Pick a host</button>`;
    const rm = (a.custom && isAdmin)
      ? `<button class="btn-icon c-danger-outline" title="Remove" data-action="removeCatalogApp" data-arg="${escAttr(a.id)}" data-arg2="${escAttr(a.name)}">${_icon('trash',14)}</button>`
      : '';
    const badge = a.custom ? ' <span class="rp-tag">custom</span>' : '';
    return `<tr>
      <td class="fw-600">${escHtml(a.name)}${badge}</td>
      <td class="hint">${escHtml(a.category || '—')}</td>
      <td class="fs-12">${escHtml(a.description || '')}</td>
      <td class="ta-center mono-12">${escHtml(String(a.port || '—'))}</td>
      <td><div class="user-actions">${dep}${rm}</div></td>
    </tr>`;
  }).join('');
  box.innerHTML = `<div class="table-card"><div class="scrollable-table-wrap audit-scroll"><table><thead id="catalog-thead"><tr><th scope="col" data-col="name">App</th><th scope="col" data-col="category">Category</th><th scope="col">Description</th><th scope="col" data-col="port" class="ta-center">Port</th><th scope="col"></th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  tableCtl.wireSortOnly('catalog-thead', 'catalog', _renderCatalog);
}

async function catalogDeploy(appId) {
  appId = String(appId);   // the data-action dispatcher coerces all-numeric args to Number
  if (!_catalogDev) { toast('Pick a target host first', 'error', {transient: true}); return; }
  const app = _catalogApps.find(a => a.id === appId);
  const label = app ? app.name : appId;
  if (!await uiConfirm({ message: `Deploy ${label} to ${_catalogDev.name}? It will run via Docker Compose on the host.`, confirmText: 'Deploy' })) return;
  try {
    const r = await api('POST', '/app-catalog/deploy', { device_id: _catalogDev.id, app_id: appId });
    toast(`${label} ${r.action === 'redeploy' ? 'redeploy' : 'deploy'} queued`, 'success');
  } catch (e) { toast(String(e), 'error'); }
}

// v5.1.0: admin can add a custom app (compose template) to the catalog.
function addCatalogApp() {
  ['catalog-add-name', 'catalog-add-category', 'catalog-add-port',
   'catalog-add-desc', 'catalog-add-yaml'].forEach(id => {
    const e = document.getElementById(id); if (e) e.value = '';
  });
  openModal('catalog-add-modal');
}

async function saveCatalogApp() {
  const val = id => (document.getElementById(id)?.value || '').trim();
  const name = val('catalog-add-name');
  const yaml = document.getElementById('catalog-add-yaml')?.value || '';
  if (!name) { toast('Name is required', 'error', {transient: true}); return; }
  if (!yaml.includes('services:')) { toast('Compose YAML must contain a "services:" block', 'error'); return; }
  try {
    const r = await api('POST', '/app-catalog/custom', {
      name, yaml,
      category: val('catalog-add-category'),
      description: val('catalog-add-desc'),
      port: parseInt(val('catalog-add-port'), 10) || 0,
    });
    if (!r || r.error) { toast((r && r.error) || 'Failed to add', 'error'); return; }
    toast(`${name} added to the catalog`, 'success');
    closeModal('catalog-add-modal');
    _catalogApps = [];
    loadCatalog();
  } catch (e) { toast(String(e), 'error'); }
}

async function removeCatalogApp(appId, label) {
  appId = String(appId);   // dispatcher coerces all-numeric args to Number
  if (!await uiConfirm({ message: `Remove ${label || appId} from the catalog? This does not affect already-deployed stacks.`, confirmText: 'Remove', danger: true })) return;
  try {
    const r = await api('POST', '/app-catalog/custom/delete', { id: appId });
    if (!r || r.error) { toast((r && r.error) || 'Failed to remove', 'error'); return; }
    toast('Removed from the catalog', 'success');
    _catalogApps = [];
    loadCatalog();
  } catch (e) { toast(String(e), 'error'); }
}

// ── v5.1.0: cron + systemd timer management ─────────────────────────────────
let _cronDev = null, _cronData = null;

async function loadCron() {
  const t = document.getElementById('cron-timers-tbody');
  if (t && !_cronDev) t.innerHTML = '<tr><td colspan="4" class="hint">Pick a host.</td></tr>';
}

async function _renderCronDeviceResults(term) {
  const box = document.getElementById('cron-device-results');
  if (!box) return;
  const devs = await _scanDeviceList();
  const q = (term || '').toLowerCase().trim();
  let matches = devs;
  if (q) matches = devs.filter(d =>
    (d.name || '').toLowerCase().includes(q) || (d.ip || '').toLowerCase().includes(q) ||
    (d.group || '').toLowerCase().includes(q) || (d.tags || []).some(t => (t || '').toLowerCase().includes(q)));
  matches = matches.slice(0, 25);
  box.innerHTML = matches.length
    ? matches.map(d =>
        `<div class="pointer mb-8" data-action="pickCronDevice" data-arg="${escAttr(d.id)}" data-arg2="${escAttr(d.name || d.id)}"><strong>${escHtml(d.name || d.id)}</strong>${d.ip ? ` <span class="hint">${escHtml(d.ip)}</span>` : ''}</div>`).join('')
    : '<div class="empty-state">No matching devices.</div>';
  box.classList.remove('hidden');
}

function pickCronDevice(id, name) {
  _cronDev = { id, name };
  document.getElementById('cron-device-results').classList.add('hidden');
  document.getElementById('cron-device-search').value = name;
  const cur = document.getElementById('cron-device-current');
  if (cur) cur.textContent = 'Host: ' + name;
  document.getElementById('cron-body').classList.remove('hidden');
  cronRefresh();
}

async function cronRefresh() {
  if (!_cronDev) return;
  try {
    const r = await api('GET', `/cron?device=${encodeURIComponent(_cronDev.id)}`);
    _cronData = r.device || {};
    _renderCronTimers();
    _renderCronSystemwide();
    cronLoadUser();
  } catch (e) { toast(String(e), 'error'); }
}

function _renderCronTimers() {
  const tb = document.getElementById('cron-timers-tbody');
  if (!tb) return;
  tableCtl.wireSortOnly('cron-timers-thead', 'crontimers', () => _renderCronTimers());
  const list = (_cronData && _cronData.timer_list) || [];
  const rows = tableCtl.sortRows('crontimers', list, t => ({
    unit: t.unit, activates: t.activates, failed: t.failed ? 1 : 0 }));
  if (!rows.length) { tb.innerHTML = '<tr><td colspan="4" class="empty-state">No timers reported.</td></tr>'; return; }
  tb.innerHTML = rows.map(t => {
    const u = escAttr(t.unit);
    const btns = ['enable', 'disable', 'start', 'stop'].map(a =>
      `<button class="btn-icon" data-action="cronTimer" data-arg="${escAttr(a)}" data-arg2="${u}">${a}</button>`).join(' ');
    const state = t.failed ? '<span class="c-accent">failed</span>' : '<span class="hint">ok</span>';
    return `<tr><td>${escHtml(t.unit)}</td><td>${escHtml(t.activates || '')}</td><td>${state}</td><td>${btns}</td></tr>`;
  }).join('');
}

function _renderCronSystemwide() {
  const box = document.getElementById('cron-systemwide');
  if (!box) return;
  const cd = (_cronData && _cronData.cron_d) || [];
  box.innerHTML = cd.length
    ? cd.map(fl => `<div class="mb-8"><strong>${escHtml(fl.file)}</strong><pre class="hint">${escHtml((fl.lines || []).join('\n'))}</pre></div>`).join('')
    : '<div class="hint">None reported.</div>';
}

function cronLoadUser() {
  const user = (document.getElementById('cron-user').value || 'root').trim() || 'root';
  const ct = ((_cronData && _cronData.crontabs) || []).find(c => c.user === user);
  document.getElementById('cron-content').value = ct ? (ct.lines || []).join('\n') : '';
}

async function cronSaveUser() {
  if (!_cronDev) { toast('Pick a host first', 'error', {transient: true}); return; }
  const user = (document.getElementById('cron-user').value || 'root').trim() || 'root';
  const content = document.getElementById('cron-content').value;
  try {
    const r = await api('POST', `/devices/${_cronDev.id}/cron-action`, { op: 'set', user, content });
    if (!r || r.error) { toast((r && r.error) || 'Failed to queue', 'error'); return; }
    toast(`Crontab for ${user} queued`, 'success');
  } catch (e) { toast(String(e), 'error'); }
}

async function cronDelUser() {
  if (!_cronDev) return;
  const user = (document.getElementById('cron-user').value || 'root').trim() || 'root';
  if (!await uiConfirm({ message: `Remove ${user}'s crontab on ${_cronDev.name}?`, danger: true, confirmText: 'Remove' })) return;
  try {
    const r = await api('POST', `/devices/${_cronDev.id}/cron-action`, { op: 'del', user });
    if (!r || r.error) { toast((r && r.error) || 'Failed to queue', 'error'); return; }
    toast('Removal queued', 'success');
  } catch (e) { toast(String(e), 'error'); }
}

async function cronTimer(action, unit) {
  if (!_cronDev) return;
  try {
    const r = await api('POST', `/devices/${_cronDev.id}/cron-action`, { op: 'timer', action, unit });
    if (!r || r.error) { toast((r && r.error) || 'Failed to queue', 'error'); return; }
    toast(`${action} ${unit} queued`, 'success');
  } catch (e) { toast(String(e), 'error'); }
}

// ── v5.1.0: web file manager ────────────────────────────────────────────────
let _fmDev = null;        // {id, name}
let _fmCwd = '/etc';
let _fmEditing = null;    // path currently open in the editor
let _fmRows = [];
let _fmArchiveJob = null; // {id, path} of the in-flight archive job, or null
let _fmArchiveTimer = null;

async function loadFileMgr() {
  const tbody = document.getElementById('fm-tbody');
  if (tbody && !_fmDev) tbody.innerHTML = '<tr><td colspan="6" class="hint">Pick a host, then Open a path.</td></tr>';
}

async function _renderFmDeviceResults(term) {
  const box = document.getElementById('fm-device-results');
  if (!box) return;
  const devs = await _scanDeviceList();
  const q = (term || '').toLowerCase().trim();
  let matches = devs;
  if (q) matches = devs.filter(d =>
    (d.name || '').toLowerCase().includes(q) || (d.ip || '').toLowerCase().includes(q) ||
    (d.hostname || '').toLowerCase().includes(q) || (d.group || '').toLowerCase().includes(q) ||
    (d.tags || []).some(t => (t || '').toLowerCase().includes(q)));
  matches = matches.slice(0, 25);
  box.innerHTML = matches.length
    ? matches.map(d =>
        `<div class="pointer mb-8" data-action="pickFmDevice" data-arg="${escAttr(d.id)}" data-arg2="${escAttr(d.name || d.id)}"><strong>${escHtml(d.name || d.id)}</strong>${d.ip ? ` <span class="hint">${escHtml(d.ip)}</span>` : ''}</div>`).join('')
    : '<div class="empty-state">No matching devices.</div>';
  box.classList.remove('hidden');
}

function pickFmDevice(id, name) {
  _fmDev = { id, name };
  const box = document.getElementById('fm-device-results');
  if (box) box.classList.add('hidden');
  const inp = document.getElementById('fm-device-search');
  if (inp) inp.value = name;
  const cur = document.getElementById('fm-device-current');
  if (cur) cur.textContent = 'Host: ' + name;
  document.getElementById('fm-browser').classList.remove('hidden');
  fmListPath('/etc');
}

async function fmListPath(p) {
  if (!_fmDev) { toast('Pick a host first', 'error', {transient: true}); return; }
  const path = (typeof p === 'string' && p) ? p : (document.getElementById('fm-path').value.trim() || '/');
  _fmCwd = path;
  document.getElementById('fm-path').value = path;
  fmCloseEditor();
  const tbody = document.getElementById('fm-tbody');
  tbody.innerHTML = _skeletonRows(6);
  try {
    const r = await api('GET', `/devices/${_fmDev.id}/files?op=list&path=${encodeURIComponent(path)}`);
    if (!r.ok) { tbody.innerHTML = `<tr><td colspan="6" class="hint">${escHtml((r.result && r.result.error) || r.error || r.message || 'Failed to list')}</td></tr>`; return; }
    _fmRows = (r.result && r.result.entries) || [];
    const sm = document.getElementById('fm-summary');
    if (sm) sm.textContent = `${_fmRows.length} entr${_fmRows.length === 1 ? 'y' : 'ies'}`;
    _renderFm();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="hint">Failed: ${escHtml(String(e))}</td></tr>`;
  }
}

function _renderFm() {
  const tbody = document.getElementById('fm-tbody');
  if (!tbody) return;
  tableCtl.wireSortOnly('fm-thead', 'filemgr', () => _renderFm());
  const rows = tableCtl.sortRows('filemgr', _fmRows || [], r => ({
    name: r.name, type: r.type, size: r.size, mtime: r.mtime, mode: r.mode }));
  if (!rows.length) { tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Empty directory.</td></tr>'; return; }
  const base = _fmCwd.endsWith('/') ? _fmCwd : _fmCwd + '/';
  tbody.innerHTML = rows.map(r => {
    const isDir = r.type === 'dir';
    const child = base + r.name;
    const act = isDir
      ? `<button class="btn-icon" data-action="fmListPath" data-arg="${escAttr(child)}">Open</button> `
        + `<button class="btn-icon" data-action="fmArchiveDir" data-arg="${escAttr(child)}">Download as .tar.gz</button>`
      : `<button class="btn-icon" data-action="fmOpen" data-arg="${escAttr(child)}">View / edit</button> `
        + `<button class="btn-icon" data-action="fmDownload" data-arg="${escAttr(child)}" data-arg2="${escAttr(r.name)}">Download</button>`;
    return `<tr><td>${escHtml(r.name)}</td><td>${escHtml(r.type)}</td><td>${isDir ? '' : _fmtBytes(r.size || 0)}</td><td>${escHtml(_fmtTs(r.mtime))}</td><td><span class="hint">${escHtml(r.mode || '')}</span></td><td>${act}</td></tr>`;
  }).join('');
}

async function fmOpen(path) {
  try {
    const r = await api('GET', `/devices/${_fmDev.id}/files?op=read&path=${encodeURIComponent(path)}`);
    if (!r.ok) { toast((r.result && r.result.error) || r.error || r.message || 'Read failed', 'error'); return; }
    const res = r.result || {};
    if (res.binary) { toast('Binary file — not editable', 'error'); return; }
    _fmEditing = path;
    document.getElementById('fm-editor').classList.remove('hidden');
    document.getElementById('fm-editor-path').textContent = path;
    document.getElementById('fm-editor-meta').textContent =
      `${_fmtBytes(res.size || 0)}${res.truncated ? ' · truncated — read-only preview of the first 256 KiB (saving would overwrite the whole file, so editing a truncated file is blocked)' : ''}`;
    const ta = document.getElementById('fm-editor-content');
    ta.value = res.content || '';
    ta.readOnly = !!res.truncated;
  } catch (e) { toast(String(e), 'error'); }
}

// W3-50: download a file (binary-safe via content_b64) as a browser save.
async function fmDownload(path, name) {
  try {
    const r = await api('GET', `/devices/${_fmDev.id}/files?op=read&path=${encodeURIComponent(path)}`);
    if (!r.ok) { toast((r.result && r.result.error) || 'Download failed', 'error'); return; }
    const res = r.result || {};
    if (res.truncated) { toast('File too large to download through the agent channel (first 256 KiB only)', 'warning'); }
    let blob;
    if (res.binary && res.content_b64) {
      const bin = atob(res.content_b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      blob = new Blob([arr], { type: 'application/octet-stream' });
    } else {
      blob = new Blob([res.content || ''], { type: 'text/plain' });
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = name || 'download';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (e) { toast(String(e), 'error'); }
}

// v6.1.1: folder-as-tar streaming archive. A SEPARATE channel from fmDownload
// above (which round-trips one file through the request/response file-manager
// op) — the agent streams a whole directory back in bounded chunks over its
// own endpoint, so this starts a job then polls status instead of a single
// request/response call. See docs/feature-buildout-scoping-internal.md #9.
function fmArchiveCwd() {
  if (!_fmDev) { toast('Pick a host first', 'error', {transient: true}); return; }
  fmArchiveDir(_fmCwd);
}

async function fmArchiveDir(path) {
  if (!_fmDev) { toast('Pick a host first', 'error', {transient: true}); return; }
  if (_fmArchiveJob) { toast('An archive is already running — cancel it first', 'error'); return; }
  try {
    const r = await api('POST', `/devices/${_fmDev.id}/files/archive`, { path });
    if (!r || !r.ok) { toast((r && r.error) || 'Failed to start archive', 'error'); return; }
    _fmArchiveJob = { id: r.job_id, path };
    _fmArchiveShowProgress('Starting…');
    _fmArchiveTimer = setInterval(_fmArchivePoll, 2000);
  } catch (e) { toast(String(e), 'error'); }
}

function _fmArchiveShowProgress(text) {
  const wrap = document.getElementById('fm-archive-progress');
  const status = document.getElementById('fm-archive-status');
  if (wrap) wrap.classList.remove('hidden');
  if (status) status.textContent = text;
}

function _fmArchiveStopPolling() {
  if (_fmArchiveTimer) { clearInterval(_fmArchiveTimer); _fmArchiveTimer = null; }
}

async function _fmArchivePoll() {
  if (!_fmDev || !_fmArchiveJob) { _fmArchiveStopPolling(); return; }
  try {
    const r = await api('GET', `/devices/${_fmDev.id}/files/archive-status?job=${encodeURIComponent(_fmArchiveJob.id)}`);
    if (!r || !r.ok) { _fmArchiveFail('Lost track of the archive job'); return; }
    if (r.status === 'pending' || r.status === 'running') {
      _fmArchiveShowProgress(`${r.status === 'pending' ? 'Waiting for the agent…' : 'Archiving…'} ${_fmtBytes(r.bytes_received || 0)} so far`);
    } else if (r.status === 'done') {
      _fmArchiveStopPolling();
      _fmArchiveShowProgress('Done — downloading…');
      await _fmArchiveDownload();
      document.getElementById('fm-archive-progress').classList.add('hidden');
      _fmArchiveJob = null;
    } else {   // failed / cancelled
      _fmArchiveFail(r.error || (r.status === 'cancelled' ? 'Cancelled' : 'Archive failed'));
    }
  } catch (e) { _fmArchiveFail(String(e)); }
}

function _fmArchiveFail(message) {
  _fmArchiveStopPolling();
  toast(message, 'error');
  document.getElementById('fm-archive-progress').classList.add('hidden');
  _fmArchiveJob = null;
}

async function _fmArchiveDownload() {
  const job = _fmArchiveJob;
  if (!job) return;
  try {
    const resp = await fetch(`/api/devices/${_fmDev.id}/files/archive-download?job=${encodeURIComponent(job.id)}`,
                             { headers: { 'X-Token': getToken() } });
    if (!resp.ok) throw new Error('download failed');
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const base = job.path.split('/').filter(Boolean).pop() || 'archive';
    a.href = url; a.download = base + '.tar.gz';
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast('Archive downloaded', 'success');
  } catch (e) { toast('Download failed: ' + String(e), 'error'); }
}

async function fmArchiveCancel() {
  if (!_fmDev || !_fmArchiveJob) return;
  const job = _fmArchiveJob;
  _fmArchiveStopPolling();
  try { await api('POST', `/devices/${_fmDev.id}/files/archive-cancel`, { job_id: job.id }); } catch (_) { /* best-effort */ }
  document.getElementById('fm-archive-progress').classList.add('hidden');
  _fmArchiveJob = null;
  toast('Archive cancelled', 'success');
}

// W3-50: upload a picked file (base64) into the current directory.
function fmUpload() {
  if (!_fmDev) { toast('Pick a host first', 'error', {transient: true}); return; }
  const input = document.createElement('input');
  input.type = 'file';
  input.onchange = () => {
    const file = input.files && input.files[0];
    if (!file) return;
    if (file.size > 8 * 1024 * 1024) { toast('File exceeds the 8 MB upload limit', 'error'); return; }
    const reader = new FileReader();
    reader.onload = async () => {
      const b64 = String(reader.result).split(',')[1] || '';
      const base = _fmCwd.endsWith('/') ? _fmCwd : _fmCwd + '/';
      const dest = base + file.name;
      const r = await api('POST', `/devices/${_fmDev.id}/files`, { op: 'upload', path: dest, content: b64 });
      if (r.ok && !(r.result && r.result.error)) { toast('Uploaded ' + file.name, 'success'); fmListPath(_fmCwd); }
      else toast((r.result && r.result.error) || r.error || 'Upload failed', 'error');
    };
    reader.readAsDataURL(file);
  };
  input.click();
}

async function fmSave() {
  if (!_fmEditing) return;
  const ta = document.getElementById('fm-editor-content');
  if (ta.readOnly) { toast('File was truncated on read — refusing to overwrite', 'error'); return; }
  try {
    const r = await api('POST', `/devices/${_fmDev.id}/files`, { op: 'write', path: _fmEditing, content: ta.value });
    if (r.ok) toast('Saved', 'success');
    else toast((r.result && r.result.error) || r.error || r.message || 'Save failed', 'error');
  } catch (e) { toast(String(e), 'error'); }
}

async function fmDelete() {
  if (!_fmEditing) return;
  if (!await uiConfirm({ message: `Delete ${_fmEditing}?`, danger: true, confirmText: 'Delete' })) return;
  try {
    const r = await api('POST', `/devices/${_fmDev.id}/files`, { op: 'delete', path: _fmEditing });
    if (r.ok) { toast('Deleted', 'success'); fmCloseEditor(); fmListPath(_fmCwd); }
    else toast((r.result && r.result.error) || r.error || r.message || 'Delete failed', 'error');
  } catch (e) { toast(String(e), 'error'); }
}

function fmCloseEditor() {
  _fmEditing = null;
  const ed = document.getElementById('fm-editor');
  if (ed) ed.classList.add('hidden');
}

async function fmMkdir() {
  if (!_fmDev) { toast('Pick a host first', 'error', {transient: true}); return; }
  const name = await uiPrompt({ title: 'New folder', message: `Created under ${_fmCwd}`, placeholder: 'folder-name' });
  if (!name) return;
  const base = _fmCwd.endsWith('/') ? _fmCwd : _fmCwd + '/';
  try {
    const r = await api('POST', `/devices/${_fmDev.id}/files`, { op: 'mkdir', path: base + name });
    if (r.ok) { toast('Created', 'success'); fmListPath(_fmCwd); }
    else toast((r.result && r.result.error) || r.error || r.message || 'mkdir failed', 'error');
  } catch (e) { toast(String(e), 'error'); }
}

function fmUp() {
  const parts = _fmCwd.replace(/\/+$/, '').split('/');
  parts.pop();
  fmListPath(parts.join('/') || '/');
}
