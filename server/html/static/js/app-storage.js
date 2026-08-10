// app-storage.js — page module extracted from app.js (buildless classic script; all
// symbols stay global, same as the rest of the client JS).
// Storage / RAID health, maintenance actions and provisioning.

// ─── v3.11.0: Storage / RAID health ──────────────────────────────────────────
let _storageResp = null;
async function loadStorage() {
  const tbody = document.getElementById('storage-tbody');
  const summary = document.getElementById('storage-summary');
  if (!tbody) return;
  tableCtl.wireSortOnly('storage-thead', 'storage', () => _renderStorage());
  tbody.innerHTML = _skeletonRows(6);
  try {
    const data = await api('GET', '/storage');
    // api() resolves with {error} on 4xx/5xx — without this the summary
    // renders "undefined pools · undefined degraded" over an empty table.
    if (!data || data.count == null) throw new Error((data && data.error) || 'unexpected response');
    _storageResp = data;
    if (summary) summary.textContent = `${data.count} pools · ${data.degraded} degraded`;
    _renderStorage();
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state-error">Failed to load: ${escHtml(String(e))}</td></tr>`;
  }
}

function _renderStorage() {
  const tbody = document.getElementById('storage-tbody');
  if (!tbody || !_storageResp) return;
  let rows = (_storageResp.pools || []).slice();
  rows = tableCtl.sortRows('storage', rows, (r) => ({
    device:   (r.device || '').toLowerCase(),
    pool:     (r.pool || '').toLowerCase(),
    kind:     r.kind || '',
    state:    r.state || '',
    capacity: r.capacity || 0,
    scrub:    r.scrub || '',
  }));
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="isl-534">No ZFS / mdadm / btrfs pools reported. Agents must be on v3.11.0+.</td></tr>';
    return;
  }
  const { rows: shown, note } = _capFleetRows(rows, 7, 'pools');
  tbody.innerHTML = shown.map(r => {
    const color = r.degraded ? 'var(--red)' : 'var(--green)';
    const cap = (r.capacity || r.capacity === 0) && r.capacity !== null ? `${r.capacity}%` : '—';
    // ZFS/Btrfs pools get a one-click maintenance modal (scrub, trim/balance,
    // snapshots, …). mdraid and unmounted btrfs have no actionable target.
    const canAct = (r.kind === 'zfs' || r.kind === 'btrfs') && r.target;
    const maintBtn = canAct
      ? `<button class="btn-icon cell-sm" data-action="openStorageMaint" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.kind + '|' + r.target + '|' + (r.pool || ''))}" title="${r.online ? 'Run a maintenance command on this pool' : 'Host offline — the command queues until it reconnects'}">Maintain…</button>`
      : '<span class="hint">—</span>';
    return `<tr>
      <td class="fw-500">${escHtml(r.device)}</td>
      <td>${escHtml(r.pool || '—')}</td>
      <td class="hint">${escHtml(r.kind || '—')}</td>
      <td class="${r.degraded ? 'fw-600' : ''}" data-color="${color}">${escHtml(r.state || '—')}</td>
      <td>${cap}</td>
      <td class="hint">${escHtml(r.scrub || '—')}</td>
      <td class="nowrap">${maintBtn}</td>
    </tr>`;
  }).join('') + note;
}

// ─── v5.0.0: one-click ZFS/Btrfs pool maintenance ───────────────────────────
let _storageMaintCtx = null;   // {deviceId, kind, target, pool}
const _STORAGE_MAINT_ACTIONS = {
  zfs: [
    { a: 'scrub',     l: 'Scrub',          mut: 1 },
    { a: 'trim',      l: 'Trim SSDs',      mut: 1 },
    { a: 'clear',     l: 'Clear errors',   mut: 1 },
    { a: 'status',    l: 'Status',         mut: 0 },
    { a: 'snapshots', l: 'List snapshots', mut: 0 },
  ],
  btrfs: [
    { a: 'scrub',     l: 'Scrub',          mut: 1 },
    { a: 'balance',   l: 'Balance (50%)',  mut: 1 },
    { a: 'usage',     l: 'Usage',          mut: 0 },
    { a: 'devstats',  l: 'Device stats',   mut: 0 },
    { a: 'snapshots', l: 'List snapshots', mut: 0 },
  ],
};
let _storagePollTimer = null;
function openStorageMaint(deviceId, packed) {
  const [kind, target, pool] = String(packed || '').split('|');
  if (!_STORAGE_MAINT_ACTIONS[kind] || !target) { toast('No maintenance actions for this pool', 'error'); return; }
  _storageMaintCtx = { deviceId, kind, target, pool: pool || target };
  if (_storagePollTimer) { clearInterval(_storagePollTimer); _storagePollTimer = null; }
  document.getElementById('storage-maint-title').textContent = `${kind.toUpperCase()} maintenance — ${pool || target}`;
  document.getElementById('storage-maint-sub').textContent = `Target: ${target}. Read actions show their output below; scrubs/balances run in the background.`;
  const snapInput = document.getElementById('storage-maint-snap');
  if (snapInput) snapInput.value = '';
  const out = document.getElementById('storage-maint-output');
  if (out) { out.classList.add('d-none'); out.textContent = ''; }
  document.getElementById('storage-maint-actions').innerHTML = _STORAGE_MAINT_ACTIONS[kind].map(x =>
    `<button class="btn-secondary cell-sm" data-action="storageRunAction" data-arg="${escAttr(x.a)}">${escHtml(x.l)}</button>`
  ).join('');
  openModal('storage-maint-modal');
}
async function storageRunAction(action) {
  const c = _storageMaintCtx;
  if (!c) return;
  const def = (_STORAGE_MAINT_ACTIONS[c.kind] || []).find(x => x.a === action);
  const isRead = !(def && def.mut);   // status / usage / device-stats / list-snapshots
  if (!isRead) {
    if (!await uiConfirm(`Run "${def.l}" on ${c.kind} ${c.pool}?\n\nThe command queues on ${c.pool} and runs on the host. Scrubs/balances are IO-intensive and run in the background.`)) return;
  }
  const out = document.getElementById('storage-maint-output');
  if (isRead && out) {
    out.classList.remove('d-none');
    out.textContent = `Running ${def ? def.l.toLowerCase() : action} on ${c.pool}…\nWaiting for the host's next check-in (up to ~90s).`;
  }
  // Baseline against the server's OWN timestamps (not the browser clock) so we
  // only surface the NEW result, not a stale older run of the same command.
  let baseTs = 0;
  if (isRead) {
    const cur = await api('GET', `/devices/${encodeURIComponent(c.deviceId)}/output`).catch(() => null);
    baseTs = Math.max(0, ...(((cur && cur.outputs) || [])
      .filter(e => String(e.cmd || '').includes(c.target)).map(e => e.ts || 0)));
  }
  const r = await api('POST', `/devices/${encodeURIComponent(c.deviceId)}/storage-action`,
                      { kind: c.kind, action, target: c.target });
  if (!r || r.error) {
    toast('Failed: ' + ((r && r.error) || 'unknown'), 'error');
    if (isRead && out) out.textContent = 'Failed: ' + ((r && r.error) || 'unknown');
    return;
  }
  if (!isRead) { toast(`Queued: ${action} on ${c.pool}. Runs on the host; pool status updates on the next check-in.`, 'success'); return; }
  _pollStorageOutput(c.deviceId, c.target, baseTs, action);
}
// Poll the host's command output for the result of a just-queued read action and
// show it in the modal. Reuses the standard /output buffer (capped 100/host).
function _pollStorageOutput(deviceId, target, baseTs, action) {
  if (_storagePollTimer) { clearInterval(_storagePollTimer); }
  const out = document.getElementById('storage-maint-output');
  const deadline = Date.now() + 95000;
  let dots = 0;
  _storagePollTimer = setInterval(async () => {
    // Stop if the modal was closed or context changed.
    if (!_storageMaintCtx || _storageMaintCtx.deviceId !== deviceId
        || !document.getElementById('storage-maint-modal')?.classList.contains('active')) {
      clearInterval(_storagePollTimer); _storagePollTimer = null; return;
    }
    const data = await api('GET', `/devices/${encodeURIComponent(deviceId)}/output`).catch(() => null);
    const list = (data && data.outputs) || [];
    // Newest matching entry for this pool/mount that landed after we queued.
    const hit = list.filter(e => e && (e.ts || 0) > baseTs && String(e.cmd || '').includes(target)).pop();
    if (hit) {
      clearInterval(_storagePollTimer); _storagePollTimer = null;
      if (action === 'snapshots') { _renderSnapshotList(out, target, hit); return; }
      const rcline = (typeof hit.rc === 'number' && hit.rc !== 0) ? `\n\n(exit code ${hit.rc})` : '';
      if (out) out.textContent = `$ ${hit.cmd}\n\n${hit.output || '(no output)'}${rcline}`;
      return;
    }
    if (Date.now() > deadline) {
      clearInterval(_storagePollTimer); _storagePollTimer = null;
      if (out) out.textContent = 'No output yet — the host may be offline or checking in slowly. It will appear in the host’s command output when it reports back.';
      return;
    }
    if (out) { dots = (dots + 1) % 4; out.textContent = out.textContent.replace(/\.*$/, '') + '.'.repeat(dots); }
  }, 3000);
}
async function storageDeleteSnapshot() {
  const c = _storageMaintCtx;
  if (!c) return;
  const snap = (document.getElementById('storage-maint-snap')?.value || '').trim();
  if (!snap) { toast('Enter the exact snapshot name to delete', 'error', {transient: true}); return; }
  if (!await uiConfirm(`Permanently DELETE snapshot:\n\n${snap}\n\nThis cannot be undone.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(c.deviceId)}/storage-action`,
                      { kind: c.kind, action: c.kind === 'zfs' ? 'destroy' : 'delete', target: c.target, snapshot: snap });
  if (!r || r.error) { toast('Failed: ' + ((r && r.error) || 'unknown'), 'error'); return; }
  toast('Snapshot deletion queued.', 'success');
  const snapInput = document.getElementById('storage-maint-snap');
  if (snapInput) snapInput.value = '';
}

// Parse a snapshot listing into individual deletable names so you can remove
// snapshots from the list without copy-pasting paths.
//  - zfs `zfs list -t snapshot`: first column is the name (contains '@').
//  - btrfs `subvolume list -s`: each line ends in `path <subvol>`; the deletable
//    path is that joined onto the filesystem mountpoint (the target).
function _parseSnapshotNames(kind, target, text) {
  const lines = String(text || '').split('\n');
  if (kind === 'zfs') {
    return lines.map(l => l.trim().split(/\s+/)[0]).filter(t => t && t.includes('@'));
  }
  const base = (target === '/' ? '' : target.replace(/\/+$/, ''));
  const out = [];
  for (const l of lines) {
    const m = l.match(/\bpath\s+(.+?)\s*$/);
    if (!m) continue;
    const rel = m[1].trim();
    out.push(rel.startsWith('/') ? rel : `${base}/${rel}`);
  }
  return out;
}
function _renderSnapshotList(out, target, hit) {
  const c = _storageMaintCtx;
  if (!out || !c) return;
  const names = _parseSnapshotNames(c.kind, target, hit.output);
  if (!names.length) {
    out.textContent = `$ ${hit.cmd}\n\n${hit.output || '(no snapshots)'}`;
    return;
  }
  const rows = names.map(n =>
    `<div class="row-8-center mb-4"><code class="fl-1 ellipsis">${escHtml(n)}</code><button class="btn-icon cell-sm c-red c-danger-outline" data-action="storageDeleteNamedSnapshot" data-arg="${escAttr(n)}" title="Delete this snapshot">${_icon('trash',14)}</button></div>`
  ).join('');
  // If the host truncated the output (very long list), say so + point at the
  // right tool for bulk cleanup rather than implying the list is complete.
  const truncated = /truncated/i.test(hit.output || '');
  let note = '';
  if (truncated) {
    note = `<div class="c-amber mb-8 fs-12"><strong>The list was truncated</strong> — you have more snapshots than shown. For bulk cleanup use the host's snapshot manager (snapper: <code>snapper delete &lt;N&gt;</code> or a timeline-cleanup policy; or <code>zfs destroy</code> with a range), rather than deleting hundreds one by one.</div>`;
  } else if (/\.snapshots\/\d+\/snapshot/.test(hit.output || '')) {
    note = `<div class="hint mb-8 fs-12">These look like <strong>snapper</strong>-managed snapshots — deleting the subvolume reclaims space but leaves snapper's metadata; <code>snapper delete &lt;N&gt;</code> keeps it consistent.</div>`;
  }
  out.innerHTML = `<div class="row-8-center mb-8"><strong>${names.length} snapshot${names.length === 1 ? '' : 's'}</strong> on ${escHtml(c.pool)} — click Delete to remove one (destructive).</div>${note}${rows}`;
}
async function storageDeleteNamedSnapshot(snap) {
  const c = _storageMaintCtx;
  if (!c || !snap) return;
  if (!await uiConfirm(`Permanently DELETE snapshot:\n\n${snap}\n\nThis cannot be undone.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(c.deviceId)}/storage-action`,
                      { kind: c.kind, action: c.kind === 'zfs' ? 'destroy' : 'delete', target: c.target, snapshot: snap });
  if (!r || r.error) { toast('Failed: ' + ((r && r.error) || 'unknown'), 'error'); return; }
  toast('Snapshot deletion queued: ' + snap, 'success');
}

// ─── v6.1.1: guided storage provisioning (create, not just maintain) ────────
// Whole-disk RAID/LVM/mkfs, not a general partition editor -- see the
// _sp_build module comment in api.py for the full guardrail rationale.
// Preview (dry_run) is a UI convenience; the server independently verifies
// the typed confirm value on the real call, so this client-side check is
// not the security boundary, just faster feedback.
let _spDryRunResult = null;   // {command, confirm_target} from the last preview

function _spFieldsHtml(recipe) {
  if (recipe === 'mdadm_create') {
    return `<div class="form-group"><label class="form-label">RAID device</label><input type="text" id="sp-p-device" class="form-input ff-mono" placeholder="/dev/md0"></div>
      <div class="form-group"><label class="form-label">RAID level</label><select id="sp-p-level" class="form-input">
        <option value="0">0 (striping, no redundancy)</option><option value="1" selected>1 (mirror)</option>
        <option value="5">5</option><option value="6">6</option><option value="10">10</option></select></div>
      <div class="form-group"><label class="form-label">Member devices (one per line, whole-disk only)</label>
        <textarea id="sp-p-members" class="form-input ff-mono" rows="3" placeholder="/dev/sdb&#10;/dev/sdc"></textarea></div>`;
  }
  if (recipe === 'lvm_pvcreate') {
    return `<div class="form-group"><label class="form-label">Devices (one per line, whole-disk only)</label>
      <textarea id="sp-p-members" class="form-input ff-mono" rows="3" placeholder="/dev/sdb"></textarea></div>`;
  }
  if (recipe === 'lvm_vgcreate') {
    return `<div class="form-group"><label class="form-label">Volume group name</label><input type="text" id="sp-p-vgname" class="form-input ff-mono" placeholder="data"></div>
      <div class="form-group"><label class="form-label">Devices (one per line, whole-disk only)</label>
        <textarea id="sp-p-members" class="form-input ff-mono" rows="3" placeholder="/dev/sdb"></textarea></div>`;
  }
  if (recipe === 'lvm_lvcreate') {
    return `<div class="form-group"><label class="form-label">Volume group</label><input type="text" id="sp-p-vgname" class="form-input ff-mono" placeholder="data"></div>
      <div class="form-group"><label class="form-label">Logical volume name</label><input type="text" id="sp-p-lvname" class="form-input ff-mono" placeholder="store"></div>
      <div class="form-group"><label class="form-label">Size (blank = 100% free)</label><input type="text" id="sp-p-size" class="form-input ff-mono" placeholder="500G"></div>`;
  }
  if (recipe === 'mkfs') {
    return `<div class="form-group"><label class="form-label">Device (whole-disk)</label><input type="text" id="sp-p-device" class="form-input ff-mono" placeholder="/dev/sdb"></div>
      <div class="form-group"><label class="form-label">Filesystem</label><select id="sp-p-fstype" class="form-input">
        <option value="ext4">ext4</option><option value="xfs">xfs</option><option value="btrfs">btrfs</option></select></div>`;
  }
  return '';
}
function spRecipeChanged() {
  const recipe = document.getElementById('sp-recipe')?.value;
  const fields = document.getElementById('sp-fields');
  if (fields) fields.innerHTML = _spFieldsHtml(recipe);
  _spDryRunResult = null;
  const prev = document.getElementById('sp-preview');
  if (prev) prev.innerHTML = '';
  document.getElementById('sp-confirm-wrap')?.classList.add('d-none');
}
async function openStorageProvision() {
  const sel = document.getElementById('sp-device-select');
  if (sel) {
    const devs = await _scanDeviceList();
    sel.innerHTML = devs.map(d => `<option value="${escAttr(d.id)}">${escHtml(d.name || d.id)}</option>`).join('');
  }
  const recipeSel = document.getElementById('sp-recipe');
  if (recipeSel) recipeSel.value = 'mdadm_create';
  spRecipeChanged();
  openModal('storage-prov-modal');
}
function _spParams() {
  const recipe = document.getElementById('sp-recipe')?.value;
  const members = () => (document.getElementById('sp-p-members')?.value || '')
    .split('\n').map(s => s.trim()).filter(Boolean);
  if (recipe === 'mdadm_create') return {
    device: (document.getElementById('sp-p-device')?.value || '').trim(),
    level: document.getElementById('sp-p-level')?.value, members: members() };
  if (recipe === 'lvm_pvcreate') return { members: members() };
  if (recipe === 'lvm_vgcreate') return {
    vgname: (document.getElementById('sp-p-vgname')?.value || '').trim(), members: members() };
  if (recipe === 'lvm_lvcreate') return {
    vgname: (document.getElementById('sp-p-vgname')?.value || '').trim(),
    lvname: (document.getElementById('sp-p-lvname')?.value || '').trim(),
    size: (document.getElementById('sp-p-size')?.value || '').trim() };
  if (recipe === 'mkfs') return {
    device: (document.getElementById('sp-p-device')?.value || '').trim(),
    fstype: document.getElementById('sp-p-fstype')?.value };
  return {};
}
async function spPreview() {
  const devId = document.getElementById('sp-device-select')?.value;
  const recipe = document.getElementById('sp-recipe')?.value;
  if (!devId) { toast('Pick a device', 'error', {transient: true}); return; }
  const r = await api('POST', `/devices/${encodeURIComponent(devId)}/storage-provision`,
    { recipe, params: _spParams(), dry_run: true }).catch(e => ({ error: String(e) }));
  const out = document.getElementById('sp-preview');
  const wrap = document.getElementById('sp-confirm-wrap');
  if (!r || !r.ok) {
    if (out) out.textContent = '';
    wrap?.classList.add('d-none');
    toast((r && r.error) || 'Preview failed', 'error');
    return;
  }
  _spDryRunResult = r;
  if (out) out.innerHTML = `<div class="ff-mono">$ ${escHtml(r.command)}</div>`;
  const tgt = document.getElementById('sp-confirm-target');
  if (tgt) tgt.textContent = r.confirm_target;
  wrap?.classList.remove('d-none');
  const ci = document.getElementById('sp-confirm');
  if (ci) ci.value = '';
}
async function spExecute() {
  const devId = document.getElementById('sp-device-select')?.value;
  const recipe = document.getElementById('sp-recipe')?.value;
  if (!_spDryRunResult) { toast('Preview the command first', 'error'); return; }
  const confirmVal = (document.getElementById('sp-confirm')?.value || '').trim();
  if (confirmVal !== _spDryRunResult.confirm_target) { toast('Confirmation text does not match', 'error'); return; }
  if (!await uiConfirm(`Run this now?\n\n${_spDryRunResult.command}\n\nThis is destructive and cannot be undone.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(devId)}/storage-provision`,
    { recipe, params: _spParams(), confirm: confirmVal }).catch(e => ({ error: String(e) }));
  if (r?.approval_required) {
    toast('Parked for a second admin to approve (change-approval is on).', 'info');
    closeModal('storage-prov-modal');
    return;
  }
  if (!r || !r.ok) { toast((r && r.error) || 'Failed', 'error'); return; }
  toast('Provisioning command queued.', 'success');
  closeModal('storage-prov-modal');
  loadStorage();
}
