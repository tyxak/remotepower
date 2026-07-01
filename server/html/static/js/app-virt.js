// app-virt.js — multi-platform virtualization lifecycle (v5.6.0).
// Buildless classic script; all symbols global like the rest of the client JS.
//
// Brings the OTHER virtualization platforms (VMware vSphere/vCenter, VMware
// Cloud Director, OpenShift Virtualization) up to Proxmox-level lifecycle on the
// sidebar Virtualization page: list VMs, power actions and snapshots. Proxmox
// keeps its dedicated client (app-proxmox.js); this module drives every platform
// configured as a lifecycle-capable integration instance, through /api/virt/*.

// Active selection: {kind:'proxmox'|'virt', id, type}. Proxmox is the default so
// the page behaves exactly as before when no other platform is configured.
window._virtActive = window._virtActive || { kind: 'proxmox', id: null, type: '' };

// Entry point the nav dispatch calls (replaces the bare loadVirtualization()).
async function loadVirtualizationPage() {
  await _renderVirtPlatformBar();
  _virtLoadActive();
}

async function _renderVirtPlatformBar() {
  const bar = document.getElementById('virt-platform-bar');
  if (!bar) return;
  let data;
  try { data = await api('GET', '/virt/platforms'); }
  catch (_) { data = { platforms: [], proxmox: true }; }
  const btns = [];
  if (data.proxmox) btns.push({ kind: 'proxmox', id: '', type: 'proxmox', label: 'Proxmox' });
  (data.platforms || []).forEach(p =>
    btns.push({ kind: 'virt', id: String(p.id), type: p.type || '', label: p.label || p.type }));
  // Only one source (or none) → no need for a selector; keep the page clean.
  if (btns.length <= 1) {
    bar.innerHTML = '';
    bar.style.display = 'none';
    const only = btns[0];
    window._virtActive = only && only.kind === 'virt'
      ? { kind: 'virt', id: only.id, type: only.type }
      : { kind: 'proxmox', id: null, type: '' };
    return;
  }
  bar.style.display = '';
  const a = window._virtActive;
  const valid = btns.some(b => b.kind === a.kind && String(b.id) === String(a.id || ''));
  if (!valid) window._virtActive = { kind: btns[0].kind, id: btns[0].id || null, type: btns[0].type };
  bar.innerHTML = btns.map(b => {
    const on = b.kind === window._virtActive.kind &&
               String(b.id) === String(window._virtActive.id || '');
    return `<button class="btn-icon${on ? ' is-active' : ''}" data-action="virtSelectPlatform"` +
           ` data-arg="${escAttr(b.kind)}" data-arg2="${escAttr(b.id)}" data-arg3="${escAttr(b.type)}">` +
           `${escHtml(b.label)}</button>`;
  }).join('');
}

function virtSelectPlatform(kind, id, type) {
  window._virtActive = { kind, id: (id === '' ? null : String(id)), type: type ? String(type) : '' };
  document.querySelectorAll('#virt-platform-bar button').forEach(b => {
    const on = b.getAttribute('data-arg') === kind &&
               (b.getAttribute('data-arg2') || '') === String(id || '');
    b.classList.toggle('is-active', on);
  });
  const sb = document.getElementById('virt-search');
  if (sb) sb.value = '';
  _virtLoadActive();
}

function _virtLoadActive() {
  const createBtn = document.getElementById('vm-create-btn');
  if (window._virtActive.kind === 'proxmox') {
    if (createBtn) createBtn.style.display = '';
    loadVirtualization();   // app.js — the existing Proxmox loader
  } else {
    if (createBtn) createBtn.style.display = 'none';   // create is Proxmox-only
    loadVirtPlatform(window._virtActive.id);
  }
}

async function loadVirtPlatform(id) {
  const body = document.getElementById('virtualization-body');
  const nodeLabel = document.getElementById('virtualization-node');
  if (nodeLabel) nodeLabel.textContent = window._virtActive.type
    ? `${window._virtActive.type}` : '';
  if (!body) return;
  body.innerHTML = '<div class="table-card isl-578">Loading…</div>';
  let data;
  try { data = await api('GET', `/virt/${encodeURIComponent(id)}/vms`); }
  catch (e) {
    body.innerHTML = `<div class="table-card isl-578">${escHtml(e.message || String(e))}</div>`;
    return;
  }
  window._virtVms = data.vms || [];
  window._virtPowerActions = data.power_actions || [];
  _renderVirtVmList();
}

function _renderVirtVmList() {
  const body = document.getElementById('virtualization-body');
  if (!body) return;
  const q = (document.getElementById('virt-search')?.value || '').trim().toLowerCase();
  const vms = (window._virtVms || []).filter(v => !q ||
    String(v.name || '').toLowerCase().includes(q) ||
    String(v.id || '').toLowerCase().includes(q));
  if (!vms.length) {
    body.innerHTML = `<div class="table-card isl-578">No VMs${q ? ` match "${escHtml(q)}"` : ''}.</div>`;
    return;
  }
  body.innerHTML = `<div class="table-card isl-579">${vms.map(_renderVirtVm).join('')}</div>`;
}

function _renderVirtVm(v) {
  const status = String(v.status || 'unknown');
  const running = status === 'running';
  const statusColor = running ? 'var(--green)'
                     : (status === 'suspended' ? 'var(--amber)' : 'var(--muted)');
  const pa = window._virtPowerActions || [];
  const id = window._virtActive.id;
  const LBL = { start: 'Start', stop: 'Stop', shutdown: 'Shutdown', reboot: 'Reboot',
                reset: 'Reset', suspend: 'Suspend', restart: 'Restart' };
  const danger = { stop: true, reset: true };
  const btn = act => pa.includes(act)
    ? `<button class="btn-icon badge-sm${danger[act] ? ' btn-danger-soft' : ''}"` +
      ` data-action="virtPower" data-arg="${escAttr(id)}" data-arg2="${escAttr(v.id)}"` +
      ` data-arg3="${escAttr(act)}" data-arg4="${escAttr(v.name || v.id)}">${LBL[act] || act}</button>`
    : '';
  // Stopped → only Start; running → the graceful + hard set the platform supports.
  const actions = `<div class="isl-458">
    ${!running ? btn('start') : ''}
    ${running ? btn('shutdown') : ''}
    ${running ? btn('reboot') : ''}
    ${running ? btn('restart') : ''}
    ${running ? btn('suspend') : ''}
    ${running ? btn('stop') : ''}
    ${running ? btn('reset') : ''}
    <button class="btn-icon badge-sm" data-action="openVirtSnapshots" data-arg="${escAttr(id)}"` +
      ` data-arg2="${escAttr(v.id)}" data-arg3="${escAttr(v.name || v.id)}">Snapshots</button>
  </div>`;
  const res = [];
  if (v.cpu) res.push(`${v.cpu} vCPU`);
  if (v.mem_mb) res.push(v.mem_mb >= 1024 ? `${(v.mem_mb / 1024).toFixed(1)} GB` : `${v.mem_mb} MB`);
  const resLine = res.length ? `<div class="isl-572">${res.join('  ·  ')}</div>` : '';
  return `<div class="isl-460">
    <div class="isl-461">
      <div class="fw-600">${escHtml(v.name || v.id)}
        ${v.host ? `<span class="isl-780" title="host / namespace">${escHtml(v.host)}</span>` : ''}
      </div>
      <div class="row-8-center">
        <span class="isl-576" data-color="${statusColor}">${escHtml(status)}</span>
      </div>
    </div>
    ${resLine}
    ${actions}
  </div>`;
}

async function virtPower(id, vmId, action, name) {
  const VERB = { start: 'Start', stop: 'Stop (hard power-off)', shutdown: 'Shut down',
                 reboot: 'Reboot', reset: 'Reset (hard)', suspend: 'Suspend', restart: 'Restart' };
  const verb = VERB[action] || action;
  if (!await uiConfirm(`${verb} ${name || vmId}?`)) return;
  try {
    const r = await api('POST', `/virt/${encodeURIComponent(id)}/power`,
      { vm_id: String(vmId), action });
    if (r && r.ok === false) { toast(r.detail || `${verb} failed`, 'error'); return; }
    toast(`${verb} sent to ${name || vmId}`, 'success');
    setTimeout(() => loadVirtPlatform(id), 1500);
  } catch (e) {
    toast(`Action failed: ${e.message || String(e)}`, 'error');
  }
}

// ── snapshots (own modal, distinct from the Proxmox snapshot-modal) ───────────
async function openVirtSnapshots(id, vmId, name) {
  window._virtSnapCtx = { id: String(id), vmId: String(vmId), name: name || String(vmId) };
  let modal = document.getElementById('virt-snapshot-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'virt-snapshot-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
      <div class="modal isl-581" role="dialog" aria-modal="true" aria-labelledby="virt-snapshot-modal-title">
        <div class="isl-582">
          <div id="virt-snapshot-modal-title" class="fw-600">Snapshots</div>
          <button class="btn-icon" data-action="closeModal" data-arg="virt-snapshot-modal" aria-label="Close">✕</button>
        </div>
        <div class="isl-583">
          <div class="form-group form-group">
            <label class="form-label fs-11" for="virt-snapshot-new-name">New snapshot name</label>
            <input type="text" id="virt-snapshot-new-name" class="form-input" placeholder="e.g. before_upgrade">
          </div>
          <div class="form-group isl-584">
            <label class="form-label fs-11" for="virt-snapshot-new-desc">Description (optional)</label>
            <input type="text" id="virt-snapshot-new-desc" class="form-input" placeholder="why">
          </div>
          <button class="btn-primary isl-40" data-action="virtSnapshotCreate">Create</button>
        </div>
        <div id="virt-snapshot-list" class="scroll-cap"></div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById('virt-snapshot-modal-title').textContent =
    `Snapshots — ${window._virtSnapCtx.name}`;
  document.getElementById('virt-snapshot-new-name').value = '';
  document.getElementById('virt-snapshot-new-desc').value = '';
  openModal('virt-snapshot-modal');
  loadVirtSnapshots();
}

async function loadVirtSnapshots() {
  const ctx = window._virtSnapCtx;
  if (!ctx) return;
  const list = document.getElementById('virt-snapshot-list');
  list.innerHTML = '<div class="isl-585">Loading…</div>';
  let data;
  try {
    data = await api('GET',
      `/virt/${encodeURIComponent(ctx.id)}/snapshots?vm=${encodeURIComponent(ctx.vmId)}`);
  } catch (e) {
    list.innerHTML = `<div class="isl-586">${escHtml(e.message || String(e))}</div>`;
    return;
  }
  const snaps = (data && data.snapshots) || [];
  if (!snaps.length) { list.innerHTML = '<div class="isl-585">No snapshots.</div>'; return; }
  list.innerHTML = `<div class="scrollable-table-wrap audit-scroll"><table class="isl-540"><thead>
    <tr class="isl-468">
      <th class="cell-pad">Name</th><th class="cell-pad">Created</th>
      <th class="cell-pad">Description</th><th></th></tr></thead><tbody>` +
    snaps.map(s => `<tr class="border-bottom">
        <td class="isl-587">${escHtml(s.name || s.id || '')}</td>
        <td class="isl-545">${escHtml(s.created || '—')}</td>
        <td class="isl-545">${escHtml(s.description || '—')}</td>
        <td class="isl-589">
          <button class="btn-icon isl-590" data-action="virtSnapshotRevert" data-arg="${escAttr(s.name || s.id || '')}">Revert</button>
          <button class="btn-icon isl-591 c-danger-outline" title="Delete" data-action="virtSnapshotDelete" data-arg="${escAttr(s.name || s.id || '')}">${_icon('trash', 14)}</button>
        </td></tr>`).join('') + '</tbody></table></div>';
}

async function virtSnapshotCreate() {
  const ctx = window._virtSnapCtx;
  if (!ctx) return;
  const name = document.getElementById('virt-snapshot-new-name').value.trim();
  const desc = document.getElementById('virt-snapshot-new-desc').value.trim();
  if (!name) { toast('Enter a snapshot name', 'error'); return; }
  try {
    const r = await api('POST', `/virt/${encodeURIComponent(ctx.id)}/snapshot`,
      { vm_id: ctx.vmId, action: 'create', name, desc });
    if (r && r.ok === false) { toast(r.detail || 'Create failed', 'error'); return; }
    toast('Snapshot creation started', 'success');
    document.getElementById('virt-snapshot-new-name').value = '';
    document.getElementById('virt-snapshot-new-desc').value = '';
    setTimeout(loadVirtSnapshots, 1500);
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

async function virtSnapshotRevert(name) {
  const ctx = window._virtSnapCtx;
  if (!ctx) return;
  const typed = await uiPrompt({
    title: 'Revert to snapshot',
    message: `REVERT is destructive — it discards ALL changes made to "${ctx.name}" since snapshot "${name}" was taken. To confirm, type the VM name exactly:`,
    placeholder: ctx.name, confirmText: 'Revert', danger: true });
  if (typed === null) return;
  if (typed.trim() !== ctx.name) { toast('Name did not match — revert cancelled', 'error'); return; }
  try {
    const r = await api('POST', `/virt/${encodeURIComponent(ctx.id)}/snapshot`,
      { vm_id: ctx.vmId, action: 'revert', name });
    if (r && r.ok === false) { toast(r.detail || 'Revert failed', 'error'); return; }
    toast('Revert started', 'success');
    setTimeout(loadVirtSnapshots, 1500);
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

async function virtSnapshotDelete(name) {
  const ctx = window._virtSnapCtx;
  if (!ctx) return;
  if (!await uiConfirm(`Delete snapshot "${name}"?\n\nThis is irreversible, but it does not affect the running VM.`)) return;
  try {
    const r = await api('POST', `/virt/${encodeURIComponent(ctx.id)}/snapshot`,
      { vm_id: ctx.vmId, action: 'delete', name });
    if (r && r.ok === false) { toast(r.detail || 'Delete failed', 'error'); return; }
    toast('Snapshot deleted', 'success');
    setTimeout(loadVirtSnapshots, 1000);
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

// Let the shared search box filter whichever platform is active.
function filterVirtualization() {
  if (window._virtActive && window._virtActive.kind === 'virt') _renderVirtVmList();
  else _renderVirtualizationList();   // app.js — the Proxmox filter
}
