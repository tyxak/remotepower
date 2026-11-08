// app-business-services.js — the Business services page (7.4.9). Buildless classic script; every symbol is global like
// the rest of the client JS, and it loads on first visit to the page (the lazy map in app.js).
//
// A service is a name, a rule and a list of parts (hosts, monitors, systemd units, containers, custom scripts, other
// services). The server reads the state of every part and applies the rule; this page lists the services, shows each
// one's parts and recent changes, and edits the definition. Nothing here decides a state.

let _bsData = null;          // {services, counts} from GET /api/business-services
let _bsParts = [];           // the parts of the service being edited
let _bsPick = null;          // what the part picker offers: {hosts, monitors, scripts, services}
let _bsDrawerSeq = 0;        // the newest request of the host drawer's section: an older answer arrives late and is dropped
let _bsDrawerRows = [];      // the services of that section, named by their place in the list in its links

const _BS_STATE = {
  ok:       ['Up',       'c-green-bold', '●'],
  warning:  ['Degraded', 'c-amber-bold', '●'],
  critical: ['Down',     'c-red-bold',   '●'],
  unknown:  ['Not known', 'c-muted',      '●'],
};
const _BS_KIND = {
  host: 'Host', monitor: 'Monitor', unit: 'systemd unit', container: 'Container', script: 'Custom script', service: 'Business service',
};

function _bsStateBadge(state) {
  const s = _BS_STATE[state] || _BS_STATE.unknown;
  // the word is a text node of its own so the translation engine can match it
  return `<span class="${s[1]}"><span aria-hidden="true">${s[2]}</span> <span>${s[0]}</span></span>`;
}

function _bsRuleText(rule) {
  if (rule && rule.type === 'any') return 'At least one part';
  if (rule && rule.type === 'min') return `At least ${Number(rule.min) || 1} parts`;
  return 'All parts';
}

async function loadBusinessServices() {
  tableCtl.wireSortOnly('bs-thead', 'business_services', renderBusinessServices);
  const tbody = document.getElementById('bs-tbody');
  if (tbody && !_bsData) tbody.innerHTML = _skeletonRows(7);
  const data = await api('GET', '/business-services');
  if (!data || data.error) {
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="empty-state-error">${escHtml((data && data.error) || 'Could not load the services.')}</td></tr>`;
    return;
  }
  _bsData = data;
  renderBusinessServices();
}

function renderBusinessServices() {
  const tbody = document.getElementById('bs-tbody');
  if (!tbody || !_bsData) return;
  const counts = _bsData.counts || {};
  for (const s of ['critical', 'warning', 'ok', 'unknown']) {
    const el = document.getElementById('bs-n-' + s);
    if (el) el.textContent = counts[s] || 0;
  }
  // a fourth card that says 0 is clutter; it appears only when some service has no data to go on
  const unk = document.getElementById('bs-card-unknown');
  if (unk) unk.hidden = !(counts.unknown > 0);
  const q = (document.getElementById('bs-filter')?.value || '').trim().toLowerCase();
  let rows = (_bsData.services || []).filter(r => !q
    || r.name.toLowerCase().includes(q)
    || (r.members || []).some(m => String(m.label || '').toLowerCase().includes(q)));
  rows = tableCtl.sortRows('business_services', rows, r => ({
    name: r.name.toLowerCase(),
    state: ({ critical: 0, warning: 1, unknown: 2, ok: 3 })[r.state] ?? 2,
    rule: _bsRuleText(r.rule),
    parts: r.parts ? r.parts_ok / r.parts : 0,
    since: r.since || 0,
    availability: r.availability_30d == null ? -1 : r.availability_30d,
  }));
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty-state">${q
      ? 'No service matches the filter.'
      : 'No business services yet. Add one to see whether the things people depend on are up.'}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const bad = (r.members || []).filter(m => m.state !== 'ok').length;
    const sid = escAttr(r.id);
    return `<tr>
      <td class="fw-500"><a href="#" data-action="openBusinessServiceDetail" data-arg="${sid}" data-prevent-default>${escHtml(r.name)}</a>
        ${r.description ? `<div class="meta-sm-nm">${escHtml(r.description)}</div>` : ''}</td>
      <td>${_bsStateBadge(r.state)}</td>
      <td class="meta-sm-nm">${escHtml(_bsRuleText(r.rule))}</td>
      <td>${r.parts_ok} of ${r.parts}${bad ? ` <span class="meta-sm-nm">(${bad} not up)</span>` : ''}</td>
      <td class="meta-sm-nm">${timeAgoHtml(r.since, {empty: '—'})}</td>
      <td class="meta-sm-nm">${r.availability_30d == null ? '—' : r.availability_30d.toFixed(2) + ' %'}</td>
      <td class="nowrap">
        <button class="btn-icon isl-600" data-action="openBusinessServiceModal" data-arg="${sid}">Edit</button>
      </td>
    </tr>`;
  }).join('');
}

// ── the detail view ────────────────────────────────────────────────────────────
async function openBusinessServiceDetail(id) {
  const d = await api('GET', '/business-services/' + encodeURIComponent(id));
  if (!d || d.error) { failToast(d); return; }
  document.getElementById('bs-detail-title').textContent = d.name;
  document.getElementById('bs-detail-sub').textContent =
    `${_bsRuleText(d.rule)} · ${d.parts_ok} of ${d.parts} parts up`
    + (d.availability_30d == null ? '' : ` · ${d.availability_30d.toFixed(2)} % over 30 days`);
  document.getElementById('bs-detail-members').innerHTML = (d.members || []).map(m => `<tr>
      <td class="fw-500">${escHtml(m.label)}</td>
      <td class="meta-sm-nm">${escHtml(_BS_KIND[m.kind] || m.kind)}</td>
      <td>${_bsStateBadge(m.state)}</td>
      <td class="meta-sm-nm">${escHtml(m.reason || '')}</td></tr>`).join('')
    || '<tr><td colspan="4" class="empty-state">No parts.</td></tr>';
  const hist = d.history || [];
  document.getElementById('bs-detail-history').innerHTML = hist.length
    ? hist.map(h => `<div class="row-8-center mb-6">${_bsStateBadge(h.state)} <span class="meta-sm-nm">${_fmtAbsTs(h.ts)}</span></div>`).join('')
    : '<div class="meta-sm-nm">No change has been recorded yet.</div>';
  openModal('bs-detail-modal');
}

// ── the editor ─────────────────────────────────────────────────────────────────
async function _bsLoadPick() {
  if (_bsPick) return _bsPick;
  const [devs, cfg, scripts] = await Promise.all([
    api('GET', '/devices?slim=1'),
    api('GET', '/config'),
    api('GET', '/custom-scripts'),
  ]);
  const hosts = ((devs && (devs.devices || devs)) || []).filter(d => d && d.id)
    .map(d => ({ id: String(d.id), name: String(d.name || d.id) }))
    .sort((a, b) => a.name.localeCompare(b.name));
  _bsPick = {
    hosts,
    monitors: ((cfg && cfg.monitors) || []).map(m => String(m.label || '')).filter(Boolean).sort(),
    scripts: ((scripts && scripts.scripts) || []).map(s => ({ id: String(s.id), name: String(s.name || s.id) })),
  };
  return _bsPick;
}

function _bsOptions(items, valueKey, labelKey) {
  return items.map(i => `<option value="${escAttr(valueKey ? i[valueKey] : i)}">${escHtml(labelKey ? i[labelKey] : i)}</option>`).join('');
}

function bsKindChanged() {
  const kind = document.getElementById('bs-add-kind').value;
  const host = _bsPick ? `<select id="bs-add-host" class="form-input" aria-label="Host">${_bsOptions(_bsPick.hosts, 'id', 'name')}</select>` : '';
  const f = document.getElementById('bs-add-fields');
  if (kind === 'host') f.innerHTML = host;
  else if (kind === 'monitor') f.innerHTML = `<select id="bs-add-monitor" class="form-input" aria-label="Monitor">${_bsOptions(_bsPick ? _bsPick.monitors : [])}</select>`;
  else if (kind === 'unit') f.innerHTML = host + `<input type="text" id="bs-add-text" class="form-input" placeholder="nginx.service" maxlength="128" aria-label="Unit name">`;
  else if (kind === 'container') f.innerHTML = host + `<input type="text" id="bs-add-text" class="form-input" placeholder="container name" maxlength="128" aria-label="Container name">`;
  else if (kind === 'script') f.innerHTML = host + `<select id="bs-add-script" class="form-input" aria-label="Custom script">${_bsOptions(_bsPick ? _bsPick.scripts : [], 'id', 'name')}</select>`;
  else if (kind === 'service') {
    const own = document.getElementById('bs-modal-id').value;
    const others = ((_bsData && _bsData.services) || []).filter(s => s.id !== own);
    f.innerHTML = `<select id="bs-add-service" class="form-input" aria-label="Business service">${_bsOptions(others, 'id', 'name')}</select>`;
  }
}

function bsRuleChanged() {
  document.getElementById('bs-modal-min').classList.toggle('d-none', document.getElementById('bs-modal-rule').value !== 'min');
}

function _bsPartLabel(p) {
  const host = _bsPick && p.device_id ? (_bsPick.hosts.find(h => h.id === p.device_id) || {}).name || p.device_id : p.device_id;
  if (p.kind === 'host') return host;
  if (p.kind === 'monitor') return p.label;
  if (p.kind === 'unit') return `${p.unit} on ${host}`;
  if (p.kind === 'container') return `${p.name} on ${host}`;
  if (p.kind === 'script') {
    const s = _bsPick && (_bsPick.scripts.find(x => x.id === p.script_id) || {}).name;
    return `${s || p.script_id} on ${host}`;
  }
  const svc = ((_bsData && _bsData.services) || []).find(s => s.id === p.service_id);
  return svc ? svc.name : p.service_id;
}

function _bsRenderParts() {
  const box = document.getElementById('bs-members');
  box.innerHTML = _bsParts.length
    ? _bsParts.map((p, i) => `<div class="row-8-center mb-6"><span class="group-badge">${escHtml(_BS_KIND[p.kind] || p.kind)}</span> ${escHtml(_bsPartLabel(p))}
        <button class="btn-icon cell-sm" data-action="bsRemovePart" data-arg="${i}" aria-label="Remove this part"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></div>`).join('')
    : '<div class="meta-sm-nm">No parts yet. Add the hosts, monitors and other things this service is made of.</div>';
}

function bsAddPart() {
  const kind = document.getElementById('bs-add-kind').value;
  const val = id => (document.getElementById(id) || {}).value || '';
  let part = null;
  if (kind === 'host') part = { kind, device_id: val('bs-add-host') };
  else if (kind === 'monitor') part = { kind, label: val('bs-add-monitor') };
  else if (kind === 'unit') part = { kind, device_id: val('bs-add-host'), unit: val('bs-add-text').trim() };
  else if (kind === 'container') part = { kind, device_id: val('bs-add-host'), name: val('bs-add-text').trim() };
  else if (kind === 'script') part = { kind, device_id: val('bs-add-host'), script_id: val('bs-add-script') };
  else if (kind === 'service') part = { kind, service_id: val('bs-add-service') };
  if (!part || Object.values(part).some(v => !v)) { toast('Choose the part first', 'error', { transient: true }); return; }
  const key = JSON.stringify(part);
  if (_bsParts.some(p => JSON.stringify(p) === key)) { toast('That part is already in the service', 'error', { transient: true }); return; }
  _bsParts.push(part);
  _bsRenderParts();
  const t = document.getElementById('bs-add-text'); if (t) t.value = '';
}

function bsRemovePart(i) {
  _bsParts.splice(Number(i), 1);
  _bsRenderParts();
}

async function openBusinessServiceModal(id) {
  await _bsLoadPick();
  if (!_bsData) await loadBusinessServices();
  document.getElementById('bs-modal-title').textContent = id ? 'Edit service' : 'New service';
  document.getElementById('bs-modal-id').value = id || '';
  document.getElementById('bs-modal-name').value = '';
  document.getElementById('bs-modal-desc').value = '';
  document.getElementById('bs-modal-rule').value = 'all';
  document.getElementById('bs-modal-min').value = '2';
  document.getElementById('bs-modal-delete-btn').classList.toggle('d-none', !id);
  _bsParts = [];
  if (id) {
    const d = await api('GET', '/business-services/' + encodeURIComponent(id));
    if (!d || d.error) { failToast(d); return; }
    document.getElementById('bs-modal-name').value = d.name || '';
    document.getElementById('bs-modal-desc').value = d.description || '';
    document.getElementById('bs-modal-rule').value = (d.rule && d.rule.type) || 'all';
    if (d.rule && d.rule.type === 'min') document.getElementById('bs-modal-min').value = String(d.rule.min || 2);
    // the parts the server returned carry state and label too; keep only what defines them
    _bsParts = (d.members || []).map(m => {
      const p = { kind: m.kind };
      for (const f of ['device_id', 'label', 'unit', 'name', 'script_id', 'service_id']) {
        if (m.kind === 'monitor' ? f === 'label' : (f !== 'label' && m[f] !== undefined)) p[f] = m[f];
      }
      return p;
    });
  }
  bsRuleChanged();
  document.getElementById('bs-add-kind').value = 'host';
  bsKindChanged();
  _bsRenderParts();
  openModal('bs-modal');
}

async function saveBusinessService() {
  const id = document.getElementById('bs-modal-id').value;
  const name = document.getElementById('bs-modal-name').value.trim();
  if (!name) { toast('Service name is required', 'error', { transient: true }); return; }
  if (!_bsParts.length) { toast('Add at least one part', 'error', { transient: true }); return; }
  const type = document.getElementById('bs-modal-rule').value;
  const rule = type === 'min'
    ? { type, min: Math.max(1, parseInt(document.getElementById('bs-modal-min').value, 10) || 1) }
    : { type };
  const body = { name, description: document.getElementById('bs-modal-desc').value.trim(), rule, members: _bsParts };
  const r = id ? await api('PUT', '/business-services/' + encodeURIComponent(id), body) : await api('POST', '/business-services', body);
  if (!r || r.error) { failToast(r); return; }
  closeModal('bs-modal');
  toast(id ? 'Service updated' : 'Service created', 'success');
  loadBusinessServices();
}

async function deleteBusinessServiceFromModal() {
  const id = document.getElementById('bs-modal-id').value;
  const name = document.getElementById('bs-modal-name').value;
  if (!id) return;
  if (!await uiConfirm({ title: 'Delete this service', message: `Delete “${name}”? Its history goes with it. The hosts, monitors and other parts are not touched.`, confirmText: 'Delete', danger: true })) return;
  const r = await api('DELETE', '/business-services/' + encodeURIComponent(id));
  if (!r || r.error) { failToast(r); return; }
  closeModal('bs-modal');
  toast('Service deleted', 'success');
  loadBusinessServices();
}

// 8.0.0: the host drawer's "Business services that depend on this host". The server answers with the services that hold the host, directly or through another service, each
// with its state (GET /api/business-services/impact); a host that is in no service has no section. The links are named by their place in the list, not by the service's id.
async function loadDrawerServices(id) {
  const sec = document.getElementById('drawer-services-section');
  const box = document.getElementById('drawer-services-list');
  if (!sec || !box) return;
  box.innerHTML = '';
  sec.hidden = true;                      // a drawer that has just been opened starts empty: what was on screen is another host's
  const seq = ++_bsDrawerSeq;
  const r = await api('GET', '/business-services/impact?device_id=' + encodeURIComponent(id)).catch(() => null);
  if (seq !== _bsDrawerSeq || _drawerDeviceId !== id) return;
  const rows = r && Array.isArray(r.services) ? r.services : [];
  if (!rows.length) return;
  _bsDrawerRows = rows;
  box.innerHTML = rows.map((s, i) => `<div class="row-8-center mb-6">${_bsStateBadge(s.state)}
      <a href="#" class="fw-500" data-action="drawerOpenService" data-arg="${i}" data-prevent-default>${escHtml(s.name)}</a>
      ${s.direct ? '' : '<span class="hint">through another service</span>'}</div>`).join('');
  sec.hidden = false;
}

function drawerOpenService(i) {
  const s = _bsDrawerRows[i];
  if (!s) return;
  closeDeviceDrawer();
  openBusinessServiceDetail(s.id);
}
