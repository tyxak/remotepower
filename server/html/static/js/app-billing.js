/*
 * app-billing.js — RemotePower "RacksMatters" time-tracking + billing UI (v5.4.0)
 * ---------------------------------------------------------------------------
 * Three surfaces over ONE time-entry ledger:
 *   - ticket "Log hours" (injected into the ticket detail by app.js),
 *   - the weekly Timesheet page (#page-timesheet, personal),
 *   - the Billing page (#page-billing, admin/finance): Worksheet / Invoices /
 *     Rates & Fees.
 *
 * CSP: production serves `script-src 'self'; style-src 'self'` (no unsafe-inline).
 * This is an external /static file, so it's allowed. It NEVER emits inline on*=
 * handlers or style="" strings — every button uses the global data-action
 * dispatch (window[dataset.action](arg,…)); dynamic styling is class-based.
 * All interpolated values pass through escHtml()/escAttr() (both global, app.js).
 *
 * Globals reused from app.js: api, toast, openModal, closeModal, escHtml,
 * escAttr, getMe, _meCache, _downloadAuthed, _icon, tableCtl.
 */

/* ── small helpers ─────────────────────────────────────────────────────── */
// NB: `_meCache` is a `let` script-global in app.js — shared across these
// classic scripts as a BAREWORD, but NOT a property of window (let/const don't
// attach to window). Reading `window._meCache` returns undefined → every role
// check fails → the admin controls render disabled. Use the bareword.
function _bMe() { try { return _meCache || {}; } catch (_) { return {}; } }
function _bRole() { return _bMe().role || ''; }
function _bIsAdmin() { return !!_bMe().admin; }                 // canonical (matches app.js)
function _bCanBilling() { return _bIsAdmin() || _bRole() === 'finance'; }
function _bMoney(n, cur) {
  return (cur ? cur + ' ' : '') + Number(n || 0).toLocaleString(undefined,
    { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}
function _bHours(n) {
  const v = Number(n || 0);
  return (Math.round(v * 100) / 100).toString();
}
function _bIcon(name, sz) { try { return _icon(name, sz || 14); } catch (_) { return ''; } }
const _B_CATS = ['project', 'meeting', 'admin', 'education', 'travel', 'internal', 'support', 'other'];
const _B_FEEKINDS = ['license', 'operation', 'service', 'other'];

/* ── shared time-entry modal ───────────────────────────────────────────────
 * One modal serves three flows via _teModal.mode:
 *   'ticket'    — POST /tickets/{tid}/hours  (site/device prefilled, billable on)
 *   'timesheet' — POST /time-entries         (date prefilled, scope free)
 *   'edit'      — PATCH /time-entries/{eid}
 */
let _teModal = { mode: '', tid: '', eid: '', site: null, device: null };

function _teReset() { _teModal = { mode: '', tid: '', eid: '', site: null, device: null }; }

function openTicketHours(tid, devId, devName, siteId) {
  _teReset();
  _teModal.mode = 'ticket';
  _teModal.tid = String(tid);
  if (devId) _teModal.device = { id: String(devId), name: devName || String(devId) };
  if (siteId) _teModal.site = { id: String(siteId), name: '' };
  _teShow({ billable: true, date: _todayStr(), hours: 1 });
}

function openTimesheetEntry(dateStr) {
  _teReset();
  _teModal.mode = 'timesheet';
  _teShow({ billable: false, date: dateStr || _todayStr(), hours: 1 });
}

function editTimeEntry(eid, entryJson) {
  _teReset();
  _teModal.mode = 'edit';
  _teModal.eid = String(eid);
  let e = {};
  try { e = JSON.parse(decodeURIComponent(entryJson)); } catch (_) { e = {}; }
  if (e.site_id) _teModal.site = { id: e.site_id, name: '' };
  if (e.device_id) _teModal.device = { id: e.device_id, name: e.device_name || '' };
  _teShow(e);
}

function _todayStr() { return new Date().toISOString().slice(0, 10); }

function _teShow(e) {
  const body = document.getElementById('time-entry-body');
  if (!body) return;
  const billable = !!e.billable;
  const showRate = _bCanBilling();   // only admin/finance see the rate-card picker
  const rateOpts = ['<option value="">Default (site rate)</option>']
    .concat((window._bRateCard || []).map(r =>
      `<option value="${escAttr(r.name)}" ${e.rate_name === r.name ? 'selected' : ''}>${escHtml(r.name)}</option>`)).join('');
  const catOpts = _B_CATS.map(c =>
    `<option value="${c}" ${(e.category || 'other') === c ? 'selected' : ''}>${c[0].toUpperCase() + c.slice(1)}</option>`).join('');
  const quick = [0.25, 0.5, 1, 2, 4, 8].map(h =>
    `<button type="button" class="btn-chip" data-action="teQuickHours" data-arg="${h}">${h}</button>`).join(' ');
  body.innerHTML = `
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Hours <span class="meta-sm-nm">(0.25 steps — 0.25 = 15 min)</span></label>
        <input type="number" id="te-hours" class="form-input" min="0.25" step="0.25" value="${escAttr(String(e.hours || 1))}">
        <div class="row-6 mt-6">${quick}</div>
      </div>
      <div class="form-group">
        <label class="form-label">Date</label>
        <input type="date" id="te-date" class="form-input" value="${escAttr(e.date || _todayStr())}">
      </div>
    </div>
    <div class="form-group">
      <label class="click-row"><input type="checkbox" id="te-billable" ${billable ? 'checked' : ''} data-action="teToggleBillable"> <strong>Billable</strong> (debtable — charged to a customer)</label>
    </div>
    <div id="te-billable-box" class="${billable ? '' : 'hidden'}">
      <div class="form-group">
        <label class="form-label">Customer (site) <span class="meta-sm-nm">— who pays</span></label>
        <div id="te-site-chip" class="mb-6"></div>
        <input type="text" id="te-site-search" class="form-input" placeholder="Search a site…" autocomplete="off">
        <div id="te-site-results" class="scroll-cap-sm"></div>
      </div>
      <div class="form-group">
        <label class="form-label">Device <span class="meta-sm-nm">(optional — fixes the site if blank)</span></label>
        <div id="te-dev-chip" class="mb-6"></div>
        <input type="text" id="te-dev-search" class="form-input" placeholder="Search a device…" autocomplete="off">
        <div id="te-dev-results" class="scroll-cap-sm"></div>
      </div>
      ${showRate ? `<div class="form-group"><label class="form-label">Rate</label><select id="te-rate" class="form-input">${rateOpts}</select></div>` : ''}
    </div>
    <div id="te-internal-box" class="form-group ${billable ? 'hidden' : ''}">
      <label class="form-label">Category</label>
      <select id="te-category" class="form-input">${catOpts}</select>
    </div>
    <div class="form-group">
      <label class="form-label">Note</label>
      <input type="text" id="te-note" class="form-input" maxlength="2000" value="${escAttr(e.note || '')}" placeholder="What did you do?">
    </div>`;
  // wire omnisearch pickers
  const ss = document.getElementById('te-site-search');
  if (ss) ss.oninput = () => _teSiteResults(ss.value);
  const ds = document.getElementById('te-dev-search');
  if (ds) ds.oninput = () => _teDevResults(ds.value);
  _teRenderChips();
  const title = document.getElementById('time-entry-title');
  if (title) title.textContent = _teModal.mode === 'edit' ? 'Edit time entry'
    : (_teModal.mode === 'ticket' ? 'Log hours on ticket' : 'Log time');
  openModal('time-entry-modal');
}

function teQuickHours(h) { const i = document.getElementById('te-hours'); if (i) i.value = String(h); }

function teToggleBillable() {
  const on = document.getElementById('te-billable')?.checked;
  document.getElementById('te-billable-box')?.classList.toggle('hidden', !on);
  document.getElementById('te-internal-box')?.classList.toggle('hidden', !!on);
}

async function _teSiteResults(term) {
  const box = document.getElementById('te-site-results');
  if (!box) return;
  const q = (term || '').toLowerCase().trim();
  if (!q) { box.innerHTML = ''; return; }
  const r = await api('GET', '/sites');
  const sites = (r && r.sites) || [];
  const m = sites.filter(s => (s.name || '').toLowerCase().includes(q)).slice(0, 20);
  box.innerHTML = m.map(s =>
    `<div class="pointer p-6" data-action="tePickSite" data-arg="${escAttr(s.id)}" data-arg2="${escAttr(s.name)}">${escHtml(s.name)}</div>`).join('')
    || '<div class="meta-sm-nm">No matching site.</div>';
}
function tePickSite(id, name) {
  _teModal.site = { id: String(id), name: name || String(id) };
  const s = document.getElementById('te-site-search'); if (s) s.value = '';
  const r = document.getElementById('te-site-results'); if (r) r.innerHTML = '';
  _teRenderChips();
}
async function _teDevResults(term) {
  const box = document.getElementById('te-dev-results');
  if (!box) return;
  const q = (term || '').toLowerCase().trim();
  if (!q) { box.innerHTML = ''; return; }
  const r = await api('GET', '/devices');
  const devs = (r && (r.devices || (Array.isArray(r) ? r : []))) || [];
  const m = devs.filter(d => (d.name || '').toLowerCase().includes(q) || (d.ip || '').toLowerCase().includes(q)).slice(0, 20);
  box.innerHTML = m.map(d =>
    `<div class="pointer p-6" data-action="tePickDev" data-arg="${escAttr(d.id)}" data-arg2="${escAttr(d.name)}">${escHtml(d.name)} <span class="meta-sm-nm">${escHtml(d.ip || '')}</span></div>`).join('')
    || '<div class="meta-sm-nm">No matches.</div>';
}
function tePickDev(id, name) {
  _teModal.device = { id: String(id), name: name || String(id) };
  const s = document.getElementById('te-dev-search'); if (s) s.value = '';
  const r = document.getElementById('te-dev-results'); if (r) r.innerHTML = '';
  _teRenderChips();
}
function teClearSite() { _teModal.site = null; _teRenderChips(); }
function teClearDev() { _teModal.device = null; _teRenderChips(); }
function _teRenderChips() {
  const sc = document.getElementById('te-site-chip');
  if (sc) sc.innerHTML = _teModal.site
    ? `<span class="group-badge">${escHtml(_teModal.site.name || _teModal.site.id)} <button class="btn-icon cell-sm" data-action="teClearSite" title="Clear">×</button></span>`
    : '<span class="meta-sm-nm">No customer chosen.</span>';
  const dc = document.getElementById('te-dev-chip');
  if (dc) dc.innerHTML = _teModal.device
    ? `<span class="group-badge">${escHtml(_teModal.device.name || _teModal.device.id)} <button class="btn-icon cell-sm" data-action="teClearDev" title="Clear">×</button></span>`
    : '<span class="meta-sm-nm">No device.</span>';
}

async function saveTimeEntry() {
  const hours = parseFloat(document.getElementById('te-hours')?.value || '0');
  if (!(hours > 0)) { toast('Hours must be greater than 0', 'error'); return; }
  const billable = !!document.getElementById('te-billable')?.checked;
  const body = {
    hours, billable,
    date: document.getElementById('te-date')?.value || _todayStr(),
    note: document.getElementById('te-note')?.value || '',
  };
  if (billable) {
    if (_teModal.device) body.device_id = _teModal.device.id;
    if (_teModal.site) body.site_id = _teModal.site.id;
    if (!body.site_id && !body.device_id) { toast('Billable hours need a customer (site) or a device', 'error'); return; }
    const rate = document.getElementById('te-rate');
    if (rate) body.rate_name = rate.value;
  } else {
    body.category = document.getElementById('te-category')?.value || 'other';
  }
  let r;
  if (_teModal.mode === 'edit') {
    r = await api('PATCH', '/time-entries/' + encodeURIComponent(_teModal.eid), body);
  } else if (_teModal.mode === 'ticket') {
    r = await api('POST', '/tickets/' + encodeURIComponent(_teModal.tid) + '/hours', body);
  } else {
    r = await api('POST', '/time-entries', body);
  }
  if (r && r.ok) {
    toast('Time saved', 'success');
    closeModal('time-entry-modal');
    if (_teModal.mode === 'ticket') renderTicketHours(_teModal.tid);
    if (document.getElementById('page-timesheet')?.classList.contains('active')) loadTimesheet();
    _teReset();
  } else {
    toast((r && r.error) || 'Failed', 'error');
  }
}

async function deleteTimeEntry(eid, ctxTid) {
  if (!confirm('Delete this time entry?')) return;
  const r = await api('DELETE', '/time-entries/' + encodeURIComponent(eid));
  if (r && r.ok) {
    toast('Deleted', 'success');
    if (ctxTid) renderTicketHours(ctxTid);
    if (document.getElementById('page-timesheet')?.classList.contains('active')) loadTimesheet();
  } else { toast((r && r.error) || 'Failed', 'error'); }
}

/* ── ticket hours (injected into the ticket detail by app.js openTicket) ─── */
async function renderTicketHours(tid) {
  const box = document.getElementById('tk-hours-box');
  if (!box) return;
  const r = await api('GET', '/tickets/' + encodeURIComponent(tid) + '/hours');
  if (!r || !r.ok) { box.innerHTML = '<div class="meta-sm-nm">Could not load hours.</div>'; return; }
  const rows = r.entries || [];
  const list = rows.length ? rows.map(e => {
    const b = e.billable ? '<span class="patch-badge warn fs-11">billable</span>' : '<span class="patch-badge ok fs-11">internal</span>';
    const lock = e.locked ? ` <span class="meta-sm-nm" title="On an issued invoice — locked">${_bIcon('lock', 12)}</span>` : '';
    const ej = encodeURIComponent(JSON.stringify(e));
    const actions = e.locked ? '' :
      `<button class="btn-icon cell-sm" data-action="editTimeEntry" data-arg="${escAttr(e.id)}" data-arg2="${escAttr(ej)}" title="Edit">${_bIcon('edit', 13)}</button>
       <button class="btn-icon cell-sm c-danger-outline" data-action="deleteTimeEntry" data-arg="${escAttr(e.id)}" data-arg2="${escAttr(tid)}" title="Delete">${_bIcon('trash', 13)}</button>`;
    return `<div class="row-6 tk-hours-row"><span class="fw-600">${_bHours(e.hours)}h</span> ${b}
      <span class="meta-sm-nm">${escHtml(e.user || '')} · ${escHtml(e.date || '')}${e.note ? ' · ' + escHtml(e.note) : ''}</span>${lock}
      <span class="ml-auto">${actions}</span></div>`;
  }).join('') : '<div class="meta-sm-nm">No hours logged yet.</div>';
  box.innerHTML = `<div class="row-6 mb-6"><span class="fw-600">Total ${_bHours(r.total_hours)}h</span>
    <span class="meta-sm-nm">(${_bHours(r.billable_hours)}h billable)</span></div>
    <div class="scroll-cap">${list}</div>`;
}

/* ── Timesheet page ────────────────────────────────────────────────────── */
let _tsCursor = null;   // a Date inside the displayed week

function _isoWeekString(d) {
  const dt = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
  const day = dt.getUTCDay() || 7;
  dt.setUTCDate(dt.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil((((dt - yearStart) / 86400000) + 1) / 7);
  return dt.getUTCFullYear() + '-W' + String(weekNo).padStart(2, '0');
}

async function loadTimesheet() {
  if (!_tsCursor) _tsCursor = new Date();
  const wk = _isoWeekString(_tsCursor);
  const r = await api('GET', '/timesheet?week=' + encodeURIComponent(wk));
  const wrap = document.getElementById('ts-week-wrap');
  if (!wrap) return;
  if (!r || !r.ok) { wrap.innerHTML = '<div class="empty-state-sm">Failed to load timesheet.</div>'; return; }
  const lbl = document.getElementById('ts-week-label');
  if (lbl) lbl.textContent = r.week + '  ·  ' + _bHours(r.total_hours) + 'h total · ' + _bHours(r.billable_hours) + 'h billable';
  const dow = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  wrap.innerHTML = (r.days || []).map((d, i) => {
    const rows = (d.entries || []).map(e => {
      const b = e.billable ? '<span class="patch-badge warn fs-11">bill</span>' : '<span class="patch-badge ok fs-11">int</span>';
      const where = e.billable ? (e.site_id ? ('site ' + escHtml((e.device_name || e.site_id))) : '')
        : escHtml(e.category || '');
      const tk = e.ticket_number ? ` <span class="meta-sm-nm">#${escHtml(String(e.ticket_number))}</span>` : '';
      const lock = e.locked ? ` <span class="meta-sm-nm" title="Invoiced — locked">${_bIcon('lock', 12)}</span>` : '';
      const ej = encodeURIComponent(JSON.stringify(e));
      const act = e.locked ? '' :
        `<button class="btn-icon cell-sm" data-action="editTimeEntry" data-arg="${escAttr(e.id)}" data-arg2="${escAttr(ej)}" title="Edit">${_bIcon('edit', 12)}</button>
         <button class="btn-icon cell-sm c-danger-outline" data-action="deleteTimeEntry" data-arg="${escAttr(e.id)}" title="Delete">${_bIcon('trash', 12)}</button>`;
      return `<div class="row-6 ts-entry"><span class="fw-600">${_bHours(e.hours)}h</span> ${b}
        <span class="meta-sm-nm">${where}${tk}${e.note ? ' · ' + escHtml(e.note) : ''}</span>${lock}
        <span class="ml-auto">${act}</span></div>`;
    }).join('') || '<div class="meta-sm-nm">—</div>';
    return `<div class="dash-card ts-day">
      <div class="row-6 ts-day-head">
        <span class="fw-600">${dow[i]} <span class="meta-sm-nm">${escHtml(d.date)}</span></span>
        <span class="ml-auto meta-sm-nm">${_bHours(d.total)}h</span>
        <button class="btn-icon cell-sm" data-action="openTimesheetEntry" data-arg="${escAttr(d.date)}" title="Add time on this day">+</button>
      </div>
      <div class="scroll-cap-sm">${rows}</div>
    </div>`;
  }).join('');
}
function tsPrevWeek() { _tsCursor = new Date((_tsCursor || new Date()).getTime() - 7 * 864e5); loadTimesheet(); }
function tsNextWeek() { _tsCursor = new Date((_tsCursor || new Date()).getTime() + 7 * 864e5); loadTimesheet(); }
function tsThisWeek() { _tsCursor = new Date(); loadTimesheet(); }
function tsExportCsv() {
  const wk = _isoWeekString(_tsCursor || new Date());
  // export my entries for the visible week via the ledger CSV (from/to bounds)
  const base = new Date(_tsCursor || new Date());
  const day = base.getUTCDay() || 7; const mon = new Date(base.getTime() - (day - 1) * 864e5);
  const from = mon.toISOString().slice(0, 10);
  const to = new Date(mon.getTime() + 6 * 864e5).toISOString().slice(0, 10);
  _downloadAuthed('/api/time-entries?format=csv&from=' + from + '&to=' + to, 'timesheet-' + wk + '.csv', 'Timesheet CSV downloaded');
}

/* ── Billing page (admin/finance) ──────────────────────────────────────── */
let _billingTab = 'worksheet';
window._bRateCard = [];

function loadBilling() {
  if (!_bCanBilling()) {
    const host = document.getElementById('billing-host');
    if (host) host.innerHTML = '<div class="empty-state"><div class="empty-title">Billing is for admins and the finance role.</div></div>';
    return;
  }
  billingTab(_billingTab || 'worksheet');
}

function billingTab(name) {
  _billingTab = name;
  document.querySelectorAll('#billing-tabs .settings-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.arg === name));
  if (name === 'worksheet') _billingWorksheet();
  else if (name === 'invoices') _billingInvoices();
  else if (name === 'rates') _billingRates();
}

async function _bSiteSelectOptions(selected) {
  const r = await api('GET', '/sites');
  const sites = (r && r.sites) || [];
  return ['<option value="">— pick a site —</option>'].concat(sites.map(s =>
    `<option value="${escAttr(s.id)}" ${s.id === selected ? 'selected' : ''}>${escHtml(s.name)}</option>`)).join('');
}

async function _billingWorksheet() {
  const host = document.getElementById('billing-host');
  if (!host) return;
  const opts = await _bSiteSelectOptions(window._wsSite || '');
  const month = window._wsMonth || new Date().toISOString().slice(0, 7);
  host.innerHTML = `
    <div class="dash-card">
      <div class="form-row">
        <div class="form-group"><label class="form-label">Customer (site)</label><select id="ws-site" class="form-input">${opts}</select></div>
        <div class="form-group"><label class="form-label">Month</label><input type="month" id="ws-month" class="form-input" value="${escAttr(month)}"></div>
        <div class="form-group form-group-btn"><button class="btn-primary" data-action="wsCompute">Compute</button></div>
      </div>
      <div id="ws-result"></div>
    </div>`;
}

async function wsCompute() {
  const site = document.getElementById('ws-site')?.value || '';
  const month = document.getElementById('ws-month')?.value || '';
  if (!site) { toast('Pick a site', 'error'); return; }
  window._wsSite = site; window._wsMonth = month;
  const r = await api('GET', '/billing/worksheet?site=' + encodeURIComponent(site) + '&month=' + encodeURIComponent(month));
  const out = document.getElementById('ws-result');
  if (!out) return;
  if (!r || !r.ok) { out.innerHTML = '<div class="empty-state-sm">Failed.</div>'; return; }
  const ws = r.worksheet;
  const rows = (ws.line_items || []).map(li =>
    `<tr><td>${escHtml(li.kind)}</td><td>${escHtml(li.label)}</td><td class="num">${_bHours(li.qty)}</td><td class="num">${_bMoney(li.unit, '')}</td><td class="num">${_bMoney(li.amount, '')}</td></tr>`).join('')
    || '<tr><td colspan="5" class="empty-state-sm">Nothing billable in this period.</td></tr>';
  out.innerHTML = `
    <div class="scrollable-table-wrap audit-scroll mt-12">
      <table class="data-table"><thead><tr><th>Kind</th><th>Description</th><th class="num">Qty/Hours</th><th class="num">Unit</th><th class="num">Amount (${escHtml(ws.currency)})</th></tr></thead>
      <tbody>${rows}</tbody></table>
    </div>
    <div class="ws-totals mt-12">
      <div>Subtotal: <strong>${_bMoney(ws.subtotal, ws.currency)}</strong></div>
      <div>VAT ${escHtml(String(ws.vat_rate))}%: <strong>${_bMoney(ws.vat_amount, ws.currency)}</strong></div>
      <div class="ws-grand">Total: <strong>${_bMoney(ws.total, ws.currency)}</strong></div>
    </div>
    <div class="row-6 mt-12">
      <button class="btn-secondary" data-action="wsExportCsv">${_bIcon('download', 14)} Export CSV</button>
      ${_bIsAdmin() ? `<button class="btn-primary" data-action="wsGenerateInvoice" data-arg="${escAttr(site)}" data-arg2="${escAttr(month)}">Generate invoice</button>` : ''}
    </div>`;
}
function wsExportCsv() {
  const site = window._wsSite, month = window._wsMonth;
  if (!site) return;
  _downloadAuthed('/api/billing/worksheet?format=csv&site=' + encodeURIComponent(site) + '&month=' + encodeURIComponent(month),
    'worksheet.csv', 'Worksheet CSV downloaded');
}
async function wsGenerateInvoice(site, month) {
  if (!confirm('Generate an invoice for this site/period? The included hours will be locked.')) return;
  const r = await api('POST', '/invoices', { site_id: site, month: month });
  if (r && r.ok) {
    toast('Invoice ' + r.number + ' created (' + r.locked_entries + ' entries locked)', 'success');
    billingTab('invoices');
  } else { toast((r && r.error) || 'Failed', 'error'); }
}

async function _billingInvoices() {
  const host = document.getElementById('billing-host');
  if (!host) return;
  const r = await api('GET', '/invoices');
  const invs = (r && r.invoices) || [];
  const statusBadge = s => {
    const cls = s === 'paid' ? 'ok' : (s === 'void' ? '' : 'warn');
    return `<span class="patch-badge ${cls} fs-11">${escHtml(s)}</span>`;
  };
  const rows = invs.length ? invs.map(inv => {
    const per = (inv.period && (inv.period.from || inv.period.to)) ? (escHtml(inv.period.from || '') + ' → ' + escHtml(inv.period.to || '')) : '—';
    const adminActs = _bIsAdmin() ? `
      <button class="btn-icon cell-sm" data-action="invoiceSetStatus" data-arg="${escAttr(inv.id)}" data-arg2="sent" title="Mark sent">Sent</button>
      <button class="btn-icon cell-sm" data-action="invoiceSetStatus" data-arg="${escAttr(inv.id)}" data-arg2="paid" title="Mark paid">Paid</button>
      <button class="btn-icon cell-sm c-danger-outline" data-action="invoiceVoid" data-arg="${escAttr(inv.id)}" title="Void (frees its hours to re-bill)">Void</button>` : '';
    return `<tr>
      <td class="fw-600">${escHtml(inv.number || '')}</td>
      <td>${escHtml(inv.site_name || inv.site_id || '')}</td>
      <td>${per}</td>
      <td class="num">${_bMoney(inv.total, inv.currency)}</td>
      <td>${statusBadge(inv.status)}</td>
      <td><div class="row-6">
        <button class="btn-icon cell-sm" data-action="invoiceView" data-arg="${escAttr(inv.id)}" title="View / print">${_bIcon('eye', 13)}</button>
        <button class="btn-icon cell-sm" data-action="invoiceExportCsv" data-arg="${escAttr(inv.id)}" title="CSV">${_bIcon('download', 13)}</button>
        ${adminActs}
      </div></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="empty-state-sm">No invoices yet — generate one from the Worksheet tab.</td></tr>';
  host.innerHTML = `<div class="dash-card"><div class="scrollable-table-wrap audit-scroll">
    <table class="data-table"><thead><tr><th>Number</th><th>Customer</th><th>Period</th><th class="num">Total</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}

async function invoiceView(iid) {
  const r = await api('GET', '/invoices/' + encodeURIComponent(iid));
  if (!r || !r.ok) { toast('Failed to load invoice', 'error'); return; }
  const inv = r.invoice;
  const rows = (inv.line_items || []).map(li =>
    `<tr><td>${escHtml(li.label)}</td><td class="num">${_bHours(li.qty)}</td><td class="num">${_bMoney(li.unit, '')}</td><td class="num">${_bMoney(li.amount, '')}</td></tr>`).join('');
  document.getElementById('invoice-view-body').innerHTML = `
    <div id="invoice-print-area">
      <div class="inv-head">
        <div><div class="inv-no">Invoice ${escHtml(inv.number || '')}</div>
          <div class="meta-sm-nm">Status: ${escHtml(inv.status)} · Issued ${inv.issued_at ? new Date(inv.issued_at * 1000).toLocaleDateString() : '—'}</div></div>
      </div>
      <div class="inv-party mt-12">
        <div><strong>${escHtml(inv.site_name || '')}</strong><br>${escHtml(inv.billing_contact || '')}<br>${escHtml(inv.billing_address || '').replace(/\n/g, '<br>')}</div>
        <div class="meta-sm-nm">Period: ${escHtml((inv.period && inv.period.from) || '')} → ${escHtml((inv.period && inv.period.to) || '')}</div>
      </div>
      <table class="data-table mt-12"><thead><tr><th>Description</th><th class="num">Qty/Hours</th><th class="num">Unit</th><th class="num">Amount (${escHtml(inv.currency)})</th></tr></thead><tbody>${rows}</tbody></table>
      <div class="ws-totals mt-12">
        <div>Subtotal: <strong>${_bMoney(inv.subtotal, inv.currency)}</strong></div>
        <div>VAT ${escHtml(String(inv.vat_rate))}%: <strong>${_bMoney(inv.vat_amount, inv.currency)}</strong></div>
        <div class="ws-grand">Total: <strong>${_bMoney(inv.total, inv.currency)}</strong></div>
      </div>
      ${inv.notes ? `<div class="mt-12 meta-sm-nm">${escHtml(inv.notes).replace(/\n/g, '<br>')}</div>` : ''}
    </div>`;
  const t = document.getElementById('invoice-view-title');
  if (t) t.textContent = 'Invoice ' + (inv.number || '');
  openModal('invoice-view-modal');
}
function invoicePrint() {
  document.body.classList.add('printing-invoice');
  window.print();
  setTimeout(() => document.body.classList.remove('printing-invoice'), 500);
}
function invoiceExportCsv(iid) {
  _downloadAuthed('/api/invoices/' + encodeURIComponent(iid) + '?format=csv', 'invoice.csv', 'Invoice CSV downloaded');
}
async function invoiceSetStatus(iid, status) {
  const r = await api('PATCH', '/invoices/' + encodeURIComponent(iid), { status });
  if (r && r.ok) { toast('Invoice ' + status, 'success'); _billingInvoices(); }
  else toast((r && r.error) || 'Failed', 'error');
}
async function invoiceVoid(iid) {
  if (!confirm('Void this invoice? Its hours are freed so they can be re-billed.')) return;
  await invoiceSetStatus(iid, 'void');
}

async function _billingRates() {
  const host = document.getElementById('billing-host');
  if (!host) return;
  const r = await api('GET', '/billing/config');
  if (!r || !r.ok) { host.innerHTML = '<div class="empty-state-sm">Failed (admin/finance only).</div>'; return; }
  window._bRateCard = r.rate_card || [];
  window._bSitesCfg = r.sites || [];
  const readonly = !_bIsAdmin();
  const cardRows = (r.rate_card || []).map((rc, i) =>
    `<tr><td><input class="form-input rate-name" value="${escAttr(rc.name)}" ${readonly ? 'disabled' : ''}></td>
     <td><input type="number" step="0.01" class="form-input rate-val" value="${escAttr(String(rc.rate))}" ${readonly ? 'disabled' : ''}></td>
     <td>${readonly ? '' : `<button class="btn-icon cell-sm c-danger-outline" data-action="rateCardDel" data-arg="${i}">×</button>`}</td></tr>`).join('');
  const siteOpts = ['<option value="">— pick a site —</option>'].concat((r.sites || []).map(s =>
    `<option value="${escAttr(s.site_id)}">${escHtml(s.name)}</option>`)).join('');
  host.innerHTML = `
    <div class="dash-card">
      <div class="section-title">Global</div>
      <div class="form-row">
        <div class="form-group"><label class="form-label">Currency</label><input id="bc-currency" class="form-input" value="${escAttr(r.currency || 'USD')}" ${readonly ? 'disabled' : ''}></div>
        <div class="form-group"><label class="form-label">Default rate / h</label><input id="bc-rate" type="number" step="0.01" class="form-input" value="${escAttr(String(r.default_rate || 0))}" ${readonly ? 'disabled' : ''}></div>
        <div class="form-group"><label class="form-label">Default VAT %</label><input id="bc-vat" type="number" step="0.1" class="form-input" value="${escAttr(String(r.default_vat || 0))}" ${readonly ? 'disabled' : ''}></div>
        <div class="form-group"><label class="form-label">Invoice prefix</label><input id="bc-prefix" class="form-input" value="${escAttr(r.invoice_prefix || '')}" placeholder="e.g. 2026-" ${readonly ? 'disabled' : ''}></div>
      </div>
      <div class="section-title mt-12">Rate card</div>
      <div class="scrollable-table-wrap audit-scroll"><table class="data-table"><thead><tr><th>Name</th><th>Rate / h</th><th></th></tr></thead><tbody id="rate-card-body">${cardRows}</tbody></table></div>
      ${readonly ? '' : `<div class="row-6 mt-6"><button class="btn-secondary" data-action="rateCardAdd">+ Rate</button><button class="btn-primary" data-action="saveBillingGlobals">Save global + rate card</button></div>`}
    </div>
    <div class="dash-card mt-16">
      <div class="section-title">Per-customer rates &amp; recurring fees</div>
      <div class="form-group"><label class="form-label">Customer (site)</label><select id="bc-site" class="form-input">${siteOpts}</select></div>
      <div id="bc-site-cfg"></div>
    </div>`;
  const sel = document.getElementById('bc-site');
  if (sel) sel.onchange = () => _renderSiteCfg(sel.value);
}
function rateCardAdd() {
  const tb = document.getElementById('rate-card-body');
  if (!tb) return;
  const i = tb.querySelectorAll('tr').length;
  const tr = document.createElement('tr');
  tr.innerHTML = `<td><input class="form-input rate-name" value=""></td><td><input type="number" step="0.01" class="form-input rate-val" value="0"></td><td><button class="btn-icon cell-sm c-danger-outline" data-action="rateCardDel" data-arg="${i}">×</button></td>`;
  tb.appendChild(tr);
}
function rateCardDel(i) {
  const tb = document.getElementById('rate-card-body');
  const rows = tb ? tb.querySelectorAll('tr') : [];
  if (rows[i]) rows[i].remove();
}
async function saveBillingGlobals() {
  const card = [];
  document.querySelectorAll('#rate-card-body tr').forEach(tr => {
    const nm = tr.querySelector('.rate-name')?.value.trim();
    const rt = parseFloat(tr.querySelector('.rate-val')?.value || '0');
    if (nm) card.push({ name: nm, rate: isNaN(rt) ? 0 : rt });
  });
  const body = {
    currency: document.getElementById('bc-currency')?.value || 'USD',
    default_rate: parseFloat(document.getElementById('bc-rate')?.value || '0') || 0,
    default_vat: parseFloat(document.getElementById('bc-vat')?.value || '0') || 0,
    invoice_prefix: document.getElementById('bc-prefix')?.value || '',
    rate_card: card,
  };
  const r = await api('POST', '/billing/config', body);
  if (r && r.ok) { toast('Billing config saved', 'success'); window._bRateCard = card; }
  else toast((r && r.error) || 'Failed', 'error');
}
function _renderSiteCfg(sid) {
  const box = document.getElementById('bc-site-cfg');
  if (!box) return;
  if (!sid) { box.innerHTML = ''; return; }
  const s = (window._bSitesCfg || []).find(x => x.site_id === sid) || { site_id: sid, recurring: [] };
  const readonly = !_bIsAdmin();
  const feeRows = (s.recurring || []).map((f, i) =>
    `<tr>
      <td><input class="form-input fee-label" value="${escAttr(f.label || '')}" ${readonly ? 'disabled' : ''}></td>
      <td><select class="form-input fee-kind" ${readonly ? 'disabled' : ''}>${_B_FEEKINDS.map(k => `<option value="${k}" ${f.kind === k ? 'selected' : ''}>${k}</option>`).join('')}</select></td>
      <td><input type="number" step="0.01" class="form-input fee-amount" value="${escAttr(String(f.amount || 0))}" ${readonly ? 'disabled' : ''}></td>
      <td><input type="number" step="1" class="form-input fee-qty" value="${escAttr(String(f.qty || 1))}" ${readonly ? 'disabled' : ''}></td>
      <td><input type="checkbox" class="fee-active" ${f.active !== false ? 'checked' : ''} ${readonly ? 'disabled' : ''}></td>
      <td>${readonly ? '' : `<button class="btn-icon cell-sm c-danger-outline" data-action="feeDel" data-arg="${i}">×</button>`}</td>
    </tr>`).join('');
  box.innerHTML = `
    <div class="form-row">
      <div class="form-group"><label class="form-label">Rate / h <span class="meta-sm-nm">(blank = global)</span></label><input id="sc-rate" type="number" step="0.01" class="form-input" value="${escAttr(s.default_rate == null ? '' : String(s.default_rate))}" ${readonly ? 'disabled' : ''}></div>
      <div class="form-group"><label class="form-label">VAT % <span class="meta-sm-nm">(blank = global)</span></label><input id="sc-vat" type="number" step="0.1" class="form-input" value="${escAttr(s.vat == null ? '' : String(s.vat))}" ${readonly ? 'disabled' : ''}></div>
    </div>
    <div class="form-group"><label class="form-label">Billing contact</label><input id="sc-contact" class="form-input" value="${escAttr(s.billing_contact || '')}" ${readonly ? 'disabled' : ''}></div>
    <div class="form-group"><label class="form-label">Billing address</label><textarea id="sc-address" class="form-input" rows="2" ${readonly ? 'disabled' : ''}>${escHtml(s.billing_address || '')}</textarea></div>
    <div class="section-title mt-8">Recurring fees (monthly)</div>
    <div class="scrollable-table-wrap audit-scroll"><table class="data-table"><thead><tr><th>Label</th><th>Kind</th><th>Amount</th><th>Qty</th><th>Active</th><th></th></tr></thead><tbody id="fee-body">${feeRows}</tbody></table></div>
    ${readonly ? '' : `<div class="row-6 mt-6"><button class="btn-secondary" data-action="feeAdd">+ Fee</button><button class="btn-primary" data-action="saveSiteCfg" data-arg="${escAttr(sid)}">Save customer config</button></div>`}`;
}
function feeAdd() {
  const tb = document.getElementById('fee-body');
  if (!tb) return;
  const i = tb.querySelectorAll('tr').length;
  const tr = document.createElement('tr');
  tr.innerHTML = `<td><input class="form-input fee-label" value=""></td>
    <td><select class="form-input fee-kind">${_B_FEEKINDS.map(k => `<option value="${k}">${k}</option>`).join('')}</select></td>
    <td><input type="number" step="0.01" class="form-input fee-amount" value="0"></td>
    <td><input type="number" step="1" class="form-input fee-qty" value="1"></td>
    <td><input type="checkbox" class="fee-active" checked></td>
    <td><button class="btn-icon cell-sm c-danger-outline" data-action="feeDel" data-arg="${i}">×</button></td>`;
  tb.appendChild(tr);
}
function feeDel(i) {
  const rows = document.querySelectorAll('#fee-body tr');
  if (rows[i]) rows[i].remove();
}
async function saveSiteCfg(sid) {
  const fees = [];
  document.querySelectorAll('#fee-body tr').forEach(tr => {
    const lbl = tr.querySelector('.fee-label')?.value.trim();
    if (!lbl) return;
    fees.push({
      label: lbl, kind: tr.querySelector('.fee-kind')?.value || 'other',
      amount: parseFloat(tr.querySelector('.fee-amount')?.value || '0') || 0,
      qty: parseFloat(tr.querySelector('.fee-qty')?.value || '1') || 1,
      active: !!tr.querySelector('.fee-active')?.checked,
    });
  });
  const rateV = document.getElementById('sc-rate')?.value;
  const vatV = document.getElementById('sc-vat')?.value;
  const site = {
    site_id: sid,
    default_rate: rateV === '' ? '' : parseFloat(rateV),
    vat: vatV === '' ? '' : parseFloat(vatV),
    billing_contact: document.getElementById('sc-contact')?.value || '',
    billing_address: document.getElementById('sc-address')?.value || '',
    recurring: fees,
  };
  const r = await api('POST', '/billing/config', { site });
  if (r && r.ok) { toast('Customer config saved', 'success'); _billingRates(); }
  else toast((r && r.error) || 'Failed', 'error');
}
