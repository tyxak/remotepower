/*
 * app-billing.js — RemotePower "RackMatters" time-tracking + billing UI (v5.4.0)
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
  // v5.4.1 (H2): locale-aware currency via the shared Intl helper — a real
  // currency symbol localized to the active UI language; empty `cur` (line-item
  // unit/amount columns, where the column header carries the currency) → plain
  // localized decimal.
  try { if (typeof fmtMoney === 'function') return fmtMoney(n, cur); } catch (_) {}
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
    ? `<span class="group-badge">${escHtml(_teModal.site.name || _teModal.site.id)} <button class="btn-icon cell-sm" data-action="teClearSite" title="Clear"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></span>`
    : '<span class="meta-sm-nm">No customer chosen.</span>';
  const dc = document.getElementById('te-dev-chip');
  if (dc) dc.innerHTML = _teModal.device
    ? `<span class="group-badge">${escHtml(_teModal.device.name || _teModal.device.id)} <button class="btn-icon cell-sm" data-action="teClearDev" title="Clear"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></span>`
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
  const _reload = () => {
    if (ctxTid) renderTicketHours(ctxTid);
    if (document.getElementById('page-timesheet')?.classList.contains('active')) loadTimesheet();
  };
  undoableDelete({
    label: 'Time entry deleted',
    hide: () => _hideRowByAction('deleteTimeEntry', eid),
    commit: () => api('DELETE', '/time-entries/' + encodeURIComponent(eid)),
    undo: _reload, after: _reload,
  });
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
  }).join('') : '<div class="meta-sm-nm">No hours logged yet — use "Log hours" on the ticket.</div>';
  box.innerHTML = `<div class="row-6 mb-6"><span class="fw-600">Total ${_bHours(r.total_hours)}h</span>
    <span class="meta-sm-nm">(${_bHours(r.billable_hours)}h billable)</span></div>
    <div class="scroll-cap">${list}</div>`;
}

/* ── Timesheet page ────────────────────────────────────────────────────── */
let _tsCursor = null;       // a Date inside the displayed week
let _tsViewUser = '';       // '' = my own timesheet; else a user I'm allowed to watch
let _tsWatchable = null;    // cached { users:[], can_view_all:bool } for the "Watch for" picker

async function _tsEnsureWatchable() {
  if (_tsWatchable) return _tsWatchable;
  const r = await api('GET', '/timesheet/watchable');
  _tsWatchable = (r && r.ok) ? { users: r.users || [], can_view_all: !!r.can_view_all }
                             : { users: [], can_view_all: false };
  return _tsWatchable;
}

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
  await _tsEnsureWatchable();
  _tsRenderWatchBar();
  const viewing = _tsViewUser;   // snapshot for this render
  // hide the "Log time" button when looking at someone else's week (read-only)
  const logBtn = document.getElementById('ts-logtime-btn');
  if (logBtn) logBtn.classList.toggle('hidden', !!viewing);
  const wk = _isoWeekString(_tsCursor);
  const r = await api('GET', '/timesheet?week=' + encodeURIComponent(wk) +
                      (viewing ? '&user=' + encodeURIComponent(viewing) : ''));
  const wrap = document.getElementById('ts-week-wrap');
  if (!wrap) return;
  if (!r || !r.ok) { wrap.innerHTML = '<div class="empty-state-sm">Failed to load timesheet.</div>'; return; }
  const lbl = document.getElementById('ts-week-label');
  if (lbl) lbl.textContent = (viewing ? viewing + '  ·  ' : '') + r.week + '  ·  ' +
    _bHours(r.total_hours) + 'h total · ' + _bHours(r.billable_hours) + 'h billable';
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
        ${viewing ? '' : `<button class="btn-icon cell-sm" data-action="openTimesheetEntry" data-arg="${escAttr(d.date)}" title="Add time on this day">+</button>`}
      </div>
      <div class="scroll-cap-sm">${rows}</div>
    </div>`;
  }).join('');
}
function tsPrevWeek() { _tsCursor = new Date((_tsCursor || new Date()).getTime() - 7 * 864e5); loadTimesheet(); }
function tsNextWeek() { _tsCursor = new Date((_tsCursor || new Date()).getTime() + 7 * 864e5); loadTimesheet(); }
function tsThisWeek() { _tsCursor = new Date(); loadTimesheet(); }

/* "Watch for" — view a timesheet you're allowed to watch (admin/finance, or a
   watch grant). Always an omnisearch typeahead, never a dropdown. */
function _tsRenderWatchBar() {
  const bar = document.getElementById('ts-watch-bar');
  if (!bar) return;
  const w = _tsWatchable || { users: [], can_view_all: false };
  if (!w.users.length && !w.can_view_all) { bar.classList.add('hidden'); bar.innerHTML = ''; return; }
  bar.classList.remove('hidden');
  const viewing = _tsViewUser
    ? `<span class="patch-badge warn">${_bIcon('eye', 12)} ${escHtml(_tsViewUser)}</span> <button class="btn-icon cell-sm" data-action="tsViewMine">Back to mine</button>`
    : '';
  bar.innerHTML = `<div class="row-6-center">
    <span class="meta-sm-nm">${_bIcon('eye', 13)} Watch for</span>
    <input type="text" id="ts-watch-input" class="form-input input-wide-sm" placeholder="Type a name…" aria-label="Watch another user's timesheet" autocomplete="off" data-input="_tsWatchResults">
    ${viewing}
    <div id="ts-watch-results" class="ts-watch-results scroll-cap-sm hidden"></div>
  </div>`;
}

function _tsWatchResults() {
  const inp = document.getElementById('ts-watch-input');
  const box = document.getElementById('ts-watch-results');
  if (!inp || !box) return;
  const q = inp.value.toLowerCase().trim();
  const users = (_tsWatchable && _tsWatchable.users) || [];
  const m = (q ? users.filter(u => u.toLowerCase().includes(q)) : users).slice(0, 20);
  if (!m.length) { box.classList.add('hidden'); box.innerHTML = ''; return; }
  box.classList.remove('hidden');
  box.innerHTML = m.map(u => `<div class="pointer p-6" data-action="tsPickWatch" data-arg="${escAttr(u)}">${escHtml(u)}</div>`).join('');
}

function tsPickWatch(u) {
  _tsViewUser = String(u);
  const box = document.getElementById('ts-watch-results');
  if (box) { box.classList.add('hidden'); box.innerHTML = ''; }
  loadTimesheet();
}

function tsViewMine() { _tsViewUser = ''; loadTimesheet(); }

function tsExportCsv() {
  const wk = _isoWeekString(_tsCursor || new Date());
  // export my entries for the visible week via the ledger CSV (from/to bounds)
  const base = new Date(_tsCursor || new Date());
  const day = base.getUTCDay() || 7; const mon = new Date(base.getTime() - (day - 1) * 864e5);
  const from = mon.toISOString().slice(0, 10);
  const to = new Date(mon.getTime() + 6 * 864e5).toISOString().slice(0, 10);
  const u = _tsViewUser ? '&user=' + encodeURIComponent(_tsViewUser) : '';
  _downloadAuthed('/api/time-entries?format=csv&from=' + from + '&to=' + to + u,
                  'timesheet-' + (_tsViewUser || 'me') + '-' + wk + '.csv', 'Timesheet CSV downloaded');
}

/* ── Timesheet watchers (admin, on the Users page) ─────────────────────── */
let _twData = null;   // { users:[], teams:[], grants:[] }

async function loadTimesheetWatchers() {
  const list = document.getElementById('tw-list');
  if (!list) return;   // not on the Users page / no card
  const r = await api('GET', '/timesheet/watchers');
  if (!r || !r.ok) { list.innerHTML = '<div class="c-muted">Failed to load.</div>'; return; }
  _twData = { users: r.users || [], teams: r.teams || [], grants: r.grants || [] };
  _twRenderList();
}

function _twRenderList() {
  const list = document.getElementById('tw-list');
  if (!list || !_twData) return;
  const g = _twData.grants;
  if (!g.length) { list.innerHTML = '<div class="meta-sm-nm">No watch grants yet — use "Add watcher" above to grant one.</div>'; return; }
  list.innerHTML = g.map(x => `<div class="row-6 ts-entry">
    <span class="fw-600">${escHtml(x.watcher)}</span>
    <span class="meta-sm-nm">watches</span>
    <span class="patch-badge">${escHtml(x.scope)}: ${escHtml(x.value)}</span>
    <span class="ml-auto"><button class="btn-icon cell-sm c-danger-outline" data-action="deleteTimesheetWatcher" data-arg="${escAttr(x.id)}" title="Remove">${_bIcon('trash', 12)}</button></span>
  </div>`).join('');
}

function _twTypeahead(inpId, boxId, src) {
  const inp = document.getElementById(inpId), box = document.getElementById(boxId);
  if (!inp || !box) return;
  const q = inp.value.toLowerCase().trim();
  const items = (q ? (src || []).filter(u => u.toLowerCase().includes(q)) : (src || [])).slice(0, 20);
  if (!items.length) { box.classList.add('hidden'); box.innerHTML = ''; return; }
  box.classList.remove('hidden');
  box.innerHTML = items.map(u => `<div class="pointer p-6" data-action="_twPick" data-arg="${escAttr(boxId)}" data-arg2="${escAttr(u)}">${escHtml(u)}</div>`).join('');
}

function _twWatcherResults() { _twTypeahead('tw-watcher', 'tw-watcher-results', _twData && _twData.users); }
function _twValueResults() {
  const scope = document.getElementById('tw-scope')?.value;
  _twTypeahead('tw-value', 'tw-value-results',
               scope === 'team' ? (_twData && _twData.teams) : (_twData && _twData.users));
}
function _twPick(boxId, val) {
  const inp = document.getElementById(String(boxId).replace('-results', ''));
  if (inp) inp.value = String(val);
  const box = document.getElementById(boxId);
  if (box) { box.classList.add('hidden'); box.innerHTML = ''; }
}
function _twScopeChanged() {
  const scope = document.getElementById('tw-scope')?.value;
  const val = document.getElementById('tw-value');
  if (val) { val.value = ''; val.placeholder = scope === 'team' ? 'Type a team…' : 'Type a username…'; }
  const box = document.getElementById('tw-value-results');
  if (box) { box.classList.add('hidden'); box.innerHTML = ''; }
}

async function addTimesheetWatcher() {
  const watcher = document.getElementById('tw-watcher')?.value.trim();
  const scope = document.getElementById('tw-scope')?.value;
  const value = document.getElementById('tw-value')?.value.trim();
  if (!watcher || !value) { toast('Watcher and target are required', 'error', {transient: true}); return; }
  const r = await api('POST', '/timesheet/watchers', { watcher, scope, value });
  if (r?.ok) {
    toast('Watch grant added', 'success');
    document.getElementById('tw-watcher').value = '';
    document.getElementById('tw-value').value = '';
    loadTimesheetWatchers();
  } else toast(r?.error || 'Failed', 'error');
}

async function deleteTimesheetWatcher(id) {
  id = String(id);
  undoableDelete({
    label: 'Watch grant removed',
    hide: () => _hideRowByAction('deleteTimesheetWatcher', id),
    commit: () => api('DELETE', '/timesheet/watchers/' + encodeURIComponent(id)),
    undo: () => loadTimesheetWatchers(), after: () => loadTimesheetWatchers(),
  });
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
  else if (name === 'quotes') _billingQuotes();      // v6.2.0
  else if (name === 'invoices') _billingInvoices();
  else if (name === 'rates') _billingRates();
}

/* ── v6.2.0: quotes ─────────────────────────────────────────────────────────
   The mirror image of an invoice: an invoice looks BACKWARD (derived from logged
   hours), a quote looks FORWARD (hand-authored) and, once accepted, becomes one.
   The Convert button only appears on an accepted quote, and the server refuses a
   second conversion even if a stale page offers it — a double-click must never
   bill a customer twice. */
async function _billingQuotes() {
  const host = document.getElementById('billing-host');
  if (!host) return;
  const r = await api('GET', '/quotes');
  const quotes = (r && r.quotes) || [];
  const badge = s => {
    const cls = s === 'accepted' ? 'ok'
      : (s === 'declined' || s === 'expired') ? 'crit'
      : (s === 'invoiced' ? '' : 'warn');
    return `<span class="patch-badge ${cls} fs-11">${escHtml(s)}</span>`;
  };
  const rows = quotes.length ? quotes.map(q => {
    const valid = q.valid_until
      ? new Date(q.valid_until * 1000).toLocaleDateString() : '—';
    // Only an ACCEPTED quote can convert. The server enforces this too — the UI
    // just doesn't dangle a button that would be refused.
    const convert = (_bIsAdmin() && q.status === 'accepted')
      ? `<button class="btn-icon cell-sm" data-action="quoteConvert" data-arg="${escAttr(q.id)}" title="Turn this accepted quote into an invoice (once only)">Invoice it</button>` : '';
    const lifecycle = (_bIsAdmin() && ['draft', 'sent'].includes(q.status)) ? `
      <button class="btn-icon cell-sm" data-action="quoteSetStatus" data-arg="${escAttr(q.id)}" data-arg2="sent" title="Mark sent">Sent</button>
      <button class="btn-icon cell-sm" data-action="quoteSetStatus" data-arg="${escAttr(q.id)}" data-arg2="accepted" title="Customer accepted">Accepted</button>
      <button class="btn-icon cell-sm c-danger-outline" data-action="quoteSetStatus" data-arg="${escAttr(q.id)}" data-arg2="declined" title="Customer declined">Declined</button>` : '';
    const inv = q.invoice_id
      ? `<span class="fs-11 c-muted">→ invoiced</span>` : '';
    return `<tr>
      <td class="fw-600">${escHtml(q.number || '')}</td>
      <td>${escHtml(q.site_name || q.site_id || '')}</td>
      <td>${escHtml(valid)}</td>
      <td class="num">${_bMoney(q.total, q.currency)}</td>
      <td>${badge(q.status)} ${inv}</td>
      <td><div class="row-6">${lifecycle}${convert}</div></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="empty-state-sm">No quotes yet — click "New quote" to create one.</td></tr>';

  const newBtn = _bIsAdmin()
    ? '<button class="btn-primary" data-action="quoteNew">New quote</button>' : '';
  host.innerHTML = `<div class="dash-card">
    <div class="toolbar">${newBtn}</div>
    <div class="scrollable-table-wrap audit-scroll">
    <table class="data-table"><thead><tr><th>Number</th><th>Customer</th><th>Valid until</th>
      <th class="num">Total</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}

async function quoteNew() {
  const site = await uiPrompt({
    title: 'New quote',
    message: 'Site id to quote for (see the Sites page).',
    confirmText: 'Next',
  });
  if (!site) return;
  const label = await uiPrompt({
    title: 'New quote — line item',
    message: 'What are you quoting for? (e.g. "Firewall replacement — labour")',
    confirmText: 'Next',
  });
  if (!label) return;
  const qty = Number(await uiPrompt({
    title: 'New quote — quantity', message: 'Quantity (e.g. hours or units)',
    value: '1', confirmText: 'Next',
  }));
  const unit = Number(await uiPrompt({
    title: 'New quote — unit price', message: 'Price per unit, excluding VAT',
    value: '0', confirmText: 'Create quote',
  }));
  if (!isFinite(qty) || !isFinite(unit)) { toast('Quantity and price must be numbers', 'error'); return; }
  const r = await api('POST', '/quotes', {
    site_id: site, line_items: [{ label, qty, unit }],
  });
  if (!r || !r.ok) { toast((r && r.error) || 'Could not create the quote', 'error'); return; }
  toast(`Quote ${r.number} created`, 'success');
  _billingQuotes();
}

async function quoteSetStatus(qid, status) {
  const r = await api('POST', '/quotes/' + encodeURIComponent(qid), { status });
  if (!r || !r.ok) { toast((r && r.error) || 'Could not update the quote', 'error'); return; }
  toast(`Quote marked ${status}`, 'success');
  _billingQuotes();
}

async function quoteConvert(qid) {
  if (!await uiConfirm('Turn this accepted quote into an invoice? A quote can be '
        + 'invoiced only once.')) return;
  const r = await api('POST', '/quotes/' + encodeURIComponent(qid) + '/convert', {});
  if (!r || !r.ok) { toast((r && r.error) || 'Could not convert the quote', 'error'); return; }
  toast(`Invoice ${r.invoice_number} created from this quote`, 'success');
  _billingQuotes();
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
  if (!site) { toast('Pick a site', 'error', {transient: true}); return; }
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
  if (!await uiConfirm('Generate an invoice for this site/period? The included hours will be locked.')) return;
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
    return `<span class="patch-badge ${cls} fs-11">${escHtml(s === 'partially_paid' ? 'partially paid' : s)}</span>`;
  };
  const rows = invs.length ? invs.map(inv => {
    const per = (inv.period && (inv.period.from || inv.period.to)) ? (escHtml(inv.period.from || '') + ' → ' + escHtml(inv.period.to || '')) : '—';
    const emailAct = (_bIsAdmin() && inv.status !== 'void' && inv.status !== 'paid') ? `
      <button class="btn-icon cell-sm" data-action="invoiceEmail" data-arg="${escAttr(inv.id)}" title="Email this invoice to the customer's billing contact">${_bIcon('mail', 13)}</button>` : '';
    const adminActs = _bIsAdmin() ? `
      <button class="btn-icon cell-sm" data-action="invoiceSetStatus" data-arg="${escAttr(inv.id)}" data-arg2="sent" title="Mark sent">Sent</button>
      <button class="btn-icon cell-sm" data-action="invoiceSetStatus" data-arg="${escAttr(inv.id)}" data-arg2="paid" title="Mark paid">Paid</button>
      <button class="btn-icon cell-sm c-danger-outline" data-action="invoiceVoid" data-arg="${escAttr(inv.id)}" title="Void (frees its hours to re-bill)">Void</button>` : '';
    const paidNote = (inv.amount_paid > 0 && inv.amount_paid < inv.total)
      ? ` <span class="c-muted fs-11">(${_bMoney(inv.amount_paid, inv.currency)} received)</span>` : '';
    return `<tr>
      <td class="fw-600">${escHtml(inv.number || '')}</td>
      <td>${escHtml(inv.site_name || inv.site_id || '')}</td>
      <td>${per}</td>
      <td class="num">${_bMoney(inv.total, inv.currency)}${paidNote}</td>
      <td>${statusBadge(inv.status)}</td>
      <td><div class="row-6">
        <button class="btn-icon cell-sm" data-action="invoiceView" data-arg="${escAttr(inv.id)}" title="View / print">${_bIcon('eye', 13)}</button>
        <button class="btn-icon cell-sm" data-action="invoiceExportCsv" data-arg="${escAttr(inv.id)}" title="CSV">${_bIcon('download', 13)}</button>
        <button class="btn-icon cell-sm" data-action="invoiceExportPdf" data-arg="${escAttr(inv.id)}" title="PDF">${_bIcon('download', 13)}</button>
        ${emailAct}
        ${adminActs}
      </div></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="empty-state-sm">No invoices yet — generate one from the Worksheet tab.</td></tr>';
  host.innerHTML = `<div class="dash-card"><div class="scrollable-table-wrap audit-scroll">
    <table class="data-table"><thead><tr><th>Number</th><th>Customer</th><th>Period</th><th class="num">Total</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>${rows}</tbody></table></div></div>`;
}

let _invViewId = null;   // v6.1.1: which invoice the view modal currently shows (for the PDF button)
async function invoiceView(iid) {
  _invViewId = iid;
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
function invoiceExportPdfCurrent() {
  if (_invViewId) invoiceExportPdf(_invViewId);
}
function invoicePrint() {
  document.body.classList.add('printing-invoice');
  window.print();
  setTimeout(() => document.body.classList.remove('printing-invoice'), 500);
}
function invoiceExportCsv(iid) {
  _downloadAuthed('/api/invoices/' + encodeURIComponent(iid) + '?format=csv', 'invoice.csv', 'Invoice CSV downloaded');
}
// v6.1.1: a real generated PDF document, not just window.print() -- can be
// archived/emailed without depending on the recipient's browser. Falls back
// to the CSV/print-based flow gracefully (a clear error toast) on an install
// without reportlab.
function invoiceExportPdf(iid) {
  _downloadAuthed('/api/invoices/' + encodeURIComponent(iid) + '?format=pdf', 'invoice.pdf', 'Invoice PDF downloaded');
}
async function invoiceSetStatus(iid, status) {
  const r = await api('PATCH', '/invoices/' + encodeURIComponent(iid), { status });
  if (r && r.ok) { toast('Invoice ' + status, 'success'); _billingInvoices(); }
  else toast((r && r.error) || 'Failed', 'error');
}
async function invoiceVoid(iid) {
  if (!await uiConfirm('Void this invoice? Its hours are freed so they can be re-billed.')) return;
  await invoiceSetStatus(iid, 'void');
}
// W1-30: email the invoice to the customer's billing contact.
async function invoiceEmail(iid) {
  if (!await uiConfirm("Email this invoice to the customer's billing contact?")) return;
  const r = await api('POST', '/invoices/' + encodeURIComponent(iid) + '/send', {});
  if (r && r.ok) { toast('Invoice emailed', 'success'); _billingInvoices(); }
  else toast((r && r.error) || 'Failed to send', 'error');
}

async function _billingRates() {
  const host = document.getElementById('billing-host');
  if (!host) return;
  const r = await api('GET', '/billing/config');
  if (!r || !r.ok) { host.innerHTML = '<div class="empty-state-sm">Failed (admin/finance only).</div>'; return; }
  window._bRateCard = r.rate_card || [];
  window._bSitesCfg = r.sites || [];
  const readonly = !_bIsAdmin();
  const cardRows = (r.rate_card || []).map(rc => {
    const rid = _bRowId();
    return `<tr data-rid="${rid}"><td><input class="form-input rate-name" value="${escAttr(rc.name)}" ${readonly ? 'disabled' : ''}></td>
     <td><input type="number" step="0.01" class="form-input rate-val" value="${escAttr(String(rc.rate))}" ${readonly ? 'disabled' : ''}></td>
     <td>${readonly ? '' : `<button class="btn-icon cell-sm c-danger-outline" aria-label="Delete" data-action="rateCardDel" data-arg="${rid}"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`}</td></tr>`;
  }).join('');
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
      <div class="form-row">
        <div class="form-group"><label class="form-label">Issuer name (invoice PDF header)</label><input id="bc-issuer-name" class="form-input" value="${escAttr(r.issuer_name || '')}" placeholder="Your business name" ${readonly ? 'disabled' : ''}></div>
        <div class="form-group"><label class="form-label">Issuer address</label><textarea id="bc-issuer-address" class="form-input" rows="2" placeholder="Street, city, tax ID…" ${readonly ? 'disabled' : ''}>${escHtml(r.issuer_address || '')}</textarea></div>
      </div>
      <div class="settings-row mt-8"><label class="form-label"><input type="checkbox" id="bc-reminders" ${r.reminders_enabled ? 'checked' : ''} ${readonly ? 'disabled' : ''}> Email overdue-invoice reminders</label></div>
      <div class="form-group"><label class="form-label" for="bc-reminder-days">Remind after N days unpaid</label><input id="bc-reminder-days" type="number" min="1" max="365" class="form-input" value="${escAttr(String(r.reminder_days || 14))}" ${readonly ? 'disabled' : ''}><span class="hint">One reminder per invoice that stays in <em>sent</em> status this many days after it was last emailed. Uses the same SMTP as notifications.</span></div>
      <div class="section-title mt-12">Rate card</div>
      <div class="scrollable-table-wrap audit-scroll"><table class="data-table"><thead><tr><th>Name</th><th>Rate / h</th><th></th></tr></thead><tbody id="rate-card-body">${cardRows}</tbody></table></div>
      ${readonly ? '' : `<div class="row-6 mt-6"><button class="btn-secondary" data-action="rateCardAdd">+ Rate</button><button class="btn-primary" data-action="saveBillingGlobals">Save global + rate card</button></div>`}
    </div>
    <div class="dash-card mt-16">
      <div class="section-title">Per-customer rates &amp; recurring fees</div>
      <div class="form-group"><label class="form-label">Customer (site)</label><select id="bc-site" class="form-input">${siteOpts}</select></div>
      <div id="bc-site-cfg"></div>
    </div>
    <div class="dash-card mt-16">
      <div class="section-title">Payment webhook</div>
      <p class="hint">A generic, provider-agnostic sink for payment reconciliation — NOT a Stripe/PayPal integration. Point your payment processor's own webhook (or a thin relay script) at the URL below with header <code>X-RP-Billing-Secret: &lt;secret&gt;</code> and a JSON body <code>{invoice_id, amount, kind: "payment"|"refund", external_ref?, provider?}</code>. Marks the invoice <code>partially_paid</code>/<code>paid</code> as payments accumulate; idempotent on <code>external_ref</code> (safe against processor webhook retries).</p>
      <div class="form-group"><label class="form-label">Webhook URL</label><input id="bc-webhook-url" class="form-input ff-mono" readonly value="${escAttr(location.origin + '/api/billing/payment-webhook')}"></div>
      <div class="form-group"><label class="form-label" for="bc-webhook-secret">Shared secret</label>
        <form autocomplete="off" data-csp-pw-form><input type="password" id="bc-webhook-secret" class="form-input" placeholder="${r.billing_webhook_secret_set ? '•••••• (set — leave blank to keep)' : 'set a shared secret to enable the webhook'}" autocomplete="off" ${readonly ? 'disabled' : ''}></form>
        <span class="hint">Saved by the "Save global + rate card" button above.</span></div>
    </div>`;
  const sel = document.getElementById('bc-site');
  if (sel) sel.onchange = () => _renderSiteCfg(sel.value);
}
// v6.1.2: rows are addressed by a STABLE id, never by their render-time
// position. The delete buttons used to carry `data-arg="${i}"` (the index at
// render time) and the table was never re-rendered after a delete — so once any
// non-last row was removed, every surviving button's index pointed one row too
// far and the next delete removed the WRONG row. Saving then persisted the
// wrong rate card / fee list. A monotonic id can't drift.
let _bRowSeq = 0;
function _bRowId() { return ++_bRowSeq; }

function _bDelRow(containerId, rid) {
  const tb = document.getElementById(containerId);
  const row = tb && tb.querySelector(`tr[data-rid="${String(rid)}"]`);
  if (row) row.remove();
}

function rateCardAdd() {
  const tb = document.getElementById('rate-card-body');
  if (!tb) return;
  const rid = _bRowId();
  const tr = document.createElement('tr');
  tr.dataset.rid = String(rid);
  tr.innerHTML = `<td><input class="form-input rate-name" value=""></td><td><input type="number" step="0.01" class="form-input rate-val" value="0"></td><td><button class="btn-icon cell-sm c-danger-outline" aria-label="Delete" data-action="rateCardDel" data-arg="${rid}"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></td>`;
  tb.appendChild(tr);
}
function rateCardDel(rid) {
  _bDelRow('rate-card-body', rid);
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
    issuer_name: document.getElementById('bc-issuer-name')?.value || '',
    issuer_address: document.getElementById('bc-issuer-address')?.value || '',
    reminders_enabled: !!document.getElementById('bc-reminders')?.checked,
    reminder_days: parseInt(document.getElementById('bc-reminder-days')?.value || '14', 10) || 14,
    rate_card: card,
  };
  const _whSecret = document.getElementById('bc-webhook-secret')?.value;
  if (_whSecret) body.billing_webhook_secret = _whSecret;
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
  const feeRows = (s.recurring || []).map(f => {
    const rid = _bRowId();
    return `<tr data-rid="${rid}">
      <td><input class="form-input fee-label" value="${escAttr(f.label || '')}" ${readonly ? 'disabled' : ''}></td>
      <td><select class="form-input fee-kind" ${readonly ? 'disabled' : ''}>${_B_FEEKINDS.map(k => `<option value="${k}" ${f.kind === k ? 'selected' : ''}>${k}</option>`).join('')}</select></td>
      <td><input type="number" step="0.01" class="form-input fee-amount" value="${escAttr(String(f.amount || 0))}" ${readonly ? 'disabled' : ''}></td>
      <td><input type="number" step="1" class="form-input fee-qty" value="${escAttr(String(f.qty || 1))}" ${readonly ? 'disabled' : ''}></td>
      <td><input type="checkbox" class="fee-active" ${f.active !== false ? 'checked' : ''} ${readonly ? 'disabled' : ''}></td>
      <td>${readonly ? '' : `<button class="btn-icon cell-sm c-danger-outline" aria-label="Delete" data-action="feeDel" data-arg="${rid}"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>`}</td>
    </tr>`;
  }).join('');
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
  const rid = _bRowId();
  const tr = document.createElement('tr');
  tr.dataset.rid = String(rid);
  tr.innerHTML = `<td><input class="form-input fee-label" value=""></td>
    <td><select class="form-input fee-kind">${_B_FEEKINDS.map(k => `<option value="${k}">${k}</option>`).join('')}</select></td>
    <td><input type="number" step="0.01" class="form-input fee-amount" value="0"></td>
    <td><input type="number" step="1" class="form-input fee-qty" value="1"></td>
    <td><input type="checkbox" class="fee-active" checked></td>
    <td><button class="btn-icon cell-sm c-danger-outline" aria-label="Delete" data-action="feeDel" data-arg="${rid}"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></td>`;
  tb.appendChild(tr);
}
function feeDel(rid) {
  _bDelRow('fee-body', rid);
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
