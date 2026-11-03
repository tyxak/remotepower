// app-timeperiods.js — Settings → Time periods: the list and the editor (7.4.9). Buildless classic script; every symbol is global like
// the rest of the client JS. It is loaded on demand (the lazy map in app.js) the first time the section is drawn or a period is opened.
//
// A time period is a name, a time zone, hours for each day of the week and a list of holidays (see time_periods.py). Quiet hours,
// after-hours detection, the ticket SLA clock and maintenance windows can each point at one. The server checks everything this page
// sends and refuses to delete a period that something still uses, so this page only has to show what it was given: every name and
// every zone here is text from the settings and goes through escHtml.

let _tpList = [];                 // the periods as last saved
let _tpEditId = '';               // the period in the editor, '' for a new one
const _TP_DAY_NAMES = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const _TP_DAY_SHORT = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const _TP_ZONES = ['UTC', 'Europe/London', 'Europe/Copenhagen', 'Europe/Berlin', 'Europe/Paris', 'Europe/Madrid', 'Europe/Stockholm',
  'Europe/Helsinki', 'Europe/Athens', 'Europe/Moscow', 'Africa/Cairo', 'Africa/Johannesburg', 'Asia/Dubai', 'Asia/Kolkata', 'Asia/Bangkok',
  'Asia/Shanghai', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney', 'Pacific/Auckland', 'America/Sao_Paulo', 'America/New_York',
  'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu'];

function _tpHHMM(min) {
  const m = Math.max(0, Math.min(1440, Number(min) || 0));
  return `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
}
function _tpMinutes(text) {
  const m = /^(\d{2}):(\d{2})$/.exec(String(text || ''));
  return m ? (+m[1]) * 60 + (+m[2]) : null;
}

// "Mon–Fri 09:00–17:00, Sat 10:00–14:00": the days that share the same hours are written once
function _tpSummary(per) {
  const groups = [];
  for (let d = 0; d < 7; d++) {
    const rs = ((per.weekly || {})[String(d)] || []).filter(r => Array.isArray(r) && r.length === 2);
    if (!rs.length) continue;
    const text = rs.map(r => `${_tpHHMM(r[0])}–${_tpHHMM(r[1])}`).join(', ');
    const last = groups[groups.length - 1];
    if (last && last.text === text && last.to === d - 1) last.to = d;
    else groups.push({ from: d, to: d, text });
  }
  const out = groups.map(g => `${g.from === g.to ? _TP_DAY_SHORT[g.from] : `${_TP_DAY_SHORT[g.from]}–${_TP_DAY_SHORT[g.to]}`} ${g.text}`);
  const hol = (per.holidays || []).length;
  return (out.join(' · ') || 'no hours') + (hol ? ` · ${hol} ${hol === 1 ? 'holiday' : 'holidays'}` : '');
}

function _tpZoneText(per) {
  if (per.tz) return per.tz;
  if (per.tz_offset_min != null && per.tz_offset_min !== '') {
    const m = Number(per.tz_offset_min) || 0;
    return `UTC${m < 0 ? '−' : '+'}${_tpHHMM(Math.abs(m))}`;
  }
  return '';
}

// Draw the list and fill every "time period" select on the page. Called with the settings document when it is loaded.
function renderTimePeriods(periods) {
  _tpList = Array.isArray(periods) ? periods.filter(p => p && typeof p === 'object') : [];
  const body = document.getElementById('tp-tbody');
  if (body) {
    body.innerHTML = _tpList.length ? _tpList.map(p => `<tr>
      <td class="fw-500">${escHtml(p.name || '')}</td>
      <td class="hint">${_tpZoneText(p) ? `<code>${escHtml(_tpZoneText(p))}</code>` : '<span>the clock of the server</span>'}</td>
      <td class="hint">${escHtml(_tpSummary(p))}</td>
      <td class="row-6"><button class="btn-icon isl-44" title="Edit" data-action-btn="_tpEditBtn" data-id="${escAttr(p.id)}">${_icon('edit', 14)}</button>
        <button class="btn-icon isl-44 c-danger-outline" title="Delete" data-action-btn="_tpDeleteBtn" data-id="${escAttr(p.id)}">${_icon('trash', 14)}</button></td>
    </tr>`).join('') : '<tr><td colspan="4" class="empty-state">No time periods yet.</td></tr>';
  }
  document.querySelectorAll('select[data-tp-select]').forEach(sel => setPeriodSelect(sel.id, sel.value));
}

// Fill one "time period" select with the periods and choose `value`. A period that is gone stays on screen as "Removed time period",
// so a save says so instead of dropping the choice without a word.
function setPeriodSelect(id, value) {
  const sel = document.getElementById(id);
  if (!sel) return;
  sel.innerHTML = `<option value="">${escHtml(sel.dataset.tpNone || 'None')}</option>`
    + _tpList.map(p => `<option value="${escAttr(p.id)}">${escHtml(p.name || p.id)}</option>`).join('');
  const want = value || '';
  sel.value = want;
  if (want && sel.value !== want) {
    sel.insertAdjacentHTML('beforeend', `<option value="${escAttr(want)}">Removed time period</option>`);
    sel.value = want;
  }
}

function _tpOpen(id) {
  _tpEditId = id || '';
  const per = _tpList.find(p => p.id === _tpEditId) || { name: '', tz: '', weekly: {}, holidays: [] };
  document.getElementById('time-period-modal-title').textContent = _tpEditId ? 'Edit time period' : 'Add a time period';
  document.getElementById('tp-name').value = per.name || '';
  document.getElementById('tp-tz').value = per.tz || '';
  document.getElementById('tp-offset').value = per.tz ? '' : (per.tz_offset_min != null ? per.tz_offset_min : '');
  document.getElementById('tp-holidays').value = (per.holidays || []).join('\n');
  const list = document.getElementById('tp-zone-list');
  if (list && !list.children.length) list.innerHTML = _TP_ZONES.map(z => `<option value="${escAttr(z)}"></option>`).join('');
  _hoursFill(document.getElementById('tp-days'), per.weekly);
  document.getElementById('tp-error').textContent = '';
  openModal('time-period-modal');
}

// The hours editor: a column of days, each with its ranges and an Add hours button. The period dialog and the ticket SLA hours
// (Settings → Tickets) both draw it into an element of class tp-days, so a day takes the same ranges in both: up to six.
const _HOURS_MAX_PER_DAY = 6;
function _hoursFill(root, weekly) {
  if (!root) return;
  root.innerHTML = _TP_DAY_NAMES.map((name, d) => `<div class="tp-day" data-day="${d}">
      <span class="tp-day-name">${escHtml(name)}</span><div class="tp-ranges"></div>
      <button type="button" class="btn-secondary" data-action-btn="_tpAddRangeBtn" data-day="${d}">Add hours</button></div>`).join('');
  for (let d = 0; d < 7; d++) for (const r of ((weekly || {})[String(d)] || [])) _hoursAddRange(root, d, r[0], r[1]);
}
function _hoursAddRange(root, day, from, to) {
  const dayEl = root && root.querySelector(`.tp-day[data-day="${day}"]`);
  const box = dayEl && dayEl.querySelector('.tp-ranges');
  if (!box || box.children.length >= _HOURS_MAX_PER_DAY) return;
  const row = document.createElement('div');
  row.className = 'tp-range';
  row.innerHTML = `<input type="time" class="form-input tp-from" value="${_tpHHMM(from == null ? 540 : from)}" aria-label="From">
    <input type="time" class="form-input tp-to" value="${to == null ? '17:00' : (to >= 1440 ? '00:00' : _tpHHMM(to))}" aria-label="To">
    <button type="button" class="btn-icon isl-44 c-danger-outline" title="Remove" data-action-btn="_tpDropRangeBtn">${_icon('trash', 14)}</button>`;
  box.appendChild(row);
  _hoursSyncAdd(dayEl);
}
// a day that holds as many ranges as it can has its Add button switched off, so the page does not accept what the server would cut
function _hoursSyncAdd(dayEl) {
  const add = dayEl && dayEl.querySelector('[data-action-btn="_tpAddRangeBtn"]');
  if (add) add.disabled = dayEl.querySelectorAll('.tp-range').length >= _HOURS_MAX_PER_DAY;
}
function _tpAddRangeBtn(btn) { _hoursAddRange(btn.closest('.tp-days'), Number(btn.dataset.day)); }
function _tpDropRangeBtn(btn) { const dayEl = btn.closest('.tp-day'); btn.closest('.tp-range')?.remove(); _hoursSyncAdd(dayEl); }
function _tpEditBtn(btn) { _tpOpen(btn.dataset.id); }

// what the editor holds, in the shape the server stores. A range whose end is before its start crosses midnight, and the server
// stores it as two (the rest of that day and the beginning of the next); one that ends at 00:00 runs to the end of its day.
function _hoursCollect(root) {
  const weekly = {};
  (root ? root.querySelectorAll('.tp-day') : []).forEach(dayEl => {
    const d = dayEl.dataset.day;
    dayEl.querySelectorAll('.tp-range').forEach(row => {
      const s = _tpMinutes(row.querySelector('.tp-from').value);
      let e = _tpMinutes(row.querySelector('.tp-to').value);
      if (s === null || e === null) return;
      if (e === 0) e = 1440;
      (weekly[d] = weekly[d] || []).push([s, e]);
    });
  });
  return weekly;
}
function _tpCollect() {
  const weekly = _hoursCollect(document.getElementById('tp-days'));
  const off = document.getElementById('tp-offset').value.trim();
  return {
    id: _tpEditId || undefined,
    name: document.getElementById('tp-name').value.trim(),
    tz: document.getElementById('tp-tz').value.trim(),
    tz_offset_min: off === '' ? null : Number(off),
    weekly,
    holidays: document.getElementById('tp-holidays').value.split(/[\s,;]+/).map(x => x.trim()).filter(Boolean),
  };
}

async function _tpSave(list) {
  const res = await api('POST', '/config', { time_periods: list });
  if (res?.ok) { await _tpReload(); return true; }
  failToast(res);
  return false;
}
// what the server holds now. It goes through _tpApply (app.js) with a number taken before the request, so the lists in the forms and
// the one on this page follow the same rule: an answer to an earlier request never replaces the answer to a later one.
async function _tpReload() {
  const ticket = _tpTicket();
  const cfg = await api('GET', '/config');
  await _tpApply(cfg || { time_periods: [] }, null, ticket);
}

async function _tpSaveNow() {
  const per = _tpCollect();
  if (!per.name) { document.getElementById('tp-error').textContent = 'A time period needs a name.'; return; }
  const list = _tpList.map(p => ({ ...p }));
  const at = list.findIndex(p => p.id === _tpEditId);
  if (at >= 0) list[at] = per; else list.push(per);
  if (await _tpSave(list)) { closeModal('time-period-modal'); toast('Time period saved', 'success'); }
}

async function _tpDeleteBtn(btn) {
  const per = _tpList.find(p => p.id === btn.dataset.id);
  if (!per) return;
  if (!await uiConfirm({
        title: 'Delete time period',
        message: `Delete "${per.name}"? Anything that uses it has to be changed first.`,
        confirmText: 'Delete', danger: true })) return;
  if (await _tpSave(_tpList.filter(p => p.id !== per.id).map(p => ({ ...p })))) toast('Time period deleted', 'info');
}
