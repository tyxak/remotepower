// Split out of app.js (v3.4.0 modularisation). Plain classic script —
// shares the global scope with app.js; loaded right after it in index.html.
// No bundler / no ES modules. Functions here are called from app.js and vice
// versa; page init is DOMContentLoaded-deferred so load order is not sensitive.

// ─── v1.8.3: Calendar ────────────────────────────────────────────────────────
let calCurrentMonth = null;   // Date object pinned to the first of the displayed month
let calCurrentEvents = [];    // events fetched for the displayed range
let calEditingId = null;      // id of event currently being edited (or null = new)
let calSelectedColor = 'blue';
// Whitelist of event-colour tokens that map to .color-<x> CSS classes. A
// server-supplied colour outside this set would otherwise inject a stray
// class or silently yield a non-existent one — clamp to a known value.
const CAL_COLORS = ['blue', 'green', 'amber', 'red', 'purple', 'teal', 'slate'];
function calSafeColor(c) { return CAL_COLORS.includes(c) ? c : 'blue'; }

function calFmtMonthTitle(d) {
  return d.toLocaleString(undefined, {month: 'long', year: 'numeric'});
}

function calNav(delta) {
  if (!calCurrentMonth) calCurrentMonth = new Date();
  if (delta === 0) {
    calCurrentMonth = new Date();
  } else {
    calCurrentMonth = new Date(
      calCurrentMonth.getFullYear(),
      calCurrentMonth.getMonth() + delta,
      1
    );
  }
  loadCalendar();
}

async function loadCalendar() {
  if (!calCurrentMonth) calCurrentMonth = new Date();
  document.getElementById('cal-title').textContent = calFmtMonthTitle(calCurrentMonth);

  // Fetch a wider window so events spanning into adjacent months still show
  const fetchStart = new Date(calCurrentMonth.getFullYear(), calCurrentMonth.getMonth() - 1, 1);
  const fetchEnd   = new Date(calCurrentMonth.getFullYear(), calCurrentMonth.getMonth() + 2, 0);
  const qs = new URLSearchParams({
    from: fetchStart.toISOString(),
    to:   fetchEnd.toISOString(),
  });
  const data = await api('GET', `/calendar?${qs.toString()}`);
  calCurrentEvents = (data && data.events) || [];
  renderCalendarGrid();
}

function renderCalendarGrid() {
  const grid = document.getElementById('cal-grid');
  if (!calCurrentMonth) calCurrentMonth = new Date();
  const year = calCurrentMonth.getFullYear();
  const month = calCurrentMonth.getMonth();
  const firstOfMonth = new Date(year, month, 1);
  // ISO weekday: Mon=1..Sun=7. JS getDay: Sun=0..Sat=6. Convert.
  const firstWeekday = (firstOfMonth.getDay() + 6) % 7;  // 0=Mon..6=Sun
  // Calendar grid starts on the Monday of the week containing the 1st
  const gridStart = new Date(year, month, 1 - firstWeekday);

  const today = new Date();
  const todayKey = `${today.getFullYear()}-${today.getMonth()}-${today.getDate()}`;

  // Index events by yyyy-m-d local-date key
  const byDay = {};
  for (const ev of calCurrentEvents) {
    let evStart, evEnd;
    try {
      evStart = new Date(ev.start);
      evEnd   = ev.end ? new Date(ev.end) : evStart;
    } catch (e) { console.warn('calendar: skipping event with bad date', ev.start, e); continue; }
    // Walk each day from start to end (inclusive)
    const cur = new Date(evStart.getFullYear(), evStart.getMonth(), evStart.getDate());
    const last = new Date(evEnd.getFullYear(), evEnd.getMonth(), evEnd.getDate());
    while (cur <= last) {
      const key = `${cur.getFullYear()}-${cur.getMonth()}-${cur.getDate()}`;
      if (!byDay[key]) byDay[key] = [];
      byDay[key].push(ev);
      cur.setDate(cur.getDate() + 1);
    }
  }

  // Render 6 weeks × 7 days = 42 cells
  let html = '';
  for (let i = 0; i < 42; i++) {
    const d = new Date(gridStart);
    d.setDate(gridStart.getDate() + i);
    const isToday = (d.getFullYear() === today.getFullYear()
                    && d.getMonth() === today.getMonth()
                    && d.getDate() === today.getDate());
    const isOtherMonth = d.getMonth() !== month;
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
    const events = byDay[key] || [];
    const eventsHtml = events.slice(0, 3).map(ev =>
      `<div class="cal-event color-${calSafeColor(ev.color)}" data-stop-prop="1" data-action="openEventModal" data-arg="${escAttr(ev.id)}" title="${escHtml(ev.title)}">${ev.is_recurring ? '<span class="cal-recur-glyph"></span>' : ''}${escHtml(ev.title)}</div>`
    ).join('');
    const more = events.length > 3 ? `<div class="isl-428">+${events.length - 3} more</div>` : '';
    const dayDate = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    html += `<div class="cal-day${isOtherMonth ? ' other-month' : ''}${isToday ? ' today' : ''}" data-action="openEventModalForDay" data-arg="${dayDate}" >
      <div class="cal-day-num">${d.getDate()}</div>
      ${eventsHtml}${more}
    </div>`;
  }
  grid.innerHTML = html;
}

function openEventModal(eventId) {
  calEditingId = eventId || null;
  document.getElementById('event-modal-title').textContent = eventId ? 'Edit event' : 'New event';
  document.getElementById('event-delete-btn').style.display = eventId ? 'block' : 'none';
  // Wire the color swatches (idempotent)
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.onclick = () => {
      calSelectedColor = el.dataset.color;
      document.querySelectorAll('#event-color-picker .ev-color').forEach(x => x.style.borderColor = 'transparent');
      el.style.borderColor = 'var(--text)';
    };
  });

  let title = '', desc = '', color = 'blue', allDay = false, recur = 'none';
  let startVal = '', endVal = '';
  if (eventId) {
    const ev = calCurrentEvents.find(e => e.id === eventId);
    if (!ev) { toast('Event not found', 'error'); return; }
    title = ev.title; desc = ev.description || ''; color = ev.color || 'blue';
    allDay = !!ev.all_day; recur = ev.recur || 'none';
    startVal = isoToLocalInput(ev.start);
    endVal   = ev.end ? isoToLocalInput(ev.end) : startVal;
  } else {
    // Default: 1 hour from now, 1 hour duration
    const now = new Date();
    now.setMinutes(0, 0, 0);
    now.setHours(now.getHours() + 1);
    const later = new Date(now.getTime() + 3600 * 1000);
    startVal = dateToLocalInput(now);
    endVal   = dateToLocalInput(later);
  }
  document.getElementById('event-title').value = title;
  document.getElementById('event-description').value = desc;
  document.getElementById('event-start').value = startVal;
  document.getElementById('event-end').value = endVal;
  document.getElementById('event-all-day').checked = allDay;
  document.getElementById('event-recur').value = recur;
  // Update delete button label to reflect recurring vs one-off
  const delBtn = document.getElementById('event-delete-btn');
  if (delBtn) delBtn.textContent = (recur !== 'none') ? 'Delete all occurrences' : 'Delete';
  calSelectedColor = color;
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.style.borderColor = (el.dataset.color === color) ? 'var(--text)' : 'transparent';
  });
  openModal('event-modal');
}

function openEventModalForDay(dayStr) {
  // dayStr is "YYYY-MM-DD" in local time
  const [y, mo, d] = dayStr.split('-').map(Number);
  const start = new Date(y, mo - 1, d, 9, 0);
  const end   = new Date(y, mo - 1, d, 10, 0);
  calEditingId = null;
  document.getElementById('event-modal-title').textContent = 'New event';
  document.getElementById('event-delete-btn').style.display = 'none';
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.onclick = () => {
      calSelectedColor = el.dataset.color;
      document.querySelectorAll('#event-color-picker .ev-color').forEach(x => x.style.borderColor = 'transparent');
      el.style.borderColor = 'var(--text)';
    };
    el.style.borderColor = (el.dataset.color === 'blue') ? 'var(--text)' : 'transparent';
  });
  document.getElementById('event-title').value = '';
  document.getElementById('event-description').value = '';
  document.getElementById('event-start').value = dateToLocalInput(start);
  document.getElementById('event-end').value = dateToLocalInput(end);
  document.getElementById('event-all-day').checked = false;
  document.getElementById('event-recur').value = 'none';
  calSelectedColor = 'blue';
  openModal('event-modal');
}

function dateToLocalInput(d) {
  // Format Date as YYYY-MM-DDTHH:MM for <input type="datetime-local">
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function isoToLocalInput(iso) {
  try { return dateToLocalInput(new Date(iso)); }
  catch { return ''; }
}

async function saveEvent() {
  const title = document.getElementById('event-title').value.trim();
  if (!title) { toast('Title is required', 'error'); return; }
  const startLocal = document.getElementById('event-start').value;
  const endLocal   = document.getElementById('event-end').value;
  if (!startLocal) { toast('Start time is required', 'error'); return; }

  const body = {
    title,
    description: document.getElementById('event-description').value,
    start:       new Date(startLocal).toISOString(),
    end:         endLocal ? new Date(endLocal).toISOString() : new Date(startLocal).toISOString(),
    all_day:     document.getElementById('event-all-day').checked,
    color:       calSelectedColor,
    recur:       document.getElementById('event-recur').value || 'none',
  };
  let result;
  if (calEditingId) {
    result = await api('PUT', `/calendar/${calEditingId}`, body);
  } else {
    result = await api('POST', '/calendar', body);
  }
  if (result && result.ok) {
    toast(calEditingId ? 'Event updated' : 'Event created', 'success');
    closeModal('event-modal');
    loadCalendar();
  } else {
    toast(result?.error || 'Failed to save', 'error');
  }
}

async function deleteCurrentEvent() {
  if (!calEditingId) return;
  const ev = calCurrentEvents.find(e => e.id === calEditingId);
  const isRecurring = ev && (ev.recur && ev.recur !== 'none' || ev.is_recurring);
  const msg = isRecurring
    ? 'Delete this recurring event and all its occurrences?'
    : 'Delete this event?';
  if (!await uiConfirm(msg)) return;
  const result = await api('DELETE', `/calendar/${calEditingId}`);
  if (result && result.ok) {
    toast(isRecurring ? 'All occurrences deleted' : 'Event deleted', 'success');
    closeModal('event-modal');
    loadCalendar();
  } else {
    toast(result?.error || 'Failed to delete', 'error');
  }
}

// ─── v1.8.3: Tasks (kanban) ──────────────────────────────────────────────────
let tasksCache = [];
let taskEditingId = null;

async function loadTasks() {
  // Populate device filter with current devices (only on first load)
  const sel = document.getElementById('tasks-device-filter');
  if (sel.options.length <= 2) {
    const devs = await api('GET', '/devices');
    if (devs) {
      const list = devs.devices || devs;
      // Keep "All devices" + "No device linked" options at top
      for (const d of list) {
        const opt = document.createElement('option');
        opt.value = d.id || d.device_id;
        opt.textContent = d.name || d.id;
        sel.appendChild(opt);
      }
    }
  }
  const filterDev = sel.value;
  const qs = new URLSearchParams();
  if (filterDev === '__none__') {
    // Server doesn't have a "no device" filter; we fetch all and filter client-side
  } else if (filterDev) {
    qs.set('device', filterDev);
  }
  const data = await api('GET', `/tasks?${qs.toString()}`);
  if (!data) return;
  let tasks = data.tasks || [];
  if (filterDev === '__none__') {
    tasks = tasks.filter(t => !t.device_id);
  }
  tasksCache = tasks;
  renderKanban(tasks);
}

function renderKanban(tasks) {
  const states = ['upcoming', 'ongoing', 'pending', 'closed'];
  for (const s of states) {
    const col = document.getElementById(`tasks-col-${s}`);
    const filtered = tasks.filter(t => (t.state || 'upcoming') === s);
    document.getElementById(`tasks-count-${s}`).textContent = filtered.length;
    if (!filtered.length) {
      col.innerHTML = `<div class="isl-429">No tasks</div>`;
      continue;
    }
    col.innerHTML = filtered.map(t => renderTaskCard(t)).join('');
  }
}

function renderTaskCard(t) {
  const devBadge = t.device_id && t._device_name
    ? `<span class="kanban-card-device">${escHtml(t._device_name)}</span>`
    : '';
  const meta = [];
  if (t.created_by) meta.push(`by ${escHtml(t.created_by)}`);
  if (t.updated_at) {
    const ago = relTime(t.updated_at);
    meta.push(ago);
  }
  return `<div class="kanban-card" draggable="true"
              data-task-id="${escAttr(t.id)}"
              data-action="openTaskModal" data-arg="${escAttr(t.id)}" >
    <div class="kanban-card-title">${escHtml(t.title)}</div>
    <div class="kanban-card-meta">
      ${devBadge}
      <span class="offline">${meta.join(' · ')}</span>
    </div>
  </div>`;
}

function onTaskDragStart(e, taskId) {
  e.dataTransfer.setData('text/plain', taskId);
  e.dataTransfer.effectAllowed = 'move';
  e.target.classList.add('dragging');
}

function onTaskDragEnd(e) {
  e.target.classList.remove('dragging');
}

function onKanbanDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  e.currentTarget.classList.add('drag-over');
}

function onKanbanDragLeave(e) {
  e.currentTarget.classList.remove('drag-over');
}

async function onKanbanDrop(e, newState) {
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  const taskId = e.dataTransfer.getData('text/plain');
  if (!taskId) return;
  const task = tasksCache.find(t => t.id === taskId);
  if (!task || task.state === newState) return;
  // Optimistic update
  task.state = newState;
  renderKanban(tasksCache);
  const result = await api('PUT', `/tasks/${taskId}`, {state: newState});
  if (!result || !result.ok) {
    toast(result?.error || 'Failed to move task', 'error');
    loadTasks();  // resync from server
  }
}

async function openTaskModal(taskId) {
  taskEditingId = taskId || null;
  document.getElementById('task-modal-title').textContent = taskId ? 'Edit task' : 'New task';
  document.getElementById('task-delete-btn').style.display = taskId ? 'block' : 'none';

  // Populate device dropdown
  const devSel = document.getElementById('task-device');
  if (devSel.options.length <= 1) {
    const devs = await api('GET', '/devices');
    if (devs) {
      const list = devs.devices || devs;
      for (const d of list) {
        const opt = document.createElement('option');
        opt.value = d.id || d.device_id;
        opt.textContent = d.name || d.id;
        devSel.appendChild(opt);
      }
    }
  }

  const meta = document.getElementById('task-meta');
  if (taskId) {
    const t = tasksCache.find(x => x.id === taskId);
    if (!t) { toast('Task not found', 'error'); return; }
    document.getElementById('task-title').value = t.title;
    document.getElementById('task-description').value = t.description || '';
    document.getElementById('task-state').value = t.state || 'upcoming';
    document.getElementById('task-device').value = t.device_id || '';
    const created = t.created_at ? new Date(t.created_at*1000).toLocaleString() : '?';
    const updated = t.updated_at ? new Date(t.updated_at*1000).toLocaleString() : created;
    meta.style.display = 'block';
    meta.innerHTML = `Created ${escHtml(created)} by ${escHtml(t.created_by||'?')} · Updated ${escHtml(updated)}`;
  } else {
    document.getElementById('task-title').value = '';
    document.getElementById('task-description').value = '';
    document.getElementById('task-state').value = 'upcoming';
    document.getElementById('task-device').value = '';
    meta.style.display = 'none';
  }
  openModal('task-modal');
}

async function saveTask() {
  const title = document.getElementById('task-title').value.trim();
  if (!title) { toast('Title is required', 'error'); return; }
  const body = {
    title,
    description: document.getElementById('task-description').value,
    state:       document.getElementById('task-state').value,
    device_id:   document.getElementById('task-device').value,
  };
  let result;
  if (taskEditingId) {
    result = await api('PUT', `/tasks/${taskEditingId}`, body);
  } else {
    result = await api('POST', '/tasks', body);
  }
  if (result && result.ok) {
    toast(taskEditingId ? 'Task updated' : 'Task created', 'success');
    closeModal('task-modal');
    loadTasks();
  } else {
    toast(result?.error || 'Failed to save', 'error');
  }
}

async function deleteCurrentTask() {
  if (!taskEditingId) return;
  if (!await uiConfirm('Delete this task?')) return;
  const result = await api('DELETE', `/tasks/${taskEditingId}`);
  if (result && result.ok) {
    toast('Task deleted', 'success');
    closeModal('task-modal');
    loadTasks();
  } else {
    toast(result?.error || 'Failed to delete', 'error');
  }
}
let notificationsEnabled = false;
function requestNotifications() {
  // v6.0.1: do NOT call Notification.requestPermission() here — this runs at app
  // boot, not from a user gesture, so Firefox logs a warning and Chrome/Safari
  // auto-defer/deny an unprompted request (and it's an intrusive first-visit
  // popup). Only reflect an already-granted permission; the actual opt-in happens
  // from the push-enable button (a real click) via app.js.
  if (!('Notification' in window)) return;
  notificationsEnabled = (Notification.permission === 'granted');
}
function sendNotification(title, body) { if (!('Notification' in window) || Notification.permission !== 'granted') return; try { new Notification(title, {body, icon: '/favicon.ico'}); } catch(e) { console.warn('Notification failed:', e); } }
let previousDeviceStates = {};
function checkDeviceNotifications(newDevices) { if (!notificationsEnabled) return; for (const d of newDevices) { const prev = previousDeviceStates[d.id]; if (prev !== undefined && prev !== d.online) sendNotification(`RemotePower: ${d.name}`, d.online ? 'Device came online' : 'Device went offline'); previousDeviceStates[d.id] = d.online; } }
// v1.8.4: fetch unauthenticated public info (server name, remember-me default)
async function loadPublicInfo() {
  try {
    const resp = await fetch('/api/public-info');
    if (!resp.ok) return;
    const info = await resp.json();
    if (info.server_name) {
      // Update page title and the login header
      document.title = info.server_name;
      const loginTitle = document.querySelector('.login-title');
      if (loginTitle) loginTitle.textContent = info.server_name;
    }
    const rememberCb = document.getElementById('login-remember');
    if (rememberCb) rememberCb.checked = !!info.remember_me_default;
    // v5.0.0: optional login banner / security notice (plain text).
    const lb = document.getElementById('login-banner');
    if (lb) {
      if (info.login_banner) { lb.textContent = info.login_banner; lb.classList.remove('d-none'); }
      else { lb.textContent = ''; lb.classList.add('d-none'); }
    }
    // v2.0: show demo banner when running as a public read-only sandbox.
    // The banner stays visible across page navigation (it lives outside
    // the .page containers) so visitors always see "this is a demo".
    if (info.read_only) {
      _readOnlyMode = true;
      const banner = document.getElementById('demo-banner');
      if (banner) banner.style.display = 'block';
    }
    // v3.2.0 (B3): reveal the OIDC sign-in button if configured
    if (info.oidc_enabled) {
      const btn = document.getElementById('login-oidc-btn');
      if (btn) btn.classList.remove('d-none');
    }
    // v4.2.0 (B1): reveal the SAML sign-in button if configured
    if (info.saml_enabled) {
      const btn = document.getElementById('login-saml-btn');
      if (btn) btn.classList.remove('d-none');
    }
    // v4.2.0 sweep: reveal the passkey button only when the server actually
    // supports it (library installed + feature on) — it used to render
    // unconditionally and clicking just produced a 503/403 toast.
    if (info.webauthn_enabled) {
      const btn = document.getElementById('login-passkey-btn');
      if (btn) btn.classList.remove('d-none');
    }
  } catch (e) { /* ignore */ }
}

// v3.2.0 (B3): pick up an OIDC redirect carrying a fresh session token in the
// URL hash. Hash fragments never reach the server (no log exposure), the SPA
// parses them on load and treats them like a normal post-login state.
function _consumeOidcHashToken() {
  // v4.2.0 (B1): SAML SSO uses the same hash-token delivery (saml_token=…).
  if (!location.hash ||
      (location.hash.indexOf('oidc_token=') < 0 &&
       location.hash.indexOf('saml_token=') < 0)) return;
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get('oidc_token') || params.get('saml_token');
  const username = params.get('username') || '';
  if (!token) return;
  try {
    localStorage.setItem('rp_token', token);
    // v4.2.0 sweep: the app reads `rp_me` everywhere (the "(you)" marker,
    // avatar menu); the old rp_role/rp_username keys were write-only.
    localStorage.setItem('rp_me', username);
  } catch (_) { /* private mode — non-fatal */ }
  // Clean the hash so a refresh doesn't replay the token
  history.replaceState(null, '', location.pathname);
  location.reload();
}
_consumeOidcHashToken();

// Surface an OIDC error returned in the query string (?oidc_error=...)
(function() {
  const qs = new URLSearchParams(location.search);
  const err = qs.get('oidc_error');
  if (!err) return;
  const target = document.getElementById('login-oidc-error');
  if (target) {
    target.textContent = 'SSO sign-in failed: ' + err;
    target.classList.remove('d-none');
  }
  // Clean the URL
  history.replaceState(null, '', location.pathname);
})();

// v2.0: read-only mode flag — set from /api/public-info on load. The
// API client uses this to surface a nicer error toast on 403 instead
// of letting the raw "Demo mode" body bubble up to the user as a
// generic alert.
let _readOnlyMode = false;

// ── v3.12.0: iCal import / export ────────────────────────────────────────────
function exportCalendarIcs() {
  fetch('/api/calendar.ics', { headers: { 'X-Token': getToken() } })
    .then(r => r.blob())
    .then(b => {
      const url = URL.createObjectURL(b);
      const a = document.createElement('a');
      a.href = url; a.download = 'remotepower-calendar.ics'; a.click();
      URL.revokeObjectURL(url);
      toast('Calendar exported', 'success');
    })
    .catch(() => toast('Export failed', 'error'));
}
function importCalendarIcs() { document.getElementById('cal-import-file')?.click(); }
document.addEventListener('change', e => {
  if (e.target && e.target.id === 'cal-import-file' && e.target.files && e.target.files[0]) {
    const f = e.target.files[0];
    e.target.value = '';
    f.text().then(async txt => {
      const r = await fetch('/api/calendar/import', {
        method: 'POST',
        headers: { 'X-Token': getToken(), 'Content-Type': 'text/calendar' },
        body: txt,
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok) {
        toast(`Imported ${j.imported} event(s)` + (j.skipped ? ` · ${j.skipped} skipped` : ''), 'success');
        loadCalendar();
      } else { toast('Import failed: ' + (j.error || r.status), 'error'); }
    });
  }
});
