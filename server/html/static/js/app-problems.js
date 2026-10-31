// app-problems.js — page module (buildless, classic script; all symbols are global like the rest of the client JS).

// The Problems page (#56). GET /api/problems joins Alerts, Needs attention and Checks on (host, kind of problem),
// so a problem that sits in all three is one row, and its state says whether the host still reports it. The four
// views (all, alerts, needs attention, checks) are filters of that one list. The actions call the endpoints the
// other pages call, with the permissions those endpoints ask for; nothing here writes by a route of its own.
let _problemsRows = [];
let _problemsView = '';   // '' = all problems; 'alert' | 'attention' | 'check' = the ones that show there
// Opening the page and choosing a view each start a load, and the answers can come back in either order. Only the
// newest request may draw, or an old answer overwrites the view the person just chose.
let _problemsSeq = 0;      // the number of the newest request
let _problemsDrawn = 0;    // the number of the request that was drawn last

const _PROBLEM_STATE = {
  failing:              {label: 'Failing',                        cls: 'critical'},
  resolved_but_failing: {label: 'Resolved, still failing',        cls: 'critical'},
  waiting_for_report:   {label: 'Resolved, waiting for the host', cls: 'warning'},
  host_clear:           {label: 'Alert open, no longer listed',   cls: 'warning'},
  resolved:             {label: 'Resolved',                       cls: 'ok'},
  recovered:            {label: 'Recovered',                      cls: 'ok'},
};
const _PROBLEM_STATE_RANK = {failing: 0, resolved_but_failing: 1, waiting_for_report: 2, host_clear: 3, resolved: 4, recovered: 5};
// alerts say critical/high/medium/low, Needs attention critical/warning/info: one pill class and one rank for all
const _PROBLEM_SEV = {critical: ['critical', 0], high: ['critical', 1], warning: ['warning', 2], medium: ['warning', 2], info: ['unknown', 3], low: ['unknown', 3]};
const _PROBLEM_PAGE = {alert: ['alerts', 'Alert'], attention: ['attention', 'Needs Attention'], check: ['checks', 'Check']};

function _problemsQuery() {
  const val = id => (document.getElementById(id) || {}).value || '';
  const p = new URLSearchParams({limit: '500', state: val('problems-filter-state') || 'active'});
  if (_problemsView) p.set('source', _problemsView);
  const q = val('problems-filter-text').trim();
  if (q) p.set('q', q);
  return p.toString();
}

async function loadProblems() {
  const tbody = document.getElementById('problems-tbody');
  if (!tbody) return;
  tableCtl.wireSortOnly('problems-thead', 'problems', renderProblems);
  tbody.innerHTML = _skeletonRows(7);
  const seq = ++_problemsSeq;
  const data = await api('GET', '/problems?' + _problemsQuery());
  if (seq !== _problemsSeq) return;   // a newer request was made while this one was on its way
  // api() RESOLVES on a 4xx/5xx, so a refusal arrives here and not in a catch
  if (!data || data.error || !Array.isArray(data.problems)) {
    _errorState(tbody, loadProblems, {
      msg: (data && data.error) ? `Could not load problems: ${data.error}` : 'Could not load problems.',
      colspan: 7});
    _problemsDrawn = seq;
    return;
  }
  _problemsRows = data.problems;
  _renderProblemTiles(data.counts);
  const more = document.getElementById('problems-more');
  if (more) more.hidden = !(data.total > data.problems.length);
  renderProblems();
  _problemsDrawn = seq;
}

// The four states that want a person, as tiles; a tile filters the list, and clicking it again undoes that. The
// four views carry how many active problems each holds.
function _renderProblemTiles(counts) {
  const states = (counts && counts.states) || {};
  for (const key of ['failing', 'resolved_but_failing', 'waiting_for_report', 'host_clear']) {
    animateStat('problems-n-' + key, states[key] || 0);
  }
  const chosen = (document.getElementById('problems-filter-state') || {}).value;
  document.querySelectorAll('#problems-state-row .stat-card').forEach(el => {
    el.setAttribute('aria-pressed', el.dataset.arg === chosen ? 'true' : 'false');
  });
  const bySource = (counts && counts.active_sources) || {};
  const setN = (id, n) => { const el = document.getElementById(id); if (el) el.textContent = String(n || 0); };
  setN('problems-view-n-all', counts && counts.active);
  for (const src of ['alert', 'attention', 'check']) setN('problems-view-n-' + src, bySource[src]);
  _markProblemViews();
}

function _markProblemViews() {
  document.querySelectorAll('#problems-views button').forEach(b => b.classList.toggle('active', b.dataset.arg === _problemsView));
}

function setProblemsState(key) {
  const sel = document.getElementById('problems-filter-state');
  if (!sel) return;
  sel.value = (sel.value === key) ? 'active' : String(key);
  loadProblems();
}

// Alerts, Needs attention and Checks are three filters of the one list.
function setProblemsView(src) {
  _problemsView = String(src || '');
  _markProblemViews();
  loadProblems();
}

function _problemRow(key) { return _problemsRows.find(x => x.key === key) || null; }

// One line per alert, Needs attention item and failing check under the problem: who closed it, what the host says.
function _problemDetailHtml(r) {
  const lines = [];
  for (const a of (r.alerts || [])) {
    let what = 'open';
    if (a.status === 'resolved') what = a.how === 'hand' ? 'resolved by ' + a.resolved_by : (a.how === 'auto' ? 'recovered' : 'closed');
    else if (a.status === 'acknowledged') what = 'acknowledged by ' + a.acknowledged_by;
    lines.push(`<div class="hint fs-12">${escHtml(a.detail || a.event)} · ${escHtml(what)} ${timeAgoHtml(a.resolved_at || a.ts, {clamp: true})}</div>`);
  }
  for (const n of (r.attention || [])) lines.push(`<div class="hint fs-12">${escHtml(n.summary)}</div>`);
  for (const c of (r.checks || [])) lines.push(`<div class="hint fs-12">${escHtml(c.name)}: ${escHtml(c.status)}</div>`);
  return lines.join('');
}

// What can be done to a problem, from what the row says it holds. The write actions are for administrators; the
// endpoints they call ask again, so hiding a button here is a courtesy and not the check.
function _problemActionsHtml(r, isAdmin) {
  const key = escAttr(r.key);
  const parts = [];
  if (isAdmin && (r.open_ids || []).length) {
    parts.push(`<button class="btn-icon btn-xs" data-action="resolveProblem" data-arg="${key}">Resolve</button>`);
  }
  parts.push(`<button class="btn-icon btn-xs" data-action="openProblemHistory" data-arg="${key}" title="Everything that happened to this problem" aria-label="History">${_icon('clock', 12)}</button>`);
  const item = (action, label, icon) =>
    `<button data-action="${action}" data-arg="${key}" role="menuitem">${_icon(icon, 14)} ${label}</button>`;
  const items = [];
  if (isAdmin) {
    if ((r.mute_events || []).length || (!r.device_id && (r.open_ids || []).length)) items.push(item('muteProblem', 'Mute', 'bell'));
    if ((r.attention || []).some(i => i.ignore_key)) {
      items.push(item('snoozeProblem', 'Snooze 24 h', 'clock'));
      items.push(item('ignoreProblem', 'Ignore', 'eye'));
    }
    if ((r.checks || []).some(c => c.key) && r.device_id) items.push(item('disableProblemChecks', 'Disable check', 'power'));
  }
  if (r.fix && r.device_id) items.push(item('fixProblem', 'Fix', 'wrench'));
  if (items.length) {
    parts.push(`<button class="btn-icon btn-xs" data-action="rowMoreMenu" data-pass-btn="1" aria-haspopup="menu" aria-expanded="false" title="More actions for this problem" aria-label="More actions">${_icon('moreHorizontal', 14)}</button>`
      + `<template class="row-more-items">${items.join('')}</template>`);
  }
  return parts.join(' ');
}

function renderProblems() {
  const tbody = document.getElementById('problems-tbody');
  if (!tbody) return;
  const rows = tableCtl.sortRows('problems', _problemsRows.slice(), r => ({
    severity: (_PROBLEM_SEV[r.severity] || ['unknown', 9])[1],
    host: (r.device || '').toLowerCase(),
    problem: (r.title || '').toLowerCase(),
    state: _PROBLEM_STATE_RANK[r.state] ?? 9,
    updated: r.updated || 0,
  }));
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No problems match.</td></tr>';
    return;
  }
  const isAdmin = !!(_meCache && _meCache.admin);
  tableCtl.renderChunked(tbody, rows.map(r => {
    const sev = _PROBLEM_SEV[r.severity] || ['unknown', 9];
    const st = _PROBLEM_STATE[r.state] || {label: r.state, cls: 'unknown'};
    const host = r.device_id
      ? `<button class="tl-devchip" data-action="openDeviceTimeline" data-arg="${escAttr(r.device_id)}" data-dev-hover="${escAttr(r.device_id)}">${escHtml(r.device || r.device_id)}</button>`
      : '<span class="hint">—</span>';
    const where = (r.sources || []).map(s => {
      const p = _PROBLEM_PAGE[s];
      return p ? `<button class="btn-icon btn-xs" data-action="showPage" data-arg="${p[0]}">${p[1]}</button>` : '';
    }).join(' ');
    return `<tr>
      <td><span class="chk-pill chk-${sev[0]}">${escHtml(r.severity || '—')}</span></td>
      <td>${host}</td>
      <td>${escHtml(r.title)}<div class="hint">${escHtml(r.family)}</div>${_problemDetailHtml(r)}</td>
      <td><span class="chk-pill chk-${st.cls}">${escHtml(st.label)}</span></td>
      <td class="nowrap">${where}</td>
      <td class="hint">${timeAgoHtml(r.updated, {clamp: true})}</td>
      <td class="nowrap">${_problemActionsHtml(r, isAdmin)}</td></tr>`;
  }), {colspan: 7});
}

// ── history ────────────────────────────────────────────────────────────────────────────────────────────────────
const _PROBLEM_EVENT = {raised: 'Raised', acknowledged: 'Acknowledged', resolved: 'Resolved'};

async function openProblemHistory(key) {
  const r = _problemRow(key);
  if (!r) return;
  const sub = document.getElementById('problem-history-sub');
  const body = document.getElementById('problem-history-body');
  if (sub) sub.textContent = `${r.device || '—'} · ${r.family}`;
  if (body) body.innerHTML = '<div class="empty-state">Loading…</div>';
  openModal('problem-history-modal');
  const q = new URLSearchParams({device_id: r.device_id || '', family: r.family, detail: r.sub || ''});
  const h = await api('GET', '/problems/history?' + q.toString());
  if (!body) return;
  if (!h || h.error || !Array.isArray(h.events)) {
    body.innerHTML = '<div class="empty-state">Could not load problems.</div>';
    return;
  }
  if (!h.events.length) {
    body.innerHTML = '<div class="empty-state">Nothing is recorded for this problem.</div>';
    return;
  }
  const rows = h.events.map(e => {
    let by = e.by ? escHtml(e.by) : '';
    if (e.kind === 'resolved' && e.how === 'auto') by = 'recovered';
    else if (e.kind === 'resolved' && e.how === 'system') by = 'closed';
    const again = (e.kind === 'raised' && e.count > 1) ? ` ×${e.count}` : '';
    const when = e.at ? new Date(e.at * 1000).toLocaleString() : '';
    return `<tr><td class="nowrap" title="${escAttr(when)}">${timeAgoHtml(e.at, {clamp: true})}</td>`
      + `<td><span>${_PROBLEM_EVENT[e.kind] || escHtml(e.kind)}</span>${escHtml(again)}`
      + `<div class="hint fs-12">${escHtml(e.detail || e.title)}</div></td>`
      + `<td>${by}</td><td class="fs-12">${escHtml(e.note)}</td></tr>`;
  }).join('');
  body.innerHTML = '<table><thead><tr><th scope="col">When</th><th scope="col">What</th><th scope="col">By</th><th scope="col">Note</th></tr></thead>'
    + `<tbody>${rows}</tbody></table>`;
}

// ── actions ────────────────────────────────────────────────────────────────────────────────────────────────────
// Closes every open alert of the problem at once; the host's next report decides whether Needs attention clears.
async function resolveProblem(key) {
  const r = _problemRow(key);
  if (!r || !(r.open_ids || []).length) return;
  const res = await api('POST', '/alerts/bulk-resolve', {ids: r.open_ids});
  if (res && res.ok) toast(`Resolved ${plural(res.resolved, 'alert', 'alerts')}`, 'success');
  else toast((res && res.error) || 'Could not resolve the alerts', 'error');
  loadProblems();
  if (typeof refreshAlertsBadge === 'function') refreshAlertsBadge();
}

// A mute is one (host, event) pair, so muting a problem mutes the events its alerts and items stand for on its host.
// One question for the hours, one mute per event, one undo for all of them.
async function muteProblem(key) {
  const r = _problemRow(key);
  if (!r) return;
  const events = r.mute_events || [];
  const byAlert = !events.length && !r.device_id && (r.open_ids || []).length > 0;
  if (!events.length && !byAlert) return;
  const hours = await uiPrompt({
    title: 'Mute these alerts on this host',
    message: (byAlert ? 'Silence this alert' : `Silence ${events.join(', ')} on ${r.device}`)
           + ' for how many hours? It stops firing and any open ones are cleared; history keeps recording. '
           + 'Leave blank to mute until you lift it (Monitoring → Tuning).',
    placeholder: 'e.g. 24 — blank = until I lift it',
    confirmText: 'Mute',
  });
  if (hours === null) return;
  const extra = {};
  if (String(hours).trim() !== '') {
    const h = parseFloat(hours);
    if (isNaN(h) || h < 0.25 || h > 8760) {
      toast('Enter hours between 0.25 and 8760, or leave blank for permanent', 'error', {transient: true});
      return;
    }
    extra.hours = h;
  }
  const bodies = byAlert
    ? [Object.assign({alert_id: r.open_ids[0]}, extra)]
    : events.map(ev => Object.assign({device_id: r.device_id, event: ev, device_name: r.device}, extra));
  const ids = [];
  let cleared = 0;
  for (const body of bodies) {
    const res = await api('POST', '/alert-mutes', body);
    if (!(res && res.ok)) { toast((res && res.error) || 'Failed to mute', 'error'); break; }
    ids.push(res.id);
    cleared += res.resolved || 0;
  }
  if (!ids.length) return;
  loadProblems();
  pushUndoableAction('Alert muted',
    async () => { for (const id of ids) await api('DELETE', '/alert-mutes/' + encodeURIComponent(id)); loadProblems(); },
    async () => { ids.length = 0; for (const body of bodies) { const u = await api('POST', '/alert-mutes', body); if (u && u.ok) ids.push(u.id); } loadProblems(); },
    'Muted — ' + (extra.hours ? `for ${extra.hours}h` : 'until you lift it') + (cleared ? ` · ${cleared} open cleared` : ''));
}

// Ignore (permanent, reviewable under Settings → Ignored items) and snooze (24 h, comes back by itself) hide the
// Needs attention items of the problem, by the key each carries. One undo for the whole row.
async function _problemHide(key, snooze) {
  const r = _problemRow(key);
  if (!r) return;
  const items = (r.attention || []).filter(i => i.ignore_key);
  if (!items.length) return;
  const expires = Math.floor(Date.now() / 1000) + 86400;
  const bodies = items.map(i => {
    const b = {category: 'needs_attention', key: i.ignore_key, label: `${r.device} — ${i.summary}`};
    if (snooze) b.expires_at = expires;
    else if (r.device_id) b.device_id = r.device_id;
    return b;
  });
  const done = [];
  for (const b of bodies) {
    const res = await api('POST', '/ignored', b);
    if (res && res.ok) done.push(b);
    else { failToast(res); break; }
  }
  if (!done.length) return;
  loadProblems();
  pushUndoableAction(snooze ? 'Snooze' : 'Hide',
    async () => { for (const b of done) await api('POST', '/ignored/remove', {category: 'needs_attention', key: b.key}); loadProblems(); },
    async () => { for (const b of done) await api('POST', '/ignored', b); loadProblems(); },
    snooze ? 'Snoozed for 24h' : 'Hidden from Needs Attention');
}
function snoozeProblem(key) { return _problemHide(key, true); }
function ignoreProblem(key) { return _problemHide(key, false); }

// The same investigate dialog the Needs attention and Alerts pages open.
function fixProblem(key) {
  const r = _problemRow(key);
  if (!r || !r.fix || !r.device_id) return;
  const alertId = r.fix.source === 'alert' ? (r.open_ids || [])[0] : undefined;
  openMitigateModal(r.device_id, r.fix.kind, r.fix.target || '', r.device || r.device_id, alertId);
}

// A check switched off on a host is no longer evaluated there (it stays on the Checks page, switched off).
async function disableProblemChecks(key) {
  const r = _problemRow(key);
  if (!r || !r.device_id) return;
  const checks = (r.checks || []).filter(c => c.key);
  if (!checks.length) return;
  const ok = await uiConfirm({
    title: 'Switch off these checks on this host?',
    message: `${checks.map(c => c.name).join(', ')} stop being evaluated on ${r.device}. They stay on the Checks page, switched off.`,
    confirmText: 'Switch off',
  });
  if (!ok) return;
  const done = [];
  for (const c of checks) {
    const res = await api('POST', '/checks/toggle', {device_id: r.device_id, check: c.key, enabled: false});
    if (res && res.ok) done.push(c.key);
    else { failToast(res); break; }
  }
  if (!done.length) return;
  loadProblems();
  const set = on => async () => {
    for (const k of done) await api('POST', '/checks/toggle', {device_id: r.device_id, check: k, enabled: on});
    loadProblems();
  };
  pushUndoableAction('Checks switched off', set(true), set(false), `Checks switched off on ${r.device}`);
}
