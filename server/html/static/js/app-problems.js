// app-problems.js — page module (buildless, classic script; all symbols are global like the rest of the client JS).

// The Problems page (#56). GET /api/problems joins Alerts, Needs attention and Checks on (host, kind of problem),
// so a problem that sits in all three is one row, and its state says whether the host still reports it.
let _problemsRows = [];

const _PROBLEM_STATE = {
  failing:              {label: 'Failing',                        cls: 'critical'},
  resolved_but_failing: {label: 'Resolved, still failing',        cls: 'critical'},
  waiting_for_report:   {label: 'Resolved, waiting for the host', cls: 'warning'},
  host_clear:           {label: 'Host reports it clear',          cls: 'warning'},
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
  const src = val('problems-filter-source');
  if (src) p.set('source', src);
  const q = val('problems-filter-text').trim();
  if (q) p.set('q', q);
  return p.toString();
}

async function loadProblems() {
  const tbody = document.getElementById('problems-tbody');
  if (!tbody) return;
  tableCtl.wireSortOnly('problems-thead', 'problems', renderProblems);
  tbody.innerHTML = _skeletonRows(7);
  const data = await api('GET', '/problems?' + _problemsQuery());
  // api() RESOLVES on a 4xx/5xx, so a refusal arrives here and not in a catch
  if (!data || data.error || !Array.isArray(data.problems)) {
    _errorState(tbody, loadProblems, {
      msg: (data && data.error) ? `Could not load problems: ${data.error}` : 'Could not load problems.',
      colspan: 7});
    return;
  }
  _problemsRows = data.problems;
  _renderProblemTiles(data.counts);
  const more = document.getElementById('problems-more');
  if (more) more.hidden = !(data.total > data.problems.length);
  renderProblems();
}

// The four states that want a person, as tiles; a tile filters the list, and clicking it again undoes that.
function _renderProblemTiles(counts) {
  const states = (counts && counts.states) || {};
  for (const key of ['failing', 'resolved_but_failing', 'waiting_for_report', 'host_clear']) {
    animateStat('problems-n-' + key, states[key] || 0);
  }
  const chosen = (document.getElementById('problems-filter-state') || {}).value;
  document.querySelectorAll('#problems-state-row .stat-card').forEach(el => {
    el.setAttribute('aria-pressed', el.dataset.arg === chosen ? 'true' : 'false');
  });
}

function setProblemsState(key) {
  const sel = document.getElementById('problems-filter-state');
  if (!sel) return;
  sel.value = (sel.value === key) ? 'active' : String(key);
  loadProblems();
}

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
    const resolve = (isAdmin && (r.open_ids || []).length)
      ? `<button class="btn-icon btn-xs" data-action="resolveProblem" data-arg="${escAttr(r.key)}">Resolve</button>` : '';
    return `<tr>
      <td><span class="chk-pill chk-${sev[0]}">${escHtml(r.severity || '—')}</span></td>
      <td>${host}</td>
      <td>${escHtml(r.title)}<div class="hint">${escHtml(r.family)}</div>${_problemDetailHtml(r)}</td>
      <td><span class="chk-pill chk-${st.cls}">${escHtml(st.label)}</span></td>
      <td class="nowrap">${where}</td>
      <td class="hint">${timeAgoHtml(r.updated, {clamp: true})}</td>
      <td class="nowrap">${resolve}</td></tr>`;
  }), {colspan: 7});
}

// Closes every open alert of the problem at once; the host's next report decides whether Needs attention clears.
async function resolveProblem(key) {
  const r = _problemsRows.find(x => x.key === key);
  if (!r || !(r.open_ids || []).length) return;
  const res = await api('POST', '/alerts/bulk-resolve', {ids: r.open_ids});
  if (res && res.ok) toast(`Resolved ${plural(res.resolved, 'alert', 'alerts')}`, 'success');
  else toast((res && res.error) || 'Could not resolve the alerts', 'error');
  loadProblems();
  if (typeof refreshAlertsBadge === 'function') refreshAlertsBadge();
}
