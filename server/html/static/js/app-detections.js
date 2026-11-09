// app-detections.js — the Detections tab of the Threat Intel page (8.0.0): rules that look at what a host does, and what they found at the last sweep. Buildless classic
// script; every symbol is global like the rest of the client JS, and it is fetched on first use (the lazy map in app.js) when the tab shows and the module is on.
//
//   detectionsEnter()        the tab was opened (app.js calls it whenever the tab shows): draw the cards, at most every few seconds
//   loadDetections()         fetch the rules and the findings and draw them (the Refresh button)
//   detectionsOpenHost(i)    a line of the Findings table opens that host's drawer
//   detectionsSave()         send the rules as they stand (the platform operator's)
//
// Host names, addresses, program names and the sentences of a finding came from a host, so they are only ever put in the page with escHtml. A host id never travels through
// data-arg (the dispatcher turns a number-looking value into a number): the lines of the table are named by their place in the list.

let _dtSeq = 0;               // the newest load: an older answer that lands after it is dropped
let _dtAt = 0;                // when the tab was last drawn (ms), so the module gate and every visit do not each fetch
let _dtData = null;           // the last answer of GET /detections
let _dtRows = [];             // the lines of the Findings table, named by index in their buttons
let _dtRegistered = false;

const _DT_SEV = { critical: ['Critical', 'crit', 0], high: ['High', 'crit', 1], medium: ['Medium', 'warn', 2], low: ['Low', '', 3] };
const _DT_COUNTS = ['critical', 'high', 'medium'];

function _dtRuleTitle(id) {
  const r = ((_dtData && _dtData.rules) || []).find(x => x.id === id);
  return r ? r.title : id;
}

function _dtSevBadge(sev) {
  const s = _DT_SEV[sev] || [sev || '', '', 9];
  return `<span class="patch-badge ${s[1]}">${escHtml(s[0])}</span>`;
}

function _dtAddress(f) { return f.ip ? f.ip + (f.port ? ':' + f.port : '') : ''; }

function _dtRow(f) {
  return `<tr>
    <td>${_dtSevBadge(f.severity)}</td>
    <td><a href="#" data-action="detectionsOpenHost" data-arg="${f._i}" data-prevent-default class="fw-500">${escHtml(f.name || f.id)}</a>${f.monitored === false ? ' <span class="patch-badge">Unmonitored</span>' : ''}</td>
    <td>${escHtml(_dtRuleTitle(f.rule))}</td>
    <td>${escHtml(f.detail || '')}</td>
    <td class="mono-12">${escHtml(_dtAddress(f))}</td>
    <td class="hint-nowrap">${f.raised_at ? timeAgoHtml(f.raised_at) : '—'}</td>
  </tr>`;
}

function _dtRegister() {
  if (_dtRegistered) return;
  _dtRegistered = true;
  tableCtl.register({
    name: 'detections-findings', tbody: 'detections-findings-tbody', sortHeaders: 'detections-findings-thead', filterInput: 'detections-findings-filter', colspan: 6,
    columns: ['severity', 'host', 'rule', 'what', 'address', 'raised'],
    getColumns: (f) => ({ severity: (_DT_SEV[f.severity] || [0, 0, 9])[2], host: f.name || f.id || '', rule: _dtRuleTitle(f.rule), what: f.detail || '', address: _dtAddress(f), raised: f.raised_at || 0 }),
    match: (f, q) => [f.name, f.id, f.rule, _dtRuleTitle(f.rule), f.detail, _dtAddress(f), f.process].join(' ').toLowerCase().includes(q),
    row: _dtRow,
    emptyMsg: 'Nothing found at the last sweep.',
  });
}

function _dtStats(d) {
  const el = document.getElementById('detections-stats');
  if (!el) return;
  const c = d.counts || {};
  const item = (label, value) => `<span><span class="hint">${label}</span> <span class="fw-500">${value}</span></span>`;
  el.innerHTML = `<div class="row-8-center">`
    + item('Findings', escHtml(String(d.total || 0)))
    + _DT_COUNTS.map(k => item(_DT_SEV[k][0], escHtml(String(c[k] || 0)))).join('')
    + item('Last sweep', d.last_run ? timeAgoHtml(d.last_run) : escHtml('—'))
    + `</div>`;
  const note = document.getElementById('detections-note');
  if (!note) return;
  note.textContent = '';
  if (!d.last_run) note.textContent = 'No sweep has run yet. The first one runs within five minutes of switching the module on.';
  else if (!d.traffic) note.textContent = 'Traffic is off, so the rules that read it find nothing. Switch it on under Settings → Advanced.';
}

function _dtRuleHtml(r, editable) {
  const dis = editable ? '' : ' disabled';
  const params = (r.params || []).map(p =>
    `<label class="meta-sm">${escHtml(p.label)} <input type="number" class="form-input input-narrow" data-rule="${escAttr(r.id)}" data-param="${escAttr(p.name)}" min="${escAttr(String(p.min))}" max="${escAttr(String(p.max))}" value="${escAttr(String(p.value))}"${dis}></label>`).join(' ');
  const needs = (r.needs || []).map(n => `<span>${escHtml(n)}</span>`).join(', ');
  return `<div class="mt-12">
    <label class="form-label"><input type="checkbox" data-rule="${escAttr(r.id)}" data-param="enabled"${r.enabled ? ' checked' : ''}${dis}> <strong>${escHtml(r.title)}</strong></label> ${_dtSevBadge(r.severity)}
    <div class="hint">${escHtml(r.why)}</div>
    <div class="hint"><span>Reads</span> ${needs}</div>
    ${params ? `<div class="row-8-center mt-8">${params}</div>` : ''}
  </div>`;
}

// A rule box that no longer holds what was drawn into it (a number typed, a box ticked) is the operator's until it is saved: an answer that lands now does not draw over it.
// The page reads this off the boxes themselves (defaultValue, defaultChecked), so it holds whatever the operator is doing, typing included, with no event to forget.
function _dtEdited() {
  return [...document.querySelectorAll('#detections-rules input')].some(el => (el.type === 'checkbox' ? el.checked !== el.defaultChecked : el.value !== el.defaultValue));
}

function _dtPaintRules(d, force) {
  const list = document.getElementById('detections-rules');
  const edit = document.getElementById('detections-rules-edit');
  const note = document.getElementById('detections-rules-note');
  const editable = !!d.editable;
  if (edit) edit.hidden = !editable;
  if (note) note.textContent = editable ? '' : 'The platform operator changes the rules.';
  if (!list || (!force && editable && _dtEdited())) return;
  list.innerHTML = (d.rules || []).map(r => _dtRuleHtml(r, editable)).join('');
}

function detectionsOpenHost(i) {
  const f = _dtRows[Number(i)];
  if (f && typeof openDeviceDrawer === 'function') openDeviceDrawer(f.id, f.name || f.id);
}

async function detectionsSave() {
  const rules = {};
  document.querySelectorAll('#detections-rules [data-rule]').forEach(el => {
    const id = el.dataset.rule, param = el.dataset.param;
    if (!rules[id]) rules[id] = {};
    if (param === 'enabled') rules[id].enabled = !!el.checked;
    else if (el.value !== '') rules[id][param] = Number(el.value);
  });
  if (!Object.keys(rules).length) return;
  const r = await api('POST', '/detections/rules', { rules });
  if (!r || r.error) { failToast(r); return; }
  toast('Saved', 'success');
  await loadDetections(true);
}

async function loadDetections(force) {
  const wrap = document.getElementById('detections-wrap');
  if (!wrap) return;
  _dtRegister();
  const seq = ++_dtSeq;
  const d = await api('GET', '/detections').catch(() => null);
  if (seq !== _dtSeq) return;
  if (!d || d.error) {
    const note = document.getElementById('detections-note');
    if (note) note.textContent = 'The detections could not be loaded.';
    return;
  }
  _dtData = d;
  _dtRows = (d.findings || []).map((f, i) => Object.assign({ _i: i }, f));
  _dtStats(d);
  tableCtl.render('detections-findings', _dtRows);
  _dtPaintRules(d, force === true);
}

function detectionsEnter() {
  const wrap = document.getElementById('detections-wrap');
  if (!wrap) return;
  const on = !!(window._modules && window._modules.detections);
  wrap.hidden = !on;
  if (!on) return;
  if (Date.now() - _dtAt < 4000) return;     // showPage and the module gate both pass through here
  _dtAt = Date.now();
  loadDetections();
}
