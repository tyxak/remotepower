// app-traffic.js — the Traffic view (8.0.0): which addresses each Linux host talks to and how much each connection moved. Buildless classic script; every symbol is global
// like the rest of the client JS, and it is fetched on first use (the lazy map in app.js): the Traffic tab of the Threat Intel page and the host drawer's Traffic section.
//
//   trafficEnter()          the tab was opened (app.js calls it whenever the tab shows): draw the cards, at most every few seconds
//   loadTraffic()           fetch the fleet's answer and the watch list and draw them (the Refresh button)
//   trafficShow()           the "Show" select above the remote addresses
//   trafficOpenHost(i)      a line of the Hosts table opens that host's drawer
//   trafficWatchAdd(), trafficWatchRemove(i), trafficWatchSave()   the watch list editor (the platform operator's)
//   loadDrawerTraffic(id)   fill the drawer's section for the host that is open
//
// Addresses, program names and host names came from a host, so they are only ever put in the page with escHtml. A host id never travels through data-arg (the dispatcher turns
// a number-looking value into a number): the rows of a table are named by their place in the list.

let _trSeq = 0;               // the newest load: an older answer that lands after it is dropped
let _trAt = 0;                // when the tab was last drawn (ms), so the module gate and every visit do not each fetch
let _trFleet = null;          // the last answer of GET /traffic/fleet
let _trCfg = null;            // the last answer of GET /traffic/config
let _trRegistered = false;
let _trDraft = null;          // the watch list being edited: while there is one, a late answer does not overwrite it
let _trHostRows = [];         // the lines of the Hosts table, named by index in their buttons
let _trDrawerSeq = 0;
let _trDrawer = null;         // the last answer of GET /devices/<id>/traffic for the drawer that is open

// What a host's line says: [label, badge class].
const _TR_STATE = {
  reporting:   ['Sampling', 'ok'],
  stale:       ['Out of date', 'warn'],
  waiting:     ['Waiting', ''],
  unsupported: ['Not supported', ''],
  error:       ['Cannot read', 'crit'],
};
// Why an agent could not read its connections: fixed phrases, so they are translated.
const _TR_ERR = {
  'no-ss': 'The agent cannot read connections: the ss tool is not installed on this host (package iproute2).',
  'ss-failed': 'The agent could not read the connection table at its last sample.',
  'no-counters': 'This kernel does not report bytes for each connection, so only the connections are shown.',
};
const _TR_KIND = { ip: 'Address', cidr: 'Network', port: 'Port', proc: 'Program' };

function _trBytes(n) { return escHtml(_fmtBytes(n || 0)); }
function _trRate(n) { return escHtml(_fmtBytes(n || 0)) + '/s'; }
function _trDir(d) { return d === 'in' ? 'Inbound' : 'Outbound'; }

function _trRemoteText(r) {
  return [r.ip, (r.hosts || []).map(h => h.name || h.id).join(' '), (r.ports || []).map(p => p.port + ' ' + (p.service || '')).join(' '), r.country, r.org].filter(Boolean).join(' ').toLowerCase();
}

function _trRemoteRow(r) {
  const shown = (r.hosts || []);
  const more = (r.hosts_n || 0) > shown.length ? ` <span class="hint">+${(r.hosts_n || 0) - shown.length}</span>` : '';
  const marks = [];
  if (r.scope && r.scope !== 'public') marks.push('<span class="patch-badge">Local network</span>');
  if (r.new_hosts) marks.push('<span class="patch-badge warn">New</span>');
  if (r.watched) marks.push('<span class="patch-badge crit">Watch list</span>');
  if (typeof r.score === 'number') marks.push(`<span class="patch-badge ${r.score >= 75 ? 'crit' : (r.score >= 25 ? 'warn' : 'ok')}"><span>Score</span> ${escHtml(String(r.score))}</span>`);
  return `<tr>
    <td class="mono-12">${escHtml(r.ip)} ${marks.join(' ')}</td>
    <td>${shown.map(h => escHtml(h.name || h.id)).join(', ')}${more}</td>
    <td class="hint">${(r.ports || []).map(p => escHtml(p.service ? p.port + ' ' + p.service : String(p.port))).join(', ')}</td>
    <td>${escHtml(String(r.n || 0))}</td>
    <td class="hint-nowrap">${_trBytes(r.tx)}</td>
    <td class="hint-nowrap">${_trBytes(r.rx)}</td>
    <td class="hint">${[r.country, r.org].filter(Boolean).map(escHtml).join(' · ')}</td>
  </tr>`;
}

function _trProgramName(p) { return p === '-' || !p ? '<span class="hint">Unknown</span>' : escHtml(p); }

function _trHostRow(h) {
  const st = _TR_STATE[h.state] || [h.state || '', ''];
  const why = h.err && _TR_ERR[h.err] ? `<div class="hint">${escHtml(_TR_ERR[h.err])}</div>` : '';
  const has = h.at !== undefined && h.at !== null;
  return `<tr>
    <td><a href="#" data-action="trafficOpenHost" data-arg="${h._i}" data-prevent-default class="fw-500">${escHtml(h.name || h.id)}</a></td>
    <td><span class="patch-badge ${st[1]}">${escHtml(st[0])}</span>${why}</td>
    <td>${has ? escHtml(String(h.conns || 0)) : '—'}</td>
    <td class="hint-nowrap">${has ? _trRate(h.tx_rate) : '—'}</td>
    <td class="hint-nowrap">${has ? _trRate(h.rx_rate) : '—'}</td>
    <td class="hint-nowrap">${has ? timeAgoHtml(h.at) : '—'}</td>
  </tr>`;
}

function _trHitRow(h) {
  return `<tr>
    <td class="fw-500">${escHtml(h.name || h.id)}</td>
    <td class="mono-12">${escHtml(h.ip)}</td>
    <td>${escHtml(String(h.port))}</td>
    <td class="mono-12">${_trProgramName(h.proc)}</td>
    <td>${escHtml(_trDir(h.d))}</td>
    <td><span class="patch-badge">${escHtml(_TR_KIND[h.kind] || h.kind)}</span> <span class="mono-12">${escHtml(h.value)}</span>${h.label ? ` <span class="hint">${escHtml(h.label)}</span>` : ''}</td>
  </tr>`;
}

function _trRegister() {
  if (_trRegistered) return;
  _trRegistered = true;
  tableCtl.register({
    name: 'traffic-remotes', tbody: 'traffic-remotes-tbody', sortHeaders: 'traffic-remotes-thead', filterInput: 'traffic-remotes-filter', colspan: 7,
    columns: ['address', 'hosts', 'ports', 'connections', 'sent', 'received', 'where'],
    getColumns: (r) => ({ address: r.ip, hosts: (r.hosts || []).map(h => h.name || h.id).join(' '), ports: (r.ports || []).map(p => p.port).join(' '), connections: r.n || 0, sent: r.tx || 0, received: r.rx || 0, where: [r.country, r.org].filter(Boolean).join(' ') }),
    match: (r, q) => _trRemoteText(r).includes(q),
    row: _trRemoteRow,
    emptyMsg: 'No connections to show yet.',
  });
  tableCtl.register({
    name: 'traffic-programs', tbody: 'traffic-programs-tbody', sortHeaders: 'traffic-programs-thead', colspan: 5,
    columns: ['program', 'hosts', 'connections', 'sent', 'received'],
    getColumns: (r) => ({ program: r.proc === '-' ? '' : (r.proc || ''), hosts: r.hosts_n || 0, connections: r.n || 0, sent: r.tx || 0, received: r.rx || 0 }),
    match: (r, q) => String(r.proc || '').toLowerCase().includes(q),
    row: (r) => `<tr><td class="mono-12">${_trProgramName(r.proc)}</td><td>${escHtml(String(r.hosts_n || 0))}</td><td>${escHtml(String(r.n || 0))}</td><td class="hint-nowrap">${_trBytes(r.tx)}</td><td class="hint-nowrap">${_trBytes(r.rx)}</td></tr>`,
    emptyMsg: 'No connections to show yet.',
  });
  tableCtl.register({
    name: 'traffic-ports', tbody: 'traffic-ports-tbody', sortHeaders: 'traffic-ports-thead', colspan: 7,
    columns: ['direction', 'port', 'service', 'hosts', 'connections', 'sent', 'received'],
    getColumns: (r) => ({ direction: r.d || '', port: r.port || 0, service: r.service || '', hosts: r.hosts_n || 0, connections: r.n || 0, sent: r.tx || 0, received: r.rx || 0 }),
    match: (r, q) => (String(r.port) + ' ' + (r.service || '') + ' ' + (r.d || '')).toLowerCase().includes(q),
    row: (r) => `<tr><td>${escHtml(_trDir(r.d))}</td><td>${escHtml(String(r.port))}</td><td>${escHtml(r.service || '')}</td><td>${escHtml(String(r.hosts_n || 0))}</td><td>${escHtml(String(r.n || 0))}</td><td class="hint-nowrap">${_trBytes(r.tx)}</td><td class="hint-nowrap">${_trBytes(r.rx)}</td></tr>`,
    emptyMsg: 'No connections to show yet.',
  });
  tableCtl.register({
    name: 'traffic-hosts', tbody: 'traffic-hosts-tbody', sortHeaders: 'traffic-hosts-thead', colspan: 6,
    columns: ['host', 'state', 'connections', 'sent', 'received', 'last'],
    getColumns: (h) => ({ host: h.name || h.id || '', state: h.state || '', connections: h.conns || 0, sent: h.tx_rate || 0, received: h.rx_rate || 0, last: h.at || 0 }),
    match: (h, q) => (String(h.name || h.id || '') + ' ' + (h.state || '')).toLowerCase().includes(q),
    row: _trHostRow,
    emptyMsg: 'No Linux host has reported yet.',
  });
  tableCtl.register({
    name: 'traffic-hits', tbody: 'traffic-hits-tbody', sortHeaders: 'traffic-hits-thead', colspan: 6,
    columns: ['host', 'address', 'port', 'program', 'direction', 'entry'],
    getColumns: (h) => ({ host: h.name || h.id || '', address: h.ip || '', port: h.port || 0, program: h.proc || '', direction: h.d || '', entry: (h.kind || '') + ' ' + (h.value || '') }),
    match: (h, q) => [h.name, h.ip, h.port, h.proc, h.value, h.label].join(' ').toLowerCase().includes(q),
    row: _trHitRow,
    emptyMsg: 'No connection matches the watch list at the moment.',
  });
}

function _trRemoteRows() {
  const mode = (document.getElementById('traffic-show') || {}).value || 'all';
  const rows = (_trFleet && _trFleet.remotes) || [];
  return rows.filter(r => mode === 'all'
    || (mode === 'public' && r.scope === 'public')
    || (mode === 'local' && r.scope !== 'public')
    || (mode === 'new' && r.new_hosts)
    || (mode === 'watched' && r.watched));
}

function trafficShow() { tableCtl.render('traffic-remotes', _trRemoteRows()); }

function _trStats(f) {
  const el = document.getElementById('traffic-stats');
  if (!el) return;
  const st = f.by_state || {};
  const reporting = (f.hosts || []).filter(h => h.state === 'reporting');
  const sum = (k) => reporting.reduce((a, h) => a + (h[k] || 0), 0);
  const total = Object.values(st).reduce((a, b) => a + b, 0);
  const item = (label, value) => `<span><span class="hint">${label}</span> <span class="fw-500">${value}</span></span>`;
  el.innerHTML = `<div class="row-8-center">`
    + item('Hosts reporting', escHtml(`${st.reporting || 0} / ${total}`))
    + item('Sent', _trRate(sum('tx_rate')))
    + item('Received', _trRate(sum('rx_rate')))
    + item('Connections', escHtml(String(sum('conns'))))
    + item('Sampling interval', escHtml(`${f.every || 0} s`))
    + `</div>`;
  const note = document.getElementById('traffic-note');
  if (note) {
    note.textContent = '';
    if (!(st.reporting || 0) && (st.waiting || 0)) note.textContent = 'No host has reported yet. A Linux agent starts sampling with its next report and sends the first sample one interval later.';
    else if (!total) note.textContent = 'There is no host with an agent yet.';
  }
}

function _trWatchPaint() {
  const cfg = _trCfg || {};
  const editable = !!cfg.editable;
  const edit = document.getElementById('traffic-wl-edit');
  const list = document.getElementById('traffic-wl-list');
  const note = document.getElementById('traffic-wl-note');
  if (edit) edit.hidden = !editable;
  const entries = editable ? (_trDraft || cfg.watch || []) : (cfg.watch || []);
  if (list) {
    list.innerHTML = entries.map((w, i) =>
      `<div class="row-8-center"><span class="patch-badge">${escHtml(_TR_KIND[w.kind] || w.kind)}</span> <span class="mono-12">${escHtml(w.value)}</span>`
      + (w.label ? ` <span class="hint">${escHtml(w.label)}</span>` : '')
      + (editable ? ` <button class="btn-icon btn-xs" data-action="trafficWatchRemove" data-arg="${i}">Remove</button>` : '')
      + `</div>`).join('');
  }
  if (note) {
    note.innerHTML = '';
    if (!editable) {
      const n = cfg.count || 0;
      note.innerHTML = (n && !entries.length ? `<span>Entries in the watch list:</span> ${escHtml(String(n))} ` : (!n ? '<span>The watch list is empty.</span> ' : ''))
        + '<span>The platform operator edits it.</span>';
    } else if (!entries.length) {
      note.innerHTML = '<span>The watch list is empty.</span>';
    }
  }
  const every = document.getElementById('traffic-every');
  if (every) {
    // the box is written only while it still holds what this script last put there (or nothing): a number the operator typed is theirs, and an answer that arrives late does not take it back
    if (every.value === '' || every.value === every.dataset.shown) {
      every.value = cfg.every || '';
      every.dataset.shown = every.value;
    }
    if (cfg.min_every) every.min = String(cfg.min_every);
    if (cfg.max_every) every.max = String(cfg.max_every);
  }
}

function trafficWatchAdd() {
  const kind = (document.getElementById('traffic-wl-kind') || {}).value || 'ip';
  const valueEl = document.getElementById('traffic-wl-value');
  const labelEl = document.getElementById('traffic-wl-label');
  const value = (valueEl && valueEl.value || '').trim();
  if (!value) { toast('Enter an address, network, port or program first', 'error', { transient: true }); if (valueEl) valueEl.focus(); return; }
  const draft = _trDraft || ((_trCfg && _trCfg.watch) || []).map(w => Object.assign({}, w));
  if (draft.length >= ((_trCfg && _trCfg.max_watch) || 100)) { toast('The watch list is full', 'error', { transient: true }); return; }
  draft.push({ kind, value, label: (labelEl && labelEl.value || '').trim() });
  _trDraft = draft;
  if (valueEl) valueEl.value = '';
  if (labelEl) labelEl.value = '';
  _trWatchPaint();
}

function trafficWatchRemove(i) {
  const draft = _trDraft || ((_trCfg && _trCfg.watch) || []).map(w => Object.assign({}, w));
  const k = Number(i);
  if (!Number.isInteger(k) || k < 0 || k >= draft.length) return;
  draft.splice(k, 1);
  _trDraft = draft;
  _trWatchPaint();
}

async function trafficWatchSave() {
  const body = {};
  if (_trDraft) body.watch = _trDraft;
  const everyEl = document.getElementById('traffic-every');
  const every = everyEl && everyEl.value !== '' ? Number(everyEl.value) : null;
  if (every !== null) body.every = every;
  if (!Object.keys(body).length) return;
  const r = await api('POST', '/traffic/config', body);
  if (!r || r.error) { failToast(r); return; }
  toast('Saved', 'success');
  _trDraft = null;
  if (everyEl) everyEl.dataset.shown = everyEl.value;      // what was saved is what the box shows now
  await loadTraffic();
}

async function loadTraffic() {
  const wrap = document.getElementById('traffic-wrap');
  if (!wrap) return;
  _trRegister();
  const seq = ++_trSeq;
  const [fleet, cfg] = await Promise.all([api('GET', '/traffic/fleet').catch(() => null), api('GET', '/traffic/config').catch(() => null)]);
  if (seq !== _trSeq) return;
  if (!fleet || fleet.error) {
    const note = document.getElementById('traffic-note');
    if (note) note.textContent = 'The traffic data could not be loaded.';
    return;
  }
  _trFleet = fleet;
  _trCfg = (cfg && !cfg.error) ? cfg : (_trCfg || {});
  _trHostRows = (fleet.hosts || []).map((h, i) => Object.assign({ _i: i }, h));
  _trStats(fleet);
  tableCtl.render('traffic-remotes', _trRemoteRows());
  tableCtl.render('traffic-programs', fleet.programs || []);
  tableCtl.render('traffic-ports', fleet.ports || []);
  tableCtl.render('traffic-hosts', _trHostRows);
  tableCtl.render('traffic-hits', fleet.hits || []);
  _trWatchPaint();
}

function trafficEnter() {
  const wrap = document.getElementById('traffic-wrap');
  if (!wrap) return;
  const on = !!(window._modules && window._modules.traffic);
  wrap.hidden = !on;
  if (!on) return;
  if (Date.now() - _trAt < 4000) return;     // showPage and the module gate both pass through here
  _trAt = Date.now();
  loadTraffic();
}

function trafficOpenHost(i) {
  const h = _trHostRows[Number(i)];
  if (h && typeof openDeviceDrawer === 'function') openDeviceDrawer(h.id, h.name || h.id);
}

// ── the host drawer's section ────────────────────────────────────────────────

function _trDrawerRowHtml(r) {
  const marks = [];
  if (r.scope === 'private' || r.scope === 'link-local') marks.push('<span class="patch-badge">Local network</span>');
  if (r.new) marks.push('<span class="patch-badge warn">New</span>');
  if (r.watched && r.watched.length) marks.push('<span class="patch-badge crit">Watch list</span>');
  if (typeof r.score === 'number') marks.push(`<span class="patch-badge ${r.score >= 75 ? 'crit' : (r.score >= 25 ? 'warn' : 'ok')}"><span>Score</span> ${escHtml(String(r.score))}</span>`);
  const where = [r.country, r.org].filter(Boolean).map(escHtml).join(' · ');
  return `<tr>
    <td class="mono-12">${escHtml(r.ip)} ${marks.join(' ')}${where ? `<div class="hint">${where}</div>` : ''}</td>
    <td>${escHtml(r.service ? r.port + ' ' + r.service : String(r.port))}</td>
    <td class="mono-12">${_trProgramName(r.proc)}</td>
    <td>${escHtml(_trDir(r.d))}</td>
    <td>${escHtml(String(r.n || 0))}</td>
    <td class="hint-nowrap">${_trBytes(r.tx)}</td>
    <td class="hint-nowrap">${_trBytes(r.rx)}</td>
  </tr>`;
}

function _trDrawerPaintTable() {
  const box = document.getElementById('drawer-traffic-rows');
  const r = _trDrawer;
  if (!box || !r) return;
  const rows = r.rows || [];
  if (!rows.length) { box.innerHTML = ''; return; }
  box.innerHTML = `<div class="scrollable-table-wrap audit-scroll"><table>
    <thead id="drawer-traffic-thead"><tr><th scope="col" data-col="address">Address</th><th scope="col" data-col="port">Port</th><th scope="col" data-col="program">Program</th><th scope="col" data-col="direction">Direction</th><th scope="col" data-col="connections">Connections</th><th scope="col" data-col="sent">Sent</th><th scope="col" data-col="received">Received</th></tr></thead>
    <tbody id="drawer-traffic-tbody"></tbody></table></div>`;
  tableCtl.wireSortOnly('drawer-traffic-thead', 'drawer-traffic', _trDrawerPaintBody);
  _trDrawerPaintBody();
  const rest = r.other || {};
  if (rest.rows) {
    box.insertAdjacentHTML('beforeend', `<div class="hint mt-6"><span>Other rows, added together:</span> ${escHtml(String(rest.rows))} · <span>Sent</span> ${_trBytes(rest.tx)} · <span>Received</span> ${_trBytes(rest.rx)}</div>`);
  }
}

function _trDrawerPaintBody() {
  const tbody = document.getElementById('drawer-traffic-tbody');
  if (!tbody || !_trDrawer) return;
  const sorted = tableCtl.sortRows('drawer-traffic', (_trDrawer.rows || []).slice(), (x) => ({
    address: x.ip, port: x.port || 0, program: x.proc || '', direction: x.d || '', connections: x.n || 0, sent: x.tx || 0, received: x.rx || 0,
  }));
  tbody.innerHTML = sorted.map(_trDrawerRowHtml).join('');
}

function _trChart(label, values, color) {
  const peak = values.reduce((a, b) => Math.max(a, b), 0);
  return `<div class="row-8-center"><span class="hint">${label}</span> ${renderSparkline(values, { width: 280, height: 34, color })} <span class="hint-nowrap"><span>Peak</span> ${_trRate(peak)}</span></div>`;
}

async function loadDrawerTraffic(id) {
  const sec = document.getElementById('drawer-traffic-section');
  const box = document.getElementById('drawer-traffic-body');
  if (!sec || !box) return;
  sec.hidden = true;
  box.innerHTML = '';
  _trDrawer = null;
  if (!(window._modules && window._modules.traffic)) return;
  const seq = ++_trDrawerSeq;
  const r = await api('GET', '/devices/' + encodeURIComponent(id) + '/traffic').catch(() => null);
  if (seq !== _trDrawerSeq || (typeof _drawerDeviceId !== 'undefined' && _drawerDeviceId !== id)) return;
  if (!r || r.error || r.state === 'unsupported') return;
  _trDrawer = r;
  sec.hidden = false;
  let html = '';
  if (r.state === 'waiting') {
    html = '<div class="hint">No sample yet. The agent sends the first one a little after its next report.</div>';
  } else {
    const st = _TR_STATE[r.state] || [r.state || '', ''];
    const summary = `<div class="row-8-center"><span class="patch-badge ${st[1]}">${escHtml(st[0])}</span>`
      + (r.at ? ` <span class="hint">${timeAgoHtml(r.at)}</span>` : '')
      + (r.state !== 'error' ? ` <span><span class="hint">Sent</span> ${_trRate(Math.round((r.tx || 0) / Math.max(1, r.win || 1)))}</span> <span><span class="hint">Received</span> ${_trRate(Math.round((r.rx || 0) / Math.max(1, r.win || 1)))}</span> <span><span class="hint">Connections</span> ${escHtml(String(r.conns || 0))}</span>` : '')
      + `</div>`;
    html = summary;
    if (r.err && _TR_ERR[r.err]) html += `<div class="hint mt-6">${escHtml(_TR_ERR[r.err])}</div>`;
    const series = (r.series || []);
    if (series.length >= 2) {
      html += `<div class="mt-8">${_trChart('Sent', series.map(p => p[1]), 'var(--accent)')}${_trChart('Received', series.map(p => p[2]), 'var(--green)')}</div>`;
    }
    html += '<div id="drawer-traffic-rows" class="mt-8"></div>';
  }
  box.innerHTML = html;
  _trDrawerPaintTable();
}
