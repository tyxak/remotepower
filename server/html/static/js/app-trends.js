// v6.4.2: ad-hoc metric explorer.
//
// Every other chart in the product is a hardcoded panel: the Trends page picks
// ONE device, ONE of four preset tiers, and draws its four series. The roll-up
// store already holds ~2 years of per-device cpu/mem/swap/disk (and, since
// v6.4.2, temperature) — but nothing could put two hosts on the same axis, ask
// for an arbitrary window, or keep a question around to ask again next week.
// This module adds that as a card on the Trends page.
//
// It is deliberately built ONLY on endpoints that already exist:
//   GET /api/devices?slim=1
//   GET /api/devices/<id>/metrics/rollup?tier=fivemin|hourly|daily
//   GET /api/devices/<id>/thermal/rollup?tier=fivemin|hourly|daily
// There is NO fleet-wide multi-device roll-up read, so N hosts costs N (or 2N
// with temperature) requests, fanned out from the browser. That is the honest
// limit and the note under the chart says so rather than pretending otherwise.
// The same reason caps each RUN at _MX_MAX_DEVICES hosts. The picker itself is
// not capped: ticking a ninth host is allowed and the note names how many were
// left out, because a cap that silently drops hosts is the worse failure.
//
// Rendering goes through the shared renderTimeSeries component (crosshair
// readout, drag-zoom, exact from/to bar) — there is no fourth chart renderer
// here, only series assembly.

// src: which endpoint carries the series. The roll-up read shape is
// {ts, <key>: {min, avg, max}} for BOTH, which is what makes one overlay
// possible at all.
const _MX_METRICS = [
  { key: 'cpu',  label: 'CPU %',       unit: '%',  src: 'metrics' },
  { key: 'mem',  label: 'Memory %',    unit: '%',  src: 'metrics' },
  { key: 'swap', label: 'Swap %',      unit: '%',  src: 'metrics' },
  { key: 'disk', label: 'Disk %',      unit: '%',  src: 'metrics' },
  { key: 'temp', label: 'Temperature', unit: '°C', src: 'thermal' },
];
const _MX_STATS = ['avg', 'min', 'max'];
const _MX_TIERS = ['auto', 'fivemin', 'hourly', 'daily'];
// Each selected host is its own HTTP request (see the header note). Eight is
// where a fan-out from one browser tab stops being polite to the API.
const _MX_MAX_DEVICES = 8;
// A tick list can legitimately run past the fetch cap (the operator is told how
// many were left out); this only bounds the O(n²) dedup against a hand-edited
// localStorage blob claiming thousands of hosts.
const _MX_MAX_PICKED = 200;
// renderTimeSeries draws a circle per point per series; 2 years of daily
// buckets x 8 hosts x 4 metrics is ~23k circles. Fold to this many points per
// series first — the shape survives, the DOM does not explode.
const _MX_MAX_POINTS = 240;
const _MX_LS_KEY = 'rp_metric_explorer_v1';
// value = seconds back from now; 0 = the absolute from/to the operator typed.
const _MX_RANGES = [
  { v: '86400',    label: 'Last 24 hours' },
  { v: '604800',   label: 'Last 7 days' },
  { v: '2592000',  label: 'Last 30 days' },
  { v: '7776000',  label: 'Last 90 days' },
  { v: '31536000', label: 'Last year' },
  { v: '63072000', label: 'Last 2 years' },
  { v: '0',        label: 'Custom window' },
];

function _mxNow() { return Math.floor(Date.now() / 1000); }

// Which tier actually HAS the resolution and the retention for a window.
// Server-side retention (api.py ROLLUP_*_KEEP): 5-min buckets ~8 days, hourly
// 30 days, daily ~2 years. Asking fivemin for a window older than its retention
// returns nothing, so the age of the window matters as much as its span.
function _mxTierFor(fromTs, toTs, nowTs) {
  const now = (nowTs == null) ? _mxNow() : nowTs;
  const span = Math.max(1, toTs - fromTs);
  const age = now - fromTs;
  if (span <= 3 * 86400 && age <= 7 * 86400) return 'fivemin';
  if (span <= 30 * 86400 && age <= 28 * 86400) return 'hourly';
  return 'daily';
}

// A saved query stores EITHER a relative range (rel > 0 seconds back from now)
// or an absolute from/to. Relative is what an operator usually means by "the
// last week", and it keeps meaning that a month later.
function _mxWindow(q, nowTs) {
  const now = (nowTs == null) ? _mxNow() : nowTs;
  const rel = Math.floor(Number(q && q.rel) || 0);
  if (rel > 0) return { from: now - rel, to: now };
  const from = Math.floor(Number(q && q.from) || 0);
  const to = Math.floor(Number(q && q.to) || 0);
  if (from > 0 && to > from) return { from, to };
  return { from: now - 604800, to: now };   // a sane week rather than an error
}

// Fold consecutive points down to <= cap. Returns the input untouched when it
// already fits, so a short window keeps every sample.
//
// The reducer MATCHES the statistic being plotted: folding a `max` series by
// averaging would quietly turn a peak chart into a mean-of-peaks — the series
// would still be labelled "max" and would no longer be one.
function _mxFold(pts, cap, stat) {
  const lim = cap || _MX_MAX_POINTS;
  if (!Array.isArray(pts) || pts.length <= lim) return pts || [];
  const group = Math.ceil(pts.length / lim);
  const out = [];
  for (let i = 0; i < pts.length; i += group) {
    const chunk = pts.slice(i, i + group);
    let y;
    if (stat === 'max') {
      y = chunk[0].y;
      for (const p of chunk) if (p.y > y) y = p.y;
    } else if (stat === 'min') {
      y = chunk[0].y;
      for (const p of chunk) if (p.y < y) y = p.y;
    } else {
      let sum = 0;
      for (const p of chunk) sum += p.y;
      y = sum / chunk.length;
    }
    out.push({ x: chunk[0].x, y });
  }
  return out;
}

// One axis, one unit. Mixing temperature with the percentage metrics is a
// legitimate thing to ask for (does that host get hot when its CPU does?), so
// it is allowed — but the axis label goes blank and the note says so, rather
// than labelling degrees as percent.
function _mxYUnit(metrics) {
  const units = [];
  (metrics || []).forEach(k => {
    const def = _MX_METRICS.find(m => m.key === k);
    if (def && units.indexOf(def.unit) < 0) units.push(def.unit);
  });
  return units.length === 1 ? units[0] : '';
}

// rows: [{id, name, metrics: [rollup points], thermal: [rollup points]}]
// Returns the renderTimeSeries series array: [{name, points:[{x,y}]}].
function _mxBuildSeries(rows, metrics, stat, fromTs, toTs, cap) {
  const st = _MX_STATS.indexOf(stat) >= 0 ? stat : 'avg';
  const out = [];
  (rows || []).forEach(row => {
    (metrics || []).forEach(key => {
      const def = _MX_METRICS.find(m => m.key === key);
      if (!def) return;
      const src = (def.src === 'thermal' ? row.thermal : row.metrics) || [];
      const pts = [];
      src.forEach(p => {
        if (!p || typeof p.ts !== 'number') return;
        if (p.ts < fromTs || p.ts > toTs) return;
        const agg = p[key];
        if (!agg || typeof agg[st] !== 'number') return;
        pts.push({ x: p.ts, y: agg[st] });
      });
      if (!pts.length) return;
      pts.sort((a, b) => a.x - b.x);
      out.push({ name: `${row.name} · ${def.label}`, points: _mxFold(pts, cap, st) });
    });
  });
  return out;
}

// Normalise anything claiming to be a saved query — including a hand-edited
// localStorage blob from a future/older build. Never throws, always returns a
// runnable query.
function _mxNormalizeQuery(q) {
  const src = (q && typeof q === 'object') ? q : {};
  const devices = [];
  // Deliberately NOT capped at _MX_MAX_DEVICES here: the fetch cap belongs at
  // the fetch (runMetricExplorer), where the operator can be TOLD that hosts
  // 9+ were left out. Capping twice made the overflow always compute as zero,
  // so the extra hosts disappeared with no note at all. The slice is only a
  // bound on a hand-edited localStorage blob, well above the fetch cap.
  (Array.isArray(src.devices) ? src.devices.slice(0, _MX_MAX_PICKED) : []).forEach(d => {
    if (typeof d === 'string' && d && devices.indexOf(d) < 0) devices.push(d);
  });
  const metrics = [];
  (Array.isArray(src.metrics) ? src.metrics : []).forEach(m => {
    if (_MX_METRICS.some(d => d.key === m) && metrics.indexOf(m) < 0) metrics.push(m);
  });
  const num = v => { const n = Math.floor(Number(v)); return isFinite(n) && n > 0 ? n : 0; };
  // The id travels through data-arg on the delete button, and the dispatcher
  // coerces a numeric-looking data-arg to Number — so it is non-numeric by
  // construction (the 'mx-' prefix), never a bare counter.
  const id = (typeof src.id === 'string' && /^mx-[A-Za-z0-9]{1,32}$/.test(src.id))
    ? src.id : 'mx-' + Math.random().toString(36).slice(2, 10);
  return {
    id,
    name: String(src.name == null ? '' : src.name).slice(0, 60),
    devices,
    metrics: metrics.length ? metrics : ['cpu'],
    stat: _MX_STATS.indexOf(src.stat) >= 0 ? src.stat : 'avg',
    tier: _MX_TIERS.indexOf(src.tier) >= 0 ? src.tier : 'auto',
    rel: num(src.rel),
    from: num(src.from),
    to: num(src.to),
  };
}

// v6.4.2: saved queries live on the SERVER, in the shared query_templates store
// (kind=metric) alongside Data Explorer and Fleet Query saved queries — so one
// sharing model and one tenant gate cover all three, instead of this page
// quietly having neither.
//
// `_mxSaved` is the in-memory mirror; every mutation refetches rather than
// patching it, because the server is the source of truth and a stale mirror is
// how a "saved" query turns out not to be.
let _mxSaved = [];

// Kept ONLY to migrate anything an operator already has in this browser.
function _mxLocalLegacy() {
  let raw = null;
  try { raw = localStorage.getItem(_MX_LS_KEY); } catch (_) { return []; }
  let arr;
  try { arr = JSON.parse(raw || '[]'); } catch (_) { return []; }
  if (!Array.isArray(arr)) return [];
  return arr.map(_mxNormalizeQuery).filter(q => q.name);
}

function _mxSavedLoad() { return _mxSaved; }

async function _mxSavedFetch() {
  const r = await api('GET', '/query/templates?kind=metric').catch(() => null);
  const rows = (r && Array.isArray(r.templates)) ? r.templates : [];
  // Normalise through the SAME function the local blobs went through, so a
  // record written by a different build is still runnable.
  _mxSaved = rows.map(t => {
    const q = _mxNormalizeQuery(Object.assign({}, t.params || {}, {name: t.name}));
    q.id = t.id;                       // server id, used for open/delete
    q.shared = t.visibility === 'shared';
    return q;
  }).filter(q => q.name);
  return _mxSaved;
}

// One-time lift of this browser's queries. The local copy is cleared only once
// every one of them is confirmed stored server-side.
async function _mxMigrateLocal() {
  const local = _mxLocalLegacy();
  if (!local.length) return;
  let moved = 0;
  for (const q of local) {
    const r = await api('POST', '/query/templates',
                        {name: q.name, kind: 'metric', params: q, shared: false})
                .catch(() => null);
    if (r && r.ok) moved++;
  }
  if (moved === local.length) {
    try { localStorage.removeItem(_MX_LS_KEY); } catch (_) {}
    toast(`Moved ${moved} saved quer${moved === 1 ? 'y' : 'ies'} to the server`, 'success');
  }
}

// ─── DOM ─────────────────────────────────────────────────────────────────────

let _mxDevices = [];        // [{id, name}] from /devices?slim=1
let _mxLastSeries = [];     // what is on the chart, for the CSV export
let _mxLastMeta = null;

function _mxCardHtml() {
  const metricBoxes = _MX_METRICS.map(m =>
    `<label class="row-6-center mb-4"><input type="checkbox" class="mx-metric-cb" value="${escAttr(m.key)}"${m.key === 'cpu' ? ' checked' : ''}> ${escHtml(m.label)}</label>`).join('');
  const statOpts = _MX_STATS.map(s => `<option value="${s}">${s}</option>`).join('');
  const tierOpts = _MX_TIERS.map(t =>
    `<option value="${t}">${t === 'auto' ? 'Tier: auto' : 'Tier: ' + t}</option>`).join('');
  const rangeOpts = _MX_RANGES.map(r =>
    `<option value="${r.v}"${r.v === '604800' ? ' selected' : ''}>${escHtml(r.label)}</option>`).join('');
  return `
    <div class="section-title">Metric explorer</div>
    <div class="hint mb-8">Overlay any hosts and metrics on one axis over any window, from the same roll-up history the charts above read. Resolution is 5-minute at best (8 days), hourly to 30 days, daily to ~2 years — the tier is picked for you unless you force one.</div>
    <div class="row-8-center mb-8">
      <input id="mx-filter" type="text" class="form-input input-auto" placeholder="Filter hosts…" aria-label="Filter hosts" data-input="filterMetricExplorerHosts" data-input-debounce="150">
      <button type="button" class="btn-icon btn-xs" data-action="clearMetricExplorerHosts">${_icon('x', 12)} Clear hosts</button>
      <select id="mx-stat" class="form-input input-auto" aria-label="Statistic">${statOpts}</select>
      <select id="mx-tier" class="form-input input-auto" aria-label="Roll-up tier">${tierOpts}</select>
      <select id="mx-rel" class="form-input input-auto" aria-label="Time window" data-change="syncMetricExplorerWindow">${rangeOpts}</select>
    </div>
    <div class="row-8-center mb-8">
      <label class="hint" for="mx-from">From</label>
      <input id="mx-from" type="datetime-local" class="form-input input-auto" aria-label="Window start">
      <label class="hint" for="mx-to">To</label>
      <input id="mx-to" type="datetime-local" class="form-input input-auto" aria-label="Window end">
      <button type="button" class="btn btn-sm" data-action="runMetricExplorer">${_icon('play', 14)} Run</button>
      <button type="button" class="btn-icon btn-xs" data-action="exportMetricExplorerCsv">${_icon('download', 12)} CSV</button>
    </div>
    <div class="row-8-center mb-8">
      <div id="mx-hosts" class="scroll-cap mx-hostbox"><div class="c-muted">Loading hosts…</div></div>
      <div id="mx-metrics" class="mx-metricbox">${metricBoxes}</div>
    </div>
    <div id="mx-chart" class="trend-chart"><div class="c-muted">Pick hosts and metrics, then Run.</div></div>
    <div id="mx-note" class="hint mt-8"></div>
    <div class="row-8-center mt-12">
      <input id="mx-name" type="text" class="form-input input-auto" placeholder="Name this query…" aria-label="Saved query name" maxlength="60">
      <button type="button" class="btn-icon btn-xs" data-action="saveMetricExplorerQuery">${_icon('clipboard', 12)} Save query</button>
      <select id="mx-saved" class="form-input input-auto" aria-label="Saved queries"></select>
      <button type="button" class="btn-icon btn-xs" data-action="openMetricExplorerQuery">${_icon('bookOpen', 12)} Open</button>
      <button type="button" class="btn-icon btn-xs" data-action="deleteMetricExplorerQuery">${_icon('trash', 12)} Delete</button>
    </div>
    <div class="hint mt-8">Saved queries are stored on the server: private to your account by default, and shareable with your team when you save one.</div>`;
}

// Mounted into the existing Trends page rather than a page of its own: the
// question it answers ("show me these hosts over this window") is the same
// question the page already asks, only unpinned.
function mountMetricExplorer() {
  const page = document.getElementById('page-trends');
  if (!page) return;
  if (!document.getElementById('mx-card')) {
    const card = document.createElement('div');
    card.id = 'mx-card';
    card.className = 'dash-card mb-16';
    card.innerHTML = _mxCardHtml();
    page.appendChild(card);
    syncMetricExplorerWindow();
  }
  // Saved queries come from the server now, so render only after they land —
  // calling _mxRenderSaved() synchronously here would paint "No saved queries"
  // over a list the operator does have.
  _mxSavedFetch()
    .then(() => { _mxRenderSaved(); return _mxMigrateLocal(); })
    .then(() => _mxSavedFetch())
    .then(_mxRenderSaved)
    .catch(() => _mxRenderSaved());
  _mxLoadDevices();
}

async function _mxLoadDevices() {
  if (_mxDevices.length) return;
  const box = document.getElementById('mx-hosts');
  const devs = await api('GET', '/devices?slim=1').catch(() => null);
  if (!Array.isArray(devs)) {
    if (box) _errorState(box, _mxLoadDevices, { msg: 'Failed to load the host list.' });
    return;
  }
  _mxDevices = devs.map(d => ({ id: String(d.id), name: String(d.name || d.id) }))
                   .sort((a, b) => a.name.localeCompare(b.name));
  _mxRenderHosts();
}

// The picked set must survive a filter re-render, so it is tracked separately
// from the checkboxes currently in the DOM (filtering unmounts them). Declared
// ahead of its first reader: _mxRenderHosts renders straight from it.
let _mxPicked = [];

function _mxRenderHosts(filter) {
  const box = document.getElementById('mx-hosts');
  if (!box) return;
  // Renders the TRACKED set, and never re-derives it from the boxes it is
  // about to replace — reading the outgoing DOM here is what made opening a
  // saved query a no-op (the stale unticked boxes un-picked the query's hosts
  // before a single one was drawn).
  const picked = new Set(_mxPicked);
  const f = String(filter == null ? (document.getElementById('mx-filter')?.value || '') : filter).toLowerCase();
  const rows = _mxDevices.filter(d => !f || d.name.toLowerCase().indexOf(f) >= 0 || d.id.toLowerCase().indexOf(f) >= 0);
  if (!rows.length) {
    box.innerHTML = `<div class="c-muted">${_mxDevices.length ? 'No host matches that filter.' : 'No devices yet.'}</div>`;
    return;
  }
  box.innerHTML = rows.map(d =>
    `<label class="row-6-center mb-4"><input type="checkbox" class="mx-host-cb" value="${escAttr(d.id)}"${picked.has(d.id) ? ' checked' : ''}> ${escHtml(d.name)}</label>`).join('');
}

// Fold the CURRENTLY MOUNTED checkboxes into the tracked set. Split out of the
// getter on purpose: it mutates, so it may only run when the boxes on screen
// are the operator's own last word — never on a path that has just replaced
// the tracked set from somewhere else (a saved query, a Clear).
function _mxSyncPickedFromDom() {
  const box = document.getElementById('mx-hosts');
  if (!box) return;
  box.querySelectorAll('.mx-host-cb').forEach(cb => {
    const i = _mxPicked.indexOf(cb.value);
    if (cb.checked && i < 0) _mxPicked.push(cb.value);
    if (!cb.checked && i >= 0) _mxPicked.splice(i, 1);
  });
}

// Pure read of the tracked set.
function _mxSelectedHosts() {
  return _mxPicked.slice();
}

function filterMetricExplorerHosts() {
  _mxSyncPickedFromDom();      // capture the current ticks before they unmount
  _mxRenderHosts();
}

function clearMetricExplorerHosts() {
  _mxPicked = [];
  _mxRenderHosts();
}

function _mxSelectedMetrics() {
  const out = [];
  document.querySelectorAll('#mx-metrics .mx-metric-cb').forEach(cb => { if (cb.checked) out.push(cb.value); });
  return out;
}

// Keep the from/to inputs in step with the relative picker, so "last 30 days"
// is also visible as two real timestamps the operator can then edit.
function syncMetricExplorerWindow() {
  const rel = parseInt(document.getElementById('mx-rel')?.value || '0', 10) || 0;
  if (!rel) return;   // Custom — leave whatever the operator typed alone
  const now = _mxNow();
  const fromIn = document.getElementById('mx-from');
  const toIn = document.getElementById('mx-to');
  if (fromIn) fromIn.value = _tsLocalInput(now - rel);
  if (toIn) toIn.value = _tsLocalInput(now);
}

function _mxReadQuery() {
  // Reading the query IS the moment the on-screen ticks become the answer, so
  // this is the one place (besides re-filtering) that folds the DOM in.
  _mxSyncPickedFromDom();
  const relRaw = document.getElementById('mx-rel')?.value || '0';
  const rel = parseInt(relRaw, 10) || 0;
  const parse = id => {
    const v = document.getElementById(id)?.value || '';
    const t = v ? Math.floor(new Date(v).getTime() / 1000) : NaN;
    return isFinite(t) ? t : 0;
  };
  return _mxNormalizeQuery({
    devices: _mxSelectedHosts(),
    metrics: _mxSelectedMetrics(),
    stat: document.getElementById('mx-stat')?.value,
    tier: document.getElementById('mx-tier')?.value,
    rel,
    from: parse('mx-from'),
    to: parse('mx-to'),
    name: document.getElementById('mx-name')?.value || '',
  });
}

function _mxApplyQuery(q) {
  _mxPicked = q.devices.slice();
  _mxRenderHosts();
  document.querySelectorAll('#mx-metrics .mx-metric-cb').forEach(cb => { cb.checked = q.metrics.indexOf(cb.value) >= 0; });
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  set('mx-stat', q.stat);
  set('mx-tier', q.tier);
  set('mx-rel', String(q.rel || 0));
  set('mx-name', q.name);
  if (q.rel) {
    syncMetricExplorerWindow();
  } else {
    if (q.from) set('mx-from', _tsLocalInput(q.from));
    if (q.to) set('mx-to', _tsLocalInput(q.to));
  }
}

function _mxNote(html) {
  const el = document.getElementById('mx-note');
  if (el) el.innerHTML = html;
}

// Zoom handler for the shared chart: a picked window becomes the query's
// window (and may re-serve it from a finer tier), which is what a drag on a
// metrics chart means everywhere else. (null, null) is the reset — leave the
// operator's own range choice alone there.
function _mxOnZoom(fromTs, toTs) {
  if (fromTs == null || toTs == null) return;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
  set('mx-rel', '0');
  set('mx-from', _tsLocalInput(Math.floor(fromTs)));
  set('mx-to', _tsLocalInput(Math.ceil(toTs)));
  // The refetch IS the window, so the chart must not ALSO clip to it — that
  // would zoom twice and leave a reset button that undoes nothing visible.
  clearTimeSeriesZoom('mx-chart');
  runMetricExplorer();
}

async function runMetricExplorer() {
  const out = document.getElementById('mx-chart');
  if (!out) return;
  const q = _mxReadQuery();
  if (!q.devices.length) {
    out.innerHTML = '<div class="empty-state">Pick at least one host.</div>';
    _mxNote('');
    return;
  }
  // Read the ticks, NOT q.metrics: _mxNormalizeQuery defaults an empty list to
  // ['cpu'] so a corrupt saved blob is still runnable, which made this branch
  // unreachable — unticking every metric quietly plotted CPU instead of saying
  // anything. The default is right for a stored query and wrong for a live one.
  if (!_mxSelectedMetrics().length) {
    out.innerHTML = '<div class="empty-state">Pick at least one metric.</div>';
    _mxNote('');
    return;
  }
  const win = _mxWindow(q);
  const tier = q.tier === 'auto' ? _mxTierFor(win.from, win.to) : q.tier;
  const wantMetric = q.metrics.some(k => (_MX_METRICS.find(m => m.key === k) || {}).src === 'metrics');
  const wantThermal = q.metrics.indexOf('temp') >= 0;
  const ids = q.devices.slice(0, _MX_MAX_DEVICES);
  const overflow = q.devices.length - ids.length;
  out.innerHTML = '<div class="c-muted">Loading…</div>';
  _mxNote('');

  // No fleet-wide roll-up read exists, so this is a per-host fan-out. Failures
  // are per-host and reported as such — one unreachable host must not blank the
  // whole chart.
  const failed = [];
  let reqs = 0;
  const rows = await Promise.all(ids.map(async id => {
    const dev = _mxDevices.find(d => d.id === id);
    const row = { id, name: (dev && dev.name) || id, metrics: [], thermal: [] };
    if (wantMetric) {
      reqs++;
      const r = await api('GET', `/devices/${encodeURIComponent(id)}/metrics/rollup?tier=${encodeURIComponent(tier)}`).catch(() => null);
      if (r && Array.isArray(r.points)) row.metrics = r.points;
      else failed.push(row.name);
    }
    if (wantThermal) {
      reqs++;
      const r = await api('GET', `/devices/${encodeURIComponent(id)}/thermal/rollup?tier=${encodeURIComponent(tier)}`).catch(() => null);
      if (r && Array.isArray(r.points)) row.thermal = r.points;
      else if (failed.indexOf(row.name) < 0) failed.push(row.name);
    }
    return row;
  }));

  const series = _mxBuildSeries(rows, q.metrics, q.stat, win.from, win.to);
  _mxLastSeries = series;
  _mxLastMeta = { tier, stat: q.stat, from: win.from, to: win.to };
  if (!series.length) {
    out.innerHTML = '<div class="empty-state">No roll-up points for those hosts in that window.'
      + ' Roll-ups fold about once an hour, and the 5-minute tier only keeps 8 days.</div>';
  } else {
    renderTimeSeries('mx-chart', series, {
      yUnit: _mxYUnit(q.metrics),
      label: `Metric explorer — ${series.length} series, ${q.stat}`,
      zoom: true,
      onZoom: _mxOnZoom,
    });
  }
  const bits = [
    `${series.length} series from ${ids.length} host${ids.length === 1 ? '' : 's'}`,
    `${tier} buckets (${q.tier === 'auto' ? 'auto-picked' : 'forced'})`,
    `${q.stat} of each bucket`,
    `${reqs} request${reqs === 1 ? '' : 's'} — there is no fleet-wide roll-up read, so hosts are fetched one by one`,
  ];
  if (!_mxYUnit(q.metrics)) bits.push('mixed units on one axis (% and °C) — the axis is unlabelled on purpose');
  if (overflow > 0) bits.push(`${overflow} more host${overflow === 1 ? '' : 's'} selected but not fetched (cap is ${_MX_MAX_DEVICES})`);
  // Host names are operator-authored: escape them exactly ONCE, here, where
  // every bit goes through escHtml on its way into innerHTML.
  if (failed.length) bits.push(`no data from: ${failed.join(', ')}`);
  _mxNote(bits.map(escHtml).join(' · '));
}

function exportMetricExplorerCsv() {
  if (!_mxLastSeries.length) { toast('Run a query first', 'error', { transient: true }); return; }
  const lines = ['series,ts,iso,value'];
  _mxLastSeries.forEach(s => {
    const nm = '"' + String(s.name).replace(/"/g, '""') + '"';
    s.points.forEach(p => {
      lines.push(`${nm},${p.x},${new Date(p.x * 1000).toISOString()},${p.y}`);
    });
  });
  const blob = new Blob([lines.join('\n')], { type: 'text/csv' });
  const u = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = u;
  a.download = `metric-explorer-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(u);
  toast('CSV downloaded', 'success');
}

// ─── saved queries (server-backed, shareable) ────────────────────────────────

function _mxRenderSaved() {
  const sel = document.getElementById('mx-saved');
  if (!sel) return;
  const list = _mxSavedLoad();
  sel.innerHTML = list.length
    ? list.map(q => `<option value="${escAttr(q.id)}">${escHtml(q.name)}</option>`).join('')
    : '<option value="">No saved queries</option>';
}

async function saveMetricExplorerQuery() {
  const q = _mxReadQuery();
  if (!q.name) { toast('Give the query a name first', 'error', { transient: true }); return; }
  if (!q.devices.length) { toast('Pick at least one host before saving', 'error', { transient: true }); return; }
  const shared = await uiConfirm({
    title: 'Share with your team?',
    message: 'Shared queries are visible to everyone in your organisation.\n\n'
             + 'Private keeps it to your account.',
    confirmText: 'Share',
  });
  const r = await api('POST', '/query/templates',
                      {name: q.name, kind: 'metric', params: q, shared: !!shared});
  if (!r || !r.ok) { toast((r && r.error) || 'Save failed', 'error'); return; }
  await _mxSavedFetch();
  _mxRenderSaved();
  const sel = document.getElementById('mx-saved');
  if (sel) sel.value = r.id || '';
  toast(`Saved "${q.name}"`, 'success');
}

function openMetricExplorerQuery() {
  const id = document.getElementById('mx-saved')?.value || '';
  const q = _mxSavedLoad().find(s => s.id === id);
  if (!q) { toast('Pick a saved query first', 'error', { transient: true }); return; }
  _mxApplyQuery(q);
  clearTimeSeriesZoom('mx-chart');
  runMetricExplorer();
}

async function deleteMetricExplorerQuery() {
  const id = document.getElementById('mx-saved')?.value || '';
  const q = _mxSavedLoad().find(s => s.id === id);
  if (!q) { toast('Pick a saved query first', 'error', { transient: true }); return; }
  const ok = await uiConfirm({
    title: 'Delete saved query',
    message: q.shared
      ? `Delete "${q.name}"? It is shared with your team, so it goes for everyone.`
      : `Delete "${q.name}"?`,
    confirmText: 'Delete', danger: true,
  });
  if (!ok) return;
  const r = await api('DELETE', '/query/templates/' + encodeURIComponent(q.id));
  if (!r || !r.ok) { toast((r && r.error) || 'Delete failed', 'error'); return; }
  await _mxSavedFetch();
  _mxRenderSaved();
}

// Reachability note: this module is mounted by showPage()'s explicit
//   if (name === 'trends')   { loadTrends(); mountMetricExplorer(); }
// with `trends: ['app-trends.js']` in _LAZY_PAGE_MODULES. It deliberately does
// NOT wrap/reassign loadTrends: a `loadTrends = function () {…}` wrapper here
// is invisible to tests/test_lazy_page_modules.py (which skips any function
// app.js also defines), so the one wiring shape no guard can verify — and it
// would lose to app.js's own hoisted declaration if this file ever evaluated
// first, mounting nothing, silently.
