// app-self.js — page module extracted from app.js (buildless classic script; all
// symbols stay global, same as the rest of the client JS).
// Self-monitoring / diagnostics page. EAGER (script tag): app-backups.js
// calls loadSelfStatus() and _selfFmtBytes() from the Backups page, so this
// cannot be keyed on navigating to `self`.

// ─── v3.0.2: Self-monitoring page ──────────────────────────────────────────
// Renders /api/self/status into expandable info cards.
function _selfFmtBytes(b) {
  if (b == null) return '—';
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b < 10 ? 1 : 0) + ' ' + u[i];
}
function _selfFmtAgo(ts) { return timeAgo(ts, { empty: 'never', clamp: true }); }

// ─── v6.4.2: one state vocabulary for every subsystem row on this page ──────
// 'ok' | 'warn' | 'bad' | 'muted'. 'muted' used to fall through to the amber
// warning glyph, so a sidecar that simply isn't in use read as a fault.
const _SELF_STATE_ICO = {
  ok:    '<path d="M20 6 9 17l-5-5"/>',
  bad:   '<path d="M18 6 6 18M6 6l12 12"/>',
  warn:  '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
  muted: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
};
const _SELF_STATE_CLS = { ok: 'c-green', bad: 'c-red', warn: 'c-amber', muted: 'c-muted' };
const _SELF_STATE_RANK = { bad: 3, warn: 2, ok: 1, muted: 0 };
const _SELF_STATE_LABEL = { ok: 'Healthy', warn: 'Check', bad: 'Degraded', muted: 'Not in use' };

function _selfStateIco(state) {
  const p = _SELF_STATE_ICO[state] || _SELF_STATE_ICO.warn;
  const cls = _SELF_STATE_CLS[state] || 'c-amber';
  return `<span class="${cls} rt-ico"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14">${p}</svg></span>`;
}
function _selfInfoRow(label, value, note, state) {
  return `<tr><td class="c-muted-padded">${escHtml(label)}</td><td>${_selfStateIco(state)} <strong>${escHtml(value)}</strong>${note ? ` <span class="hint">— ${escHtml(note)}</span>` : ''}</td></tr>`;
}

// Whether the state actually lives in a database (where the DR archive's
// logical-store export is the ONLY copy) rather than in DATA_DIR files.
function _selfDbBackend(s) { return ((s || {}).runtime || {}).storage_backend || ''; }

// Shared by the "Serving & runtime" card and the readiness table so the two
// can never disagree about whether the scheduler is alive.
function _selfSchedulerState(rt) {
  if (rt.scheduler_configured && rt.scheduler_running) {
    return { value: 'Running', state: 'ok',
             note: rt.scheduler_last_beat_s != null
               ? `heartbeat ${rt.scheduler_last_beat_s}s ago; request path skips the cadence`
               : 'out-of-band process owns the maintenance cadence' };
  }
  if (rt.scheduler_configured) {
    return { value: 'Configured — no heartbeat', state: 'bad',
             note: 'flag is set but no scheduler process is reporting — start/enable remotepower-scheduler' };
  }
  return { value: 'Off', state: 'warn',
           note: 'the maintenance cadence runs inside each request' };
}

// The co-located sidecars, as row descriptors. Rendered BOTH as the
// "Distributed subsystems" table and as rows of the readiness table.
function _selfSidecarRows(s) {
  const sub = s.subsystems || {};
  const rows = [];
  const fleet = (label, b, offlineNote) => {
    if (!b || !b.total) { rows.push({ label, state: 'muted', status: 'None configured', detail: '' }); return; }
    rows.push({ label,
                state: b.online >= b.total ? 'ok' : (b.online > 0 ? 'warn' : 'bad'),
                status: `${b.online} online / ${b.total} total`,
                detail: b.online < b.total ? offlineNote : '' });
  };
  fleet('Relay satellites', sub.satellites && sub.satellites.relays, 'some relayed >5 min ago');
  fleet('Scan workers', sub.satellites && sub.satellites.scanners, 'some relayed >5 min ago');
  const push = sub.push || {};
  if (!push.enabled) {
    rows.push({ label: 'Agent push daemon', state: 'muted', status: 'Off',
                detail: 'the opt-in wake-nudge channel is disabled' });
  } else if (push.reachable) {
    rows.push({ label: 'Agent push daemon', state: 'ok', status: 'Running',
                detail: `accepting connections on port ${push.port}` });
  } else {
    rows.push({ label: 'Agent push daemon', state: 'bad', status: 'Enabled — unreachable',
                detail: `nothing listening on port ${push.port} — check systemctl status remotepower-push` });
  }
  // Syslog / flow receivers are INFORMATIONAL: optional, and they may legitimately
  // run on another host, so "not detected locally" is never a fault here.
  const sy = sub.syslog || {};
  const syAgo = sy.last_ingest ? `last intake ${_selfFmtAgo(sy.last_ingest)}` : 'no intake recorded';
  // v6.4.3: `unit === 'active'` only says systemd started the process. A
  // receiver that is running with ZERO mapped sources is not healthy — and it
  // is the exact signature of the storage-import bug fixed this release, where
  // the daemon could not reach the app's storage layer, read an empty token map
  // and dropped every packet while this card said Running. Report what it is
  // DOING, not that it exists.
  const syslogRow = sy.unit === 'active'
    ? (sy.sources
        ? { label: 'Syslog receiver', state: sy.last_ingest ? 'ok' : 'warn',
            status: sy.last_ingest ? 'Running' : 'Running — nothing received yet',
            detail: `${sy.sources} source(s) · ${syAgo}` }
        : { label: 'Syslog receiver', state: 'warn',
            status: 'Running — no sources mapped',
            detail: 'the daemon is up but its source map is empty, so every '
                  + 'packet is dropped. Enrol a device with a kind=syslog '
                  + 'inbound token; if one exists, check the daemon log for a '
                  + '"storage backend detection failed" warning.' })
    : (sy.sources
      ? { label: 'Syslog receiver', state: 'muted', status: 'Not detected locally',
          detail: `${sy.sources} source(s) enrolled · ${syAgo} — the receiver may run on another host` }
      : { label: 'Syslog receiver', state: 'muted', status: 'Not in use',
          detail: 'optional agentless intake — see syslog.md' });
  rows.push(syslogRow);
  const fl = sub.flow || {};
  const flAgo = fl.last_ingest ? `last export ${_selfFmtAgo(fl.last_ingest)}` : 'no export recorded';
  const flowRow = fl.unit === 'active'
    ? (fl.sources
        ? { label: 'Flow receiver', state: fl.last_ingest ? 'ok' : 'warn',
            status: fl.last_ingest ? 'Running' : 'Running — nothing received yet',
            detail: `${fl.sources} exporter(s) · ${flAgo}` }
        : { label: 'Flow receiver', state: 'warn',
            status: 'Running — no exporters mapped',
            detail: 'the daemon is up but its exporter map is empty, so every '
                  + 'flow is dropped. Enrol the exporter with a kind=flow '
                  + 'inbound token; if one exists, check the daemon log for a '
                  + '"storage backend detection failed" warning.' })
    : (fl.sources
      ? { label: 'Flow receiver', state: 'muted', status: 'Not detected locally',
          detail: `${fl.sources} exporter(s) enrolled · ${flAgo} — may run on another host` }
      : { label: 'Flow receiver', state: 'muted', status: 'Not in use',
          detail: 'optional agentless NetFlow/IPFIX — see flow.md' });
  rows.push(flowRow);
  // KMIP is reported only when enabled — and unlike syslog/flow its outage stops
  // encrypted volumes mounting, so "enabled but not running" IS a fault.
  const km = sub.kmip || {};
  if (km.unit || km.clients != null) {
    const pki = (km.pki_expires_days == null || km.pki_expires_days > 30)
      ? '' : ` · certificate expires in ${km.pki_expires_days} day${km.pki_expires_days === 1 ? '' : 's'}`;
    const det = `${km.clients || 0} client(s) · ${km.keys || 0} key(s)${pki}`;
    if (km.unit === 'active') {
      rows.push({ label: 'KMIP key server', state: pki ? 'warn' : 'ok',
                  status: 'Running', detail: det });
    } else {
      rows.push({ label: 'KMIP key server', state: 'bad', status: 'Enabled — not detected locally',
                  detail: `${det} — appliances cannot fetch keys while it is down` });
    }
  }
  return rows;
}

// The control plane itself: storage, request tier, scheduler, the maintenance
// sweeps, the recurring jobs and the DR archive. None of these has a webhook
// event (only server_disk_low/_ok does), so this table is where a wedged sweep
// or a hollow backup becomes visible at all.
function _selfControlPlaneRows(s) {
  const rt = s.runtime || {};
  const rows = [];
  const dd = s.data_dir || {};
  const sb = s.storage_backend || {};
  const beName = ({ postgres: 'PostgreSQL', sqlite: 'SQLite', json: 'JSON files' })[rt.storage_backend]
                 || (rt.storage_backend || 'unknown');
  if (dd.error) {
    rows.push({ label: 'Storage', state: 'bad', status: 'Unreadable',
                detail: `${beName} — ${dd.error}` });
  } else if (sb.last_integrity && sb.last_integrity !== 'ok') {
    rows.push({ label: 'Storage', state: 'bad', status: 'Integrity check failed',
                detail: `${beName} — last check reported "${sb.last_integrity}"` });
  } else if (rt.storage_backend === 'postgres' || rt.storage_backend === 'sqlite') {
    rows.push({ label: 'Storage', state: 'ok', status: beName, detail: 'readable' });
  } else {
    rows.push({ label: 'Storage', state: 'warn', status: beName,
                detail: rt.storage_backend === 'json'
                  ? 'dev / very small fleets only'
                  : 'the backend did not report itself' });
  }
  rows.push(rt.server_tier === 'wsgi'
    ? { label: 'Request tier', state: 'ok', status: 'WSGI · gunicorn + Flask', detail: 'persistent worker pool' }
    : { label: 'Request tier', state: 'warn', status: rt.server_tier || 'unknown',
        detail: 'not being served through wsgi.py' });
  const sch = _selfSchedulerState(rt);
  rows.push({ label: 'Maintenance scheduler', state: sch.state, status: sch.value, detail: sch.note });
  const obs = _selfObsLast;
  if (!obs) {
    rows.push({ label: 'Maintenance sweeps', state: 'muted', status: 'Not available',
                detail: 'sweep health is admin-only' });
  } else if (obs.failing) {
    rows.push({ label: 'Maintenance sweeps', state: 'bad',
                status: `${obs.failing} of ${obs.tracked} failing`,
                detail: 'a failing sweep silently takes its feature down — no alert event fires for it' });
  } else {
    rows.push({ label: 'Maintenance sweeps', state: 'ok',
                status: `${obs.tracked} tracked, none failing`, detail: '' });
  }
  const jobs = s.cadence_jobs || {};
  const jobKeys = Object.keys(jobs).filter(k => k !== 'error' && jobs[k] && typeof jobs[k] === 'object');
  const stale = jobKeys.filter(k => jobs[k].stale);
  if (jobs.error || !jobKeys.length) {
    rows.push({ label: 'Recurring jobs', state: 'muted', status: 'Not reported',
                detail: jobs.error ? String(jobs.error) : '' });
  } else if (stale.length) {
    rows.push({ label: 'Recurring jobs', state: 'bad', status: `${stale.length} wedged`,
                detail: `${stale.join(', ')} — last run older than 3× the interval` });
  } else {
    rows.push({ label: 'Recurring jobs', state: 'ok', status: 'On cadence',
                detail: `${jobKeys.length} tracked` });
  }
  rows.push(_selfBackupReadinessRow(s));
  return rows;
}

// v6.4.2: the DR archive as a readiness row. The case that matters is a
// database backend whose archive carries ZERO logical stores — the tar opens
// and looks fine, and restoring it produces an empty install.
function _selfBackupReadinessRow(s) {
  const bk = s.backup || {};
  const label = 'Backup & DR';
  if (!bk.last_run) {
    return { label, state: 'warn', status: 'Never run',
             detail: 'no DR archive has been written yet' };
  }
  if (bk.stores === 0 && _selfDbBackend(s) === 'postgres') {
    return { label, state: 'bad', status: 'Last archive is hollow',
             detail: 'it carries no logical stores, and on PostgreSQL those ARE the state — a restore would produce an empty install' };
  }
  if (bk.rpo_breached) {
    return { label, state: 'bad', status: 'RPO breached',
             detail: `last archive ${bk.hours_since_last_backup != null ? bk.hours_since_last_backup + 'h' : 'unknown'} ago, target ${bk.rpo_hours}h` };
  }
  if (bk.last_drill_ok === false) {
    return { label, state: 'bad', status: 'Last restore drill failed',
             detail: `${_selfFmtAgo(bk.last_drill_at)}${bk.last_drill_file ? ' · ' + bk.last_drill_file : ''} — run "Verify restorability now" for the reason` };
  }
  if (bk.stores === 0 && _selfDbBackend(s) === 'sqlite') {
    return { label, state: 'warn', status: 'Database image only',
             detail: 'the archive carries no logical stores — it can only be restored onto SQLite' };
  }
  return { label, state: 'ok', status: `Last run ${_selfFmtAgo(bk.last_run)}`,
           detail: `${bk.stores != null ? bk.stores + ' store(s) · ' : ''}${bk.encrypted ? 'encrypted' : 'plaintext'}` };
}

// Populated by loadSelfStatus() / _loadSelfObs(); the readiness table is
// re-rendered whenever either lands, in whichever order they arrive.
let _selfStatusLast = null;
let _selfObsLast = null;

function _selfReadinessRows() {
  const s = _selfStatusLast;
  if (!s) return [];
  return _selfControlPlaneRows(s).concat(_selfSidecarRows(s));
}

function _renderSelfReadiness() {
  const tb = document.getElementById('self-readiness-rows');
  if (!tb) return;
  tableCtl.wireSortOnly('self-readiness-thead', 'self_readiness', _renderSelfReadiness);
  // Degraded first by default; the user's own sort (if any) wins on top.
  const rows = _selfReadinessRows()
    .sort((a, b) => (_SELF_STATE_RANK[b.state] || 0) - (_SELF_STATE_RANK[a.state] || 0));
  const sorted = tableCtl.sortRows('self_readiness', rows, r => ({
    subsystem: r.label,
    state: _SELF_STATE_RANK[r.state] || 0,
    status: r.status,
    detail: r.detail,
  }));
  tb.innerHTML = sorted.map(r =>
    `<tr><td>${escHtml(r.label)}</td>`
    + `<td>${_selfStateIco(r.state)} <span class="${_SELF_STATE_CLS[r.state] || ''}">${escHtml(_SELF_STATE_LABEL[r.state] || r.state)}</span></td>`
    + `<td><strong>${escHtml(r.status)}</strong></td>`
    + `<td class="hint">${escHtml(r.detail || '')}</td></tr>`).join('');
  const sum = document.getElementById('self-readiness-summary');
  if (!sum) return;
  const bad = rows.filter(r => r.state === 'bad').length;
  const warn = rows.filter(r => r.state === 'warn').length;
  sum.innerHTML = `${rows.length} subsystem${rows.length === 1 ? '' : 's'} · `
    + `<span class="${bad ? 'c-red' : 'c-green'}">${bad} degraded</span> · `
    + `<span class="${warn ? 'c-amber' : 'c-muted'}">${warn} needing a look</span>`;
}

async function _loadSelfObs() {
  const el = document.getElementById('self-obs-body');
  if (!el) return;
  const d = await api('GET', '/self/observability').catch(() => null);
  if (!d || d.error) {
    _selfObsLast = null; _renderSelfReadiness();
    el.innerHTML = '<div class="c-muted">Unavailable.</div>'; return;
  }
  _selfObsLast = d;
  _renderSelfReadiness();
  const rows = d.sweeps || [];
  if (!rows.length) {
    el.innerHTML = '<div class="c-muted">No sweep activity recorded yet — it accumulates over the next maintenance cycles.</div>';
    return;
  }
  const trs = rows.map(r => {
    const status = r.failing ? '<span class="c-red">● FAILING</span>'
      : (r.last_ok ? '<span class="c-green">● OK</span>' : '<span class="c-muted">● never run</span>');
    return `<tr><td class="ff-mono fs-12">${escHtml(r.name)}</td><td>${status}</td>`
      + `<td class="hint">${r.last_ok ? _selfFmtAgo(r.last_ok) : '—'}</td>`
      + `<td class="hint">${r.err_count || 0}</td>`
      + `<td class="c-red fs-12">${r.failing ? escHtml((r.err || '').slice(0, 90)) : ''}</td></tr>`;
  }).join('');
  const errs = (d.errors || []).slice(-10).reverse().map(e =>
    `<div class="fs-12"><span class="hint">${_selfFmtAgo(e.ts)}</span> <span class="ff-mono">${escHtml(e.ctx)}</span> — <span class="c-red">${escHtml((e.err || '').slice(0, 120))}</span></div>`).join('');
  el.innerHTML =
    `<div class="hint mb-8">${d.tracked} sweeps tracked · <span class="${d.failing ? 'c-red' : 'c-green'}">${d.failing} failing</span></div>`
    + `<div class="scrollable-table-wrap audit-scroll"><table><thead><tr><th>Sweep</th><th>Status</th><th>Last OK</th><th>Errors</th><th>Last error</th></tr></thead><tbody>${trs}</tbody></table></div>`
    + (errs ? `<div class="section-title mt-16">Recent internal errors</div><div class="scroll-cap">${errs}</div>` : '');
}

// v6.3.1: detection self-test — prove the alert detection→routing chain is wired.
const _DS_LEVEL = { critical: 'c-red', warning: 'c-warning', info: 'c-muted' };
const _DS_STATUS = {
  ok: '<span class="c-green">● reaches a human</span>',
  silent: '<span class="c-red">● SILENT — reaches nobody</span>',
  silent_by_default: '<span class="c-muted">● quiet by default</span>',
  webhook_no_destination: '<span class="c-warning">● no destination</span>',
};
async function loadDetectionSelftest() {
  const el = document.getElementById('detection-selftest-body');
  if (!el) return;
  el.innerHTML = '<div class="c-muted">Running…</div>';
  const d = await api('GET', '/detection-selftest').catch(() => null);
  if (!d || d.error) { el.innerHTML = '<div class="c-muted">Unavailable (admin only).</div>'; return; }
  const s = d.summary || {};
  const issues = d.issues || [];
  const issuesHtml = issues.length
    ? '<div class="section-title mt-12">Issues</div>' + issues.map(i =>
        `<div class="fs-12 mb-4"><span class="${_DS_LEVEL[i.level] || 'c-muted'}">●</span> `
        + `<span class="${_DS_LEVEL[i.level] || ''}">${escHtml(i.level.toUpperCase())}</span> — ${escHtml(i.message)}</div>`).join('')
    : '<div class="c-green fs-14 mt-8">● Every alertable event type routes to a human. No silent gaps.</div>';
  const rows = (d.kinds || []).slice()
    .sort((a, b) => (a.reachable === b.reachable) ? 0 : (a.reachable ? 1 : -1))
    .map(k => {
      const cols = k.routes || {};
      const on = c => cols[c] ? '<span class="c-green">✓</span>' : '<span class="c-muted">·</span>';
      return `<tr><td>${escHtml(k.label)}</td><td>${_DS_STATUS[k.status] || escHtml(k.status)}</td>`
        + `<td class="ta-center">${on('alerts')}</td><td class="ta-center">${on('needs_attention')}</td>`
        + `<td class="ta-center">${on('webhook')}</td><td class="hint fs-12">${k.event_count}</td></tr>`;
    }).join('');
  const deliv = d.delivery || {};
  el.innerHTML =
    `<div class="fs-12 mb-8">${s.total_kinds} alert types · `
    + `<span class="${s.silent ? 'c-red' : 'c-green'}">${s.silent || 0} silent</span> · `
    + `${s.webhook_no_destination || 0} no-destination · ${s.ok || 0} ok &nbsp; `
    + (deliv.sandbox_mode ? '<span class="c-red">sandbox mode ON</span> · ' : '')
    + `<span class="${deliv.external_configured ? 'c-green' : 'c-muted'}">external delivery ${deliv.external_configured ? 'configured' : 'off'}</span></div>`
    + issuesHtml
    + '<div class="scrollable-table-wrap audit-scroll mt-12"><table><thead><tr><th>Alert type</th><th>Reaches</th><th>Inbox</th><th>Attention</th><th>Webhook</th><th>Events</th></tr></thead><tbody>'
    + rows + '</tbody></table></div>';
}

// v6.4.0: render the frontend error beacon's ring (collected since v5.4.1 with
// no UI consumer — the "for Server Status" display it was built for). Admin-only
// on the server; the card stays hidden when the list isn't readable.
async function _loadClientErrors() {
  const card = document.getElementById('client-errors-card');
  const body = document.getElementById('client-errors-body');
  if (!card || !body) return;
  let r = null;
  try { r = await api('GET', '/client-error'); } catch (e) { r = null; }
  if (!r || !Array.isArray(r.errors)) { card.classList.add('d-none'); return; }
  card.classList.remove('d-none');
  if (!r.errors.length) {
    body.innerHTML = '<div class="empty-state">No client-side errors reported. Quiet console, happy fleet.</div>';
    return;
  }
  // Group by error CLASS (message + source + line): the ring stores every
  // occurrence, so one hot bug would otherwise render as 30 identical rows.
  // Newest occurrence carries the shown time/page/IP; ×N is the real signal.
  const groups = new Map();
  r.errors.forEach(e => {   // list arrives newest-first — first hit wins
    const key = `${e.message}|${e.source}|${e.line}`;
    const g = groups.get(key);
    if (g) g.count++;
    else groups.set(key, { ...e, count: 1 });
  });
  body.innerHTML = '<div class="scrollable-table-wrap audit-scroll"><table class="data-table"><thead><tr><th>Last seen</th><th>Count</th><th>Message</th><th>Source</th><th>Page</th><th>From</th></tr></thead><tbody>'
    + [...groups.values()].map(e => `<tr><td class="hint">${e.ts ? _fmtAbsTs(e.ts) : '—'}</td><td>${e.count > 1 ? `<span class="fw-600">×${e.count}</span>` : '1'}</td><td title="${escAttr(e.stack || '')}">${escHtml(e.message || '—')}</td><td class="ff-mono fs-11">${escHtml((e.source || '').split('/').pop() || '—')}${e.line ? ':' + e.line : ''}</td><td class="hint">${escHtml((e.page || '').replace(/^https?:\/\/[^/]+/, '') || '—')}</td><td class="ff-mono fs-11">${escHtml(e.ip || '')}${e.country_code ? ` <span class="hint">(${escHtml(e.country_code)})</span>` : ''}</td></tr>`).join('')
    + '</tbody></table></div>';
}
async function clearClientErrors() {
  // Deliberately confirm-then-clear, NOT undo-instead-of-confirm (the v6.3.0
  // house rule): a cleared error ring is gone — there is nothing to restore
  // an Undo from, and a fake Undo would be worse than a dialog.
  if (!await uiConfirm({
        title: 'Clear client-side errors',
        message: 'Clear the reported browser-error ring? After a fix ships, the list refilling (or staying empty) is the verification.',
        confirmText: 'Clear' })) return;
  const r = await api('DELETE', '/client-error');
  if (r && r.ok) { toast(`Cleared ${r.cleared} entr${r.cleared === 1 ? 'y' : 'ies'}`, 'success'); _loadClientErrors(); }
  else toast((r && r.error) || 'Failed', 'error');
}
// v6.4.2: when this version started running, and the last few transitions.
//
// RemotePower tracks every package upgrade on every managed device and kept no
// history of its own version — so "did we change anything?", the first question
// asked when alert volume triples or heartbeat p95 doubles, was unanswerable
// in-app about the one host RemotePower manages least. The Timeline and the
// metric charts now carry a `server_upgraded` marker; this is the same fact
// where an operator is already looking at the server.
function _versionSinceHtml(s) {
  return s.version_since
    ? ` <span class="hint">since ${escHtml(_fmtAbsTs(s.version_since))}</span>`
    : '';
}

function _versionHistoryRow(s) {
  const h = (s.version_history || []).filter(e => e && e.from);
  if (!h.length) return '';
  const rows = h.slice(-5).reverse().map(e =>
    `${escHtml(e.from)} → ${escHtml(e.to)} <span class="hint">${escHtml(_fmtAbsTs(e.at))}</span>`
  ).join('<br>');
  return `<tr><td class="c-muted-padded">Upgrade history</td><td class="fs-12">${rows}</td></tr>`;
}

async function loadSelfStatus() {
  const body = document.getElementById('self-status-body');
  body.innerHTML = _skeletonBlock();
  _loadSelfObs();
  _loadClientErrors();
  // v6.4.2: /version rides along — it carries privileged_mode/privileged_help,
  // which is what explains an unavailable in-app restart on this page.
  const [s, ver] = await Promise.all([
    api('GET', '/self/status'),
    api('GET', '/version').catch(() => null),
  ]);
  if (!s || s.error) {
    body.innerHTML = '<div class="c-red">Failed to load: ' + escHtml(s?.error || 'unknown') + '</div>';
    return;
  }
  _selfStatusLast = s;
  // Devices freshness card
  const dev = s.devices || {};
  const offlineSev = dev.offline > 0 ? 'var(--red)' : 'var(--green)';
  // Webhook delivery card
  const w24 = (s.webhooks || {}).last_24h;
  const w7d = (s.webhooks || {}).last_7d;
  const _whHtml = w => {
    if (!w) return '<span class="c-muted">no log entries</span>';
    if (w.attempts === 0) {
      // v3.2.0 fix: distinguish "no deliveries attempted" (every event was
      // suppressed/filtered/disabled — fine!) from "deliveries failed".
      return `<span class="c-muted">no deliveries</span>` +
        (w.skipped ? ` <span class="hint">(${w.skipped} skipped — disabled/maintenance/filtered)</span>` : '');
    }
    const pct = (w.rate * 100).toFixed(1);
    const pctCls = w.rate >= 0.95 ? 'c-green' : w.rate >= 0.8 ? 'c-amber' : 'c-red';
    return `<strong>${w.success}</strong> / ${w.attempts} <span class="${pctCls}">(${pct}%)</span>` +
      (w.skipped ? ` <span class="hint">+${w.skipped} skipped</span>` : '');
  };
  // Disk usage
  const dd = s.data_dir || {};
  const diskPct = (dd.fs_free_bytes && dd.fs_total_bytes)
    ? Math.round((1 - dd.fs_free_bytes / dd.fs_total_bytes) * 100) : null;
  const bigFiles = (dd.big_files || []).map(f =>
    `<div class="isl-712">
       <code>${escHtml(f.name)}</code><span class="c-muted">${_selfFmtBytes(f.bytes)}</span>
     </div>`).join('');
  // Backup state
  const bk = s.backup || {};
  // v3.2.0: performance snapshot
  const perf = s.performance || {};
  const la = perf.load_avg || {};
  const mem = perf.memory || {};
  const sess = perf.sessions || {};
  const healthOk = perf.health === 'ok';
  const healthPill = healthOk
    ? '<span class="sev-pill sev-success">healthy</span>'
    : `<span class="sev-pill sev-medium">${(perf.health_flags || []).length} warning(s)</span>`;
  const memBar = mem.used_pct != null
    ? `<div class="perf-bar" title="${mem.used_pct}% used"><div class="perf-bar-fill" data-pct="${mem.used_pct}"></div></div>`
    : '';
  const onlinePct = perf.devices_online_pct;
  const onlinePctText = onlinePct != null ? `${onlinePct}%` : '—';
  const flagsHtml = (perf.health_flags || []).length
    ? `<details class="mt-8"><summary class="c-muted">View ${perf.health_flags.length} reason(s)</summary><ul class="mt-4">${perf.health_flags.map(f => `<li>${escHtml(f)}</li>`).join('')}</ul></details>`
    : '';
  // v5.6.x: "Serving & runtime" — what is ACTUALLY serving this instance (storage
  // backend, request tier, out-of-band scheduler). Answers "am I really on WSGI /
  // Postgres / the scheduler?" at a glance. See docs/scaling.md.
  const rt = s.runtime || {};
  const _beMap = { postgres: ['PostgreSQL', 'shared DB — scales across app nodes', 'ok'], sqlite: ['SQLite', 'single-box embedded DB', 'ok'], json: ['JSON files', 'dev / very small fleets only', 'warn'] };
  const _tierMap = { wsgi: ['WSGI · gunicorn + Flask', 'persistent worker pool (the only server)', 'ok'], cgi: ['direct', 'bare api.py invocation, not through wsgi.py', 'warn'] };
  const be = _beMap[rt.storage_backend] || [rt.storage_backend || 'unknown', '', 'warn'];
  const tier = _tierMap[rt.server_tier] || [rt.server_tier || 'unknown', '', 'warn'];
  const sched = _selfSchedulerState(rt);
  const runtimeCard = `
    <div class="dash-card">
      <div class="section-title">Serving &amp; runtime</div>
      <table class="fs-13">
        ${_selfInfoRow('Storage backend', be[0], be[1], be[2])}
        ${_selfInfoRow('Request tier', tier[0], tier[1], tier[2])}
        ${_selfInfoRow('Out-of-band scheduler', sched.value, sched.note, sched.state)}
        ${_selfInfoRow('Per-request maintenance', rt.cadence_in_request ? 'Runs in each request' : 'Offloaded to scheduler', '', rt.cadence_in_request ? 'warn' : 'ok')}
      </table>
      <div class="hint mt-8">This is what's actually serving right now. To change it (persistent WSGI/SCGI app tier, PostgreSQL, out-of-band scheduler) see <a href="docs/scaling.md" class="c-accent">scaling.md</a> — env vars go in <code>/etc/remotepower/api.env</code>.</div>
    </div>`;
  // OTHER-2: co-located distributed subsystems (relay/scanner satellites, push
  // daemon). The scheduler is in the runtime card above. Row descriptors come
  // from _selfSidecarRows() so this card and the readiness table above it can
  // never disagree about a sidecar's state.
  const sub = s.subsystems || {};
  const subsystemsCard = `
    <div class="dash-card">
      <div class="section-title">Distributed subsystems</div>
      ${sub.error ? `<div class="c-red fs-12 mb-8">Subsystem probe failed: ${escHtml(String(sub.error))}</div>` : ''}
      <table class="fs-13">
        ${_selfSidecarRows(s).map(r => _selfInfoRow(r.label, r.status, r.detail, r.state)).join('')}
      </table>
      <div class="hint mt-8">Relays/scan workers extend reach into segmented networks; the push daemon wakes agents on demand; the syslog receiver takes agentless appliance logs. See <a href="docs/scaling.md" class="c-accent">scaling.md</a>, <a href="docs/push.md" class="c-accent">push.md</a> and <a href="docs/syslog.md" class="c-accent">syslog.md</a>.</div>
    </div>`;
  // OTHER-3: restart-the-stack runbook. RemotePower runs as an unprivileged
  // service so a live restart needs root on the host; surface the exact,
  // copy-pasteable systemctl command (scoped to the subsystems that are
  // actually running) rather than a privileged in-app endpoint.
  const _scannerSvc = (sub.satellites && sub.satellites.scanners && sub.satellites.scanners.total) ? ' remotepower-scanner' : '';
  const _pushSvc = (sub.push && sub.push.enabled) ? ' remotepower-push' : '';
  const _syslogSvc = (sub.syslog && sub.syslog.unit === 'active') ? ' remotepower-syslogd' : '';
  const _flowSvc = (sub.flow && sub.flow.unit === 'active') ? ' remotepower-flowd' : '';
  const _restartCmd = `sudo systemctl restart remotepower-wsgi remotepower-scheduler${_scannerSvc}${_pushSvc}${_syslogSvc}${_flowSvc}`;
  const restartAvail = _selfRestartAvailability(ver);
  const restartCard = `
    <div class="dash-card">
      <div class="section-title">Restart the stack</div>
      <div class="hint mb-8">RemotePower runs as an unprivileged service, so restarting it is a host action (needs root on the server). This cleanly restarts the app workers and the out-of-band scheduler${_scannerSvc ? ', the scan worker' : ''}${_pushSvc ? ', the push daemon' : ''} — workers cycle with no dropped requests behind nginx and agents reconnect on their own:</div>
      <div class="row-8-mb8"><code class="self-restart-cmd">${escHtml(_restartCmd)}</code><button class="btn-icon" data-action="copyText" data-arg="${escAttr(_restartCmd)}"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>Copy</button></div>
      ${restartAvail}
      <div class="hint">See <a href="docs/self-monitoring.md" class="c-accent">self-monitoring.md</a> and <a href="docs/scaling.md" class="c-accent">scaling.md</a>.</div>
    </div>`;
  // v6.4.2: one explicit row per control-plane subsystem. Of the 183 registered
  // events only server_disk_low/_ok concern the control plane — a wedged sweep,
  // a dead sidecar or a hollow DR archive fires nothing, so this table is the
  // only place they are visible.
  const readinessCard = `
    <div class="dash-card">
      <div class="section-title">Control-plane readiness</div>
      <p class="hint">Every part of RemotePower itself that can fail without paging anyone: storage, the request tier, the maintenance scheduler and its sweeps, the recurring jobs, the DR archive and each co-located sidecar. A degraded row here is a fault in the monitoring, not in the fleet. <a href="docs/self-monitoring.md" class="c-accent">Documentation</a></p>
      <div id="self-readiness-summary" class="fs-12 mb-8"></div>
      <div class="scrollable-table-wrap audit-scroll">
        <table class="fs-13">
          <thead id="self-readiness-thead"><tr>
            <th data-col="subsystem">Subsystem</th>
            <th data-col="state">State</th>
            <th data-col="status">Status</th>
            <th data-col="detail">Detail</th>
          </tr></thead>
          <tbody id="self-readiness-rows"></tbody>
        </table>
      </div>
    </div>`;
  body.innerHTML = readinessCard + runtimeCard + subsystemsCard + restartCard + `
    <div class="dash-card">
      <div class="section-title">Site health ${healthPill}</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Server version</td><td>${escHtml(s.server_version || '?')}${_versionSinceHtml(s)}</td></tr>
        ${_versionHistoryRow(s)}
        ${la['1m'] != null ? `<tr><td class="c-muted-padded">Load average</td><td>${la['1m'].toFixed(2)} · ${la['5m'].toFixed(2)} · ${la['15m'].toFixed(2)} <span class="c-muted">(1m · 5m · 15m)</span></td></tr>` : ''}
        ${mem.used_pct != null ? `<tr><td class="c-muted-padded">System memory</td><td>${mem.used_pct}% used · ${_selfFmtBytes((mem.total_kb - mem.available_kb)*1024)} of ${_selfFmtBytes(mem.total_kb*1024)} ${memBar}</td></tr>` : ''}
        ${s.process?.vmrss_kb ? `<tr><td class="c-muted-padded">Worker process RSS</td><td>${_selfFmtBytes(s.process.vmrss_kb*1024)}</td></tr>` : ''}
        ${sess.active != null ? `<tr><td class="c-muted-padded">Active sessions</td><td>${sess.active}</td></tr>` : ''}
        <tr><td class="c-muted-padded">Devices online</td><td>${onlinePctText}</td></tr>
        ${s.process?.pid ? `<tr><td class="c-muted-padded">PID</td><td>${s.process.pid}</td></tr>` : ''}
      </table>
      ${flagsHtml}
    </div>

    <div class="dash-card">
      <div class="section-title">Devices</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Monitored</td><td>${dev.monitored ?? '—'}</td></tr>
        <tr><td class="c-muted-padded">Currently offline</td><td><span class="isl-713" data-color="${offlineSev}">${dev.offline ?? '—'}</span></td></tr>
        <tr><td class="c-muted-padded">Freshest heartbeat</td><td>${_selfFmtAgo(dev.freshest_seen)}</td></tr>
        <tr><td class="c-muted-padded">Oldest heartbeat</td><td>${_selfFmtAgo(dev.oldest_seen)}</td></tr>
        <tr><td class="c-muted-padded">Online TTL</td><td>${dev.online_ttl_s ?? '—'}s</td></tr>
      </table>
    </div>

    <div class="dash-card">
      <div class="section-title">Webhook delivery — outbound</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Last 24h</td><td>${_whHtml(w24)}</td></tr>
        <tr><td class="c-muted-padded">Last 7 days</td><td>${_whHtml(w7d)}</td></tr>
        <tr><td class="c-muted-padded">Logged total</td><td>${(s.webhooks || {}).total_logged ?? '—'}</td></tr>
      </table>
    </div>

    ${(() => {
      // v3.2.0 follow-up: inbound webhooks + syslog hit log
      const iw = s.inbound_webhooks || {};
      const i24 = iw.last_24h, i7d = iw.last_7d;
      const _iwHtml = w => {
        if (!w) return '<span class="c-muted">no inbound hits yet</span>';
        const pct = (w.rate * 100).toFixed(1);
        const pctCls = w.rate >= 0.95 ? 'c-green' : w.rate >= 0.8 ? 'c-amber' : 'c-red';
        const kinds = w.by_kind || {};
        const kindsTxt = Object.keys(kinds).map(k => `${escHtml(k)}:${kinds[k]}`).join(' · ');
        return `<strong>${w.success}</strong> / ${w.attempts} <span class="${pctCls}">(${pct}%)</span>` +
               (kindsTxt ? ` <span class="hint">[${kindsTxt}]</span>` : '');
      };
      return `<div class="dash-card">
        <div class="section-title">Inbound webhooks &amp; syslog</div>
        <table class="fs-13">
          <tr><td class="c-muted-padded">Last 24h</td><td>${_iwHtml(i24)}</td></tr>
          <tr><td class="c-muted-padded">Last 7 days</td><td>${_iwHtml(i7d)}</td></tr>
          <tr><td class="c-muted-padded">Logged total</td><td>${iw.total_logged ?? '—'}</td></tr>
        </table>
      </div>`;
    })()}

    <div class="dash-card">
      <div class="section-title">Disk — <code>${escHtml(dd.path || '/var/lib/remotepower')}</code></div>
      <table class="isl-714">
        <tr><td class="c-muted-padded">RemotePower data</td><td>${_selfFmtBytes(dd.total_bytes)}</td></tr>
        ${diskPct != null ? `<tr><td class="c-muted-padded">Filesystem used</td><td>${diskPct}% (${_selfFmtBytes(dd.fs_total_bytes - dd.fs_free_bytes)} of ${_selfFmtBytes(dd.fs_total_bytes)})</td></tr>` : ''}
      </table>
      ${bigFiles ? `<details><summary class="isl-715">Largest files (>100KB)</summary><div class="mt-8">${bigFiles}</div></details>` : ''}
    </div>

    <div class="dash-card">
      <div class="section-title">Audit log</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Active entries</td><td>${(s.audit_log || {}).entries ?? '—'}</td></tr>
        <tr><td class="c-muted-padded">Retention</td><td>${(s.audit_log || {}).retention_days ?? '—'} days</td></tr>
        ${(s.audit_log || {}).archive_bytes ? `<tr><td class="c-muted-padded">Archive (gzip)</td><td>${_selfFmtBytes(s.audit_log.archive_bytes)}</td></tr>` : ''}
      </table>
    </div>

    <div class="dash-card">
      <div class="section-title">Backup</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Encryption</td><td>${bk.encryption_armed
          ? '<span class="patch-badge ok">AES-256-GCM at rest</span>'
          : `<span class="patch-badge warn">plaintext</span> <span class="hint">not encrypted</span>`}${
          bk.encryption_armed && bk.encryption_available === false
          ? ' <span class="c-red">— cryptography lib missing!</span>' : ''}</td></tr>
        ${(bk.plaintext_archives != null || bk.encrypted_archives != null) ? `
        <tr><td class="c-muted-padded">Archives</td><td>${bk.encrypted_archives || 0} encrypted, ${bk.plaintext_archives || 0} plaintext</td></tr>` : ''}
      </table>
      ${!bk.encryption_armed && bk.encryption_available !== false ? `
        <details class="mt-6 fs-12">
          <summary class="pointer c-accent">How do I turn on backup encryption?</summary>
          <div class="mt-6">
            <div class="mb-6">There are two parts. <strong>For ongoing scheduled backups</strong>, set the <code>RP_BACKUP_PASSPHRASE</code> environment variable on the process that runs RemotePower (it's read at backup time and never written to disk), then restart. Pick the one that matches your install:</div>
            <div class="mb-4"><strong>systemd</strong> (package / install.sh):</div>
            <pre class="ff-mono fs-11 scroll-cap">sudo systemctl edit remotepower-api        # or your fcgiwrap unit
# add under [Service]:
Environment=RP_BACKUP_PASSPHRASE=choose-a-strong-passphrase
sudo systemctl restart remotepower-api</pre>
            <div class="mb-4 mt-6"><strong>Docker compose</strong>:</div>
            <pre class="ff-mono fs-11 scroll-cap">services:
  remotepower:
    environment:
      RP_BACKUP_PASSPHRASE: choose-a-strong-passphrase
# then:  docker compose up -d</pre>
            <div class="mt-6 c-muted">Keep the passphrase safe — without it, encrypted backups cannot be restored. <strong>Already have plaintext archives?</strong> Use the button below to convert them now (no env var or restart needed for that).</div>
          </div>
        </details>` : ''}
      ${(bk.plaintext_archives > 0 && bk.encryption_available !== false) ? `
        <button class="btn-icon mt-8" data-action="encryptExistingBackups" title="Encrypt the plaintext backup archives already on disk">${_icon('power', 14)} Encrypt existing backups (${bk.plaintext_archives})</button>
        <div class="hint mt-6">Encrypts archives on disk now with a passphrase you supply (never stored). For ongoing scheduled backups, set <code>RP_BACKUP_PASSPHRASE</code>.</div>` :
        (bk.encryption_available === false ? '<div class="hint mt-6">Install the <code>cryptography</code> library to enable backup encryption.</div>' : '')}
      ${bk.last_run ? `
        <table class="fs-13 mt-6">
          <tr><td class="c-muted-padded">Last run</td><td>${_selfFmtAgo(bk.last_run)} <span class="c-muted">(${escHtml(bk.triggered_by || 'scheduled')})</span></td></tr>
          <tr><td class="c-muted-padded">Last file</td><td><code class="fs-11">${escHtml(bk.last_file || '—')}</code>${bk.encrypted ? ' <span class="patch-badge ok">encrypted</span>' : ''}</td></tr>
          <tr><td class="c-muted-padded">Size</td><td>${_selfFmtBytes(bk.last_bytes)}</td></tr>
          ${_selfBackupContentsRow(s)}
          <tr><td class="c-muted-padded">Retention</td><td>${bk.retain_days ?? 14} days (last prune removed ${bk.pruned ?? 0})</td></tr>
          ${bk.last_drill_at ? `<tr><td class="c-muted-padded">Restore drill</td><td>${bk.last_drill_ok === false
            ? '<span class="patch-badge crit">failed</span>'
            : (bk.last_drill_ok ? '<span class="patch-badge ok">passed</span>' : '<span class="patch-badge warn">no result</span>')} ${_selfFmtAgo(bk.last_drill_at)}${
            bk.last_drill_seconds != null ? ` <span class="hint">· checked in ${bk.last_drill_seconds}s</span>` : ''}${
            bk.last_drill_file ? ` <code class="fs-11">${escHtml(bk.last_drill_file)}</code>` : ''}</td></tr>` : ''}
        </table>
        ${_selfHollowArchiveWarning(s)}
        <div class="mt-8"><button class="btn-icon" data-action="selfVerifyRestore" id="self-verify-restore-btn" title="Decrypt, decompress and inspect the newest archive — reports how much restorable state it actually carries. Nothing is written.">${_icon('fileSearch', 14)} Verify restorability now</button></div>
        <div id="self-verify-restore-result" class="fs-12 mt-6" role="status" aria-live="polite"></div>`
        : '<div class="c-muted-fs13 mt-6">No backup has run yet. The scheduled job runs once per 24h via the heartbeat hook; click "Run backup now" to trigger one immediately.</div>'}
      ${bk.rpo_hours ? `
        <table class="fs-13 mt-6">
          <tr><td class="c-muted-padded">RPO target</td><td>${bk.rpo_hours}h — last backup ${bk.hours_since_last_backup != null ? bk.hours_since_last_backup + 'h ago' : 'never'}
            ${bk.rpo_breached ? ' <span class="patch-badge crit">breached</span>' : ' <span class="patch-badge ok">met</span>'}</td></tr>
        </table>` : ''}
      ${bk.rto_hours ? `
        <table class="fs-13 mt-6">
          <tr><td class="c-muted-padded">RTO target</td><td>${bk.rto_hours}h${bk.last_test_restore_seconds != null
            ? ` — last "Test restore" checked in ${bk.last_test_restore_seconds}s ${_selfFmtAgo(bk.last_test_restore_at)} <span class="hint">(decrypt/decompress/structure check only — a lower bound, not a full restore)</span>`
            : ' — no "Test restore" run yet'}</td></tr>
        </table>` : ''}
    </div>

    ${_cadenceJobsCard(s.cadence_jobs)}

    ${_slowHandlersCard(s.slow_handlers)}

    <div class="dash-card">
      <div class="section-title">Fleet events</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Current log</td><td>${_selfFmtBytes((s.fleet_events || {}).bytes)}</td></tr>
        ${(s.fleet_events || {}).archive_bytes ? `<tr><td class="c-muted-padded">Archive (gzip)</td><td>${_selfFmtBytes(s.fleet_events.archive_bytes)}</td></tr>` : ''}
      </table>
    </div>
  `;
  _renderSelfReadiness();
}

// v6.4.2: the in-app "Restart server" button is simply HIDDEN when the
// privileged helper cannot run, so an operator hunting for it found nothing and
// no reason. /version now reports WHY: 'blocked' is the shipped hardened unit
// (NoNewPrivileges=true), where no sudoers drop-in can ever help — say that
// instead of quietly omitting the control.
function _selfRestartAvailability(ver) {
  const mode = ver && ver.privileged_mode;
  if (mode === 'blocked') {
    return '<div class="hint mt-8"><span class="c-amber">In-app restart is unavailable on this install.</span> '
      + escHtml(ver.privileged_help || '')
      + ' <a href="docs/upgrading.md" class="c-accent">upgrading.md</a></div>';
  }
  if (mode === 'absent') {
    return '<div class="hint mt-8">In-app restart is not set up — the privileged restart helper '
      + '(<code>packaging/remotepower-server-restart.sh</code>) is not installed, so the command above is the way in. '
      + 'See <a href="docs/upgrading.md" class="c-accent">upgrading.md</a>.</div>';
  }
  if (ver && ver.restart_available) {
    return '<div class="hint mt-8">This install can also restart the app server in place from '
      + 'Settings → Install → Restart server'
      + (mode === 'spool' ? ' (performed by the privileged path unit)' : '') + '.</div>';
  }
  return '';
}

// v6.4.2: what the last DR archive actually CARRIES. `stores` is the number of
// logical documents the export wrote into the tar; on a database backend that
// is the entire state, and 0 there means the archive is hollow — it opens, it
// looks the right size, and restoring it produces an empty install.
function _selfBackupContentsRow(s) {
  const bk = s.backup || {};
  if (bk.stores == null) return '';
  const be = _selfDbBackend(s);
  const n = `${bk.stores} logical store${bk.stores === 1 ? '' : 's'}`;
  if (bk.stores === 0 && be === 'postgres') {
    return `<tr><td class="c-muted-padded">Archive contents</td><td><span class="patch-badge crit">hollow</span> <span class="c-red">${n}</span></td></tr>`;
  }
  if (bk.stores === 0 && be === 'sqlite') {
    return `<tr><td class="c-muted-padded">Archive contents</td><td><span class="patch-badge warn">database image only</span> <span class="hint">${n} — restorable onto SQLite only</span></td></tr>`;
  }
  const note = be === 'json'
    ? 'plus the data directory itself'
    : 'exported from the database — restorable onto any backend';
  return `<tr><td class="c-muted-padded">Archive contents</td><td>${n} <span class="hint">— ${note}</span></td></tr>`;
}

function _selfHollowArchiveWarning(s) {
  const bk = s.backup || {};
  if (bk.stores !== 0 || _selfDbBackend(s) !== 'postgres') return '';
  return '<div class="c-red fs-12 mt-6">The last archive carried no logical stores. On PostgreSQL nothing else in the tarball holds the state, '
    + 'so a restore from it would produce an empty install — treat this as having no backup. Check the backup sweep under '
    + '"Internal health — maintenance sweeps" for the export error, then run a backup again.</div>';
}

// v6.4.2: run the same decrypt→decompress→structure check the scheduled drill
// runs, and show its verdict verbatim — the hollow-archive case has its own
// specific message, which a generic "restore test failed" would have hidden.
async function selfVerifyRestore() {
  const el = document.getElementById('self-verify-restore-result');
  if (el) { el.className = 'fs-12 mt-6 c-muted'; el.textContent = 'Opening the newest archive…'; }
  const r = await api('POST', '/backup/test-restore').catch(() => null);
  const ok = !!(r && r.ok);
  if (el) {
    el.className = 'fs-12 mt-6 ' + (ok ? 'c-green' : 'c-red');
    // textContent, not innerHTML: the message embeds a server-side file name.
    el.textContent = ok
      ? (r.message || 'Restorable.')
      : ((r && (r.error || r.message)) || 'Restore test failed.');
  }
  toast(ok ? 'Backup restore test passed' : 'Restore test failed', ok ? 'success' : 'error');
}

// v4.3.0: recent slow requests (handlers past the slow threshold). Tells you
// which endpoint is slow on the real fleet without external profiling.
function _slowHandlersCard(sh) {
  if (!sh || sh.error || !sh.count) return '';
  const rows = (sh.recent || []).map(r => {
    const cls = r.ms >= sh.threshold_ms * 3 ? 'c-red' : 'c-amber';
    return `<tr><td class="c-muted-padded">${escHtml(r.method || '')} <code class="fs-11">${escHtml(r.path || '')}</code></td>`
      + `<td class="${cls}">${r.ms} ms</td><td class="hint">${_selfFmtAgo(r.ts)}</td></tr>`;
  }).join('');
  return `<div class="dash-card">
      <div class="section-title">Slow requests <span class="hint">(> ${sh.threshold_ms} ms; last ${sh.count})</span></div>
      <div class="scrollable-table-wrap audit-scroll"><table>${rows}</table></div>
    </div>`;
}

// v4.3.0: cadence-job staleness — a job that quietly stopped looks identical to
// one that simply isn't due, so surface last-ran + a stale flag.
function _cadenceJobsCard(jobs) {
  if (!jobs || jobs.error) return '';
  const labels = {
    kev_epss_refresh: 'KEV / EPSS refresh',
    monitors: 'Monitors',
    scheduled_scans: 'Scheduled scans',
  };
  const rows = Object.keys(labels).filter(k => jobs[k]).map(k => {
    const j = jobs[k];
    let state, cls;
    if (j.enabled === false)      { state = 'off';     cls = 'c-muted'; }
    else if (j.never_ran)         { state = 'not yet run'; cls = 'c-muted'; }
    else if (j.stale)             { state = `stale — last ran ${_selfFmtAgo(j.last_run)}`; cls = 'c-red'; }
    else                          { state = `ran ${_selfFmtAgo(j.last_run)}`; cls = 'c-green'; }
    const cnt = j.count ? ` <span class="hint">(${j.count})</span>` : '';
    return `<tr><td class="c-muted-padded">${escHtml(labels[k])}${cnt}</td><td class="${cls}">${escHtml(state)}</td></tr>`;
  }).join('');
  if (!rows) return '';
  // v6.4.2: the scheduler's job list grows every release (~30 rows now) — cap
  // it and scroll, like the self-test table below and the box-overflow rule.
  return `<div class="dash-card">
      <div class="section-title">Recurring jobs</div>
      <div class="scrollable-table-wrap audit-scroll"><table class="fs-13">${rows}</table></div>
    </div>`;
}
// v4.3.0: download the support diagnostics bundle (secrets scrubbed server-side).
// v5.0.0 (#U9): one-click health check with a green/red summary.
async function runSelfTest() {
  const box = document.getElementById('self-test-result');
  if (box) { box.classList.remove('d-none'); box.innerHTML = '<div class="c-muted">Running diagnostics…</div>'; }
  const data = await api('GET', '/self-test');
  if (!data || !Array.isArray(data.checks)) { if (box) box.innerHTML = '<div class="c-red">Diagnostics failed to run.</div>'; return; }
  const rows = data.checks.map(c =>
    `<tr><td>${c.ok ? '<span class="c-green">●</span>' : '<span class="c-red">●</span>'}</td>`
    + `<td class="fw-600">${escHtml(c.name)}</td><td class="hint">${escHtml(c.detail || '')}</td></tr>`).join('');
  box.innerHTML = `<div class="dash-card"><div class="section-title">${data.ok
    ? '<span class="c-green">● All checks passed</span>'
    : '<span class="c-red">● Some checks failed</span>'}</div>`
    // v6.4.1: was a bare <table> with no cap — one row per server
    // self-test check, and that list grows every release.
    + `<div class="scrollable-table-wrap audit-scroll">`
    + `<table class="fs-13">${rows}</table></div></div>`;
}

function downloadDiagnostics() {
  _downloadAuthed('/api/diagnostics', 'remotepower-diagnostics.json',
    'Diagnostics bundle downloaded');
}
