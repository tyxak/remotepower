// app-tuning.js — Monitoring → Tuning (v5.6.0). Surfaces the noisiest alerts
// from the fleet-event timeline and lets you silence them per (host + alert
// type). Buildless classic script; every symbol stays global like the rest of
// the client JS. Reads /api/alert-tuning (top-10 noisy pairs + sources, both
// derived from fleet_events) and writes /api/alert-mutes.

let _tuningData = null;

async function loadTuning() {
  const d = await api('GET', '/alert-tuning');
  if (!d || !d.ok) {
    ['tuning-noisy', 'tuning-sources', 'tuning-mutes'].forEach(id => {
      const el = document.getElementById(id);
      if (el) _errorState(el, loadTuning);
    });
    return;
  }
  _tuningData = d;
  _renderTuningNoisy(d.noisy || []);
  _renderTuningSources(d.sources || []);
  _renderTuningMutes(d.mutes || []);
}

function _renderTuningNoisy(rows) {
  const el = document.getElementById('tuning-noisy');
  if (!el) return;
  if (!rows.length) { el.innerHTML = '<div class="meta-sm-nm">No alert activity in this window — nothing to tune.</div>'; return; }
  el.innerHTML = rows.map(r => {
    const action = r.muted
      ? '<span class="patch-badge ok fs-11">silenced</span>'
      : `<button class="btn-icon cell-sm" data-action-btn="silenceNoisy" data-dev="${escAttr(r.device_id)}" data-name="${escAttr(r.device_name || '')}" data-event="${escAttr(r.event)}" title="Silence this alert from this host">${_icon('bellOff', 12)} Silence</button>`;
    return `<div class="row-6 ts-entry">
      <span class="fw-600">${escHtml(r.device_name || r.device_id)}</span>
      <span class="patch-badge">${escHtml(r.event)}</span>
      <span class="meta-sm-nm">${Number(r.count) || 0}×</span>
      <span class="ml-auto">${action}</span>
    </div>`;
  }).join('');
}

function _renderTuningSources(rows) {
  const el = document.getElementById('tuning-sources');
  if (!el) return;
  if (!rows.length) { el.innerHTML = '<div class="meta-sm-nm">No alert activity in this window.</div>'; return; }
  el.innerHTML = rows.map(r => `<div class="row-6 ts-entry">
    <span class="patch-badge">${escHtml(r.event)}</span>
    <span class="meta-sm-nm">${Number(r.count) || 0}× fleet-wide</span>
    <span class="ml-auto">${_tuningVerdict(r)}</span>
  </div>`).join('');
}

// v6.4.2: whether this noise is SAFE TO SILENCE.
//
// The page ranked purely on how loud an event was, which is the one number that
// does not answer its own question. 340 nic_errors that all auto-resolved in 90
// seconds and were never acknowledged is noise; 12 backup_stale that a human
// resolved by hand after six hours each is work. Both got the same Mute button
// and the loud one got sorted to the top. The resolution data existed one
// endpoint away, aggregated only per host; it is now joined per event.
//
// Deliberately a recommendation, not an automatic action — this is a judgement
// call about what the operator wants to be woken for, and the page's job is to
// inform it, not to make it.
function _tuningVerdict(r) {
  if (r.resolved == null || !r.resolved) {
    return '<span class="hint" title="No alert from this event has been resolved in this window, so there is nothing to judge it by yet">no resolution data</span>';
  }
  const auto = Number(r.auto_pct) || 0;
  const acked = Number(r.acked_pct) || 0;
  const mttr = Number(r.mttr_mean) || 0;
  const detail = `${r.resolved} resolved · ${auto}% auto · ${acked}% acknowledged · mean time to resolve ${_fmtDuration(mttr)}`;
  // "Nobody ever acknowledged it and it always cleared itself" is the shape of
  // noise. The MTTR bound matters: an event that auto-resolves after six hours
  // is a condition that persisted, not a blip.
  if (auto >= 90 && acked <= 10 && mttr < 900) {
    return `<span class="patch-badge fs-11" title="${escAttr(detail)}">likely noise — safe to silence</span>`;
  }
  if (auto <= 40 || acked >= 50) {
    return `<span class="patch-badge fs-11 c-amber" title="${escAttr(detail)}">people act on this</span>`;
  }
  return `<span class="hint" title="${escAttr(detail)}">${auto}% auto · ${acked}% acked</span>`;
}

function _renderTuningMutes(rows) {
  const el = document.getElementById('tuning-mutes');
  if (!el) return;
  if (!rows.length) { el.innerHTML = '<div class="meta-sm-nm">No active mutes. Silence a noisy alert above, or click Mute on any alert.</div>'; return; }
  // v6.1.2: a mute may be TIMED — show when it lapses, so a mute can't quietly
  // become "I stopped monitoring this months ago and forgot".
  const _until = m => {
    if (!m.expires_at) return '<span class="hint" title="Stays muted until you lift it">permanent</span>';
    const secs = m.expires_at - Math.floor(Date.now() / 1000);
    if (secs <= 0) return '<span class="hint">expiring…</span>';
    const h = Math.floor(secs / 3600), mins = Math.round((secs % 3600) / 60);
    const left = h >= 24 ? `${Math.floor(h / 24)}d ${h % 24}h` : (h >= 1 ? `${h}h ${mins}m` : `${mins}m`);
    return `<span class="patch-badge fs-11" title="Lapses on its own at ${escAttr(new Date(m.expires_at * 1000).toLocaleString())}">${escHtml(left)} left</span>`;
  };
  // v6.4.2: a mute row is EITHER an event mute or a per-container mute (the
  // Containers drawer's Mute button). Without this branch a container mute
  // rendered as an empty badge — present in the list, unreadable, and the only
  // place to lift it.
  const _what = m => m.container
    ? `<span class="patch-badge" title="Every alert about this container is silenced">container · ${escHtml(m.container)}</span>`
    : `<span class="patch-badge">${escHtml(m.event)}</span>`;
  el.innerHTML = rows.map(m => `<div class="row-6 ts-entry">
    <span class="fw-600">${escHtml(m.device_name || m.device_id)}</span>
    ${_what(m)}
    ${_until(m)}
    <span class="ml-auto"><button class="btn-icon cell-sm c-danger-outline" data-action="unmuteAlert" data-arg="${escAttr(m.id)}" title="Lift this mute — alerts resume">${_icon('bellOff', 12)} Un-silence</button></span>
  </div>`).join('');
}

async function silenceNoisy(btn) {
  const dev = btn.dataset.dev, event = btn.dataset.event;
  if (!dev || !event) return;
  // v6.3.1: undo instead of are-you-sure — the mute applies immediately and
  // the topbar arrow / Ctrl-Z lifts it again.
  const body = { device_id: dev, device_name: btn.dataset.name || '', event };
  const r = await api('POST', '/alert-mutes', body);
  if (r && r.ok) {
    loadTuning();
    let _muteId = r.id;
    const doUndo = async () => { const u = await api('DELETE', '/alert-mutes/' + encodeURIComponent(_muteId)); if (u?.ok) loadTuning(); };
    const doRedo = async () => { const u = await api('POST', '/alert-mutes', body); if (u?.ok) { _muteId = u.id; loadTuning(); } };
    pushUndoableAction(`Silence ${btn.dataset.name || dev} · ${event}`, doUndo, doRedo,
      'Silenced' + (r.resolved ? ` · ${r.resolved} open cleared` : ''));
  }
  else toast((r && r.error) || 'Failed', 'error');
}

async function unmuteAlert(id) {
  id = String(id);
  // v6.3.1: undo instead of are-you-sure — capture the mute so the topbar
  // arrow / Ctrl-Z can re-create it (a re-created mute gets a fresh id, so
  // the closures track the current one).
  const m = ((_tuningData && _tuningData.mutes) || []).find(x => String(x.id) === id);
  const r = await api('DELETE', '/alert-mutes/' + encodeURIComponent(id));
  if (r && r.ok) {
    loadTuning();
    if (m) {
      const reBody = m.container
        ? { device_id: m.device_id, container: m.container, device_name: m.device_name || '' }
        : { device_id: m.device_id, event: m.event, device_name: m.device_name || '' };
      if (m.expires_at) {
        const hrs = (m.expires_at - Date.now() / 1000) / 3600;
        if (hrs >= 0.25) reBody.hours = Math.min(8760, Math.round(hrs * 4) / 4);
      }
      let curId = null;
      const doUndo = async () => { const u = await api('POST', '/alert-mutes', reBody); if (u?.ok) { curId = u.id; loadTuning(); } };
      const doRedo = async () => { if (curId != null) { const u = await api('DELETE', '/alert-mutes/' + encodeURIComponent(curId)); if (u?.ok) loadTuning(); } };
      pushUndoableAction(`Unmute ${m.device_name || m.device_id} · ${m.container || m.event}`,
                         doUndo, doRedo, 'Mute lifted');
    } else {
      toast('Mute lifted', 'info');
    }
  }
  else toast((r && r.error) || 'Failed', 'error');
}
