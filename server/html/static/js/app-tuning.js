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
    <span class="ml-auto meta-sm-nm">${Number(r.count) || 0}× fleet-wide</span>
  </div>`).join('');
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
  el.innerHTML = rows.map(m => `<div class="row-6 ts-entry">
    <span class="fw-600">${escHtml(m.device_name || m.device_id)}</span>
    <span class="patch-badge">${escHtml(m.event)}</span>
    ${_until(m)}
    <span class="ml-auto"><button class="btn-icon cell-sm c-danger-outline" data-action="unmuteAlert" data-arg="${escAttr(m.id)}" title="Lift this mute — alerts resume">${_icon('bellOff', 12)} Un-silence</button></span>
  </div>`).join('');
}

async function silenceNoisy(btn) {
  const dev = btn.dataset.dev, event = btn.dataset.event;
  if (!dev || !event) return;
  if (!await uiConfirm('Silence ' + (btn.dataset.name || dev) + ' · ' + event + '? It stops alerting until you lift it here.')) return;
  const r = await api('POST', '/alert-mutes', { device_id: dev, device_name: btn.dataset.name || '', event });
  if (r && r.ok) { toast('Silenced' + (r.resolved ? ` · ${r.resolved} open cleared` : ''), 'success'); loadTuning(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function unmuteAlert(id) {
  id = String(id);
  if (!await uiConfirm('Lift this mute? Alerts of this type from this host will resume.')) return;
  const r = await api('DELETE', '/alert-mutes/' + encodeURIComponent(id));
  if (r && r.ok) { toast('Mute lifted', 'info'); loadTuning(); }
  else toast((r && r.error) || 'Failed', 'error');
}
