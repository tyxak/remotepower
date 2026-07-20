// Split out of app.js (v3.4.0 modularisation). Plain classic script —
// shares the global scope with app.js; loaded right after it in index.html.
// No bundler / no ES modules. Functions here are called from app.js and vice
// versa; page init is DOMContentLoaded-deferred so load order is not sensitive.

// ── Containers ───────────────────────────────────────────────────────────────
let _containersOverview = [];
// v1.11.4: id of the device whose detail modal is currently open. Used by
// the "Clear data" button to know which device's containers.json entry to
// wipe.
let _containersOpenDeviceId = null;

async function enterContainers() {
  await loadContainersOverview();
  // v3.3.4: image-update freshness for the agent-reported containers.
  loadImageUpdates();
  // v3.3.4: operator-uploaded compose stacks.
  loadComposeStacks();
  // v2.3.0: also pull Proxmox LXC containers (section self-hides if
  // Proxmox isn't configured).
  loadProxmoxLXC();
}

// ── v3.3.4: container image-update detection ───────────────────────────────
let _imageUpdates = [];

async function loadImageUpdates() {
  // Eager sort wire-up so the ↕ indicators show before data arrives.
  _registerImageUpdatesTable();
  const tbody = document.getElementById('image-updates-tbody');
  if (tbody) tbody.innerHTML = _skeletonRows(7);   // v6.2.2: skeleton, not bare text
  const data = await api('GET', '/image-updates');
  _imageUpdates = (data && data.images) || [];
  _renderImageUpdatesMeta(data && data.summary);
  renderImageUpdates();
}

function _renderImageUpdatesMeta(summary) {
  const el = document.getElementById('image-updates-meta');
  if (!el) return;
  if (!summary) { el.textContent = ''; return; }
  const bits = [];
  if (summary.updates_available) bits.push(`${summary.updates_available} update(s) available`);
  if (summary.unchecked) bits.push(`${summary.unchecked} not yet checked`);
  if (summary.local) bits.push(`${summary.local} local`);
  if (summary.ignored) bits.push(`${summary.ignored} ignored`);
  if (!summary.enabled) bits.push('detection disabled');
  if (summary.last_full_scan) bits.push(`last scan ${new Date(summary.last_full_scan * 1000).toLocaleString()}`);
  el.textContent = bits.length ? `— ${bits.join(' · ')}` : '';
}

let _imageUpdatesRegistered = false;
function _registerImageUpdatesTable() {
  if (_imageUpdatesRegistered) return;
  _imageUpdatesRegistered = true;
  tableCtl.register({
    name: 'image-updates',
    tbody: 'image-updates-tbody',
    filterInput: 'image-updates-search',
    sortHeaders: 'image-updates-thead',
    colspan: 7,
    columns: ['image', 'tag', 'hosts', 'status', 'registry', 'checked'],
    getColumns: (r) => ({
      image:    r.image || '',
      tag:      r.tag || '',
      hosts:    (r.hosts || []).length,
      // Sort rank mirrors the server: update(0) < unchecked(1) <
      // up-to-date(2) < local(3) < ignored(4).
      status:   r.update_available ? 0 : (r.ignored ? 4 : (r.local ? 3 : (r.registry_digest ? 2 : 1))),
      registry: r.registry || '',
      checked:  r.last_checked || 0,
    }),
    match: (r, q) =>
      (r.image || '').toLowerCase().includes(q) ||
      (r.tag || '').toLowerCase().includes(q) ||
      (r.registry || '').toLowerCase().includes(q),
    row: (r) => {
      let statusCell;
      if (r.ignored) {
        statusCell = `<span class="patch-badge" title="${escAttr(r.ignore_reason || 'Accepted — not alerting')}">Ignored</span>`;
      } else if (r.local) {
        statusCell = `<span class="c-muted" title="Locally-built or loaded image — no registry to compare against">Local</span>`;
      } else if (r.update_available) {
        statusCell = `<span class="patch-badge warn">Update available</span>`;
      } else if (r.registry_digest) {
        statusCell = `<span class="patch-badge ok">Up to date</span>`;
      } else if (r.last_error) {
        statusCell = `<span class="c-muted" title="${escAttr(r.last_error)}">Unknown</span>`;
      } else {
        statusCell = `<span class="c-muted">Not checked</span>`;
      }
      const hosts = (r.hosts || []);
      const hostTitle = hosts.map(h => `${h.device_name}${h.container ? ' · ' + h.container : ''}${h.stale ? ' (stale)' : ''}`).join(', ');
      const checked = (r.local || !r.last_checked) ? '—' : new Date(r.last_checked * 1000).toLocaleString();
      // Container name(s) running this image — the only identifier when the
      // image itself is an untagged bare ID (e.g. right after a compose pull
      // that hasn't recreated the container yet, so `docker ps` shows sha256:…).
      const cnames = [...new Set(hosts.map(h => h.container).filter(Boolean))];
      const looksLikeId = /^(sha256|[0-9a-f]{12,64})$/i.test(r.image || '');
      const imageCell = looksLikeId && cnames.length
        ? `${escHtml(cnames.join(', '))} <span class="hint" title="The container runs an untagged image (${escAttr(r.image)}:${escAttr(r.tag)}) — usually a pulled-but-not-recreated image. Recreate it (Update) to move onto the tagged one.">untagged</span>`
        : `${escHtml(r.image)}${cnames.length ? ` <span class="hint">${escHtml(cnames.join(', '))}</span>` : ''}`;
      // Update = pull + recreate (compose) on the hosts that reported a compose
      // working dir. Only offered when an update is actually available.
      const updatable = hosts.filter(h => h.compose_dir);
      const updateBtn = (r.update_available && updatable.length)
        ? `<button class="btn-icon" data-action="updateImageNow" data-arg="${escAttr(r.ref)}" title="Pull the new image and recreate the container(s) — docker compose pull + up -d — on ${updatable.length} host(s)">Update</button> `
        : '';
      const action = r.ignored
        ? `<button class="btn-icon" data-action="unignoreImageUpdate" data-arg="${escAttr(r.ref)}" title="Resume alerting on updates for this image">Un-ignore</button>`
        : `${updateBtn}<button class="btn-icon c-muted" data-action="ignoreImageUpdate" data-arg="${escAttr(r.ref)}" title="Accept the current version and stop alerting until a newer one ships">Ignore</button>`;
      return `<tr>
        <td class="fw-500">${imageCell}</td>
        <td class="mono-12">${escHtml(r.tag)}</td>
        <td title="${escAttr(hostTitle)}">${hosts.length}</td>
        <td>${statusCell}</td>
        <td class="hint">${escHtml(r.registry || '—')}</td>
        <td class="hint-nowrap">${checked}</td>
        <td class="nowrap">${action}</td>
      </tr>`;
    },
    emptyMsg: 'No container images reported yet. The agent reports image digests with each container sweep (~5 min when Docker/Podman is installed); the server then checks each unique image against its registry.',
    emptyMsgFiltered: 'No images match the filter.',
  });
}

function renderImageUpdates() {
  _registerImageUpdatesTable();
  tableCtl.render('image-updates', _imageUpdates || []);
}

async function scanImageUpdatesNow(btn) {
  const original = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = 'Scanning…'; }
  try {
    const r = await api('POST', '/image-updates/scan', {});
    if (r && r.ok) {
      toast(`Checked ${r.checked} image(s)`, 'success');
      await loadImageUpdates();
    } else {
      toast((r && r.error) || 'Scan failed', 'error');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = original; }
  }
}

async function updateImageNow(ref) {
  const row = (_imageUpdates || []).find(r => r.ref === ref);
  if (!row) return;
  // Prefer the hosts actually flagged stale; fall back to any compose-managed
  // host running this image.
  const stale = (row.hosts || []).filter(h => h.compose_dir && h.stale);
  const list = stale.length ? stale : (row.hosts || []).filter(h => h.compose_dir);
  if (!list.length) {
    toast('No compose-managed host found for this image — update it manually (compose pull && up -d).', 'error');
    return;
  }
  const names = [...new Set(list.map(h => h.device_name))].join(', ');
  if (!await uiConfirm(`Update "${ref}" on ${list.length} host(s) (${names})?\n\nThis runs "docker compose pull" then "up -d" to pull the new image and recreate the container(s) — expect a brief restart. Output arrives on the next heartbeat.`)) return;
  let ok = 0, fail = 0;
  for (const h of list) {
    const r = await api('POST', `/devices/${encodeURIComponent(h.device_id)}/compose/action`,
      { action: 'update', dir: h.compose_dir }).catch(() => null);
    if (r && r.ok) ok++; else fail++;
  }
  if (ok) toast(`Update queued on ${ok} host(s)${fail ? ` (${fail} failed)` : ''} — recreated containers report on the next heartbeat (~60s).`, fail ? 'info' : 'success');
  else toast('Failed to queue the update.', 'error');
  loadImageUpdates();
}

async function ignoreImageUpdate(ref) {
  const reason = await uiPrompt({title: 'Ignore image update',
    message: `Accept the current version of "${ref}" and stop alerting until a newer one ships? Reason (optional):`,
    placeholder: 'reason (optional)', confirmText: 'Ignore'});
  if (reason === null) return;   // cancelled
  const r = await api('POST', '/image-updates/ignore', { ref, reason });
  if (r && r.ok) { toast('Image ignored', 'success'); loadImageUpdates(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function unignoreImageUpdate(ref) {
  const r = await api('DELETE', '/image-updates/ignore', { ref });
  if (r && r.ok) { toast('Resumed update alerts', 'success'); loadImageUpdates(); }
  else toast((r && r.error) || 'Failed', 'error');
}

// ── v3.3.4: compose stacks ─────────────────────────────────────────────────
let _composeStacks = [];

async function loadComposeStacks() {
  _registerComposeStacksTable();
  const tbody = document.getElementById('compose-stacks-tbody');
  if (tbody) tbody.innerHTML = _skeletonRows(5);   // v6.2.2: skeleton, not bare text
  const data = await api('GET', '/compose/stacks');
  _composeStacks = (data && data.stacks) || [];
  renderComposeStacks();
}

let _composeStacksRegistered = false;
function _registerComposeStacksTable() {
  if (_composeStacksRegistered) return;
  _composeStacksRegistered = true;
  tableCtl.register({
    name: 'compose-stacks',
    tbody: 'compose-stacks-tbody',
    sortHeaders: 'compose-stacks-thead',
    colspan: 5,
    columns: ['name', 'device', 'status', 'last'],
    getColumns: (s) => ({
      name:   s.name || '',
      device: s.device_name || '',
      status: s.status || '',
      last:   s.last_action_ts || 0,
    }),
    row: (s) => {
      const statusMap = {
        up:        '<span class="patch-badge ok">Up</span>',
        down:      '<span class="c-muted">Down</span>',
        deploying: '<span class="patch-badge warn">Deploying…</span>',
        error:     '<span class="c-red">Error</span>',
        created:   '<span class="c-muted">Not deployed</span>',
      };
      const statusCell = statusMap[s.status] || `<span class="c-muted">${escHtml(s.status || '?')}</span>`;
      const last = s.last_action_ts
        ? `${escHtml(s.last_action || '')} · ${new Date(s.last_action_ts * 1000).toLocaleString()}`
        : '—';
      const view = `<button class="btn-icon badge-xs" data-action="viewComposeStack" data-arg="${escAttr(s.id)}">View</button>`;
      const del = `<button class="btn-icon badge-xs c-danger-outline" data-action="deleteComposeStack" data-arg="${escAttr(s.id)}" data-arg2="${escAttr(s.name)}">Delete</button>`;
      let actions;
      if (s.compose_enabled) {
        actions =
          `<button class="btn-icon badge-xs" data-action="composeStackAction" data-arg="${escAttr(s.id)}" data-arg2="up" title="docker compose up -d">Up</button>` +
          `<button class="btn-icon badge-xs" data-action="composeStackAction" data-arg="${escAttr(s.id)}" data-arg2="down" title="docker compose down">Down</button>` +
          `<button class="btn-icon badge-xs" data-action="composeStackAction" data-arg="${escAttr(s.id)}" data-arg2="redeploy" title="docker compose pull + up -d">Redeploy</button>` +
          view + del;
      } else {
        actions =
          `<span class="hint">deploys off</span> ` +
          `<button class="btn-icon badge-xs" data-action="enableComposeOnDevice" data-arg="${escAttr(s.device_id)}" data-arg2="${escAttr(s.device_name)}" title="Allow compose deploys on this device">Enable</button>` +
          view + del;
      }
      return `<tr>
        <td class="fw-500">${escHtml(s.name)}</td>
        <td class="hint">${escHtml(s.device_name)}</td>
        <td>${statusCell}</td>
        <td class="hint-nowrap">${last}</td>
        <td class="nowrap">${actions}</td>
      </tr>`;
    },
    emptyMsg: 'No compose stacks yet. Click "New stack" to upload a docker-compose file and deploy it to a device.',
  });
}

function renderComposeStacks() {
  _registerComposeStacksTable();
  tableCtl.render('compose-stacks', _composeStacks || []);
}

async function openComposeCreate() {
  const sel = document.getElementById('compose-create-device');
  const devs = await api('GET', '/devices');
  const list = Array.isArray(devs) ? devs : (devs && devs.devices) || [];
  sel.innerHTML = list
    .filter(d => !d.agentless)
    .map(d => `<option value="${escAttr(d.id)}">${escHtml(d.name)}${d.compose_enabled ? '' : ' (deploys off)'}</option>`)
    .join('') || '<option value="">No agent devices</option>';
  document.getElementById('compose-create-name').value = '';
  document.getElementById('compose-create-yaml').value = '';
  openModal('compose-create-modal');
}

async function submitComposeStack() {
  const name = document.getElementById('compose-create-name').value.trim();
  const device_id = document.getElementById('compose-create-device').value;
  const yaml = document.getElementById('compose-create-yaml').value;
  if (!name || !device_id || !yaml.trim()) {
    toast('Name, device, and compose file are all required', 'error', {transient: true}); return;
  }
  const r = await api('POST', '/compose/stacks', { name, device_id, yaml });
  if (r && r.ok) { toast('Stack created', 'success'); closeModal('compose-create-modal'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function composeStackAction(stackId, action) {
  if (action === 'down' && !await uiConfirm('Run `docker compose down` for this stack?')) return;
  const r = await api('POST', `/compose/stacks/${encodeURIComponent(stackId)}/action`, { action });
  if (r && r.ok) { toast(`${action} queued — runs on the device's next heartbeat (~60s)`, 'success'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function deleteComposeStack(stackId, name) {
  if (!await uiConfirm(`Delete stack "${name}"?\n\nThis only removes it from RemotePower — it does NOT stop running containers. Run "Down" first if you want to tear it down.`)) return;
  const r = await api('DELETE', `/compose/stacks/${encodeURIComponent(stackId)}`);
  if (r && r.ok) { toast('Stack deleted', 'success'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function enableComposeOnDevice(deviceId, deviceName) {
  if (!await uiConfirm(`Enable compose deploys on "${deviceName}"?\n\nThis lets RemotePower run uploaded compose files as root on that host.`)) return;
  const r = await api('PATCH', `/devices/${encodeURIComponent(deviceId)}/compose_enabled`, { compose_enabled: true });
  if (r && r.ok) { toast('Compose deploys enabled', 'success'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function viewComposeStack(stackId) {
  const body = document.getElementById('compose-view-body');
  body.innerHTML = _skeletonBlock(5);
  openModal('compose-view-modal');
  const s = await api('GET', `/compose/stacks/${encodeURIComponent(stackId)}`);
  if (!s || s.error) { body.innerHTML = `<div class="c-red">${escHtml((s && s.error) || 'Failed')}</div>`; return; }
  document.getElementById('compose-view-title').textContent = `Stack — ${s.name || ''}`;
  const out = s.last_output
    ? `<h4>Last run (${escHtml(s.last_action || '')}, rc=${s.last_rc != null ? s.last_rc : '?'})</h4><pre class="isl-514"><code>${escHtml(s.last_output)}</code></pre>`
    : '';
  body.innerHTML = `<h4>docker-compose.yml</h4><pre class="isl-514"><code>${escHtml(s.yaml || '')}</code></pre>${out}`;
}

// v6.1.2: docker prints HUMAN sizes ("12.3GB"). We keep the string for display
// — it's exactly what `docker system df` shows on the box, so there's nothing to
// reconcile when the operator goes and checks — but sorting needs bytes.
const _SIZE_UNITS = { b: 1, kb: 1e3, mb: 1e6, gb: 1e9, tb: 1e12,
                      kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, tib: 1024 ** 4 };

function _parseSize(s) {
  const m = /^\s*([\d.]+)\s*([A-Za-z]+)/.exec(String(s || ''));
  if (!m) return 0;
  const n = parseFloat(m[1]);
  return isNaN(n) ? 0 : n * (_SIZE_UNITS[m[2].toLowerCase()] || 1);
}

function _dfTotalBytes(df) {
  if (!df) return 0;
  return ['images', 'containers', 'local_volumes', 'build_cache']
    .reduce((t, k) => t + (df[k] ? _parseSize(df[k].size) : 0), 0);
}

// Bytes -> human, for the container LIMITS (which arrive as raw bytes from
// docker's HostConfig, unlike `system df` which is already formatted).
function _fmtSize(bytes) {
  const b = Number(bytes) || 0;
  if (b >= 1024 ** 3) return `${(b / 1024 ** 3).toFixed(1)}GiB`;
  if (b >= 1024 ** 2) return `${Math.round(b / 1024 ** 2)}MiB`;
  if (b >= 1024) return `${Math.round(b / 1024)}KiB`;
  return `${b}B`;
}

async function loadContainersOverview() {
  const tbody = document.getElementById('containers-tbody');
  tbody.innerHTML = _skeletonRows(10);   // v6.2.2: skeleton, not bare text
  const data = await api('GET', '/containers');
  _containersOverview = Array.isArray(data) ? data : [];
  renderContainersOverview();
}

// v1.11.5: containers overview now goes through tableCtl. The existing
// containers-search input keeps working, but we also wire up sortable
// headers (data-col attrs in the <thead>), and the filter is persisted
// per-user. The old in-memory filter input keeps its existing behaviour
// — we wire it as the tableCtl filterInput so persistence is automatic.
let _containersOverviewRegistered = false;
function _registerContainersOverviewTable() {
  if (_containersOverviewRegistered) return;
  _containersOverviewRegistered = true;
  tableCtl.register({
    name: 'containers',
    tbody: 'containers-tbody',
    filterInput: 'containers-search',
    sortHeaders: 'containers-thead',
    colspan: 10,
    columns: ['name', 'os', 'total', 'running', 'stopped', 'restarting', 'disk',
              'runtimes', 'reported_at'],
    getColumns: (r) => {
      const s = r.summary || {};
      return {
        name:       r.name || '',
        os:         r.os || '',
        total:      s.total || 0,
        running:    s.running || 0,
        stopped:    s.stopped || 0,
        restarting: s.restarting || 0,
        // v6.1.2: sort by TOTAL docker footprint in BYTES, not the printed
        // string — "9MB" sorts above "10GB" lexicographically, which is exactly
        // backwards from what anyone hunting for the fat host wants. Every
        // data-col must have a key here or the header shows a sort arrow that
        // does nothing (the Restore-drill bug, fixed earlier this release).
        disk:       _dfTotalBytes(r.df),
        // Concatenate runtime names so sorting groups same-runtime hosts
        runtimes:   Object.keys(s.by_runtime || {}).sort().join(','),
        reported_at: r.reported_at || 0,
      };
    },
    match: (r, q) => {
      if ((r.name || '').toLowerCase().includes(q)) return true;
      if ((r.os || '').toLowerCase().includes(q)) return true;
      return false;
    },
    row: (r) => {
      const s = r.summary || {total: 0, running: 0, stopped: 0, restarting: 0, by_runtime: {}};
      const runtimes = Object.entries(s.by_runtime || {})
        .map(([rt, n]) => `${escHtml(rt)}: ${n}`)
        .join(', ') || '—';
      const reported = r.reported_at ? new Date(r.reported_at * 1000).toLocaleString() : '—';
      const staleBadge = r.is_stale
        ? '<span class="isl-450">STALE</span>'
        : '';
      const restartingCell = s.restarting > 0
        ? `<span class="c-red">${s.restarting}</span>`
        : `<span class="c-muted">0</span>`;
      // v6.1.2: `docker system df`. The 40 GB build-cache surprise is a homelab
      // rite of passage — the box fills up and nothing says WHY, because "disk
      // 94%" doesn't distinguish your data from layers of images whose
      // containers you deleted months ago. Reclaimable is the number you act on.
      const df = r.df || null;
      let dfCell = '<span class="c-muted">—</span>';
      if (df) {
        const parts = [];
        for (const [k, lbl] of [['images', 'img'], ['local_volumes', 'vol'],
                                ['build_cache', 'cache']]) {
          if (df[k] && df[k].size) parts.push(`${lbl} ${escHtml(df[k].size)}`);
        }
        // "Reclaimable" comes back as "12.3GB (57%)"; the leading size is enough.
        const recl = (df.images && df.images.reclaimable) || '';
        const reclSize = String(recl).split(' ')[0];
        const wasteful = _parseSize(reclSize) >= 5e9;   // ≥5 GB is worth a nudge
        dfCell = `<span class="hint">${parts.join(' · ') || '—'}</span>`
          + (reclSize && reclSize !== '0B'
              ? `<div class="fs-11 ${wasteful ? 'c-amber' : 'c-muted'}" title="Reclaimable by docker system prune">${escHtml(reclSize)} reclaimable</div>`
              : '');
      }
      return `<tr class="isl-451">
        <td class="fw-500">${osIcon(r.os, 14)} ${escHtml(r.name)}</td>
        <td class="hint">${escHtml(r.os || '—')}</td>
        <td class="fw-500">${s.total}</td>
        <td class="c-green">${s.running}</td>
        <td class="c-muted">${s.stopped}</td>
        <td>${restartingCell}</td>
        <td>${dfCell}</td>
        <td class="hint">${runtimes}</td>
        <td class="hint-nowrap">${reported}${staleBadge}</td>
        <td class="row-4-center">
          <button class="btn-icon" data-action="containersOpen" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.name)}" >View</button>
          <button class="btn-icon c-muted" title="Hide this device from the Containers page" data-action="ignoreContainerDevice" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.name)}" ><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        </td>
      </tr>`;
    },
    emptyMsg: 'No devices have reported containers yet. The agent reports every 5 polls (~5 minutes) when Docker, Podman, or Kubernetes is installed. Stale rows are flagged automatically.',
    emptyMsgFiltered: 'No containers match the filter.',
  });
}

function renderContainersOverview() {
  _registerContainersOverviewTable();
  tableCtl.render('containers', _containersOverview || []);
}

async function containersOpen(deviceId, name) {
  _containersOpenDeviceId = deviceId;
  document.getElementById('containers-detail-title').textContent = `Containers — ${name}`;
  const body = document.getElementById('containers-detail-body');
  body.innerHTML = _skeletonBlock(5);
  openModal('containers-detail-modal');
  const data = await api('GET', `/devices/${encodeURIComponent(deviceId)}/containers`);
  if (!data) return;
  const items = data.items || [];
  // v1.11.4: stale-data warning at the top of the modal.
  const reportedHuman = data.reported_at ? new Date(data.reported_at * 1000).toLocaleString() : 'never';
  const staleBanner = data.is_stale
    ? `<div class="isl-452">
         Container data is stale (last reported: ${escHtml(reportedHuman)}).
         Agent reports every ~5 min when a runtime is installed; check
         <code>journalctl -u remotepower-agent</code> on the device.
       </div>`
    : '';
  // v6.1.2: `docker system df` — where the disk actually went, plus the
  // per-volume sizes. "Disk 94%" doesn't distinguish your data from layers of
  // images whose containers you deleted months ago; this does, and it makes
  // "which volume is eating 200 GB" answerable without SSHing in.
  const dfPanel = _renderDockerDf(data.df, deviceId);

  if (!items.length) {
    body.innerHTML = staleBanner + dfPanel
      + '<div class="empty-state">No containers reported.</div>';
    return;
  }
  body.innerHTML = staleBanner + dfPanel + items.map(c => {
    const statusLower = (c.status || '').toLowerCase();
    const statusColor = statusLower.includes('running') || statusLower.includes('up ')
      ? 'var(--green)'
      : statusLower.includes('exit') ? 'var(--red)' : 'var(--muted)';
    const ports = (c.ports || []).map(p => `<code class="isl-453">${escHtml(p)}</code>`).join(' ');
    const restart = c.restart_count > 0
      ? `<span class="isl-454 ${c.restart_count >= 5 ? 'c-red' : 'c-amber'}">restart×${c.restart_count}</span>`
      : '';
    const ns = c.namespace ? `<span class="c-muted">${escHtml(c.namespace)}/</span>` : '';
    // v2.2.6: container health badge — the agent parses (healthy)/
    // (unhealthy)/(starting) out of the docker status string.
    let healthBadge = '';
    if (c.health === 'healthy') {
      healthBadge = '<span class="status-pill ok isl-455">healthy</span>';
    } else if (c.health === 'unhealthy') {
      healthBadge = '<span class="status-pill critical isl-455">unhealthy</span>';
    } else if (c.health === 'starting') {
      healthBadge = '<span class="status-pill warn isl-455">starting</span>';
    }
    // v2.2.6: per-container CPU / memory from `docker stats`. Only
    // shown when the agent reported them (omitted for kubectl pods
    // and older agents).
    let resourceLine = '';
    if (c.cpu_percent != null || c.mem_percent != null) {
      const cpuTxt = c.cpu_percent != null ? `CPU ${c.cpu_percent}%` : '';
      const memTxt = c.mem_percent != null
        ? `MEM ${c.mem_percent}%${c.mem_usage ? ` (${escHtml(c.mem_usage)})` : ''}`
        : '';
      const memColor = c.mem_percent > 85 ? 'var(--red)'
                     : c.mem_percent > 70 ? 'var(--amber)' : 'var(--muted)';
      // v6.1.2: the configured LIMITS beside the usage. Usage alone is half a
      // story — "using 3 GB" means something entirely different capped at 4 GB
      // versus uncapped, and an UNCAPPED container is the one that can OOM the
      // whole host. That's how a homelab box actually falls over, so say so.
      const lim = [];
      if (c.mem_limit_bytes) lim.push(`mem ≤ ${_fmtSize(c.mem_limit_bytes)}`);
      if (c.cpu_limit_cores) lim.push(`cpu ≤ ${c.cpu_limit_cores}`);
      const limTxt = lim.length
        ? `<span class="hint">${escHtml(lim.join(' · '))}</span>`
        : (c.mem_limit_bytes === 0 && c.cpu_limit_cores === 0
            ? '<span class="hint c-amber" title="No memory or CPU limit — this container can consume the whole host">unlimited</span>'
            : '');
      resourceLine = `<div class="isl-456">
        ${cpuTxt ? `<span>${cpuTxt}</span>` : ''}
        ${memTxt ? `<span class="isl-457" data-color="${memColor}">${memTxt}</span>` : ''}
        ${limTxt}
      </div>`;
    }
    const cid = c.id || c.name || '';
    const runtime = (c.runtime || 'docker').toLowerCase();
    const actionable = (runtime === 'docker' || runtime === 'podman') && cid;
    const isRunning = statusLower.includes('running') || statusLower.includes('up ');
    const actions = actionable ? `
      <div class="isl-458">
        ${!isRunning ? `<button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="start" data-arg5="${escAttr(c.name||'')}">Start</button>` : ''}
        ${isRunning  ? `<button class="btn-icon isl-459" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="stop" data-arg5="${escAttr(c.name||'')}">Stop</button>` : ''}
        <button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="restart" data-arg5="${escAttr(c.name||'')}">Restart</button>
        ${isRunning ? `<button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="update" data-arg5="${escAttr(c.name||'')}" title="Pull the latest image and recreate this standalone container (compose-managed containers update via their stack)">Update</button>` : ''}
        <button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="logs" data-arg5="${escAttr(c.name||'')}">Logs</button>
      </div>` : '';
    return `<div class="isl-460">
      <div class="isl-461">
        <div class="isl-462">${ns}${escHtml(c.name)}${healthBadge}</div>
        <div class="isl-463">
          <span class="isl-376" data-color="${statusColor}">${escHtml(c.status || '?')}</span>
          ${restart}
          <span class="cmd-badge ${escHtml(c.runtime)} isl-464">${escHtml(c.runtime)}</span>
        </div>
      </div>
      <div class="isl-465">${escHtml(c.image)}${c.tag ? ':' + escHtml(c.tag) : ''}</div>
      ${resourceLine}
      ${ports ? `<div class="isl-466">${ports}</div>` : ''}
      ${actions}
    </div>`;
  }).join('');
}

// v6.1.2: reclaim docker disk space. Rides the audited command queue, so
// quarantine / audit-mode / maker-checker apply exactly as to any other exec.
//
// The scope list splits into two classes and the split IS the safety model:
// images/cache/networks/all remove only RECREATABLE things (an image re-pulls,
// a cache rebuilds, an unused network is re-created by `compose up`) — worst
// case you wait. volumes/full delete the DATA in every volume no *running*
// container references, and a stopped stack's volumes look exactly like
// abandoned ones to Docker. That's how people lose their Nextcloud data, so it
// takes a typed confirmation — which the SERVER checks, because a browser-only
// confirm is theatre when anything can POST to the API.
// v6.2.3: granular Docker cleanup — a CHECKBOX picker (each target independent)
// + run-and-wait FEEDBACK that shows the real docker output (reclaimed space per
// target, deleted volumes). Replaces the old "type a number 1–6" prompt that ran
// silently. Targets mirror the server's _DOCKER_PRUNE_TARGETS; `df` label maps to
// the `docker system df` bucket so each row shows what it will reclaim. 'images'
// is prune -a on the server (all unused, not just dangling — the dangling-only
// default reclaimed 0B and looked broken).
const DOCKER_PRUNE_UI = [
  { id: 'containers', label: 'Stopped containers', df: 'containers',    safe: true,  hint: 'Exited containers not part of a running stack' },
  { id: 'images',     label: 'Unused images',      df: 'images',        safe: true,  hint: 'Every image no container uses — not just dangling layers' },
  { id: 'cache',      label: 'Build cache',        df: 'build_cache',   safe: true,  hint: 'Rebuilt on the next build' },
  { id: 'networks',   label: 'Unused networks',    df: null,            safe: true,  hint: 'Re-created by compose up' },
  { id: 'volumes',    label: 'Unused volumes',     df: 'local_volumes', safe: false, hint: 'DELETES DATA in every volume no running container uses — including a stopped stack’s volumes' },
];
const DOCKER_PRUNE_CONFIRM = 'DELETE VOLUMES';
const _DOCKER_PRUNE_LBL = Object.fromEntries(DOCKER_PRUNE_UI.map(t => [t.id, t.label]));
let _dockerDfByDev = {};   // deviceId → last `docker system df`, for per-row reclaimable sizes
let _dockerPruneDev = null;

// Open the checkbox picker for a host. `df` (optional) fills in the reclaimable
// size next to each target.
function pruneDocker(deviceId) {
  _dockerPruneDev = deviceId;
  const df = _dockerDfByDev[deviceId] || null;
  const box = document.getElementById('docker-prune-choices');
  if (!box) return;
  box.innerHTML = DOCKER_PRUNE_UI.map(t => {
    const b = t.df && df && df[t.df];
    const recl = b ? String(b.reclaimable || '').split(' ')[0] : '';
    const sizeTag = (recl && recl !== '0B')
      ? ` — <span class="${t.safe ? 'c-muted' : 'c-amber'} fs-12">${escHtml(recl)} reclaimable</span>` : '';
    return `<label class="click-row-6 mb-8">
      <input type="checkbox" class="docker-prune-cb" value="${escAttr(t.id)}" ${t.safe ? 'checked' : ''} data-change="_dockerPruneSyncConfirm">
      <span><strong>${escHtml(t.label)}</strong>${sizeTag}<br><span class="hint">${escHtml(t.hint)}</span></span>
    </label>`;
  }).join('');
  document.getElementById('docker-prune-confirm-row').classList.add('d-none');
  document.getElementById('docker-prune-confirm-input').value = '';
  const res = document.getElementById('docker-prune-result');
  res.classList.add('d-none'); res.innerHTML = '';
  const runBtn = document.getElementById('docker-prune-run');
  runBtn.disabled = false; runBtn.textContent = 'Prune'; runBtn.classList.remove('d-none');
  document.getElementById('docker-prune-cancel').textContent = 'Cancel';
  openModal('docker-prune-modal');
}

// The volumes checkbox reveals the typed-confirmation row (also enforced server-side).
function _dockerPruneSyncConfirm() {
  const volCb = document.querySelector('.docker-prune-cb[value="volumes"]');
  const row = document.getElementById('docker-prune-confirm-row');
  if (row) row.classList.toggle('d-none', !(volCb && volCb.checked));
}

async function dockerPruneRun() {
  const targets = Array.from(document.querySelectorAll('.docker-prune-cb:checked')).map(c => c.value);
  if (!targets.length) { toast('Pick at least one thing to prune', 'error', {transient: true}); return; }
  const body = { targets, wait: true };
  if (targets.includes('volumes')) {
    const typed = (document.getElementById('docker-prune-confirm-input').value || '').trim();
    if (typed !== DOCKER_PRUNE_CONFIRM) { toast(`Type ${DOCKER_PRUNE_CONFIRM} to remove volumes`, 'error'); return; }
    body.confirm = DOCKER_PRUNE_CONFIRM;
  }
  const runBtn = document.getElementById('docker-prune-run');
  const res = document.getElementById('docker-prune-result');
  runBtn.disabled = true; runBtn.textContent = 'Pruning…';
  res.classList.remove('d-none');
  res.innerHTML = `<div class="hint mt-8">Running on the host and waiting for the agent to report back…</div>`;
  let r = null;
  try { r = await api('POST', `/devices/${encodeURIComponent(_dockerPruneDev)}/docker/prune`, body); }
  catch (e) { r = null; }
  if (!r || r.error) {
    res.innerHTML = `<div class="c-red mt-8">${escHtml((r && r.error) || 'Prune failed')}</div>`;
    runBtn.disabled = false; runBtn.textContent = 'Prune';
    return;
  }
  // Done — swap the primary button out, turn Cancel into Close.
  runBtn.classList.add('d-none');
  document.getElementById('docker-prune-cancel').textContent = 'Close';
  res.innerHTML = (r.timeout || r.shutdown)
    ? `<div class="c-amber mt-8">${escHtml(r.message || 'Still running — the footprint will refresh shortly.')}</div>`
    : _renderPruneResult(r.output);
  // Refresh the footprint panel so the numbers reflect the reclaim.
  if (typeof loadContainersOverview === 'function') loadContainersOverview();
}

// Turn the agent's raw docker output (with our @@RP:<target> markers) into a
// tidy per-target reclaim table + total, with the full output foldable below.
function _renderPruneResult(output) {
  const text = (output && (output.output != null ? output.output : output.stdout)) || '';
  const rc = output && typeof output.rc === 'number' ? output.rc : null;
  const sections = {};
  let cur = '_pre';
  String(text).split('\n').forEach(line => {
    const m = line.match(/^@@RP:(\w+)\s*$/);
    if (m) { cur = m[1]; sections[cur] = []; return; }
    (sections[cur] = sections[cur] || []).push(line);
  });
  let totalBytes = 0, rows = '';
  DOCKER_PRUNE_UI.forEach(t => {
    if (!sections[t.id]) return;
    const seg = sections[t.id].join('\n');
    const mm = seg.match(/Total reclaimed space:\s*([0-9.]+\s*[KkMGTP]?i?B)/i);
    const recl = mm ? mm[1].replace(/\s+/g, '') : '0B';
    totalBytes += _parseSize(recl) || 0;
    const delVols = /Deleted Volumes:/.test(seg)
      ? (seg.split(/Deleted Volumes:/)[1] || '').split('\n').filter(l => l.trim() && !/Total reclaimed/i.test(l)).length
      : 0;
    const note = delVols ? ` <span class="c-amber fs-11">(${delVols} volume${delVols === 1 ? '' : 's'} deleted)</span>` : '';
    rows += `<tr><td>${escHtml(_DOCKER_PRUNE_LBL[t.id] || t.id)}${note}</td><td class="ta-right">${escHtml(recl)}</td></tr>`;
  });
  const warn = (rc != null && rc !== 0)
    ? `<div class="c-amber fs-12 mt-6">The agent reported a non-zero exit (${rc}) — see the full output.</div>` : '';
  return `<div class="section-title mt-12">Result</div>
    <div class="scrollable-table-wrap audit-scroll"><table class="audit-table"><tbody>${rows || '<tr><td class="hint">No output parsed</td></tr>'}</tbody></table></div>
    <div class="mt-8"><strong>Total reclaimed: ${escHtml(_fmtSize(totalBytes))}</strong></div>
    ${warn}
    <details class="mt-8"><summary class="hint">Full output</summary><pre class="ff-mono fs-12 scroll-cap mt-6">${escHtml(String(text).trim())}</pre></details>`;
}

// v6.1.2: the `docker system df` panel — footprint by bucket, what a prune
// would reclaim, and the biggest volumes.
function _renderDockerDf(df, deviceId) {
  if (!df) return '';
  _dockerDfByDev[deviceId] = df;   // so the prune picker can show per-target reclaimable sizes
  const LBL = { images: 'Images', containers: 'Containers',
                local_volumes: 'Volumes', build_cache: 'Build cache' };
  const cells = Object.keys(LBL).filter(k => df[k]).map(k => {
    const b = df[k];
    // Reclaimable arrives as "12.3GB (57%)" — the size is the actionable part.
    const recl = String(b.reclaimable || '').split(' ')[0];
    const big = _parseSize(recl) >= 5e9;
    return `<div class="sysinfo-pill">
      <div class="label">${LBL[k]}</div>
      <div class="value">${escHtml(b.size || '—')}</div>
      ${recl && recl !== '0B'
        ? `<div class="fs-11 ${big ? 'c-amber' : 'c-muted'}">${escHtml(recl)} reclaimable</div>`
        : ''}
    </div>`;
  }).join('');

  const vols = (df.volumes || []).slice(0, 15);
  const volRows = vols.map(v => `<tr>
      <td><code class="fs-12">${escHtml(v.name)}</code></td>
      <td class="ta-right">${escHtml(v.size || '—')}</td>
      <td class="ta-center ${v.links === 0 ? 'c-amber' : 'hint'}"
          title="${v.links === 0 ? 'No container uses this volume — it may be an orphan' : 'Containers using this volume'}">${v.links == null ? '—' : v.links}</td>
    </tr>`).join('');

  return `<div class="dash-card mb-12">
    <div class="section-header">
      <div class="section-title">Docker disk footprint</div>
      <button class="btn-icon" data-action="pruneDocker" data-arg="${escAttr(deviceId)}"
              title="Choose what to reclaim (images, cache, networks, containers, volumes) and see what each freed.">Prune…</button>
    </div>
    <div class="sysinfo-row">${cells}</div>
    ${vols.length ? `<div class="section-title mt-12">Largest volumes</div>
      <div class="scrollable-table-wrap audit-scroll"><table class="audit-table">
        <thead><tr><th>Volume</th><th class="ta-right">Size</th><th class="ta-center" title="How many containers use it">Used by</th></tr></thead>
        <tbody>${volRows}</tbody></table></div>` : ''}
  </div>`;
}

// v2.1.1: per-container action — start/stop/restart/logs. Goes through
// the agent's command queue (same path as compose actions), so output
// arrives on the next heartbeat. Stop and restart prompt for confirmation
// because they're disruptive; start and logs don't.
async function containerAction(deviceId, runtime, containerId, action, displayName) {
  const verb = action.charAt(0).toUpperCase() + action.slice(1);
  // v5.8.0 (B1.1): 'update' pulls the latest image and RECREATES the container —
  // disruptive, so it gets an explicit confirm that names the recreate.
  if (action === 'update') {
    if (!await uiConfirm(`Update ${displayName || containerId}?\n\nThis pulls the latest image and recreates the container with the same configuration. Compose-managed containers are skipped — update those from their stack. Output arrives on the next heartbeat.`)) return;
  } else if ((action === 'stop' || action === 'restart') &&
      !await uiConfirm(`${verb} container ${displayName || containerId}?`)) return;
  const resp = await api('POST',
    '/devices/' + encodeURIComponent(deviceId) + '/containers/action',
    {runtime, action, container_id: containerId});
  if (!resp || resp.error) { toast(resp?.error || 'Failed', 'error'); return; }
  toast(`${verb} queued — runs on next heartbeat (~60s)`, 'success');
}

// v1.11.4: clear stored container data for the currently-open device.
// The agent will repopulate on its next heartbeat (~5 min by default), so
// this is safe to use during decommissioning or just to force a refresh
// after deliberately removing containers via `docker rm`.
async function containersClearCurrent() {
  if (!_containersOpenDeviceId) return;
  if (!await uiConfirm('Clear stored container data for this device?\n\nThis only clears the dashboard snapshot — it does NOT touch any actual containers on the host. The agent will repopulate the list on its next heartbeat (~5 min).')) {
    return;
  }
  const deviceId = _containersOpenDeviceId;
  const res = await api('DELETE', `/devices/${encodeURIComponent(deviceId)}/containers`);
  if (res?.ok) {
    toast(res.cleared ? 'Container data cleared' : 'Nothing to clear', 'success');
    closeModal('containers-detail-modal');
    // Refresh overview so the row disappears (or shows "—" until next report)
    await loadContainersOverview();
  } else {
    toast('Failed to clear container data', 'error');
  }
}
