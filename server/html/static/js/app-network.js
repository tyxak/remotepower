// Split out of app.js (v3.4.0 modularisation). Plain classic script —
// shares the global scope with app.js; loaded right after it in index.html.
// No bundler / no ES modules. Functions here are called from app.js and vice
// versa; page init is DOMContentLoaded-deferred so load order is not sensitive.

// ── Network map ──────────────────────────────────────────────────────────────
// v1.11.1: Now also carries `tunnels` (peer links) and per-node positions.
// Render-time the data is mutated in place — `_netmapNodes` is the source
// of truth for current screen position, kept separate so we don't rebuild
// the whole array every drag event.
let _netmapData = {nodes: [], edges: [], tunnels: []};
let _netmapNodes = [];          // working copy with x/y for rendering
let _netmapDirty = new Set();   // device IDs whose position has been moved

async function enterNetmap() {
  await loadNetmap();
  loadWan();                      // v6.1.2 — independent of the topology fetch
  loadDeadman();
  loadMdns();
}

// ── v6.1.2: internet (WAN) watch ─────────────────────────────────────────────
// Public IP + reachability + the outage log. Deliberately a separate fetch from
// the topology: it's a different question ("is the internet up?" vs "how are my
// hosts wired?") and it must still render when the map is empty.
async function loadWan() {
  const body = document.getElementById('wan-body');
  if (!body) return;
  let d;
  try {
    d = await api('GET', '/wan');
  } catch (e) {
    body.textContent = 'Could not load WAN status.';
    return;
  }
  body.innerHTML = '';
  if (!d.enabled) {
    const p = document.createElement('div');
    p.className = 'hint';
    p.textContent = 'Off. Enable "Internet (WAN) watch" under Settings → Security to track your public IP, ISP outages and 30-day uptime.';
    body.appendChild(p);
    return;
  }

  const row = document.createElement('div');
  row.className = 'stats-row';
  const stat = (label, value, cls) => {
    const w = document.createElement('div'); w.className = 'stat-card';
    const inner = document.createElement('div');
    const v = document.createElement('div'); v.className = 'stat-value' + (cls ? ' ' + cls : '');
    v.textContent = value;
    const l = document.createElement('div'); l.className = 'stat-label'; l.textContent = label;
    inner.appendChild(v); inner.appendChild(l);
    w.appendChild(inner); row.appendChild(w);
  };
  stat('Public IP', d.ip || '—');
  stat('Status', d.online ? 'Online' : 'Offline', d.online ? 'c-green' : 'c-red');
  stat('Outages (30d)', String(d.outage_count_30d ?? 0));
  stat('Uptime (30d)', (d.uptime_pct_30d ?? 100).toFixed(2) + '%');
  body.appendChild(row);

  if (d.ddns) {
    const dd = document.createElement('div');
    dd.className = 'hint mt-8';
    // The failure case is the one worth surfacing: DDNS did NOT update, and
    // silently-stale DNS is exactly the failure this feature exists to prevent.
    dd.textContent = d.ddns.ok
      ? 'Dynamic DNS: updated ' + timeAgo(d.ddns.ts)
      : 'Dynamic DNS: not updated — ' + (d.ddns.error || 'unknown error');
    if (!d.ddns.ok) dd.classList.add('c-amber');   // c-warn is not a real class
    body.appendChild(dd);
  }

  const outages = d.outages || [];
  if (!outages.length) {
    const p = document.createElement('div');
    p.className = 'hint mt-8';
    p.textContent = 'No outages recorded yet.';
    body.appendChild(p);
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'scrollable-table-wrap audit-scroll mt-8';
  const t = document.createElement('table');
  t.className = 'data-table';
  const th = document.createElement('thead');
  th.innerHTML = '<tr><th>Started</th><th>Ended</th><th>Duration</th></tr>';
  const tb = document.createElement('tbody');
  outages.slice().reverse().forEach(o => {
    const tr = document.createElement('tr');
    const c1 = document.createElement('td'); c1.textContent = _fmtTs(o.start, 4 * 86400);
    const c2 = document.createElement('td');
    c2.textContent = o.end ? _fmtTs(o.end, 4 * 86400) : 'ongoing';
    const c3 = document.createElement('td');
    c3.textContent = o.end ? _fmtDuration(Math.max(0, o.end - o.start)) : '—';
    tr.appendChild(c1); tr.appendChild(c2); tr.appendChild(c3);
    tb.appendChild(tr);
  });
  t.appendChild(th); t.appendChild(tb); wrap.appendChild(t);
  body.appendChild(wrap);
}

// ── v6.1.2: inbound dead-man's-switch ────────────────────────────────────────
async function loadDeadman() {
  const el = document.getElementById('deadman-list');
  if (!el) return;
  let d;
  try {
    d = await api('GET', '/deadman');
  } catch (e) {
    el.textContent = 'Could not load job check-ins.';
    return;
  }
  el.innerHTML = '';
  const jobs = d.jobs || [];
  if (!jobs.length) {
    const p = document.createElement('div');
    p.className = 'hint';
    p.textContent = 'No check-in jobs yet.';
    el.appendChild(p);
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'scrollable-table-wrap audit-scroll';
  const t = document.createElement('table');
  t.className = 'data-table';
  const th = document.createElement('thead');
  th.innerHTML = '<tr><th>Job</th><th>Every</th><th>Last check-in</th><th>State</th><th>Ping URL</th><th></th></tr>';
  const tb = document.createElement('tbody');
  jobs.forEach(j => {
    const tr = document.createElement('tr');
    const name = document.createElement('td'); name.textContent = j.name;
    const every = document.createElement('td');
    every.textContent = _fmtDuration((j.period_minutes || 0) * 60) + ' (+' + (j.grace_minutes || 0) + 'm grace)';
    const last = document.createElement('td');
    last.textContent = j.last_ping ? timeAgo(j.last_ping) : 'never';
    const state = document.createElement('td');
    const b = document.createElement('span');
    // "waiting" (never pinged) is deliberately NOT "late" — the clock only starts
    // on the first check-in, so a job you just created doesn't page you at once.
    const late = !!j.late, seen = !!j.last_ping;
    b.className = 'badge badge-sm ' + (late ? 'c-red' : seen ? 'c-green' : 'c-muted');
    b.textContent = late ? 'late' : seen ? 'ok' : 'waiting';
    state.appendChild(b);
    const url = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = j.url || '';
    code.className = 'ellipsis';
    url.appendChild(code);
    const act = document.createElement('td');
    const copy = document.createElement('button');
    copy.className = 'btn-icon';
    copy.textContent = 'Copy';
    copy.dataset.action = 'copyText';
    copy.dataset.arg = j.url || '';
    const del = document.createElement('button');
    del.className = 'btn-icon';
    del.textContent = 'Delete';
    del.dataset.action = 'deleteDeadmanJob';
    del.dataset.arg = j.id;
    act.appendChild(copy); act.appendChild(del);
    [name, every, last, state, url, act].forEach(c => tr.appendChild(c));
    tb.appendChild(tr);
  });
  t.appendChild(th); t.appendChild(tb); wrap.appendChild(t);
  el.appendChild(wrap);
}

async function addDeadmanJob() {
  const name = document.getElementById('dm-name')?.value.trim();
  const period = parseInt(document.getElementById('dm-period')?.value ?? '0', 10);
  const grace = parseInt(document.getElementById('dm-grace')?.value ?? '0', 10);
  if (!name) { toast('Give the job a name', 'error'); return; }
  if (!(period > 0)) { toast('Set how often the job runs', 'error'); return; }
  try {
    await api('POST', '/deadman', {name: name, period_minutes: period, grace_minutes: grace});
  } catch (e) {
    toast(e.message || 'Could not add the job', 'error');
    return;
  }
  const n = document.getElementById('dm-name'); if (n) n.value = '';
  toast('Job added — have it curl the ping URL when it finishes');
  loadDeadman();
}

async function deleteDeadmanJob(id) {
  if (!await uiConfirm('Delete this check-in job? Its ping URL stops working.')) return;
  try {
    await api('DELETE', '/deadman/' + encodeURIComponent(id));
  } catch (e) {
    toast(e.message || 'Could not delete the job', 'error');
    return;
  }
  loadDeadman();
}

// ── v6.1.2: mDNS-advertised LAN services ─────────────────────────────────────
async function loadMdns() {
  const el = document.getElementById('mdns-list');
  if (!el) return;
  let d;
  try {
    d = await api('GET', '/mdns');
  } catch (e) {
    el.textContent = 'Could not load LAN services.';
    return;
  }
  el.innerHTML = '';
  if (!d.enabled) {
    const p = document.createElement('div');
    p.className = 'hint';
    p.textContent = 'Off. Enable "LAN service discovery (mDNS)" under Settings → Security.';
    el.appendChild(p);
    return;
  }
  const svcs = d.services || [];
  if (!svcs.length) {
    const p = document.createElement('div');
    p.className = 'hint';
    p.textContent = 'Nothing discovered yet. Agents report on their next heartbeat, and need avahi-browse installed.';
    el.appendChild(p);
    return;
  }
  const wrap = document.createElement('div');
  wrap.className = 'scrollable-table-wrap audit-scroll';
  const t = document.createElement('table');
  t.className = 'data-table';
  const th = document.createElement('thead');
  th.innerHTML = '<tr><th>Name</th><th>Type</th><th>Host</th><th>Address</th><th>Port</th><th>Seen by</th></tr>';
  const tb = document.createElement('tbody');
  svcs.forEach(s => {
    const tr = document.createElement('tr');
    [s.name, s.type, s.host, s.address, s.port ? String(s.port) : '', s.seen_by].forEach(v => {
      const td = document.createElement('td');
      td.textContent = v || '—';
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
  t.appendChild(th); t.appendChild(tb); wrap.appendChild(t);
  el.appendChild(wrap);
}

// v5.0.0: scope the topology to one site / group / tag so a big fleet stays
// legible instead of rendering all N nodes at once.
function _netmapScopeQuery() {
  const g = document.getElementById('netmap-scope-group')?.value || '';
  const t = document.getElementById('netmap-scope-tag')?.value || '';
  const s = document.getElementById('netmap-scope-site')?.value || '';
  const p = [];
  if (g) p.push('group=' + encodeURIComponent(g));
  if (t) p.push('tag=' + encodeURIComponent(t));
  if (s) p.push('site=' + encodeURIComponent(s));
  return p.length ? '?' + p.join('&') : '';
}
function _netmapFillScope(sel, values, active) {
  const el = document.getElementById(sel);
  if (!el) return;
  const allLabel = el.options[0] ? el.options[0].textContent : 'All';
  // allLabel is the static first-option text from index.html (author-controlled),
  // but escape it anyway — defense-in-depth and it clears the CodeQL textContent→
  // innerHTML flow (js/xss-through-dom #51).
  el.innerHTML = `<option value="">${escHtml(allLabel)}</option>` +
    (values || []).map(v => `<option value="${escAttr(v)}"${v === active ? ' selected' : ''}>${escHtml(v)}</option>`).join('');
  el.value = active || '';
}

// W3-8: dependency auto-suggestions from observed traffic.
async function loadDepSuggestions() {
  const box = document.getElementById('dep-suggestions');
  if (!box) return;
  const r = await api('GET', '/dependency-suggestions');
  if (!r || !r.ok) { box.innerHTML = '<div class="c-muted">Not available.</div>'; return; }
  const s = r.suggestions || [];
  if (!s.length) { box.innerHTML = '<div class="c-muted">No new dependency suggestions.</div>'; return; }
  box.innerHTML = '<div class="scrollable-table-wrap audit-scroll"><table class="data-table">'
    + '<thead><tr><th>Device</th><th>→ Upstream</th><th>Evidence</th><th></th></tr></thead><tbody>'
    + s.map(x => `<tr><td>${escHtml(x.device_name)}</td><td>${escHtml(x.upstream_name)}</td>`
        + `<td class="fs-12">${escHtml(x.evidence)}</td>`
        + `<td class="nowrap"><button class="btn-icon cell-sm c-success" data-action="depSuggestAct" data-arg="${escAttr(x.device_id)}" data-arg2="${escAttr(x.upstream_id)}" data-arg3="accept">Accept</button> `
        + `<button class="btn-icon cell-sm" data-action="depSuggestAct" data-arg="${escAttr(x.device_id)}" data-arg2="${escAttr(x.upstream_id)}" data-arg3="dismiss">Dismiss</button></td></tr>`).join('')
    + '</tbody></table></div>';
}
async function depSuggestAct(deviceId, upstreamId, action) {
  const r = await api('POST', '/dependency-suggestions', { device_id: deviceId, upstream_id: upstreamId, action });
  if (r && r.ok) { toast(action === 'accept' ? 'Dependency added' : 'Dismissed', 'success'); loadDepSuggestions(); }
  else toast(r?.error || 'Failed', 'error');
}

// W5-1: LLDP topology suggestions (physical connected_to edges).
async function loadLldpSuggestions() {
  const box = document.getElementById('lldp-suggestions');
  if (!box) return;
  const r = await api('GET', '/lldp-suggestions');
  if (!r || !r.ok) { box.innerHTML = '<div class="c-muted">Not available.</div>'; return; }
  const s = r.suggestions || [];
  if (!s.length) { box.innerHTML = '<div class="c-muted">No LLDP topology suggestions (install lldpd on hosts to discover neighbors).</div>'; return; }
  box.innerHTML = '<div class="scrollable-table-wrap audit-scroll"><table class="data-table">'
    + '<thead><tr><th>Device</th><th>↔ Neighbor</th><th>Link</th><th></th></tr></thead><tbody>'
    + s.map(x => `<tr><td>${escHtml(x.device_name)}</td><td>${escHtml(x.peer_name)}</td>`
        + `<td class="fs-12">${escHtml(x.evidence)}</td>`
        + `<td class="nowrap"><button class="btn-icon cell-sm c-success" data-action="lldpSuggestAct" data-arg="${escAttr(x.device_id)}" data-arg2="${escAttr(x.peer_id)}" data-arg3="accept">Accept</button> `
        + `<button class="btn-icon cell-sm" data-action="lldpSuggestAct" data-arg="${escAttr(x.device_id)}" data-arg2="${escAttr(x.peer_id)}" data-arg3="dismiss">Dismiss</button></td></tr>`).join('')
    + '</tbody></table></div>';
}
async function lldpSuggestAct(deviceId, peerId, action) {
  const r = await api('POST', '/lldp-suggestions', { device_id: deviceId, peer_id: peerId, action });
  if (r && r.ok) { toast(action === 'accept' ? 'Topology edge added' : 'Dismissed', 'success'); loadLldpSuggestions(); }
  else toast(r?.error || 'Failed', 'error');
}

async function loadNetmap() {
  const data = await api('GET', '/network-map' + _netmapScopeQuery());
  if (!data) return;
  // populate the scope pickers (preserving the active selection)
  const sc = data.scopes || {}; const act = data.scope || {};
  _netmapFillScope('netmap-scope-site',  sc.sites,  act.site);
  _netmapFillScope('netmap-scope-group', sc.groups, act.group);
  _netmapFillScope('netmap-scope-tag',   sc.tags,   act.tag);
  // v3.0.5: guard against the demo / read-only API path that returns
  // `{}` (or `{error: ...}`) instead of the full shape. Previously
  // `data.nodes.map(...)` would throw "can't access property 'map',
  // data.nodes is undefined" and the page would render blank.
  _netmapData = {
    nodes:   Array.isArray(data.nodes)   ? data.nodes   : [],
    edges:   Array.isArray(data.edges)   ? data.edges   : [],
    tunnels: Array.isArray(data.tunnels) ? data.tunnels : [],
    dep_edges: Array.isArray(data.dep_edges) ? data.dep_edges : [],
  };
  _netmapDirty.clear();
  // Auto-layout for nodes without a saved position. We keep saved positions
  // exactly as the server returned them so a refresh shows the same picture.
  const w = document.getElementById('netmap-svg')?.clientWidth || 900;
  const byType = {};
  _netmapNodes = _netmapData.nodes.map(n => ({...n}));
  _netmapNodes.forEach(n => { (byType[n.type] = byType[n.type] || []).push(n); });
  const types = Object.keys(byType).sort();
  let yPos = 80;
  types.forEach(t => {
    const list = byType[t];
    const stepX = w / (list.length + 1);
    list.forEach((n, i) => {
      // Use saved position if present, otherwise fall back to auto-layout
      if (n.pos_x == null || n.pos_y == null) {
        n.x = stepX * (i + 1);
        n.y = yPos;
      } else {
        n.x = n.pos_x;
        n.y = n.pos_y;
      }
    });
    yPos += 120;
  });
  renderNetmap();
  const scoped = !!(act.site || act.group || act.tag);
  document.getElementById('netmap-stats').textContent =
    `${_netmapData.nodes.length}${scoped && data.total ? ' of ' + data.total : ''} node(s), ` +
    `${_netmapData.edges.length} link(s), ${_netmapData.tunnels.length} tunnel(s)` +
    (scoped ? ' — scoped' : '');
}

// SVG renderer — physical edges as solid lines, tunnels as dashed amber.
// Each node lives in a <g> that we can move with `transform=translate(...)`
// during drag, instead of regenerating innerHTML (which would orphan the
// pointer-captured element and limit drags to a single pointermove).
function renderNetmap() {
  const svg = document.getElementById('netmap-svg');
  if (!svg) return;
  if (!_netmapNodes.length) {
    svg.innerHTML = '<text x="50%" y="50%" fill="currentColor" opacity="0.6" font-size="13.5" text-anchor="middle">No devices yet. Enroll an agent or add an agentless device.</text>';
    return;
  }
  const lookup = Object.fromEntries(_netmapNodes.map(n => [n.id, n]));
  // Edges first so they're behind the nodes. We give each edge an id so
  // _netmapUpdateEdges() can locate and update its endpoints in place
  // during a drag without touching the node DOM.
  const edgeMarkup = (_netmapData.edges || []).map((e, i) => {
    const a = lookup[e.from], b = lookup[e.to];
    if (!a || !b) return '';
    // v6.1.1 (#71): a "discovered" edge (netscan-seen unmanaged host, not a
    // manually-set connected_to link) renders dotted + muted -- distinct
    // from a confirmed physical link, since it's an inferred/unconfirmed
    // relationship (this device's netscan saw that host on its subnet).
    if (e.kind === 'discovered') {
      return `<line data-edge-from="${escHtml(e.from)}" data-edge-to="${escHtml(e.to)}" data-edge-kind="discovered" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--muted)" stroke-width="1" stroke-dasharray="1 3" opacity="0.5"><title>Discovered by netscan: ${escHtml(a.name)}</title></line>`;
    }
    return `<line data-edge-from="${escHtml(e.from)}" data-edge-to="${escHtml(e.to)}" data-edge-kind="phys" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--border)" stroke-width="1.5" opacity="0.65"/>`;
  }).join('');
  const tunnelMarkup = (_netmapData.tunnels || []).map((t, i) => {
    const a = lookup[t.endpoints[0]], b = lookup[t.endpoints[1]];
    if (!a || !b) return '';
    return `<line data-edge-from="${escHtml(t.endpoints[0])}" data-edge-to="${escHtml(t.endpoints[1])}" data-edge-kind="tun" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--amber)" stroke-width="2" stroke-dasharray="6 4" opacity="0.85"><title>Tunnel: ${escHtml(a.name)} ↔ ${escHtml(b.name)}</title></line>`;
  }).join('');
  // v3.4.2: dependency edges (downstream → upstream), dashed violet. A red glow
  // when the upstream is offline flags the root cause at a glance.
  const depMarkup = (_netmapData.dep_edges || []).map(e => {
    const a = lookup[e.from], b = lookup[e.to];
    if (!a || !b) return '';
    const col = b.online ? '#a855f7' : 'var(--red)';
    return `<line data-edge-from="${escHtml(e.from)}" data-edge-to="${escHtml(e.to)}" data-edge-kind="dep" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${col}" stroke-width="2" stroke-dasharray="2 4" opacity="0.85"><title>${escHtml(a.name)} depends on ${escHtml(b.name)}${b.online ? '' : ' (UPSTREAM DOWN)'}</title></line>`;
  }).join('');
  // Nodes — single <g class="netmap-node"> per device. The shapes inside use
  // coordinates relative to the node's centre (0,0); the <g> itself is
  // positioned via `transform="translate(x, y)"`. This way a drag updates
  // a single attribute instead of rewriting the whole subtree.
  const nodeMarkup = _netmapNodes.map(n => {
    // v6.1.1 (#71): an unmanaged (netscan-discovered) host has no online/
    // offline concept -- it's a passive sighting, not a monitored device --
    // so it gets its own muted, dashed treatment instead of the green/red
    // health color.
    const isUnmanaged = n.type === 'unmanaged';
    const fill   = isUnmanaged ? 'var(--muted)' : (n.online ? 'var(--green)' : 'var(--red)');
    const stroke = isUnmanaged ? 'var(--muted)' : (n.agentless ? 'var(--amber)' : 'var(--accent)');
    const dash   = isUnmanaged ? ' stroke-dasharray="3 2"' : '';
    const r = 14;
    return `<g class="netmap-node isl-467" data-node-id="${escHtml(n.id)}" transform="translate(${n.x}, ${n.y})">
      <circle cx="0" cy="0" r="${r}" fill="${fill}" fill-opacity="0.18" stroke="${stroke}" stroke-width="2"${dash}/>
      <text x="0" y="4" font-size="10" fill="currentColor" text-anchor="middle" font-weight="600" pointer-events="none">${escHtml((n.type || '?').slice(0,3).toUpperCase())}</text>
      <text x="0" y="${r + 14}" font-size="11" fill="currentColor" text-anchor="middle" pointer-events="none">${escHtml(n.name)}</text>
      <text x="0" y="${r + 28}" font-size="10" fill="currentColor" opacity="0.55" text-anchor="middle" pointer-events="none">${escHtml(n.ip || '')}</text>
    </g>`;
  }).join('');
  svg.innerHTML = edgeMarkup + tunnelMarkup + depMarkup + nodeMarkup;
  netmapInstallDrag(svg);
}

// Update the visual position of a single node and any edges/tunnels touching
// it. Called from pointermove during a drag — does NOT rebuild innerHTML, so
// the node element with our captured pointer keeps existing.
function _netmapMoveNode(id, x, y) {
  // Update the working data so the next renderNetmap() (refresh, page
  // re-enter) shows the latest position.
  const n = _netmapNodes.find(x => x.id === id);
  if (!n) return;
  n.x = x; n.y = y;

  const svg = document.getElementById('netmap-svg');
  if (!svg) return;
  // Device IDs are [A-Za-z0-9_-] so attribute selectors don't need escaping.
  // Avoid CSS.escape() because it's missing on some older runtimes.
  const g = svg.querySelector(`.netmap-node[data-node-id="${id}"]`);
  if (g) g.setAttribute('transform', `translate(${x}, ${y})`);

  // Update every edge/tunnel touching this node — both as `from` and `to`.
  svg.querySelectorAll(`line[data-edge-from="${id}"]`).forEach(line => {
    line.setAttribute('x1', x); line.setAttribute('y1', y);
  });
  svg.querySelectorAll(`line[data-edge-to="${id}"]`).forEach(line => {
    line.setAttribute('x2', x); line.setAttribute('y2', y);
  });
}

// Hand-rolled drag. Listeners live on the SVG, not on each node — that way
// they survive any future re-render and pointer movement off the node circle
// (onto the label, into empty space) keeps tracking rather than stopping.
//
// We use pointer events for mouse + touch + stylus uniformly. Pointer
// capture is essential: it routes every move event to the original target
// even if the cursor leaves it, which is exactly what drag needs.
function netmapInstallDrag(svg) {
  // Wipe any previous handlers from a prior render
  if (svg.__netmapDragInstalled) return;
  svg.__netmapDragInstalled = true;

  let dragging = null;   // {id, offX, offY, moved, startEvtX, startEvtY}

  function svgPoint(evt) {
    // Convert client coords to SVG coords accounting for viewBox/scaling.
    const pt = svg.createSVGPoint();
    pt.x = evt.clientX; pt.y = evt.clientY;
    const ctm = svg.getScreenCTM();
    if (!ctm) return {x: evt.clientX, y: evt.clientY};
    const inv = ctm.inverse();
    return pt.matrixTransform(inv);
  }

  svg.addEventListener('pointerdown', (evt) => {
    if (evt.button !== 0) return;
    // Walk up to find the .netmap-node group (the actual click target may
    // be the inner <circle>).
    let target = evt.target;
    while (target && target !== svg && !(target.classList && target.classList.contains('netmap-node'))) {
      target = target.parentNode;
    }
    if (!target || target === svg) return;
    const id = target.getAttribute('data-node-id');
    const node = _netmapNodes.find(n => n.id === id);
    if (!node) return;
    evt.preventDefault();
    const p = svgPoint(evt);
    dragging = {
      id,
      offX: p.x - node.x,
      offY: p.y - node.y,
      moved: false,
      startEvtX: evt.clientX,
      startEvtY: evt.clientY,
      target,
    };
    target.style.cursor = 'grabbing';
    // Capture on the SVG, not the node — capture on a removed-and-replaced
    // element silently breaks. The SVG persists across re-renders.
    try { svg.setPointerCapture(evt.pointerId); } catch (e) {}
  });

  svg.addEventListener('pointermove', (evt) => {
    if (!dragging) return;
    const dx = evt.clientX - dragging.startEvtX;
    const dy = evt.clientY - dragging.startEvtY;
    if (!dragging.moved && (Math.abs(dx) > 4 || Math.abs(dy) > 4)) {
      dragging.moved = true;
    }
    if (!dragging.moved) return;
    const p = svgPoint(evt);
    _netmapMoveNode(dragging.id,
                    Math.round(p.x - dragging.offX),
                    Math.round(p.y - dragging.offY));
  });

  function endDrag(evt) {
    if (!dragging) return;
    const wasMoved = dragging.moved;
    const id = dragging.id;
    if (dragging.target) dragging.target.style.cursor = 'grab';
    try { svg.releasePointerCapture(evt.pointerId); } catch (e) {}
    dragging = null;
    if (wasMoved) {
      _netmapDirty.add(id);
      netmapSavePositionsDebounced();
    } else {
      // Pure click — open the device modal
      netmapNodeClick(id);
    }
  }
  svg.addEventListener('pointerup', endDrag);
  svg.addEventListener('pointercancel', endDrag);
}

// Debounced batch save — if you drag five nodes in a row we send one PUT,
// not five. 400ms of no further drags triggers the flush.
let _netmapSaveTimer = null;
function netmapSavePositionsDebounced() {
  clearTimeout(_netmapSaveTimer);
  _netmapSaveTimer = setTimeout(netmapFlushPositions, 400);
}

async function netmapFlushPositions() {
  if (!_netmapDirty.size) return;
  const positions = [];
  for (const id of _netmapDirty) {
    const n = _netmapNodes.find(x => x.id === id);
    if (n) positions.push({id, x: n.x, y: n.y});
  }
  _netmapDirty.clear();
  const r = await api('PUT', '/network-map/positions', {positions});
  if (!r || !r.ok) {
    toast('Failed to save positions — they may not survive refresh', 'error');
  }
}

function netmapNodeClick(deviceId) {
  // v6.1.1 (#71): an unmanaged (netscan-discovered) node has no device
  // record to open -- surface what we do know instead of a failed lookup.
  const n = _netmapNodes.find(x => x.id === deviceId);
  if (n && n.type === 'unmanaged') {
    toast(`Discovered host — ${n.ip || 'unknown IP'}${n.mac ? ' · ' + n.mac : ''}${n.hostname ? ' · ' + n.hostname : ''}. Not enrolled.`, 'info');
    return;
  }
  if (typeof openDeviceInfo === 'function') {
    openDeviceInfo(deviceId);
  } else {
    cmdbOpenAsset(deviceId);
  }
}

async function netmapEditOpen() {
  // Refresh data first so the editor has the current shape
  await loadNetmap();
  const body = document.getElementById('netmap-edit-body');
  // v6.1.1 (#71): unmanaged (netscan-discovered) nodes have no device
  // record, so they're not editable here -- excluded from both the row
  // list and the "connect to" / "depends on" option lists.
  const nodes = _netmapData.nodes.filter(n => n.type !== 'unmanaged');
  if (!nodes.length) {
    body.innerHTML = '<div class="empty-state">No devices to link.</div>';
    openModal('netmap-edit-modal');
    return;
  }
  // Build an option list of all devices for the dropdowns
  const optsHtml = '<option value="">— none —</option>' +
    nodes.map(n => `<option value="${escHtml(n.id)}">${escHtml(n.name)} (${escHtml(n.type || 'host')})</option>`).join('');
  body.innerHTML = `<div class="scrollable-table-wrap audit-scroll"><table class="w-full"><thead><tr class="isl-468"><th class="cell-m">Device</th><th class="cell-m">Type</th><th class="cell-m">Connected to (upstream)</th><th class="cell-m">Depends on <span class="meta-sm-nm">(alerts suppressed when down)</span></th></tr></thead><tbody>${
    nodes.map(n => {
      const cur = (_netmapData.edges.find(e => e.from === n.id) || {}).to || '';
      // Build per-row options where the current value is selected and self-link is removed
      const rowOpts = '<option value="">— none —</option>' +
        nodes.filter(o => o.id !== n.id).map(o =>
          `<option value="${escHtml(o.id)}"${o.id === cur ? ' selected' : ''}>${escHtml(o.name)} (${escHtml(o.type || 'host')})</option>`
        ).join('');
      const deps = (n.depends_on || []);
      const depOpts = nodes.filter(o => o.id !== n.id).map(o =>
        `<option value="${escHtml(o.id)}"${deps.includes(o.id) ? ' selected' : ''}>${escHtml(o.name)}</option>`).join('');
      return `<tr>
        <td class="isl-469">${escHtml(n.name)}</td>
        <td class="isl-470">${escHtml(n.type || 'host')}</td>
        <td class="cell-m"><select class="form-input netmap-link-sel device-combo w-full" data-device-id="${escHtml(n.id)}" data-original="${escHtml(cur)}" data-combo-placeholder="Search devices…">${rowOpts}</select></td>
        <td class="cell-m"><select multiple class="form-input netmap-dep-sel w-full" data-device-id="${escHtml(n.id)}" data-original="${escHtml(deps.join(','))}" size="3">${depOpts}</select></td>
      </tr>`;
    }).join('')
  }</tbody></table></div>`;
  openModal('netmap-edit-modal');
}

async function netmapEditSaveAll() {
  // v3.14.0: scope to select.* — the device-combo enhancement copies the
  // select's classes onto its companion <input>, so a bare '.netmap-link-sel'
  // would also match the combo input.
  const sels = Array.from(document.querySelectorAll('select.netmap-link-sel'));
  let changed = 0, failed = 0;
  for (const s of sels) {
    const deviceId = s.getAttribute('data-device-id');
    const orig = s.getAttribute('data-original') || '';
    const newVal = s.value || '';
    if (newVal === orig) continue;
    const r = await api('PUT', `/devices/${encodeURIComponent(deviceId)}/connected-to`, {connected_to: newVal});
    if (r && r.ok) {
      changed++;
      s.setAttribute('data-original', newVal);
    } else {
      failed++;
    }
  }
  // v3.4.2: save dependency changes (multi-select per row).
  const depSels = Array.from(document.querySelectorAll('select.netmap-dep-sel'));
  for (const s of depSels) {
    const deviceId = s.getAttribute('data-device-id');
    const orig = (s.getAttribute('data-original') || '').split(',').filter(Boolean).sort().join(',');
    const chosen = Array.from(s.selectedOptions).map(o => o.value).filter(Boolean);
    if (chosen.slice().sort().join(',') === orig) continue;
    const r = await api('PUT', `/devices/${encodeURIComponent(deviceId)}/depends-on`, {depends_on: chosen});
    if (r && r.ok) { changed++; s.setAttribute('data-original', chosen.join(',')); }
    else { failed++; }
  }
  if (changed) toast(`${changed} link(s) updated`, 'success');
  if (failed) toast(`${failed} link(s) failed to update`, 'error');
  if (!changed && !failed) toast('No changes', 'info');
  closeModal('netmap-edit-modal');
  loadNetmap();
}

// ── v1.11.1: tunnels (peer links) ────────────────────────────────────────────

async function netmapTunnelsOpen() {
  // Refresh node list so the dropdowns are current
  await loadNetmap();
  // Populate the From/To dropdowns
  const fromSel = document.getElementById('tun-from');
  const toSel   = document.getElementById('tun-to');
  const optHtml = '<option value="">— pick —</option>' +
    _netmapData.nodes.map(n => `<option value="${escHtml(n.id)}">${escHtml(n.name)} (${escHtml(n.type || 'host')})</option>`).join('');
  fromSel.innerHTML = optHtml;
  toSel.innerHTML   = optHtml;
  await tunnelRenderList();
  openModal('netmap-tunnels-modal');
}

async function tunnelRenderList() {
  const list = document.getElementById('tun-list');
  const tunnels = await api('GET', '/network-map/tunnels');
  if (!Array.isArray(tunnels) || !tunnels.length) {
    list.innerHTML = '<div class="empty-state-sm">No tunnels yet.</div>';
    return;
  }
  // Build a name lookup for friendlier rendering
  const nameOf = id => {
    const n = _netmapData.nodes.find(x => x.id === id);
    return n ? n.name : id;
  };
  list.innerHTML = tunnels.map(t => `<div class="isl-471">
    <div class="fw-500">${escHtml(nameOf(t.endpoints[0]))} <span class="c-amber">↔</span> ${escHtml(nameOf(t.endpoints[1]))}</div>
    <button class="btn-icon c-danger-outline" data-action="tunnelDelete" data-arg="${escAttr(t.id)}" title="Delete tunnel" aria-label="Delete tunnel"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
  </div>`).join('');
}

async function tunnelAdd() {
  const a = document.getElementById('tun-from').value;
  const b = document.getElementById('tun-to').value;
  if (!a || !b) { toast('Pick both endpoints', 'error'); return; }
  if (a === b)  { toast('Endpoints must differ',  'error'); return; }
  const r = await api('POST', '/network-map/tunnels', {endpoints: [a, b]});
  if (!r || !r.ok) {
    toast(r?.error || 'Add failed', 'error');
    return;
  }
  document.getElementById('tun-from').value = '';
  document.getElementById('tun-to').value = '';
  await tunnelRenderList();
  // Refresh the underlying netmap data so the dashed line shows immediately
  // when the modal closes
  await loadNetmap();
  await netmapTunnelsOpen.__refresh?.();   // no-op, kept for symmetry
}

async function tunnelDelete(id) {
  if (!await uiConfirm('Delete this tunnel?')) return;
  const r = await api('DELETE', '/network-map/tunnels/' + encodeURIComponent(id));
  if (!r || !r.ok) { toast('Delete failed', 'error'); return; }
  await tunnelRenderList();
  await loadNetmap();
}

async function netmapResetPositions() {
  if (!await uiConfirm('Clear all manual positions and revert to auto-layout?')) return;
  // Send null for every node — server treats that as "clear"
  const positions = _netmapData.nodes.map(n => ({id: n.id, x: null, y: null}));
  const r = await api('PUT', '/network-map/positions', {positions});
  if (!r || !r.ok) { toast('Failed to reset', 'error'); return; }
  toast('Positions cleared', 'info');
  await loadNetmap();
}

// ── TLS / DNS ────────────────────────────────────────────────────────────────
let _tlsTargets = [];

async function enterTLS() {
  await loadTLS();
}

async function loadTLS() {
  const tbody = document.getElementById('tls-tbody');
  tbody.innerHTML = _skeletonRows(8);   // v6.2.2: skeleton, not bare text (old line also had a broken </tbody> close)
  const data = await api('GET', '/tls/targets');
  _tlsTargets = Array.isArray(data) ? data : [];
  renderTLS();
  _loadCtWatch();
}

// W1-17: certificate-transparency watch — domain list lives in config.
async function _loadCtWatch() {
  const box = document.getElementById('ct-domains');
  if (!box) return;
  try {
    const cfg = await api('GET', '/config');
    box.value = (cfg?.ct_watch_domains || []).join('\n');
  } catch (e) { /* non-admin config read failure leaves the box empty */ }
}
async function saveCtWatch() {
  const box = document.getElementById('ct-domains');
  const res = document.getElementById('ct-watch-result');
  if (!box) return;
  const domains = box.value.split('\n').map(s => s.trim()).filter(Boolean);
  const r = await api('POST', '/config', { ct_watch_domains: domains });
  if (r && !r.error) {
    toast('CT watch saved', 'success');
    if (res) res.textContent = domains.length ? `Watching ${domains.length} domain${domains.length === 1 ? '' : 's'} — first check baselines silently.` : 'CT watch is off.';
    _loadCtWatch();
  } else {
    toast(r?.error || 'Failed', 'error');
    if (res) res.textContent = r?.error || 'Failed';
  }
}

// v1.11.5: TLS table now goes through tableCtl
let _tlsRegistered = false;
function _registerTlsTable() {
  if (_tlsRegistered) return;
  _tlsRegistered = true;
  tableCtl.register({
    name: 'tls',
    tbody: 'tls-tbody',
    filterInput: 'tls-filter',
    sortHeaders: 'tls-thead',
    colspan: 8,
    columns: ['status', 'host', 'port', 'days_left', 'expires_at', 'issuer', 'last_check'],
    getColumns: (t) => ({
      // Order matters here — sort 'critical' / 'warning' to top by mapping
      // them to numeric ranks rather than relying on alphabetical order.
      status:     ({critical: 0, error: 1, warning: 2, ok: 3}[t.status] ?? 9),
      host:       t.host || '',
      port:       t.port || 0,
      days_left:  (typeof t.days_left === 'number') ? t.days_left : 99999,
      expires_at: t.expires_at || 0,
      issuer:     t.issuer || '',
      last_check: t.last_check || 0,
    }),
    row: (t) => {
      const statusBadge = (() => {
        if (t.status === 'critical') return '<span class="c-red-bold">● critical</span>';
        if (t.status === 'warning')  return '<span class="c-amber-bold">● warn</span>';
        if (t.status === 'error')    return '<span class="c-red">● error</span>';
        if (t.status === 'ok')       return '<span class="c-green">● ok</span>';
        return '<span class="c-muted">— never scanned</span>';
      })();
      const daneBadge = (() => {
        if (!t.dane_check) return '';
        const s = t.dane_status || 'not_checked';
        const colours = { ok: 'var(--green)', mismatch: 'var(--amber)', insecure: 'var(--red)', error: 'var(--red)', missing: 'var(--muted)', not_checked: 'var(--muted)' };
        const labels  = { ok: 'DANE ok', mismatch: 'DANE mismatch', insecure: 'DANE insecure', error: 'DANE error', missing: 'DANE missing', not_checked: 'DANE pending' };
        return `<span class="isl-472" data-color="${colours[s] || 'var(--muted)'}">${labels[s] || s}</span>`;
      })();
      const expires = t.expires_at ? new Date(t.expires_at * 1000).toLocaleDateString() : '—';
      const lastChk = t.last_check ? new Date(t.last_check * 1000).toLocaleString() : '—';
      const days = (t.status === 'ok' || t.status === 'warning' || t.status === 'critical')
        ? `${t.days_left}d` : (t.dns_error ? 'DNS' : t.tls_error ? 'TLS' : '—');
      const issuer = (t.issuer || '').replace(/CN=/, '').split(',')[0] || '—';
      const labelHtml = t.label ? `<span class="isl-289">${escHtml(t.label)}</span>` : '';
      const connectHtml = t.connect_address ? `<div class="isl-473">via ${escHtml(t.connect_address)}</div>` : '';
      const starttlsHtml = (t.starttls && t.starttls !== 'none')
        ? `<span class="isl-474">${escHtml(t.starttls)}</span>`
        : '';
      // v2.1.5: AITriage only on warning/critical/error — no point asking
      // about cert lifecycle on a healthy 90-days-left target.
      const aiBtn = (t.status === 'warning' || t.status === 'critical' || t.status === 'error')
        ? `<button class="btn-icon isl-475" data-action="aiExplainTls" data-stop-prop="1" data-arg="${escAttr(t.host)}" data-arg2="${t.port||443}" data-arg3="${t.expires_at||0}" data-arg4="${escAttr(t.issuer||'')}" data-arg5="starttls=${escAttr(t.starttls||'none')}" title="AI: triage this cert">${_icon('sparkles',14)}</button>`
        : '';
      return `<tr data-action="tlsDetailOpen" data-arg="${escAttr(t.id)}" class="pointer">
        <td>${statusBadge}${daneBadge}</td>
        <td class="ff-mono">${escHtml(t.host)}${labelHtml}${starttlsHtml}${connectHtml}</td>
        <td class="isl-476">${t.port}</td>
        <td class="fw-500">${days}</td>
        <td class="hint">${expires}</td>
        <td class="hint">${escHtml(issuer.slice(0,30))}</td>
        <td class="hint-nowrap">${lastChk}</td>
        <td data-stop-prop="1" >${aiBtn}<button class="btn-icon" title="Edit" data-action="tlsEditOpen" data-arg="${escAttr(t.id)}">${_icon('edit',14)}</button><button class="btn-icon c-danger-outline" title="Delete" data-action="tlsDelete" data-arg="${escAttr(t.id)}" data-arg2="${escAttr(t.host)}" >${_icon('trash',14)}</button></td>
      </tr>`;
    },
    emptyMsg: 'No TLS targets yet. Click "+ Add target" to start.',
    emptyMsgFiltered: 'No TLS targets match the filter.',
  });
}

function renderTLS() {
  _registerTlsTable();
  // Update summary first so it reflects total counts, not filtered counts —
  // the summary lives outside the table and shows fleet-wide health.
  let crit = 0, warn = 0, err = 0, ok = 0;
  for (const t of _tlsTargets) {
    if (t.status === 'critical') crit++;
    else if (t.status === 'warning') warn++;
    else if (t.status === 'error') err++;
    else if (t.status === 'ok') ok++;
  }
  if (_tlsTargets.length) {
    document.getElementById('tls-status-summary').textContent =
      `${_tlsTargets.length} target(s): ${ok} OK · ${warn} warn · ${crit} critical · ${err} error`;
  } else {
    document.getElementById('tls-status-summary').textContent = '';
  }
  tableCtl.render('tls', _tlsTargets);
}

// v3.3.0: TLS modal shared between Add and Edit. _tlsEditId holds the
// target id when editing, or null for a new target.
let _tlsEditId = null;
function tlsAddOpen() {
  _tlsEditId = null;
  const t = document.querySelector('#tls-add-modal .modal-title');
  if (t) t.textContent = 'Add TLS target';
  document.getElementById('tls-add-host').value = '';
  document.getElementById('tls-add-connect-addr').value = '';
  document.getElementById('tls-add-starttls').value = 'auto';
  document.getElementById('tls-add-port').value = '443';
  document.getElementById('tls-add-warn').value = '14';
  document.getElementById('tls-add-crit').value = '3';
  document.getElementById('tls-add-label').value = '';
  document.getElementById('tls-add-dane').checked = false;
  openModal('tls-add-modal');
  setTimeout(() => document.getElementById('tls-add-host').focus(), 50);
}

function tlsEditOpen(id) {
  const target = _tlsTargets.find(x => x.id === id);
  if (!target) { toast('Target not found', 'error'); return; }
  _tlsEditId = id;
  const t = document.querySelector('#tls-add-modal .modal-title');
  if (t) t.textContent = 'Edit TLS target';
  document.getElementById('tls-add-host').value          = target.host || '';
  document.getElementById('tls-add-connect-addr').value  = target.connect_address || '';
  document.getElementById('tls-add-starttls').value      = target.starttls || 'auto';
  document.getElementById('tls-add-port').value          = String(target.port || 443);
  document.getElementById('tls-add-warn').value          = String(target.warn_days ?? 14);
  document.getElementById('tls-add-crit').value          = String(target.crit_days ?? 3);
  document.getElementById('tls-add-label').value         = target.label || '';
  document.getElementById('tls-add-dane').checked        = !!target.dane_check;
  openModal('tls-add-modal');
}

async function tlsAddSave() {
  const body = {
    host:            document.getElementById('tls-add-host').value.trim(),
    connect_address: document.getElementById('tls-add-connect-addr').value.trim(),
    starttls:        document.getElementById('tls-add-starttls').value || 'auto',
    port:            parseInt(document.getElementById('tls-add-port').value, 10) || 443,
    warn_days:       parseInt(document.getElementById('tls-add-warn').value, 10),
    crit_days:       parseInt(document.getElementById('tls-add-crit').value, 10),
    label:           document.getElementById('tls-add-label').value.trim(),
    dane_check:      document.getElementById('tls-add-dane').checked,
  };
  if (!body.host) { toast('Host required', 'error'); return; }
  const r = _tlsEditId
    ? await api('PUT',  '/tls/targets/' + encodeURIComponent(_tlsEditId), body)
    : await api('POST', '/tls/targets', body);
  if (!r || !r.ok) { toast(r?.error || 'Save failed', 'error'); return; }
  closeModal('tls-add-modal');
  toast(_tlsEditId ? 'Target updated' : 'Target added — click "Scan now" to probe it', 'success');
  _tlsEditId = null;
  loadTLS();
}

async function tlsDelete(id, host) {
  if (!await uiConfirm(`Remove TLS target ${host}?`)) return;
  const r = await api('DELETE', '/tls/targets/' + encodeURIComponent(id));
  if (!r || !r.ok) { toast('Delete failed', 'error'); return; }
  toast('Target removed', 'info');
  loadTLS();
}

async function tlsScanNow() {
  toast('Probing — this can take a while for many targets', 'info');
  const r = await api('POST', '/tls/scan');
  if (!r || !r.ok) { toast('Scan failed', 'error'); return; }
  toast(`Scanned ${r.scanned} target(s)`, 'success');
  loadTLS();
}

function tlsDetailOpen(id) {
  const t = _tlsTargets.find(x => x.id === id);
  if (!t) return;
  document.getElementById('tls-detail-title').textContent = `${t.host}:${t.port}`;
  const fmt = (v, fallback) => v ? escHtml(v) : `<span class="c-muted">${fallback}</span>`;
  const sans = (t.san && t.san.length)
    ? t.san.map(s => `<code class="isl-477">${escHtml(s)}</code>`).join('')
    : '<span class="c-muted">none</span>';
  const errs = [
    t.dns_error    ? `<div class="isl-478">DNS: ${escHtml(t.dns_error)}</div>`    : '',
    t.tls_error    ? `<div class="isl-478">TLS: ${escHtml(t.tls_error)}</div>`    : '',
    t.verify_error ? `<div class="isl-479">Verification: ${escHtml(t.verify_error)}</div>` : '',
  ].join('');

  // v1.11.2: hostname-match indicator. Useful when probing by IP — helps
  // distinguish "wrong cert" from "right cert, wrong IP."
  const hostnameMatchHtml = (() => {
    if (t.hostname_match === null || t.hostname_match === undefined) {
      return '<span class="c-muted">—</span>';
    }
    return t.hostname_match
      ? '<span class="c-green">✓ matches</span>'
      : '<span class="c-amber">✗ no match</span>';
  })();

  // Connect-address row only renders when overridden — otherwise it's noise
  const connectAddrRow = t.connect_address
    ? `<div class="c-muted">Connect address</div><div class="ff-mono">${escHtml(t.connect_address)}</div>`
    : '';

  // STARTTLS row only renders when not 'none' — direct TLS doesn't need a label
  const starttlsRow = (t.starttls && t.starttls !== 'none')
    ? `<div class="c-muted">STARTTLS</div><div class="ff-mono">${escHtml(t.starttls.toUpperCase())}</div>`
    : '';

  // DANE block — render the records in a compact table when present.
  // Status colour mirrors the regular cert status semantics:
  //   ok        green
  //   missing   muted ("not configured")
  //   insecure  red ("found but DNSSEC failed")
  //   mismatch  amber ("found but didn't match")
  //   error     red (DNS lookup failed, etc)
  //   not_checked  muted (DANE not enabled for this target)
  let daneHtml = '';
  if (t.dane_check || t.dane_status === 'ok' || t.dane_status === 'mismatch' || t.dane_status === 'insecure') {
    const daneStatusColors = {
      ok:          'var(--green)',
      mismatch:    'var(--amber)',
      insecure:    'var(--red)',
      error:       'var(--red)',
      missing:     'var(--muted)',
      not_checked: 'var(--muted)',
    };
    const daneStatusText = {
      ok:          '✓ records found and cert matches',
      mismatch:    '✗ records published but cert does not match',
      insecure:    '✗ records found but DNSSEC validation failed',
      error:       '✗ DNS lookup failed',
      missing:     'No TLSA records published',
      not_checked: 'Not enabled for this target',
    };
    const status = t.dane_status || 'not_checked';
    const colour = daneStatusColors[status] || 'var(--muted)';
    const text   = daneStatusText[status]   || status;
    let recordsHtml = '';
    if ((t.dane_records || []).length) {
      recordsHtml = `<div class="scrollable-table-wrap audit-scroll"><table class="isl-480">
        <thead><tr class="isl-481">
          <th class="isl-44">Usage</th>
          <th class="isl-44">Selector</th>
          <th class="isl-44">Match</th>
          <th class="isl-44">Data</th>
        </tr></thead><tbody>
        ${t.dane_records.map(r => `<tr>
          <td class="isl-44">${escHtml(String(r.usage ?? ''))}</td>
          <td class="isl-44">${escHtml(String(r.selector ?? ''))}</td>
          <td class="isl-44">${escHtml(String(r.matching_type ?? ''))}</td>
          <td class="isl-482">${escHtml(String(r.data || '').slice(0, 64))}${(r.data || '').length > 64 ? '…' : ''}</td>
        </tr>`).join('')}
        </tbody></table></div>`;
    }
    daneHtml = `<div class="isl-483">
      <div class="isl-421">DANE / TLSA</div>
      <div class="isl-484" data-color="${colour}">${escHtml(text)}</div>
      ${t.dane_error ? `<div class="isl-485">${escHtml(t.dane_error)}</div>` : ''}
      ${recordsHtml}
    </div>`;
  }

  // master-improvement-scoping #99: intermediates + root, when the stdlib
  // exposed them (Python 3.13+'s get_unverified_chain(); empty on older
  // Python or a chain-of-one server — both normal, not shown as an error).
  const chainHtml = (t.chain && t.chain.length)
    ? `<div class="isl-483">
        <div class="isl-421">Full chain (${t.chain.length} intermediate${t.chain.length > 1 ? 's' : ''}/root)</div>
        <div class="scrollable-table-wrap audit-scroll"><table class="isl-480">
          <thead><tr class="isl-481"><th class="isl-44">Subject</th><th class="isl-44">Issuer</th><th class="isl-44">Expires</th></tr></thead>
          <tbody>${t.chain.map(c => `<tr>
            <td class="isl-482">${escHtml(c.subject || '—')}</td>
            <td class="isl-482">${escHtml(c.issuer || '—')}</td>
            <td class="isl-44">${c.expires_at ? new Date(c.expires_at * 1000).toLocaleDateString() : '—'}</td>
          </tr>`).join('')}</tbody>
        </table></div>
      </div>`
    : '';

  const body = document.getElementById('tls-detail-body');
  body.innerHTML = `
    <div class="isl-486">
      <div class="c-muted">Host (SNI)</div><div class="ff-mono">${escHtml(t.host)}:${t.port}</div>
      ${connectAddrRow}
      ${starttlsRow}
      <div class="c-muted">Hostname match</div><div>${hostnameMatchHtml}</div>
      <div class="c-muted">Label</div><div>${fmt(t.label, '—')}</div>
      <div class="c-muted">Status</div><div>${escHtml(t.status)}</div>
      <div class="c-muted">Days left</div><div>${t.days_left}d</div>
      <div class="c-muted">Expires</div><div>${t.expires_at ? new Date(t.expires_at*1000).toLocaleString() : '—'}</div>
      <div class="c-muted">Issuer</div><div>${fmt(t.issuer, '—')}</div>
      <div class="c-muted">Subject</div><div>${fmt(t.subject, '—')}</div>
      <div class="c-muted">SAN</div><div>${sans}</div>
      <div class="c-muted">DNS A/AAAA</div><div class="ff-mono">${(t.addresses || []).map(escHtml).join(', ') || '—'}</div>
      <div class="c-muted">Warn / Critical</div><div>${t.warn_days}d / ${t.crit_days}d</div>
    </div>
    ${errs}
    ${chainHtml}
    ${daneHtml}
  `;
  openModal('tls-detail-modal');
}

// ── Agentless devices (modal opener used from Devices page) ──────────────────

async function agentlessAddOpen(prefill) {
  // prefill (optional): {name, hostname, ip, mac} — used by the network-map
  // "Add as device" cross-link so a discovered host lands pre-populated.
  prefill = prefill || {};
  document.getElementById('al-name').value = prefill.name || '';
  document.getElementById('al-hostname').value = prefill.hostname || '';
  document.getElementById('al-ip').value = prefill.ip || '';
  document.getElementById('al-mac').value = prefill.mac || '';
  document.getElementById('al-group').value = '';
  document.getElementById('al-notes').value = prefill.ip ? `Imported from LAN discovery (${prefill.ip})` : '';
  document.getElementById('al-type').value = '';
  document.getElementById('al-status').checked = true;
  // Populate connected-to dropdown
  const sel = document.getElementById('al-connected-to');
  sel.innerHTML = '<option value="">— none —</option>';
  if (Array.isArray(devices)) {
    for (const d of devices) {
      const opt = document.createElement('option');
      opt.value = d.id;
      opt.textContent = `${d.name} (${d.device_type || (d.agentless ? 'other' : 'host')})`;
      sel.appendChild(opt);
    }
  }
  openModal('agentless-add-modal');
  setTimeout(() => document.getElementById('al-name').focus(), 50);
}

async function agentlessSave() {
  const body = {
    name:          document.getElementById('al-name').value.trim(),
    hostname:      document.getElementById('al-hostname').value.trim(),
    ip:            document.getElementById('al-ip').value.trim(),
    mac:           document.getElementById('al-mac').value.trim(),
    group:         document.getElementById('al-group').value.trim(),
    notes:         document.getElementById('al-notes').value,
    device_type:   document.getElementById('al-type').value || '',
    connected_to:  document.getElementById('al-connected-to').value || '',
    manual_status: document.getElementById('al-status').checked,
  };
  if (!body.name) { toast('Name required', 'error'); return; }
  const r = await api('POST', '/devices/agentless', body);
  if (!r || !r.ok) { toast(r?.error || 'Failed to add', 'error'); return; }
  closeModal('agentless-add-modal');
  toast(`Added ${escHtml(body.name)}`, 'success');
  if (typeof loadDevices === 'function') loadDevices();
}


// ══════════════════════════════════════════════════════════════════════════════
// v1.11.2: Shared link dashboard
// ══════════════════════════════════════════════════════════════════════════════
// Card grid grouped by category. Internal links (LAN/VPN-only) get an amber
// border to distinguish from external links — same visual language as the
// network map (amber = "different, special, doesn't reach the internet").
//
// Edit mode is a UI toggle that surfaces edit/delete buttons on each card.
// We deliberately keep the cards mouse-friendly when not in edit mode — a
// click anywhere on the card opens the link in a new tab. Adding edit
// buttons to every card all the time clutters the dashboard for the 99%
// of the time users want to click links, not edit them.

let _linksData = {links: [], categories: []};
let _linksEditMode = false;

function showLinksPage() { showPage('links'); }

async function enterLinks() {
  await loadLinks();
}

async function loadLinks() {
  const data = await api('GET', '/links');
  if (!data) return;
  _linksData = data;
  // Update the datalist for the add/edit modal's category autocomplete
  const dl = document.getElementById('links-category-datalist');
  if (dl) {
    dl.innerHTML = (data.categories || []).map(c => `<option value="${escHtml(c)}">`).join('');
  }
  renderLinks();
}

function renderLinks() {
  const grid = document.getElementById('links-grid');
  if (!grid) return;
  const all = _linksData.links || [];
  const q = (document.getElementById('links-search')?.value || '').trim().toLowerCase();
  const scopeFilter = document.getElementById('links-scope-filter')?.value || '';

  // Apply filters
  const filtered = all.filter(l => {
    if (scopeFilter && l.scope !== scopeFilter) return false;
    if (q) {
      const hay = `${l.title} ${l.url} ${l.description} ${l.category}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (!filtered.length) {
    if (!all.length) {
      grid.innerHTML = '<div class="isl-487">No links yet. Click "+ Add link" to start.</div>';
    } else {
      grid.innerHTML = '<div class="isl-487">No links match the current filter.</div>';
    }
    return;
  }

  // Group by category
  const byCat = {};
  for (const l of filtered) {
    (byCat[l.category] = byCat[l.category] || []).push(l);
  }
  // Render each category as a section. Sort categories case-insensitively
  // but keep "Uncategorised" last regardless — it's the catch-all bucket.
  const cats = Object.keys(byCat).sort((a, b) => {
    if (a === 'Uncategorised') return 1;
    if (b === 'Uncategorised') return -1;
    return a.toLowerCase().localeCompare(b.toLowerCase());
  });

  grid.innerHTML = cats.map(cat => {
    const items = byCat[cat];
    const cards = items.map(l => _renderLinkCard(l)).join('');
    return `<div>
      <div class="isl-488">
        <h3 class="isl-489">${escHtml(cat)}</h3>
        <span class="isl-490">${items.length}</span>
        <div class="isl-491"></div>
      </div>
      <div class="isl-492">${cards}</div>
    </div>`;
  }).join('');
}

function _renderLinkCard(l) {
  const isInternal = l.scope === 'internal';
  const borderColor = isInternal ? 'var(--amber)' : 'var(--accent)';
  const borderStyle = isInternal ? 'dashed' : 'solid';
  const scopeBadge = isInternal
    ? '<span class="isl-493">Internal</span>'
    : '<span class="isl-494">External</span>';

  // Display the URL's hostname (stripped) for visual reference. Falls back
  // to the full URL if it can't be parsed.
  let displayUrl = l.url;
  try {
    const u = new URL(l.url);
    displayUrl = u.hostname + (u.pathname !== '/' ? u.pathname : '');
  } catch (e) { /* keep original */ }

  // Edit-mode actions overlay the bottom-right corner. In normal mode the
  // entire card is clickable; in edit mode the click is intercepted to
  // avoid accidentally opening the link while editing.
  const editButtons = _linksEditMode
    ? `<div class="isl-495">
         <button class="btn-icon badge-xs" data-stop-prop="1" data-action="linkEditOpen" data-arg="${escAttr(l.id)}" >Edit</button>
         <button class="btn-icon isl-459" data-stop-prop="1" data-action="linkDelete" data-arg="${escAttr(l.id)}" data-arg2="${escAttr(l.title)}" >Delete</button>
       </div>`
    : '';

  // The whole card is the click target when not in edit mode. We use an
  // <a> wrapper rather than onclick=window.open so middle-click and
  // ctrl-click work naturally for power users.
  const cardInner = `<div
    title="${escHtml(l.description || l.url)}" class="isl-496 ${_linksEditMode ? 'edit-mode' : ''}" data-bd-style="${borderStyle}" data-bd-color="${borderColor}">
    <div>
      <div class="isl-497">
        <div class="isl-498">${escHtml(l.title)}</div>
        ${scopeBadge}
      </div>
      <div class="isl-499">${escHtml(displayUrl)}</div>
      ${l.description ? `<div class="isl-500">${escHtml(l.description)}</div>` : ''}
    </div>
    ${editButtons}
  </div>`;

  if (_linksEditMode) {
    // No anchor — clicks go through stopPropagation on edit buttons above.
    return cardInner;
  }
  return `<a href="${_safeHttpHref(l.url)}" target="_blank" rel="noopener noreferrer" class="isl-501">${cardInner}</a>`;
}

function linksToggleEditMode() {
  _linksEditMode = !_linksEditMode;
  const btn = document.getElementById('links-edit-toggle');
  if (btn) {
    btn.textContent = _linksEditMode ? 'Done editing' : 'Edit mode';
    btn.style.background = _linksEditMode ? 'rgba(59,126,255,0.12)' : '';
    btn.style.borderColor = _linksEditMode ? 'var(--accent)' : '';
    btn.style.color = _linksEditMode ? 'var(--accent)' : '';
  }
  renderLinks();
}

function linkAddOpen() {
  document.getElementById('link-edit-mode').value = 'add';
  document.getElementById('link-edit-id').value = '';
  document.getElementById('link-edit-title').textContent = 'Add link';
  document.getElementById('link-edit-title-input').value = '';
  document.getElementById('link-edit-url').value = '';
  document.getElementById('link-edit-category').value = '';
  document.getElementById('link-edit-description').value = '';
  // Reset radio to 'external' default
  const ext = document.querySelector('input[name="link-edit-scope"][value="external"]');
  if (ext) ext.checked = true;
  openModal('link-edit-modal');
  setTimeout(() => document.getElementById('link-edit-title-input').focus(), 50);
}

function linkEditOpen(linkId) {
  const l = (_linksData.links || []).find(x => x.id === linkId);
  if (!l) { toast('Link not found', 'error'); return; }
  document.getElementById('link-edit-mode').value = 'edit';
  document.getElementById('link-edit-id').value = linkId;
  document.getElementById('link-edit-title').textContent = 'Edit link';
  document.getElementById('link-edit-title-input').value = l.title || '';
  document.getElementById('link-edit-url').value = l.url || '';
  document.getElementById('link-edit-category').value = (l.category && l.category !== 'Uncategorised') ? l.category : '';
  document.getElementById('link-edit-description').value = l.description || '';
  const target = document.querySelector(`input[name="link-edit-scope"][value="${l.scope || 'external'}"]`);
  if (target) target.checked = true;
  openModal('link-edit-modal');
}

async function linkSave() {
  const mode = document.getElementById('link-edit-mode').value;
  const id   = document.getElementById('link-edit-id').value;
  const scopeRadio = document.querySelector('input[name="link-edit-scope"]:checked');
  const body = {
    title:       document.getElementById('link-edit-title-input').value.trim(),
    url:         document.getElementById('link-edit-url').value.trim(),
    category:    document.getElementById('link-edit-category').value.trim(),
    description: document.getElementById('link-edit-description').value.trim(),
    scope:       scopeRadio ? scopeRadio.value : 'external',
  };
  if (!body.title) { toast('Title required', 'error'); return; }
  if (!body.url)   { toast('URL required', 'error'); return; }

  let r;
  if (mode === 'edit' && id) {
    r = await api('PUT', '/links/' + encodeURIComponent(id), body);
  } else {
    r = await api('POST', '/links', body);
  }
  if (!r || !r.ok) { toast(r?.error || 'Save failed', 'error'); return; }
  closeModal('link-edit-modal');
  toast(mode === 'edit' ? 'Link updated' : 'Link added', 'success');
  loadLinks();
}

async function linkDelete(linkId, title) {
  if (!await uiConfirm(`Delete link "${title}"?`)) return;
  const r = await api('DELETE', '/links/' + encodeURIComponent(linkId));
  if (!r || !r.ok) { toast('Delete failed', 'error'); return; }
  toast('Link deleted', 'info');
  loadLinks();
}


// CMDB active-tab styling lives in styles.css (.cmdb-tab-btn.active) —
// dynamic <style> injection was blocked by CSP after L1 (no 'unsafe-inline').

// Helper for CMDB rendering — escapes both quote styles since we interpolate
// user-supplied labels into single-quoted onclick attributes. The project's
// own escHtml() doesn't escape single quotes.
function _cmdbEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ── v5.0.0: Network metrics (per-device throughput, scoped) ──────────────────
// Fleet-wide RX/TX or rolled up by group / tag / site (a site = a customer).
// Data from /api/network-metrics (agent `network_io` samples). Mirrors the NOC
// board's segmented-scope pattern.
let _netMetricsBy   = 'fleet';
let _netMetricsData = null;   // last response, so the sort re-render is local

function netMetricsBy(by) {
  if (!['fleet', 'group', 'tag', 'site'].includes(by)) by = 'fleet';
  _netMetricsBy = by;
  document.querySelectorAll('#netmetrics-by button').forEach(b =>
    b.classList.toggle('active', b.dataset.arg === by));
  loadNetMetrics();
}

async function loadNetMetrics() {
  const body = document.getElementById('netmetrics-body');
  if (!body) return;
  // eager sort wire-up so the ↕ indicator shows before data arrives
  tableCtl.wireSortOnly('netmetrics-thead', 'netmetrics', _renderNetMetricsBody);
  const data = await api('GET', '/network-metrics?by=' + encodeURIComponent(_netMetricsBy));
  if (!data || !data.totals) { body.innerHTML = '<div class="c-red">Failed to load network metrics.</div>'; return; }
  _netMetricsData = data;
  _renderNetMetricsBody();
}

function _renderNetMetricsBody() {
  const body = document.getElementById('netmetrics-body');
  if (!body || !_netMetricsData) return;
  const data = _netMetricsData;
  const t = data.totals || {};
  const stat = (label, val, cls) =>
    `<div class="board-stat"><span class="meta-label">${escHtml(label)}</span><span class="big ${cls || ''}">${val}</span></div>`;
  const vitals = `<div class="board-vitals">
    ${stat('Total RX', _fmtBps(t.rx_bps))}
    ${stat('Total TX', _fmtBps(t.tx_bps))}
    ${stat('Reporting', (t.reporting || 0) + ' / ' + (t.devices || 0))}
  </div>`;

  let tilesHtml = '';
  if (_netMetricsBy !== 'fleet' && (data.tiles || []).length) {
    const lbl = _netMetricsBy.charAt(0).toUpperCase() + _netMetricsBy.slice(1);
    tilesHtml = `<div class="dash-card mb-16"><div class="section-title">By ${escHtml(lbl)}</div>
      <div class="scrollable-table-wrap audit-scroll"><table><thead><tr>
        <th scope="col">${escHtml(lbl)}</th><th scope="col" class="ta-right">RX</th>
        <th scope="col" class="ta-right">TX</th><th scope="col" class="ta-right">Devices</th>
      </tr></thead><tbody>` +
      data.tiles.map(ti => `<tr><td>${escHtml(ti.name)}</td>
        <td class="ta-right mono-12">${_fmtBps(ti.rx_bps)}</td>
        <td class="ta-right mono-12">${_fmtBps(ti.tx_bps)}</td>
        <td class="ta-right">${ti.devices}</td></tr>`).join('') +
      `</tbody></table></div></div>`;
  }

  const rows = tableCtl.sortRows('netmetrics', data.devices || [], (r) => ({
    name:  (r.name || '').toLowerCase(),
    group: (r.group || '').toLowerCase(),
    site:  (r.site || '').toLowerCase(),
    rx:    r.rx_bps || 0,
    tx:    r.tx_bps || 0,
    iface: (r.ifaces && r.ifaces[0] ? r.ifaces[0].iface : '') || '',
  }));
  const devTable = `<div class="dash-card"><div class="section-title">Per-device throughput <span class="meta-sm">(top ${(data.devices || []).length})</span></div>
    <div class="scrollable-table-wrap audit-scroll"><table id="netmetrics-table"><thead id="netmetrics-thead"><tr>
      <th scope="col" data-col="name">Device</th><th scope="col" data-col="group">Group</th>
      <th scope="col" data-col="site">Site</th>
      <th scope="col" data-col="rx" class="ta-right">RX</th><th scope="col" data-col="tx" class="ta-right">TX</th>
      <th scope="col" data-col="iface">Top interface</th>
    </tr></thead><tbody>` +
    (rows.length ? rows.map(r => {
      const top = (r.ifaces && r.ifaces[0]) ? r.ifaces[0] : null;
      const flag = r.decommissioned
        ? ' <span class="patch-badge fs-10 c-muted" title="Decommissioned">decomm</span>'
        : (!r.monitored ? ' <span class="patch-badge fs-10 c-muted" title="Unmonitored — collecting, no alerts">unmon</span>' : '');
      return `<tr class="${r.decommissioned ? 'decommissioned' : ''}">
        <td>${escHtml(r.name)}${flag}</td>
        <td class="hint">${escHtml(r.group || '—')}</td>
        <td class="hint">${escHtml(r.site || '—')}</td>
        <td class="ta-right mono-12">${_fmtBps(r.rx_bps)}</td>
        <td class="ta-right mono-12">${_fmtBps(r.tx_bps)}</td>
        <td class="mono-12">${top ? escHtml(top.iface) : '<span class="c-muted">—</span>'}</td></tr>`;
    }).join('') : '<tr><td colspan="6" class="empty-state">No network throughput reported yet — agents send it on their next heartbeat.</td></tr>') +
    `</tbody></table></div></div>`;

  body.innerHTML = vitals + tilesHtml + devTable;
  tableCtl.wireSortOnly('netmetrics-thead', 'netmetrics', _renderNetMetricsBody);
}
