// app-vpn.js — page module extracted from app.js (buildless classic script; all
// symbols stay global, same as the rest of the client JS).
// WG Access (WireGuard) tunnels + clients. The in-browser keypair
// helper stays in wg-access.js; this is the page UI around it.

// ─── v5.2.0 AccessMatters: WG Access (WireGuard road-warrior VPN) ─────────────
// Tunnels = WireGuard hub interfaces; clients = per-device peers issued under a
// tunnel. The keypair for a client is generated IN THE BROWSER (window.WGAccess)
// so the private key never reaches the server — only the public key is POSTed.
let _vpnTunnelsRegistered = false;
let _vpnClientsRegistered = false;
let _vpnTunnelsCache = [];
let _vpnClientsCache = [];
let _vpnSelectedTunnel = null;      // {id, name, …} of the tunnel whose clients are shown
let _vpnTunnelEditId = null;        // null = create mode
let _vpnLastClient = null;          // {name, conf} of the just-created client (for download/copy)

const _VPN_TTL_SECONDS = { minutes: 60, hours: 3600, days: 86400, weeks: 604800, years: 31536000 };

function _vpnReachLabel(t) {
  const v = t.reach_scope_value || '';
  let base;
  switch (t.reach_scope_type) {
    case 'all':   base = 'Entire fleet'; break;
    case 'site':  base = 'Site: ' + v; break;
    case 'group': base = 'Group: ' + v; break;
    case 'tag':   base = 'Tag: ' + v; break;
    default:      base = 'Dashboard only';
  }
  return base + (t.allow_internet ? ' · full tunnel' : '');
}

function _vpnExpiryCell(ts) {
  if (!ts) return '<span class="hint">never</span>';
  const now = Math.floor(Date.now() / 1000);
  const cls = ts <= now ? 'c-red' : (ts <= now + 7 * 86400 ? 'c-amber' : 'hint');
  const pre = ts <= now ? 'expired ' : '';
  return `<span class="${cls}">${pre}${_fmtAbsDate(ts)}</span>`;
}

function _vpnAge(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 90) return s + 's';
  if (s < 5400) return Math.round(s / 60) + 'm';
  if (s < 172800) return Math.round(s / 3600) + 'h';
  return Math.round(s / 86400) + 'd';
}

// Read a number + unit TTL control into an absolute unix expiry (or null = never).
function _vpnReadTtl(numId, unitId) {
  const unit = document.getElementById(unitId)?.value || 'never';
  if (unit === 'never') return null;
  const n = parseInt(document.getElementById(numId)?.value || '', 10);
  if (!n || n <= 0) return null;
  const secs = _VPN_TTL_SECONDS[unit] || 0;
  if (!secs) return null;
  return Math.floor(Date.now() / 1000) + n * secs;
}

function _registerVpnTunnelsTable() {
  if (_vpnTunnelsRegistered) return;
  _vpnTunnelsRegistered = true;
  tableCtl.register({
    name: 'vpn_tunnels',
    tbody: 'vpn-tunnels-tbody',
    sortHeaders: 'vpn-tunnels-thead',
    colspan: 6,
    columns: ['name', 'reach', 'clients', 'port', 'expires'],
    getColumns: (t) => ({
      name:    t.name || '',
      reach:   _vpnReachLabel(t),
      clients: t.client_count || 0,
      port:    t.listen_port || 0,
      expires: t.expires_at || 0,
    }),
    row: (t) => {
      const id = escAttr(t.id);
      const nm = escHtml(t.name || t.iface || t.id);
      const dis = t.enabled === false ? ' <span class="hint">(disabled)</span>' : '';
      const clients = `${t.connected_count || 0}/${t.client_count || 0}`;
      const nameCell = `<a href="#" data-action="selectVpnTunnel" data-arg="${id}" data-prevent-default class="c-accent">${nm}</a>${dis}`;
      const acts =
        `<button class="btn-icon" data-action="selectVpnTunnel" data-arg="${id}" title="View clients">Clients</button> ` +
        `<button class="btn-icon" data-action="editVpnTunnel" data-arg="${id}" title="Edit tunnel">${_icon('edit', 12)} Edit</button> ` +
        `<button class="btn-icon isl-45 c-danger-outline" title="Delete" data-action="deleteVpnTunnel" data-arg="${id}" data-arg2="${escAttr(t.name || '')}">${_icon('trash',14)}</button>`;
      return `<tr><td class="fw-600">${nameCell}</td><td class="hint">${escHtml(_vpnReachLabel(t))}</td><td>${clients}</td><td class="hint">${t.listen_port || '—'}</td><td>${_vpnExpiryCell(t.expires_at)}</td><td>${acts}</td></tr>`;
    },
    emptyMsg: 'No tunnels yet. Create one to issue road-warrior clients.',
  });
}

function _registerVpnClientsTable() {
  if (_vpnClientsRegistered) return;
  _vpnClientsRegistered = true;
  tableCtl.register({
    name: 'vpn_clients',
    tbody: 'vpn-clients-tbody',
    sortHeaders: 'vpn-clients-thead',
    colspan: 7,
    columns: ['name', 'address', 'status', 'endpoint', 'transfer', 'expires'],
    getColumns: (c) => ({
      name:     c.name || '',
      address:  c.address || '',
      status:   c.status || '',
      endpoint: c.endpoint || '',
      transfer: (c.rx_bytes || 0) + (c.tx_bytes || 0),
      expires:  c.expires_at || 0,
    }),
    row: (c) => {
      const id = escAttr(c.id);
      const dis = c.enabled === false ? ' <span class="hint">(disabled)</span>' : '';
      const st = c.status || 'offline';
      const stCls = st === 'connected' ? 'c-green' : (st === 'idle' ? 'c-amber' : 'hint');
      const stCell = `<span class="${stCls}" title="Last handshake ${escAttr(_vpnAge(c.last_handshake))} ago">${escHtml(st)}</span>`;
      const epCell = c.endpoint
        ? `<span class="ff-mono hint" title="Source the client last connected from">${escHtml(c.endpoint)}</span>`
        : '<span class="hint">—</span>';
      const xfer = `<span class="hint" title="received / sent">${_fmtBytes(c.rx_bytes || 0)} ↓ / ${_fmtBytes(c.tx_bytes || 0)} ↑</span>`;
      const acts =
        `<button class="btn-icon" data-action="editVpnClient" data-arg="${id}" title="Edit client">${_icon('edit', 12)} Edit</button> ` +
        `<button class="btn-icon" data-action="viewVpnClientHistory" data-arg="${id}" data-arg2="${escAttr(c.name || c.id)}" title="RX/TX history">${_icon('activity', 12)} History</button> ` +
        `<button class="btn-icon isl-45 c-danger-outline" title="Delete" data-action="deleteVpnClient" data-arg="${id}" data-arg2="${escAttr(c.name || '')}">${_icon('trash',14)}</button>`;
      const pskBadge = c.psk_configured
        ? ` <span class="hint" title="Preshared key configured (post-quantum-resistant peer)">${_icon('lock', 11)}</span>` : '';
      return `<tr><td class="fw-600">${escHtml(c.name || c.id)}${dis}${pskBadge}</td><td class="ff-mono">${escHtml(c.address || '—')}</td><td>${stCell}</td><td>${epCell}</td><td>${xfer}</td><td>${_vpnExpiryCell(c.expires_at)}</td><td>${acts}</td></tr>`;
    },
    emptyMsg: 'No clients on this tunnel yet. Create one to get a config + QR.',
  });
}

async function loadVpn() {
  _registerVpnTunnelsTable();
  _registerVpnClientsTable();
  const status = document.getElementById('vpn-status');
  if (status) status.textContent = '';
  const data = await api('GET', '/vpn-tunnels');
  if (!data) return;
  const unavail = document.getElementById('vpn-unavailable');
  const tcard = document.getElementById('vpn-tunnels-card');
  if (data.available === false) {
    if (unavail) unavail.classList.remove('d-none');
    const rsn = document.getElementById('vpn-unavail-reason');
    if (rsn) rsn.textContent = data.reason || '';
    if (tcard) tcard.classList.add('d-none');
    document.getElementById('vpn-clients-card')?.classList.add('d-none');
    return;
  }
  if (unavail) unavail.classList.add('d-none');
  if (tcard) tcard.classList.remove('d-none');
  _vpnTunnelsCache = Array.isArray(data.tunnels) ? data.tunnels : [];
  tableCtl.render('vpn_tunnels', _vpnTunnelsCache);
  // If a tunnel was selected, refresh its clients view (and its name).
  if (_vpnSelectedTunnel) {
    const fresh = _vpnTunnelsCache.find(t => String(t.id) === String(_vpnSelectedTunnel.id));
    if (fresh) { _vpnSelectedTunnel = fresh; reloadVpnClients(); }
    else { _vpnSelectedTunnel = null; document.getElementById('vpn-clients-card')?.classList.add('d-none'); }
  }
}

// ── Tunnel create / edit ─────────────────────────────────────────────────────
function _vpnTunnelModalReset() {
  document.getElementById('vpn-tunnel-name').value = '';
  const portEl = document.getElementById('vpn-tunnel-port');
  if (portEl) { portEl.value = ''; portEl.disabled = false; }
  document.getElementById('vpn-tunnel-allow-internet').checked = false;
  document.getElementById('vpn-tunnel-reach-type').value = 'none';
  document.getElementById('vpn-tunnel-reach-value').value = '';
  document.getElementById('vpn-tunnel-dns').value = '';
  document.getElementById('vpn-tunnel-ttl-num').value = '';
  document.getElementById('vpn-tunnel-ttl-unit').value = 'never';
  const r = document.getElementById('vpn-tunnel-result'); if (r) r.textContent = '';
  vpnReachTypeChanged();
  vpnTtlUnitChanged();
}

async function openVpnTunnelCreate() {
  _vpnTunnelEditId = null;
  const t = document.getElementById('vpn-tunnel-modal-title'); if (t) t.textContent = 'Create tunnel';
  const btn = document.getElementById('vpn-tunnel-save-btn'); if (btn) btn.textContent = 'Create';
  _vpnTunnelModalReset();
  // master-improvement-scoping #88: pre-fill from the saved default template,
  // if one exists -- still fully editable, and creating the tunnel is still
  // an explicit action either way (nothing inherits automatically server-side).
  try {
    const r = await api('GET', '/vpn-default-template');
    const tmpl = r && r.template;
    if (tmpl && (tmpl.reach_scope_type || tmpl.allow_internet || tmpl.dns)) {
      document.getElementById('vpn-tunnel-allow-internet').checked = !!tmpl.allow_internet;
      document.getElementById('vpn-tunnel-reach-type').value = tmpl.reach_scope_type || 'none';
      document.getElementById('vpn-tunnel-reach-value').value = tmpl.reach_scope_value || '';
      document.getElementById('vpn-tunnel-dns').value = tmpl.dns || '';
      vpnReachTypeChanged();
    }
  } catch (e) { /* no template yet, or fetch failed -- the blank form is a fine fallback */ }
  openModal('vpn-tunnel-modal');
}

async function vpnSaveTunnelDefaults() {
  const body = {
    allow_internet: !!document.getElementById('vpn-tunnel-allow-internet')?.checked,
    reach_scope_type: document.getElementById('vpn-tunnel-reach-type')?.value || 'none',
    reach_scope_value: document.getElementById('vpn-tunnel-reach-value')?.value.trim() || '',
    dns: document.getElementById('vpn-tunnel-dns')?.value.trim() || '',
  };
  const r = await api('POST', '/vpn-default-template', body);
  if (!r || r.error) { toast((r && r.error) || 'Failed to save default', 'error'); return; }
  toast('Saved as the default for new tunnels.', 'success');
}

function editVpnTunnel(id) {
  const t = _vpnTunnelsCache.find(x => String(x.id) === String(id));
  if (!t) { toast('Tunnel not found', 'error'); return; }
  _vpnTunnelEditId = t.id;
  const title = document.getElementById('vpn-tunnel-modal-title'); if (title) title.textContent = 'Edit tunnel';
  const btn = document.getElementById('vpn-tunnel-save-btn'); if (btn) btn.textContent = 'Save changes';
  _vpnTunnelModalReset();
  document.getElementById('vpn-tunnel-name').value = t.name || '';
  // Port is immutable after creation (iface/port/pool are fixed) — show it read-only.
  const portEl = document.getElementById('vpn-tunnel-port');
  if (portEl) { portEl.value = t.listen_port || ''; portEl.disabled = true; }
  document.getElementById('vpn-tunnel-allow-internet').checked = !!t.allow_internet;
  document.getElementById('vpn-tunnel-reach-type').value = t.reach_scope_type || 'none';
  document.getElementById('vpn-tunnel-reach-value').value = t.reach_scope_value || '';
  document.getElementById('vpn-tunnel-dns').value = t.dns || '';
  vpnReachTypeChanged();
  vpnTtlUnitChanged();
  openModal('vpn-tunnel-modal');
}

function vpnReachTypeChanged() {
  const type = document.getElementById('vpn-tunnel-reach-type')?.value || 'none';
  const row = document.getElementById('vpn-tunnel-reach-value-row');
  if (row) row.classList.toggle('d-none', !(type === 'site' || type === 'group' || type === 'tag'));
  vpnReachPreview();
}

function vpnTtlUnitChanged() {
  const unit = document.getElementById('vpn-tunnel-ttl-unit')?.value || 'never';
  const num = document.getElementById('vpn-tunnel-ttl-num');
  if (num) num.disabled = (unit === 'never');
}

function vpnReachPreview() {
  const el = document.getElementById('vpn-tunnel-reach-preview');
  if (!el) return;
  const type = document.getElementById('vpn-tunnel-reach-type')?.value || 'none';
  const val = document.getElementById('vpn-tunnel-reach-value')?.value.trim() || '';
  const full = document.getElementById('vpn-tunnel-allow-internet')?.checked;
  const label = _vpnReachLabel({ reach_scope_type: type, reach_scope_value: val, allow_internet: full });
  el.textContent = 'Clients on this tunnel will reach: ' + label + '.';
}

async function vpnTunnelSave() {
  const name = document.getElementById('vpn-tunnel-name').value.trim();
  if (!name) { toast('Name required', 'error', {transient: true}); return; }
  const reach_scope_type = document.getElementById('vpn-tunnel-reach-type').value;
  const reach_scope_value = document.getElementById('vpn-tunnel-reach-value').value.trim();
  if ((reach_scope_type === 'site' || reach_scope_type === 'group' || reach_scope_type === 'tag') && !reach_scope_value) {
    toast('Scope value required for ' + reach_scope_type, 'error'); return;
  }
  const body = {
    name,
    allow_internet: document.getElementById('vpn-tunnel-allow-internet').checked,
    reach_scope_type,
    reach_scope_value: (reach_scope_type === 'site' || reach_scope_type === 'group' || reach_scope_type === 'tag') ? reach_scope_value : '',
    dns: document.getElementById('vpn-tunnel-dns').value.trim(),
    expires_at: _vpnReadTtl('vpn-tunnel-ttl-num', 'vpn-tunnel-ttl-unit'),
  };
  // Listen port is optional and immutable — only send it when creating.
  if (!_vpnTunnelEditId) {
    const portRaw = (document.getElementById('vpn-tunnel-port')?.value || '').trim();
    if (portRaw) {
      const port = Number(portRaw);
      if (!Number.isInteger(port) || port < 1 || port > 65535) { toast('Listen port must be a whole number 1–65535', 'error'); return; }
      body.listen_port = port;
    }
  }
  let data;
  if (_vpnTunnelEditId) data = await api('PATCH', '/vpn-tunnels/' + encodeURIComponent(_vpnTunnelEditId), body);
  else data = await api('POST', '/vpn-tunnels', body);
  if (data?.ok) {
    toast(_vpnTunnelEditId ? 'Tunnel updated' : 'Tunnel created', 'success');
    closeModal('vpn-tunnel-modal');
    _vpnTunnelEditId = null;
    loadVpn();
  } else toast(data?.error || 'Failed', 'error');
}

async function deleteVpnTunnel(id, name) {
  if (!await uiConfirm({ title: 'Delete tunnel',
    message: `Delete tunnel “${name || id}” and all its clients? Issued configs will stop working.`,
    confirmText: 'Delete', danger: true })) return;
  const data = await api('DELETE', '/vpn-tunnels/' + encodeURIComponent(id));
  if (data?.ok) {
    toast('Tunnel deleted', 'info');
    if (_vpnSelectedTunnel && String(_vpnSelectedTunnel.id) === String(id)) {
      _vpnSelectedTunnel = null;
      document.getElementById('vpn-clients-card')?.classList.add('d-none');
    }
    loadVpn();
  } else toast(data?.error || 'Failed', 'error');
}

// ── Clients of the selected tunnel ───────────────────────────────────────────
function selectVpnTunnel(id) {
  const t = _vpnTunnelsCache.find(x => String(x.id) === String(id));
  if (!t) { toast('Tunnel not found', 'error'); return; }
  _vpnSelectedTunnel = t;
  const card = document.getElementById('vpn-clients-card');
  if (card) card.classList.remove('d-none');
  const nm = document.getElementById('vpn-sel-name');
  if (nm) nm.textContent = '— ' + (t.name || t.iface || t.id);
  reloadVpnClients();
}

async function reloadVpnClients() {
  if (!_vpnSelectedTunnel) return;
  _registerVpnClientsTable();
  const data = await api('GET', '/vpn-tunnels/' + encodeURIComponent(_vpnSelectedTunnel.id) + '/clients');
  if (!data) return;
  _vpnClientsCache = Array.isArray(data.clients) ? data.clients : [];
  tableCtl.render('vpn_clients', _vpnClientsCache);
  _vpnRenderReach();
}

// Show what the selected tunnel's clients can actually reach right now — resolved
// live on the server from the current fleet (so it reflects scope changes since
// the last sync). Built with textContent/DOM, no innerHTML (CSP-safe).
// v6.4.3: a tunnel whose UDP port is not forwarded looks EXACTLY like one
// nobody has got round to connecting to — right config, server up, client
// correct, no handshake ever. It is the classic WG-Access support question and
// the page said only "0 connected now".
//
// The server decides (see _vpn_inbound_verdict); this only paints the one
// verdict worth interrupting for. Nothing is drawn for `proven` or `unknown` —
// a permanently-visible "we cannot tell" box is noise that teaches operators to
// ignore the panel, which is how a real warning gets missed later.
function _vpnPaintInbound(st) {
  const el = document.getElementById('vpn-sel-inbound');
  if (!el) return;
  const inb = (st && st.inbound) || {};
  if (inb.state !== 'never') { el.hidden = true; el.textContent = ''; return; }
  const port = inb.port || 0;
  const n = inb.client_count || 0;
  el.hidden = false;
  el.textContent = '';
  const msg = document.createElement('span');
  msg.textContent =
    `${n} client${n === 1 ? ' has' : 's have'} been configured on this tunnel and `
    + `not one has ever completed a handshake. The usual cause is inbound `
    + `UDP ${port || '(no port set)'} not reaching this host — check the port `
    + `forward on your router and any firewall in front of it. WireGuard never `
    + `replies to unauthenticated packets, so a port scan cannot confirm this `
    + `either way; a single successful handshake will.`;
  el.appendChild(msg);
  const doc = document.createElement('a');
  doc.href = 'docs/wg-access.md';
  doc.className = 'c-accent ml-8';
  doc.textContent = 'Documentation';
  el.appendChild(doc);
}

async function _vpnRenderReach() {
  const el = document.getElementById('vpn-sel-reach');
  const stEl = document.getElementById('vpn-sel-stats');
  if (!el || !_vpnSelectedTunnel) return;
  el.textContent = '';
  if (stEl) stEl.textContent = '';
  const s = await api('GET', '/vpn-tunnels/' + encodeURIComponent(_vpnSelectedTunnel.id) + '/stats');
  const st = s && s.stats;
  if (!st) return;
  // Tunnel rollup: address-pool utilisation + aggregate throughput (collected
  // from wg but otherwise unsurfaced).
  if (stEl) {
    const used = st.pool_used || 0, size = st.pool_size || 0;
    const bits = [used + '/' + size + ' addresses used'];
    if ((st.rx_bytes || 0) || (st.tx_bytes || 0)) {
      bits.push('↓ ' + _fmtBytes(st.rx_bytes || 0) + '  ↑ ' + _fmtBytes(st.tx_bytes || 0));
    }
    bits.push((st.connected_count || 0) + ' connected now');
    stEl.textContent = bits.join('  ·  ');
  }
  _vpnPaintInbound(st);
  if (st.allow_internet) {
    el.textContent = 'Reaches: the dashboard + the internet (full tunnel).';
    return;
  }
  const type = st.reach_scope_type || 'none';
  if (type === 'none') {
    el.textContent = 'Reaches: the dashboard only.';
    return;
  }
  const scope = type === 'all' ? 'all devices' : (type + ' = ' + (st.reach_scope_value || ''));
  const names = (st.reach_devices || []).map(d => (d.name || d.ip) + ' (' + d.ip + ')');
  let txt = 'Reaches: the dashboard + ' + (st.reach_count || 0) + ' device'
          + ((st.reach_count === 1) ? '' : 's') + ' [' + scope + ']';
  if (names.length) {
    txt += ' — ' + names.slice(0, 12).join(', ') + (names.length > 12 ? ', …' : '');
  } else {
    txt += ' — no devices in scope have a known IP yet';
  }
  el.textContent = txt;
}

// master-improvement-scoping #87: per-peer RX/TX history sparkline.
function _vpnRxTxSparkline(samples) {
  if (!samples || samples.length < 2) return '';
  const W = 260, H = 60, n = samples.length;
  const maxV = Math.max(1, ...samples.map(s => Math.max(s.rx_bytes || 0, s.tx_bytes || 0)));
  const line = (key) => samples.map((s, i) => {
    const x = (i / (n - 1)) * W;
    const y = H - ((s[key] || 0) / maxV) * H;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" width="${W}" height="${H}" aria-hidden="true">`
    + `<polyline class="c-accent" points="${line('rx_bytes')}" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`
    + `<polyline class="c-muted" points="${line('tx_bytes')}" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`
    + `</svg>`;
}

async function viewVpnClientHistory(cid, name) {
  if (!_vpnSelectedTunnel) return;
  const nmEl = document.getElementById('vpn-history-client-name');
  if (nmEl) nmEl.textContent = name || cid;
  const body = document.getElementById('vpn-history-body');
  if (body) body.innerHTML = '<div class="hint">Loading…</div>';
  openModal('vpn-client-history-modal');
  const data = await api('GET', '/vpn-tunnels/' + encodeURIComponent(_vpnSelectedTunnel.id)
    + '/clients/' + encodeURIComponent(cid) + '/history');
  if (!body) return;
  const samples = (data && data.samples) || [];
  if (samples.length < 2) {
    body.innerHTML = '<div class="c-muted">Not enough samples yet — check back after a couple of stats polls.</div>';
    return;
  }
  const last = samples[samples.length - 1];
  const first = samples[0];
  body.innerHTML =
    `<div class="mb-8">${_vpnRxTxSparkline(samples)}</div>`
    + `<div class="hint"><span class="c-accent">■</span> received &nbsp; <span class="c-muted">■</span> sent</div>`
    + `<div class="hint mt-6">${escHtml(_fmtBytes(first.rx_bytes || 0))} → ${escHtml(_fmtBytes(last.rx_bytes || 0))} received, `
    + `${escHtml(_fmtBytes(first.tx_bytes || 0))} → ${escHtml(_fmtBytes(last.tx_bytes || 0))} sent, `
    + `over ${samples.length} sample(s) (${timeAgo(first.ts)} to ${timeAgo(last.ts)})</div>`;
}

function openVpnClientCreate() {
  if (!_vpnSelectedTunnel) { toast('Select a tunnel first', 'error'); return; }
  document.getElementById('vpn-client-name').value = '';
  document.getElementById('vpn-client-ttl-num').value = '';
  document.getElementById('vpn-client-ttl-unit').value = 'never';
  const r = document.getElementById('vpn-client-result'); if (r) r.textContent = '';
  const btn = document.getElementById('vpn-client-create-btn'); if (btn) { btn.disabled = false; btn.textContent = 'Create'; }
  openModal('vpn-client-modal');
}

async function vpnClientCreate() {
  if (!_vpnSelectedTunnel) { toast('Select a tunnel first', 'error'); return; }
  if (!window.WGAccess) { toast('WireGuard helper script not loaded', 'error'); return; }
  const name = document.getElementById('vpn-client-name').value.trim();
  if (!name) { toast('Name required', 'error', {transient: true}); return; }
  const expires_at = _vpnReadTtl('vpn-client-ttl-num', 'vpn-client-ttl-unit');
  const btn = document.getElementById('vpn-client-create-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }
  let kp;
  try {
    kp = window.WGAccess.genKeypair();
  } catch (e) {
    if (btn) { btn.disabled = false; btn.textContent = 'Create'; }
    toast('Key generation failed: ' + (e?.message || e), 'error');
    return;
  }
  const data = await api('POST', '/vpn-tunnels/' + encodeURIComponent(_vpnSelectedTunnel.id) + '/clients',
    { name, pubkey: kp.publicKey, expires_at });
  if (!data?.ok) {
    if (btn) { btn.disabled = false; btn.textContent = 'Create'; }
    toast(data?.error || 'Failed to create client', 'error');
    return;
  }
  // Assemble the .conf locally — the private key never left the browser.
  const conf = window.WGAccess.buildClientConf({
    privateKey:   kp.privateKey,
    address:      data.address,
    dns:          data.dns,
    hubPublicKey: data.hub_pubkey,
    endpoint:     data.endpoint,
    allowedIps:   data.allowed_ips,
    presharedKey: data.preshared_key,
  });
  _vpnLastClient = { name, conf };
  closeModal('vpn-client-modal');
  // v6.1.1 (#86): the preshared key is stored server-side too (to configure
  // the hub peer) -- flag when it's sitting in plaintext because the
  // operator hasn't set RP_CONFIG_KEY, rather than silently leaving them to
  // discover that later.
  if (data.preshared_key && data.psk_encrypted === false) {
    toast('Preshared key generated, but RP_CONFIG_KEY is not set — it is stored in plaintext. Set RP_CONFIG_KEY to encrypt it at rest.', 'error');
  }
  // Render result panel.
  const ta = document.getElementById('vpn-conf-text');
  if (ta) ta.value = conf;
  try {
    const canvas = document.getElementById('vpn-qr-canvas');
    if (canvas) window.WGAccess.renderQR(canvas, conf, { size: 240 });
  } catch (e) { /* QR is best-effort; the .conf text + download still work */ }
  openModal('vpn-client-result-modal');
  reloadVpnClients();
}

function vpnDownloadConf() {
  if (!_vpnLastClient || !window.WGAccess) return;
  window.WGAccess.downloadConf((_vpnLastClient.name || 'wireguard') + '.conf', _vpnLastClient.conf);
}

async function vpnCopyConf() {
  if (!_vpnLastClient) return;
  try {
    await navigator.clipboard.writeText(_vpnLastClient.conf);
    toast('Config copied to clipboard', 'success');
  } catch (e) {
    const ta = document.getElementById('vpn-conf-text');
    if (ta) { ta.focus(); ta.select(); }
    toast('Select the text and copy manually', 'info');
  }
}

function editVpnClient(id) {
  if (!_vpnSelectedTunnel) return;
  const c = _vpnClientsCache.find(x => String(x.id) === String(id));
  if (!c) { toast('Client not found', 'error'); return; }
  uiPrompt({ title: 'Rename client', message: 'New name for this client.', value: c.name || '' }).then(async (name) => {
    if (name == null) return;
    name = String(name).trim();
    if (!name) { toast('Name required', 'error', {transient: true}); return; }
    const data = await api('PATCH', '/vpn-tunnels/' + encodeURIComponent(_vpnSelectedTunnel.id) +
      '/clients/' + encodeURIComponent(id), { name });
    if (data?.ok) { toast('Client updated', 'info'); reloadVpnClients(); }
    else toast(data?.error || 'Failed', 'error');
  });
}

async function deleteVpnClient(id, name) {
  if (!_vpnSelectedTunnel) return;
  if (!await uiConfirm({ title: 'Delete client',
    message: `Delete client “${name || id}”? Its config will stop working immediately.`,
    confirmText: 'Delete', danger: true })) return;
  const data = await api('DELETE', '/vpn-tunnels/' + encodeURIComponent(_vpnSelectedTunnel.id) +
    '/clients/' + encodeURIComponent(id));
  if (data?.ok) { toast('Client deleted', 'info'); reloadVpnClients(); }
  else toast(data?.error || 'Failed', 'error');
}
