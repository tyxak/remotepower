// ══════════════════════════════════════════════════════════════════════════════
//  RouterOS / OPNsense / Synology integration cards
//  Split out of app.js (v3.13.0). Classic script — shares the global scope with
//  app.js (loaded first); calls core helpers (api, escHtml, toast, openModal, …)
//  at runtime. Not a module — do not wrap in an IIFE.
// ══════════════════════════════════════════════════════════════════════════════

// ── v3.3.4: RouterOS (MikroTik) card ───────────────────────────────────────
function _renderRouterosCard(body, badge, data) {
  const cfg = data.config || {};
  const ov  = data.overview;
  const fmtB = (b) => {
    if (b == null) return '—';
    if (b < 1024) return String(b);
    const u = ['B','KB','MB','GB','TB']; let i = 0; let v = b;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(v < 10 ? 1 : 0) + u[i];
  };

  let h = `<div class="mb-12">
    <label class="click-row-6"><input type="checkbox" id="ros-enabled" ${cfg.enabled ? 'checked' : ''}><span class="fs-12">Enable RouterOS REST (v7+)</span></label>
    <input class="form-input mt-6" id="ros-user" placeholder="username" value="${escAttr(cfg.username || '')}">
    <input class="form-input mt-6" id="ros-pass" type="password" placeholder="${cfg.has_password ? '•••••• (unchanged)' : 'password'}">
    <input class="form-input mt-6" id="ros-port" type="number" placeholder="443" value="${cfg.port || 443}">
    <div class="row-6 mt-6">
      <button class="btn-icon" data-action="saveRouterosConfig">Save</button>
      <button class="btn-icon" data-action="routerosReload">Load</button>
    </div>
    <div class="hint mt-6">Use a dedicated RouterOS user — a read-only group for visibility, a write group only if you'll use the actions. TLS verification is off (RouterOS self-signed cert).</div>
  </div>`;

  if (data.error) {
    badge.textContent = 'error';
    body.innerHTML = h + `<div class="c-red">RouterOS error: ${escHtml(data.error)}</div>`;
    return;
  }
  if (!cfg.enabled || !ov) {
    badge.textContent = cfg.enabled ? 'configured' : 'off';
    body.innerHTML = h + (cfg.enabled ? '' : '<div class="c-muted">Not enabled — add credentials, Save, then Load.</div>');
    return;
  }

  const sys = ov.system || {}, rb = ov.routerboard || {}, up = ov.update || {};
  h += `<h4 class="mt-12">System</h4>`;
  h += `<div class="hint mb-6">${escHtml(rb.model || sys.board_name || 'RouterOS')} · RouterOS ${escHtml(sys.version || '?')}${sys.cpu_load != null ? ' · CPU ' + escHtml(String(sys.cpu_load)) + '%' : ''}${sys.uptime ? ' · up ' + escHtml(sys.uptime) : ''}</div>`;
  if (up.installed_version || up.latest_version) {
    const stale = up.latest_version && up.installed_version && up.latest_version !== up.installed_version;
    h += `<div class="hint mb-6">Update: ${escHtml(up.installed_version || '?')} → ${stale ? `<span class="c-amber">${escHtml(up.latest_version)}</span>` : escHtml(up.latest_version || 'current')}</div>`;
  }
  h += `<div class="row-6 mb-12">
    <button class="btn-icon" data-action="routerosCheckUpdate" title="Ask MikroTik whether a newer RouterOS is available">Check for updates</button>
    <button class="btn-icon c-danger-outline" data-action="routerosUpgrade" title="Download + install the update — REBOOTS the router">Upgrade firmware</button>
    <button class="btn-icon" data-action="routerosAction" data-arg="reboot" title="Reboot the router">${_icon('refresh',14)} Reboot</button>
    <button class="btn-icon" data-action="routerosAction" data-arg="export" title="Export the running config">Export config</button>
    <button class="btn-icon" data-action="openRouterosConsole" title="Open the full-width RouterOS console"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M21 14v7H3V3h7"/></svg> Console</button>
  </div><div id="ros-action-out"></div>`;

  const ifs = ov.interfaces || [];
  if (ifs.length) {
    h += `<h4 class="mt-12">Interfaces (${ifs.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Name</th><th>Type</th><th>State</th><th class="ta-right">RX</th><th class="ta-right">TX</th><th></th></tr></thead><tbody>`;
    for (const i of ifs) {
      const state = i.disabled ? '<span class="c-muted">disabled</span>'
                  : (i.running ? '<span class="c-green">up</span>' : '<span class="c-amber">down</span>');
      const btn = i.disabled
        ? `<button class="btn-icon badge-xs" data-action="routerosAction" data-arg="enable_interface" data-arg2="${escAttr(i.id)}">Enable</button>`
        : `<button class="btn-icon badge-xs" data-action="routerosAction" data-arg="disable_interface" data-arg2="${escAttr(i.id)}">Disable</button>`;
      h += `<tr><td><strong>${escHtml(i.name || '?')}</strong></td><td class="hint">${escHtml(i.type || '')}</td><td>${state}</td><td class="ta-right">${fmtB(i.rx_byte)}</td><td class="ta-right">${fmtB(i.tx_byte)}</td><td class="nowrap">${btn}</td></tr>`;
    }
    h += '</tbody></table></div>';
  }

  const leases = ov.dhcp_leases || [];
  if (leases.length) {
    h += `<h4 class="mt-12">DHCP leases (${leases.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Address</th><th>MAC</th><th>Host</th><th>Status</th></tr></thead><tbody>`;
    for (const l of leases.slice(0, 100)) {
      h += `<tr><td class="mono-12">${escHtml(l.address || '')}</td><td class="mono-12">${escHtml(l.mac || '')}</td><td>${escHtml(l.hostname || '—')}</td><td class="hint">${escHtml(l.status || '')}${l.dynamic ? '' : ' · static'}</td></tr>`;
    }
    h += '</tbody></table></div>';
  }

  const wl = ov.wireless || [];
  if (wl.length) {
    h += `<h4 class="mt-12">Wireless clients (${wl.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Interface</th><th>MAC</th><th>Signal</th></tr></thead><tbody>`;
    for (const w of wl.slice(0, 100)) {
      h += `<tr><td>${escHtml(w.interface || '')}</td><td class="mono-12">${escHtml(w.mac || '')}</td><td class="hint">${escHtml(String(w.signal || '—'))}</td></tr>`;
    }
    h += '</tbody></table></div>';
  }

  const fw = ov.firewall || {};
  h += `<div class="hint mt-12">Firewall: ${fw.filter || 0} filter · ${fw.nat || 0} nat${ov.routes != null ? ' · ' + ov.routes + ' routes' : ''}</div>`;
  if (ov.errors && Object.keys(ov.errors).length) {
    h += `<div class="hint mt-6">Sections unavailable: ${escHtml(Object.keys(ov.errors).join(', '))}</div>`;
  }
  badge.textContent = sys.version ? 'v' + sys.version : 'loaded';
  body.innerHTML = h;
}

async function saveRouterosConfig() {
  const id = _drawerDeviceId;
  if (!id) return;
  const body = {
    enabled:  !!document.getElementById('ros-enabled')?.checked,
    username: document.getElementById('ros-user')?.value.trim() || '',
    port:     parseInt(document.getElementById('ros-port')?.value || '443', 10),
  };
  const pw = document.getElementById('ros-pass')?.value || '';
  if (pw) body.password = pw;
  const r = await api('PATCH', `/devices/${encodeURIComponent(id)}/routeros`, body);
  if (r?.ok) { toast('RouterOS config saved', 'success'); routerosReload(); }
  else toast(r?.error || 'Failed', 'error');
}

// ── v3.4.0: OPNsense card — mirrors the RouterOS firewall console ───────────
let _opnFirewall = { filter: [], nat: [] };

function _renderOpnsenseCard(body, badge, data) {
  const cfg = data.config || {};
  const ov  = data.overview;
  let h = `<div class="mb-12">
    <label class="click-row-6"><input type="checkbox" id="opn-enabled" ${cfg.enabled ? 'checked' : ''}><span class="fs-12">Enable OPNsense API</span></label>
    <input class="form-input mt-6" id="opn-key" placeholder="API key" value="${escAttr(cfg.api_key || '')}">
    <input class="form-input mt-6" id="opn-secret" type="password" placeholder="${cfg.has_secret ? '•••••• (unchanged)' : 'API secret'}">
    <input class="form-input mt-6" id="opn-port" type="number" placeholder="443" value="${cfg.port || 443}">
    <div class="row-6 mt-6">
      <button class="btn-icon" data-action="saveOpnsenseConfig">Save</button>
    </div>
    <div class="hint mt-6">Create an API key/secret under System → Access → Users (a dedicated user scoped to the firewall pages). TLS verification is off (OPNsense self-signed cert).</div>
  </div>`;

  if (data.error) {
    badge.textContent = 'error';
    body.innerHTML = h + `<div class="c-red">OPNsense error: ${escHtml(data.error)}</div>`;
    return;
  }
  if (!cfg.enabled || !ov) {
    badge.textContent = cfg.enabled ? 'configured' : 'off';
    body.innerHTML = h + (cfg.enabled ? '' : '<div class="c-muted">Not enabled — add an API key/secret, Save, then Load firewall.</div>');
    return;
  }

  const fwv = ov.firmware || {}, counts = ov.counts || {};
  h += `<h4 class="mt-12">System</h4>`;
  // Update state comes from OPNsense's own `status` + package counts — NOT a
  // version!=latest string compare, since product_version carries a patch
  // suffix (e.g. 26.1.8_5) that never equals product_latest (26.1.8).
  h += `<div class="hint mb-6">OPNsense ${escHtml(String(fwv.version || '?'))}`;
  if (fwv.updates_available) {
    h += ` · <span class="c-amber">${escHtml(String(fwv.updates_available))} update(s) available</span>`;
  }
  if (fwv.needs_reboot) h += ` · <span class="c-amber">reboot required</span>`;
  h += `</div>`;
  h += `<div class="row-6 mb-12">
    <button class="btn-icon" data-action="opnsenseAction" data-arg="check_update" title="Ask OPNsense whether updates are available">Check for updates</button>
    <button class="btn-icon c-danger-outline" data-action="opnsenseAction" data-arg="upgrade" title="Run the OPNsense firmware upgrade — may REBOOT the firewall">Upgrade</button>
    <button class="btn-icon" data-action="opnsenseAction" data-arg="reboot" title="Reboot the firewall">${_icon('refresh',14)} Reboot</button>
    <button class="btn-icon" data-action="openOpnsenseConsole" title="Open the full-width OPNsense console"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M21 14v7H3V3h7"/></svg> Console</button>
  </div><div id="opn-action-out"></div>`;
  h += `<div class="hint mb-6">Firewall: ${counts.filter ?? '?'} filter · ${counts.nat ?? '?'} nat (API-managed rules)</div>`;
  if (ov.errors && Object.keys(ov.errors).length) {
    h += `<div class="hint mb-6">Sections unavailable: ${escHtml(Object.keys(ov.errors).join(', '))}</div>`;
  }
  h += `<h4 class="mt-12">Firewall &amp; NAT rules</h4>
    <div class="row-6 mb-6">
      <button class="btn-icon" data-action="loadOpnsenseFirewall">${_icon('refresh',14)} Load / refresh rules</button>
    </div>
    <div id="opn-fw-body"><div class="c-muted">Click "Load / refresh rules" to view and manage filter + NAT rules.</div></div>`;
  badge.textContent = fwv.version ? String(fwv.version).replace(/^OPNsense\s*/i, 'v') : 'loaded';
  body.innerHTML = h;
}

async function opnsenseAction(action, arg) {
  const id = _drawerDeviceId;
  if (!id) return;
  const act = action;   // data-arg carries the action name (matches routerosAction shape)
  if (act === 'reboot' && !confirm('Reboot this OPNsense firewall? It will drop all connections through it.')) return;
  if (act === 'upgrade' && !confirm('Run the OPNsense firmware upgrade now? This can take several minutes and may reboot the firewall.')) return;
  if (act === 'check_update') toast('Checking OPNsense for updates…', 'info');
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/opnsense/action`, { action: act });
  if (!r || r.error) { toast((r && r.error) || 'Action failed', 'error'); return; }

  // Build a visible verdict for check_update — with 0 updates the card looks
  // unchanged, so an explicit "up to date" message is what the operator needs.
  let resultMsg = '';
  if (act === 'check_update') {
    const u = (r.result && r.result.update) || {};
    resultMsg = u.updates_available
      ? `${u.updates_available} update(s) available${u.latest ? ' — latest ' + u.latest : ''}`
      : `Up to date — OPNsense ${u.version || '?'}${u.needs_reboot ? ' (reboot pending)' : ''}`;
    toast(resultMsg, 'success');
  } else {
    toast(`${act.replace('_', ' ')} ok`, 'success');
  }

  // Refresh the active surface so the new firmware/update state shows.
  if (act !== 'reboot') {
    const data = await api('GET', `/devices/${encodeURIComponent(id)}/opnsense`);
    const { body, badge } = _opnsenseSurface();
    if (body) {
      _renderOpnsenseCard(body, badge, data || {});
      _opnsenseConsoleAppendFirewall(body, data);
      if (resultMsg) {
        const out = document.getElementById('opn-action-out');
        if (out) out.innerHTML = `<div class="hint mb-6">${escHtml(resultMsg)}</div>`;
      }
    }
  }
}

async function openOpnsenseConsole() {
  const id = _drawerDeviceId;
  if (!id) return;
  openModal('opnsense-console-modal');
  const title = document.getElementById('opnsense-console-title');
  if (title) title.textContent = `OPNsense — ${_drawerDeviceName || id}`;
  const body = document.getElementById('opnsense-console-body');
  body.innerHTML = '<div class="c-muted">Loading…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/opnsense`);
  _renderOpnsenseCard(body, { textContent: '' }, data || {});
  _opnsenseConsoleAppendFirewall(body, data);
}

// In the console, drop the firewall management straight into the body (more
// room than the drawer card) instead of behind a "Load firewall" click.
function _opnsenseConsoleAppendFirewall(surface, data) {
  // Console only — auto-load the rules into the roomy modal. The compact
  // drawer card stays button-driven (Load / refresh rules), matching the
  // RouterOS/MikroTik load-on-demand UX.
  const modal = document.getElementById('opnsense-console-modal');
  if (!modal || !modal.classList.contains('active')) return;
  if (!surface || !data || !data.config || !data.config.enabled || !data.overview) return;
  const holder = surface.querySelector('#opn-fw-body');
  if (holder) loadOpnsenseFirewall();
}

async function saveOpnsenseConfig() {
  const id = _drawerDeviceId;
  if (!id) return;
  const body = {
    enabled: !!document.getElementById('opn-enabled')?.checked,
    api_key: document.getElementById('opn-key')?.value.trim() || '',
    port:    parseInt(document.getElementById('opn-port')?.value || '443', 10),
  };
  const sec = document.getElementById('opn-secret')?.value || '';
  if (sec) body.api_secret = sec;
  const r = await api('PATCH', `/devices/${encodeURIComponent(id)}/opnsense`, body);
  if (r?.ok) {
    toast('OPNsense config saved', 'success');
    const data = await api('GET', `/devices/${encodeURIComponent(id)}/opnsense`);
    const cardBody = document.getElementById('audit-body-opnsense');
    const badge = document.getElementById('audit-badge-opnsense');
    if (cardBody) _renderOpnsenseCard(cardBody, badge || { textContent: '' }, data || {});
  } else toast(r?.error || 'Failed', 'error');
}

// Pick the active OPNsense surface — the full-width console modal if open,
// else the drawer card — so writes never land in the hidden duplicate.
function _opnsenseSurface() {
  const modal = document.getElementById('opnsense-console-modal');
  if (modal && modal.classList.contains('active')) {
    return { body: document.getElementById('opnsense-console-body'), badge: { textContent: '' } };
  }
  return {
    body:  document.getElementById('audit-body-opnsense'),
    badge: document.getElementById('audit-badge-opnsense') || { textContent: '' },
  };
}

async function loadOpnsenseFirewall() {
  const id = _drawerDeviceId;
  const surf = _opnsenseSurface();
  const body = (surf.body && surf.body.querySelector('#opn-fw-body')) || document.getElementById('opn-fw-body');
  if (!id || !body) return;
  body.innerHTML = '<div class="c-muted">Loading rules…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/opnsense/firewall`);
  if (!data || data.error) { body.innerHTML = `<div class="c-red">${escHtml((data && data.error) || 'Failed')}</div>`; return; }
  _opnFirewall = { filter: data.filter || [], nat: data.nat || [], errors: data.errors || {} };
  _renderOpnsenseFirewall(body);
}

function _renderOpnsenseFirewall(body) {
  const f = _opnFirewall.filter || [], n = _opnFirewall.nat || [];
  const errs = _opnFirewall.errors || {};
  let h = '';
  if (Object.keys(errs).length) {
    h += `<div class="c-red mb-6">Could not read: ${escHtml(Object.entries(errs).map(([k, v]) => `${k} (${v})`).join('; '))}</div>`;
  }
  h += `<div class="hint mb-6">Shows rules managed via the OPNsense API (Firewall → Automation). Rules created in the classic Firewall → Rules GUI are not exposed by the API and won't appear here.</div>`;
  h += `<h4 class="mt-12">Filter rules (${f.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Interface</th><th>Action</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>Description</th><th></th></tr></thead><tbody>`;
  h += f.map(r => _ruleRow(r, 'filter', 'opnsense')).join('') || '<tr><td colspan="7" class="c-muted">No filter rules.</td></tr>';
  h += '</tbody></table></div>';

  h += `<h4 class="mt-12">NAT rules — outbound / source (${n.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Interface</th><th>Target</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>→ target:port</th><th>Description</th><th></th></tr></thead><tbody>`;
  h += n.map(r => _ruleRow(r, 'nat', 'opnsense')).join('') || '<tr><td colspan="8" class="c-muted">No NAT rules.</td></tr>';
  h += '</tbody></table></div>';

  // Add-filter-rule form. New rules land DISABLED for review.
  h += `<h4 class="mt-12">Add filter rule</h4>
    <div class="hint mb-6">New rules are created <strong>disabled</strong> — review, then Enable from the table. Changes are applied to the live ruleset on save.</div>
    <div class="row-6">
      <select class="form-input mw-200" id="opn-fw-action"><option value="pass">pass</option><option value="block">block</option><option value="reject">reject</option></select>
      <input class="form-input mw-200" id="opn-fw-iface" placeholder="interface (e.g. lan, wan)">
    </div>
    <div class="row-6 mt-6">
      <select class="form-input mw-200" id="opn-fw-ipproto"><option value="inet">IPv4 (inet)</option><option value="inet6">IPv6 (inet6)</option></select>
      <input class="form-input mw-200" id="opn-fw-proto" placeholder="protocol (any/TCP/UDP/…)">
    </div>
    <input class="form-input mt-6" id="opn-fw-src" placeholder="source_net (e.g. any or 192.168.1.0/24)">
    <input class="form-input mt-6" id="opn-fw-dst" placeholder="destination_net (optional)">
    <input class="form-input mt-6" id="opn-fw-dport" placeholder="destination_port (optional)">
    <input class="form-input mt-6" id="opn-fw-desc" placeholder="description">
    <div class="row-6 mt-6"><button class="btn-primary" data-action="addOpnsenseFilterRule">Add filter rule (disabled)</button></div>`;

  // Add-NAT-rule form (outbound / source NAT).
  h += `<h4 class="mt-12">Add NAT rule (outbound / source)</h4>
    <div class="hint mb-6">New rules are created <strong>disabled</strong> — review, then Enable from the table. <strong>target</strong> (the translation/NAT address — e.g. the WAN interface address) is required by OPNsense for outbound NAT.</div>
    <input class="form-input" id="opn-nat-iface" placeholder="interface (e.g. wan)">
    <div class="row-6 mt-6">
      <select class="form-input mw-200" id="opn-nat-ipproto"><option value="inet">IPv4 (inet)</option><option value="inet6">IPv6 (inet6)</option></select>
      <input class="form-input mw-200" id="opn-nat-proto" placeholder="protocol (any/TCP/UDP/…)">
    </div>
    <input class="form-input mt-6" id="opn-nat-src" placeholder="source_net (e.g. 192.168.1.0/24)">
    <input class="form-input mt-6" id="opn-nat-dst" placeholder="destination_net (optional)">
    <div class="row-6 mt-6">
      <input class="form-input mw-200" id="opn-nat-target" placeholder="target — translation address (required)">
      <input class="form-input mw-200" id="opn-nat-tport" placeholder="target_port (optional)">
    </div>
    <input class="form-input mt-6" id="opn-nat-desc" placeholder="description">
    <div class="row-6 mt-6"><button class="btn-primary" data-action="addOpnsenseNatRule">Add NAT rule (disabled)</button></div>`;
  body.innerHTML = h;
}

async function addOpnsenseFilterRule() {
  const id = _drawerDeviceId;
  if (!id) return;
  const rule = {
    action:           document.getElementById('opn-fw-action')?.value,
    interface:        document.getElementById('opn-fw-iface')?.value.trim() || '',
    ipprotocol:       document.getElementById('opn-fw-ipproto')?.value || 'inet',
    protocol:         document.getElementById('opn-fw-proto')?.value.trim() || '',
    source_net:       document.getElementById('opn-fw-src')?.value.trim() || '',
    destination_net:  document.getElementById('opn-fw-dst')?.value.trim() || '',
    destination_port: document.getElementById('opn-fw-dport')?.value.trim() || '',
    description:      document.getElementById('opn-fw-desc')?.value.trim() || '',
  };
  if (!rule.interface) { toast('interface is required', 'error'); return; }
  if (!confirm(`Add a ${rule.action} rule on "${rule.interface}"? It will be created DISABLED — enable it from the table after reviewing.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/opnsense/action`, { action: 'add_filter_rule', rule });
  if (r && r.ok) { toast('Filter rule added (disabled) — review then enable', 'success'); loadOpnsenseFirewall(); }
  else toast((r && r.error) || 'Add failed', 'error');
}

async function addOpnsenseNatRule() {
  const id = _drawerDeviceId;
  if (!id) return;
  const rule = {
    interface:        document.getElementById('opn-nat-iface')?.value.trim() || '',
    ipprotocol:       document.getElementById('opn-nat-ipproto')?.value || 'inet',
    protocol:         document.getElementById('opn-nat-proto')?.value.trim() || '',
    source_net:       document.getElementById('opn-nat-src')?.value.trim() || '',
    destination_net:  document.getElementById('opn-nat-dst')?.value.trim() || '',
    target:           document.getElementById('opn-nat-target')?.value.trim() || '',
    target_port:      document.getElementById('opn-nat-tport')?.value.trim() || '',
    description:      document.getElementById('opn-nat-desc')?.value.trim() || '',
  };
  if (!rule.interface) { toast('interface is required', 'error'); return; }
  if (!rule.target) { toast('target (translation address) is required for outbound NAT', 'error'); return; }
  if (!confirm(`Add an outbound NAT rule on "${rule.interface}"? It will be created DISABLED — enable it from the table after reviewing.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/opnsense/action`, { action: 'add_nat_rule', rule });
  if (r && r.ok) { toast('NAT rule added (disabled) — review then enable', 'success'); loadOpnsenseFirewall(); }
  else toast((r && r.error) || 'Add failed', 'error');
}

async function opnsenseRuleToggle(uuid, mode, table) {
  const id = _drawerDeviceId;
  if (!id) return;
  if (mode === 'enable' && !confirm('Enable this rule? Make sure it won’t lock you out.')) return;
  const nat = table === 'nat';
  const action = mode === 'enable'
    ? (nat ? 'enable_nat_rule' : 'enable_filter_rule')
    : (nat ? 'disable_nat_rule' : 'disable_filter_rule');
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/opnsense/action`, { action, arg: uuid });
  if (r && r.ok) { toast(`Rule ${mode}d`, 'success'); loadOpnsenseFirewall(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function opnsenseRuleDelete(uuid, table) {
  const id = _drawerDeviceId;
  if (!id) return;
  const nat = table === 'nat';
  if (!confirm(`Permanently delete this ${nat ? 'NAT' : 'filter'} rule? This cannot be undone.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/opnsense/action`,
    { action: nat ? 'delete_nat_rule' : 'delete_filter_rule', arg: uuid });
  if (r && r.ok) { toast('Rule deleted', 'success'); loadOpnsenseFirewall(); }
  else toast((r && r.error) || 'Delete failed', 'error');
}

// ── v3.4.0: Synology (DSM) audit section — SSH creds + one-button upgrade ───
async function _renderSynologyCard(body, badge) {
  const id = _drawerDeviceId;
  if (!id || !body) return;
  let sshCfg = {}, sy = {};
  try { const s = await api('GET', `/devices/${encodeURIComponent(id)}/ssh`); sshCfg = (s && s.config) || {}; } catch (_) {}
  try {
    const sn = await api('GET', `/devices/${encodeURIComponent(id)}/snmp`);
    sy = (sn && sn.data && sn.data.synology && sn.data.synology.system) || {};
  } catch (_) {}

  let h = '';
  if (sy.model || sy.dsm_version) {
    h += `<div class="hint mb-6">${escHtml(sy.model || 'Synology')}${sy.dsm_version ? ' · ' + escHtml(sy.dsm_version) : ''}${sy.upgrade === 'available' ? ' · <span class="c-amber">DSM update available</span>' : ''}</div>`;
  } else {
    h += '<div class="hint mb-6">DSM health appears here once the device is polled over SNMP. The SSH upgrade below works independently of SNMP.</div>';
  }

  h += `<h4 class="mt-12">DSM upgrade (SSH)</h4>
    <div class="hint mb-6">Synology has no API to trigger a DSM upgrade, so this runs it over SSH (root). One button: it checks for a DSM update and, if found, applies it and <strong>reboots the NAS</strong>. Save SSH credentials once — a key (recommended) or a password (needs sshpass on the server).</div>
    <label class="click-row-6"><input type="checkbox" id="ssh-enabled" ${sshCfg.enabled ? 'checked' : ''}><span class="fs-12">Enable SSH for this device</span></label>
    <div class="row-6 mt-6">
      <input class="form-input mw-200" id="ssh-user" placeholder="username" value="${escAttr(sshCfg.username || 'root')}">
      <input class="form-input mw-200" id="ssh-port" type="number" placeholder="22" value="${sshCfg.port || 22}">
    </div>
    <input class="form-input mt-6" id="ssh-pass" type="password" placeholder="${sshCfg.has_password ? '•••••• (unchanged)' : 'password (or use a key below)'}">
    <textarea class="form-input mt-6" id="ssh-key" rows="2" placeholder="${sshCfg.has_key ? '•••••• private key stored (paste to replace)' : 'private key (PEM) — preferred, no sshpass needed'}"></textarea>
    <div class="row-6 mt-6">
      <button class="btn-icon" data-action="saveDeviceSsh">Save SSH credentials</button>
      <button class="btn-icon c-danger-outline" data-action="synologyUpgrade" title="Check for a DSM update; if found, apply it and reboot the NAS">${_icon('refresh',14)} Upgrade DSM &amp; reboot</button>
    </div>
    ${(sshCfg.has_password || sshCfg.has_key) ? '' : '<div class="hint mt-6">No SSH credentials saved yet — save them before using the upgrade button.</div>'}
    <div id="syno-upgrade-out"></div>`;

  badge.textContent = sy.dsm_version ? sy.dsm_version
                    : (sshCfg.enabled ? 'ssh on' : 'ssh off');
  body.innerHTML = h;
}

// ── v3.4.0: agentless SSH creds + Synology DSM upgrade ──────────────────────
async function saveDeviceSsh() {
  const id = _drawerDeviceId;
  if (!id) return;
  const body = {
    enabled:  !!document.getElementById('ssh-enabled')?.checked,
    username: document.getElementById('ssh-user')?.value.trim() || 'root',
    port:     parseInt(document.getElementById('ssh-port')?.value || '22', 10),
  };
  const pw = document.getElementById('ssh-pass')?.value || '';
  if (pw) body.password = pw;
  const k = document.getElementById('ssh-key')?.value || '';
  if (k.trim()) body.private_key = k;
  const r = await api('PATCH', `/devices/${encodeURIComponent(id)}/ssh`, body);
  if (r && r.ok) toast('SSH credentials saved', 'success');
  else toast((r && r.error) || 'Failed', 'error');
}

async function synologyUpgrade() {
  const id = _drawerDeviceId;
  if (!id) return;
  if (!confirm('Upgrade DSM and REBOOT this NAS now?\n\n' +
    'It checks for a DSM update and, if one is available, applies it and ' +
    'reboots the NAS — every service on it goes down during the reboot. ' +
    'Make sure SSH credentials are saved first.')) return;
  const out = document.getElementById('syno-upgrade-out');
  if (out) out.innerHTML = '<div class="hint mt-6">Starting DSM upgrade over SSH…</div>';
  toast('Starting DSM upgrade over SSH…', 'info');
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/synology/upgrade`, {});
  if (r && r.ok) {
    toast('DSM upgrade started', 'success');
    if (out) out.innerHTML = `<div class="hint mt-6 c-green">${escHtml(r.message || 'DSM upgrade started on the NAS.')}</div>`;
  } else {
    toast((r && r.error) || 'Upgrade failed', 'error');
    if (out) out.innerHTML = `<div class="hint mt-6 c-red">${escHtml((r && r.error) || 'Upgrade failed')}</div>`;
  }
}

// Render into whichever surface is active — the full-width console modal
// if it's open, else the compact drawer card.
function _routerosSurface() {
  const modal = document.getElementById('routeros-console-modal');
  if (modal && modal.classList.contains('active')) {
    return { body: document.getElementById('routeros-console-body'), badge: { textContent: '' } };
  }
  return {
    body:  document.getElementById('audit-body-routeros'),
    badge: document.getElementById('audit-badge-routeros') || { textContent: '' },
  };
}

async function routerosReload() {
  const id = _drawerDeviceId;
  if (!id) return;
  const { body, badge } = _routerosSurface();
  if (!body) return;
  body.innerHTML = '<div class="c-muted">Loading…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/routeros`);
  _renderRouterosCard(body, badge, data || {});
}

async function openRouterosConsole() {
  const id = _drawerDeviceId;
  if (!id) return;
  openModal('routeros-console-modal');
  const title = document.getElementById('routeros-console-title');
  if (title) title.textContent = `RouterOS — ${_drawerDeviceName || id}`;
  const body = document.getElementById('routeros-console-body');
  body.innerHTML = '<div class="c-muted">Loading…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/routeros`);
  _renderRouterosCard(body, { textContent: '' }, data || {});
  // Console-only: a Firewall section below the overview (P2).
  if (data && data.config && data.config.enabled) {
    const fw = document.createElement('div');
    fw.innerHTML = `
      <div class="page-title isl-172 mt-32">Firewall</div>
      <div class="row-6 mb-6">
        <button class="btn-icon" data-action="loadRouterosFirewall">Load rules</button>
        <button class="btn-icon" data-action="routerosFirewallExplain" title="AI: explain this ruleset + flag risks">${_icon('sparkles',14)} Explain</button>
        <button class="btn-icon" data-action="routerosFirewallDraft" title="AI: draft a rule from a plain-English description">${_icon('sparkles',14)} Draft rule</button>
      </div>
      <div id="ros-fw-body"><div class="c-muted">Click "Load rules".</div></div>`;
    body.appendChild(fw);

    const qos = document.createElement('div');
    qos.innerHTML = `
      <div class="page-title isl-172 mt-32">QoS &amp; traffic</div>
      <div class="row-6 mb-6">
        <button class="btn-icon" data-action="loadRouterosQos">Load queues</button>
        <button class="btn-icon" data-action="routerosLiveRates">Live interface rates</button>
      </div>
      <div id="ros-qos-body"><div class="c-muted">Queues, and a ~1s live-throughput sample per interface.</div></div>`;
    body.appendChild(qos);
  }
}

async function routerosCheckUpdate() {
  const id = _drawerDeviceId;
  if (!id) return;
  toast('Checking RouterOS for updates…', 'info');
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`, { action: 'check_update' });
  if (r && r.ok) routerosReload();
  else toast((r && r.error) || 'Check failed', 'error');
}

async function routerosUpgrade() {
  const id = _drawerDeviceId;
  if (!id) return;
  if (!confirm('Upgrade RouterOS firmware?\n\nThis downloads the update and REBOOTS the router — it will be offline for a minute or two. Run it in a maintenance window.')) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`, { action: 'upgrade' });
  if (r && r.ok) toast('Upgrade started — router is rebooting', 'success');
  else toast((r && r.error) || 'Upgrade failed', 'error');
}

// ── RouterOS firewall (P2) ──────────────────────────────────────────────────
let _rosFirewall = { filter: [], nat: [] };

async function loadRouterosFirewall() {
  const id = _drawerDeviceId;
  const body = document.getElementById('ros-fw-body');
  if (!id || !body) return;
  body.innerHTML = '<div class="c-muted">Loading rules…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/routeros/firewall`);
  if (!data || data.error) { body.innerHTML = `<div class="c-red">${escHtml((data && data.error) || 'Failed')}</div>`; return; }
  _rosFirewall = { filter: data.filter || [], nat: data.nat || [] };
  _renderRouterosFirewall(body);
}

function _ruleRow(r, table, ns) {
  ns = ns || 'routeros';   // 'routeros' | 'opnsense' — picks the handler pair
  const dimmed = r.disabled ? ' c-muted' : '';
  const toggle = r.disabled
    ? `<button class="btn-icon badge-xs" data-action="${ns}RuleToggle" data-arg="${escAttr(r.id)}" data-arg2="enable" data-arg3="${table}">Enable</button>`
    : `<button class="btn-icon badge-xs" data-action="${ns}RuleToggle" data-arg="${escAttr(r.id)}" data-arg2="disable" data-arg3="${table}">Disable</button>`;
  const del = `<button class="btn-icon badge-xs c-red" data-action="${ns}RuleDelete" data-arg="${escAttr(r.id)}" data-arg2="${table}" title="Delete this rule">${_icon('trash', 13)}</button>`;
  const actCls = r.action === 'drop' || r.action === 'reject' ? 'c-red' : (r.action === 'accept' || r.action === 'masquerade' ? 'c-green' : '');
  const natCell = table === 'nat'
    ? `<td class="mono-12">${escHtml([r.to_addresses, r.to_ports].filter(Boolean).join(':'))}</td>`
    : '';
  return `<tr class="${dimmed.trim()}">
    <td>${escHtml(r.chain || '')}</td>
    <td class="${actCls}">${escHtml(r.action || '')}${r.disabled ? ' <span class="hint">(off)</span>' : ''}</td>
    <td class="mono-12">${escHtml(r.src_address || '')}</td>
    <td class="mono-12">${escHtml(r.dst_address || '')}</td>
    <td class="hint">${escHtml([r.protocol, r.dst_port].filter(Boolean).join(':'))}</td>
    ${natCell}
    <td class="hint">${escHtml(r.comment || '')}</td>
    <td class="nowrap">${toggle} ${del}</td>
  </tr>`;
}

function _renderRouterosFirewall(body) {
  const f = _rosFirewall.filter || [], n = _rosFirewall.nat || [];
  let h = `<h4>Filter rules (${f.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Chain</th><th>Action</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>Comment</th><th></th></tr></thead><tbody>`;
  h += f.map(r => _ruleRow(r, 'filter')).join('') || '<tr><td colspan="7" class="c-muted">No filter rules.</td></tr>';
  h += '</tbody></table></div>';

  h += `<h4 class="mt-12">NAT rules (${n.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Chain</th><th>Action</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>→ to-addr:port</th><th>Comment</th><th></th></tr></thead><tbody>`;
  h += n.map(r => _ruleRow(r, 'nat')).join('') || '<tr><td colspan="8" class="c-muted">No NAT rules.</td></tr>';
  h += '</tbody></table></div>';

  // Add-filter-rule form. New rules land DISABLED for review.
  h += `<h4 class="mt-12">Add filter rule</h4>
    <div class="hint mb-6">New rules are created <strong>disabled</strong> — review, then Enable from the table.</div>
    <div class="row-6">
      <select class="form-input mw-200" id="fw-add-chain"><option value="input">input</option><option value="forward">forward</option><option value="output">output</option></select>
      <select class="form-input mw-200" id="fw-add-action"><option value="accept">accept</option><option value="drop">drop</option><option value="reject">reject</option></select>
    </div>
    <input class="form-input mt-6" id="fw-add-src" placeholder="src-address (e.g. 192.168.2.50)">
    <input class="form-input mt-6" id="fw-add-dst" placeholder="dst-address (optional)">
    <div class="row-6 mt-6">
      <input class="form-input mw-200" id="fw-add-proto" placeholder="protocol (tcp/udp/…)">
      <input class="form-input mw-200" id="fw-add-dport" placeholder="dst-port (optional)">
    </div>
    <input class="form-input mt-6" id="fw-add-comment" placeholder="comment">
    <div class="row-6 mt-6">
      <button class="btn-primary" data-action="addRouterosFirewallRule">Add rule (disabled)</button>
    </div>`;

  // Add-NAT-rule form. srcnat (masquerade/src-nat) or dstnat (dst-nat/redirect).
  h += `<h4 class="mt-12">Add NAT rule</h4>
    <div class="hint mb-6">New rules are created <strong>disabled</strong> — review, then Enable from the table. For masquerade leave to-addresses empty; for dst-nat set to-addresses (and to-ports for port-forward).</div>
    <div class="row-6">
      <select class="form-input mw-200" id="nat-add-chain"><option value="srcnat">srcnat</option><option value="dstnat">dstnat</option></select>
      <select class="form-input mw-200" id="nat-add-action"><option value="masquerade">masquerade</option><option value="src-nat">src-nat</option><option value="dst-nat">dst-nat</option><option value="redirect">redirect</option></select>
    </div>
    <input class="form-input mt-6" id="nat-add-src" placeholder="src-address (optional)">
    <input class="form-input mt-6" id="nat-add-dst" placeholder="dst-address (optional)">
    <div class="row-6 mt-6">
      <input class="form-input mw-200" id="nat-add-proto" placeholder="protocol (tcp/udp/…)">
      <input class="form-input mw-200" id="nat-add-dport" placeholder="dst-port (optional)">
    </div>
    <div class="row-6 mt-6">
      <input class="form-input mw-200" id="nat-add-toaddr" placeholder="to-addresses (e.g. 10.0.0.5)">
      <input class="form-input mw-200" id="nat-add-toports" placeholder="to-ports (e.g. 8080)">
    </div>
    <input class="form-input mt-6" id="nat-add-iface" placeholder="out-interface (srcnat) / in-interface (dstnat)">
    <input class="form-input mt-6" id="nat-add-comment" placeholder="comment">
    <div class="row-6 mt-6">
      <button class="btn-primary" data-action="addRouterosNatRule">Add NAT rule (disabled)</button>
    </div>`;
  body.innerHTML = h;
}

async function addRouterosFirewallRule() {
  const id = _drawerDeviceId;
  if (!id) return;
  const rule = {
    chain:   document.getElementById('fw-add-chain')?.value,
    action:  document.getElementById('fw-add-action')?.value,
    'src-address': document.getElementById('fw-add-src')?.value.trim() || '',
    'dst-address': document.getElementById('fw-add-dst')?.value.trim() || '',
    protocol: document.getElementById('fw-add-proto')?.value.trim() || '',
    'dst-port': document.getElementById('fw-add-dport')?.value.trim() || '',
    comment: document.getElementById('fw-add-comment')?.value.trim() || '',
    disabled: 'yes',
  };
  if (!confirm(`Add a ${rule.action} rule to chain "${rule.chain}"? It will be created DISABLED — enable it from the table after reviewing.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`, { action: 'add_firewall_rule', rule });
  if (r && r.ok) { toast('Rule added (disabled) — review then enable', 'success'); loadRouterosFirewall(); }
  else toast((r && r.error) || 'Add failed', 'error');
}

async function addRouterosNatRule() {
  const id = _drawerDeviceId;
  if (!id) return;
  const chain = document.getElementById('nat-add-chain')?.value;
  const iface = document.getElementById('nat-add-iface')?.value.trim() || '';
  const rule = {
    chain,
    action:  document.getElementById('nat-add-action')?.value,
    'src-address': document.getElementById('nat-add-src')?.value.trim() || '',
    'dst-address': document.getElementById('nat-add-dst')?.value.trim() || '',
    protocol: document.getElementById('nat-add-proto')?.value.trim() || '',
    'dst-port': document.getElementById('nat-add-dport')?.value.trim() || '',
    'to-addresses': document.getElementById('nat-add-toaddr')?.value.trim() || '',
    'to-ports': document.getElementById('nat-add-toports')?.value.trim() || '',
    comment: document.getElementById('nat-add-comment')?.value.trim() || '',
    disabled: 'yes',
  };
  // out-interface is the usual match for srcnat; in-interface for dstnat.
  if (iface) rule[chain === 'dstnat' ? 'in-interface' : 'out-interface'] = iface;
  if (!confirm(`Add a ${rule.action} rule to chain "${rule.chain}"? It will be created DISABLED — enable it from the table after reviewing.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`, { action: 'add_nat_rule', rule });
  if (r && r.ok) { toast('NAT rule added (disabled) — review then enable', 'success'); loadRouterosFirewall(); }
  else toast((r && r.error) || 'Add failed', 'error');
}

async function routerosRuleToggle(ruleId, mode, table) {
  const id = _drawerDeviceId;
  if (!id) return;
  if (mode === 'enable' && !confirm('Enable this rule? Make sure it won’t lock you out.')) return;
  const nat = table === 'nat';
  const action = mode === 'enable'
    ? (nat ? 'enable_nat_rule' : 'enable_rule')
    : (nat ? 'disable_nat_rule' : 'disable_rule');
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`,
    { action, arg: ruleId });
  if (r && r.ok) { toast(`Rule ${mode}d`, 'success'); loadRouterosFirewall(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function routerosRuleDelete(ruleId, table) {
  const id = _drawerDeviceId;
  if (!id) return;
  const nat = table === 'nat';
  if (!confirm(`Permanently delete this ${nat ? 'NAT' : 'filter'} rule? This cannot be undone.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`,
    { action: nat ? 'delete_nat_rule' : 'delete_filter_rule', arg: ruleId });
  if (r && r.ok) { toast('Rule deleted', 'success'); loadRouterosFirewall(); }
  else toast((r && r.error) || 'Delete failed', 'error');
}

function _rosFirewallText() {
  const fmt = (r) => `${r.chain} ${r.action} src=${r.src_address || '-'} dst=${r.dst_address || '-'} ` +
    `${[r.protocol, r.dst_port].filter(Boolean).join(':')} ${r.disabled ? '[disabled] ' : ''}${r.comment ? '# ' + r.comment : ''}`;
  return 'FILTER:\n' + (_rosFirewall.filter || []).map(fmt).join('\n') +
         '\n\nNAT:\n' + (_rosFirewall.nat || []).map(fmt).join('\n');
}

function routerosFirewallExplain() {
  if (!(_rosFirewall.filter || []).length && !(_rosFirewall.nat || []).length) {
    toast('Load the rules first', 'info'); return;
  }
  openAIModal({
    title:   'Explain firewall',
    system:  'routeros_firewall_explain',
    userMsg: _rosFirewallText(),
    context: 'routeros-firewall',
    maxTokens: 1500,
  });
}

async function routerosFirewallDraft() {
  const desc = await uiPrompt({title: 'Draft firewall rule',
    message: 'Describe the rule in plain English:', multiline: true,
    placeholder: 'e.g. block 192.168.2.50 from reaching the internet', confirmText: 'Draft'});
  if (!desc) return;
  openAIModal({
    title:   'Draft firewall rule',
    system:  'routeros_firewall_rule',
    userMsg: desc,
    context: 'routeros-firewall',
    maxTokens: 500,
    actionLabel: 'Fill the add-rule form',
    onResult: (text) => {
      let rule;
      try { rule = JSON.parse(text.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '')); }
      catch (e) { toast('AI did not return a clean rule — see the response', 'error'); return; }
      const set = (id, v) => { const el = document.getElementById(id); if (el && v != null) el.value = v; };
      set('fw-add-chain', rule.chain); set('fw-add-action', rule.action);
      set('fw-add-src', rule['src-address'] || rule.src_address || '');
      set('fw-add-dst', rule['dst-address'] || rule.dst_address || '');
      set('fw-add-proto', rule.protocol || '');
      set('fw-add-dport', rule['dst-port'] || rule.dst_port || '');
      set('fw-add-comment', rule.comment || 'drafted by AI — review before enabling');
      toast('Form filled from AI draft — review, then Add (it stays disabled)', 'success');
    },
  });
}

// ── RouterOS QoS + live traffic (P3) ────────────────────────────────────────
async function loadRouterosQos() {
  const id = _drawerDeviceId;
  const body = document.getElementById('ros-qos-body');
  if (!id || !body) return;
  body.innerHTML = '<div class="c-muted">Loading queues…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/routeros/qos`);
  if (!data || data.error) { body.innerHTML = `<div class="c-red">${escHtml((data && data.error) || 'Failed')}</div>`; return; }
  const rows = (data.simple || []).concat(data.tree || []);
  if (!rows.length) { body.innerHTML = '<div class="c-muted">No queues configured.</div>'; return; }
  let h = `<h4>Queues (${rows.length})</h4><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Name</th><th>Target / parent</th><th>Max limit</th><th>Rate</th></tr></thead><tbody>`;
  for (const q of rows) {
    h += `<tr class="${q.disabled ? 'c-muted' : ''}"><td><strong>${escHtml(q.name || '')}</strong>${q.disabled ? ' <span class="hint">(off)</span>' : ''}</td><td class="mono-12">${escHtml(q.target || '')}</td><td class="hint">${escHtml(q.max_limit || '')}</td><td class="hint">${escHtml(q.rate || '')}</td></tr>`;
  }
  h += '</tbody></table></div><div class="row-6 mt-6"><button class="btn-icon" data-action="routerosLiveRates">Live interface rates</button></div>';
  body.innerHTML = h;
}

async function routerosLiveRates() {
  const id = _drawerDeviceId;
  const body = document.getElementById('ros-qos-body');
  if (!id || !body) return;
  body.innerHTML = '<div class="c-muted">Sampling ~1s…</div>';
  const data = await api('GET', `/devices/${encodeURIComponent(id)}/routeros/traffic`);
  if (!data || data.error) { body.innerHTML = `<div class="c-red">${escHtml((data && data.error) || 'Failed')}</div>`; return; }
  const fmt = (b) => {
    const u = ['bit/s', 'Kbit/s', 'Mbit/s', 'Gbit/s']; let i = 0; let v = b || 0;
    while (v >= 1000 && i < u.length - 1) { v /= 1000; i++; }
    return v.toFixed(v < 10 && i ? 1 : 0) + ' ' + u[i];
  };
  const ifs = (data.interfaces || []).filter(i => i.rx_bps || i.tx_bps);
  let h = `<h4>Live interface rates</h4><div class="hint mb-6">~1-second sample.</div><div class="scrollable-table-wrap audit-scroll"><table class="fs-13"><thead><tr><th>Interface</th><th class="ta-right">RX</th><th class="ta-right">TX</th></tr></thead><tbody>`;
  if (!ifs.length) h += '<tr><td colspan="3" class="c-muted">No active traffic right now.</td></tr>';
  for (const i of ifs) {
    h += `<tr><td><strong>${escHtml(i.name)}</strong></td><td class="ta-right c-green">${fmt(i.rx_bps)}</td><td class="ta-right c-accent">${fmt(i.tx_bps)}</td></tr>`;
  }
  h += '</tbody></table></div><div class="row-6 mt-6"><button class="btn-icon" data-action="routerosLiveRates">Refresh</button><button class="btn-icon" data-action="loadRouterosQos">Queues</button></div>';
  body.innerHTML = h;
}

async function routerosAction(action, arg) {
  const id = _drawerDeviceId;
  if (!id) return;
  if (action === 'reboot' && !confirm('Reboot this RouterOS device?')) return;
  if (action === 'disable_interface' &&
      !confirm('Disable this interface? If it carries your access you could lock yourself out.')) return;
  const r = await api('POST', `/devices/${encodeURIComponent(id)}/routeros/action`, { action, arg });
  if (!r || r.error) { toast(r?.error || 'Action failed', 'error'); return; }
  if (action === 'export' && r.result && r.result.export != null) {
    const out = document.getElementById('ros-action-out');
    if (out) out.innerHTML = `<h4 class="mt-12">Config export</h4><pre class="isl-514"><code>${escHtml(r.result.export)}</code></pre>`;
    toast('Config exported', 'success');
    return;
  }
  toast(`${action.replace('_', ' ')} ok`, 'success');
  if (action !== 'export') routerosReload();
}

