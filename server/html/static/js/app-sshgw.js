// RemotePower — SSH gateway page: your keys, the ~/.ssh/config block, which
// servers are opted in, and the session log.
//
// Lazy, page-scoped module (see _LAZY_PAGE_MODULES in app.js).
//
// api() RESOLVES on 403/404 rather than throwing, so every outcome is read from
// the resolved body. Device ids and fingerprints travel in data-dev / data-fp
// attributes read by delegated listeners, not through the data-arg dispatcher,
// which turns numeric-looking strings into numbers.

let _sshgwStatus = null;
let _sshgwKeys = [];
let _sshgwDevices = [];
let _sshgwSessions = [];
let _sshgwWired = false;

function _sshgwConfigText(st) {
  const host = (st && st.public_host) || 'gateway.example.com';
  const port = (st && st.public_port) || 2222;
  const user = (st && st.username) || 'you';
  const suffix = (st && st.target_suffix) || '.rp';
  // The gateway is its own Host entry: options under `Host *.rp` apply to the
  // server being reached, never to the jump host, so an IdentityFile written
  // there would not be offered to the gateway.
  return `Host rp-gateway\n    HostName ${host}\n` + (port === 22 ? '' : `    Port ${port}\n`) +
    `    User ${user}\n` +
    `    # If you have more than one key, name the one you added on this page:\n` +
    `    # IdentityFile ~/.ssh/id_ed25519\n    # IdentitiesOnly yes\n\n` +
    `Host *${suffix}\n    ProxyJump rp-gateway\n`;
}

function _sshgwWire() {
  if (_sshgwWired) return;
  _sshgwWired = true;
  const keys = document.getElementById('sshgw-keys-tbody');
  if (keys) keys.addEventListener('click', (ev) => {
    const btn = ev.target.closest('button[data-fp]');
    if (btn) deleteSshgwKey(btn.dataset.fp, btn.dataset.user || '');
  });
  const devs = document.getElementById('sshgw-dev-tbody');
  if (devs) devs.addEventListener('change', (ev) => {
    const cb = ev.target.closest('input[data-dev]');
    if (cb) toggleSshgwDevice(cb.dataset.dev, cb.checked, cb);
  });
  const filter = document.getElementById('sshgw-dev-filter');
  if (filter) filter.addEventListener('input', () => _sshgwRenderDevices());
}

async function loadSshgw() {
  tableCtl.wireSortOnly('sshgw-keys-thead', 'sshgw-keys', () => _sshgwRenderKeys());
  tableCtl.wireSortOnly('sshgw-dev-thead', 'sshgw-dev', () => _sshgwRenderDevices());
  tableCtl.wireSortOnly('sshgw-sess-thead', 'sshgw-sess', () => _sshgwRenderSessions());
  _sshgwWire();
  const st = await api('GET', '/sshgw/status').catch(() => null);
  const stateEl = document.getElementById('sshgw-state');
  if (!st || st.error) {
    // The module 404s its whole prefix when switched off.
    _sshgwStatus = null;
    if (stateEl) stateEl.textContent = 'The SSH gateway is turned off. An admin can turn it on in Settings → Advanced.';
    document.getElementById('sshgw-config').textContent = _sshgwConfigText(null);
    return;
  }
  _sshgwStatus = st;
  document.getElementById('sshgw-config').textContent = _sshgwConfigText(st);
  const notes = [];
  if (!st.public_host) notes.push('No public hostname is set yet, so the block below shows a placeholder.');
  if (!st.daemon_secret_set) notes.push('The gateway service is not connected to RemotePower yet. Install it with install-server.sh --with-sshgw.');
  if (!st.can_connect) notes.push('Your role does not have the ssh permission, so the gateway will refuse your connections.');
  // One element per note, so each is a whole text node the i18n engine can match.
  if (stateEl) stateEl.innerHTML = notes.map(n => `<div>${escHtml(n)}</div>`).join('');
  const admin = document.getElementById('sshgw-admin-card');
  if (admin) {
    admin.hidden = !st.is_admin;
    if (st.is_admin) {
      document.getElementById('sshgw-public-host').value = st.public_host || '';
      document.getElementById('sshgw-public-port').value = st.public_port || 2222;
    }
  }
  const [k, d, s] = await Promise.all([
    api('GET', '/sshgw/keys').catch(() => null),
    api('GET', '/sshgw/devices').catch(() => null),
    api('GET', '/sshgw/sessions').catch(() => null),
  ]);
  _sshgwKeys = (k && Array.isArray(k.keys)) ? k.keys : [];
  if (k && Array.isArray(k.all_keys)) {
    // Admins see every account's keys, so they can revoke one.
    _sshgwKeys = k.all_keys;
  }
  _sshgwDevices = (d && Array.isArray(d.devices)) ? d.devices : [];
  // Sessions are admins and auditors only; anyone else gets a 403 body.
  const sessCard = document.getElementById('sshgw-sessions-card');
  _sshgwSessions = (s && Array.isArray(s.sessions)) ? s.sessions : [];
  if (sessCard) sessCard.hidden = !(s && Array.isArray(s.sessions));
  // Clearing is for admins; auditors can read the list but not empty it.
  const sessTools = document.getElementById('sshgw-sess-tools');
  if (sessTools) sessTools.hidden = !(_sshgwStatus && _sshgwStatus.is_admin);
  _sshgwRenderKeys();
  _sshgwRenderDevices();
  _sshgwRenderSessions();
}

function _sshgwRenderKeys() {
  const tb = document.getElementById('sshgw-keys-tbody');
  if (!tb) return;
  const me = _sshgwStatus ? _sshgwStatus.username : '';
  const rows = tableCtl.sortRows('sshgw-keys', _sshgwKeys, r => ({
    name: (r.username && r.username !== me ? r.username + ' / ' : '') + (r.name || ''),
    type: r.type || '', fingerprint: r.fingerprint || '',
    added: r.added || 0, last_used: r.last_used || 0,
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="6" class="hint">${escHtml('No keys yet.')}</td></tr>`;
    return;
  }
  tb.innerHTML = rows.map(r => {
    const owner = r.username && r.username !== me
      ? `<span class="hint">${escHtml(r.username)}</span> ` : '';
    return `<tr>
      <td>${owner}${escHtml(r.name || '')}</td>
      <td>${escHtml(r.type || '')}</td>
      <td class="ff-mono fs-11">${escHtml(r.fingerprint || '')}</td>
      <td>${escHtml(timeAgo(r.added))}</td>
      <td>${escHtml(timeAgo(r.last_used, {empty: 'never'}))}</td>
      <td><button class="btn-icon" data-fp="${escAttr(r.fingerprint || '')}" data-user="${escAttr(r.username || '')}" aria-label="Remove key"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/></svg> Remove</button></td>
    </tr>`;
  }).join('');
}

function _sshgwRenderDevices() {
  const tb = document.getElementById('sshgw-dev-tbody');
  if (!tb) return;
  const q = ((document.getElementById('sshgw-dev-filter') || {}).value || '').trim().toLowerCase();
  const admin = !!(_sshgwStatus && _sshgwStatus.is_admin);
  let rows = _sshgwDevices;
  if (q) rows = rows.filter(r => `${r.name} ${r.hostname} ${r.os}`.toLowerCase().includes(q));
  rows = tableCtl.sortRows('sshgw-dev', rows, r => ({
    name: r.name || '', hostname: r.hostname || '', os: r.os || '',
    enabled: r.enabled ? 1 : 0, tunnel_seen: r.tunnel_seen || 0,
    last_session: r.last_session || 0,
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="6" class="hint">${escHtml('No servers to show.')}</td></tr>`;
    return;
  }
  tb.innerHTML = rows.map(r => {
    const disabled = (!admin || (!r.linux && !r.enabled)) ? ' disabled' : '';
    const why = !r.linux ? ' title="Linux agents only for now"' : '';
    return `<tr>
      <td>${escHtml(r.name || r.device_id)}</td>
      <td>${escHtml(r.hostname || '')}</td>
      <td>${escHtml(r.os || '')}</td>
      <td><input type="checkbox" data-dev="${escAttr(r.device_id)}"${r.enabled ? ' checked' : ''}${disabled}${why} aria-label="Reachable through the gateway"></td>
      <td>${escHtml(timeAgo(r.tunnel_seen, {empty: 'never'}))}</td>
      <td>${escHtml(timeAgo(r.last_session, {empty: 'never'}))}</td>
    </tr>`;
  }).join('');
}

function _sshgwRenderSessions() {
  const tb = document.getElementById('sshgw-sess-tbody');
  if (!tb) return;
  const names = {};
  for (const d of _sshgwDevices) names[d.device_id] = d.name;
  const rows = tableCtl.sortRows('sshgw-sess', _sshgwSessions, r => ({
    started: r.started || 0, username: r.username || '',
    device: names[r.device_id] || r.device_id || '', client_ip: r.client_ip || '',
    duration_s: r.duration_s || 0, bytes: (r.bytes_in || 0) + (r.bytes_out || 0),
    reason: r.reason || '',
  }));
  if (!rows.length) {
    tb.innerHTML = `<tr><td colspan="7" class="hint">${escHtml('No sessions yet.')}</td></tr>`;
    return;
  }
  tb.innerHTML = rows.map(r => `<tr>
      <td>${escHtml(timeAgo(r.started))}</td>
      <td>${escHtml(r.username || '')}</td>
      <td>${escHtml(names[r.device_id] || r.device_id || '')}</td>
      <td class="ff-mono">${escHtml(r.client_ip || '')}</td>
      <td>${escHtml((r.duration_s || 0) < 60 ? `${r.duration_s || 0}s` : _fmtDuration(r.duration_s))}</td>
      <td>${escHtml(_fmtBytes(r.bytes_in || 0))} / ${escHtml(_fmtBytes(r.bytes_out || 0))}</td>
      <td class="hint">${escHtml(r.reason || '')}</td>
    </tr>`).join('');
}

function copySshgwConfig() {
  copyText(_sshgwConfigText(_sshgwStatus));
}

async function addSshgwKey() {
  const keyEl = document.getElementById('sshgw-key-text');
  const nameEl = document.getElementById('sshgw-key-name');
  const pwEl = document.getElementById('sshgw-key-pw');
  const secret = pwEl.value;
  const body = {public_key: keyEl.value.trim(), name: nameEl.value.trim()};
  // One field for both: a six-digit answer is a TOTP code, anything else the
  // password. The server accepts either.
  if (/^\d{6}$/.test(secret)) body.totp_code = secret; else body.password = secret;
  if (!body.public_key) { toast('Paste a public key first', 'error'); return; }
  const r = await api('POST', '/sshgw/keys', body).catch(() => null);
  pwEl.value = '';
  if (!r || r.error) { toast((r && r.error) || 'Could not add the key', 'error'); return; }
  keyEl.value = '';
  nameEl.value = '';
  toast('Key added', 'success');
  loadSshgw();
}

async function deleteSshgwKey(fp, user) {
  if (!fp) return;
  const ok = await uiConfirm({title: 'Remove key', message: 'Remove this key? Connections already open stay open; new ones are refused.', confirmText: 'Remove', danger: true});
  if (!ok) return;
  const body = {fingerprint: fp};
  if (user) body.username = user;
  const r = await api('DELETE', '/sshgw/keys', body).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not remove the key', 'error'); return; }
  toast('Key removed', 'success');
  loadSshgw();
}

async function clearSshgwSessions() {
  const ok = await uiConfirm({title: 'Clear sessions', message: 'Remove every session from this list? The audit log keeps the record of who connected.', confirmText: 'Clear', danger: true});
  if (!ok) return;
  const r = await api('DELETE', '/sshgw/sessions').catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not clear the sessions', 'error'); return; }
  toast(`Cleared ${r.removed || 0} sessions`, 'success');
  loadSshgw();
}

async function toggleSshgwDevice(devId, enabled, el) {
  const r = await api('PATCH', `/devices/${encodeURIComponent(devId)}/sshgw`, {enabled}).catch(() => null);
  if (!r || r.error) {
    if (el) el.checked = !enabled;
    toast((r && r.error) || 'Could not change the server', 'error');
    return;
  }
  const row = _sshgwDevices.find(d => d.device_id === devId);
  if (row) row.enabled = enabled;
}

async function saveSshgwAddress() {
  const host = document.getElementById('sshgw-public-host').value.trim();
  const port = parseInt(document.getElementById('sshgw-public-port').value, 10) || 2222;
  const r = await api('POST', '/config', {sshgw_public_host: host, sshgw_public_port: port}).catch(() => null);
  if (!r || r.error) { toast((r && r.error) || 'Could not save', 'error'); return; }
  toast('Saved', 'success');
  loadSshgw();
}
