// app-kmip.js — Security → KMIP key server (v6.4.0).
// Buildless classic script; all symbols are globals like the rest of the
// client JS. Lazy-loaded via _LAZY_PAGE_MODULES.

let _kmipStatus = null;
let _kmipClients = [];
let _kmipKeys = [];
let _kmipLog = [];
let _kmipWizStep = 1;
let _kmipWizCreds = null;      // issued creds, held in memory for this wizard run only
let _kmipWizPoll = null;

const _KMIP_KIND_LABELS = {
  synology: 'Synology DSM',
  truenas: 'TrueNAS',
  vsphere: 'VMware vSphere',
  generic: 'Generic KMIP',
};

function _kmipAgo(ts) {
  if (!ts) return '—';
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

function _kmipDate(ts) {
  return ts ? new Date(ts * 1000).toLocaleDateString() : '—';
}

// api() resolves with the parsed body for EVERY status, 2xx or not — it only
// returns null on a 401 (where it has already logged out). So `if (!r) return`
// happily lets a 500 body through, and the code below would close the modal and
// toast success over a failed save. That shipped: enabling the KMIP server
// 500'd server-side while the UI said "KMIP server enabled" and left the
// checkbox unticked. Every KMIP call goes through this instead.
function _kmipOk(r, what) {
  if (!r) return false;                     // 401 — doLogout() already ran
  if (r.error) {
    toast(`${what} failed: ${r.error}`, 'error', { duration: 10000 });
    return false;
  }
  return true;
}

// ── page load ───────────────────────────────────────────────────────────────
async function loadKmip() {
  const tbody = document.getElementById('kmip-clients-tbody');
  if (!tbody) return;
  tableCtl.wireSortOnly('kmip-clients-thead', 'kmipclients', () => _renderKmipClients());
  tableCtl.wireSortOnly('kmip-keys-thead', 'kmipkeys', () => _renderKmipKeys());
  tableCtl.wireSortOnly('kmip-log-thead', 'kmiplog', () => _renderKmipLog());
  tbody.innerHTML = _skeletonRows(7);
  try {
    const [status, clients, keys] = await Promise.all([
      api('GET', '/kmip/status'),
      api('GET', '/kmip/clients'),
      api('GET', '/kmip/keys'),
    ]);
    if (!_kmipOk(status, 'Loading KMIP status')) return;
    _kmipStatus = status;
    _kmipClients = (clients && clients.clients) || [];
    _kmipKeys = (keys && keys.keys) || [];
    _renderKmipServer();
    _renderKmipClients();
    _renderKmipKeys();
  } catch (e) {
    _errorState(tbody, loadKmip, { msg: `Failed to load: ${String(e)}`, colspan: 7 });
  }
  kmipLoadLog();
}

function _renderKmipServer() {
  const el = document.getElementById('kmip-server-status');
  if (!el || !_kmipStatus) return;
  const s = _kmipStatus;
  const rows = [];
  const stateTone = !s.enabled ? 'muted' : (s.daemon_alive ? 'ok' : 'warn');
  const stateText = !s.enabled ? 'Disabled'
    : (s.daemon_alive ? `Running · port ${s.port}` : 'Enabled, but the sidecar has not checked in');
  rows.push(['Status', stateText, stateTone]);
  // secret_hint explains a half-installed state ("the file is there but this
  // server cannot read it") — a bare "not installed" was actively misleading
  // when the daemon was running fine and only the API's view was broken.
  rows.push(['Sidecar', s.secret_installed
    ? (s.daemon_alive ? `Last seen ${_kmipAgo(s.daemon_last_seen)}`
       : (s.secret_hint || 'Installed, but the sidecar has not checked in'))
    : (s.secret_hint || 'Not installed — use “Install sidecar”'),
    (s.secret_installed && s.daemon_alive) ? '' : 'warn']);
  rows.push(['Certificate authority', s.ca
    ? `Expires ${_kmipDate(s.ca.not_after)}` : 'Not generated yet', '']);
  rows.push(['Server certificate', s.server_cert
    ? `${(s.server_cert.hosts || []).join(', ') || '—'} · expires ${_kmipDate(s.server_cert.not_after)}`
    : 'Not generated yet', '']);
  const c = s.counts || {};
  rows.push(['Clients', `${c.clients_active || 0} active of ${c.clients || 0}`, '']);
  rows.push(['Stored keys', `${c.objects || 0} (${c.keys_active || 0} active)`, '']);

  el.textContent = '';
  const dl = document.createElement('div');
  dl.className = 'kmip-status-grid';
  for (const [label, value, tone] of rows) {
    const k = document.createElement('div');
    k.className = 'hint';
    k.textContent = label;
    const v = document.createElement('div');
    if (tone) v.className = tone === 'ok' ? 'c-green' : (tone === 'warn' ? 'c-warning' : 'hint');
    v.textContent = value;
    dl.appendChild(k);
    dl.appendChild(v);
  }
  el.appendChild(dl);

  const hint = document.getElementById('kmip-recovery-hint');
  if (hint) {
    hint.textContent = s.master_key
      ? 'A master key exists on this server. Without a bundle, losing this machine means losing every key it holds.'
      : 'KMIP is not set up yet — nothing to export.';
  }
}

function _renderKmipClients() {
  const tbody = document.getElementById('kmip-clients-tbody');
  if (!tbody) return;
  let rows = _kmipClients.slice();
  rows = tableCtl.sortRows('kmipclients', rows, (r) => ({
    name: (r.name || '').toLowerCase(),
    kind: r.kind || '',
    fingerprint: r.fingerprint || '',
    last_seen: r.last_seen || 0,
    objects: r.objects || 0,
    status: r.revoked ? 0 : 1,
  }));
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="hint">No clients yet. Use “Add client” to register your first appliance.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => `<tr>
    <td>${escHtml(r.name || '')}</td>
    <td>${escHtml(_KMIP_KIND_LABELS[r.kind] || r.kind || '')}</td>
    <td class="mono fs-11" title="SHA-256 fingerprint">${escHtml((r.fingerprint || '').slice(0, 16))}…<br><span class="hint">expires ${escHtml(_kmipDate(r.not_after))}</span></td>
    <td>${escHtml(_kmipAgo(r.last_seen))}${r.last_peer ? `<br><span class="hint mono fs-11">${escHtml(r.last_peer)}</span>` : ''}</td>
    <td>${r.objects || 0}</td>
    <td>${r.revoked
      ? '<span class="status-pill critical">Revoked</span>'
      : '<span class="status-pill ok">Active</span>'}</td>
    <td class="ta-right">
      <button class="btn-icon" data-action-btn="kmipReissueClient" data-cid="${escAttr(r.id)}" data-name="${escAttr(r.name || '')}" data-kind="${escAttr(r.kind || 'generic')}" title="Issue a replacement certificate — the appliance keeps its stored keys">Re-issue</button>
      ${r.revoked ? '' : `<button class="btn-icon" data-action-btn="kmipRevokeClient" data-cid="${escAttr(r.id)}" data-name="${escAttr(r.name || '')}" title="Block this appliance from the KMIP server">Revoke</button>`}
      <button class="btn-icon" data-action-btn="kmipDeleteClient" data-cid="${escAttr(r.id)}" data-name="${escAttr(r.name || '')}" data-keys="${r.objects || 0}" title="Remove this client registration entirely">Delete</button>
    </td>
  </tr>`).join('');
}

function _renderKmipKeys() {
  const tbody = document.getElementById('kmip-keys-tbody');
  if (!tbody) return;
  let rows = _kmipKeys.slice();
  rows = tableCtl.sortRows('kmipkeys', rows, (r) => ({
    uid: parseInt(r.uid, 10) || 0,
    name: (r.name || '').toLowerCase(),
    object_type: r.object_type || '',
    algorithm: r.algorithm || 0,
    state: r.state || '',
    client: (r.client || '').toLowerCase(),
    last_access: r.last_access || 0,
  }));
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="hint">No keys stored yet. They appear here once an appliance registers or creates one.</td></tr>';
    return;
  }
  const algName = { 3: 'AES', 4: '3DES', 6: 'RSA', 15: 'HMAC-SHA256' };
  const stateBadge = {
    active: 'ok', pre_active: 'info', deactivated: 'warn',
    compromised: 'critical', destroyed: 'neutral',
  };
  tbody.innerHTML = rows.map(r => `<tr>
    <td class="mono">${escHtml(r.uid)}</td>
    <td>${escHtml(r.name || '—')}</td>
    <td>${escHtml((r.object_type || '').replace(/_/g, ' '))}</td>
    <td>${escHtml(algName[r.algorithm] || (r.algorithm ? String(r.algorithm) : '—'))}${r.length ? ` ${r.length}` : ''}</td>
    <td><span class="status-pill ${stateBadge[r.state] || 'neutral'}">${escHtml((r.state || '').replace(/_/g, '-'))}</span></td>
    <td>${escHtml(r.client || '—')}</td>
    <td>${escHtml(_kmipAgo(r.last_access))}${r.access_count ? `<br><span class="hint">${r.access_count} reads</span>` : ''}</td>
    <td class="ta-right">${r.state === 'destroyed'
      ? `<button class="btn-icon" data-action-btn="kmipPurgeKey" data-uid="${escAttr(r.uid)}" data-name="${escAttr(r.name || r.uid)}" title="Remove this destroyed record from the inventory">Remove</button>`
      : `<button class="btn-icon" data-action-btn="kmipDestroyKey" data-uid="${escAttr(r.uid)}" data-name="${escAttr(r.name || r.uid)}" title="Permanently destroy this key">Destroy</button>`}</td>
  </tr>`).join('');
}

async function kmipLoadLog() {
  const tbody = document.getElementById('kmip-log-tbody');
  if (!tbody) return;
  tbody.innerHTML = _skeletonRows(7, 3);
  try {
    const data = await api('GET', '/kmip/log?n=300');
    _kmipLog = (data && data.entries) || [];
    _renderKmipLog();
  } catch (e) {
    _errorState(tbody, kmipLoadLog, { msg: `Failed to load: ${String(e)}`, colspan: 7 });
  }
}

function _renderKmipLog() {
  const tbody = document.getElementById('kmip-log-tbody');
  if (!tbody) return;
  let rows = _kmipLog.slice();
  rows = tableCtl.sortRows('kmiplog', rows, (r) => ({
    ts: r.ts || 0,
    kind: r.kind || '',
    client: (r.client || '').toLowerCase(),
    op: r.op || '',
    uid: parseInt(r.uid, 10) || 0,
    ok: r.ok === false ? 0 : 1,
    detail: r.detail || '',
  }));
  const sm = document.getElementById('kmip-log-summary');
  if (sm) {
    const fails = rows.filter(r => r.ok === false || r.kind === 'auth_fail').length;
    sm.textContent = `${rows.length} event(s)${fails ? ` · ${fails} failed` : ''}`;
  }
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="hint">Nothing logged yet.</td></tr>';
    return;
  }
  const kindBadge = {
    op: 'info', connect: 'ok', auth_fail: 'critical',
    started: 'neutral', admin: 'warn',
  };
  tbody.innerHTML = rows.map(r => `<tr>
    <td class="mono fs-11">${escHtml(new Date((r.ts || 0) * 1000).toLocaleString())}</td>
    <td><span class="status-pill ${kindBadge[r.kind] || 'neutral'}">${escHtml((r.kind || '').replace(/_/g, ' '))}</span></td>
    <td>${escHtml(r.client || r.actor || '—')}</td>
    <td>${escHtml((r.op || '').replace(/_/g, ' ') || '—')}</td>
    <td class="mono">${escHtml(r.uid || '—')}</td>
    <td>${r.ok === false ? '<span class="c-warning">failed</span>' : (r.kind === 'auth_fail' ? '<span class="c-warning">rejected</span>' : 'ok')}</td>
    <td class="hint">${escHtml(r.detail || (r.peer ? `from ${r.peer}` : ''))}</td>
  </tr>`).join('');
}

// ── server settings ─────────────────────────────────────────────────────────
function kmipOpenConfig() {
  const s = _kmipStatus || {};
  document.getElementById('kmip-cfg-enabled').checked = !!s.enabled;
  document.getElementById('kmip-cfg-port').value = s.port || 5696;
  document.getElementById('kmip-cfg-hosts').value =
    ((s.server_cert && s.server_cert.hosts) || []).join(' ');
  openModal('kmip-config-modal');
}

async function kmipSaveConfig() {
  const enabled = document.getElementById('kmip-cfg-enabled').checked;
  const hosts = document.getElementById('kmip-cfg-hosts').value;
  // The port is display-only: the sidecar binds from RP_KMIP_BIND and never
  // reads a configured value, so sending one here only created a setting that
  // appeared to work while the daemon stayed where it was.
  try {
    const r = await api('POST', '/kmip/config', { enabled, hosts });
    if (!_kmipOk(r, 'Saving KMIP settings')) { loadKmip(); return; }
    closeModal('kmip-config-modal');
    toast(enabled ? 'KMIP server enabled' : 'KMIP server disabled', 'success');
    loadKmip();
  } catch (e) {
    toast(`Save failed: ${String(e)}`, 'error');
  }
}

async function kmipShowInstall() {
  try {
    const r = await api('GET', '/kmip/install');
    if (!_kmipOk(r, 'Loading the install snippet')) return;
    document.getElementById('kmip-install-snippet').textContent = r.snippet || '';
    const note = document.getElementById('kmip-install-note');
    note.textContent = r.already_installed
      ? 'A secret is already installed on this server. Running this again replaces it — the sidecar must be restarted afterwards.'
      : 'The secret is shown once. Run the commands on the RemotePower server itself.';
    openModal('kmip-install-modal');
  } catch (e) {
    toast(`Failed: ${String(e)}`, 'error');
  }
}

async function kmipCopySnippet() {
  const txt = document.getElementById('kmip-install-snippet').textContent || '';
  try {
    await navigator.clipboard.writeText(txt);
    toast('Commands copied', 'success', { transient: true });
  } catch {
    toast('Could not copy — select the text manually', 'error', { transient: true });
  }
}

// ── client wizard ───────────────────────────────────────────────────────────
function kmipOpenWizard() {
  _kmipWizStep = 1;
  _kmipWizCreds = null;
  document.getElementById('kmip-wiz-name').value = '';
  document.getElementById('kmip-wiz-address').value = '';
  document.getElementById('kmip-wiz-kind').value = 'synology';
  document.getElementById('kmip-wiz-fp').textContent = '';
  document.getElementById('kmip-wiz-instructions').textContent = '';
  document.getElementById('kmip-wiz-waiting').textContent = '';
  _kmipRenderWizStep();
  openModal('kmip-wizard-modal');
  setTimeout(() => document.getElementById('kmip-wiz-name').focus(), 50);
}

function kmipWizardClose() {
  if (_kmipWizPoll) { clearInterval(_kmipWizPoll); _kmipWizPoll = null; }
  _kmipWizCreds = null;             // drop the private key from memory
  closeModal('kmip-wizard-modal');
  loadKmip();
}

function _kmipRenderWizStep() {
  document.querySelectorAll('#kmip-wizard-modal .kmip-step').forEach(el => {
    el.classList.toggle('d-none', Number(el.dataset.step) !== _kmipWizStep);
  });
  document.querySelectorAll('#kmip-wizard-modal .acme-step-pill').forEach(el => {
    const n = Number(el.dataset.step);
    el.classList.toggle('active', n === _kmipWizStep);
    el.classList.toggle('done', n < _kmipWizStep);
  });
  const next = document.getElementById('kmip-wiz-next');
  next.textContent = _kmipWizStep === 1 ? 'Issue certificate'
    : (_kmipWizStep === 2 ? 'Next →' : 'Done');
}

async function kmipWizardNext() {
  if (_kmipWizStep === 1) {
    const name = document.getElementById('kmip-wiz-name').value.trim();
    const kind = document.getElementById('kmip-wiz-kind').value;
    const address = document.getElementById('kmip-wiz-address').value.trim();
    if (!name) { toast('Enter a name for this appliance', 'error', { transient: true }); return; }
    try {
      const r = await api('POST', '/kmip/clients', { name, kind, address });
      if (!_kmipOk(r, 'Issuing the certificate')) return;
      _kmipWizCreds = r;
      document.getElementById('kmip-wiz-fp').textContent =
        `Certificate fingerprint: ${(r.fingerprint || '').slice(0, 32)}…`;
      _kmipWizStep = 2;
      _kmipRenderWizStep();
    } catch (e) {
      toast(`Could not issue a certificate: ${String(e)}`, 'error');
    }
    return;
  }
  if (_kmipWizStep === 2) {
    _kmipWizStep = 3;
    _kmipRenderInstructions();
    _kmipRenderWizStep();
    _kmipWatchFirstContact();
    return;
  }
  kmipWizardClose();
}

function _kmipDownloadBlob(filename, text) {
  const blob = new Blob([text], { type: 'application/x-pem-file' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function kmipDownloadCred(which) {
  if (!_kmipWizCreds) { toast('Nothing to download', 'error', { transient: true }); return; }
  const map = {
    ca: ['ca.crt', _kmipWizCreds.ca_pem],
    cert: ['client.crt', _kmipWizCreds.cert_pem],
    key: ['client.key', _kmipWizCreds.key_pem],
  };
  const hit = map[which];
  if (!hit || !hit[1]) { toast('Nothing to download', 'error', { transient: true }); return; }
  _kmipDownloadBlob(hit[0], hit[1]);
}

function _kmipServerAddress() {
  const s = _kmipStatus || {};
  const hosts = (s.server_cert && s.server_cert.hosts) || [];
  const host = hosts[0] || location.hostname;
  return { host, port: s.port || 5696 };
}

const _KMIP_SETUP_STEPS = {
  // The exact DSM flow. Note ca.crt is used TWICE, and that DSM's import
  // dialog calls its third field "Intermediate Certificate" — that is simply
  // where the CA goes; it is not asking for an intermediate.
  synology: (a) => [
    '<strong>Import.</strong> Control Panel → Security → Certificate → <strong>Add</strong> → <em>Add a new certificate</em> → Description <code>KMIP</code> → <em>Import certificate</em>.',
    'Fill it exactly: <strong>Private Key</strong> = <code>client.key</code>, <strong>Certificate</strong> = <code>client.crt</code>, <strong>Intermediate Certificate</strong> = <code>ca.crt</code>. DSM labels that last field "Intermediate" — the CA goes there anyway; that is not a mistake.',
    '<strong>Assign it — the step everyone misses.</strong> Control Panel → Security → Certificate → <strong>Settings</strong> → <strong>Configure</strong>, find the <strong>KMIP</strong> row, pick the certificate you just named <code>KMIP</code> from its dropdown, and Save. Importing alone does nothing: without this DSM keeps sending its own default certificate and this server refuses it.',
    `<strong>Connect.</strong> KMIP tab → <strong>Remote Key Client</strong>: Hostname <strong>${escHtml(a.host)}</strong>, Port <strong>${escHtml(String(a.port))}</strong>, Certificate Authority = <code>ca.crt</code> <em>again</em> (second use — here it is the trust anchor). Apply.`,
    '<strong>Move the vault.</strong> Control Panel → Shared Folder → Encryption → <strong>Key Manager</strong>. Keys should then appear here as <em>active</em>.',
    '<strong>Then reboot the NAS to prove it.</strong> Encrypted shares must come back on their own — you have moved the unlock path onto this server, so test it deliberately now rather than during a power cut. Requires DSM 7.2-64570+.',
  ],
  truenas: (a) => [
    'Open TrueNAS → System Settings → Services and confirm outbound access to this server.',
    'Go to <strong>Datasets → Encryption</strong> (or System → SED) and choose a KMIP key server.',
    `Set the server to <strong>${escHtml(a.host)}:${escHtml(String(a.port))}</strong>.`,
    'Upload <strong>ca.crt</strong> as the certificate authority and <strong>client.crt</strong> + <strong>client.key</strong> as the client certificate.',
    'Enable “Manage SED passwords” / “Manage ZFS keys” as needed and apply.',
  ],
  vsphere: (a) => [
    'In vSphere Client, select the vCenter object → Configure → <strong>Key Providers</strong>.',
    'Add a <strong>Standard key provider</strong> and give it a name.',
    `Add a KMS with address <strong>${escHtml(a.host)}</strong> and port <strong>${escHtml(String(a.port))}</strong>.`,
    'Choose <strong>Make vCenter trust the KMS</strong> → upload <strong>ca.crt</strong>.',
    'Then <strong>Upload certificate and private key</strong> → <strong>client.crt</strong> and <strong>client.key</strong>.',
    'Confirm the connection status turns green before encrypting any VM.',
  ],
  generic: (a) => [
    `Point the client at <strong>${escHtml(a.host)}:${escHtml(String(a.port))}</strong> (KMIP 1.0–1.4 over TLS).`,
    'Trust <strong>ca.crt</strong>, and present <strong>client.crt</strong> + <strong>client.key</strong> — mutual TLS is mandatory.',
    'Supported operations: Discover Versions, Query, Create, Register, Get, Get Attributes, Locate, Activate, Revoke, Destroy.',
  ],
};

function _kmipRenderInstructions() {
  const el = document.getElementById('kmip-wiz-instructions');
  if (!el) return;
  const kind = (_kmipWizCreds && _kmipWizCreds.kind) || 'generic';
  const addr = _kmipServerAddress();
  const steps = (_KMIP_SETUP_STEPS[kind] || _KMIP_SETUP_STEPS.generic)(addr);
  el.innerHTML = `<div class="section-title">${escHtml(_KMIP_KIND_LABELS[kind] || 'KMIP client')} setup</div>
    <ol class="kmip-steps">${steps.map(s => `<li>${s}</li>`).join('')}</ol>`;
}

function _kmipWatchFirstContact() {
  const el = document.getElementById('kmip-wiz-waiting');
  const cid = _kmipWizCreds && _kmipWizCreds.id;
  if (!el || !cid) return;
  el.textContent = 'Waiting for the appliance to connect…';
  el.classList.remove('c-green');      // a previous run's success must not stick
  if (_kmipWizPoll) clearInterval(_kmipWizPoll);
  let ticks = 0;
  _kmipWizPoll = setInterval(async () => {
    ticks += 1;
    // Only the Cancel button routes through kmipWizardClose — Escape and a
    // backdrop click call closeModal directly. Without this self-guard the
    // poll kept running for five minutes, toasting over an unrelated page,
    // and _kmipWizCreds kept holding the client PRIVATE KEY that the server
    // deliberately never stores.
    const open = document.getElementById('kmip-wizard-modal');
    if (!open || !open.classList.contains('active')) {
      clearInterval(_kmipWizPoll); _kmipWizPoll = null; _kmipWizCreds = null;
      return;
    }
    if (ticks > 60) { clearInterval(_kmipWizPoll); _kmipWizPoll = null; return; }
    try {
      const r = await api('GET', '/kmip/clients');
      const me = ((r && r.clients) || []).find(c => c.id === cid);
      if (me && me.last_seen) {
        clearInterval(_kmipWizPoll);
        _kmipWizPoll = null;
        el.textContent = `Connected from ${me.last_peer || 'the appliance'} — setup verified.`;
        el.classList.add('c-green');
        toast('KMIP client connected', 'success');
      }
    } catch { /* keep polling quietly */ }
  }, 5000);
}

// ── client actions ──────────────────────────────────────────────────────────
async function kmipRevokeClient(btn) {
  const cid = btn.dataset.cid;
  const name = btn.dataset.name || cid;
  const ok = await uiConfirm({
    title: 'Revoke KMIP client',
    message: `${name} will be refused within 30 seconds. Any encrypted volume it unlocks with keys from this server will fail to mount after a reboot. Its stored keys are kept.`,
    confirmText: 'Revoke', danger: true,
  });
  if (!ok) return;
  try {
    const r = await api('POST', `/kmip/clients/${encodeURIComponent(cid)}/revoke`);
    if (!_kmipOk(r, 'Revoking the client')) return;
    toast(`${name} revoked`, 'success');
    loadKmip();
  } catch (e) {
    toast(`Revoke failed: ${String(e)}`, 'error');
  }
}

async function kmipDeleteClient(btn) {
  const cid = btn.dataset.cid;
  const name = btn.dataset.name || cid;
  const keys = Number(btn.dataset.keys || 0);
  const msg = keys
    ? `${name} still holds ${keys} key(s). Deleting the client DESTROYS them — `
      + 'any data the appliance encrypted with them becomes permanently '
      + 'unrecoverable unless you hold a recovery bundle exported before now.\n\n'
      + 'To cut the appliance off while keeping its keys, use Revoke instead.'
    : `Remove ${name}? Its certificate stops working immediately. It holds no `
      + 'keys, so nothing is lost.';
  const ok = await uiConfirm({
    title: keys ? 'Delete client and destroy its keys' : 'Delete client',
    message: msg,
    confirmText: keys ? 'Delete and destroy keys' : 'Delete', danger: true,
  });
  if (!ok) return;
  try {
    const r = await api('DELETE',
      `/kmip/clients/${encodeURIComponent(cid)}${keys ? '?purge=1' : ''}`);
    if (!_kmipOk(r, 'Deleting the client')) return;
    toast(r.keys_destroyed
      ? `${name} deleted — ${r.keys_destroyed} key(s) destroyed`
      : `${name} deleted`, 'success');
    loadKmip();
  } catch (e) {
    toast(`Delete failed: ${String(e)}`, 'error');
  }
}

async function kmipClearLog() {
  const ok = await uiConfirm({
    title: 'Clear activity log',
    message: 'Removes the KMIP activity history. The clear itself is recorded '
      + 'here and in the audit log, so the trail cannot appear to start clean.',
    confirmText: 'Clear log', danger: true,
  });
  if (!ok) return;
  try {
    const r = await api('DELETE', '/kmip/log');
    if (!_kmipOk(r, 'Clearing the log')) return;
    toast(`Cleared ${r.cleared || 0} event(s)`, 'success');
    kmipLoadLog();
  } catch (e) {
    toast(`Clear failed: ${String(e)}`, 'error');
  }
}

async function kmipReissueClient(btn) {
  const cid = btn.dataset.cid;
  const name = btn.dataset.name || cid;
  const ok = await uiConfirm({
    title: 'Re-issue certificate',
    message: `A new certificate and key are issued for ${name}. The old certificate stops working immediately — you must install the new files on the appliance. Its stored keys are kept.`,
    confirmText: 'Re-issue',
  });
  if (!ok) return;
  try {
    const r = await api('POST', `/kmip/clients/${encodeURIComponent(cid)}/reissue`);
    if (!_kmipOk(r, 'Re-issuing the certificate')) return;
    // Carry the client's REAL type over — the reissue response has no `kind`,
    // so defaulting to generic showed generic prose to a Synology admin and
    // dropped the assign-the-certificate step the code itself calls "the step
    // everyone misses". Without it DSM keeps sending its default cert.
    _kmipWizCreds = Object.assign(
      { id: cid, name, kind: btn.dataset.kind || 'generic' }, r);
    _kmipWizStep = 2;
    document.getElementById('kmip-wiz-fp').textContent =
      `Certificate fingerprint: ${(r.fingerprint || '').slice(0, 32)}…`;
    document.getElementById('kmip-wiz-instructions').textContent = '';
    document.getElementById('kmip-wiz-waiting').textContent = '';
    _kmipRenderWizStep();
    openModal('kmip-wizard-modal');
    toast('New certificate issued — download the files now', 'success');
  } catch (e) {
    toast(`Re-issue failed: ${String(e)}`, 'error');
  }
}

async function kmipDestroyKey(btn) {
  const uid = btn.dataset.uid;
  const name = btn.dataset.name || uid;
  const ok = await uiConfirm({
    title: 'Destroy key',
    message: `Key ${name} is destroyed permanently. Any data encrypted with it becomes unrecoverable unless you hold a recovery bundle exported before now. This cannot be undone.`,
    confirmText: 'Destroy key', danger: true,
  });
  if (!ok) return;
  try {
    const r = await api('DELETE', `/kmip/keys/${encodeURIComponent(uid)}`);
    if (!_kmipOk(r, 'Destroying the key')) return;
    toast(`Key ${name} destroyed`, 'success');
    loadKmip();
  } catch (e) {
    toast(`Destroy failed: ${String(e)}`, 'error');
  }
}

async function kmipPurgeKey(btn) {
  const uid = btn.dataset.uid;
  const name = btn.dataset.name || uid;
  // The material is already gone — this only clears the tombstone, so the
  // warning should not imply otherwise.
  const ok = await uiConfirm({
    title: 'Remove destroyed key',
    message: `Remove the record for ${name}? Its key material was already `
      + 'destroyed; this just clears the row from the inventory.',
    confirmText: 'Remove',
  });
  if (!ok) return;
  try {
    const r = await api('DELETE', `/kmip/keys/${encodeURIComponent(uid)}?purge=1`);
    if (!_kmipOk(r, 'Removing the record')) return;
    toast(`Removed ${name}`, 'info');
    loadKmip();
  } catch (e) {
    toast(`Remove failed: ${String(e)}`, 'error');
  }
}

async function kmipPurgeDestroyed() {
  const n = (_kmipKeys || []).filter(k => k.state === 'destroyed').length;
  if (!n) { toast('No destroyed keys to clear', 'info', { transient: true }); return; }
  const ok = await uiConfirm({
    title: 'Clear destroyed keys',
    message: `Remove ${n} destroyed record(s) from the inventory. Their key `
      + 'material was already destroyed; this only clears the rows.',
    confirmText: 'Clear',
  });
  if (!ok) return;
  try {
    const r = await api('DELETE', '/kmip/keys');
    if (!_kmipOk(r, 'Clearing destroyed keys')) return;
    toast(`Removed ${r.removed || 0} record(s)`, 'info');
    loadKmip();
  } catch (e) {
    toast(`Clear failed: ${String(e)}`, 'error');
  }
}

// ── recovery bundle ─────────────────────────────────────────────────────────
function kmipOpenExport() {
  document.getElementById('kmip-export-pass').value = '';
  document.getElementById('kmip-export-pass2').value = '';
  openModal('kmip-export-modal');
  setTimeout(() => document.getElementById('kmip-export-pass').focus(), 50);
}

async function kmipDoExport() {
  const p1 = document.getElementById('kmip-export-pass').value;
  const p2 = document.getElementById('kmip-export-pass2').value;
  if (p1.length < 12) { toast('Passphrase must be at least 12 characters', 'error', { transient: true }); return; }
  if (p1 !== p2) { toast('Passphrases do not match', 'error', { transient: true }); return; }
  try {
    // Binary download — fetch directly so the browser gets the octet-stream.
    const r = await fetch('/api/kmip/export', {
      method: 'POST',
      headers: { 'X-Token': getToken(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: p1 }),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      toast(err.error || `Export failed (${r.status})`, 'error');
      return;
    }
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `kmip-recovery-${stamp}.rpkmip`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    closeModal('kmip-export-modal');
    toast('Recovery bundle exported — store it off this machine', 'success');
    kmipLoadLog();
  } catch (e) {
    toast(`Export failed: ${String(e)}`, 'error');
  }
}

function kmipOpenReset() {
  const c = (_kmipStatus && _kmipStatus.counts) || {};
  const el = document.getElementById('kmip-reset-scope');
  el.textContent = (c.objects || c.clients)
    ? `This will destroy ${c.objects || 0} stored key(s) and remove `
      + `${c.clients || 0} client(s).`
    : 'No clients or keys are stored — nothing will be lost.';
  el.classList.toggle('c-warning', !!(c.objects || c.clients));
  document.getElementById('kmip-reset-confirm').value = '';
  openModal('kmip-reset-modal');
  setTimeout(() => document.getElementById('kmip-reset-confirm').focus(), 50);
}

async function kmipDoReset() {
  const confirm = document.getElementById('kmip-reset-confirm').value.trim();
  try {
    const r = await api('POST', '/kmip/reset', { confirm });
    if (!_kmipOk(r, 'Removing the KMIP server')) return;
    closeModal('kmip-reset-modal');
    // The sidecar lives outside the app, so finish-up is a root shell step.
    // Show it rather than pretending the removal is complete.
    document.getElementById('kmip-install-snippet').textContent =
      (r.next || []).join('\n');
    document.getElementById('kmip-install-note').textContent = r.note || '';
    openModal('kmip-install-modal');
    toast(`Removed — ${r.keys_destroyed || 0} key(s), `
      + `${r.clients_removed || 0} client(s)`, 'success');
    loadKmip();
  } catch (e) {
    toast(`Removal failed: ${String(e)}`, 'error');
  }
}

function kmipOpenImport() {
  document.getElementById('kmip-import-file').value = '';
  document.getElementById('kmip-import-pass').value = '';
  openModal('kmip-import-modal');
}

function _kmipReadFileB64(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onload = () => {
      const s = String(fr.result || '');
      resolve(s.slice(s.indexOf(',') + 1));    // strip the data: URL prefix
    };
    fr.onerror = () => reject(fr.error);
    fr.readAsDataURL(file);
  });
}

async function kmipDoImport() {
  const f = document.getElementById('kmip-import-file').files[0];
  const pass = document.getElementById('kmip-import-pass').value;
  if (!f) { toast('Choose a bundle file', 'error', { transient: true }); return; }
  if (!pass) { toast('Enter the bundle passphrase', 'error', { transient: true }); return; }
  let b64;
  try {
    b64 = await _kmipReadFileB64(f);
  } catch (e) {
    toast(`Could not read the file: ${String(e)}`, 'error');
    return;
  }
  const send = async (confirm) => {
    const r = await fetch('/api/kmip/import', {
      method: 'POST',
      headers: { 'X-Token': getToken(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ passphrase: pass, bundle_b64: b64, confirm }),
    });
    return { status: r.status, body: await r.json().catch(() => ({})) };
  };
  try {
    let res = await send(false);
    if (res.status === 409 && res.body.needs_confirm) {
      const ok = await uiConfirm({
        title: 'Replace existing keys',
        message: 'This server already holds KMIP keys. Restoring replaces all of them, and any key not in the bundle is lost. Continue?',
        confirmText: 'Replace', danger: true,
      });
      if (!ok) return;
      res = await send(true);
    }
    if (res.status !== 200) {
      toast(res.body.error || `Restore failed (${res.status})`, 'error');
      return;
    }
    closeModal('kmip-import-modal');
    toast(`Restored ${res.body.objects || 0} key(s) and ${res.body.clients || 0} client(s)`, 'success');
    loadKmip();
  } catch (e) {
    toast(`Restore failed: ${String(e)}`, 'error');
  }
}
