// app-scans.js — page module extracted from app.js (buildless classic script; all
// symbols stay global, same as the rest of the client JS).
// Security Scans page (targets, schedules, results, netscan).

// ── v4.2.0 (B5): Security Scans — authorized scans against enrolled hosts ────
let _scansRegistered = false;
let scansData = [];

function _registerScansTable() {
  if (_scansRegistered) return;
  _scansRegistered = true;
  tableCtl.register({
    name: 'scans',
    tbody: 'scans-tbody',
    filterInput: 'scans-filter',
    sortHeaders: 'scans-thead',
    colspan: 9,
    columns: ['target', 'status', 'critical', 'high', 'medium', 'low', 'info', 'created'],
    getColumns: (s) => ({
      target:   (s.target_name || '') + ' ' + (s.target || ''),
      status:   s.status || '',
      critical: s.severity_counts?.critical || 0,
      high:     s.severity_counts?.high || 0,
      medium:   s.severity_counts?.medium || 0,
      low:      s.severity_counts?.low || 0,
      info:     s.severity_counts?.info || 0,
      created:  s.created || 0,
    }),
    row: (s) => {
      const sc = s.severity_counts || {};
      const statusColor = { queued: 'c-muted', running: 'c-amber', done: 'c-green',
                            failed: 'c-red', cancelled: 'c-muted' }[s.status] || 'c-muted';
      const cell = (n, cls) => n > 0 ? `<td class="ta-center ${cls}">${n}</td>` : '<td class="ta-center c-muted">0</td>';
      const when = s.created ? _fmtAbsTs(s.created) : '—';
      const removeBtn = ` <button class="btn-icon cell-sm c-danger-outline" data-stop-prop="1" data-prevent-default="1" data-action-btn="_deleteScanBtn" data-scan-id="${escAttr(s.id)}" title="Remove this scan and its findings">${_icon('trash',14)}</button>`;
      return `<tr data-action="viewScan" data-arg="${escAttr(s.id)}" class="pointer"><td class="fw-500">${escHtml(s.target_name || s.target)}<div class="hint">${escHtml(s.target)} · ${escHtml(s.tool)}/${escHtml(s.profile)}/${escHtml(s.intensity || 'quick')}</div></td><td class="${statusColor}" title="${escAttr(s.error || '')}">${escHtml(s.status)}</td>${cell(sc.critical, 'c-red')}${cell(sc.high, 'c-red')}${cell(sc.medium, 'c-amber')}${cell(sc.low, 'c-muted')}${cell(sc.info, 'c-muted')}<td class="meta-sm-nm">${when}</td><td><button class="btn-icon cell-sm" data-stop-prop="1" data-prevent-default="1" data-action-btn="_viewScanBtn" data-scan-id="${escAttr(s.id)}">View</button>${removeBtn}</td></tr>`;
    },
    emptyMsg: 'No scans yet. Select an enrolled device and queue one.',
    emptyMsgFiltered: 'No scans match the filter.',
  });
}

// Device selection is a SEARCH typeahead (never a dropdown — it would pile up
// at fleet scale), backed by the same window._devicesCache the global omnisearch
// palette uses. Type → filtered matches → pick one.
let _scanSelectedDevice = null;
let _scanDeviceSearchWired = false;

async function _renderScanDeviceResults(term) {
  const box = document.getElementById('scan-device-results');
  if (!box) return;
  const devs = await _scanDeviceList();
  const q = (term || '').toLowerCase().trim();
  let matches = devs;
  if (q) {
    matches = devs.filter(d =>
      (d.name || '').toLowerCase().includes(q) ||
      (d.ip || '').toLowerCase().includes(q) ||
      (d.hostname || '').toLowerCase().includes(q) ||
      (d.group || '').toLowerCase().includes(q) ||
      (d.tags || []).some(t => (t || '').toLowerCase().includes(q)));
  }
  matches = matches.slice(0, 25);
  box.innerHTML = matches.length
    ? matches.map(d =>
        `<div class="pointer mb-8" data-action="pickScanDevice" data-arg="${escAttr(d.id)}" data-arg2="${escAttr(d.name || d.id)}" tabindex="0"><strong>${escHtml(d.name || d.id)}</strong>${d.ip ? ` <span class="hint">${escHtml(d.ip)}</span>` : ''}${d.group ? ` <span class="group-badge">${escHtml(d.group)}</span>` : ''}</div>`).join('')
    : '<div class="empty-state">No matching devices.</div>';
  box.classList.remove('hidden');
}

function _wireScanDeviceSearch() {
  if (_scanDeviceSearchWired) return;
  const inp = document.getElementById('scan-device-search');
  if (!inp) return;
  _scanDeviceSearchWired = true;
  inp.addEventListener('input', () => { _scanSelectedDevice = null; _renderScanDeviceResults(inp.value); });
  inp.addEventListener('focus', () => _renderScanDeviceResults(inp.value));
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#scan-device-results') && e.target !== inp) {
      document.getElementById('scan-device-results')?.classList.add('hidden');
    }
  });
}

function pickScanDevice(id, name) {
  _scanSelectedDevice = { id, name };
  const inp = document.getElementById('scan-device-search');
  if (inp) inp.value = name;
  document.getElementById('scan-device-results')?.classList.add('hidden');
}

async function loadScans() {
  _registerScansTable();
  _wireScanDeviceSearch();
  for (const id of ['scan-tool', 'scan-profile']) {
    const el = document.getElementById(id);
    if (el && !el.dataset.scWired) { el.dataset.scWired = '1'; el.addEventListener('change', _syncScanControls); }
  }
  _syncScanControls();
  const tbody = document.getElementById('scans-tbody');
  if (tbody) tbody.innerHTML = '<tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line med"></div></td></tr>';
  const data = await api('GET', '/scans');
  if (!data || data.error) return;
  scansData = data.scans || [];
  _SCANNER_VERSION = data.scanner_version || '';
  let crit = 0, high = 0, running = 0;
  for (const s of scansData) {
    crit += s.severity_counts?.critical || 0;
    high += s.severity_counts?.high || 0;
    if (s.status === 'running' || s.status === 'queued') running++;
  }
  document.getElementById('scan-stat-total').textContent = scansData.length;
  document.getElementById('scan-stat-critical').textContent = crit;
  document.getElementById('scan-stat-high').textContent = high;
  document.getElementById('scan-stat-running').textContent = running;
  // populate the satellite picker (preserve the current choice across refresh)
  const satSel = document.getElementById('scan-satellite');
  if (satSel) {
    const cur = satSel.value;
    // Show the satellite's reported version. A satellite is a script copied
    // onto another host, so it drifts out of date silently — and "is my scanner
    // current?" was previously only answerable by SSHing to it.
    satSel.innerHTML = '<option value="">Any scanner satellite</option>' +
      (data.satellites || []).map(s => {
        const stale = s.version && _SCANNER_VERSION && s.version !== _SCANNER_VERSION;
        const tag = s.version ? ` — v${s.version}${stale ? ' (outdated)' : ''}`
                              : ' — version unknown';
        return `<option value="${escAttr(s.id)}">${escHtml((s.name || s.id) + tag)}</option>`;
      }).join('');
    _paintScannerVersionHint(data.satellites || []);
    satSel.value = cur;
  }
  tableCtl.render('scans', scansData);
  loadScanTargets();
  loadScanSchedules();
  loadNetscanSchedules();
}

// The scanner version this server ships. A satellite older than this is
// running code the server does not know about — worth saying out loud, since
// upgrading one means copying the file across by hand.
let _SCANNER_VERSION = '';
function _paintScannerVersionHint(sats) {
  const el = document.getElementById('scan-sat-hint');
  if (!el) return;
  const stale = sats.filter(s => s.version && _SCANNER_VERSION
                                 && s.version !== _SCANNER_VERSION);
  const unknown = sats.filter(s => !s.version);
  if (!stale.length && !unknown.length) { el.textContent = ''; return; }
  const bits = [];
  if (stale.length) {
    bits.push(`${stale.map(s => escHtml(s.name || s.id)).join(', ')} `
              + `running v${escHtml(stale[0].version)}, this server ships `
              + `v${escHtml(_SCANNER_VERSION)}`);
  }
  if (unknown.length) {
    bits.push(`${unknown.map(s => escHtml(s.name || s.id)).join(', ')} has not `
              + 'reported a version yet (pre-v4.4.0, or it has not polled since '
              + 'the server was updated)');
  }
  el.innerHTML = `Scanner out of date: ${bits.join('; ')}. `
    + 'Re-copy <span class="mono-12">client/remotepower-scanner.py</span> to '
    + '<span class="mono-12">/opt/remotepower/</span> on that host and restart '
    + '<span class="mono-12">remotepower-scanner</span>. '
    + '<a href="docs/security-scans.md" class="c-accent">Documentation</a>';
}

function _selectedScanTool() {
  const t = document.getElementById('scan-tool');
  return (t && t.value) || 'nuclei';
}

// #6: keep tool/profile/intensity to VALID combos only (grey out the rest).
// zap/wapiti are active-only; lynis is an on-host audit (profile/intensity N/A).
function _syncScanControls() {
  const toolSel = document.getElementById('scan-tool');
  const profSel = document.getElementById('scan-profile');
  const intSel  = document.getElementById('scan-intensity');
  if (!toolSel || !profSel) return;
  const isHost = toolSel.value === 'lynis';
  profSel.disabled = isHost;
  if (intSel) intSel.disabled = isHost;
  if (isHost) return;
  const activeOnly = (toolSel.value === 'zap' || toolSel.value === 'wapiti');
  if (activeOnly) profSel.value = 'active';
  const passiveOpt = profSel.querySelector('option[value="passive"]');
  if (passiveOpt) passiveOpt.disabled = activeOnly;       // can't make zap/wapiti passive
  const passive = (profSel.value === 'passive');
  for (const o of toolSel.querySelectorAll('option')) {
    if (o.value === 'zap' || o.value === 'wapiti') o.disabled = passive;  // not valid passive
  }
}

// Build the shared scan options (tool/profile + active-tier attestation).
// Returns null if the active tier is selected without the authorization box.
function _scanOptions() {
  const profile = (document.getElementById('scan-profile') || {}).value || 'passive';
  const opts = { tool: _selectedScanTool(), profile };
  const intensity = (document.getElementById('scan-intensity') || {}).value;
  if (intensity) opts.intensity = intensity;
  const sat = document.getElementById('scan-satellite');
  if (sat && sat.value) opts.satellite_id = sat.value;
  if (profile === 'active') {
    const attest = document.getElementById('scan-attest');
    if (!attest || !attest.checked) {
      toast('Active scans send attack traffic — tick the authorization box first.', 'error');
      return null;
    }
    opts.attestation = true;
    const ov = document.getElementById('scan-override');
    if (ov && ov.checked) opts.override_window = true;
  }
  return opts;
}

async function queueScan() {
  if (!_scanSelectedDevice) {
    // The box can LOOK filled — typing clears the selection — so say what is
    // actually wrong rather than repeating the label.
    const typed = (document.getElementById('scan-device-search') || {}).value || '';
    toast(typed.trim()
            ? `Pick "${typed.trim()}" from the dropdown — typing the name alone does not select it.`
            : 'Search and pick a device to scan first.',
          'error', {transient: true});
    document.getElementById('scan-device-search')?.focus();
    return;
  }
  const opts = _scanOptions();
  if (!opts) return;
  const vhost = ((document.getElementById('scan-vhost') || {}).value || '').trim();
  if (vhost) {
    // Fail HERE, where the fix is visible, instead of on the server round-trip:
    // the vhost must be an ownership-verified target, which stops a host you
    // own being used to scan somebody else's domain.
    if (_scanVerifiedVhosts.length && !_scanVerifiedVhosts.includes(vhost.toLowerCase())) {
      toast(`"${vhost}" is not an ownership-verified target yet — add it under `
            + `External targets below, publish the DNS TXT or file proof, then Verify.`,
            'error', {transient: true});
      document.getElementById('scan-targets-list')?.scrollIntoView({behavior: 'smooth', block: 'center'});
      return;
    }
    opts.vhost = vhost;
  } else if (opts.tool === 'wpscan') {
    // wpscan against a bare IP finds nothing useful: WordPress answers on a
    // hostname, and the scanner needs the right Host header to see the site.
    toast('wpscan needs a vhost — WordPress answers on a hostname, not the bare IP. '
          + 'Pick an ownership-verified target in the vhost box.',
          'error', {transient: true});
    document.getElementById('scan-vhost')?.focus();
    return;
  }
  const res = await api('POST', '/scans', { device_id: _scanSelectedDevice.id, ...opts });
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  toast(res.count ? `Queued ${res.count} scans (one per tool).`
                  : 'Scan queued — runs on the next scanner-satellite poll.', 'success');
  loadScans();
}

// A zero-finding scan is ambiguous: it can mean "genuinely clean" or "the tool
// never actually checked". Saying only "clean scan" asserts the first, which is
// the more dangerous of the two to be wrong about — so spell out what ran, and
// what this tool can and cannot conclude.
const _SCAN_ZERO_NOTES = {
  wpscan: 'wpscan reports vulnerabilities only when version matching is enabled, '
        + 'which needs a free WPScan API token (RP_WPSCAN_API_TOKEN on the scanner '
        + 'satellite). Without it wpscan still fingerprints core/plugin/theme '
        + 'versions but cannot say which are vulnerable — so zero findings here '
        + 'does NOT mean zero vulnerabilities. It also only sees a site it can '
        + 'identify as WordPress at the scanned URL.',
  nuclei: 'nuclei only reports what its templates match. Zero means no template '
        + 'fired — not that the target is free of flaws a template does not cover.',
  nikto:  'nikto checks known-bad paths and server misconfigurations. Zero means '
        + 'none of those matched.',
  nmap:   'nmap reports open services. Zero open ports usually means the target '
        + 'filtered the scan — worth confirming the satellite can reach it.',
};

// What MODE the run used, shown on every scan detail — not only empty ones.
// A wpscan that returns five informational findings and no vulnerabilities
// looks identical whether matching was enabled and the site is clean, or the
// satellite had no token and never checked. The operator cannot tell those
// apart from the finding list, so say it outright.
function _scanModeHtml(data) {
  const caps = data.capabilities || {};
  if (data.tool !== 'wpscan' || caps.wpscan_vuln_db === undefined) return '';
  if (caps.wpscan_vuln_db) {
    return '<div class="hint mb-8">' + _icon('check', 12)
      + ' Vulnerability matching was <strong>enabled</strong> for this run — '
      + 'core, plugin and theme versions were checked against the WPScan '
      + 'database.</div>';
  }
  return '<div class="hint c-amber mb-8">' + _icon('alertTriangle', 12)
    + ' Vulnerability matching was <strong>OFF</strong> for this run (no '
    + 'RP_WPSCAN_API_TOKEN on the satellite), so no vulnerability could be '
    + 'reported whatever the state of the site. The findings below are '
    + 'informational only.</div>';
}

function _scanZeroExplanation(data) {
  if (data.status !== 'done') {
    return `<div class="empty-state">No findings yet (status: ${escHtml(data.status)}).`
         + `${data.error ? ' ' + escHtml(data.error) : ''}</div>`;
  }
  let note = _SCAN_ZERO_NOTES[data.tool] || '';
  // If the satellite told us what it could actually do, say the sharper thing.
  // This lives HERE, on the scan you opened, and not in a per-scan notice: an
  // unconfigured token is a property of the satellite, so pushing it once per
  // run turns one config gap into an endless stream of identical messages.
  const caps = data.capabilities || {};
  if (data.tool === 'wpscan' && caps.wpscan_vuln_db === false) {
    // Lead with the ACTION. The explanation was three sentences long and the
    // operator sees it on every wpscan until the token is set, so the fix has
    // to be the first thing on the line, not the conclusion.
    // Concrete steps with the real paths the installer uses. "Set an env var"
    // is not a resolution if the operator has to work out where.
    note = {html:
      '<strong>wpscan could not check for vulnerabilities.</strong> It matched '
      + 'nothing because this scanner satellite has no WPScan API token, not '
      + 'because the site is clean. To fix it, on the satellite host:'
      + '<ol class="mt-6">'
      + '<li>Get a free token at <a href="https://wpscan.com/api" target="_blank" rel="noopener" class="c-accent">wpscan.com/api</a>.</li>'
      + '<li>Add it to <span class="mono-12">/etc/remotepower/scanner.env</span>:'
      + '<br><span class="mono-12">RP_WPSCAN_API_TOKEN=&lt;your-token&gt;</span>'
      + '<br><span class="hint">(installed by <span class="mono-12">packaging/scanner-setup.sh</span>; '
      + 'if you wrote the unit by hand, add it as an <span class="mono-12">Environment=</span> line instead)</span></li>'
      + '<li><span class="mono-12">sudo systemctl restart remotepower-scanner</span></li>'
      + '<li>Re-run this scan.</li></ol>'
      + '<span class="hint">The free tier allows 25 API requests a day. '
      + '<a href="docs/security-scans.md" class="c-accent">Documentation</a></span>'};
  } else if (data.tool === 'wpscan' && caps.wpscan_vuln_db === true) {
    note = 'Vulnerability matching was enabled, so this is a real clean result '
         + 'for the core/plugin/theme versions wpscan could identify.';
  }
  return '<div class="empty-state ta-left">'
    + `<strong>No findings.</strong> ${escHtml(data.tool || 'The scan')} completed against `
    + `<span class="mono-12">${escHtml(data.target || '')}</span>`
    + `${data.profile ? ` (${escHtml(data.profile)}/${escHtml(data.intensity || 'quick')})` : ''}.`
    + (data.error
        // A COMPLETED scan's `error` is a note, not a failure — older scans
        // carry a stored caveat here. Painting it amber made a clean run look
        // broken. A scan that actually failed is handled above, where the
        // status is not 'done'.
        ? `<div class="hint mt-8"><strong>Note from this run:</strong> ${escHtml(data.error)}</div>`
        : '')
    + (note
        // A note may carry markup when it is a set of steps — those are all
        // built from literals here, never from scan data, which stays escaped.
        ? `<div class="hint mt-8">${typeof note === 'string' ? escHtml(note) : note.html}</div>`
        : '')
    + '</div>';
}

async function viewScan(scanId) {
  const data = await api('GET', '/scans/' + encodeURIComponent(scanId));
  if (!data) return;
  if (data.error) { toast(data.error, 'error'); return; }
  const box = document.getElementById('scan-detail');
  document.getElementById('scan-detail-target').textContent =
    (data.target_name || '') + ' (' + (data.target || '') + ')';
  const body = document.getElementById('scan-detail-body');
  const findings = data.findings || [];
  // v4.2.0 sweep: lynis host-hardening score (0–100) — the headline number
  // of an on-host audit, shown above the finding list.
  const hidx = (typeof data.hardening_index === 'number')
    ? `<div class="mb-8"><strong>Hardening index:</strong> <span class="${data.hardening_index >= 75 ? 'c-green' : data.hardening_index >= 50 ? 'c-amber' : 'c-red'} fw-600">${data.hardening_index}/100</span> <span class="hint">lynis host-hardening score</span></div>`
    : '';
  if (!findings.length) {
    body.innerHTML = hidx + _scanModeHtml(data) + _scanZeroExplanation(data);
  } else {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
    const sevColor = { critical: 'c-red', high: 'c-red', medium: 'c-amber', low: 'c-muted', info: 'c-muted', unknown: 'c-muted' };
    const sorted = findings.slice().sort((a, b) => (order[a.severity] ?? 9) - (order[b.severity] ?? 9));
    body.innerHTML = hidx + _scanModeHtml(data) + sorted.map(f =>
      `<div class="mb-8"><span class="${sevColor[f.severity] || 'c-muted'} fw-500">${escHtml(f.severity)}</span> <strong>${escHtml(f.title || f.rule_id)}</strong>${f.rule_id ? ` <span class="hint">${escHtml(f.rule_id)}</span>` : ''}${f.evidence ? `<div class="hint">${escHtml(f.evidence)}</div>` : ''}${/^https?:\/\//.test(f.reference || '') ? `<div class="hint"><a href="${escAttr(f.reference)}" target="_blank" rel="noopener" class="c-accent">reference</a></div>` : ''}</div>`
    ).join('');
  }
  box.classList.remove('hidden');
  box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function deleteScan(scanId) {
  const res = await api('DELETE', '/scans/' + encodeURIComponent(scanId));
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  toast('Scan removed.', 'success');
  loadScans();
}

async function clearScans() {
  if (!await uiConfirm({
        title: 'Clear finished scans',
        message: 'Remove every finished scan (done / failed / cancelled) and all of their findings? This cannot be undone.',
        confirmText: 'Clear', danger: true })) return;
  const res = await api('POST', '/scans/clear');
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  toast(`Cleared ${res.removed} finished scan${res.removed === 1 ? '' : 's'}.`, 'success');
  loadScans();
}

function _viewScanBtn(btn)   { viewScan(btn.dataset.scanId); }
function _deleteScanBtn(btn) { deleteScan(btn.dataset.scanId); }

// ── B5 P2: verified non-enrolled scan targets (ACME-style ownership proof) ───
let _scanTargetProofs = {};   // id -> {token, dns, file} captured at create time
// Verified web targets, mirrored into the vhost box's datalist so the
// requirement is visible BEFORE the queue attempt rather than after it.
let _scanVerifiedVhosts = [];
function _syncVerifiedVhosts(targets) {
  _scanVerifiedVhosts = (targets || [])
    .filter(t => t && t.verified && t.kind !== 'ip')
    .map(t => String(t.target).toLowerCase());
  const dl = document.getElementById('scan-vhost-verified');
  if (dl) {
    dl.innerHTML = '';
    for (const v of _scanVerifiedVhosts) dl.appendChild(new Option(v));
  }
  const inp = document.getElementById('scan-vhost');
  if (inp) {
    inp.placeholder = _scanVerifiedVhosts.length
      ? 'vhost (optional) — verified targets'
      : 'vhost — add a verified target first';
  }
}

async function loadScanTargets() {
  const box = document.getElementById('scan-targets-list');
  if (!box) return;
  const data = await api('GET', '/scan-targets');
  if (!data || data.error) return;
  const targets = data.targets || [];
  _syncVerifiedVhosts(targets);
  if (!targets.length) {
    box.innerHTML = '<div class="empty-state">No external targets. Add a domain or IP you own to scan it.</div>';
    return;
  }
  box.innerHTML = targets.map(t => {
    const proof = _scanTargetProofs[t.id];
    const badge = t.verified
      ? `<span class="c-green fw-500">verified</span> <span class="hint">via ${escHtml(t.method || '')}</span>`
      : '<span class="c-amber fw-500">unverified</span>';
    const actions = t.verified
      ? `<button class="btn-icon cell-sm" data-action="scanTarget" data-arg="${escAttr(t.id)}">Scan</button> <button class="btn-icon cell-sm" data-action="scheduleScanTarget" data-arg="${escAttr(t.id)}" title="Schedule a recurring scan (uses the cron + tool/profile below)">Schedule</button>`
      : `<button class="btn-icon cell-sm" data-action="verifyScanTarget" data-arg="${escAttr(t.id)}">Verify</button>`;
    const proofBlock = (!t.verified && proof)
      ? `<div class="hint mb-8">Publish ONE proof, then Verify:<br>• DNS TXT <code>${escHtml(proof.dns ? proof.dns.name : '(IP target — use file)')}</code>${proof.dns ? ` = <code>${escHtml(proof.dns.value)}</code>` : ''}<br>• File <code>${escHtml(proof.file.path)}</code> containing <code>${escHtml(proof.file.content)}</code></div>`
      : '';
    return `<div class="mb-8"><strong>${escHtml(t.target)}</strong> <span class="hint">${escHtml(t.kind)}</span> — ${badge} ${actions} <button class="btn-icon cell-sm c-danger-outline" title="Remove" data-action="deleteScanTarget" data-arg="${escAttr(t.id)}">${_icon('trash',14)}</button>${proofBlock}</div>`;
  }).join('');
}

async function addScanTarget() {
  const inp = document.getElementById('scan-target-input');
  const target = inp && inp.value.trim();
  if (!target) { toast('Enter a domain or IP.', 'info'); return; }
  const res = await api('POST', '/scan-targets', { target });
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  _scanTargetProofs[res.id] = { token: res.token, dns: res.dns, file: res.file };
  inp.value = '';
  toast('Target added — publish the proof shown, then Verify.', 'success');
  loadScanTargets();
}

async function verifyScanTarget(id) {
  const res = await api('POST', '/scan-targets/' + encodeURIComponent(id) + '/verify');
  if (!res) return;
  if (res.error && !('verified' in res)) { toast(res.error, 'error'); return; }
  toast(res.verified ? 'Ownership verified — you can scan it now.' : ('Not verified: ' + (res.error || 'proof not found')),
        res.verified ? 'success' : 'error');
  loadScanTargets();
}

async function scanTarget(id) {
  const opts = _scanOptions();
  if (!opts) return;
  const res = await api('POST', '/scans', { scan_target_id: id, ...opts });
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  toast(res.count ? `Queued ${res.count} scans (one per tool).` : 'Scan queued for the target.', 'success');
  loadScans();
}

// v6.3.1: undoable (deferred commit) — the ownership proof survives an
// accidental click (nothing is discarded until the undo window closes).
async function deleteScanTarget(id) {
  undoableDelete({
    label: 'Scan target removed',
    hide: () => _hideRowByAction('deleteScanTarget', id, '.mb-8'),
    commit: async () => {
      const res = await api('DELETE', '/scan-targets/' + encodeURIComponent(id));
      if (res && !res.error) delete _scanTargetProofs[id];
    },
    undo: () => loadScanTargets(),
    after: () => loadScanTargets(),
  });
}

// ── #4: scheduled scans (recurring; high/critical findings raise an alert) ───
async function loadScanSchedules() {
  const box = document.getElementById('scan-schedules-list');
  if (!box) return;
  const data = await api('GET', '/scan-schedules');
  if (!data || data.error) return;
  const scheds = data.schedules || [];
  if (!scheds.length) {
    box.innerHTML = '<div class="empty-state">No scheduled scans. Set up a scan above, enter a cron, and Add schedule.</div>';
    return;
  }
  box.innerHTML = scheds.map(s => {
    const when = s.next_run ? _fmtAbsTs(s.next_run) : '—';
    const last = s.last_run ? _fmtAbsTs(s.last_run) : 'never';
    const tgt = s.device_id ? 'device' : (s.scan_target_id ? 'verified target' : '—');
    const paused = s.enabled === false;
    const stateBadge = paused ? ' <span class="patch-badge warn fs-11">paused</span>' : '';
    const nextStr = paused ? '' : ` · next ${escHtml(when)}`;
    return `<div class="mb-8"><strong>${escHtml(s.name)}</strong>${stateBadge} <span class="hint">${escHtml(s.cron)} · ${escHtml(s.tool)}/${escHtml(s.profile)}/${escHtml(s.intensity)} · ${escHtml(tgt)} · last ${escHtml(last)}${nextStr}</span> <button class="btn-icon cell-sm" data-action="runScanSchedule" data-arg="${escAttr(s.id)}" title="Fire this schedule now">Run now</button> <button class="btn-icon cell-sm" data-action="toggleScanSchedule" data-arg="${escAttr(s.id)}" title="${paused ? 'Resume the cron' : 'Pause without deleting'}">${paused ? 'Resume' : 'Pause'}</button> <button class="btn-icon cell-sm c-danger-outline" title="Remove" data-action="deleteScanSchedule" data-arg="${escAttr(s.id)}">${_icon('trash',14)}</button></div>`;
  }).join('');
}

async function _createScanSchedule(extra) {
  const cronEl = document.getElementById('scan-sched-cron');
  const cron = cronEl && cronEl.value.trim();
  if (!cron) { toast('Enter a cron expression (e.g. 0 3 * * *).', 'info'); return; }
  const opts = _scanOptions();
  if (!opts) return;
  const res = await api('POST', '/scan-schedules', { cron, ...opts, ...extra });
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  if (cronEl) cronEl.value = '';
  toast('Schedule created.', 'success');
  loadScanSchedules();
}

async function addScanSchedule() {
  if (!_scanSelectedDevice) { toast('Search and pick a device first (or use a verified target’s Schedule button).', 'info'); return; }
  _createScanSchedule({ device_id: _scanSelectedDevice.id });
}

function scheduleScanTarget(id) { _createScanSchedule({ scan_target_id: id }); }

async function runScanSchedule(id) {
  const res = await api('POST', '/scan-schedules/' + encodeURIComponent(id) + '/run');
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  toast('Schedule fired — scan(s) queued.', 'success');
  loadScans();
}

async function toggleScanSchedule(id) {
  const res = await api('POST', '/scan-schedules/' + encodeURIComponent(id) + '/toggle');
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  loadScanSchedules();
  // Self-inverse endpoint — toggling again flips it back.
  const _flip = async () => { const u = await api('POST', '/scan-schedules/' + encodeURIComponent(id) + '/toggle'); if (u && !u.error) loadScanSchedules(); };
  pushUndoableAction(res.enabled ? 'Resume scan schedule' : 'Pause scan schedule',
    _flip, _flip, res.enabled ? 'Schedule resumed' : 'Schedule paused');
}

// v6.3.1: undoable (deferred commit) — was a danger-confirm.
async function deleteScanSchedule(id) {
  undoableDelete({
    label: 'Scan schedule deleted',
    hide: () => _hideRowByAction('deleteScanSchedule', id, '.mb-8'),
    commit: () => api('DELETE', '/scan-schedules/' + encodeURIComponent(id)),
    undo: () => loadScanSchedules(),
    after: () => loadScanSchedules(),
  });
}

// ── v6.1.1: scheduled LAN discovery — turns handle_device_netscan's one-shot
// scan into a living, auto-refreshed unmanaged-host list. Reuses the same
// device search/pick widget as scheduled scans (#scan-device-search /
// _scanSelectedDevice), just with a subnet + interval instead of a cron.
async function loadNetscanSchedules() {
  const box = document.getElementById('netscan-schedules-list');
  if (!box) return;
  const data = await api('GET', '/netscan-schedules');
  if (!data || data.error) return;
  const scheds = data.schedules || [];
  if (!scheds.length) {
    box.innerHTML = '<div class="empty-state">No scheduled LAN discovery. Pick a device above, enter a subnet, and Add schedule.</div>';
    return;
  }
  box.innerHTML = scheds.map(s => {
    const last = s.last_run ? _fmtAbsTs(s.last_run) : 'never';
    const paused = s.enabled === false;
    const stateBadge = paused ? ' <span class="patch-badge warn fs-11">paused</span>' : '';
    return `<div class="mb-8"><strong>${escHtml(s.device_name || s.device_id)}</strong>${stateBadge} <span class="hint">${escHtml(s.subnet)} · every ${s.interval_minutes}m · last ${escHtml(last)}</span> <button class="btn-icon cell-sm c-danger-outline" title="Remove" data-action="deleteNetscanSchedule" data-arg="${escAttr(s.id)}">${_icon('trash',14)}</button></div>`;
  }).join('');
}

async function addNetscanSchedule() {
  if (!_scanSelectedDevice) { toast('Search and pick a device above first.', 'info'); return; }
  const subnetEl = document.getElementById('netscan-sched-subnet');
  const subnet = subnetEl && subnetEl.value.trim();
  if (!subnet) { toast('Enter a subnet, e.g. 192.168.1.0/24.', 'info'); return; }
  const intervalEl = document.getElementById('netscan-sched-interval');
  const interval_minutes = parseInt((intervalEl && intervalEl.value) || '60', 10);
  const res = await api('POST', '/netscan-schedules',
    { device_id: _scanSelectedDevice.id, subnet, interval_minutes });
  if (!res) return;
  if (res.error) { toast(res.error, 'error'); return; }
  if (subnetEl) subnetEl.value = '';
  toast('LAN discovery schedule created.', 'success');
  loadNetscanSchedules();
}

async function deleteNetscanSchedule(id) {
  const res = await api('DELETE', '/netscan-schedules/' + encodeURIComponent(id));
  if (!res || res.error) { if (res && res.error) toast(res.error, 'error'); return; }
  loadNetscanSchedules();
}
