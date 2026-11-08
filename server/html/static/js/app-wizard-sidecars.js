// app-wizard-sidecars.js — wizards for the optional sidecars (8.0.0). Buildless classic script, fetched after app-wizard.js (whose runner and helpers it uses) when one of
// them is started. Both parts are options beside the controls that were already there: nothing here replaces one.
//
//   wizStart('syslog')     a host sends its logs to the syslog receiver of this server
//   wizStart('flow')       a router sends its traffic records (NetFlow, IPFIX, sFlow) to the flow receiver
//   wizStart('satellite')  a relay satellite, or a scan worker, for another network
//
// The two receivers know a device by the address its packets come from, and the token is attached to a host on the server's side, so the device never holds it: what the wizard
// does for each is the three things the guides list (a host that carries the address, a token of the right kind pinned to it, the sender's own settings) and then it waits for the
// first thing to arrive and says so. Text a person typed is only ever set as a property or as textContent, never put into markup.

const _WIZ_RX = {
  syslog: { title: 'Receive logs from a host', unit: 'remotepower-syslogd', flag: '--with-syslogd', port: 5514, doc: 'docs/syslog.md',
            senders: [['opnsense', 'OPNsense', 'firewall'], ['pfsense', 'pfSense', 'firewall'], ['mikrotik', 'MikroTik RouterOS', 'router'], ['rsyslog', 'rsyslog (Linux)', 'other'],
                      ['syslogng', 'syslog-ng', 'other'], ['esxi', 'VMware ESXi', 'other'], ['other', 'Something else', 'other']] },
  flow: { title: 'Receive network flows from a router', unit: 'remotepower-flowd', flag: '--with-flowd', port: 2055, doc: 'docs/flow.md',
          senders: [['opnsense', 'OPNsense', 'firewall'], ['pfsense', 'pfSense', 'firewall'], ['mikrotik', 'MikroTik RouterOS', 'router'], ['cisco', 'Cisco IOS', 'router'],
                    ['other', 'Something else', 'other']] },
};
const _WIZ_RX_IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const _WIZ_RX_GUIDE = {          // where the guide has the fields of a device that is set up in a page and not with a command
  syslog: { opnsense: 'docs/opnsense.md#send-the-firewalls-logs', pfsense: 'docs/syslog.md#pfsense' },
  flow: { opnsense: 'docs/opnsense.md#send-traffic-records-netflow', pfsense: 'docs/flow.md#setup' },
};

// What goes on the device, as text to copy: the commands of the guides with this server's address and the port filled in. A device that is set up in a page gets the guide instead.
function _wizRxCommands(kind, sender, server, port) {
  const s = server, p = port;
  if (kind === 'syslog') {
    if (sender === 'mikrotik') return ['/system logging action add name=remotepower target=remote remote=' + s + ' remote-port=' + p, '/system logging add topics=info action=remotepower',
                                       '/system logging add topics=error action=remotepower', '/system logging add topics=warning action=remotepower', '/system logging add topics=critical action=remotepower'].join('\n');
    if (sender === 'rsyslog') return '# /etc/rsyslog.d/90-remotepower.conf  (@ is UDP: @@ would be TCP, which the receiver does not speak)\n*.*  @' + s + ':' + p + '\n# then: sudo rsyslogd -N1 && sudo systemctl restart rsyslog';
    if (sender === 'syslogng') return 'destination d_remotepower { udp("' + s + '" port(' + p + ')); };\nlog { source(s_src); destination(d_remotepower); };';
    if (sender === 'esxi') return ['esxcli system syslog config set --loghost=udp://' + s + ':' + p, 'esxcli system syslog reload', 'esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true'].join('\n');
    return '';
  }
  if (sender === 'mikrotik') return '/ip traffic-flow set enabled=yes\n/ip traffic-flow target add dst-address=' + s + ' port=' + p + ' version=9';
  if (sender === 'cisco') return 'ip flow-export version 9\nip flow-export destination ' + s + ' ' + p;
  return '';
}

// A line to send from the device to see it arrive: the guide's own test (FreeBSD's logger takes other flags than Linux's).
function _wizRxTest(sender, server, port) {
  if (sender === 'opnsense' || sender === 'pfsense') return 'logger -h ' + server + ' -P ' + port + ' -t remotepower-test "hello"';
  if (sender === 'rsyslog' || sender === 'syslogng' || sender === 'other') return 'logger -n ' + server + ' -P ' + port + ' -d "hello from $(hostname)"';
  return '';
}

function _wizRxDef(kind) {
  const k = _WIZ_RX[kind];
  return {
    title: k.title,
    init: () => ({ kind, mode: 'existing', hostId: '', host: null, name: '', ip: '', sender: k.senders[0][0], server: location.hostname, devices: null, status: null, checking: false,
                   tokenId: '', baseHits: 0, defect: '', arrived: null, watching: false, watchFrom: 0, late: false }),
    steps: [
      { label: 'Sender', render: _wizRxDevice, validate: _wizRxDeviceCheck, next: _wizRxDeviceNext },
      { label: 'Receiver', render: _wizRxReceiver, validate: st => (st.server.trim() ? null : { msg: 'The address of this server is needed', focus: 'wiz-rx-server' }), next: _wizRxToken },
      { label: 'Send', render: _wizRxSend, primary: 'Continue' },
      { label: 'Done', render: _wizRxDone, closeOnly: true, noBack: true },
    ],
  };
}

function _wizRxHosts(st) {
  return (st.devices || []).filter(d => d && !d.decommissioned).sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

function _wizRxDevice(st, body) {
  const k = _WIZ_RX[st.kind];
  _wizChoices(body, {
    legend: 'Which host sends them?', name: 'wiz-rx-mode', value: st.mode, onPick: v => { st.mode = v; paint(); },
    items: [{ v: 'existing', t: 'A host that is already here', d: 'Pick one that has an address.' }, { v: 'new', t: 'A new host', d: 'Added without an agent, by its address.' }],
  });
  const sub = _wizNode('div', 'mt-8');
  sub.id = 'wiz-rx-sub';
  body.appendChild(sub);
  _wizField(body, { id: 'wiz-rx-sender', label: 'What is it?', value: st.sender, options: k.senders.map(x => [x[0], x[1]]), onInput: v => { st.sender = v; } });
  function paint() {
    sub.textContent = '';
    if (st.mode === 'new') {
      _wizField(sub, { id: 'wiz-rx-name', label: 'Name', value: st.name, maxlength: 64, onInput: v => { st.name = v; } });
      _wizField(sub, { id: 'wiz-rx-ip', label: 'Address (IPv4)', value: st.ip, placeholder: '192.0.2.20', maxlength: 15,
                       hint: 'The address the sender sends from. The receiver knows a sender by it.', onInput: v => { st.ip = v; } });
      return;
    }
    if (st.devices === null) {
      sub.appendChild(_wizNode('div', 'hint', 'Loading…'));
      api('GET', '/devices?slim=1').then(r => {
        st.devices = Array.isArray(r) ? r : (r && r.devices) || [];
        if (_wiz && _wiz.st === st && st.mode === 'existing' && document.getElementById('wiz-rx-sub')) paint();
      }).catch(() => { st.devices = []; });
      return;
    }
    const opts = [['', 'Choose a host']].concat(_wizRxHosts(st).map(d => [d.id, d.name + ' · ' + (d.ip || '—')]));
    _wizField(sub, { id: 'wiz-rx-host', label: 'Host', value: st.hostId, options: opts, onInput: v => { st.hostId = v; st.host = (st.devices || []).find(d => d.id === v) || null; } });
  }
  paint();
}

function _wizRxDeviceCheck(st) {
  if (st.mode === 'existing') {
    if (!st.hostId || !st.host) return { msg: 'Choose a host', focus: 'wiz-rx-host' };
    if (!String(st.host.ip || '').trim()) return { msg: 'That host has no address. Give it one on its page, or add a new host here.', focus: 'wiz-rx-host' };
    return null;
  }
  if (!st.name.trim()) return { msg: 'Name required', focus: 'wiz-rx-name' };
  if (!_WIZ_RX_IPV4.test(st.ip.trim())) return { msg: 'Enter an IPv4 address such as 192.0.2.10', focus: 'wiz-rx-ip' };
  return null;
}

// A new device is made now (a switch, firewall or router with no agent), and from here on the wizard treats it as the host that was picked, so going back does not make a second.
async function _wizRxDeviceNext(st) {
  if (st.mode !== 'new') return true;
  const type = (_WIZ_RX[st.kind].senders.find(x => x[0] === st.sender) || [])[2] || 'other';
  const r = await api('POST', '/devices/agentless', { name: st.name.trim(), ip: st.ip.trim(), device_type: type });
  if (!r || r.error || !r.id) { _wizMsg((r && r.error) || 'Could not add the host. Try again.', 'wiz-rx-name'); return false; }
  st.host = { id: r.id, name: st.name.trim(), ip: st.ip.trim() };
  st.hostId = r.id;
  st.mode = 'existing';
  st.devices = null;
  return true;
}

async function _wizRxStatus(st) {
  st.checking = true;
  const r = await api('GET', '/self/status').catch(() => null);
  st.checking = false;
  st.status = (r && r.subsystems && r.subsystems[st.kind]) || {};
  if (_wiz && _wiz.st === st && document.getElementById('wiz-rx-state')) _wizRxPaintState(st);
}

function _wizRxPaintState(st) {
  const k = _WIZ_RX[st.kind];
  const el = document.getElementById('wiz-rx-state');
  if (!el) return;
  el.textContent = '';
  if (st.status === null) { el.className = 'wiz-watch c-muted'; el.appendChild(_wizNode('span', '', 'Loading…')); return; }
  if (st.status.unit === 'active') {
    el.className = 'wiz-watch c-green';
    el.appendChild(_wizNode('span', 'wiz-state', 'Running'));
    el.appendChild(_wizNode('span', 'wiz-chip', k.unit));
    return;
  }
  el.className = 'wiz-watch c-amber';
  el.appendChild(_wizNode('span', '', 'Not detected on this server. It may run on another host: carry on if it does. If it is not installed, run this on the server:'));
  _wizCommand(el, 'wiz-rx-install', 'Install the receiver', '', 'sudo ./install-server.sh ' + k.flag);
  const b = _wizNode('button', 'btn-secondary mt-6', 'Check again');
  b.type = 'button';
  b.setAttribute('data-action', 'wizRxCheck');
  el.appendChild(b);
}

function wizRxCheck() {
  const w = _wiz;
  if (w && w.st && !w.st.checking) { w.st.status = null; _wizRxPaintState(w.st); _wizRxStatus(w.st); }
}

function _wizRxReceiver(st, body) {
  const k = _WIZ_RX[st.kind];
  body.appendChild(_wizNode('div', 'wiz-q', 'Is the receiver running on this server?'));
  const state = _wizNode('div', 'wiz-watch c-muted');
  state.id = 'wiz-rx-state';
  state.setAttribute('role', 'status');
  body.appendChild(state);
  const listen = _wizNode('div', 'hint mb-12');
  listen.appendChild(_wizNode('span', '', 'It listens on UDP'));
  listen.appendChild(document.createTextNode(' ' + k.port));
  body.appendChild(listen);
  _wizField(body, { id: 'wiz-rx-server', label: 'Address of this server', value: st.server, maxlength: 255,
                    hint: 'The address the sender sends to. Use the server itself: UDP does not pass through a proxy.', onInput: v => { st.server = v; } });
  _wizRxPaintState(st);
  if (st.status === null && !st.checking) _wizRxStatus(st);
}

// Finds the token of this kind pinned to the host, or makes one: going back and forward, or running the wizard again for the same device, does not make a second.
async function _wizRxToken(st) {
  const list = await api('GET', '/inbound-webhooks');
  if (!list || list.error) { _wizMsg((list && list.error) || 'Could not read the tokens. Try again.'); return false; }
  const mine = (list.tokens || []).find(t => t.kind === st.kind && t.scope_device_id === st.hostId && t.enabled !== false);
  if (mine) {
    Object.assign(st, { tokenId: mine.id, baseHits: Number(mine.hit_count || 0), defect: mine.receiver_defect || '', arrived: null, late: false });
    return true;
  }
  const r = await api('POST', '/inbound-webhooks', { label: String(st.host.name).slice(0, 52) + ' ' + st.kind, scope_device_id: st.hostId, kind: st.kind });
  if (!r || r.error || !r.id) { _wizMsg((r && r.error) || 'Could not create the token. Try again.'); return false; }
  Object.assign(st, { tokenId: r.id, baseHits: 0, defect: '', arrived: null, late: false });
  return true;
}

function _wizRxSend(st, body) {
  const k = _WIZ_RX[st.kind];
  body.appendChild(_wizNode('div', 'wiz-q', 'Point the sender at this server'));
  const server = st.server.trim();
  const cmds = _wizRxCommands(st.kind, st.sender, server, k.port);
  if (cmds) {
    _wizCommand(body, 'wiz-rx-cmd', 'On the sender', '', cmds);
  } else {
    const guide = (_WIZ_RX_GUIDE[st.kind] || {})[st.sender] || k.doc;
    body.appendChild(_wizNode('div', 'hint mb-6', st.kind === 'syslog' ? "Add the address and port of this server to the sender's remote logging settings. The fields are in the guide."
                                                                   : "Add the address and port of this server to the sender's flow export settings. The fields are in the guide."));
    _wizList(body, [['Server', server], ['Port', 'UDP ' + k.port]]);
    const a = _wizNode('a', 'c-accent', 'Open the guide');
    a.href = guide;
    a.target = '_blank';
    a.rel = 'noopener';
    body.appendChild(a);
  }
  const test = st.kind === 'syslog' ? _wizRxTest(st.sender, server, k.port) : '';
  if (test) _wizCommand(body, 'wiz-rx-test', 'To send one test line from the sender', '', test);
  const watch = _wizNode('div', 'wiz-watch');
  watch.id = 'wiz-watch';
  watch.setAttribute('role', 'status');
  body.appendChild(watch);
  _wizRxWatch();
  _wizRxPaint();
}

const _WIZ_RX_DEFECT = {          // what the receiver says when it cannot map the device (the same causes Server Status names)
  no_ip: 'The host has no address, so the receiver cannot map its packets.',
  no_device: 'The host this token belongs to is gone.',
  disabled: 'The token is switched off.',
};

function _wizRxPaint() {
  const el = document.getElementById('wiz-watch');
  const w = _wiz;
  if (!el || !w) return;
  const st = w.st, k = _WIZ_RX[st.kind];
  el.textContent = '';
  if (st.arrived) {
    el.className = 'wiz-watch c-green';
    el.appendChild(_wizNode('span', 'wiz-state', 'Arriving'));
    el.appendChild(_wizNode('span', 'wiz-chip', String(st.arrived.hits)));
  } else if (st.defect && _WIZ_RX_DEFECT[st.defect]) {
    el.className = 'wiz-watch c-amber';
    el.appendChild(_wizNode('span', '', _WIZ_RX_DEFECT[st.defect]));
  } else if (st.late) {
    el.className = 'wiz-watch c-amber';
    el.appendChild(_wizNode('span', '', 'Nothing has arrived after 5 minutes. Check that the sender sends from the address the host carries, and that the port is open to it.'));
  } else {
    el.className = 'wiz-watch c-muted';
    el.appendChild(_wizNode('span', '', st.kind === 'syslog' ? 'Waiting for the first line…' : 'Waiting for the first record…'));
    const s = st.watchFrom ? Math.round((Date.now() - st.watchFrom) / 1000) : 0;
    if (s > 0) el.appendChild(_wizNode('span', 'ff-mono', s + ' s'));
  }
}

// Looks at the token every few seconds, and stops when something has arrived, after five minutes, or when the dialog goes. What counts is the token's own count of what it
// received: the browser's clock is not compared with the server's.
function _wizRxWatch() {
  const w = _wiz;
  if (!w || w.st.watching || w.st.arrived) return;
  const st = w.st;
  st.watching = true;
  st.watchFrom = Date.now();
  const stop = () => { st.watching = false; clearInterval(timer); };
  const tick = async () => {
    if (_wiz !== w) { stop(); return; }
    if ((Date.now() - st.watchFrom) / 1000 > _WIZ_WATCH_LIMIT_S) { st.late = true; stop(); _wizRxPaint(); return; }
    const r = await api('GET', '/inbound-webhooks').catch(() => null);
    if (_wiz !== w || !st.watching) return;
    const t = ((r && r.tokens) || []).find(x => x.id === st.tokenId);
    if (t) {
      st.defect = t.receiver_defect || '';
      const hits = Number(t.hit_count || 0);
      if (hits > st.baseHits) {
        st.arrived = { hits: hits - st.baseHits };
        stop();
        _wizRxPaint();
        if (w.def.steps[w.i].label === 'Done') _wizShow(w.i);
        return;
      }
    }
    _wizRxPaint();
  };
  const timer = setInterval(tick, _WIZ_WATCH_MS);
  w.timers.push(timer);
}

function _wizRxDone(st, body) {
  if (st.arrived) {
    body.appendChild(_wizNode('div', 'wiz-q c-green', 'It is arriving'));
    _wizList(body, [['Host', st.host.name], ['Address', st.host.ip], [st.kind === 'syslog' ? 'Lines received' : 'Records received', String(st.arrived.hits)]]);
  } else {
    body.appendChild(_wizNode('div', 'wiz-q', 'Nothing has arrived yet'));
    body.appendChild(_wizNode('div', 'hint', 'Close this window and look at the Server Status page: its receiver row says whether the receiver is running and how much it has taken in.'));
  }
  const row = _wizNode('div', 'row-8 mt-12');
  const open = _wizNode('button', 'btn-primary', 'Open host');
  open.type = 'button';
  open.setAttribute('data-action', 'wizRxOpenHost');
  row.appendChild(open);
  body.appendChild(row);
}

function wizRxOpenHost() {
  const w = _wiz;
  const h = w && w.st.host;
  if (!h) return;
  w.finished = true;
  closeModal('wizard-modal');
  if (typeof openDeviceDrawer === 'function') openDeviceDrawer(h.id, h.name);
}

// ── "Add a relay satellite" ─────────────────────────────────────────────────────────────────────────────────────────────────
function _wizSatDef() {
  return {
    title: 'Add a relay satellite',
    init: () => ({ name: '', scanner: false, id: '', token: '', sig: '', arrived: null, watching: false, watchFrom: 0, late: false }),
    steps: [
      { label: 'Satellite', render: _wizSatKind, validate: st => (st.name.trim() ? null : { msg: 'Name required', focus: 'wiz-sat-name' }), next: _wizSatMake },
      { label: 'Install', render: _wizSatInstall, primary: 'Continue', noBack: true },
      { label: 'Done', render: _wizSatDone, closeOnly: true, noBack: true },
    ],
  };
}

function _wizSatKind(st, body) {
  _wizField(body, { id: 'wiz-sat-name', label: 'Name', value: st.name, placeholder: 'dmz-relay', maxlength: 64, onInput: v => { st.name = v; } });
  _wizChoices(body, {
    legend: 'What will it do?', name: 'wiz-sat-kind', value: st.scanner ? 'scanner' : 'relay', onPick: v => { st.scanner = v === 'scanner'; },
    items: [{ v: 'relay', t: 'Relay', d: 'Agents in a separate network report through it.' }, { v: 'scanner', t: 'Scan worker', d: 'Runs the scans of Security ‣ Pentest from that network.' }],
  });
}

// Makes the satellite and its token. Once the token is on screen it is shown once, so the next step has no way back.
async function _wizSatMake(st) {
  const sig = st.name.trim() + '|' + st.scanner;
  if (st.token && st.sig === sig) return true;
  const r = await api('POST', '/satellites', { name: st.name.trim(), scanner: st.scanner });
  if (!r || r.error || !r.token) { _wizMsg((r && r.error) || 'Could not create the satellite. Try again.', 'wiz-sat-name'); return false; }
  Object.assign(st, { id: r.id, token: r.token, sig, arrived: null, late: false });
  return true;
}

function _wizSatCommand(st) {
  const url = location.origin;
  return st.scanner ? "sudo RP_SERVER_URL=" + url + " RP_SATELLITE_TOKEN='" + st.token + "' bash packaging/scanner-setup.sh"
                    : "sudo RP_UPSTREAM=" + url + " RP_SATELLITE_TOKEN='" + st.token + "' bash packaging/satellite-setup.sh";
}

function _wizSatInstall(st, body) {
  body.appendChild(_wizNode('div', 'wiz-q', 'Run this on the satellite host'));
  _wizCommand(body, 'wiz-sat-cmd', st.scanner ? 'Scan worker' : 'Relay', 'The token is shown once. Run it from a copy of the RemotePower files, as root.', _wizSatCommand(st));
  if (location.protocol !== 'https:') body.appendChild(_wizNode('div', 'hint c-amber', 'This page is not on https. A satellite connects to its server over https: use the address your server answers on with a certificate.'));
  const watch = _wizNode('div', 'wiz-watch');
  watch.id = 'wiz-watch';
  watch.setAttribute('role', 'status');
  body.appendChild(watch);
  _wizSatWatch();
  _wizSatPaint();
}

function _wizSatPaint() {
  const el = document.getElementById('wiz-watch');
  const w = _wiz;
  if (!el || !w) return;
  const st = w.st;
  el.textContent = '';
  if (st.arrived) {
    el.className = 'wiz-watch c-green';
    el.appendChild(_wizNode('span', 'wiz-state', 'Connected'));
    if (st.arrived.ip) el.appendChild(_wizNode('span', 'wiz-chip', st.arrived.ip));
  } else if (st.late) {
    el.className = 'wiz-watch c-amber';
    el.appendChild(_wizNode('span', '', 'Nothing has connected after 5 minutes. Check the installer output on the satellite host, and that it can reach this server over https.'));
  } else {
    el.className = 'wiz-watch c-muted';
    el.appendChild(_wizNode('span', '', 'Waiting for the satellite to connect…'));
    const s = st.watchFrom ? Math.round((Date.now() - st.watchFrom) / 1000) : 0;
    if (s > 0) el.appendChild(_wizNode('span', 'ff-mono', s + ' s'));
  }
}

function _wizSatWatch() {
  const w = _wiz;
  if (!w || w.st.watching || w.st.arrived) return;
  const st = w.st;
  st.watching = true;
  st.watchFrom = Date.now();
  const stop = () => { st.watching = false; clearInterval(timer); };
  const tick = async () => {
    if (_wiz !== w) { stop(); return; }
    if ((Date.now() - st.watchFrom) / 1000 > _WIZ_WATCH_LIMIT_S) { st.late = true; stop(); _wizSatPaint(); return; }
    const r = await api('GET', '/satellites').catch(() => null);
    if (_wiz !== w || !st.watching) return;
    const s = (Array.isArray(r) ? r : (r && r.satellites) || []).find(x => x.id === st.id);
    if (s && s.last_seen) {
      st.arrived = { ip: s.last_ip || '' };
      stop();
      _wizSatPaint();
      if (typeof loadSatellites === 'function') loadSatellites();
      if (w.def.steps[w.i].label === 'Done') _wizShow(w.i);
      return;
    }
    _wizSatPaint();
  };
  const timer = setInterval(tick, _WIZ_WATCH_MS);
  w.timers.push(timer);
}

function _wizSatDone(st, body) {
  if (st.arrived) {
    body.appendChild(_wizNode('div', 'wiz-q c-green', 'The satellite has connected'));
    _wizList(body, [['Name', st.name], ['Address', st.arrived.ip || '—'], ['Kind', st.scanner ? 'Scan worker' : 'Relay']]);
  } else {
    body.appendChild(_wizNode('div', 'wiz-q', 'Nothing has connected yet'));
    body.appendChild(_wizNode('div', 'hint', 'Keep going on the satellite host: it shows on the satellites list under Settings when it connects.'));
  }
}

// The runner (app-wizard.js) looks a wizard up here when it is not one of its own. Nothing of app-wizard.js is touched when this file loads, so the two load in either order.
const _WIZARDS_MORE = { syslog: () => _wizRxDef('syslog'), flow: () => _wizRxDef('flow'), satellite: _wizSatDef };
