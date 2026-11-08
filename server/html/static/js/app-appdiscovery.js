// app-appdiscovery.js — the apps an agent found on a host, and what can be done about each one (8.0.0). Buildless classic script; every symbol is global like the rest of
// the client JS, and it is fetched on first use (the lazy map in app.js): the host drawer's "Discovered on this host" and the Integrations page's "Found on your hosts".
//
//   loadDrawerApps(id)  fills the drawer's section for the host that is open
//   loadFoundApps()     fills the card on the Integrations page
//   appMonitor, appConnect, appHide, appShow, appToggleHidden   the buttons of a host's list
//   appFoundConnect, appFoundHide                               the buttons of the card
//   appsRefresh()       draws again whatever is on screen (the integration wizard calls it when it has added one)
//
// What the server says about an app (name, address) came from a host, so it is only ever put in the page with escHtml. A host id never travels through data-arg (the dispatcher
// turns a number-looking value into a number): the drawer's own host is `_drawerDeviceId`, and the card's rows are named by their place in the list.

let _appsSeq = 0;             // the newest request of the drawer's list: an older answer arrives late and is dropped
let _appsOf = {};             // host id -> the last answer of GET /devices/<id>/apps
let _appsShown = '';          // the host whose list is on screen
let _appsShowHidden = false;
let _foundRows = [];          // the rows of the card, named by index in its buttons

function _appRowHtml(a, hidden) {
  const bits = [`<span class="app-name">${escHtml(a.name)}</span>`];
  if (a.port) bits.push(`<span class="hint">:${escHtml(String(a.port))}</span>`);
  if (hidden) {
    bits.push(`<button class="btn-icon btn-xs app-end" data-action="appShow" data-arg="${escAttr(a.id)}">Show</button>`);
    return `<div class="app-row">${bits.join(' ')}</div>`;
  }
  if (a.monitored) bits.push('<span class="c-green">Monitored</span>');
  else if (a.can_monitor) bits.push(`<button class="btn-icon btn-xs" data-action="appMonitor" data-arg="${escAttr(a.id)}">Monitor</button>`);
  const c = a.connector;
  if (c && c.connected) bits.push('<span class="c-green">Connected</span>');
  else if (c && c.reachable) bits.push(`<button class="btn-icon btn-xs" data-action="appConnect" data-arg="${escAttr(a.id)}">Connect</button>`);
  else if (c && a.scope === 'local') bits.push('<span class="hint">listens on this host only, so the server cannot read it</span>');
  bits.push(`<button class="btn-icon btn-xs app-end" data-action="appHide" data-arg="${escAttr(a.id)}">Hide</button>`);
  return `<div class="app-row">${bits.join(' ')}</div>`;
}

async function loadDrawerApps(id, keep) {
  const sec = document.getElementById('drawer-apps-section');
  const box = document.getElementById('drawer-apps-list');
  if (!sec || !box) return;
  // a drawer that has just been opened starts empty: what was on screen is another host's, or this one's of a visit ago, and `keep` is for the draw after a button
  if (!keep || _appsShown !== id) { box.innerHTML = ''; sec.hidden = true; _appsShown = ''; }
  const seq = ++_appsSeq;
  const r = await api('GET', '/devices/' + encodeURIComponent(id) + '/apps').catch(() => null);
  if (seq !== _appsSeq || _drawerDeviceId !== id) return;
  if (!r || r.error) { sec.hidden = true; return; }
  _appsOf[id] = r;
  _appsShown = id;
  const apps = r.apps || [], hidden = r.dismissed || [];
  sec.hidden = !(apps.length || hidden.length);
  let html = apps.map(a => _appRowHtml(a, false)).join('');
  if (r.monitor_problem && apps.some(a => a.port)) html += `<div class="hint mt-6"><span>A monitor cannot run from this host:</span> <span>${escHtml(r.monitor_problem)}</span></div>`;
  if (hidden.length) {
    html += `<div class="mt-8"><button class="btn-icon btn-xs" data-action="appToggleHidden" aria-expanded="${_appsShowHidden ? 'true' : 'false'}"><span>Hidden apps</span> <span class="hint">${hidden.length}</span></button></div>`;
    if (_appsShowHidden) html += hidden.map(a => _appRowHtml(a, true)).join('');
  }
  box.innerHTML = html;
}

function appToggleHidden() {
  _appsShowHidden = !_appsShowHidden;
  if (typeof _drawerDeviceId !== 'undefined' && _drawerDeviceId) loadDrawerApps(_drawerDeviceId, true);
}

async function appMonitor(appId) {
  const id = _drawerDeviceId;
  if (!id) return;
  const r = await api('POST', '/devices/' + encodeURIComponent(id) + '/apps/monitor', { app: appId });
  if (!r || r.error) { failToast(r); return; }
  toast(r.existing ? 'Already monitored' : 'Monitor added', 'success');
  loadDrawerApps(id, true);
}

// The integration wizard, started on the connection step with the address of the app on that host and the instance bound to the host ("Runs on host").
function _appsConnectWizard(a, hostId, hostName) {
  return _loadJsModule('app-wizard.js').then(() => {
    if (typeof wizStart === 'function') wizStart('integration', { type: a.connector.type, url: a.connector.url, name: a.name + ' on ' + hostName, device_id: hostId });
  });
}

function appConnect(appId) {
  const id = _drawerDeviceId;
  const r = _appsOf[id];
  const a = r && (r.apps || []).find(x => x.id === appId);
  if (!a || !a.connector || !a.connector.reachable) return;
  _appsConnectWizard(a, id, _drawerDeviceName || id);
}

async function _appsDismiss(hostId, appId, hide) {
  const r = await api('POST', '/devices/' + encodeURIComponent(hostId) + '/apps/dismiss', { app: appId, dismissed: hide });
  if (!r || r.error) { failToast(r); return false; }
  toast(hide ? 'Hidden' : 'Shown again', 'success');
  return true;
}

async function appHide(appId) {
  const id = _drawerDeviceId;
  if (id && await _appsDismiss(id, appId, true)) loadDrawerApps(id, true);
}

async function appShow(appId) {
  const id = _drawerDeviceId;
  if (id && await _appsDismiss(id, appId, false)) loadDrawerApps(id, true);
}

async function loadFoundApps() {
  const card = document.getElementById('found-apps-card');
  const box = document.getElementById('found-apps-list');
  if (!card || !box) return;
  const r = await api('GET', '/app-discovery').catch(() => null);
  _foundRows = (r && !r.error && Array.isArray(r.apps)) ? r.apps : [];
  card.hidden = !_foundRows.length;
  box.innerHTML = _foundRows.map((a, i) =>
    `<div class="app-row"><span class="app-name">${escHtml(a.name)}</span> <span class="hint">${escHtml(a.device_name)}:${escHtml(String(a.port))}</span> `
    + `<button class="btn-icon btn-xs" data-action="appFoundConnect" data-arg="${i}">Connect</button> `
    + `<button class="btn-icon btn-xs app-end" data-action="appFoundHide" data-arg="${i}">Hide</button></div>`).join('');
}

function appFoundConnect(i) {
  const a = _foundRows[Number(i)];
  if (a && a.connector) _appsConnectWizard(a, a.device_id, a.device_name);
}

async function appFoundHide(i) {
  const a = _foundRows[Number(i)];
  if (a && await _appsDismiss(a.device_id, a.id, true)) loadFoundApps();
}

function appsRefresh() {
  if (typeof _drawerDeviceId !== 'undefined' && _drawerDeviceId && document.getElementById('device-drawer')?.classList.contains('open')) loadDrawerApps(_drawerDeviceId, true);
  if (document.getElementById('page-integrations')?.classList.contains('active')) loadFoundApps();
}
