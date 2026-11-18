// app-persistence.js — what starts by itself on a Windows host, and what was added or removed since its first inventory (8.0.2). Buildless classic script; every symbol is
// global like the rest of the client JS, and it is fetched when the host drawer opens (the lazy map in app.js).
//
//   loadDrawerPersistence(id)  fills the drawer's Persistence section for the host that is open: the changes, newest first, then the entries on the host now, by place
//
// The names and command lines in the answer came from a host, so they are only ever put in the page with escHtml; the server has already cut them, taken the control
// characters out and replaced a password in a command line. A host id never travels through data-arg: the drawer's own host is `_drawerDeviceId`. The section is not drawn for
// a host that is not a Windows one (no request is made) and stays hidden for one that has sent no inventory yet.

let _persSeq = 0;           // the newest request of the drawer: an older answer arrives late and is dropped

const _PERS_CATS = ['run', 'winlogon', 'services', 'tasks', 'startup'];
const _PERS_LABEL = { run: 'Run key', winlogon: 'Winlogon value', services: 'Service', tasks: 'Scheduled task', startup: 'Startup folder' };

function _persEntryHtml(e) {
  const place = e.loc ? ` <span class="hint">${escHtml(e.loc)}</span>` : '';
  const cmd = e.data ? ` <code class="pers-cmd">${escHtml(e.data)}</code>` : '';
  return `<span class="app-name">${escHtml(e.name)}</span>${place}${cmd}`;
}

function _persChangeHtml(c) {
  const added = c.op === 'added';
  return `<div class="app-row"><span class="patch-badge${added ? ' warn' : ''}">${added ? 'Added' : 'Removed'}</span> <span class="hint">${_PERS_LABEL[c.cat] || ''}</span> ${_persEntryHtml(c)} <span class="hint">${timeAgoHtml(c.ts)}</span></div>`;
}

function _persPlaceHtml(cat, place) {
  const items = place.items || [];
  let notes = '';
  if (!place.ok) notes += '<div class="hint">This place could not be read at the last inventory. It is shown as it was.</div>';
  else if (!place.complete) notes += '<div class="hint">This list was cut at its limit, so changes in it are not tracked.</div>';
  if (!items.length && !notes) return '';
  return `<div class="mt-8"><span class="app-name">${_PERS_LABEL[cat]}</span> <span class="hint">${items.length}</span></div>${notes}`
    + items.map(e => `<div class="app-row">${_persEntryHtml(e)}</div>`).join('');
}

async function loadDrawerPersistence(id) {
  const sec = document.getElementById('drawer-persistence-section');
  if (!sec) return;
  sec.hidden = true;
  const isWindows = /windows/i.test(String((typeof _drawerDeviceData !== 'undefined' && _drawerDeviceData ? _drawerDeviceData.os : '') || ''));
  if (!isWindows) return;
  const seq = ++_persSeq;
  const r = await api('GET', '/devices/' + encodeURIComponent(id) + '/persistence').catch(() => null);
  if (seq !== _persSeq || (typeof _drawerDeviceId !== 'undefined' && _drawerDeviceId !== id)) return;
  const p = r && !r.error ? r.persistence : null;
  if (!p) return;
  document.getElementById('drawer-persistence-when').innerHTML =
    `<span class="hint">First inventory</span> ${timeAgoHtml(p.baseline)} <span class="hint">Last inventory</span> ${timeAgoHtml(p.ts)}`;
  const changes = p.changes || [];
  document.getElementById('drawer-persistence-changes').innerHTML = changes.length
    ? changes.map(_persChangeHtml).join('')
    : '<div class="hint">Nothing has changed since the first inventory.</div>';
  document.getElementById('drawer-persistence-list').innerHTML = _PERS_CATS.map(c => _persPlaceHtml(c, (p.inventory || {})[c] || {})).join('');
  sec.hidden = false;
}
