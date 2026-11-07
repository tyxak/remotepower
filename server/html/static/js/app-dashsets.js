// app-dashsets.js — the layouts manager at the top of the Home Customize panel (8.0.0). Buildless classic script; every symbol is global
// like the rest of the client JS. It is fetched when the panel opens (the lazy map in app.js), and the core it manages stays in app.js:
// _dashSets, _dashSetId, _dashSetById, _dashSetsFit, setDashSet and _dashWrite. A layout is a name and the list of widgets it shows.
// The saved layout of the account ("My layout") is not one of them: it is always there, and it can be neither renamed nor deleted.
// Every name here is text the person typed, so it goes through escHtml / escAttr.

// Ready-made starting points. Each lists the widgets it shows, in order, by their keys in DASH_WIDGETS (a test holds every key to that
// list); the sizes are the widgets' own. A person gets one as a layout of their own and changes it from there.
const _DASH_PRESETS = [
  { id: 'fleet', label: 'Fleet overview',
    w: ['health', 'heatmap', 'fleettotal', 'healthscore', 'offline', 'stale', 'neverseen', 'groups', 'os', 'devtypes', 'agentver', 'recentonline',
        'overview', 'roster'] },
  { id: 'security', label: 'Security',
    w: ['heatmap', 'attseverity', 'alertsev', 'crittotal', 'cves', 'bruteforce', 'threatintel', 'worldports', 'newports', 'fwchanges', 'sshkeys', 'tls', 'drift',
        'atttop', 'tickets'] },
  { id: 'patching', label: 'Patching',
    w: ['patchpct', 'updatestotal', 'updates', 'rebootreq', 'crittotal', 'cves', 'versionskew', 'agentver', 'os', 'maintenance', 'atttop'] },
  { id: 'capacity', label: 'Capacity',
    w: ['capacity', 'diskfill', 'mounts', 'smart', 'storagedeg', 'temp', 'ups', 'bandwidth', 'oom', 'backups', 'heatmap'] },
];

// the name a ready-made layout gets when the person did not type one: in the language of the page
function _dashTr(text) {
  try { const i18n = window.RPi18n; return (i18n && typeof i18n.t === 'function' && i18n.t(text)) || text; } catch (_) { return text; }
}

// keep: what was typed in the new-layout row before the panel was drawn again (any change of the layout redraws it)
function renderDashSetManage(keep) {
  const box = document.getElementById('dash-set-manage');
  if (!box) return;
  const sets = _dashSets(), cur = _dashSetId();
  const row = (id, name, inUse, own) =>
    '<div class="dash-set-item' + (inUse ? ' on' : '') + '" role="listitem">'
    + '<span class="dash-set-name" title="' + escAttr(name) + '">' + escHtml(name) + '</span>'
    + (inUse ? '<span class="dash-set-state">Showing now</span>'
             : '<button class="btn-icon" data-action="dashSetUse" data-arg="' + escAttr(id) + '" title="Use this layout">Use</button>')
    + (own ? '' :
       '<button class="btn-icon" data-action="dashSetRename" data-arg="' + escAttr(id) + '" title="Rename this layout">Rename</button>'
       + '<button class="btn-icon c-danger-outline" data-action="dashSetDelete" data-arg="' + escAttr(id) + '" title="Delete this layout">Delete</button>')
    + '</div>';
  let h = '<div class="section-title">Layouts</div>';
  if (!sets.length) {
    h += '<p class="hint">Keep more than one arrangement of this page, for example one for security and one for patching, and switch between them from the top of the page. Your current layout stays as it is.</p>';
  } else {
    h += '<div class="dash-set-list" role="list">' + row('', 'My layout', !cur, true)
      + sets.map(s => row(s.id, s.name, s.id === cur, false)).join('') + '</div>';
  }
  h += '<div class="dash-set-new">'
    + '<input id="dash-set-name" class="form-input" type="text" maxlength="' + _DASH_SET_NAME + '" placeholder="Name of the new layout"'
    + ' aria-label="Name of the new layout" autocomplete="off">'
    + '<select id="dash-set-from" class="form-input input-auto" aria-label="Start from">'
    + '<option value="copy">A copy of this layout</option>'
    + _DASH_PRESETS.map(p => '<option value="' + p.id + '">' + escHtml(p.label) + '</option>').join('')
    + '<option value="empty">An empty layout</option>'
    + '</select>'
    + '<button class="btn-icon" data-action="dashSetCreate">Create layout</button>'
    + '</div>';
  if (sets.length) {
    h += '<div class="dash-set-wall"><button class="btn-icon" data-action="dashSetWallLink" title="Copy a link that opens the wall display">'
      + 'Copy wall display link</button><span class="hint">Opens the page as a wall display and shows each layout in turn, 30 seconds each.</span></div>';
  }
  box.innerHTML = h;
  const nameEl = document.getElementById('dash-set-name'), fromEl = document.getElementById('dash-set-from');
  if (keep && nameEl) nameEl.value = keep.name || '';
  if (keep && fromEl && keep.from) fromEl.value = keep.from;
  if (nameEl) nameEl.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); dashSetCreate(); } });
}

function dashSetUse(id) { setDashSet(id || ''); }

function dashSetCreate() {
  const nameEl = document.getElementById('dash-set-name'), fromEl = document.getElementById('dash-set-from');
  const from = fromEl ? fromEl.value : 'copy';
  const preset = _DASH_PRESETS.find(p => p.id === from);
  const name = (String((nameEl && nameEl.value) || '').trim() || (preset ? _dashTr(preset.label) : '')).slice(0, _DASH_SET_NAME);
  if (!name) { toast('Give the layout a name', 'warning'); if (nameEl) nameEl.focus(); return; }
  if (_dashSets().some(s => s.name.toLowerCase() === name.toLowerCase())) { toast('A layout with that name already exists', 'warning'); return; }
  const w = from === 'copy' ? _dashLayoutToSet(_dashLayout())
    : from === 'empty' ? []
      : (preset ? preset.w.filter(k => _DASH_KEYS.includes(k)) : []);
  let id;
  do { id = 's' + Math.random().toString(36).slice(2, 8); } while (_dashSetById(id));   // a letter first: the click dispatcher turns "123" into a number
  const next = _dashSets().concat([{ id, name, w }]);
  if (!_dashSetsFit(next)) {
    toast(next.length > _DASH_SET_MAX ? 'You can keep up to 8 layouts: delete one first' : 'There is no room for another layout: delete one first', 'warning');
    return;
  }
  _uiPrefs.dashboard_sets = next;
  if (nameEl) nameEl.value = '';          // the panel is drawn again below and keeps what is typed: that was used now
  setDashSet(id);
  toast('Layout created', 'success');
}

async function dashSetRename(id) {
  const set = _dashSetById(id);
  if (!set) return;
  const answer = await uiPrompt({ message: 'Name for this layout:', value: set.name });
  if (answer === null || answer === undefined) return;
  const name = String(answer).trim().slice(0, _DASH_SET_NAME);
  if (!name || name === set.name) return;
  if (_dashSets().some(s => s !== set && s.name.toLowerCase() === name.toLowerCase())) { toast('A layout with that name already exists', 'warning'); return; }
  if (!_dashSetsFit(_dashSets().map(s => s === set ? { id: s.id, name, w: s.w } : s))) {
    toast('There is no room for that name: delete a layout first', 'warning');
    return;
  }
  set.name = name;
  _scheduleFlushUiPrefs();
  applyDashboardLayout();      // redraws the switcher
  _renderDashEditPanel();
}

async function dashSetDelete(id) {
  const set = _dashSetById(id);
  if (!set) return;
  if (!await uiConfirm({ message: 'Delete this layout?', confirmText: 'Delete', danger: true })) return;
  const at = _dashSets().indexOf(set), inUse = _dashSetId() === id;
  const remove = () => {
    const next = _dashSets().filter(s => s.id !== id);
    if (next.length) _uiPrefs.dashboard_sets = next; else delete _uiPrefs.dashboard_sets;
    if (_uiPrefs.dashboard_set === id) delete _uiPrefs.dashboard_set;
    if (inUse || _dashSetOverride === id) setDashSet('');
    else { applyDashboardLayout(); _renderDashEditPanel(); _scheduleFlushUiPrefs(); }
  };
  const restore = () => {
    if (_dashSetById(id)) return;           // already back (the toast and the topbar arrow both undo)
    const next = _dashSets().slice();
    next.splice(Math.min(at, next.length), 0, set);
    if (!_dashSetsFit(next)) { toast('There is no room for another layout: delete one first', 'warning'); return; }
    _uiPrefs.dashboard_sets = next;
    if (inUse) setDashSet(id);
    else { applyDashboardLayout(); _renderDashEditPanel(); _scheduleFlushUiPrefs(); }
  };
  remove();
  uiUndoCtl.push({ label: 'Layout deleted', undo: restore, redo: remove });
  toast('Layout deleted', 'info', { action: { label: 'Undo', icon: 'undo', fn: restore } });
}

// A link that opens the page as a wall display (kiosk) and rotates through the saved layout and every named one.
function dashSetWallLink() {
  const url = location.origin + location.pathname + '?kiosk=1&cycle=30&pages=home&sets=all';
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(url)
      .then(() => toast('Wall display link copied', 'success'))
      .catch(() => uiPrompt({ message: 'Copy this wall display link:', value: url }));
  } else {
    uiPrompt({ message: 'Copy this wall display link:', value: url });
  }
}
