// ══════════════════════════════════════════════════════════════════════════════
// State
// ══════════════════════════════════════════════════════════════════════════════
let devices         = [];
let shutdownTarget  = null;
let rebootTarget    = null;
let pinTimer        = null;
let pinSeconds      = 0;
let refreshTimer    = null;
let refreshInterval = 60;
let refreshRemaining = refreshInterval;
let activeTagFilter = null;

// ══════════════════════════════════════════════════════════════════════════════
// v1.11.5: per-user UI prefs (density, persistent filter strings, multi-column
// sort). One source of truth (`_uiPrefs`); `tableCtl` and `densityCtl` read
// from / write to it; a debounced `flushUiPrefs()` POSTs the whole document
// back to the server. The server replaces the user's `ui_prefs` field on each
// POST — partial updates would race when the same user has two tabs open.
//
// Schema, mirrored in api.py::_sanitise_ui_prefs:
//   _uiPrefs = {
//     <table_name>: {
//        density: 'compact'|'comfortable'|'spacious',
//        filter:  string,
//        sort:    [{col: string, dir: 'asc'|'desc'}, ...]
//     }
//   }
// ══════════════════════════════════════════════════════════════════════════════
let _uiPrefs = {};
let _uiPrefsLoaded = false;     // true once we've fetched at least once
let _uiPrefsFlushTimer = null;

async function loadUiPrefs() {
  // Best-effort. If the server is on an older version that doesn't have
  // /api/ui-prefs yet, the api() helper returns null and we proceed with
  // empty prefs — the page still works, just without persistence.
  try {
    const data = await api('GET', '/ui-prefs');
    _uiPrefs = (data && typeof data === 'object') ? data : {};
  } catch (e) {
    _uiPrefs = {};
  }
  _uiPrefsLoaded = true;
}

function _scheduleFlushUiPrefs() {
  // Debounce — typing into a filter box generates an event per keystroke.
  // 600ms after the last change feels right: long enough that we don't
  // spam the server, short enough that closing the tab in a hurry still
  // saves.
  if (_uiPrefsFlushTimer) clearTimeout(_uiPrefsFlushTimer);
  _uiPrefsFlushTimer = setTimeout(flushUiPrefs, 600);
}

async function flushUiPrefs() {
  if (!_uiPrefsLoaded) return;     // don't overwrite server state with empty
  _uiPrefsFlushTimer = null;
  try {
    await api('POST', '/ui-prefs', _uiPrefs);
  } catch (e) {
    // Non-fatal — prefs persistence is cosmetic. The current session still
    // works from the in-memory _uiPrefs object.
  }
}

function getTablePrefs(tableName) {
  if (!_uiPrefs[tableName] || typeof _uiPrefs[tableName] !== 'object') {
    _uiPrefs[tableName] = {};
  }
  return _uiPrefs[tableName];
}

// ══════════════════════════════════════════════════════════════════════════════
// v1.11.5: tableCtl — a small wrapper that gives any tbody filter + sort
// behaviour without each page rewriting the same boilerplate.
//
// Pages register their table by calling tableCtl.register(opts). On each
// data refresh they call tableCtl.render(tableName, rows). The ctl handles
// applying the persistent filter string, applying the multi-column sort,
// rendering the rows via the page-supplied row-builder, and rendering an
// empty-state message when the filter eliminates everything.
//
// Usage from a page:
//   tableCtl.register({
//     name: 'cves_overview',                   // unique key, becomes prefs key
//     tbody: 'cve-tbody',                      // <tbody id="...">
//     filterInput: 'cve-filter-input',         // <input id="..."> (optional)
//     sortHeaders: 'cve-thead',                // <thead id="..."> with data-col attrs
//     columns: ['name', 'group', 'critical'],  // sortable column ids
//     // Required: build a row from one record. Receives normalised columns
//     // map (see `getColumns` below). Returns innerHTML for the <tr>.
//     row: (rec) => `<tr><td>${escHtml(rec.name)}</td>…</tr>`,
//     // How to extract sortable values for each column. Defaults to
//     // rec[col]; override for derived columns ('total_cves' -> sum of
//     // critical+high+medium+low, etc.).
//     getColumns: (rec) => ({...}),  // optional
//     // How to filter — receives the lowercased filter string and a
//     // record. Default checks all primitive fields stringified.
//     match: (rec, q) => boolean,    // optional
//     emptyMsg: 'No CVE findings found.',
//     emptyMsgFiltered: 'No findings match the filter.',
//   });
//
// Reasoning for the structure:
// - Server-roundtrip on every keystroke would be silly when filtering 50
//   rows. Filter+sort is fully client-side; only the prefs are server-side.
// - Sort state lives in prefs (multi-column, persistent). Click a header
//   and it's the only sort; shift+click to add as secondary; click an
//   already-sorted column to flip its direction; click while it's
//   descending to remove it from the sort list.
// - Filter is a single substring match. Power users can use the dropdown
//   filters that already exist on some pages (status, group, severity).
// ══════════════════════════════════════════════════════════════════════════════
const tableCtl = (() => {
  const _registry = {};

  function register(opts) {
    _registry[opts.name] = opts;
    // Wire the filter input if present — restore stored value, attach
    // listener that re-renders + persists.
    if (opts.filterInput) {
      const el = document.getElementById(opts.filterInput);
      if (el) {
        const stored = (getTablePrefs(opts.name).filter) || '';
        if (stored && !el.value) el.value = stored;
        el.addEventListener('input', () => {
          getTablePrefs(opts.name).filter = el.value;
          _scheduleFlushUiPrefs();
          // v1.11.6: pages that compose multiple filters (e.g. audit
          // log's action dropdown + free-text) supply their own
          // re-render via opts.refresh. Without it, fall back to
          // re-rendering the last-known rows.
          if (opts.refresh) {
            opts.refresh();
          } else if (opts._lastRows) {
            render(opts.name, opts._lastRows);
          }
        });
      }
    }
    // Wire sort headers if present.
    if (opts.sortHeaders) {
      _wireHeaders(opts);
    }
  }

  function _wireHeaders(opts) {
    const thead = document.getElementById(opts.sortHeaders);
    if (!thead) return;
    // v3.3.0 freeze fix: wireSortOnly used to call addEventListener
    // on every invocation. For tables whose <thead> is static markup
    // (Monitoring → Processes is the canonical example), each call
    // STACKED another click handler — N handlers per th after N
    // wire calls. Every handler fires on click, each one re-renders
    // (which re-wires), so handler count doubles per click. Browser
    // freezes within a few clicks.
    //
    // Tables that re-render their thead via innerHTML (e.g. the
    // ports table) get a fresh element without our flag and wire
    // normally. So this guard is safe for both shapes.
    if (thead.dataset.sortWired === '1') {
      _renderSortIndicators(opts);
      return;
    }
    thead.dataset.sortWired = '1';
    thead.querySelectorAll('th[data-col]').forEach(th => {
      th.style.cursor = 'pointer';
      th.style.userSelect = 'none';
      th.addEventListener('click', (ev) => {
        const col = th.getAttribute('data-col');
        const prefs = getTablePrefs(opts.name);
        if (!Array.isArray(prefs.sort)) prefs.sort = [];
        const existing = prefs.sort.find(s => s.col === col);
        if (ev.shiftKey) {
          // Multi-column: append, or flip if it's already in the list
          if (existing) {
            existing.dir = existing.dir === 'asc' ? 'desc' : 'asc';
          } else {
            prefs.sort.push({col, dir: 'asc'});
          }
        } else {
          // Single-column: replace the whole list with this one,
          // unless we're already sorting only by this and need to
          // either flip or clear.
          if (prefs.sort.length === 1 && prefs.sort[0].col === col) {
            if (prefs.sort[0].dir === 'asc') {
              prefs.sort[0].dir = 'desc';
            } else {
              // third click on the same column — clear sort
              prefs.sort = [];
            }
          } else {
            prefs.sort = [{col, dir: 'asc'}];
          }
        }
        _renderSortIndicators(opts);
        _scheduleFlushUiPrefs();
        // v1.11.6: same pattern as the filter handler — page can
        // compose multiple filters and supply a refresh function.
        if (opts.refresh) {
          opts.refresh();
        } else if (opts._lastRows) {
          render(opts.name, opts._lastRows);
        }
      });
    });
    _renderSortIndicators(opts);
  }

  function _renderSortIndicators(opts) {
    const thead = document.getElementById(opts.sortHeaders);
    if (!thead) return;
    const sort = getTablePrefs(opts.name).sort || [];
    thead.querySelectorAll('th[data-col]').forEach(th => {
      const col = th.getAttribute('data-col');
      const idx = sort.findIndex(s => s.col === col);
      // Strip any old indicator
      const baseLabel = th.getAttribute('data-label') || th.textContent.replace(/[▲▼²³⁴⁵\s]+$/g,'').trim();
      th.setAttribute('data-label', baseLabel);
      if (idx === -1) {
        th.innerHTML = baseLabel + ' <span class="isl-304">↕</span>';
      } else {
        const arrow = sort[idx].dir === 'asc' ? '▲' : '▼';
        // Multi-column: show the priority order as a small superscript
        const prio = sort.length > 1 ? `<sup class="isl-305">${idx+1}</sup>` : '';
        th.innerHTML = baseLabel + ` <span class="isl-306">${arrow}${prio}</span>`;
      }
    });
  }

  // Default substring match: lowercase the filter, lowercase every primitive
  // value on the record, check inclusion. Good enough for almost every use
  // case; pages that need smarter matching (e.g. ranges) supply their own.
  function _defaultMatch(rec, q) {
    if (!q) return true;
    for (const k in rec) {
      const v = rec[k];
      if (v == null) continue;
      const t = typeof v;
      if (t === 'string' || t === 'number' || t === 'boolean') {
        if (String(v).toLowerCase().includes(q)) return true;
      } else if (Array.isArray(v)) {
        for (const x of v) {
          if (x != null && String(x).toLowerCase().includes(q)) return true;
        }
      }
    }
    return false;
  }

  function _applySort(rows, sortKeys, getColumns) {
    if (!sortKeys || !sortKeys.length) return rows;
    const sorted = rows.slice();
    sorted.sort((a, b) => {
      const colsA = getColumns ? getColumns(a) : a;
      const colsB = getColumns ? getColumns(b) : b;
      for (const {col, dir} of sortKeys) {
        let va = colsA[col];
        let vb = colsB[col];
        // Empty/null sorts to the end regardless of direction
        const aEmpty = (va == null || va === '');
        const bEmpty = (vb == null || vb === '');
        if (aEmpty && bEmpty) continue;
        if (aEmpty) return 1;
        if (bEmpty) return -1;
        // Numeric vs string compare
        if (typeof va === 'number' && typeof vb === 'number') {
          if (va !== vb) return dir === 'asc' ? va - vb : vb - va;
        } else {
          const sa = String(va).toLowerCase();
          const sb = String(vb).toLowerCase();
          if (sa < sb) return dir === 'asc' ? -1 : 1;
          if (sa > sb) return dir === 'asc' ? 1 : -1;
        }
      }
      return 0;
    });
    return sorted;
  }

  function render(name, rows) {
    const opts = _registry[name];
    if (!opts) return;
    opts._lastRows = rows;          // cached for re-render on filter change
    const prefs = getTablePrefs(name);
    const tbody = document.getElementById(opts.tbody);
    if (!tbody) return;

    const filter = (prefs.filter || '').toLowerCase().trim();
    const matchFn = opts.match || _defaultMatch;
    let filtered = filter ? rows.filter(r => matchFn(r, filter)) : rows;

    filtered = _applySort(filtered, prefs.sort || [], opts.getColumns);

    if (!filtered.length) {
      const colspan = opts.colspan || 9;
      const msg = filter
        ? (opts.emptyMsgFiltered || `No matches for "${escHtml(filter)}".`)
        : (opts.emptyMsg || 'No data.');
      tbody.innerHTML = `<tr><td colspan="${colspan}" class="empty-state">${msg}</td></tr>`;
      _applyScrollWrap(tbody, 0);
      return;
    }
    tbody.innerHTML = filtered.map(opts.row).join('');
    _applyScrollWrap(tbody, filtered.length);
  }

  // v2.2.5: when a rendered table has more than 20 rows, wrap its
  // nearest `.table-card` ancestor in a fixed-height scroll container.
  // Sticky thead keeps the column headers pinned. The class is toggled
  // every render so filtering down to <=20 rows removes the wrap, and
  // expanding back up restores it.
  const SCROLL_THRESHOLD = 20;
  function _applyScrollWrap(tbody, count) {
    // The wrap lives on the .table-card around the <table>.
    const card = tbody.closest('.table-card');
    if (!card) return;
    if (count > SCROLL_THRESHOLD) {
      card.classList.add('scrollable-table-wrap');
    } else {
      card.classList.remove('scrollable-table-wrap');
    }
  }

  function getStoredFilter(name) {
    return (getTablePrefs(name).filter) || '';
  }

  // v3.2.1: lightweight sort wiring for tables with custom HTML renderers
  // that don't fit the register/render contract. Some pages (ACME, CMDB
  // asset list, Listening Ports, etc.) build their own intricate row HTML
  // and have for years; rewriting them all to fit tableCtl's `row:`
  // callback is a wide change. Instead, those renderers can just call
  //
  //   tableCtl.wireSortOnly('acme-thead', 'acme', () => _acmeRenderTable());
  //   const sorted = tableCtl.sortRows('acme', rowsArr, getColumnsFn);
  //
  // wireSortOnly() handles click handlers + sort indicators; sortRows()
  // is a one-shot apply for the renderer to use before building HTML.
  function wireSortOnly(theadId, prefsName, rerender) {
    const thead = document.getElementById(theadId);
    if (!thead) return;
    const opts = { name: prefsName, sortHeaders: theadId, refresh: rerender };
    // Keep a registry entry so sort indicators render correctly even when
    // the renderer is custom. Filter is not wired (the renderer handles it).
    if (!_registry[prefsName]) {
      _registry[prefsName] = opts;
    }
    // Re-wire on every call (safe — addEventListener on new th elements).
    _wireHeaders(opts);
  }

  function sortRows(prefsName, rows, getColumns) {
    const prefs = getTablePrefs(prefsName);
    return _applySort(rows, prefs.sort || [], getColumns);
  }

  return { register, render, getStoredFilter, wireSortOnly, sortRows };
})();

// ══════════════════════════════════════════════════════════════════════════════
// v1.11.5: densityCtl — three-mode density toggle, persisted to ui_prefs.
// Currently only used on the front Devices index. Future-proofed so any
// page can opt in by setting a different `name`.
// ══════════════════════════════════════════════════════════════════════════════
const densityCtl = (() => {
  function getDensity(name) {
    return getTablePrefs(name).density || 'comfortable';
  }
  function setDensity(name, value, onChange) {
    // v1.11.6: 'minimal' added as a 4th mode for the Devices grid (one
    // device per row). Server-side UI_DENSITY_VALUES is also extended.
    if (!['minimal','compact','comfortable','spacious'].includes(value)) return;
    getTablePrefs(name).density = value;
    _scheduleFlushUiPrefs();
    if (onChange) onChange(value);
  }
  // Render a 4-button segmented control. Returns an HTML string the caller
  // can drop into a toolbar.
  function renderControl(name, onChange) {
    const cur = getDensity(name);
    const btn = (val, label, title) => {
      const sel = cur === val;
      return `<button data-action-btn="_densityCtlBtn" data-dname="${escAttr(name)}" data-val="${val}" title="${escHtml(title)}" class="isl-307 ${sel ? 'sel' : ''}">${escHtml(label)}</button>`;
    };
    // Stash the callback under a deterministic global so the inline onclick
    // can find it. Slightly hacky, but avoids needing a UUID per control.
    window['__densityCb_' + name] = onChange;
    return `<div class="isl-308">
      ${btn('minimal', '≡', 'Minimal — one device per line')}
      ${btn('compact', '▤', 'Compact — denser cards')}
      ${btn('comfortable', '⊞', 'Comfortable — default')}
      ${btn('spacious', '⊟', 'Spacious — larger, roomier')}
    </div>`;
  }
  return { get: getDensity, set: setDensity, renderControl };
})();

// ══════════════════════════════════════════════════════════════════════════════
// v1.10.0: OS icons
// ══════════════════════════════════════════════════════════════════════════════
// Two icons total: Linux (Tux) and Windows. Anything that doesn't match
// either gets a question-mark glyph so detection failures are visible
// rather than silent. Detection is a coarse string match against the
// agent-reported `os` field — most distros report something containing
// "Linux" or a distro name we can recognise; Windows reports "Windows".
//
// The SVGs are kept tiny (16×16) and use currentColor so they inherit the
// surrounding text colour. Stylised glyphs, not full-fidelity logos.
const _OS_ICONS = {
  // Tux silhouette, very stylised
  linux:   '<svg viewBox="0 0 24 24" fill="currentColor" aria-label="Linux"><path d="M12 3c-2.2 0-3.5 1.8-3.5 4 0 1.5.5 2.5.5 3.5 0 1-1.5 1.5-2.5 3-1 1.5-1.5 3.5-1.5 5 0 1.5 1 2.5 2 2.5h10c1 0 2-1 2-2.5 0-1.5-.5-3.5-1.5-5-1-1.5-2.5-2-2.5-3 0-1 .5-2 .5-3.5C15.5 4.8 14.2 3 12 3zm-1.5 4.5a.75.75 0 1 1 0-1.5.75.75 0 0 1 0 1.5zm3 0a.75.75 0 1 1 0-1.5.75.75 0 0 1 0 1.5z"/></svg>',
  // Windows tile
  windows: '<svg viewBox="0 0 24 24" fill="currentColor" aria-label="Windows"><path d="M3 5.5l8-1.1v7.4H3V5.5zm0 7.6h8v7.4l-8-1.1v-6.3zm9-8.8 9-1.3v9H12V4.3zm0 9h9v9l-9-1.3v-7.7z"/></svg>',
  unknown: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-label="Unknown OS"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 4 2c-.7.5-1.5 1-1.5 2v.5"/><circle cx="12" cy="17" r=".7" fill="currentColor"/></svg>',
};

function osIconKey(osStr) {
  // Returns 'linux', 'windows', or 'unknown' for the given OS string.
  // Linux detection is broad: distro names, kernel hints, and "GNU"
  // all count. macOS, BSD, and unknowns fall through to 'unknown' —
  // we only ship the two icons the user asked for.
  if (!osStr) return 'unknown';
  const s = String(osStr).toLowerCase();
  if (s.includes('windows') || s.includes('microsoft')
      || s.includes('win10') || s.includes('win11')
      || s.includes('win 10') || s.includes('win 11')) {
    return 'windows';
  }
  // Linux and friends — distro names included so e.g. a misconfigured
  // agent that reports "Ubuntu 22.04" without the word "Linux" still
  // gets the right icon.
  const linuxHints = [
    'linux', 'gnu', 'ubuntu', 'debian', 'fedora', 'rhel', 'red hat',
    'redhat', 'rocky', 'alma', 'centos', 'arch', 'cachyos', 'manjaro',
    'alpine', 'suse', 'opensuse', 'mint', 'pop!_os', 'pop_os',
    'gentoo', 'slackware', 'nixos',
  ];
  if (linuxHints.some(h => s.includes(h))) return 'linux';
  return 'unknown';
}

function osIcon(osStr, sizePx) {
  // v2.2.1: now returns the branded distro logo from getDistroIcon().
  // Old API preserved — sizePx (default 16) overrides the default 14px
  // class size via inline width/height attributes (which beat class CSS).
  // Existing callers benefit automatically.
  const px = sizePx || 16;
  const branded = getDistroIcon(osStr);
  // Inject width/height onto the <svg> tag, dropping the class size
  const sized = branded.replace(
    /<svg /,
    `<svg width="${px}" height="${px}" `);
  return `<span class="os-icon va-middle icon-inline-flex" title="${(osStr || 'Unknown OS').replace(/"/g,'&quot;')}">${sized}</span>`;
}

// ══════════════════════════════════════════════════════════════════════════════
// Auth
// ══════════════════════════════════════════════════════════════════════════════
function checkAuth() {
  // v1.8.5: getToken() checks both localStorage (remember-me) and sessionStorage
  if (getToken()) {
    showApp();
  } else {
    document.getElementById('login-page').style.display = 'flex';
  }
}
async function doLogin() {
  const user = document.getElementById('login-user').value.trim();
  const pass = document.getElementById('login-pass').value;
  const totpInput = document.getElementById('login-totp');
  const totp_code = totpInput ? totpInput.value.trim() : '';
  const rememberCb = document.getElementById('login-remember');
  const remember_me = !!(rememberCb && rememberCb.checked);
  const err  = document.getElementById('login-error');
  err.classList.remove('show');
  err.style.color = '';
  if (!user || !pass) return;
  try {
    const payload = {username: user, password: pass, remember_me};
    if (totp_code) payload.totp_code = totp_code;
    const resp = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload),
    });
    const data = await resp.json();
    if (data.totp_required) {
      document.getElementById('totp-group').style.display = 'block';
      totpInput.focus();
      if (data.totp_invalid) {
        err.textContent = 'Invalid authenticator code — try again';
        err.classList.add('show');
      } else {
        err.textContent = 'Enter your 6-digit authenticator code';
        err.style.color = 'var(--accent)';
        err.classList.add('show');
      }
      return;
    }
    if (data.ok) {
      // v1.8.5: remember-me uses localStorage (survives browser close);
      // un-checked uses sessionStorage (cleared with the tab).
      // Always clear *both* first so toggling between modes doesn't leave stale tokens.
      sessionStorage.removeItem('rp_token'); sessionStorage.removeItem('rp_me');
      localStorage.removeItem('rp_token');   localStorage.removeItem('rp_me');
      const store = remember_me ? localStorage : sessionStorage;
      store.setItem('rp_token', data.token);
      store.setItem('rp_me',    data.username || user);
      // v2.3.2: remember whether this account is still on the default
      // password so showApp() can raise a warning banner.
      window._mustChangePassword = !!data.must_change_password;
      showApp();
    } else {
      err.textContent = 'Invalid username or password';
      err.classList.add('show');
    }
  } catch(e) {
    err.textContent = 'Connection error';
    err.classList.add('show');
  }
}
function doLogout() {
  // v1.11.5: synchronously flush any pending prefs save before we toss the
  // token. The fetch is fire-and-forget — we don't await it because logout
  // should be snappy even on slow networks. If it fails the user keeps the
  // unsaved prefs in their browser session if they log back in within a
  // session lifetime (server still has the previous saved version).
  if (_uiPrefsLoaded) {
    try { flushUiPrefs(); } catch(e) {}
  }
  _uiPrefs = {}; _uiPrefsLoaded = false;
  // v1.8.5: clear both stores
  sessionStorage.removeItem('rp_token'); sessionStorage.removeItem('rp_me');
  localStorage.removeItem('rp_token');   localStorage.removeItem('rp_me');
  document.getElementById('app').style.display = 'none';
  document.getElementById('login-page').style.display = 'flex';
  clearInterval(refreshTimer);
}
function getToken() {
  // v1.8.5: check both — remember-me persists in localStorage, regular in sessionStorage
  return localStorage.getItem('rp_token') || sessionStorage.getItem('rp_token') || '';
}
function getMe() {
  return localStorage.getItem('rp_me') || sessionStorage.getItem('rp_me') || '';
}
async function showApp() {
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('app').style.display = 'block';
  // v1.11.5: load per-user UI prefs before any table renders so the
  // first paint already reflects density / filters / sort. Best-effort —
  // a server that doesn't support /api/ui-prefs (older release) just
  // returns null and we proceed with empty prefs.
  await loadUiPrefs();
  // v2.2.1: Home is the new default landing page. We still kick off
  // loadDevices() so the device search/group dropdowns and the cached
  // devices array are warm for whenever the operator clicks Devices.
  loadHome();
  loadDevices();
  startRefreshCycle();
  checkServerVersion();
  applyTheme();
  requestNotifications();
  // v2.3.0: show/hide the Virtualization nav entry based on whether
  // Proxmox is configured.
  refreshProxmoxNav();
  // v2.3.2: warn loudly while the account is still on the default
  // password. The banner links to the password change form and
  // disappears once the password is changed (server clears the flag).
  if (window._mustChangePassword) {
    let banner = document.getElementById('default-pw-banner');
    if (!banner) {
      banner = document.createElement('div');
      banner.id = 'default-pw-banner';
      banner.style.cssText = 'background:var(--red-soft,#3a1f1f);border-bottom:1px solid var(--red-edge,#7f1d1d);color:var(--red,#f87171);padding:10px 16px;font-size:13px;text-align:center;cursor:pointer';
      banner.innerHTML = '\u26a0 This account is using the default password. <strong>Change it now</strong> \u2014 click here.';
      banner.onclick = () => showPage('settings', document.querySelector('.nav-btn[data-page=\"settings\"]'));
      document.body.insertBefore(banner, document.body.firstChild);
    }
    banner.style.display = 'block';
  }
}
async function checkServerVersion() {
  try {
    const data = await api('GET', '/version');
    if (!data || !data.update_available) return;
    // v3.0.1: respect a per-version snooze stored in localStorage.
    // Key includes the specific version so a new release re-shows the banner.
    const snoozeKey = `rp_version_snooze_${data.latest}`;
    const snoozeUntil = parseInt(localStorage.getItem(snoozeKey) || '0', 10);
    if (snoozeUntil && Date.now() < snoozeUntil) return;
    document.getElementById('update-banner')?.remove();
    const banner = document.createElement('div');
    banner.id = 'update-banner';
    banner.className = 'update-banner';
    // v2.4.6: the banner now carries the actual update steps, not just
    // a release link — RemotePower never self-updates, so the operator
    // runs these by hand (see docs/admin-guide.md §7).
    banner.innerHTML = `
      <span>${_icon('zap',14)} RemotePower <strong>v${data.latest}</strong> is available
      (you have v${data.current}).</span>
      <a href="${data.release_url}" target="_blank" rel="noopener">Release notes →</a>
      <button type="button" class="update-steps-btn" data-action="toggleUpdateSteps" >How to update</button>
      <button type="button" class="update-steps-btn" data-action="snoozeUpdateBanner" data-arg="${escAttr(data.latest)}" title="Hide for 30 days">Snooze 30d</button>
      <div id="update-steps" class="d-none">
        <div class="isl-309">
          Back up your data directory first, then on the server:</div>
        <code>git pull &amp;&amp; sudo bash install-server.sh</code>
        <div class="isl-310">
          RemotePower does not update itself — this is a deliberate manual step.</div>
      </div>`;
    document.querySelector('header').insertAdjacentElement('afterend', banner);
  } catch(e) {}
}

// v3.0.1: snooze the update banner for 30 days for a specific version.
function snoozeUpdateBanner(version) {
  const until = Date.now() + 30 * 86400 * 1000;
  localStorage.setItem(`rp_version_snooze_${version}`, String(until));
  document.getElementById('update-banner')?.remove();
  toast(`Update reminder for v${version} snoozed for 30 days`, 'info');
}
function toggleUpdateSteps() {
  const s = document.getElementById('update-steps');
  if (s) s.style.display = s.style.display === 'none' ? 'block' : 'none';
}
// v3.3.0: theme toggle uses Lucide moon/sun SVGs instead of emoji
const _THEME_MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
const _THEME_SUN  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
function applyTheme() {
  const theme = localStorage.getItem('rp_theme') || 'dark';
  document.body.classList.toggle('light', theme === 'light');
  const btn = document.querySelector('.theme-btn');
  if (btn) btn.innerHTML = theme === 'light' ? _THEME_MOON : _THEME_SUN;
}
function toggleTheme() {
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('rp_theme', isLight ? 'light' : 'dark');
  const btn = document.querySelector('.theme-btn');
  if (btn) btn.innerHTML = isLight ? _THEME_MOON : _THEME_SUN;
}
async function api(method, path, body, extra) {
  const opts = {method, headers: {'X-Token': getToken()}};
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  // v3.2.1: callers can pass an AbortController signal (and other fetch
  // options) via the optional `extra` arg. Used by long-running calls
  // like AI mitigation so the operator can cancel a hung request.
  if (extra && typeof extra === 'object') {
    for (const k of ['signal']) {
      if (extra[k] !== undefined) opts[k] = extra[k];
    }
  }
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) { doLogout(); return null; }
  // v2.0: surface a friendly toast for demo-mode 403s. The server
  // returns {demo: true, error: "..."} which this catches centrally so
  // every caller sees the right behaviour without per-call handling.
  // We still return the parsed body so callers that want to react
  // (close modals, restore form state, etc.) can.
  if (r.status === 403) {
    try {
      const parsed = await r.clone().json();
      if (parsed && parsed.demo) {
        if (typeof toast === 'function') {
          toast('Demo mode — read-only sandbox. Nothing was changed.', 'error');
        } else {
          alert(parsed.error || 'Read-only demo mode.');
        }
        return parsed;
      }
      // v3.0.3: F2 interceptor returns must_change_password: true on
      // every blocked endpoint until the password is changed. The
      // login-response flag already drives the banner; this branch
      // covers the case where a user reloads the page or hits an
      // endpoint directly while still on the default password.
      if (parsed && parsed.must_change_password) {
        window._mustChangePassword = true;
        if (typeof toast === 'function') {
          toast('Change your password first — every other action is blocked.', 'error');
        }
        // Route to Settings → Account so the change form is one click away.
        try { showPage('settings', document.querySelector('.nav-btn[data-page=\"settings\"]')); } catch (_) {}
        return parsed;
      }
    } catch (_) { /* fall through to generic handler */ }
  }
  return r.json();
}

// ─── v2.0: sidebar group collapse state ─────────────────────────────────────
//
// State is per-browser (localStorage) — feels right for a UI preference,
// avoids round-tripping it through the server. The active page always
// expands its containing group regardless of stored state, so a
// freshly-loaded session shows the user where they are.

function toggleSidebarGroup(name) {
  const group = document.querySelector(`.sidebar-group[data-group="${name}"]`);
  if (!group) return;
  const willCollapse = !group.classList.contains('collapsed');
  group.classList.toggle('collapsed', willCollapse);
  try {
    localStorage.setItem(`sidebar.${name}.collapsed`, willCollapse ? '1' : '0');
  } catch (_) { /* private mode / quota — non-fatal */ }
}

function _restoreSidebarGroups() {
  document.querySelectorAll('.sidebar-group').forEach(group => {
    const name = group.dataset.group;
    let collapsed;
    try {
      collapsed = localStorage.getItem(`sidebar.${name}.collapsed`);
    } catch (_) { collapsed = null; }
    // Default state: Fleet, Monitoring, Security, Planning, Help expanded; Admin collapsed.
    if (collapsed === null) {
      collapsed = (name === 'admin') ? '1' : '0';
    }
    group.classList.toggle('collapsed', collapsed === '1');
  });
}
// Run on load — sidebar exists by the time DOMContentLoaded fires
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', _restoreSidebarGroups);
} else {
  _restoreSidebarGroups();
}

// v2.0: docs page filter. Substring match against the summary text and
// data-keywords attribute, no fancy ranking. Auto-expands matching cards
// so search results are immediately visible.
function filterDocs(query) {
  const q = (query || '').trim().toLowerCase();
  document.querySelectorAll('#docs-container .doc-card').forEach(card => {
    if (!q) {
      card.classList.remove('hidden');
      card.removeAttribute('open');
      return;
    }
    const summary = (card.querySelector('summary')?.textContent || '').toLowerCase();
    const body = (card.querySelector('.doc-body')?.textContent || '').toLowerCase();
    const keywords = (card.dataset.keywords || '').toLowerCase();
    if (summary.includes(q) || body.includes(q) || keywords.includes(q)) {
      card.classList.remove('hidden');
      card.setAttribute('open', '');
    } else {
      card.classList.add('hidden');
    }
  });
}

function showPage(name, btn) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const el = document.getElementById('page-' + name);
  if (el) el.classList.add('active');
  if (btn) btn.classList.add('active');
  // v3.0.2: keep the URL bar in sync with the visible page. Without this,
  // the hash sticks at whatever switchSettingsTab last wrote (e.g.
  // #settings/notifs) and stays there as you click through Home, Devices,
  // Logs etc. replaceState (not pushState) so back-button doesn't trap
  // the user in deep history of every page they tabbed through.
  try {
    if (name === 'settings') {
      // switchSettingsTab will set #settings/<tab>; leave hash alone here
      // so we don't fight with it. Just ensure we're at the settings root
      // when arriving cold.
      if (!location.hash.startsWith('#settings')) {
        history.replaceState(null, '', '#settings');
      }
    } else {
      const newHash = '#' + name;
      if (location.hash !== newHash) {
        history.replaceState(null, '', newHash);
      }
    }
  } catch (_) { /* private mode, file://, etc — non-fatal */ }
  // v2.0: auto-expand the sidebar group containing this nav button so
  // the active item is always visible (avoids the surprise of clicking
  // a saved bookmark and seeing nothing highlighted in the sidebar).
  if (btn) {
    const group = btn.closest('.sidebar-group');
    if (group && group.classList.contains('collapsed')) {
      group.classList.remove('collapsed');
      try { localStorage.setItem(`sidebar.${group.dataset.group}.collapsed`, '0'); } catch(_){}
    }
  }
  if (name === 'home')     loadHome();
  if (name === 'monitor')  { runMonitor(); loadDeviceMetrics(); loadCustomScripts(); loadListeningPorts(); loadProcesses(); _showAllMonPanels(); }
  if (name === 'history')  loadHistory();
  if (name === 'schedule') loadSchedule();
  if (name === 'users')    loadUsers();
  if (name === 'settings') { loadSettings(); loadTotpStatus(); loadWebhookLog(); }
  if (name === 'ai') { loadAIPage(); }
  if (name === 'about')    loadAbout();
  if (name === 'apikeys')  loadApiKeys();
  if (name === 'cmdlib')   loadCmdLib();
  if (name === 'scripts')  loadScripts();
  if (name === 'patches')        loadPatchReport();
  if (name === 'cve')            loadCVEReport();
  if (name === 'services') loadServicesReport();
  if (name === 'maintenance') loadMaintenance();
  if (name === 'logs')     enterLogsPage();
  else                     leaveLogsPage();
  if (name === 'iac')      loadIacPage();
  if (name === 'calendar') loadCalendar();
  if (name === 'tasks')    loadTasks();
  if (name === 'cmdb')     enterCMDB();
  if (name === 'containers') { enterContainers(); _showAllContainerPanels(); }
  if (name === 'virtualization') loadVirtualization();
  if (name === 'netmap')   { enterNetmap(); loadDiscovery(); }
  if (name === 'compliance') loadCompliance();
  if (name === 'tls')      { enterTLS(); _showAllTLSPanels(); }
  if (name === 'drift')    loadDrift();
  if (name === 'links')    enterLinks();
  if (name === 'audit')    loadAuditLog();
  if (name === 'alerts')   loadAlerts();
  if (name === 'confirmations') loadConfirmations();
  if (name === 'self')     loadSelfStatus();
}

const _MON_PANELS = ['mon-panel-targets', 'mon-panel-metrics', 'mon-panel-ports', 'mon-panel-scripts', 'mon-panel-processes'];
function _showAllMonPanels() {
  _MON_PANELS.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'block'; });
}
function showMonitorSection(sectionId, btn) {
  // sectionId is e.g. 'section-targets' → panel is 'mon-panel-targets'
  const panelId = 'mon-panel-' + sectionId.replace('section-', '');
  showPage('monitor', btn);
  _MON_PANELS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = (id === panelId) ? 'block' : 'none';
  });
}

const _CONTAINER_PANELS = ['containers-panel-agent', 'containers-panel-lxc'];
function _showAllContainerPanels() {
  _CONTAINER_PANELS.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'block'; });
}
function showContainerSection(sectionId, btn) {
  showPage('containers', btn);
  _CONTAINER_PANELS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = (id === sectionId) ? 'block' : 'none';
  });
  if (sectionId === 'containers-panel-lxc') {
    // When navigating directly to LXC, always show the section and load with
    // focused=true so a "not configured" hint is shown instead of hiding.
    const sec = document.getElementById('containers-lxc-section');
    if (sec) sec.style.display = 'block';
    loadProxmoxLXC(true);
  }
}

const _TLS_PANELS = ['tls-panel-expiry', 'tls-panel-acme'];
function _showAllTLSPanels() {
  _TLS_PANELS.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'block'; });
}
function showTLSSection(sectionId, btn) {
  showPage('tls', btn);
  _TLS_PANELS.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = (id === sectionId) ? 'block' : 'none';
  });
  if (sectionId === 'tls-panel-acme') loadAcme();
}

async function loadDevices() {
  try {
    const data = await api('GET', '/devices');
    if (!data) return;
    devices = data;
    window._devicesCache = data;  // v3.0.2: command palette consumes this
    renderDevices();
  } catch(e) {
    toast('Failed to load devices', 'error');
  }
}
function renderDevices() {
  const container = document.getElementById('devices-container');
  // v1.11.5: apply density class so card padding/font-size match the
  // user's stored preference. The renderControl() call returns innerHTML
  // for the segmented control; the callback re-applies the class and
  // re-renders so the change is instant.
  const dens = densityCtl.get('devices');
  // v1.11.6: 'dens-minimal' added (one device per line). Strip all
  // four before adding the current one to avoid stale-state issues
  // when toggling between modes rapidly.
  container.classList.remove('dens-minimal', 'dens-compact', 'dens-comfortable', 'dens-spacious');
  container.classList.add('dens-' + dens);
  const densHolder = document.getElementById('devices-density-toggle');
  if (densHolder) {
    densHolder.innerHTML = densityCtl.renderControl('devices', () => renderDevices());
  }
  // v1.11.5: restore stored search term on first render. After that the
  // input is the source of truth and we sync back into prefs whenever
  // it changes (via filterDevices()).
  const searchEl = document.getElementById('device-search-input');
  if (searchEl && _uiPrefsLoaded && !searchEl.dataset.prefsRestored) {
    const stored = (getTablePrefs('devices').filter) || '';
    if (stored && !searchEl.value) searchEl.value = stored;
    searchEl.dataset.prefsRestored = '1';
  }
  const online = devices.filter(d => d.online).length;
  checkDeviceNotifications(devices);
  const allGroups = [...new Set(devices.map(d => d.group).filter(g => g))].sort();
  const groupSel = document.getElementById('device-group-filter');
  if (groupSel) {
    const cur = groupSel.value;
    groupSel.innerHTML = '<option value="all">All groups</option>' + allGroups.map(g => `<option value="${escHtml(g)}">${escHtml(g)}</option>`).join('');
    groupSel.value = cur;
  }
  document.getElementById('stat-total').textContent   = devices.length;
  document.getElementById('stat-online').textContent  = online;
  document.getElementById('stat-offline').textContent = devices.length - online;
  const allTags = [...new Set(devices.flatMap(d => d.tags || []))].sort();
  const filterBar = document.getElementById('tag-filter-bar');
  if (filterBar) {
    filterBar.innerHTML = allTags.map(t => `<button data-action="setTagFilter" data-arg="${escAttr(t)}" class="isl-311 ${activeTagFilter===t ? 'active' : ''}">${escHtml(t)}</button>`).join('');
    if (activeTagFilter) filterBar.innerHTML += `<button data-action="_setTagFilterClear" class="isl-312">✕ clear</button>`;
  }
  let filtered = activeTagFilter ? devices.filter(d => (d.tags || []).includes(activeTagFilter)) : devices;
  const deviceSearchTerm = (document.getElementById('device-search-input')?.value || '').toLowerCase();
  if (deviceSearchTerm) filtered = filtered.filter(d => (d.name||'').toLowerCase().includes(deviceSearchTerm) || (d.hostname||'').toLowerCase().includes(deviceSearchTerm) || (d.ip||'').toLowerCase().includes(deviceSearchTerm) || (d.os||'').toLowerCase().includes(deviceSearchTerm) || (d.group||'').toLowerCase().includes(deviceSearchTerm) || (d.tags||[]).some(t => t.toLowerCase().includes(deviceSearchTerm)));
  const deviceStatusFilter = document.getElementById('device-status-filter')?.value || 'all';
  if (deviceStatusFilter === 'online') filtered = filtered.filter(d => d.online);
  else if (deviceStatusFilter === 'offline') filtered = filtered.filter(d => !d.online);
  // v3.2.0 follow-up: SNMP status filter for agentless devices
  const snmpFilter = document.getElementById('device-snmp-filter')?.value || 'all';
  if (snmpFilter === 'configured') filtered = filtered.filter(d => d.snmp_status && d.snmp_status.enabled);
  else if (snmpFilter === 'ok')   filtered = filtered.filter(d => d.snmp_status && d.snmp_status.ok);
  else if (snmpFilter === 'fail') filtered = filtered.filter(d => d.snmp_status && d.snmp_status.enabled && !d.snmp_status.ok);
  const deviceGroupFilter = document.getElementById('device-group-filter')?.value || 'all';
  if (deviceGroupFilter !== 'all') filtered = filtered.filter(d => d.group === deviceGroupFilter);
  if (filtered.length === 0) {
    container.innerHTML = `<div class="empty-state"><div class="empty-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div><div class="empty-title">No devices enrolled</div><div class="empty-text">Click "Enroll device" to generate a PIN,<br>then run the client installer on your machine.</div></div>`;
    return;
  }
  // v1.11.7: split path. Minimal density renders as a real table with
  // sortable column headers and aligned columns — the v1.11.6 attempt
  // used flex on a per-card basis which made columns ragged across rows
  // (the user reported "Online" not appearing under "Online" and so on).
  // A table is the correct primitive: each <tr> has the same <td> layout,
  // browsers handle alignment, headers click-to-sort via tableCtl.
  if (dens === 'minimal') {
    _renderDevicesMinimal(filtered);
    return;
  }
  // v2.2.5: scroll wrap when the device grid has >20 cards. Without
  // this, dense fleets push the page to several thousand pixels and
  // the Home tile row gets lost off-screen. The class adds max-height
  // + overflow-y to the existing grid.
  const SCROLL_THRESHOLD = 20;
  if (filtered.length > SCROLL_THRESHOLD) {
    container.classList.add('scrollable-grid-wrap');
  } else {
    container.classList.remove('scrollable-grid-wrap');
  }
  container.innerHTML = filtered.map(d => {
    const isOnline = d.online;
    const lastSeen = d.last_seen ? timeAgo(d.last_seen) : 'Never';
    const si = d.sysinfo || {};
    const pkg = si.packages;
    const isSel = selectedDevices.has(d.id);
    const isMonitored = d.monitored !== false;
    let patchHtml = '';
    if (pkg && pkg.upgradable !== null && pkg.upgradable !== undefined) {
      const cls = pkg.upgradable > 0 ? 'warn' : 'ok';
      patchHtml = `<span class="patch-badge ${cls}">${pkg.upgradable} update${pkg.upgradable !== 1 ? 's' : ''}</span>`;
    }
    const missedHtml = (!isOnline && d.missed_polls && d.offline_reason === 'missed_polls') ? `<span class="missed-badge">~${d.missed_polls} missed</span>` : '';
    const iconContent = d.icon ? `<span class="isl-313">${escHtml(d.icon)}</span>` : (isSel ? `<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>` : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`);
    // v2.2.1: sparkline for the dominant disk/memory metric (whichever
    // is more "interesting" — closer to capacity). The metrics history
    // lives in the device's stored sysinfo trail. If we don't have ≥2
    // points we render an empty box (renderSparkline handles this).
    const mounts = (si.mounts || []);
    const rootMount = mounts.find(m => m.path === '/') || mounts[0];
    const memPct = si.mem && si.mem.percent != null ? si.mem.percent : null;
    // Pull from per-device metrics history (window stored client-side
    // from heartbeats). If the history isn't there yet, we'll render
    // nothing — the value still shows numerically.
    const metricsHist = (window._metricsHistory && window._metricsHistory[d.id]) || {};
    const diskHist = metricsHist.disk || [];
    const memHist  = metricsHist.mem || [];
    const cpuHist  = metricsHist.cpu || [];
    const diskSpark = rootMount && diskHist.length >= 2
      ? renderSparkline(diskHist, {width: 52, height: 14, color: rootMount.percent > 85 ? 'var(--red)' : rootMount.percent > 70 ? 'var(--amber)' : 'var(--green)'})
      : '';
    const memSpark = memPct != null && memHist.length >= 2
      ? renderSparkline(memHist, {width: 52, height: 14, color: memPct > 85 ? 'var(--red)' : memPct > 70 ? 'var(--amber)' : 'var(--accent)'})
      : '';
    // v3.2.0 (B5): SNMP status pill for agentless devices.
    const ss = d.snmp_status;
    let snmpPill = '';
    let snmpMeta = '';
    if (ss && ss.enabled) {
      const cls = ss.ok ? 'snmp-pill snmp-ok' : 'snmp-pill snmp-fail';
      const tip = ss.ok
        ? `SNMP polled OK · sysName ${ss.sys_name || '?'}${ss.last_ok ? ' · ' + timeAgo(ss.last_ok) : ''}`
        : `SNMP failing (${ss.fails || 1} cycle${(ss.fails || 1) > 1 ? 's' : ''})${ss.last_error ? ' — ' + ss.last_error : ''}`;
      snmpPill = ` <span class="${cls}" title="${escAttr(tip)}">${_icon('radio',12)} ${ss.ok ? 'SNMP' : 'SNMP×'}</span>`;
      if (ss.ok && ss.sys_uptime != null) {
        // sysUpTime is hundredths of a second (TimeTicks)
        const days = Math.floor(ss.sys_uptime / 100 / 86400);
        snmpMeta = `<div class="meta-item"><div class="meta-label">SNMP up</div><div class="meta-value">${days}d</div></div>`;
      }
    }
    return `<div class="device-card ${isOnline ? 'online' : 'offline'} isl-314 ${isSel ? 'is-selected' : ''}">
      <div class="device-header">
        <div class="device-info">
          <div class="device-icon pointer" data-action="toggleSelect" data-arg="${d.id}" title="Select for batch action">${iconContent}</div>
          <div><div class="device-name">${getDistroIcon(d.os)}${escHtml(d.name)}${d.notes ? `<span class="notes-tip" title="${escHtml(d.notes)}" data-action="openNotesModal" data-arg="${d.id}" data-arg2="${escAttr(d.notes)}" >${_icon('edit',12)}</span>` : ''}${snmpPill}</div><div class="device-hostname">${escHtml(d.hostname)}${d.group ? ` <span class="group-badge">${escHtml(d.group)}</span>` : ''}${isMonitored ? '' : ' <span class="isl-315">unmonitored</span>'}${d.agent_uninstalled ? _uninstallBadge(d) : ''}</div></div>
        </div>
        <div class="status-badge ${isOnline ? 'online' : 'offline'}"><div class="status-badge-dot"></div>${isOnline ? 'Online' : 'Offline'}${missedHtml}</div>
      </div>
      <div class="device-meta"><div class="meta-item"><div class="meta-label">OS</div><div class="meta-value">${escHtml(d.os || '—')}</div></div><div class="meta-item"><div class="meta-label">IP</div><div class="meta-value">${escHtml(d.ip || '—')}</div></div><div class="meta-item"><div class="meta-label">Version</div><div class="meta-value">${escHtml(d.version || '—')} ${patchHtml}</div></div><div class="meta-item"><div class="meta-label">Poll / Enrolled</div><div class="meta-value">${d.poll_interval||60}s · ${d.enrolled ? timeAgo(d.enrolled) : '—'}</div></div>${rootMount ? `<div class="meta-item"><div class="meta-label">Disk /</div><div class="meta-value">${rootMount.percent}% ${diskSpark}</div></div>` : ''}${memPct != null ? `<div class="meta-item"><div class="meta-label">Memory</div><div class="meta-value">${memPct}% ${memSpark}</div></div>` : ''}${snmpMeta}</div>
      ${deviceDropdownHtml(d, isMonitored)}
      ${(d.tags||[]).length ? `<div class="mt-8">${(d.tags||[]).map(t=>`<span class="tag-pill">${escHtml(t)}</span>`).join('')}</div>` : ''}
      <div class="last-seen">Last seen: ${lastSeen}</div>
    </div>`;
  }).join('');
  // v2.2.1: update the client-side metrics history ring buffer so the
  // next render gets ≥2 points for sparklines. Stored in window so it
  // persists across re-renders within the same session.
  window._metricsHistory = window._metricsHistory || {};
  filtered.forEach(d => {
    const si = d.sysinfo || {};
    const h = window._metricsHistory[d.id] = window._metricsHistory[d.id] || {disk: [], mem: [], cpu: []};
    const rootMount = (si.mounts || []).find(m => m.path === '/');
    if (rootMount && typeof rootMount.percent === 'number') {
      h.disk.push(rootMount.percent);
      if (h.disk.length > 24) h.disk.shift();
    }
    if (si.mem && typeof si.mem.percent === 'number') {
      h.mem.push(si.mem.percent);
      if (h.mem.length > 24) h.mem.shift();
    }
    if (si.cpu && typeof si.cpu.percent === 'number') {
      h.cpu.push(si.cpu.percent);
      if (h.cpu.length > 24) h.cpu.shift();
    }
  });
}

// v3.3.0: badge for devices whose agent has been queued for uninstall.
// Two states:
//   • pending     — uninstall queued, but the agent hasn't heartbeated
//                   since (so the device might still be running it).
//   • completed   — last heartbeat happened BEFORE the uninstall was
//                   queued, OR the agent has been offline long enough
//                   that we assume it executed and stopped reporting.
function _uninstallBadge(d) {
  if (!d.agent_uninstalled) return '';
  const queuedAt = d.agent_uninstalled_at || 0;
  const lastSeen = d.last_seen || 0;
  // If the device has heartbeated AFTER the uninstall was queued and
  // is still online, it hasn't picked up the command yet → "pending".
  // Otherwise treat the uninstall as completed.
  const stillRunning = d.online && lastSeen > queuedAt;
  const cls   = stillRunning ? 'isl-315' : 'isl-315';
  const label = stillRunning
    ? 'agent uninstalling…'
    : 'agent uninstalled';
  const tip   = stillRunning
    ? `Queued ${queuedAt ? timeAgo(queuedAt) : ''}; awaiting next heartbeat (~60 s).`
    : `Agent has been removed from this host. Re-enroll to bring it back.`;
  return ` <span class="${cls}" title="${escAttr(tip)}">${escHtml(label)}</span>`;
}

// v1.11.7: render Devices as an aligned, sortable table. This is the new
// 'minimal' density layout — replaces the old flex-row hacky one that
// couldn't keep columns aligned when cell contents had different widths.
//
// v3.2.1 fix: the previous one-shot _devicesMinimalRegistered guard meant
// the click handlers on the column headers got wired ONCE on the very
// first render, then renderDevices() rebuilt `container.innerHTML` on
// every subsequent refresh — destroying the thead and its listeners
// with no re-wire. Result: sort indicators (↕ / ▲ / ▼) still rendered
// but clicking them did nothing. We now call tableCtl.register() on
// every render. Safe because devices_minimal has no filterInput, so
// the only side effect is re-wiring sort header click handlers — and
// the previous thead's th nodes have been garbage-collected along
// with their listeners by the innerHTML replacement, so there's no
// double-fire either.
function _registerDevicesMinimalTable() {
  // Filter is already applied upstream by the existing devices-search /
  // status / group / tag filter chain, so we tell tableCtl `match: () => true`.
  // Sort is handled here. We use a separate prefs key ('devices_minimal')
  // from the cards view ('devices') so a sort applied in minimal doesn't
  // bleed into the cards' filter-string state.
  tableCtl.register({
    name: 'devices_minimal',
    tbody: 'devices-minimal-tbody',
    sortHeaders: 'devices-minimal-thead',
    columns: ['name', 'group', 'os', 'ip', 'version', 'status', 'last_seen', 'enrolled'],
    refresh: () => renderDevices(),     // re-render through the parent path
    match: () => true,
    getColumns: (d) => ({
      name:      d.name || '',
      group:     d.group || '',
      os:        d.os || '',
      ip:        d.ip || '',
      version:   d.version || '',
      // online → 'a' / offline → 'z' so "asc" puts online first
      status:    d.online ? 'a-online' : 'z-offline',
      last_seen: d.last_seen || 0,
      enrolled:  d.enrolled || 0,
    }),
    row: (d) => {
      const isOnline = d.online;
      const lastSeen = d.last_seen ? timeAgo(d.last_seen) : 'Never';
      const isMonitored = d.monitored !== false;
      const si = d.sysinfo || {};
      const pkg = si.packages;
      let patchHtml = '';
      if (pkg && pkg.upgradable !== null && pkg.upgradable !== undefined) {
        const cls = pkg.upgradable > 0 ? 'warn' : 'ok';
        patchHtml = ` <span class="patch-badge ${cls} isl-316">${pkg.upgradable}</span>`;
      }
      const groupHtml = d.group ? `<span class="group-badge fs-10">${escHtml(d.group)}</span>` : '<span class="c-muted">—</span>';
      // v1.11.7: dropdown HTML is identical to the cards path — exact same
      // menu items, same handlers, same `dropdown-${d.id}` id so
      // toggleDropdown() works without changes. Just wrapped in a <td>.
      const dropdownHtml = `${deviceDropdownHtml(d, isMonitored)}`;
      // v1.12.1: leading checkbox cell mirrors the cards-mode batch-select
      // experience. Reuses the same selectedDevices Set so cards/minimal
      // share state — switch density mid-selection, your selection survives.
      const isSel = selectedDevices.has(d.id);
      // v2.2.5: hover-revealed `Detail · Logs · Run` strip removed.
      // The buttons were in a clunky spot and the focus-ring clipping
      // had been a pain across 2.2.1/2.2.2. The dropdown chevron in
      // the actions cell already exposes the same commands; row
      // click → openDetail covers the most common action. Less
      // visual noise, fewer fiddly edge cases.
      return `<tr class="dev-row ${isOnline ? 'online' : 'offline'} ${isSel ? 'selected' : ''}" data-dev-id="${d.id}">
        <td class="isl-317"><input type="checkbox" ${isSel ? 'checked' : ''} data-action="toggleSelect" data-arg="${d.id}" class="isl-42"></td>
        <td class="dev-status-cell"><span class="status-badge ${isOnline ? 'online' : 'offline'} isl-318"><div class="status-badge-dot"></div>${isOnline ? 'Online' : 'Offline'}</span></td>
        <td class="dev-name-cell"><a href="#" data-action="openDetail" data-arg="${d.id}" data-arg2="${escAttr(d.name)}" data-prevent-default class="isl-319">${getDistroIcon(d.os)}${escHtml(d.name)}</a>${isMonitored ? '' : ' <span class="isl-320">unmon</span>'}${d.agent_uninstalled ? _uninstallBadge(d) : ''}</td>
        <td class="dev-host-cell hint">${escHtml(d.hostname || '—')}${sshLinkIcon(d)}</td>
        <td class="dev-group-cell">${groupHtml}</td>
        <td class="dev-os-cell fs-12">${escHtml(d.os || '—')}</td>
        <td class="dev-ip-cell mono-12">${escHtml(d.ip || '—')}</td>
        <td class="dev-version-cell fs-12">${escHtml(d.version || '—')}${patchHtml}</td>
        <td class="dev-lastseen-cell hint">${lastSeen}</td>
        <td class="dev-actions-cell ta-right">${dropdownHtml}</td>
      </tr>`;
    },
    // We don't use tableCtl's empty-state because parent renderDevices
    // already handles the "no devices match filter" case — by the time
    // we get here we always have ≥1 row.
    emptyMsg: 'No devices.',
    colspan: 10,
  });
}

function _renderDevicesMinimal(filtered) {
  const container = document.getElementById('devices-container');
  // v1.11.9: column widths now explicitly sized so `table-layout: fixed`
  // can compute the layout deterministically. The OS column has no
  // width set, so it gets the remaining space — that's the column most
  // likely to have long content ("Debian GNU/Linux 12 (bookworm)") and
  // benefits most from flex sizing within an ellipsis cap. Total of
  // fixed widths is ~900px; in a 1052px container that leaves ~152px
  // for OS, which is enough for OS short names plus an ellipsis on the
  // longer ones. Narrower viewports drop columns via the @media rules
  // before things get cramped.
  // v2.2.5: when the filtered device list has more than 20 rows, wrap
  // the table in a fixed-height scroll container with a sticky thead.
  // Keeps the page short and the column headers visible. Below the
  // threshold the table renders full-height as before — small fleets
  // don't get an unnecessary scrollbar.
  const SCROLL_THRESHOLD = 20;
  const wrapClasses = filtered.length > SCROLL_THRESHOLD
    ? 'devices-minimal-wrap scrollable-table-wrap'
    : 'devices-minimal-wrap';
  container.innerHTML = `<div class="${wrapClasses}">
    <table class="devices-minimal-table">
      <thead id="devices-minimal-thead">
        <tr>
          <th class="isl-321"><input type="checkbox" id="dev-min-select-all" data-action-btn="toggleSelectAllMinimal" title="Select all visible" class="isl-42"></th>
          <th data-col="status" class="isl-188">Status</th>
          <th data-col="name" class="isl-322">Name</th>
          <th data-col="hostname" class="isl-323">Hostname</th>
          <th data-col="group" class="isl-80">Group</th>
          <th data-col="os">OS</th>
          <th data-col="ip" class="isl-324">IP</th>
          <th data-col="version" class="isl-188">Version</th>
          <th data-col="last_seen" class="isl-80">Last seen</th>
          <th class="isl-325"></th>
        </tr>
      </thead>
      <tbody id="devices-minimal-tbody"></tbody>
    </table>
  </div>`;
  _registerDevicesMinimalTable();
  tableCtl.render('devices_minimal', filtered);
}

// v2.1.0: track the live close-handler so a subsequent toggleDropdown()
// (or device-grid re-render) can remove it cleanly. The 2.0.0 implementation
// captured `el` in a closure that lived on as long as the user didn't
// click; if loadDevices() rewrote the device container and destroyed `el`,
// the handler kept firing on every document click and trying to mutate a
// detached node. Combined with the escHtml/' bug this was the visible
// "tab gets weird after a few refreshes" symptom.
let _dropdownCloseHandler = null;
function _detachDropdownCloseHandler() {
  if (_dropdownCloseHandler) {
    document.removeEventListener('click', _dropdownCloseHandler);
    _dropdownCloseHandler = null;
  }
}
function toggleDropdown(id) {
  const el = document.getElementById(`dropdown-${id}`);
  if (!el) return;
  // Close any other open dropdowns and detach their stale handler
  document.querySelectorAll('.device-dropdown.active').forEach(dd => {
    if (dd.id !== `dropdown-${id}`) dd.classList.remove('active');
  });
  _detachDropdownCloseHandler();
  el.classList.toggle('active');
  if (!el.classList.contains('active')) return;
  // Look up the dropdown by ID on every click rather than capturing the
  // node by reference — survives re-renders cleanly.
  const dropId = `dropdown-${id}`;
  _dropdownCloseHandler = (e) => {
    const live = document.getElementById(dropId);
    if (!live || !live.contains(e.target)) {
      if (live) live.classList.remove('active');
      _detachDropdownCloseHandler();
    }
  };
  setTimeout(() => {
    if (_dropdownCloseHandler) document.addEventListener('click', _dropdownCloseHandler);
  }, 10);
}
function requestShutdown(id, name) { shutdownTarget = id; document.getElementById('shutdown-name').textContent = name; openModal('shutdown-modal'); }
async function confirmShutdown() { closeModal('shutdown-modal'); const data = await api('POST', '/shutdown', {device_id: shutdownTarget}); if (data?.ok) { toast('Shutdown queued', 'success'); setTimeout(loadDevices, 3000); } else toast(data?.error || 'Failed', 'error'); }
function requestReboot(id, name) { rebootTarget = id; document.getElementById('reboot-name').textContent = name; openModal('reboot-modal'); }
async function confirmReboot() { closeModal('reboot-modal'); const data = await api('POST', '/reboot', {device_id: rebootTarget}); if (data?.ok) { toast('Reboot queued', 'success'); setTimeout(loadDevices, 5000); } else toast(data?.error || 'Failed', 'error'); }
async function sendWol(id, name) { const data = await api('POST', '/wol', {device_id: id}); if (data?.ok) toast(`Magic packet sent to ${name} (${data.mac})`, 'success'); else toast(data?.error || 'WoL failed', 'error'); }
async function removeDevice(id) { if (!confirm('Remove this device from RemotePower?')) return; const data = await api('DELETE', '/devices/' + id); if (data?.ok) { toast('Device removed', 'info'); loadDevices(); } else toast(data?.error || 'Error', 'error'); }
// v3.3.0: device-icon palette is now Lucide SVG names from _ICONS.
// Legacy emoji values stored on devices still render — _renderDeviceIcon
// returns the raw value when it's not a known icon name.
const deviceIcons = ['monitor','laptop','smartphone','printer','radio','globe','server','hardDrive','gamepad','tv','home','building','factory','cloud','ship','shield','lock','zap','package','search','wrench','terminal'];
function _renderDeviceIcon(val) {
  if (!val) return '';
  if (_ICONS[val]) return _icon(val, 16);
  return escHtml(val);
}
function openIconModal(id, current) {
  document.getElementById('icon-device-id').value = id;
  document.getElementById('icon-custom').value = current || '';
  const picker = document.getElementById('icon-picker');
  picker.innerHTML = deviceIcons.map(name =>
    `<button data-set-icon-val="${name}" class="isl-326" title="${escAttr(name)}">${_icon(name, 18)}</button>`
  ).join('');
  openModal('icon-modal');
}
async function saveDeviceIcon(icon) { const id = document.getElementById('icon-device-id').value; const data = await api('PATCH', '/devices/' + id + '/icon', { icon }); if (data?.ok) { toast(icon ? `Icon set to ${icon}` : 'Icon cleared', 'success'); closeModal('icon-modal'); loadDevices(); } else toast(data?.error || 'Failed', 'error'); }
async function toggleMonitored(id, monitored) { const data = await api('PATCH', '/devices/' + id + '/monitored', { monitored }); if (data?.ok) { toast(monitored ? 'Monitoring enabled' : 'Monitoring disabled', 'success'); loadDevices(); } else toast(data?.error || 'Failed', 'error'); }

// v3.3.4: agentless reachability mode — reveal the manual Up/Down checkmark
// only when "Manual" is picked.
function onReachabilityModeChange() {
  const mode = document.getElementById('ds-reachability')?.value;
  const row = document.getElementById('ds-manual-status-row');
  if (row) row.classList.toggle('d-none', mode !== 'manual');
}
async function clearMonitorAlerts() { if (!confirm('Reset all monitor alert state? This allows alerts to re-fire.')) return; const data = await api('DELETE', '/monitor/alerts/clear'); if (data?.ok) toast('Monitor alert state cleared', 'success'); else toast(data?.error || 'Failed', 'error'); }
async function clearWebhookLog() { if (!confirm('Clear the webhook delivery log?')) return; const data = await api('DELETE', '/webhook/log'); if (data?.ok) { toast('Webhook log cleared', 'success'); loadWebhookLog(); } else toast(data?.error || 'Failed', 'error'); }
function openDetail(id, name) {
  // v2.9.0: replaced by device drawer
  openDeviceDrawer(id, name, 'audit');
}function openEnrollModal() { generateNewPin(); openModal('enroll-modal'); }
async function generateNewPin() { document.getElementById('pin-code').textContent = '……'; try { const data = await api('POST', '/enroll/pin'); document.getElementById('pin-code').textContent = data.pin; startPinCountdown(600); } catch(e) { document.getElementById('pin-code').textContent = 'ERROR'; } }
function startPinCountdown(seconds) { clearInterval(pinTimer); pinSeconds = seconds; updatePinDisplay(); pinTimer = setInterval(() => { pinSeconds--; updatePinDisplay(); if (pinSeconds <= 0) clearInterval(pinTimer); }, 1000); }
function updatePinDisplay() { const m = Math.floor(pinSeconds / 60).toString().padStart(2, '0'); const s = (pinSeconds % 60).toString().padStart(2, '0'); document.getElementById('pin-countdown').textContent = `${m}:${s}`; }
let monitorTargets = [];
// v1.11.5: monitor table gets filter+sort via tableCtl. Same pattern as
// the other tables — register on first call, then push rows in.
let _monitorRegistered = false;
function _registerMonitorTable() {
  if (_monitorRegistered) return;
  _monitorRegistered = true;
  tableCtl.register({
    name: 'monitor',
    tbody: 'monitor-tbody',
    filterInput: 'monitor-filter',
    sortHeaders: 'monitor-thead',
    colspan: 7,
    columns: ['label', 'type', 'target', 'status', 'detail', 'checked'],
    getColumns: (m) => ({
      label:   m.label || '',
      type:    m.type || '',
      target:  m.target || '',
      // Sort 'up' before 'down' alphabetically by accident — fine; users
      // who want all-down at the top can click descending.
      status:  m.ok ? 'up' : 'down',
      detail:  m.detail || '',
      checked: m.checked || 0,
    }),
    row: (m) => {
      const i = (window.monitorTargets || []).indexOf(m);
      return `<tr><td class="fw-500">${escHtml(m.label)}</td><td><span class="isl-327">${escHtml(m.type)}</span></td><td class="isl-328">${escHtml(m.target)}</td><td><span class="mon-status ${m.ok ? 'up' : 'down'}">${m.ok ? '↑ up' : '↓ down'}</span></td><td class="hint">${escHtml(m.detail || '—')}</td><td class="hint">${m.checked ? timeAgo(m.checked) : '—'}</td><td class="row-6"><button class="btn-icon isl-44" title="History" data-action="openMonitorHistory" data-arg="${escAttr(m.label)}" ><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></button><button class="btn-icon isl-44" title="Edit" data-action="editMonitor" data-arg="${i}">${_icon('edit',14)}</button><button class="btn-icon isl-44" title="Delete" data-action="removeMonitor" data-arg="${i}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></td></tr>`;
    },
    emptyMsg: 'No monitors configured.',
    emptyMsgFiltered: 'No monitors match the filter.',
  });
}
async function runMonitor() {
  _registerMonitorTable();
  const tbody = document.getElementById('monitor-tbody');
  tbody.innerHTML = '<tr><td colspan="7" class="empty-state-sm">Checking…</td></tr>';
  const data = await api('GET', '/monitor');
  if (!data) return;
  const results = data.monitors || [];
  monitorTargets = results;
  // Set on window so the row builder can find indexes for the remove
  // button (its onclick uses the array index, not an id).
  window.monitorTargets = results;
  tableCtl.render('monitor', results);
}
// v3.3.0: Monitor add/edit share a single modal. _monitorEditIdx is the
// array index of the monitor being edited, or -1 for "add new".
let _monitorEditIdx = -1;
function openMonitorAdd() {
  _monitorEditIdx = -1;
  const t = document.querySelector('#monitor-add-modal .modal-title');
  if (t) t.textContent = 'Add monitor target';
  document.getElementById('mon-label').value = '';
  document.getElementById('mon-type').value = 'ping';
  document.getElementById('mon-target').value = '';
  openModal('monitor-add-modal');
}
function editMonitor(idx) {
  const m = (window.monitorTargets || [])[idx];
  if (!m) return;
  _monitorEditIdx = idx;
  const t = document.querySelector('#monitor-add-modal .modal-title');
  if (t) t.textContent = 'Edit monitor target';
  document.getElementById('mon-label').value  = m.label  || '';
  document.getElementById('mon-type').value   = m.type   || 'ping';
  document.getElementById('mon-target').value = m.target || '';
  openModal('monitor-add-modal');
}
async function addMonitor() {
  const label  = document.getElementById('mon-label').value.trim();
  const type   = document.getElementById('mon-type').value;
  const target = document.getElementById('mon-target').value.trim();
  if (!target) { toast('Target is required', 'error'); return; }
  const cfg = await api('GET', '/config');
  if (!cfg) return;
  const monitors = [...(cfg.monitors || [])];
  const entry = {label: label || target, type, target};
  if (_monitorEditIdx >= 0 && _monitorEditIdx < monitors.length) {
    monitors[_monitorEditIdx] = entry;
  } else {
    monitors.push(entry);
  }
  const wasEdit = _monitorEditIdx >= 0;
  const res = await api('POST', '/config', {monitors});
  if (res?.ok) {
    toast(wasEdit ? 'Monitor updated' : 'Monitor added', 'success');
    _monitorEditIdx = -1;
    closeModal('monitor-add-modal');
    runMonitor();
  } else toast(res?.error || 'Failed', 'error');
}
async function removeMonitor(idx) { const cfg = await api('GET', '/config'); if (!cfg) return; const monitors = (cfg.monitors || []).filter((_, i) => i !== idx); const res = await api('POST', '/config', {monitors}); if (res?.ok) { toast('Removed', 'info'); runMonitor(); } else toast(res?.error || 'Failed', 'error'); }
async function openMonitorHistory(label) { document.getElementById('mon-history-title').textContent = `History: ${label}`; document.getElementById('mon-history-body').innerHTML = '<div class="empty-state">Loading…</div>'; openModal('mon-history-modal'); const data = await api('GET', `/monitor/history?label=${encodeURIComponent(label)}`); if (!data) return; const history = data.history || []; if (!history.length) { document.getElementById('mon-history-body').innerHTML = '<div class="empty-state">No history yet — run a check first.</div>'; return; } const recent = history.slice(-20); const dots = recent.map(h => `<span title="${new Date(h.ts*1000).toLocaleString()} — ${h.detail||''}" class="isl-329 ${h.ok ? 'ok' : 'bad'}"></span>`).join(''); const upCount = history.filter(h => h.ok).length; const pct = Math.round(upCount / history.length * 100); const lastCheck = history[history.length - 1]; document.getElementById('mon-history-body').innerHTML = `<div class="sysinfo-row mb-16"><div class="sysinfo-pill"><div class="label">Checks</div><div class="value">${history.length}</div></div><div class="sysinfo-pill"><div class="label">Uptime</div><div class="value isl-330 ${pct>=90?'c-green': pct>=70?'c-amber': 'c-red'}">${pct}%</div></div><div class="sysinfo-pill"><div class="label">Last status</div><div class="value isl-331 ${lastCheck.ok?'c-green': 'c-red'}">${lastCheck.ok ? '↑ up' : '↓ down'}</div></div></div><div class="hint-mb">Last ${recent.length} checks (newest right)</div><div class="isl-332">${dots}</div><div class="table-card isl-333"><table><thead><tr><th>Time</th><th>Status</th><th>Detail</th></tr></thead><tbody>${[...history].reverse().slice(0,50).map(h => `<tr><td class="hint">${new Date(h.ts*1000).toLocaleString()}</td><td><span class="mon-status ${h.ok?'up':'down'}">${h.ok?'↑ up':'↓ down'}</span></td><td class="hint">${escHtml(h.detail||'—')}</td></tr>`).join('')}</tbody></table></div>`; }
// v1.11.6: users page gets filter+sort
let _usersRegistered = false;
function _registerUsersTable() {
  if (_usersRegistered) return;
  _usersRegistered = true;
  tableCtl.register({
    name: 'users',
    tbody: 'users-tbody',
    filterInput: 'users-filter',
    sortHeaders: 'users-thead',
    colspan: 4,
    columns: ['username', 'created', 'role'],
    getColumns: (u) => ({
      username: u.username || '',
      created:  u.created || 0,
      role:     u.role || 'admin',
    }),
    row: (u) => {
      const me = getMe();
      return `<tr class="user-row"><td class="fw-600">${escHtml(u.username)}${u.username === me ? ' <span class="meta-sm-nm">(you)</span>' : ''}</td><td class="hint">${u.created ? new Date(u.created * 1000).toLocaleDateString() : '—'}</td><td><span class="patch-badge ${u.role==='viewer'?'ok':'warn'} fs-11">${escHtml(u.role||'admin')}</span></td><td><div class="user-actions"><button class="btn-icon" data-action="openPasswd" data-arg="${escAttr(u.username)}" >Change pw</button><button class="btn-icon" data-action="editUserRole" data-arg="${escAttr(u.username)}" data-arg2="${escAttr(u.role||'admin')}">Edit role</button><button class="btn-icon c-danger-outline" data-action="deleteUser" data-arg="${escAttr(u.username)}" >Delete</button></div></td></tr>`;
    },
    emptyMsg: 'No users.',
    emptyMsgFiltered: 'No users match the filter.',
  });
}
async function loadUsers() {
  _registerUsersTable();
  const data = await api('GET', '/users');
  if (!data) return;
  tableCtl.render('users', data);
}
function openUserAdd() { document.getElementById('new-username').value = ''; document.getElementById('new-password').value = ''; openModal('user-add-modal'); }
async function createUser() { const username = document.getElementById('new-username').value.trim(); const password = document.getElementById('new-password').value; const role = document.getElementById('new-role').value; if (!username || !password) { toast('Both fields required', 'error'); return; } const data = await api('POST', '/users', {username, password, role}); if (data?.ok) { toast(`User ${username} created (${data.role})`, 'success'); closeModal('user-add-modal'); loadUsers(); } else toast(data?.error || 'Failed', 'error'); }
async function deleteUser(username) { if (!confirm(`Delete user "${username}"?`)) return; const data = await api('DELETE', '/users/' + username); if (data?.ok) { toast(`${username} deleted`, 'info'); loadUsers(); } else toast(data?.error || 'Failed', 'error'); }

// v3.3.0: flip a user between admin and viewer without delete+recreate.
// Server refuses to demote the last admin.
async function editUserRole(username, currentRole) {
  const newRole = currentRole === 'admin' ? 'viewer' : 'admin';
  const msg = currentRole === 'admin'
    ? `Demote "${username}" from admin to viewer?\n\nViewers can read everything but cannot mutate.`
    : `Promote "${username}" from viewer to admin?\n\nAdmins can run commands, delete devices, and change settings.`;
  if (!confirm(msg)) return;
  const data = await api('PATCH', '/users/' + username, { role: newRole });
  if (data?.ok) { toast(`${username} is now ${newRole}`, 'success'); loadUsers(); }
  else toast(data?.error || 'Failed', 'error');
}
function openPasswd(username) { document.getElementById('passwd-username').value = username; document.getElementById('passwd-old').value = ''; document.getElementById('passwd-new').value = ''; document.getElementById('passwd-old-wrap').style.display = 'block'; openModal('passwd-modal'); }
async function submitPasswd() { const username = document.getElementById('passwd-username').value; const old_pw = document.getElementById('passwd-old').value; const new_pw = document.getElementById('passwd-new').value; if (!new_pw) { toast('New password required', 'error'); return; } const data = await api('POST', '/users/passwd', {username, old_password: old_pw, new_password: new_pw}); if (data?.ok) { toast('Password updated', 'success'); closeModal('passwd-modal'); } else toast(data?.error || 'Failed', 'error'); }
// ─── v1.8.4: Settings tabs + new fields ─────────────────────────────────────
function switchSettingsTab(tab) {
  document.querySelectorAll('.settings-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.settings-pane').forEach(p =>
    p.classList.toggle('active', p.id === `settings-pane-${tab}`));
  if (tab) {
    // v3.0.2: replaceState instead of assigning to location.hash so
    // clicking through settings tabs doesn't bloat browser history
    // (one history entry per tab click is hostile to back-button users).
    try { history.replaceState(null, '', `#settings/${tab}`); }
    catch (_) { location.hash = `settings/${tab}`; }
  }
  // v2.4.2: populate the SSH username field when the Security pane opens.
  if (tab === 'security') loadSshUsername();
  // v2.4.4: load the mailbox monitor config when its pane opens.
  if (tab === 'mailbox') loadMailwatchSettings();
}

function renderEventToggleTable(events, descriptions, emailEvents) {
  const tbody = document.querySelector('#event-toggle-table tbody');
  if (!tbody) return;
  emailEvents = emailEvents || {};
  // Header — emit if not already present (re-renders on each loadSettings)
  const table = document.getElementById('event-toggle-table');
  let thead = table.querySelector('thead');
  if (!thead) {
    thead = document.createElement('thead');
    thead.innerHTML = `<tr>
      <th class="isl-334">Event</th>
      <th class="isl-334">Description</th>
      <th class="isl-335">Webhook</th>
      <th class="isl-335">Email</th>
    </tr>`;
    table.insertBefore(thead, tbody);
  }
  const order = Object.keys(descriptions);
  tbody.innerHTML = order.map(ev => {
    const wh    = events[ev] === false ? '' : 'checked';
    const email = emailEvents[ev] === true ? 'checked' : '';
    const desc = descriptions[ev] || '';
    let extra = '';
    if (ev === 'patch_alert') {
      extra = `<div class="event-extra isl-156"><span class="hint">Threshold:</span><input type="number" id="cfg-patch-threshold" min="0" placeholder="e.g. 10" class="isl-336"><span class="meta-sm-nm">pending updates</span></div>`;
    } else if (ev === 'cve_found') {
      extra = `<div class="event-extra"><div class="isl-337">Severities to alert on:</div><div id="cfg-cve-severity-row" class="isl-338"></div></div>`;
    }
    return `<tr>
      <td><code>${escHtml(ev)}</code></td>
      <td>${escHtml(desc)}${extra}</td>
      <td class="ta-center"><input type="checkbox" class="toggle-switch toggle-webhook" data-event="${escHtml(ev)}" ${wh}></td>
      <td class="ta-center"><input type="checkbox" class="toggle-switch toggle-email"   data-event="${escHtml(ev)}" ${email}></td>
    </tr>`;
  }).join('');
}

function renderCveSeverityRow(severities, current) {
  const row = document.getElementById('cfg-cve-severity-row');
  if (!row) return;
  row.innerHTML = severities.map(s => {
    const checked = current.includes(s) ? 'checked' : '';
    return `<label class="isl-339"><input type="checkbox" class="cfg-cve-sev isl-340" value="${escHtml(s)}" ${checked}>${escHtml(s)}</label>`;
  }).join('');
}

async function loadSettings() {
  const data = await api('GET', '/config');
  if (!data) return;
  // General
  document.getElementById('cfg-server-name').value = data.server_name || '';
  document.getElementById('cfg-default-poll').value = data.default_poll_interval || 60;
  document.getElementById('cfg-online-ttl').value = data.online_ttl || 180;
  document.getElementById('cfg-monitor-interval').value = data.monitor_interval || 300;
  document.getElementById('cfg-cve-cache-days').value = data.cve_cache_days || 7;
  document.getElementById('cfg-wol-bcast').value = data.wol_broadcast || '255.255.255.255';
  document.getElementById('cfg-wol-port').value  = data.wol_port || '9';

  // v3.3.0: Healthchecks.io watchdog
  const hcUrl = document.getElementById('cfg-healthchecks-url');
  if (hcUrl) hcUrl.value = data.healthchecks_url || '';
  const hcInt = document.getElementById('cfg-healthchecks-interval');
  if (hcInt) hcInt.value = data.healthchecks_interval_seconds || 60;

  // v3.0.2: multi-webhook destinations editor
  _webhookDests = Array.isArray(data.webhook_urls) ? data.webhook_urls.map(d => ({...d})) : [];
  renderWebhookDests();

  // v3.0.2: session/audit/backup settings
  const _ss = document.getElementById('session-ttl-short');
  if (_ss) _ss.value = data.session_ttl_short || '';
  const _sl = document.getElementById('session-ttl-long');
  if (_sl) _sl.value = data.session_ttl_long || '';
  const _ar = document.getElementById('audit-retention-days');
  if (_ar) _ar.value = data.audit_log_retention_days ?? '';
  const _bk = data.backup || {};
  const _be = document.getElementById('backup-enabled');
  if (_be) _be.checked = _bk.enabled !== false;
  const _bp = document.getElementById('backup-path');
  if (_bp) _bp.value = _bk.path || '';
  const _br = document.getElementById('backup-retain-days');
  if (_br) _br.value = _bk.retain_days || '';

  // v2.3.0: Proxmox connection. Token secret is masked — the field
  // shows a placeholder when one is set; blank means "keep current".
  const pxEnabled = document.getElementById('proxmox-enabled');
  if (pxEnabled) {
    pxEnabled.value = data.proxmox_enabled ? '1' : '0';
    document.getElementById('proxmox-host').value = data.proxmox_host || '';
    document.getElementById('proxmox-node').value = data.proxmox_node || '';
    document.getElementById('proxmox-token-id').value = data.proxmox_token_id || '';
    document.getElementById('proxmox-verify-tls').value = data.proxmox_verify_tls === false ? '0' : '1';
    const secEl = document.getElementById('proxmox-token-secret');
    secEl.value = '';
    if (data.proxmox_token_secret_from_env) {
      // Secret comes from RP_PROXMOX_TOKEN_SECRET — the config field
      // is irrelevant; make that clear and disable it.
      secEl.placeholder = 'set via RP_PROXMOX_TOKEN_SECRET env var';
      secEl.disabled = true;
    } else {
      secEl.disabled = false;
      secEl.placeholder = data.proxmox_token_secret_set
        ? '•••••••• (saved — leave blank to keep)'
        : 'token secret';
    }
    const envHint = document.getElementById('proxmox-env-hint');
    if (envHint) {
      envHint.style.display = data.proxmox_token_secret_from_env ? 'block' : 'none';
    }
  }

  const meta = data._meta || {};
  if (meta.min_online_ttl) {
    document.getElementById('cfg-online-ttl-hint').textContent = `${meta.min_online_ttl}–7200 (default 180)`;
  }
  // Notifications
  document.getElementById('cfg-webhook').value = data.webhook_url || '';
  const note = document.getElementById('cfg-webhook-note');
  note.style.display = data.webhook_configured ? 'block' : 'none';
  const currentEl = document.getElementById('cfg-webhook-current');
  if (data.webhook_url) { currentEl.textContent = data.webhook_url; currentEl.style.display = 'block'; }
  else                  { currentEl.style.display = 'none'; }

  renderEventToggleTable(data.webhook_events || {}, meta.webhook_event_descriptions || {}, data.email_events || {});
  const patchInput = document.getElementById('cfg-patch-threshold');
  if (patchInput) patchInput.value = data.patch_alert_threshold || '';
  if (meta.cve_severities) {
    renderCveSeverityRow(meta.cve_severities, data.cve_severity_filter || ['critical', 'high']);
  }

  // v1.8.6: SMTP
  document.getElementById('cfg-smtp-enabled').checked = !!data.smtp_enabled;
  document.getElementById('cfg-smtp-host').value      = data.smtp_host || '';
  document.getElementById('cfg-smtp-port').value      = data.smtp_port || 587;
  document.getElementById('cfg-smtp-tls').value       = data.smtp_tls || 'starttls';
  document.getElementById('cfg-smtp-from').value      = data.smtp_from || '';
  document.getElementById('cfg-smtp-username').value  = data.smtp_username || '';
  document.getElementById('cfg-smtp-password').value  = '';  // never echo back
  document.getElementById('cfg-smtp-helo').value      = data.smtp_helo_name || '';
  document.getElementById('cfg-smtp-recipients').value = data.smtp_recipients || '';
  document.getElementById('cfg-smtp-pw-set-badge').style.display = data.smtp_password_set ? '' : 'none';
  // v3.0.3: surface the RP_SMTP_PASSWORD env-var override status. Same
  // pattern as proxmox_token_secret_from_env (v2.3.1).
  {
    const smtpPwEl = document.getElementById('cfg-smtp-password');
    if (data.smtp_password_from_env) {
      smtpPwEl.disabled = true;
      smtpPwEl.placeholder = 'set via RP_SMTP_PASSWORD env var';
    } else {
      smtpPwEl.disabled = false;
      smtpPwEl.placeholder = 'Leave blank to keep existing';
    }
    const smtpEnvHint = document.getElementById('smtp-env-hint');
    if (smtpEnvHint) smtpEnvHint.style.display = data.smtp_password_from_env ? 'block' : 'none';
  }

  // v1.8.6: LDAP
  document.getElementById('cfg-ldap-enabled').checked    = !!data.ldap_enabled;
  document.getElementById('cfg-ldap-url').value          = data.ldap_url || '';
  document.getElementById('cfg-ldap-bind-dn').value      = data.ldap_bind_dn || '';
  document.getElementById('cfg-ldap-bind-password').value = '';
  document.getElementById('cfg-ldap-user-base').value    = data.ldap_user_base || '';
  document.getElementById('cfg-ldap-user-filter').value  = data.ldap_user_filter || '(uid={u})';
  document.getElementById('cfg-ldap-required-group').value = data.ldap_required_group || '';
  document.getElementById('cfg-ldap-admin-group').value  = data.ldap_admin_group || '';
  document.getElementById('cfg-ldap-tls-verify').checked = data.ldap_tls_verify !== false;
  document.getElementById('cfg-ldap-timeout').value      = data.ldap_timeout || 5;
  document.getElementById('cfg-ldap-pw-set-badge').style.display = data.ldap_bind_password_set ? '' : 'none';
  // v3.0.3: RP_LDAP_BIND_PASSWORD env-var override status.
  {
    const ldapPwEl = document.getElementById('cfg-ldap-bind-password');
    if (data.ldap_bind_password_from_env) {
      ldapPwEl.disabled = true;
      ldapPwEl.placeholder = 'set via RP_LDAP_BIND_PASSWORD env var';
    } else {
      ldapPwEl.disabled = false;
      ldapPwEl.placeholder = 'Leave blank to keep existing';
    }
    const ldapEnvHint = document.getElementById('ldap-env-hint');
    if (ldapEnvHint) ldapEnvHint.style.display = data.ldap_bind_password_from_env ? 'block' : 'none';
  }

  // Security
  document.getElementById('cfg-session-short').value = Math.round((data.session_ttl_short || 86400) / 3600);
  document.getElementById('cfg-session-long').value  = Math.round((data.session_ttl_long  || 86400 * 30) / 86400);
  document.getElementById('cfg-remember-default').checked = !!data.remember_me_default;

  // Activate tab from URL hash
  const hash = (location.hash || '').replace(/^#/, '');
  if (hash.startsWith('settings/')) {
    const tab = hash.split('/')[1];
    if (['general','notifs','security','ai','advanced'].includes(tab)) switchSettingsTab(tab);
  }

  // v2.1.3: pull AI config alongside the rest of the settings page.
  // Lives in its own endpoint so non-admins can still load /api/config
  // for their own use.
  try { await loadAISettings(); } catch(e) {}

  // v3.0.6: load Security pane diagnostics (audit-log counts, CSP
  // toggle state, HSTS detection). Lives in its own endpoint and
  // is fire-and-forget — failures degrade gracefully to placeholders.
  try { await loadSecurityDiag(); } catch(e) {}
}

// v3.0.6: populate the Security pane's diagnostics from /api/security/diag
// plus a live read of the current document's response headers (for HSTS).
async function loadSecurityDiag() {
  const diag = await api('GET', '/security/diag');
  if (diag && !diag.error) {
    document.getElementById('cfg-csp-report-logging').checked =
      diag.csp_report_logging !== false;
    document.getElementById('cfg-csp-throttle').value =
      Number.isFinite(diag.csp_report_throttle_per_minute)
        ? diag.csp_report_throttle_per_minute
        : 10;
    document.getElementById('cfg-csp-stat-24h').textContent =
      String(diag.csp_reports_last_24h ?? '—');
    document.getElementById('cfg-audit-entries').textContent =
      String(diag.audit_log_entries ?? '—');
    const archive = diag.audit_log_archive_size_bytes || 0;
    document.getElementById('cfg-audit-archive').textContent =
      archive > 0 ? `${(archive / 1024).toFixed(1)} KB` : '—';
    document.getElementById('cfg-audit-retention').textContent =
      String(diag.audit_log_retention_days ?? '—');
    // v3.3.0: IP allowlist UI state.
    const ipEnabled = document.getElementById('cfg-ipal-enabled');
    const ipList    = document.getElementById('cfg-ipal-list');
    const ipMine    = document.getElementById('cfg-ipal-mine');
    if (ipEnabled) ipEnabled.checked = !!diag.ip_allowlist_enabled;
    if (ipList)    ipList.value = (diag.ip_allowlist || []).join('\n');
    if (ipMine)    ipMine.textContent = diag.your_ip || '(unknown)';
  }
  // HSTS detection — issue a HEAD against the current page and read
  // the Strict-Transport-Security header out of the response. Fetch
  // is same-origin, doesn't need any auth context.
  const hstsEl = document.getElementById('cfg-hsts-status');
  try {
    const r = await fetch('/', { method: 'HEAD', credentials: 'omit' });
    const sts = r.headers.get('Strict-Transport-Security');
    if (sts) {
      hstsEl.innerHTML = `<span class="c-green">✓ HSTS enabled.</span> Header: <code>${escHtml(sts)}</code>`;
    } else {
      hstsEl.innerHTML = '<span class="c-amber">!HSTS is not currently being served.</span> Enable in nginx (see below) once your deployment is HTTPS-only.';
    }
  } catch (_) {
    hstsEl.textContent = 'Unable to probe HSTS — could not reach the server.';
  }
}

function clearWebhook() { document.getElementById('cfg-webhook').value = ''; toast('Webhook URL cleared — click Save to apply', 'info'); }
async function saveSettings(btn) {
  const webhook_events = {};
  document.querySelectorAll('#event-toggle-table .toggle-webhook').forEach(cb => {
    webhook_events[cb.dataset.event] = cb.checked;
  });
  // v1.8.6: per-event email toggles
  const email_events = {};
  document.querySelectorAll('#event-toggle-table .toggle-email').forEach(cb => {
    email_events[cb.dataset.event] = cb.checked;
  });
  const cve_severity_filter = Array.from(document.querySelectorAll('.cfg-cve-sev'))
    .filter(cb => cb.checked).map(cb => cb.value);
  if (cve_severity_filter.length === 0) {
    toast('Pick at least one CVE severity to alert on', 'error');
    return;
  }
  const sessShortHours = parseInt(document.getElementById('cfg-session-short').value) || 24;
  const sessLongDays   = parseInt(document.getElementById('cfg-session-long').value)  || 30;
  const payload = {
    server_name:           document.getElementById('cfg-server-name').value.trim(),
    default_poll_interval: parseInt(document.getElementById('cfg-default-poll').value) || 60,
    online_ttl:            parseInt(document.getElementById('cfg-online-ttl').value) || 180,
    monitor_interval:      parseInt(document.getElementById('cfg-monitor-interval').value) || 300,
    cve_cache_days:        parseInt(document.getElementById('cfg-cve-cache-days').value) || 7,
    wol_broadcast:         document.getElementById('cfg-wol-bcast').value.trim() || '255.255.255.255',
    wol_port:              parseInt(document.getElementById('cfg-wol-port').value) || 9,
    webhook_url:           document.getElementById('cfg-webhook').value.trim(),
    webhook_events,
    email_events,
    cve_severity_filter,
    patch_alert_threshold: (() => { const el = document.getElementById('cfg-patch-threshold'); return el ? (parseInt(el.value) || 0) : 0; })(),
    session_ttl_short:     sessShortHours * 3600,
    session_ttl_long:      sessLongDays * 86400,
    remember_me_default:   document.getElementById('cfg-remember-default').checked,

    // v1.8.6: SMTP
    smtp_enabled:    document.getElementById('cfg-smtp-enabled').checked,
    smtp_host:       document.getElementById('cfg-smtp-host').value.trim(),
    smtp_port:       parseInt(document.getElementById('cfg-smtp-port').value) || 587,
    smtp_tls:        document.getElementById('cfg-smtp-tls').value,
    smtp_from:       document.getElementById('cfg-smtp-from').value.trim(),
    smtp_username:   document.getElementById('cfg-smtp-username').value.trim(),
    smtp_helo_name:  document.getElementById('cfg-smtp-helo').value.trim(),
    smtp_recipients: document.getElementById('cfg-smtp-recipients').value.trim(),

    // v1.8.6: LDAP
    ldap_enabled:        document.getElementById('cfg-ldap-enabled').checked,
    ldap_url:            document.getElementById('cfg-ldap-url').value.trim(),
    ldap_bind_dn:        document.getElementById('cfg-ldap-bind-dn').value.trim(),
    ldap_user_base:      document.getElementById('cfg-ldap-user-base').value.trim(),
    ldap_user_filter:    document.getElementById('cfg-ldap-user-filter').value.trim() || '(uid={u})',
    ldap_required_group: document.getElementById('cfg-ldap-required-group').value.trim(),
    ldap_admin_group:    document.getElementById('cfg-ldap-admin-group').value.trim(),
    ldap_tls_verify:     document.getElementById('cfg-ldap-tls-verify').checked,
    ldap_timeout:        parseInt(document.getElementById('cfg-ldap-timeout').value) || 5,

    // v3.0.6: CSP report toggle + per-IP throttle. Both editable on the
    // Security pane; defaults are on / 10-per-minute.
    csp_report_logging:             document.getElementById('cfg-csp-report-logging')?.checked ?? true,
    csp_report_throttle_per_minute: (() => {
      const el = document.getElementById('cfg-csp-throttle');
      return el ? (parseInt(el.value, 10) || 0) : 10;
    })(),
  };
  // Only send password fields if the user typed something — empty string
  // v3.0.2: multi-webhook destinations — collect current editor state
  if (Array.isArray(_webhookDests)) {
    payload.webhook_urls = _webhookDests.map(d => {
      const c = {...d};
      delete c.pushover_token_set;
      delete c.pushover_user_set;
      return c;
    });
  }

  // v3.0.2: session timeout + audit retention + backup config
  const _sShort = parseInt(document.getElementById('session-ttl-short')?.value || '', 10);
  if (!isNaN(_sShort)) payload.session_ttl_short = _sShort;
  const _sLong  = parseInt(document.getElementById('session-ttl-long')?.value || '', 10);
  if (!isNaN(_sLong)) payload.session_ttl_long = _sLong;
  const _aRet   = parseInt(document.getElementById('audit-retention-days')?.value || '', 10);
  if (!isNaN(_aRet)) payload.audit_log_retention_days = _aRet;
  // backup is nested
  const _bkEl = document.getElementById('backup-enabled');
  if (_bkEl) {
    payload.backup = {
      enabled:     _bkEl.checked,
      path:        (document.getElementById('backup-path')?.value || '').trim() || undefined,
      retain_days: parseInt(document.getElementById('backup-retain-days')?.value || '14', 10),
    };
  }

  // would clear them on the server. Leave key out to preserve existing.
  const smtpPw = document.getElementById('cfg-smtp-password').value;
  if (smtpPw) payload.smtp_password = smtpPw;
  const ldapPw = document.getElementById('cfg-ldap-bind-password').value;
  if (ldapPw) payload.ldap_bind_password = ldapPw;

  const _btn = btn || document.getElementById('btn-save-settings');
  const _origText = _btn ? _btn.textContent : '';
  if (_btn) { _btn.disabled = true; _btn.textContent = 'Saving…'; }
  const data = await api('POST', '/config', payload);
  if (data?.ok) {
    if (_btn) { _btn.textContent = '✓ Settings saved'; setTimeout(() => { _btn.textContent = _origText; _btn.disabled = false; }, 2000); }
    toast('Settings saved', 'success');
    // Clear password fields after save so they don't sit in the DOM
    document.getElementById('cfg-smtp-password').value = '';
    document.getElementById('cfg-ldap-bind-password').value = '';
    // v2.1.3: AI settings live in their own endpoint, save in parallel
    try { await saveAISettings(); } catch(e) {}
    loadSettings(); loadWebhookLog();
  } else {
    if (_btn) { _btn.textContent = '✗ Save failed'; setTimeout(() => { _btn.textContent = _origText; _btn.disabled = false; }, 2500); }
    toast(data?.error || 'Failed', 'error');
  }
}

// ─── v1.8.6: SMTP / LDAP test buttons ─────────────────────────────────────────

async function testSmtp() {
  const btn = document.getElementById('btn-smtp-test');
  const resultEl = document.getElementById('cfg-smtp-test-result');
  resultEl.style.display = 'none';
  btn.disabled = true; btn.style.opacity = '0.5';
  try {
    const overrideRecipient = document.getElementById('cfg-smtp-test-recipient').value.trim();
    const body = overrideRecipient ? {recipient: overrideRecipient} : {};
    const data = await api('POST', '/smtp/test', body);
    if (!data) return;
    resultEl.style.display = 'block';
    if (data.ok) {
      const list = (data.recipients || []).join(', ');
      resultEl.style.background = 'rgba(34,197,94,0.1)';
      resultEl.style.color = 'var(--green)';
      resultEl.textContent = `✓ Test email sent to: ${list}`;
      toast('Test email sent', 'success');
    } else {
      resultEl.style.background = 'rgba(239,68,68,0.1)';
      resultEl.style.color = 'var(--red)';
      resultEl.textContent = `✕ ${data.error || 'unknown error'}`;
      toast(`SMTP test failed: ${data.error || 'unknown'}`, 'error');
    }
  } finally {
    btn.disabled = false; btn.style.opacity = '1';
  }
}

async function testLdap() {
  const resultEl = document.getElementById('cfg-ldap-test-result');
  resultEl.style.display = 'none';
  // Send the in-form values so user can test before saving
  const body = {
    ldap_url:            document.getElementById('cfg-ldap-url').value.trim(),
    ldap_bind_dn:        document.getElementById('cfg-ldap-bind-dn').value.trim(),
    ldap_user_base:      document.getElementById('cfg-ldap-user-base').value.trim(),
    ldap_user_filter:    document.getElementById('cfg-ldap-user-filter').value.trim() || '(uid={u})',
    ldap_tls_verify:     document.getElementById('cfg-ldap-tls-verify').checked,
    ldap_timeout:        parseInt(document.getElementById('cfg-ldap-timeout').value) || 5,
  };
  const ldapPw = document.getElementById('cfg-ldap-bind-password').value;
  if (ldapPw) body.ldap_bind_password = ldapPw;
  const data = await api('POST', '/ldap/test', body);
  if (!data) return;
  resultEl.style.display = 'block';
  if (data.ok) {
    resultEl.style.background = 'rgba(34,197,94,0.1)';
    resultEl.style.color = 'var(--green)';
    resultEl.textContent = `✓ ${data.detail || 'OK'}`;
  } else {
    resultEl.style.background = 'rgba(239,68,68,0.1)';
    resultEl.style.color = 'var(--red)';
    resultEl.textContent = `✕ ${data.detail || 'failed'}`;
  }
}

function openLdapTestUserModal() {
  document.getElementById('ldap-test-user-name').value = '';
  document.getElementById('ldap-test-user-pw').value = '';
  document.getElementById('ldap-test-user-result').style.display = 'none';
  openModal('ldap-test-user-modal');
}

async function runLdapTestUser() {
  const username = document.getElementById('ldap-test-user-name').value.trim();
  const password = document.getElementById('ldap-test-user-pw').value;
  const resultEl = document.getElementById('ldap-test-user-result');
  if (!username || !password) { toast('Username and password required', 'error'); return; }
  resultEl.style.display = 'block';
  resultEl.style.background = 'rgba(100,116,139,0.1)';
  resultEl.style.color = 'var(--muted)';
  resultEl.textContent = 'Testing...';
  const data = await api('POST', '/ldap/test-user', {username, password});
  if (!data) return;
  if (data.ok) {
    resultEl.style.background = 'rgba(34,197,94,0.1)';
    resultEl.style.color = 'var(--green)';
    resultEl.innerHTML = `✓ Authenticated successfully<br>` +
      `<span class="isl-341">DN: ${escHtml(data.dn)}<br>` +
      `Role: ${escHtml(data.role)}<br>` +
      (data.full_name ? `Name: ${escHtml(data.full_name)}<br>` : '') +
      (data.email ? `Email: ${escHtml(data.email)}` : '') +
      `</span>`;
  } else {
    resultEl.style.background = 'rgba(239,68,68,0.1)';
    resultEl.style.color = 'var(--red)';
    resultEl.textContent = `✕ ${data.error || 'unknown error'}`;
  }
}
async function testWebhook() { const btn = document.getElementById('btn-webhook-test'); btn.disabled = true; btn.style.opacity = '0.5'; try { const data = await api('POST', '/webhook/test'); if (!data) { toast('Request failed', 'error'); return; } if (data.error) { toast(data.error, 'error'); return; } const r = data.result; if (r && (r.status === '200' || String(r.status).startsWith('2') || r.status === 200)) toast('Test webhook sent successfully!', 'success'); else if (r) toast(`Webhook failed: ${r.detail || r.status}`, 'error'); else toast('Test sent — check the log below', 'info'); loadWebhookLog(); } finally { btn.disabled = false; btn.style.opacity = '1'; } }
async function loadWebhookLog() {
  const tbody = document.getElementById('webhook-log-tbody');
  const data = await api('GET', '/webhook/log');
  if (!data) return;
  let entries = Array.isArray(data) ? data : [];
  if (!entries.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty-state-sm">No webhook deliveries yet. </td></tr>'; return; }
  // v3.2.1: sortable. Default = chronological (ts desc).
  tableCtl.wireSortOnly('webhook-log-thead', 'webhook_log', loadWebhookLog);
  entries = tableCtl.sortRows('webhook_log', entries, (e) => ({
    ts:     e.ts || 0,
    event:  e.event || '',
    status: String(e.status || ''),
    detail: e.detail || '',
  }));
  tbody.innerHTML = entries.slice(0, 50).map(e => {
    const isOk = String(e.status).startsWith('2') || e.status === 200;
    return `<tr><td class="hint-nowrap">${new Date(e.ts * 1000).toLocaleString()}</td><td><span class="cmd-badge isl-342">${escHtml(e.event)}</span></td><td class="isl-343 ${isOk?'c-green':'c-red'}">${escHtml(e.status)}</td><td title="${escHtml(e.detail)}" class="isl-344">${escHtml(e.detail)}</td><td class="nowrap"><button class="btn-icon isl-238" data-action-btn="_aiExplainAlertWh" data-arg="${escAttr(e.event)}" data-arg2="" data-arg3="${escAttr(e.detail||'')}">${_icon('sparkles',14)} Explain</button></td></tr>`;
  }).join('');
}
// v2.1.0: refresh cycle pauses while a modal is open or the tab is in
// the background. The "auto-refresh closes browser window" bug had two
// independent triggers in 2.0.0:
//
//   1. escHtml didn't escape ' — see escAttr() above. A device name like
//      `O'Brien` injected literal apostrophes into data-action="fn" data-arg="${name}" 
//      attributes. When the periodic loadDevices() re-rendered the device
//      grid (innerHTML = ...), the parser hit `fn('O'Brien')`, threw a
//      SyntaxError on parse, and (depending on the surrounding content)
//      could call other inline handlers — including, in the worst case,
//      window.close-like APIs. Even where it didn't close the tab, every
//      60s refresh ran broken JS and the page became unresponsive.
//
//   2. setInterval fires regardless of visibility / modal state. Browsers
//      throttle setInterval in background tabs (Chrome: 1 Hz minimum) but
//      don't stop it; on the foreground it fired loadDevices() right under
//      an open modal, wiping device-grid event listeners that the modal's
//      internal onclick handlers had captured by reference. With #1's
//      broken JS already in play, this was the second-shoe-drops trigger.
//
// Fix: (a) escAttr above closes the injection vector for good; (b) this
// rewrite of startRefreshCycle skips the loadDevices() tick whenever a
// .modal-overlay.active is present or the tab is hidden. The countdown
// label still updates so the user sees state, and the refresh resumes
// exactly where it paused as soon as the modal closes / tab returns.
function _refreshShouldPause() {
  if (typeof document !== 'undefined' && document.hidden) return true;
  // Modal open: don't redraw under the user's hand
  if (document.querySelector('.modal-overlay.active')) return true;
  // v2.1.0 follow-up: a device-card dropdown lives *inside* the device grid
  // that loadDevices() rewrites via innerHTML. Re-rendering while a dropdown
  // is open closes the dropdown — the user clicks the ⋯ button, opens the
  // menu, the 60s tick fires before they pick an item, and the menu vanishes
  // mid-click. Pause for these the same way we do for modals.
  if (document.querySelector('.device-dropdown.active')) return true;
  return false;
}
function startRefreshCycle() {
  clearInterval(refreshTimer);
  refreshRemaining = refreshInterval;
  refreshTimer = setInterval(() => {
    const label = document.getElementById('last-refresh-label');
    const bar = document.getElementById('refresh-progress');
    if (_refreshShouldPause()) {
      // Hold the countdown — don't advance, don't fire loadDevices(). This
      // also avoids races where loadDevices() re-renders the device grid
      // while the user is interacting with a modal that references it.
      if (label) label.textContent = 'Refresh paused';
      return;
    }
    refreshRemaining--;
    const pct = (refreshRemaining / refreshInterval) * 100;
    if (bar) bar.style.width = pct + '%';
    if (refreshRemaining <= 0) {
      refreshRemaining = refreshInterval;
      loadDevices();
    }
    const m = Math.floor(refreshRemaining / 60);
    const s = refreshRemaining % 60;
    if (label) label.textContent = `Refresh in ${m > 0 ? m + 'm ' : ''}${s}s`;
  }, 1000);
}
// v2.2.6: opening a modal also closes the mobile nav drawer (two
// slide-in surfaces fighting was the "windows over each other" bug on
// mobile) and locks body scroll so the page behind doesn't scroll
// under the modal. closeModal releases the lock only when no other
// modal is still open (nested modals — e.g. drift diff over drift
// detail — must keep the lock until the last one closes).
function openModal(id) {
  const el = document.getElementById(id);
  if (!el) return;
  document.body.classList.remove('mobile-nav-open');
  el.classList.add('active');
  document.body.classList.add('modal-open');
}
function closeModal(id) {
  const el = document.getElementById(id);
  if (el) el.classList.remove('active');
  // Only release the scroll lock if no modal-overlay is still active
  const anyOpen = document.querySelector('.modal-overlay.active');
  if (!anyOpen) document.body.classList.remove('modal-open');
}
document.querySelectorAll('.modal-overlay').forEach(el => { el.addEventListener('click', e => { if (e.target === el) closeModal(el.id); }); });
// v2.1.0: escHtml escapes for HTML content + double-quoted attribute values.
// It deliberately does NOT escape ' — HTML entity decoding turns &#39; back
// into ' before the JS-in-attribute parser sees it, which would break any
// `onclick="foo('${escAttr(x)}')"` site. Use escAttr() for values that are
// interpolated into JS string literals inside an HTML attribute.
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
// v2.1.0: escape for use inside a JS string that's embedded in an HTML
// attribute, e.g. onclick="foo('${escAttr(x)}')". The output is pure ASCII
// (no HTML metacharacters) so the HTML parser passes it through verbatim,
// and the JS hex escapes (\xNN) decode to the original chars when the
// attribute fires. This is the bug behind "auto-refresh closes the
// browser window": a device name containing an apostrophe broke out of
// the inline JS string in the dropdown rebuild and could call window.close()
// (or any other API) on re-render, depending on what followed the quote.
// v1.x's escHtml passed ' through unchanged, so anyone whose hostname had
// `O'Brien` or whose group ended with a tick caused the failure on every
// 60s refresh.
function escAttr(s) { return String(s).replace(/[&<>"'`\\\n\r\u2028\u2029]/g, c => '\\x' + c.charCodeAt(0).toString(16).padStart(2,'0')); }
function timeAgo(ts) { const diff = Math.floor(Date.now() / 1000 - parseInt(ts)); if (diff < 60) return diff + 's ago'; if (diff < 3600) return Math.floor(diff / 60) + 'm ago'; if (diff < 86400) return Math.floor(diff / 3600) + 'h ago'; return Math.floor(diff / 86400) + 'd ago'; }
let toastId = 0;
function toast(msg, type = 'info') { const id = 'toast-' + (++toastId); const icons = {success: '✓', error: '✕', info: 'ℹ'}; const el = document.createElement('div'); el.className = `toast ${type}`; el.id = id; el.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ'}</span><span>${escHtml(msg)}</span>`; document.getElementById('toast-container').appendChild(el); requestAnimationFrame(() => el.classList.add('show')); setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 400); }, 3500); }
function setTagFilter(tag) { activeTagFilter = tag; renderDevices(); }
// v1.11.5: schedule and history get filter+sort via tableCtl. Minimal
// refactor — register once on first load, then push rows in.
let _scheduleRegistered = false;
function _registerScheduleTable() {
  if (_scheduleRegistered) return;
  _scheduleRegistered = true;
  tableCtl.register({
    name: 'schedule',
    tbody: 'schedule-tbody',
    filterInput: 'schedule-filter',
    sortHeaders: 'schedule-thead',
    colspan: 5,
    columns: ['device_name', 'command', 'run_at', 'actor'],
    getColumns: (j) => ({
      device_name: j.device_name || '',
      command:     j.command || '',
      run_at:      j.run_at || 0,
      actor:       j.actor || '',
    }),
    row: (j) => {
      const isScript = j.command.startsWith('script:');
      const cmdCls   = isScript ? 'script' : j.command;
      const cmdLabel = isScript ? 'run script' : j.command;
      const jKey = _storeEvtData(j);
      return `<tr><td class="fw-500">${escHtml(j.device_name)}</td><td><span class="cmd-badge ${escHtml(cmdCls)}">${escHtml(cmdLabel)}</span></td><td class="mono-12">${j.recurring ? `<span class="c-accent">${escHtml(j.cron)}</span>` : new Date(j.run_at*1000).toLocaleString()}</td><td class="hint">${escHtml(j.actor)}</td><td><button class="btn-icon" title="Edit" data-action-btn="_editScheduleBtn" data-store-key="${jKey}">${_icon('edit',14)}</button> <button class="btn-icon c-danger-outline" title="Delete" data-action="deleteJob" data-arg="${escAttr(j.id)}" >${_icon('trash',14)}</button></td></tr>`;
    },
    emptyMsg: 'No scheduled jobs.',
    emptyMsgFiltered: 'No jobs match the filter.',
  });
}
async function loadSchedule() {
  _registerScheduleTable();
  const data = await api('GET', '/schedule');
  tableCtl.render('schedule', data || []);
}

let _historyRegistered = false;
function _registerHistoryTable() {
  if (_historyRegistered) return;
  _historyRegistered = true;
  tableCtl.register({
    name: 'history',
    tbody: 'history-tbody',
    filterInput: 'history-filter',
    sortHeaders: 'history-thead',
    colspan: 4,
    columns: ['ts', 'actor', 'device_name', 'command'],
    getColumns: (e) => ({
      ts:          e.ts || 0,
      actor:       e.actor || '',
      device_name: e.device_name || '',
      command:     e.command || '',
    }),
    row: (e) => `<tr><td class="isl-345">${new Date(e.ts*1000).toLocaleString()}</td><td class="fw-500">${escHtml(e.actor)}</td><td class="mono-12">${escHtml(e.device_name)}</td><td><span class="cmd-badge ${escHtml(e.command)}">${escHtml(e.command)}</span></td></tr>`,
    emptyMsg: 'No commands logged yet.',
    emptyMsgFiltered: 'No commands match the filter.',
  });
}
async function loadHistory() {
  _registerHistoryTable();
  const tbody = document.getElementById('history-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="empty-state-sm">Loading…</tbody>';
  const data = await api('GET', '/history');
  tableCtl.render('history', data || []);
}
function _schedNextDate(type, runAt) {
  if (runAt) return new Date(runAt * 1000);
  const now = new Date();
  if (type === 'hourly') {
    const d = new Date(now); d.setMinutes(0, 0, 0); d.setHours(d.getHours() + 1); return d;
  }
  if (type === 'nhours') {
    const n = Math.max(1, parseInt(document.getElementById('sched-nhours').value) || 4);
    const d = new Date(now); const nextH = Math.ceil((d.getHours() + 1) / n) * n;
    d.setHours(nextH, 0, 0, 0); return d;
  }
  const timeId = type === 'daily' ? 'sched-daily-time' : type === 'weekly' ? 'sched-weekly-time' : 'sched-monthly-time';
  const [hh, mm] = (document.getElementById(timeId)?.value || '03:00').split(':');
  const H = parseInt(hh) || 3, M = parseInt(mm) || 0;
  if (type === 'daily') {
    const d = new Date(now); d.setHours(H, M, 0, 0); if (d <= now) d.setDate(d.getDate() + 1); return d;
  }
  if (type === 'weekly') {
    const target = parseInt(document.getElementById('sched-weekly-day').value); // 0=Sun…6=Sat, same as JS getDay()
    const d = new Date(now); d.setHours(H, M, 0, 0);
    let ahead = target - d.getDay(); if (ahead < 0 || (ahead === 0 && d <= now)) ahead += 7;
    d.setDate(d.getDate() + ahead); return d;
  }
  if (type === 'monthly') {
    const dom = Math.max(1, Math.min(28, parseInt(document.getElementById('sched-monthly-day').value) || 1));
    const d = new Date(now); d.setDate(dom); d.setHours(H, M, 0, 0);
    if (d <= now) d.setMonth(d.getMonth() + 1); return d;
  }
  const d = new Date(now); d.setDate(d.getDate() + 1); return d;
}
function _buildSchedCron() {
  const type = document.getElementById('sched-recur-type').value;
  if (type === 'once')   return null;
  if (type === 'hourly') return '0 * * * *';
  if (type === 'nhours') {
    const n = Math.max(1, Math.min(23, parseInt(document.getElementById('sched-nhours').value) || 4));
    return `0 */${n} * * *`;
  }
  const timeId = type === 'daily' ? 'sched-daily-time' : type === 'weekly' ? 'sched-weekly-time' : 'sched-monthly-time';
  const [hh, mm] = (document.getElementById(timeId)?.value || '03:00').split(':');
  const H = parseInt(hh) || 3, M = parseInt(mm) || 0;
  if (type === 'daily')   return `${M} ${H} * * *`;
  if (type === 'weekly')  return `${M} ${H} * * ${document.getElementById('sched-weekly-day').value}`;
  if (type === 'monthly') { const dom = Math.max(1, Math.min(28, parseInt(document.getElementById('sched-monthly-day').value) || 1)); return `${M} ${H} ${dom} * *`; }
  if (type === 'custom')  return document.getElementById('sched-cron').value.trim() || null;
  return null;
}
async function _schedLoadScripts() {
  const sel = document.getElementById('sched-script-id');
  if (!sel || sel.dataset.loaded) return;
  sel.dataset.loaded = '1';
  const data = await api('GET', '/scripts');
  if (!data || !data.length) { sel.innerHTML = '<option value="">No scripts available</option>'; return; }
  sel.innerHTML = data.map(s => `<option value="${escAttr(s.id)}">${escHtml(s.name)}</option>`).join('');
}
function onSchedCommandChange() {
  const cmd = document.getElementById('sched-command').value;
  document.getElementById('sched-script-row').classList.toggle('d-none', cmd !== 'script');
  document.getElementById('sched-upgrade-note').classList.toggle('d-none', !cmd.startsWith('upgrade'));
  if (cmd === 'script') _schedLoadScripts();
  // Auto-suggest maintenance window and calendar entry for disruptive commands
  const disruptive = cmd === 'reboot' || cmd.startsWith('upgrade');
  const maintCb = document.getElementById('sched-maint-cb');
  if (maintCb) maintCb.checked = disruptive;
  const calCb = document.getElementById('sched-cal-cb');
  if (calCb) calCb.checked = disruptive;
}
function onSchedTypeChange() {
  const type = document.getElementById('sched-recur-type').value;
  ['once','nhours','daily','weekly','monthly','custom'].forEach(t =>
    document.getElementById(`sched-${t}-row`)?.classList.toggle('d-none', t !== type));
}
async function addScheduleJob() {
  const dev_id = document.getElementById('sched-device').value;
  let command = document.getElementById('sched-command').value;
  if (command === 'script') {
    const sid = document.getElementById('sched-script-id').value;
    if (!sid) { toast('Select a script', 'error'); return; }
    command = `script:${sid}`;
  }
  const cron = _buildSchedCron();
  const payload = {device_id: dev_id, command};
  if (cron) {
    payload.cron = cron;
  } else {
    const dt = document.getElementById('sched-datetime').value;
    if (!dt) { toast('Select a date and time', 'error'); return; }
    payload.run_at = Math.floor(new Date(dt).getTime() / 1000);
  }
  const wasEdit = !!_scheduleEditId;
  const data = wasEdit
    ? await api('PUT',  '/schedule/' + _scheduleEditId, payload)
    : await api('POST', '/schedule', payload);
  const label = command.startsWith('script:') ? 'Script' : command;
  if (data?.ok && wasEdit) {
    toast(cron ? `Recurring "${label}" updated (${cron})` : `"${label}" updated`, 'success');
    _scheduleEditId = null;
    closeModal('schedule-add-modal');
    loadSchedule();
    return;
  }
  if (data?.ok) {
    if (document.getElementById('sched-maint-cb')?.checked) {
      const maintBody = {scope: 'device', target: dev_id, reason: `Scheduled: ${label}`, events: []};
      if (cron) { maintBody.cron = cron; maintBody.duration = 3600; }
      else { maintBody.start = new Date(payload.run_at * 1000).toISOString(); maintBody.end = new Date((payload.run_at + 3600) * 1000).toISOString(); }
      await api('POST', '/maintenance', maintBody).catch(() => {});
    }
    if (document.getElementById('sched-cal-cb')?.checked) {
      const type = document.getElementById('sched-recur-type').value;
      const devName = devices.find(d => d.id === dev_id)?.name || dev_id;
      const calStart = _schedNextDate(type, payload.run_at);
      const calEnd   = new Date(calStart.getTime() + 3600000);
      const isDisruptive = command === 'reboot' || command.startsWith('upgrade');
      // Map schedule recurrence type to calendar recur field
      const recurMap = {once:'none', hourly:'daily', nhours:'daily', daily:'daily', weekly:'weekly', monthly:'monthly', custom:'none'};
      const calRecur = recurMap[type] || 'none';
      const calBody = {
        title:       `Scheduled: ${label} — ${devName}`,
        description: cron ? `Cron: ${cron}` : '',
        start:       calStart.toISOString(),
        end:         calEnd.toISOString(),
        all_day:     false,
        color:       isDisruptive ? 'amber' : 'blue',
        recur:       calRecur,
      };
      await api('POST', '/calendar', calBody).catch(() => {});
    }
    toast(cron ? `Recurring "${label}" scheduled (${cron})` : `"${label}" scheduled`, 'success');
    closeModal('schedule-add-modal'); loadSchedule();
  } else toast(data?.error || 'Failed', 'error');
}
async function deleteJob(id) { const data = await api('DELETE', '/schedule/' + id); if (data?.ok) { toast('Job cancelled', 'info'); loadSchedule(); } else toast(data?.error || 'Failed', 'error'); }
function openExecModal(id, name) { document.getElementById('exec-device-id').value = id; document.getElementById('exec-cmd').value = ''; document.querySelector('#exec-modal .modal-title').textContent = `Run command on ${name}`; api('GET', '/cmd-library').then(data => { const sel = document.getElementById('exec-library-pick'); sel.innerHTML = '<option value="">— Command library —</option>'; (data || []).forEach(s => { const opt = document.createElement('option'); opt.value = s.cmd; opt.textContent = s.name; sel.appendChild(opt); }); }).catch(() => {}); openModal('exec-modal'); }
function pickFromLibrary() { const val = document.getElementById('exec-library-pick').value; if (val) document.getElementById('exec-cmd').value = val; }
// v3.3.0: schedule modal carries an editing id for in-place updates.
let _scheduleEditId = null;
function openScheduleAdd() {
  _scheduleEditId = null;
  const titleEl = document.querySelector('#schedule-add-modal .modal-title');
  if (titleEl) titleEl.textContent = 'Schedule a job';
  const sel = document.getElementById('sched-device');
  sel.innerHTML = devices.map(d => `<option value="${escHtml(d.id)}">${escHtml(d.name)}${d.online ? '' : ' (offline)'}</option>`).join('');
  document.getElementById('sched-command').value = 'shutdown';
  document.getElementById('sched-script-row').classList.add('d-none');
  document.getElementById('sched-upgrade-note').classList.add('d-none');
  const maintCb = document.getElementById('sched-maint-cb');
  if (maintCb) maintCb.checked = false;
  const calCb = document.getElementById('sched-cal-cb');
  if (calCb) calCb.checked = false;
  const scriptSel = document.getElementById('sched-script-id');
  scriptSel.innerHTML = '<option value="">Loading…</option>';
  delete scriptSel.dataset.loaded;
  document.getElementById('sched-recur-type').value = 'once';
  onSchedTypeChange();
  const dt = new Date(Date.now() + 3600000);
  const local = new Date(dt - dt.getTimezoneOffset()*60000).toISOString().slice(0,16);
  document.getElementById('sched-datetime').value = local;
  document.getElementById('sched-cron').value = '';
  openModal('schedule-add-modal');
}

async function _editScheduleBtn(btn) {
  const j = _evtData.get(btn.dataset.storeKey);
  if (!j) return;
  _scheduleEditId = j.id;
  const titleEl = document.querySelector('#schedule-add-modal .modal-title');
  if (titleEl) titleEl.textContent = 'Edit scheduled job';
  const sel = document.getElementById('sched-device');
  sel.innerHTML = devices.map(d => `<option value="${escHtml(d.id)}">${escHtml(d.name)}${d.online ? '' : ' (offline)'}</option>`).join('');
  sel.value = j.device_id || '';
  // Detect script vs static command
  const isScript = (j.command || '').startsWith('script:');
  document.getElementById('sched-command').value = isScript ? 'script' : j.command;
  document.getElementById('sched-script-row').classList.toggle('d-none', !isScript);
  const scriptSel = document.getElementById('sched-script-id');
  scriptSel.innerHTML = '<option value="">Loading…</option>';
  delete scriptSel.dataset.loaded;
  // Mark the modal so onSchedCommandChange (if present) can read this
  scriptSel.dataset.preselect = isScript ? (j.command.slice(7)) : '';
  document.getElementById('sched-upgrade-note').classList.toggle('d-none', !(j.command || '').startsWith('upgrade'));
  // One-shot vs cron
  const recurType = j.recurring ? (j.cron ? 'custom' : 'daily') : 'once';
  document.getElementById('sched-recur-type').value = recurType;
  onSchedTypeChange();
  if (j.cron) {
    document.getElementById('sched-cron').value = j.cron || '';
  } else if (j.run_at) {
    const dt = new Date(j.run_at * 1000);
    const local = new Date(dt - dt.getTimezoneOffset()*60000).toISOString().slice(0,16);
    document.getElementById('sched-datetime').value = local;
  }
  // The maintenance + calendar tickboxes are post-create side-effects
  // that don't apply on edit — uncheck them so a re-save doesn't try
  // to create duplicates.
  const maintCb = document.getElementById('sched-maint-cb');
  if (maintCb) maintCb.checked = false;
  const calCb = document.getElementById('sched-cal-cb');
  if (calCb) calCb.checked = false;
  openModal('schedule-add-modal');
}
async function sendExecCmd() { const id = document.getElementById('exec-device-id').value; const cmd = document.getElementById('exec-cmd').value.trim(); if (!cmd) { toast('Enter a command', 'error'); return; } const data = await api('POST', '/exec', {device_id: id, cmd}); if (data?.ok) { toast('Command queued — output on next heartbeat (~60s)', 'success'); closeModal('exec-modal'); } else toast(data?.error || 'Failed', 'error'); }
// ─── "Did you know?" tips (About page) ───────────────────────────────────
const _DYK_TIPS = [
  "The CMDB has a built-in credential vault — store per-device SSH logins and secrets right next to your documentation.",
  "You can open an SSH session to any device straight from its row using the quick-connect button.",
  "Stuck on an alert? Ask the built-in AI assistant for remediation suggestions tailored to the affected device.",
  "RemotePower can take a Proxmox snapshot automatically before deploying changes, giving you an instant rollback point.",
  "You can write custom scripts to monitor almost anything — niche services, sensors, or your own health checks.",
  "Issue and renew TLS certificates directly from the dashboard through the built-in ACME (acme.sh) integration.",
  "Set up a staggered, rolling patch schedule so your fleet updates in waves instead of all at once.",
  "On the planning board you can drag scheduled tasks around like sticky notes.",
  "A full REST API with named, non-expiring keys lets you wire RemotePower into the rest of your tooling.",
  "Connect RemotePower to Claude over MCP to ask questions about your fleet and run commands in plain language.",
  "Notifications can be routed per event and per channel, so the right people hear about the right things.",
  "The IaC generator can export your fleet's configuration as Infrastructure-as-Code for version control and reuse.",
  "There's a built-in web terminal — a full SSH session in your browser, with no client to install.",
  "Poll your network gear over SNMP to track switches, routers, UPSes, and printers alongside your servers.",
  "RemotePower hashes watched config files and alerts you the moment one drifts from its baseline.",
  "Tail any unit or log file and get alerted when a pattern like 'error' or 'FATAL' appears.",
  "Define maintenance windows to suppress alerts during planned work, so a reboot doesn't page everyone.",
  "Every table is sortable and filterable — click a column header to reorder, or type to filter in place.",
  "Agents verify their own updates by hash, not just version number, so a tampered or partial download is refused.",
  "Protect your account with TOTP two-factor authentication from the Security settings.",
  "RemotePower supports LDAP and Active Directory login, so your team can use the credentials they already have.",
  "Repeated failed logins trigger automatic brute-force lockout, tracked per IP and per account.",
  "Schedule automatic configuration backups, or export a full backup archive whenever you like.",
  "Select several devices at once and run a single action across all of them with bulk operations.",
  "Group your devices and target an entire group with one command, schedule, or maintenance window.",
  "Manage Docker and Podman containers — start, stop, and restart — straight from the Containers page.",
  "Keep a per-device runbook so whoever's on call knows exactly what to do.",
  "Save your most-used commands to the Command Library and reuse them in a single click.",
  "Export patch reports as CSV or XML for compliance and record-keeping.",
  "Track CPU, memory, disk, swap, and load metrics for every agent.",
  "RemotePower watches itself — disk, webhooks, audit log, and backups — on the Server status page.",
  "Every privileged action is recorded in the audit log, so you always know who did what.",
  "Send notifications to Slack, Discord, email, or any generic webhook.",
  "Trigger actions from your own automation using inbound webhooks.",
  "See exactly what's listening on each device with the open-ports inventory.",
  "Hand scripts read-only access with viewer-role API keys, or full control with admin keys.",
  "Tighten the poll interval on a critical host so it checks in more often than the rest of the fleet.",
  "A fleet-events timeline records every device coming online, going offline, and firing an alert.",
  "There's a keyboard-shortcut cheat sheet to help you fly through the dashboard without a mouse.",
  "Pin quick links to the tools you live in — Grafana, Proxmox, your wiki — so they're one click from the dashboard.",
];
let _dykIdx = -1;
function _renderAboutTip() {
  const el = document.getElementById('about-tip-text');
  if (!el) return;
  let i;
  do { i = Math.floor(Math.random() * _DYK_TIPS.length); } while (_DYK_TIPS.length > 1 && i === _dykIdx);
  _dykIdx = i;
  el.textContent = _DYK_TIPS[i];
}
function nextAboutTip() { _renderAboutTip(); }

async function loadAbout() { _renderAboutTip(); try { const v = await api('GET', '/version'); if (v) { document.getElementById('about-server-version').textContent = v.current || '—'; const latestEl = document.getElementById('about-latest-version'); if (v.latest) { latestEl.textContent = v.latest; if (v.update_available) { latestEl.style.color = 'var(--amber)'; latestEl.textContent += ' · update available'; } else { latestEl.style.color = 'var(--green)'; latestEl.textContent += ' ✓ up to date'; } } } } catch(e) {} try { const av = await api('GET', '/agent/version'); if (av && av.version) document.getElementById('about-agent-version').textContent = av.version; } catch(e) {} }
function openTagModal(id, currentTags) { document.getElementById('tag-device-id').value = id; document.getElementById('tag-input').value = currentTags; openModal('tag-modal'); }
async function saveTags() { const id = document.getElementById('tag-device-id').value; const raw = document.getElementById('tag-input').value; const tags = raw.split(',').map(t => t.trim()).filter(t => t.length > 0); const r = await fetch('/api/devices/' + id + '/tags', { method: 'PATCH', headers: {'Content-Type': 'application/json', 'X-Token': getToken()}, body: JSON.stringify({tags}) }); if (r.status === 401) { doLogout(); return; } const data = await r.json(); if (data?.ok) { toast(`Tags saved: ${tags.length ? tags.join(', ') : 'none'}`, 'success'); closeModal('tag-modal'); loadDevices(); } else toast(data?.error || 'Failed', 'error'); }
async function sendUpdate(id, name) { if (!confirm(`Push agent self-update to "${name}"?\nThe agent will update and restart within 60 seconds.`)) return; const data = await api('POST', '/update-device', {device_id: id}); if (data?.ok) toast(`Update queued for ${name}`, 'success'); else toast(data?.error || 'Failed', 'error'); }

// v3.3.0: operator-triggered agent removal. Server queues an 'uninstall'
// command; on next heartbeat (~60s) the agent stops + disables the
// systemd unit, deletes credentials + state, removes the binary, then
// exits. The device record stays in the dashboard so history, tags,
// groups, etc. survive — re-enrollment with the same device_id is
// supported if the operator re-installs the agent later.
async function uninstallAgent(id, name) {
  const msg = `Uninstall the RemotePower agent on "${name}"?\n\n` +
              `This will:\n` +
              `  • stop and disable the systemd service\n` +
              `  • delete /etc/remotepower/credentials and state files\n` +
              `  • remove /usr/local/bin/remotepower-agent\n\n` +
              `The device record stays here so you can re-enroll later.\n` +
              `Continue?`;
  if (!confirm(msg)) return;
  const r = await api('POST', `/devices/${id}/uninstall-agent`, {});
  if (r && r.ok) {
    toast(`Uninstall queued for ${name} — completes on next heartbeat`, 'success');
    setTimeout(loadDevices, 3000);
  } else {
    toast(r?.error || 'Failed to queue uninstall', 'error');
  }
}
// v1.11.7: per-device upgrade packages from the dropdown menu. Mirrors
// the existing batch-upgrade flow but for one device at a time. Used to
// require selecting the device first, then clicking the toolbar batch
// button — now available directly from the ⋯ menu on each row.
async function upgradePackages(id, name) {
  if (!confirm(`Upgrade packages on "${name}"?\nThis will run apt / dnf / pacman upgrade on the device. Output arrives on the next heartbeat after the run completes (typically 30–120s for apt upgrade, longer for big upgrade sets). View progress under "Update history".`)) return;
  const data = await api('POST', '/upgrade-device', {device_ids: [id]});
  if (data?.ok) toast(`Package upgrade queued for ${name}. Output will appear in Update history shortly.`, 'success');
  else toast(data?.error || 'Failed', 'error');
}

// ─── v1.12.0: per-device metric thresholds editor ───────────────────────────
//
// Modal accessible from the device dropdown. Loads current overrides + defaults
// from GET /api/devices/{id}/metric-thresholds, lets the user adjust values
// (including per-mount disk overrides), saves via PATCH. The reset button
// DELETEs the overrides so the device falls back to fleet-wide defaults.

let _currentMetricThresholdsDevice = null;

async function openMetricThresholds(id, name) {
  _currentMetricThresholdsDevice = id;
  document.getElementById('metric-thresholds-device-id').value = id;
  document.querySelector('#metric-thresholds-modal .modal-title').textContent =
    `Metric thresholds — ${name}`;
  document.getElementById('metric-thresholds-error').style.display = 'none';

  // Clear the form before loading — avoids flashing stale values
  ['mem-warn','mem-crit','swap-warn','swap-crit','disk-warn','disk-crit','cpu-warn','cpu-crit',
   'snmp-cpu-warn','snmp-cpu-crit','temp-warn','temp-crit']
    .forEach(k => {
      const el = document.getElementById('thr-' + k);
      if (el) el.value = '';
    });
  document.getElementById('thr-mounts-list').innerHTML = '';

  openModal('metric-thresholds-modal');

  const data = await api('GET', `/devices/${id}/metric-thresholds`);
  if (!data) return;

  // The form shows EFFECTIVE values (overrides ?? defaults). The placeholder
  // shows the default; we leave the field blank if there's no override so
  // the user can see at a glance what's customised vs. inherited.
  const o = data.overrides || {};
  const d = data.defaults  || {};

  const fillField = (fieldId, key) => {
    const el = document.getElementById(fieldId);
    el.placeholder = String(d[key]);
    el.value = (key in o) ? String(o[key]) : '';
  };
  fillField('thr-mem-warn',  'mem_warn_percent');
  fillField('thr-mem-crit',  'mem_crit_percent');
  fillField('thr-swap-warn', 'swap_warn_percent');
  fillField('thr-swap-crit', 'swap_crit_percent');
  fillField('thr-disk-warn', 'disk_warn_percent');
  fillField('thr-disk-crit', 'disk_crit_percent');
  fillField('thr-cpu-warn',  'cpu_warn_load_ratio');
  fillField('thr-cpu-crit',  'cpu_crit_load_ratio');
  // v3.2.0 follow-up: SNMP-derived thresholds
  fillField('thr-snmp-cpu-warn', 'snmp_cpu_warn_percent');
  fillField('thr-snmp-cpu-crit', 'snmp_cpu_crit_percent');
  fillField('thr-temp-warn',     'temp_warn_celsius');
  fillField('thr-temp-crit',     'temp_crit_celsius');

  // Per-mount overrides
  const perMount = (o.disk_per_mount || {});
  for (const [path, vals] of Object.entries(perMount)) {
    addMountThresholdRow(path, vals.warn, vals.crit);
  }

  // Show the device's current sysinfo metrics so the user knows what
  // thresholds make sense. (Pulled from the cached devices array — no
  // extra API call.)
  const dev = (typeof devices !== 'undefined' ? devices : []).find(x => x.id === id);
  const si = dev?.sysinfo || {};
  const lines = [];
  if (si.mem_percent !== undefined)    lines.push(`current mem: ${si.mem_percent}%`);
  if (si.swap_percent !== undefined)   lines.push(`swap: ${si.swap_percent}%`);
  if (si.loadavg_1m !== undefined && si.cpu_count) {
    lines.push(`load: ${si.loadavg_1m} on ${si.cpu_count} cpu (ratio ${(si.loadavg_1m / si.cpu_count).toFixed(2)})`);
  }
  if (Array.isArray(si.mounts)) {
    for (const m of si.mounts.slice(0, 6)) {
      lines.push(`disk ${m.path}: ${m.percent}%`);
    }
  }
  document.getElementById('metric-thresholds-current').textContent =
    lines.length ? lines.join('  •  ') : 'No metrics yet — agent hasn\'t reported sysinfo.';
}

function addMountThresholdRow(path = '', warn = '', crit = '') {
  const container = document.getElementById('thr-mounts-list');
  const row = document.createElement('div');
  row.className = 'mount-row';
  row.style.cssText = 'display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:6px;align-items:center';
  row.innerHTML = `
    <input type="text" class="form-input mount-path mono-12" placeholder="/var" value="${escHtml(path)}">
    <input type="number" class="form-input mount-warn" placeholder="warn %" min="1" max="99" value="${warn === '' ? '' : warn}">
    <input type="number" class="form-input mount-crit" placeholder="crit %" min="1" max="99" value="${crit === '' ? '' : crit}">
    <button class="btn-icon isl-346" type="button" data-remove-parent="1">×</button>
  `;
  container.appendChild(row);
}

async function saveMetricThresholds() {
  const id = _currentMetricThresholdsDevice;
  if (!id) return;
  const errEl = document.getElementById('metric-thresholds-error');
  errEl.style.display = 'none';

  const payload = {};

  const readPair = (warnId, critId, warnKey, critKey) => {
    const w = document.getElementById(warnId).value.trim();
    const c = document.getElementById(critId).value.trim();
    if (w !== '') payload[warnKey] = parseFloat(w);
    if (c !== '') payload[critKey] = parseFloat(c);
  };
  readPair('thr-mem-warn',  'thr-mem-crit',  'mem_warn_percent',   'mem_crit_percent');
  readPair('thr-swap-warn', 'thr-swap-crit', 'swap_warn_percent',  'swap_crit_percent');
  readPair('thr-disk-warn', 'thr-disk-crit', 'disk_warn_percent',  'disk_crit_percent');
  readPair('thr-cpu-warn',  'thr-cpu-crit',  'cpu_warn_load_ratio', 'cpu_crit_load_ratio');
  // v3.2.0 follow-up: SNMP-derived thresholds (CPU% and temperature)
  readPair('thr-snmp-cpu-warn', 'thr-snmp-cpu-crit', 'snmp_cpu_warn_percent', 'snmp_cpu_crit_percent');
  readPair('thr-temp-warn',     'thr-temp-crit',     'temp_warn_celsius',     'temp_crit_celsius');

  // Per-mount overrides
  const mountRows = document.querySelectorAll('#thr-mounts-list .mount-row');
  if (mountRows.length > 0) {
    const perMount = {};
    for (const row of mountRows) {
      const path = row.querySelector('.mount-path').value.trim();
      const warn = row.querySelector('.mount-warn').value.trim();
      const crit = row.querySelector('.mount-crit').value.trim();
      if (!path) continue;
      if (!path.startsWith('/')) {
        errEl.textContent = `Mount path must start with / (got "${path}")`;
        errEl.style.display = 'block';
        return;
      }
      if (!warn || !crit) {
        errEl.textContent = `Both warn and crit required for mount ${path}`;
        errEl.style.display = 'block';
        return;
      }
      perMount[path] = {warn: parseFloat(warn), crit: parseFloat(crit)};
    }
    payload.disk_per_mount = perMount;
  }

  const resp = await api('PATCH', `/devices/${id}/metric-thresholds`, payload);
  if (resp?.ok) {
    toast('Metric thresholds saved', 'success');
    closeModal('metric-thresholds-modal');
  } else {
    errEl.textContent = resp?.error || 'Save failed';
    errEl.style.display = 'block';
  }
}

async function resetMetricThresholds() {
  const id = _currentMetricThresholdsDevice;
  if (!id) return;
  if (!confirm('Reset all metric thresholds for this device to fleet defaults?\n\nPer-device overrides AND per-mount disk overrides will be cleared.')) return;
  const resp = await api('DELETE', `/devices/${id}/metric-thresholds`);
  if (resp?.ok) {
    toast('Reset to defaults', 'success');
    closeModal('metric-thresholds-modal');
  } else {
    toast(resp?.error || 'Reset failed', 'error');
  }
}

// ─── v1.12.0: device metrics on the Monitor page ────────────────────────────
//
// Surfaces each device's current sysinfo (memory, swap, CPU loadavg, per-mount
// disk) alongside the alert level computed from metric_state. Click a row to
// jump straight to the threshold editor for that device.

let _deviceMetricsRegistered = false;

function _registerDeviceMetricsTable() {
  if (_deviceMetricsRegistered) return;
  _deviceMetricsRegistered = true;
  tableCtl.register({
    name: 'device_metrics',
    tbody: 'device-metrics-tbody',
    filterInput: 'device-metrics-filter',
    sortHeaders: 'device-metrics-thead',
    colspan: 7,
    columns: ['name', 'status', 'memory', 'swap', 'cpu', 'disks'],
    getColumns: (d) => {
      const si = d.sysinfo || {};
      const state = d.metric_state || {};
      let level = 'ok';
      for (const [, v] of Object.entries(state)) {
        if (v === 'critical') { level = 'critical'; break; }
        if (v === 'warning')  { level = 'warning'; }
      }
      return {
        name:   d.name || '',
        status: level === 'critical' ? 'a-critical' : level === 'warning' ? 'b-warning' : 'c-ok',
        memory: si.mem_percent ?? -1,
        swap:   si.swap_percent ?? -1,
        cpu:    (si.loadavg_1m && si.cpu_count) ? si.loadavg_1m / si.cpu_count : -1,
        disks:  Array.isArray(si.mounts) && si.mounts.length
                  ? Math.max(...si.mounts.map(m => m.percent || 0))
                  : (si.disk_percent ?? -1),
      };
    },
    match: (d, q) => {
      const hay = `${d.name || ''} ${d.hostname || ''} ${d.group || ''} ${(d.tags||[]).join(' ')}`.toLowerCase();
      if (hay.includes(q)) return true;
      // Also match against mount paths so people can search "/var" etc.
      const mounts = (d.sysinfo?.mounts || []).map(m => (m.path || '').toLowerCase()).join(' ');
      return mounts.includes(q);
    },
    row: (d) => {
      const si = d.sysinfo || {};
      const state = d.metric_state || {};
      const isMonitored = d.monitored !== false;
      let level = 'ok';
      for (const [, v] of Object.entries(state)) {
        if (v === 'critical') { level = 'critical'; break; }
        if (v === 'warning')  level = 'warning';
      }
      const levelBadge =
        !isMonitored        ? '<span class="patch-badge fs-10 c-muted" title="Unmonitored — data collected, no alerts">silent</span>' :
        level === 'critical' ? '<span class="patch-badge isl-347">CRIT</span>' :
        level === 'warning'  ? '<span class="patch-badge warn fs-10">WARN</span>' :
        d.online ? '<span class="patch-badge ok fs-10">OK</span>' :
        '<span class="meta-sm-nm">offline</span>';

      const fmtPct = (v, key) => {
        if (v === undefined || v === null) return '<span class="c-muted">—</span>';
        const lv = state[key] || 'ok';
        const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
        return `<span class="isl-348" data-color="${color}">${Number(v).toFixed(1)}%</span>`;
      };

      const memCell  = fmtPct(si.mem_percent,  'memory:');
      const swapCell = fmtPct(si.swap_percent, 'swap:');

      let cpuCell = '<span class="c-muted">—</span>';
      if (si.loadavg_1m !== undefined && si.cpu_count) {
        const ratio = si.loadavg_1m / si.cpu_count;
        const lv = state['cpu:'] || 'ok';
        const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
        cpuCell = `<span class="isl-348" data-color="${color}">${si.loadavg_1m.toFixed(2)} / ${si.cpu_count} (${ratio.toFixed(2)}×)</span>`;
      }

      // Disks: list each mount with its percent + alert state
      let diskCell = '<span class="c-muted">—</span>';
      const mounts = Array.isArray(si.mounts) ? si.mounts : [];
      if (mounts.length > 0) {
        const items = mounts.map(m => {
          const lv = state[`disk:${m.path}`] || 'ok';
          const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--muted)';
          return `<span title="${escHtml(m.path)} — ${m.used_gb}/${m.total_gb} GB" class="isl-349" data-color="${color}">${escHtml(m.path.length > 14 ? '…' + m.path.slice(-13) : m.path)}: ${Number(m.percent).toFixed(0)}%</span>`;
        });
        diskCell = items.join('');
      } else if (si.disk_percent !== undefined) {
        // Pre-v1.11.10 agent: only legacy root disk
        const lv = state['disk:/'] || 'ok';
        const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
        diskCell = `<span class="isl-348" data-color="${color}">/ ${si.disk_percent.toFixed(1)}%</span>`;
      }

      return `<tr>
        <td class="fw-500"><a href="#" data-action="openDetail" data-arg="${d.id}" data-arg2="${escAttr(d.name)}" data-prevent-default class="isl-350">${escHtml(d.name)}</a>${d.group ? ` <span class="group-badge fs-10">${escHtml(d.group)}</span>` : ''}</td>
        <td>${levelBadge}</td>
        <td class="ta-right">${memCell}</td>
        <td class="ta-right">${swapCell}</td>
        <td class="ta-right">${cpuCell}</td>
        <td>${diskCell}</td>
        <td class="nowrap"><button class="btn-icon isl-351" data-action="openMetrics" data-arg="${d.id}" data-arg2="${escAttr(d.name)}" title="Show metric trend over time">Trend</button><button class="btn-icon isl-352" data-action="openMetricThresholds" data-arg="${d.id}" data-arg2="${escAttr(d.name)}" >Thresholds</button></td>
      </tr>`;
    },
    emptyMsg: 'No devices to show metrics for.',
    emptyMsgFiltered: 'No devices match the filter.',
  });
  // v3.2.0 follow-up: SNMP devices table (separate from agent metrics)
  tableCtl.register({
    name: 'snmp_metrics',
    tbody: 'snmp-metrics-tbody',
    filterInput: 'snmp-metrics-filter',
    sortHeaders: 'snmp-metrics-thead',
    colspan: 8,
    columns: ['name', 'status', 'cpu', 'memory', 'disks', 'temp', 'uptime'],
    getColumns: (d) => {
      const ss = d.snmp_status || {};
      const state = d.metric_state || {};
      const isMonitored = d.monitored !== false;
      let level = 'ok';
      for (const [, v] of Object.entries(state)) {
        if (v === 'critical') { level = 'critical'; break; }
        if (v === 'warning')  { level = 'warning'; }
      }
      if (isMonitored && ss.enabled && !ss.ok && ss.fails >= 2) {
        if (level !== 'critical' && ss.fails >= 72) level = 'critical';
        else if (level === 'ok') level = 'warning';
      }
      return {
        name:   d.name || '',
        status: level === 'critical' ? 'a-critical' : level === 'warning' ? 'b-warning' : 'c-ok',
        cpu:    ss.cpu_pct ?? -1,
        memory: ss.mem_pct ?? -1,
        disks:  Array.isArray(ss.mounts) && ss.mounts.length
                  ? Math.max(...ss.mounts.map(m => m.percent || 0))
                  : -1,
        temp:   ss.temp_board ?? ss.temp_cpu ?? -1000,
        uptime: ss.sys_uptime ?? -1,
      };
    },
    match: (d, q) => {
      const ss = d.snmp_status || {};
      const hay = `${d.name || ''} ${ss.sys_name || ''} ${ss.sys_descr || ''} ${d.group || ''} ${(d.tags||[]).join(' ')}`.toLowerCase();
      return hay.includes(q);
    },
    row: (d) => _snmpMetricsRow(d),
    emptyMsg: 'No SNMP devices yet — enable SNMP on an agentless device\'s Settings tab.',
    emptyMsgFiltered: 'No SNMP devices match the filter.',
  });
}

function _snmpMetricsRow(d) {
  const ss = d.snmp_status || {};
  const state = d.metric_state || {};
  const isMonitored = d.monitored !== false;
  // Aggregate alert level
  let level = 'ok';
  for (const [, v] of Object.entries(state)) {
    if (v === 'critical') { level = 'critical'; break; }
    if (v === 'warning')  level = 'warning';
  }
  if (isMonitored && ss.enabled && !ss.ok && ss.fails >= 2) {
    if (level !== 'critical' && ss.fails >= 72) level = 'critical';
    else if (level === 'ok') level = 'warning';
  }
  const levelBadge =
    !isMonitored          ? '<span class="patch-badge fs-10 c-muted" title="Unmonitored — collecting, no alerts">silent</span>' :
    !ss.ok && ss.fails >= 72 ? '<span class="patch-badge isl-347" title="SNMP polling failed for 6+ hours">SNMP DEAD</span>' :
    !ss.ok && ss.fails >= 2  ? '<span class="patch-badge warn fs-10" title="SNMP poll failing">SNMP FAIL</span>' :
    level === 'critical' ? '<span class="patch-badge isl-347">CRIT</span>' :
    level === 'warning'  ? '<span class="patch-badge warn fs-10">WARN</span>' :
    '<span class="patch-badge ok fs-10">OK</span>';

  const fmtPct = (v, key) => {
    if (v === null || v === undefined) return '<span class="c-muted">—</span>';
    const lv = state[key] || 'ok';
    const col = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
    return `<span class="isl-348" data-color="${col}">${Number(v).toFixed(1)}%</span>`;
  };

  let cpuCell = '<span class="c-muted">—</span>';
  if (ss.cpu_pct != null) {
    const cores = ss.cpu_count ? ` <span class="hint">(${ss.cpu_count} core${ss.cpu_count > 1 ? 's' : ''})</span>` : '';
    cpuCell = `${fmtPct(ss.cpu_pct, 'snmp_cpu:')}${cores}`;
  }
  const memCell = ss.mem_pct != null
    ? fmtPct(ss.mem_pct, 'snmp_mem:')
    : '<span class="c-muted">—</span>';

  // Storage cell: list each filesystem with its percent
  let diskCell = '<span class="c-muted">—</span>';
  if (Array.isArray(ss.mounts) && ss.mounts.length) {
    diskCell = ss.mounts.map(m => {
      const lv = state[`snmp_disk:${m.path}`] || 'ok';
      const col = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--muted)';
      const label = m.path.length > 18 ? '…' + m.path.slice(-17) : m.path;
      return `<span title="${escAttr(m.path)} — ${m.used_gb.toFixed(1)}/${m.size_gb.toFixed(1)} GB" class="isl-349" data-color="${col}">${escHtml(label)}: ${Number(m.percent).toFixed(0)}%</span>`;
    }).join('');
  }

  // Temperature
  let tempCell = '<span class="c-muted">—</span>';
  const t = ss.temp_board ?? ss.temp_cpu;
  if (t != null) {
    const lv = state['temp_board:'] || state['temp_cpu:'] || 'ok';
    const col = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
    const which = ss.temp_board != null ? 'board' : 'cpu';
    tempCell = `<span class="isl-348" data-color="${col}" title="${which} temperature">${t.toFixed(1)} °C</span>`;
  }

  // Uptime
  let uptimeCell = '<span class="c-muted">—</span>';
  if (ss.sys_uptime != null) {
    const secs = ss.sys_uptime / 100;
    const days = Math.floor(secs / 86400);
    const hours = Math.floor((secs % 86400) / 3600);
    uptimeCell = `<span class="ta-right">${days}d ${hours}h</span>`;
  }

  // sysName below the device name as a hint
  const sysNm = ss.sys_name ? `<div class="hint fs-11">${escHtml(ss.sys_name)}</div>` : '';

  return `<tr>
    <td class="fw-500">
      <a href="#" data-action="openDeviceDrawer" data-arg="${d.id}" data-arg2="${escAttr(d.name)}" data-arg3="audit" data-prevent-default class="isl-350">${escHtml(d.name)}</a>${d.group ? ` <span class="group-badge fs-10">${escHtml(d.group)}</span>` : ''}
      ${sysNm}
    </td>
    <td>${levelBadge}</td>
    <td class="ta-right">${cpuCell}</td>
    <td class="ta-right">${memCell}</td>
    <td>${diskCell}</td>
    <td class="ta-right">${tempCell}</td>
    <td class="ta-right nowrap">${uptimeCell}</td>
    <td class="nowrap"><button class="btn-icon isl-352" data-action="openMetricThresholds" data-arg="${d.id}" data-arg2="${escAttr(d.name)}">Thresholds</button></td>
  </tr>`;
}

async function loadDeviceMetrics() {
  _registerDeviceMetricsTable();
  const data = await api('GET', '/devices');
  if (!data) return;
  // Update the global cache so other code paths see fresh sysinfo too
  if (typeof devices !== 'undefined') devices = data;

  // v3.2.0 follow-up: split rows into agent-based and SNMP-polled.
  // The two tables have different columns and threshold conventions.
  const agentRows = data.filter(d => !d.agentless);
  const snmpRows  = data.filter(d => d.snmp_status && d.snmp_status.enabled);

  // Agent table summary: count alert levels on monitored devices only
  let warn = 0, crit = 0;
  for (const d of agentRows) {
    if (d.monitored === false) continue;
    const state = d.metric_state || {};
    let level = 'ok';
    for (const [, v] of Object.entries(state)) {
      if (v === 'critical') { level = 'critical'; break; }
      if (v === 'warning')  level = 'warning';
    }
    if (level === 'critical') crit++;
    else if (level === 'warning') warn++;
  }
  const agentSum = document.getElementById('device-metrics-summary');
  if (agentSum) {
    const parts = [];
    if (crit) parts.push(`<span class="c-red-bold">${crit} critical</span>`);
    if (warn) parts.push(`<span class="c-amber-bold">${warn} warning</span>`);
    if (!crit && !warn) parts.push(`<span class="c-green">all clear</span>`);
    agentSum.innerHTML = parts.join('  •  ');
  }

  // SNMP table summary: counts split by ok/failing/silent
  let snmpOk = 0, snmpFail = 0, snmpSilent = 0;
  for (const d of snmpRows) {
    const ss = d.snmp_status;
    if (d.monitored === false) snmpSilent++;
    else if (ss.ok) snmpOk++;
    else snmpFail++;
  }
  const snmpSum = document.getElementById('snmp-metrics-summary');
  if (snmpSum) {
    const parts = [];
    if (snmpOk)     parts.push(`${_icon('radio',12)} <span class="c-green">${snmpOk} ok</span>`);
    if (snmpFail)   parts.push(`<span class="c-red">${snmpFail} failing</span>`);
    if (snmpSilent) parts.push(`<span class="c-muted">${snmpSilent} silent</span>`);
    if (!parts.length) parts.push('<span class="c-muted">no SNMP devices</span>');
    snmpSum.innerHTML = parts.join('  •  ');
  }
  tableCtl.render('device_metrics', agentRows);
  tableCtl.render('snmp_metrics',   snmpRows);
}

// ─── v1.11.11: web terminal ─────────────────────────────────────────────────
//
// Opens a modal asking for SSH host/user/password + admin password.
// Submits to /api/webterm/auth which validates the admin password and
// returns a short-lived ticket. Then opens a WebSocket to
// /api/webterm/connect (proxied by nginx to remotepower-webterm
// daemon), sends the SSH creds as the first message, and pumps bytes
// to/from an xterm.js terminal.
//
// xterm.js loads on first use rather than at page load — saves ~250 KB
// for users who never touch the terminal feature.

let _webtermXtermLoaded = false;
let _webtermActiveSession = null;   // {ws, term, fitAddon}

function _loadXtermOnce() {
  if (_webtermXtermLoaded) return Promise.resolve();
  // xterm.js@5.5.0 + addon-fit@0.10.0, self-hosted under /static/vendor/
  // so the strict CSP (`script-src 'self'; style-src 'self'`) doesn't
  // block them. SRI hashes (v3.0.6): the browser refuses to execute /
  // apply the file if its SHA-384 differs from the pinned value.
  // Update procedure when bumping versions: replace the file in
  // static/vendor/, then update the integrity attribute below — the
  // CSP migration sweep test reads `_VENDOR_SRI` and the actual file
  // hashes to keep them in sync.
  return Promise.all([
    new Promise((resolve, reject) => {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = '/static/vendor/xterm/xterm.min.css';
      link.integrity = 'sha384-tStR1zLfWgsiXCF3IgfB3lBa8KmBe/lG287CL9WCeKgQYcp1bjb4/+mwN6oti4Co';
      link.onload = resolve;
      link.onerror = reject;
      document.head.appendChild(link);
    }),
    new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = '/static/vendor/xterm/xterm.min.js';
      s.integrity = 'sha384-J4qzUjBl1FxyLsl/kQPQIOeINsmp17OHYXDOMpMxlKX53ZfYsL+aWHpgArvOuof9';
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    }),
  ]).then(() => new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = '/static/vendor/xterm-addon-fit/addon-fit.min.js';
    s.integrity = 'sha384-XGqKrV8Jrukp1NITJbOEHwg01tNkuXr6uB6YEj69ebpYU3v7FvoGgEg23C1Gcehk';
    s.onload = resolve;
    s.onerror = reject;
    document.head.appendChild(s);
  })).then(() => { _webtermXtermLoaded = true; });
}

function openWebTerm(id, name) {
  // Find the device in our cached list to pre-fill the IP. The global
  // `devices` is populated by loadDevices() and refreshed periodically.
  const dev = (typeof devices !== 'undefined' ? devices : []).find(d => d.id === id);
  document.getElementById('webterm-device-id').value = id;
  document.getElementById('webterm-host').value = dev?.ip || '';
  document.getElementById('webterm-user').value = '';
  document.getElementById('webterm-port').value = 22;
  document.getElementById('webterm-ssh-pw').value = '';
  document.getElementById('webterm-admin-pw').value = '';
  document.getElementById('webterm-error').style.display = 'none';
  document.querySelector('#webterm-modal .modal-title').textContent = `Open web terminal — ${name}`;
  openModal('webterm-modal');
  // Pre-warm xterm.js so the first connect doesn't have a noticeable
  // delay (the user is busy typing the password anyway).
  _loadXtermOnce().catch(() => {});
}

async function webtermConnect() {
  const id = document.getElementById('webterm-device-id').value;
  const host = document.getElementById('webterm-host').value.trim();
  const user = document.getElementById('webterm-user').value.trim();
  const port = parseInt(document.getElementById('webterm-port').value) || 22;
  const sshPw = document.getElementById('webterm-ssh-pw').value;
  const adminPw = document.getElementById('webterm-admin-pw').value;
  const errEl = document.getElementById('webterm-error');
  errEl.style.display = 'none';

  if (!host || !user || !sshPw || !adminPw) {
    errEl.textContent = 'All fields are required.';
    errEl.style.display = 'block';
    return;
  }

  const btn = document.getElementById('webterm-connect-btn');
  btn.disabled = true; btn.textContent = 'Authenticating…';

  // Step 1: get a ticket from the CGI
  let ticketResp;
  try {
    ticketResp = await api('POST', '/webterm/auth', {
      device_id: id,
      admin_password: adminPw,
    });
  } catch (e) {
    errEl.textContent = 'Network error contacting server.';
    errEl.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Connect';
    return;
  }
  if (!ticketResp || !ticketResp.ticket) {
    errEl.textContent = ticketResp?.error || 'Ticket request failed.';
    errEl.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Connect';
    return;
  }

  // Step 2: ensure xterm.js is loaded
  btn.textContent = 'Loading terminal…';
  try { await _loadXtermOnce(); }
  catch (e) {
    errEl.textContent = 'Could not load xterm.js. Check your network/CSP.';
    errEl.style.display = 'block';
    btn.disabled = false; btn.textContent = 'Connect';
    return;
  }

  // Step 3: open the WebSocket
  btn.textContent = 'Connecting…';
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  // The daemon_url in the response is a relative path; combine with
  // current origin. If it's already absolute (operator override), use as-is.
  let wsUrl = ticketResp.daemon_url;
  if (wsUrl.startsWith('/')) {
    wsUrl = `${proto}//${window.location.host}${wsUrl}`;
  } else if (!wsUrl.startsWith('ws')) {
    wsUrl = `${proto}//${wsUrl}`;
  }
  wsUrl += `?ticket=${encodeURIComponent(ticketResp.ticket)}`;

  const ws = new WebSocket(wsUrl);
  ws.binaryType = 'arraybuffer';

  // Switch UIs: close the auth modal, open the terminal screen
  closeModal('webterm-modal');
  openModal('webterm-screen');
  document.getElementById('webterm-screen-title').textContent =
    `${user}@${host}:${port}  (${ticketResp.device.name})`;
  document.getElementById('webterm-screen-status').textContent = 'connecting…';

  // Set up xterm
  const xtermDiv = document.getElementById('webterm-xterm');
  xtermDiv.innerHTML = '';   // wipe any previous session
  const Term = window.Terminal;
  const FitAddon = window.FitAddon?.FitAddon;
  const term = new Term({
    // JetBrains Mono ships under /static/vendor/fonts/ — the strict-CSP
    // migration self-hosted it. Putting it at the front of the chain
    // gives a consistent monospace across Linux / macOS / Windows
    // instead of the per-OS fallback that operators reported as
    // "the font changed after the migration".
    fontFamily: '"JetBrains Mono", Menlo, Monaco, "Courier New", monospace',
    fontSize: 13,
    theme: { background: '#000000', foreground: '#dddddd' },
    cursorBlink: true,
  });
  const fitAddon = FitAddon ? new FitAddon() : null;
  if (fitAddon) term.loadAddon(fitAddon);
  term.open(xtermDiv);
  if (fitAddon) fitAddon.fit();
  term.focus();

  _webtermActiveSession = {ws, term, fitAddon, ssh_pw: sshPw};

  // WS event handlers
  ws.onopen = () => {
    // First message: SSH credentials + initial terminal size
    const cols = term.cols || 80;
    const rows = term.rows || 24;
    ws.send(JSON.stringify({
      host, user, port, password: sshPw,
      cols, rows,
    }));
    // Wipe the password from memory ASAP (the WS holds the only copy now)
    if (_webtermActiveSession) _webtermActiveSession.ssh_pw = null;
  };
  ws.onmessage = (ev) => {
    const data = ev.data;
    if (typeof data === 'string') {
      // Control messages from daemon are JSON; raw shell output isn't.
      // The simplest distinguishing test: starts with '{' AND parses.
      if (data.startsWith('{')) {
        try {
          const obj = JSON.parse(data);
          if (obj.type === 'connecting') {
            document.getElementById('webterm-screen-status').textContent = 'SSH handshake…';
            return;
          }
          if (obj.type === 'connected') {
            document.getElementById('webterm-screen-status').textContent =
              `connected (session ${obj.session_id})`;
            return;
          }
          if (obj.type === 'error') {
            term.write('\r\n\x1b[31m✗ ' + obj.message + '\x1b[0m\r\n');
            document.getElementById('webterm-screen-status').textContent = 'error';
            return;
          }
          // Unknown JSON message — fall through to display
        } catch (e) { /* not JSON; raw output */ }
      }
      term.write(data);
    } else if (data instanceof ArrayBuffer) {
      term.write(new Uint8Array(data));
    }
  };
  ws.onerror = () => {
    term.write('\r\n\x1b[31m✗ WebSocket error\x1b[0m\r\n');
    document.getElementById('webterm-screen-status').textContent = 'error';
  };
  ws.onclose = (ev) => {
    document.getElementById('webterm-screen-status').textContent =
      `disconnected (${ev.code})`;
    if (term && !ev.wasClean) {
      term.write(`\r\n\x1b[33m✗ Connection closed (${ev.code})\x1b[0m\r\n`);
    }
  };

  // Pipe terminal input to WS
  term.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
  });
  // Resize: forward to daemon so the SSH PTY adjusts
  term.onResize(({cols, rows}) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({type: 'resize', cols, rows}));
    }
  });
  // Resize on window resize
  const resize = () => { if (fitAddon) fitAddon.fit(); };
  window.addEventListener('resize', resize);
  _webtermActiveSession.resizeListener = resize;

  // Reset the connect button for next time
  btn.disabled = false; btn.textContent = 'Connect';
}

function webtermDisconnect() {
  const s = _webtermActiveSession;
  if (!s) { closeModal('webterm-screen'); return; }
  try { s.ws.close(); } catch (e) {}
  try { s.term.dispose(); } catch (e) {}
  if (s.resizeListener) window.removeEventListener('resize', s.resizeListener);
  _webtermActiveSession = null;
  closeModal('webterm-screen');
}

async function clearHistory() { if (!confirm('Clear all command history? This cannot be undone.')) return; const data = await api('DELETE', '/history'); if (data?.ok) { toast('History cleared', 'success'); loadHistory(); } else toast(data?.error || 'Failed', 'error'); }
let selectedDevices = new Set();
function toggleSelect(id) { if (selectedDevices.has(id)) selectedDevices.delete(id); else selectedDevices.add(id); updateBatchBar(); renderDevices(); }
function clearSelection() { selectedDevices.clear(); updateBatchBar(); renderDevices(); }
// v1.12.1: select-all checkbox in the minimal table's header. Selects /
// deselects every currently-rendered row (i.e. respects the visible filter,
// not the entire device fleet). If you've filtered to "production" tag,
// the checkbox toggles only those rows.
function toggleSelectAllMinimal(checkbox) {
  const rows = document.querySelectorAll('#devices-minimal-tbody tr.dev-row');
  if (checkbox.checked) {
    rows.forEach(tr => {
      const id = tr.getAttribute('data-dev-id');
      if (id) selectedDevices.add(id);
    });
  } else {
    rows.forEach(tr => {
      const id = tr.getAttribute('data-dev-id');
      if (id) selectedDevices.delete(id);
    });
  }
  updateBatchBar();
  renderDevices();
}
function updateBatchBar() { const bar = document.getElementById('batch-bar'); const cnt = document.getElementById('batch-count'); if (selectedDevices.size > 0) { bar.classList.add('visible'); cnt.textContent = selectedDevices.size; } else bar.classList.remove('visible'); }
async function batchAction(command) { if (!selectedDevices.size) return; const verbs = {shutdown:'Shut down', reboot:'Reboot', update:'Update agent on', upgrade:'Upgrade packages on'}; const verb = verbs[command] || 'Run'; if (!confirm(`${verb} ${selectedDevices.size} device(s)?`)) return; const eps = {shutdown:'/shutdown', reboot:'/reboot', update:'/update-device', upgrade:'/upgrade-device'}; const ep = eps[command]; const data = await api('POST', ep, {device_ids: [...selectedDevices]}); if (data?.ok) { const msg = command === 'upgrade' ? `Package upgrade queued for ${selectedDevices.size} device(s). Output arrives on next heartbeat (~60s).` : `${verb} queued for ${selectedDevices.size} device(s)`; toast(msg, 'success'); clearSelection(); setTimeout(loadDevices, 3000); } else toast(data?.error || 'Failed', 'error'); }
function openNotesModal(id, currentNotes) { document.getElementById('notes-device-id').value = id; document.getElementById('notes-input').value = currentNotes || ''; openModal('notes-modal'); }
async function saveNotes() { const id = document.getElementById('notes-device-id').value; const notes = document.getElementById('notes-input').value; const r = await api('PATCH', '/devices/' + id + '/notes', {notes}); if (r?.ok) { toast('Notes saved', 'success'); closeModal('notes-modal'); loadDevices(); } else toast(r?.error || 'Failed', 'error'); }
function openGroupModal(id, current) { document.getElementById('group-device-id').value = id; document.getElementById('group-input').value = current || ''; openModal('group-modal'); }
async function saveGroup() { const id = document.getElementById('group-device-id').value; const group = document.getElementById('group-input').value.trim(); const r = await api('PATCH', '/devices/' + id + '/group', {group}); if (r?.ok) { toast('Group saved', 'success'); closeModal('group-modal'); loadDevices(); } else toast(r?.error || 'Failed', 'error'); }
function openPollModal(id, current) { document.getElementById('poll-device-id').value = id; document.getElementById('poll-input').value = current || 60; openModal('poll-modal'); }
async function savePollInterval() { const id = document.getElementById('poll-device-id').value; const interval = parseInt(document.getElementById('poll-input').value); const r = await api('PATCH', '/devices/' + id + '/poll_interval', {poll_interval: interval}); if (r?.ok) { toast(`Poll interval set to ${r.poll_interval}s`, 'success'); closeModal('poll-modal'); loadDevices(); } else toast(r?.error || 'Failed', 'error'); }
async function openAllowlistModal(id) { document.getElementById('allowlist-device-id').value = id; document.getElementById('allowlist-input').value = ''; openModal('allowlist-modal'); const r = await api('GET', '/devices/' + id + '/allowlist'); if (r) document.getElementById('allowlist-input').value = (r.allowed_commands || []).join('\n'); }
async function saveAllowlist() { const id = document.getElementById('allowlist-device-id').value; const raw = document.getElementById('allowlist-input').value; const cmds = raw.split('\n').map(s => s.trim()).filter(s => s.length > 0); const r = await api('POST', '/devices/' + id + '/allowlist', {allowed_commands: cmds}); if (r?.ok) { toast(`Allowlist saved (${cmds.length} commands)`, 'success'); closeModal('allowlist-modal'); } else toast(r?.error || 'Failed', 'error'); }
async function openMetrics(id, name) { document.getElementById('metrics-title').textContent = `Metrics: ${name}`; document.getElementById('metrics-body').innerHTML = '<div class="empty-state">Loading…</div>'; openModal('metrics-modal'); const data = await api('GET', '/devices/' + id + '/metrics'); if (!data || !data.metrics || !data.metrics.length) { document.getElementById('metrics-body').innerHTML = '<div class="empty-state">No metrics yet. Agent needs psutil installed for CPU/RAM/disk tracking.</div>'; return; } const metrics = data.metrics.slice(-60); function spark(key, color) { const vals = metrics.map(m => m[key]).filter(v => v !== null && v !== undefined); if (!vals.length) return '<span class="hint">no data</span>'; const w = 6; const h = 32; const bars = vals.map((v, i) => { const bh = Math.max(2, Math.round((v / 100) * h)); return `<rect x="${i*w}" y="${h-bh}" width="${w-1}" height="${bh}" fill="${color}" rx="1"/>`; }).join(''); const latest = vals[vals.length-1]; return `<svg width="${vals.length*w}" height="${h}" class="va-middle">${bars}</svg> <span class="isl-353" data-color="${color}">${latest.toFixed(1)}%</span>`; } document.getElementById('metrics-body').innerHTML = `<div class="sysinfo-row isl-128"><div class="sysinfo-pill"><div class="label">Points</div><div class="value">${metrics.length}</div></div><div class="sysinfo-pill"><div class="label">From</div><div class="value fs-11">${new Date(metrics[0].ts*1000).toLocaleTimeString()}</div></div></div><div class="isl-354"><div class="isl-355"><div class="isl-356">CPU</div>${spark('cpu','var(--accent)')}</div><div class="isl-355"><div class="isl-356">Memory</div>${spark('mem','var(--green)')}</div><div class="isl-355"><div class="isl-356">Disk</div>${spark('disk','var(--amber)')}</div></div><p class="isl-357">Requires <code>psutil</code> on the client: <code>pip install psutil --break-system-packages</code></p>`; }
function exportBackup() { const token = getToken(); fetch('/api/export', {headers: {'X-Token': token}}).then(r => r.blob()).then(blob => { const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = `remotepower-backup-${new Date().toISOString().slice(0,10)}.zip`; a.click(); URL.revokeObjectURL(url); toast('Backup downloaded', 'success'); }).catch(() => toast('Export failed', 'error')); }
// v1.11.6: API keys page gets filter+sort
let _apikeysRegistered = false;
function _registerApiKeysTable() {
  if (_apikeysRegistered) return;
  _apikeysRegistered = true;
  tableCtl.register({
    name: 'apikeys',
    tbody: 'apikeys-tbody',
    filterInput: 'apikeys-filter',
    sortHeaders: 'apikeys-thead',
    colspan: 5,
    columns: ['name', 'role', 'user', 'created'],
    getColumns: (k) => ({
      name:    k.name || '',
      role:    k.role || '',
      user:    k.user || '',
      created: k.created || 0,
    }),
    row: (k) => `<tr><td class="fw-600">${escHtml(k.name)}</td><td><span class="patch-badge ${k.role==='admin'?'warn':'ok'}">${escHtml(k.role)}</span></td><td class="hint">${escHtml(k.user)}</td><td class="hint">${k.created ? new Date(k.created*1000).toLocaleDateString() : '—'}</td><td><button class="btn-icon isl-45" data-action="deleteApiKey" data-arg="${escAttr(k.id)}" >Delete</button></td></tr>`,
    emptyMsg: 'No API keys. Create one for scripting access.',
    emptyMsgFiltered: 'No keys match the filter.',
  });
}
async function loadApiKeys() {
  _registerApiKeysTable();
  const data = await api('GET', '/apikeys');
  if (!data) return;
  tableCtl.render('apikeys', data);
}
function openApiKeyCreate() { document.getElementById('apikey-name').value = ''; document.getElementById('apikey-role').value = 'admin'; document.getElementById('apikey-result').style.display = 'none'; document.getElementById('apikey-create-btn').style.display = ''; openModal('apikey-create-modal'); }
async function createApiKey() { const name = document.getElementById('apikey-name').value.trim(); const role = document.getElementById('apikey-role').value; if (!name) { toast('Name required', 'error'); return; } const data = await api('POST', '/apikeys', {name, role}); if (data?.ok) { document.getElementById('apikey-value-display').textContent = data.key; document.getElementById('apikey-result').style.display = 'block'; document.getElementById('apikey-create-btn').style.display = 'none'; loadApiKeys(); } else toast(data?.error || 'Failed', 'error'); }
async function deleteApiKey(id) { if (!confirm('Delete this API key? Scripts using it will stop working.')) return; const data = await api('DELETE', '/apikeys/' + id); if (data?.ok) { toast('Key deleted', 'info'); loadApiKeys(); } else toast(data?.error || 'Failed', 'error'); }
// v1.11.6: command library gets filter+sort
let _cmdlibRegistered = false;
function _registerCmdLibTable() {
  if (_cmdlibRegistered) return;
  _cmdlibRegistered = true;
  tableCtl.register({
    name: 'cmdlib',
    tbody: 'cmdlib-tbody',
    filterInput: 'cmdlib-filter',
    sortHeaders: 'cmdlib-thead',
    colspan: 4,
    columns: ['name', 'cmd', 'description'],
    getColumns: (s) => ({
      name:        s.name || '',
      cmd:         s.cmd || '',
      description: s.description || '',
    }),
    row: (s) => {
      const sKey = _storeEvtData(s);
      return `<tr><td class="fw-600">${escHtml(s.name)}</td><td class="isl-358">${escHtml(s.cmd)}</td><td class="hint">${escHtml(s.description||'—')}</td><td class="row-6"><button class="btn-icon isl-44" data-action="useCmdSnippet" data-arg="${escAttr(s.cmd)}" >Use</button><button class="btn-icon isl-44" data-action-btn="_editCmdSnippetBtn" data-store-key="${sKey}">Edit</button><button class="btn-icon isl-45" data-action="deleteCmdSnippet" data-arg="${escAttr(s.id)}" >✕</button></tr>`;
    },
    emptyMsg: 'No snippets yet.',
    emptyMsgFiltered: 'No snippets match the filter.',
  });
}
async function loadCmdLib() {
  _registerCmdLibTable();
  const data = await api('GET', '/cmd-library');
  if (!data) return;
  tableCtl.render('cmdlib', data);
}
// v3.3.0: cmd snippet modal is shared between Add and Edit. _cmdLibEditId
// is null when adding, the snippet id when editing — saveCmdSnippet
// branches between POST and PUT on that.
let _cmdLibEditId = null;
function openCmdLibAdd() {
  _cmdLibEditId = null;
  const t = document.querySelector('#cmdlib-add-modal .modal-title');
  if (t) t.textContent = 'Add command snippet';
  document.getElementById('cmdlib-name').value = '';
  document.getElementById('cmdlib-cmd').value = '';
  document.getElementById('cmdlib-desc').value = '';
  openModal('cmdlib-add-modal');
}
function _editCmdSnippetBtn(btn) {
  const s = _evtData.get(btn.dataset.storeKey);
  if (!s) return;
  _cmdLibEditId = s.id;
  const t = document.querySelector('#cmdlib-add-modal .modal-title');
  if (t) t.textContent = 'Edit command snippet';
  document.getElementById('cmdlib-name').value = s.name || '';
  document.getElementById('cmdlib-cmd').value  = s.cmd  || '';
  document.getElementById('cmdlib-desc').value = s.description || '';
  openModal('cmdlib-add-modal');
}
async function addCmdSnippet() {
  const name = document.getElementById('cmdlib-name').value.trim();
  const cmd  = document.getElementById('cmdlib-cmd').value.trim();
  const desc = document.getElementById('cmdlib-desc').value.trim();
  if (!name || !cmd) { toast('Name and command required', 'error'); return; }
  const body = {name, cmd, description: desc};
  const data = _cmdLibEditId
    ? await api('PUT',  '/cmd-library/' + _cmdLibEditId, body)
    : await api('POST', '/cmd-library', body);
  if (data?.ok) {
    toast(_cmdLibEditId ? 'Snippet updated' : 'Snippet added', 'success');
    _cmdLibEditId = null;
    closeModal('cmdlib-add-modal');
    loadCmdLib();
  } else toast(data?.error || 'Failed', 'error');
}
async function deleteCmdSnippet(id) { const data = await api('DELETE', '/cmd-library/' + id); if (data?.ok) { toast('Removed', 'info'); loadCmdLib(); } else toast(data?.error || 'Failed', 'error'); }
function useCmdSnippet(cmd) { document.getElementById('exec-cmd').value = cmd; closeModal('cmdlib-add-modal'); toast('Command pasted into exec modal', 'info'); }
function generateQRCode(containerId, text) {
  if (window.qrcode) { _renderQR(containerId, text); return; }
  // qrcode-generator@1.4.4, self-hosted under /static/vendor/ so the
  // strict CSP (`script-src 'self'`) doesn't block it. SRI hash
  // pins the on-disk file to its v1.4.4 SHA-384 — if the file is
  // ever overwritten with something else, the browser refuses to
  // execute it.
  const script = document.createElement('script');
  script.src = '/static/vendor/qrcode-generator/qrcode.min.js';
  script.integrity = 'sha384-mZT2gIty7ZDdOGkxfP6joZcYdMW1Jvj9dRlfpTmaJAKKXTqzygtB22k7FLe+KZC1';
  script.onload  = () => _renderQR(containerId, text);
  script.onerror = () => {
    const el = document.getElementById(containerId);
    if (!el) return;
    const fallback = document.createElement('div');
    fallback.className = 'isl-359';
    fallback.textContent = 'QR unavailable. Enter secret manually.';
    el.replaceChildren(fallback);
  };
  document.head.appendChild(script);
}
function _renderQR(containerId, text) { const el = document.getElementById(containerId); if (!el || !window.qrcode) return; try { const qr = qrcode(0, 'M'); qr.addData(text); qr.make(); /* Render as a data-URL <img>, not inline SVG: the strict CSP (style-src 'self') blocks the inline styles createSvgTag() emits, while img-src 'self' data: permits a data-URL image. */ const img = document.createElement('img'); img.src = qr.createDataURL(4, 0); img.width = 160; img.height = 160; img.alt = 'TOTP QR code'; el.replaceChildren(img); } catch(e) { el.innerHTML = '<div class="isl-359">QR generation failed.<br>Enter secret manually.</div>'; } }
async function loadTotpStatus() { const data = await api('GET', '/totp/status'); if (!data) return; const statusEl = document.getElementById('totp-status'); const setupEl = document.getElementById('totp-setup-area'); if (data.enabled) { statusEl.innerHTML = '<span class="c-green-bold">✓ 2FA is enabled</span>'; setupEl.innerHTML = `<button class="btn-secondary c-danger-outline" data-action="disableTotp" >Disable 2FA</button>`; } else { statusEl.innerHTML = '<span class="c-muted">2FA is not enabled</span>'; setupEl.innerHTML = `<button class="btn-primary mw-200" data-action="setupTotp" >Enable 2FA</button>`; } }
async function setupTotp() { const data = await api('POST', '/totp/setup'); if (!data?.ok) { toast(data?.error || 'Failed', 'error'); return; } const setupEl = document.getElementById('totp-setup-area'); const qrContainerId = 'totp-qr-' + Date.now(); setupEl.innerHTML = `<div class="isl-360"><div class="isl-361"><div id="${qrContainerId}" class="isl-362"><span class="isl-363">Generating…</span></div><div class="isl-364"><div class="isl-365">Scan with your authenticator app</div><div class="isl-366">Google Authenticator, Authy, 1Password, Bitwarden, etc.</div><div class="isl-367">Or enter manually:</div><div data-action-btn="_copySecretBtn" data-secret="${data.secret}" title="Click to copy" class="isl-368">${data.secret}</div></div></div></div><div class="form-group"><label class="form-label">Verify — enter a code from your app</label><input type="text" id="totp-confirm-code" class="form-input isl-369" placeholder="123456" maxlength="6" inputmode="numeric"></div><button class="btn-primary mw-200" data-action="confirmTotp" >Confirm & Enable</button>`; generateQRCode(qrContainerId, data.uri); }
async function confirmTotp() { const code = document.getElementById('totp-confirm-code').value.trim(); if (!code) { toast('Enter a code', 'error'); return; } const data = await api('POST', '/totp/confirm', {code}); if (data?.ok) { toast('2FA enabled!', 'success'); loadTotpStatus(); } else toast(data?.error || 'Invalid code', 'error'); }
async function disableTotp() { const pw = prompt('Enter your password to disable 2FA:'); if (!pw) return; const data = await api('POST', '/totp/disable', {password: pw}); if (data?.ok) { toast('2FA disabled', 'info'); loadTotpStatus(); } else toast(data?.error || 'Failed', 'error'); }
function filterDevices() {
  // v1.11.5: persist filter input across reloads. The actual filter logic
  // still lives in renderDevices(); this just captures the current value
  // and schedules a debounced server save.
  const el = document.getElementById('device-search-input');
  if (el && _uiPrefsLoaded) {
    getTablePrefs('devices').filter = el.value || '';
    _scheduleFlushUiPrefs();
  }
  renderDevices();
}
let patchReportData = null;
// v1.11.6: register patches table for sort. The existing 3-control filter
// system (text + group dropdown + device dropdown) keeps owning filter
// logic — we pass `match: () => true` and rely on getFilteredPatchDevices()
// to do the filtering before handing the rows to tableCtl.
let _patchRegistered = false;
function _registerPatchTable() {
  if (_patchRegistered) return;
  _patchRegistered = true;
  tableCtl.register({
    name: 'patches',
    tbody: 'patch-tbody',
    sortHeaders: 'patch-thead',
    colspan: 9,
    columns: ['name', 'group', 'os', 'status', 'pkg_manager', 'upgradable', 'patch_status'],
    refresh: () => renderPatchTable(),
    getColumns: (d) => ({
      name:         d.name || '',
      group:        d.group || '',
      os:           d.os || '',
      // Online > Offline alphabetically — clicking column flips dir.
      status:       d.online ? 'online' : 'offline',
      pkg_manager:  d.pkg_manager || '',
      upgradable:   typeof d.upgradable === 'number' ? d.upgradable : -1,
      patch_status: d.patch_status || '',
    }),
    match: () => true,  // patches has its own filter chain
    row: (d) => {
      const statusCls = d.patch_status === 'fully_patched' ? 'ok' : d.patch_status === 'patches_available' ? 'warn' : '';
      const statusLabel = d.patch_status === 'fully_patched' ? 'Patched' : d.patch_status === 'patches_available' ? `${d.upgradable} pending` : (d.online ? 'No data' : 'Offline — No data');
      const recentCmds = (d.recent_patch_commands || []).slice(-2).map(c => `<div title="${escHtml(c.output||'')}" class="isl-370">${escHtml(c.cmd?.substring(0,30)||'')} (rc=${c.rc})</div>`).join('');
      // v2.1.5: AIPrioritise only on devices with pending updates
      // v3.0.4: pass the event so the handler can disable the button +
      // show a spinner during the API call (previously the button just
      // toasted silently — operators reported "I clicked it, nothing
      // happened" because the toast was easy to miss and there was no
      // in-place feedback).
      const aiBtn = d.upgradable > 0
        ? `<button class="btn-icon isl-371" data-action-btn="_aiPrioritisePatchesBtn" data-dev-id="${d.device_id}" data-dev-name="${escAttr(d.name)}" title="AI: prioritise these updates">${_icon('sparkles',14)}</button>`
        : '';
      const rebootBadge = d.reboot_required
        ? `<span title="Pending reboot — /run/reboot-required exists on this host" class="isl-372"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" class="isl-373"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-.85-5.92"/></svg>Reboot</span>`
        : '';
      return `<tr><td class="fw-500">${escHtml(d.name)}${rebootBadge}</td><td class="hint">${escHtml(d.group||'—')}</td><td class="fs-12">${escHtml(d.os?.substring(0,25)||'—')}</td><td><span class="mon-status ${d.online?'up':'down'}">${d.online?'Online':'Offline'}</span></td><td class="mono-12">${escHtml(d.pkg_manager)}</td><td class="isl-374 ${d.upgradable>0?'c-amber': d.upgradable===0?'c-green': 'c-muted'}">${d.upgradable !== null && d.upgradable !== undefined ? d.upgradable : '—'}</td><td><span class="patch-badge ${statusCls}">${statusLabel}</span></td><td>${recentCmds || '<span class="meta-sm-nm">—</span>'}</td><td><div class="isl-375">${aiBtn}<button class="btn-icon cell-sm" data-action="openDevicePatchReport" data-arg="${d.device_id}" data-arg2="${escAttr(d.name)}" >Detail</button></div></td></tr>`;
    },
    emptyMsg: 'No devices match the current filter.',
    emptyMsgFiltered: 'No devices match the current filter.',
  });
}

async function loadPatchReport() { _registerPatchTable(); const tbody = document.getElementById('patch-tbody'); tbody.innerHTML = '<tr><td colspan="9" class="empty-state-sm">Loading…</tbody>'; const data = await api('GET', '/patch-report'); if (!data) return; patchReportData = data; const groups = [...new Set(data.devices.map(d => d.group).filter(g => g))].sort(); const gSel = document.getElementById('patch-group-filter'); const cur = gSel.value; gSel.innerHTML = '<option value="all">All groups</option>' + groups.map(g => `<option value="${escHtml(g)}">${escHtml(g)}</option>`).join(''); gSel.value = cur; const dSel = document.getElementById('patch-device-filter'); const curD = dSel.value; dSel.innerHTML = '<option value="all">All devices</option>' + data.devices.map(d => `<option value="${escHtml(d.device_id)}">${escHtml(d.name)}</option>`).join(''); dSel.value = curD; renderPatchTable(); }
function getFilteredPatchDevices() { if (!patchReportData) return []; let devs = patchReportData.devices; const gf = document.getElementById('patch-group-filter')?.value || 'all'; const df = document.getElementById('patch-device-filter')?.value || 'all'; const search = (document.getElementById('patch-search-input')?.value || '').toLowerCase(); if (gf !== 'all') devs = devs.filter(d => d.group === gf); if (df !== 'all') devs = devs.filter(d => d.device_id === df); if (search) devs = devs.filter(d => (d.name||'').toLowerCase().includes(search) || (d.hostname||'').toLowerCase().includes(search) || (d.os||'').toLowerCase().includes(search) || (d.group||'').toLowerCase().includes(search) || (d.pkg_manager||'').toLowerCase().includes(search) || (d.tags||[]).some(t => t.toLowerCase().includes(search))); return devs; }
function renderPatchTable() {
  if (!patchReportData) return;
  const filtered = getFilteredPatchDevices();
  let total = filtered.length, patched = 0, withPatches = 0, pending = 0;
  for (const d of filtered) {
    if (d.patch_status === 'fully_patched') patched++;
    else if (d.patch_status === 'patches_available') { withPatches++; pending += (d.upgradable || 0); }
  }
  const onlineWithData = patched + withPatches;
  const pct = onlineWithData > 0 ? Math.round((patched / onlineWithData) * 1000) / 10 : 0;
  document.getElementById('patch-total').textContent = total;
  document.getElementById('patch-patched').textContent = patched;
  document.getElementById('patch-pending').textContent = withPatches;
  document.getElementById('patch-count').textContent = pending;
  document.getElementById('patch-pct').textContent = pct + '%';
  // v1.11.6: tableCtl handles the empty state and applies sort — but it
  // only renders if registered. Guard against edge case where renderPatchTable
  // is called before _registerPatchTable() (shouldn't happen, but defensive).
  _registerPatchTable();
  tableCtl.render('patches', filtered);
}
function exportPatchFiltered(format) { const gf = document.getElementById('patch-group-filter')?.value || 'all'; const df = document.getElementById('patch-device-filter')?.value || 'all'; if (df !== 'all' && format !== 'csv' && format !== 'xml') { openDevicePatchReport(df, ''); return; } let url = `/api/patch-report/${format}`; const params = []; if (gf !== 'all') params.push(`group=${encodeURIComponent(gf)}`); if (df !== 'all') params.push(`device_id=${encodeURIComponent(df)}`); if (params.length) url += '?' + params.join('&'); fetch(url, {headers: {'X-Token': getToken()}}).then(r => { if (!r.ok) throw new Error('Export failed'); return r.blob(); }).then(blob => { const u = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = u; const suffix = gf !== 'all' ? `-${gf}` : df !== 'all' ? `-device` : ''; a.download = `patch-report${suffix}-${new Date().toISOString().slice(0,10)}.${format}`; a.click(); URL.revokeObjectURL(u); toast(`${format.toUpperCase()} downloaded`, 'success'); }).catch(() => toast('Export failed', 'error')); }
async function openDevicePatchReport(devId, devName) { document.getElementById('device-patch-title').textContent = `Patch Report: ${devName}`; document.getElementById('device-patch-body').innerHTML = '<div class="empty-state">Loading…</div>'; openModal('device-patch-modal'); const data = await api('GET', `/patch-report/device/${devId}`); if (!data) return; const statusColor = data.patch_status === 'fully_patched' ? 'var(--green)' : data.patch_status === 'patches_available' ? 'var(--amber)' : 'var(--muted)'; const statusLabel = data.patch_status === 'fully_patched' ? 'Fully Patched' : data.patch_status === 'patches_available' ? `${data.upgradable} patches pending` : 'No data'; let html = `<div class="sysinfo-row mb-16"><div class="sysinfo-pill"><div class="label">Status</div><div class="value isl-376">${statusLabel}</div></div><div class="sysinfo-pill"><div class="label">OS</div><div class="value fs-11">${escHtml(data.os||'—')}</div></div><div class="sysinfo-pill"><div class="label">Pkg Manager</div><div class="value">${escHtml(data.pkg_manager)}</div></div><div class="sysinfo-pill"><div class="label">Agent</div><div class="value">${escHtml(data.version||'—')}</div></div><div class="sysinfo-pill"><div class="label">Online</div><div class="value isl-377">${data.online?'Yes':'No'}</div></div></div>`; if (data.uptime) html += `<div class="isl-366">Uptime: ${escHtml(data.uptime)}</div>`; if (data.group) html += `<div class="isl-366">Group: <span class="group-badge">${escHtml(data.group)}</span></div>`; html += '<div class="isl-378">Patch Command History</div>'; if (data.patch_history && data.patch_history.length) { html += data.patch_history.slice().reverse().map(o => `<div class="isl-379"><div class="isl-380"><code class="isl-381">${escHtml(o.cmd)}</code><span class="meta-sm-nm">${new Date(o.ts*1000).toLocaleString()} · rc=${o.rc}</span></div><div class="journal-wrap isl-382">${escHtml(o.output||'(no output)')}</div></div>`).join(''); } else html += '<div class="isl-383">No patch commands recorded yet.</div>'; document.getElementById('device-patch-body').innerHTML = html; }

// ─── v1.7.0: CVE Scanner ──────────────────────────────────────────────────────
let cveReportData = null;
let _cveRegistered = false;

function _registerCveTable() {
  if (_cveRegistered) return;
  _cveRegistered = true;
  tableCtl.register({
    name: 'cves',
    tbody: 'cve-tbody',
    filterInput: 'cve-filter',
    sortHeaders: 'cve-thead',
    colspan: 9,
    columns: ['name', 'group', 'ecosystem', 'critical', 'high', 'medium', 'low', 'last_scan'],
    getColumns: (d) => ({
      name:      d.name || '',
      group:     d.group || '',
      ecosystem: d.ecosystem || '',
      critical:  d.counts?.critical || 0,
      high:      d.counts?.high || 0,
      medium:    d.counts?.medium || 0,
      low:       d.counts?.low || 0,
      last_scan: d.scanned_at || 0,
    }),
    row: (d) => {
      const statusBadge = {
        'scanned':     '<span class="c-green">●</span>',
        'not_scanned': '<span class="c-muted">●</span> not scanned',
        'no_packages': '<span class="c-muted">●</span> no package list',
        'unsupported': '<span class="c-amber">●</span> unsupported',
      }[d.status] || d.status;
      const scanText = d.scanned_at ? new Date(d.scanned_at * 1000).toLocaleString() : statusBadge;
      const cell = (n, color) => n > 0 ? `<td class="isl-384" data-color="${color}">${n}</td>` : '<td class="isl-385">0</td>';
      const cveTotal = (d.counts.critical||0) + (d.counts.high||0) + (d.counts.medium||0) + (d.counts.low||0);
      const prioBtn = cveTotal > 0
        ? `<button class="btn-icon cell-sm" data-stop-prop="1" data-prevent-default="1" data-action-btn="_aiPrioritiseCvesBtn" data-dev-id="${escAttr(d.device_id)}" data-dev-name="${escAttr(d.name)}" title="AI: prioritise this device's CVEs">${_icon('sparkles',14)}</button> `
        : '';
      return `<tr data-action="openDeviceCVE" data-arg="${escAttr(d.device_id)}" data-arg2="${escAttr(d.name)}" class="pointer"><td class="fw-500">${escHtml(d.name)}</td><td class="hint">${d.group ? `<span class="group-badge">${escHtml(d.group)}</span>` : '—'}</td><td class="isl-110">${escHtml(d.ecosystem)}</td>${cell(d.counts.critical, 'var(--red)')}${cell(d.counts.high, '#f97316')}${cell(d.counts.medium, 'var(--amber)')}${cell(d.counts.low, 'var(--muted)')}<td class="meta-sm-nm">${scanText}</td><td>${prioBtn}<button class="btn-icon cell-sm" data-stop-prop="1" data-prevent-default="1" data-action-btn="_forcePackageScanBtn" data-dev-id="${escAttr(d.device_id)}" data-dev-name="${escAttr(d.name)}" title="Ask the agent to send its full installed-package list now">Send list</button> <button class="btn-icon cell-sm" data-stop-prop="1" data-prevent-default="1" data-action-btn="_cveScanBtn" data-dev-id="${escAttr(d.device_id)}" >Scan</button></td></tr>`;
    },
    emptyMsg: 'No devices enrolled.',
    emptyMsgFiltered: 'No CVE rows match the filter.',
  });
}

async function loadCVEReport() {
  _registerCveTable();
  const tbody = document.getElementById('cve-tbody');
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="9"><div class="skeleton skeleton-line long"></div></td></tr>';
  const data = await api('GET', '/cve/findings');
  if (!data) return;
  cveReportData = data;
  document.getElementById('cve-stat-critical').textContent = data.summary.critical;
  document.getElementById('cve-stat-high').textContent = data.summary.high;
  document.getElementById('cve-stat-medium').textContent = data.summary.medium;
  document.getElementById('cve-stat-low').textContent = data.summary.low;
  document.getElementById('cve-stat-devices').textContent = data.summary.devices_scanned;
  tableCtl.render('cves', data.devices || []);
}
async function triggerCVEScan(devId, btn) {
  const label = devId ? 'device' : 'all devices';
  const origText = btn?.textContent || '';
  if (btn) { btn.disabled = true; btn.textContent = 'Scanning…'; }
  toast(`Scanning ${label}… may take a minute`, 'info');
  const body = devId ? {device_id: devId} : {};
  const result = await api('POST', '/cve/scan', body);
  if (btn) {
    const ok = result && !result.errors?.length;
    btn.textContent = ok ? '✓ Done' : '✗ Error';
    btn.style.color = ok ? 'var(--green)' : 'var(--red)';
    btn.disabled = false;
    setTimeout(() => { if (btn.isConnected) { btn.textContent = origText; btn.style.color = ''; } }, 4000);
  }
  if (!result) return;
  const s = result.scanned?.length || 0, k = result.skipped?.length || 0, e = result.errors?.length || 0;
  toast(`Scan complete: ${s} scanned, ${k} skipped, ${e} errors`, e > 0 ? 'error' : 'success');
  loadCVEReport();
}
async function openDeviceCVE(devId, devName) {
  document.getElementById('cve-detail-title').textContent = `CVE Findings: ${devName}`;
  document.getElementById('cve-detail-body').innerHTML = '<div class="empty-state">Loading…</div>';
  openModal('cve-detail-modal');
  const data = await api('GET', `/devices/${devId}/cve`);
  if (!data) return;
  const sevColor = {critical: 'var(--red)', high: '#f97316', medium: 'var(--amber)', low: 'var(--muted)', unknown: 'var(--muted)'};
  let html = `<div class="sysinfo-row mb-16"><div class="sysinfo-pill"><div class="label">Ecosystem</div><div class="value fs-12">${escHtml(data.ecosystem)}</div></div><div class="sysinfo-pill"><div class="label">Packages</div><div class="value">${data.packages_count}</div></div><div class="sysinfo-pill"><div class="label">Last scan</div><div class="value fs-11">${data.scanned_at ? new Date(data.scanned_at*1000).toLocaleString() : 'never'}</div></div><div class="sysinfo-pill"><div class="label">Findings</div><div class="value">${data.findings.length}</div></div></div>`;
  html += `<div class="mb-14"><button class="btn-icon isl-387" data-action-btn="_forcePackageScanBtn" data-dev-id="${escAttr(devId)}" data-dev-name="${escAttr(devName)}" title="Ask the agent to send its full installed-package list now — the CVE scanner compares this against OSV">⟳ Send package list now</button></div>`;
  if (data.error) html += `<div class="isl-388">${escHtml(data.error)}</div>`;
  if (!data.findings.length) { html += '<div class="empty-state">No vulnerabilities found.</div>'; }
  else {
    html += data.findings.map(f => {
      const color = sevColor[f.severity] || 'var(--muted)';
      const refsHtml = (f.refs||[]).slice(0,2).map(r => { try { return `<a href="${escHtml(r)}" target="_blank" class="c-accent">${escHtml(new URL(r).hostname)}</a>`; } catch(e) { return ''; } }).filter(Boolean).join('');
      const aliasesHtml = (f.aliases||[]).map(a => `<code class="isl-389">${escHtml(a)}</code>`).join('');
      return `<div class="isl-390 ${f.ignored?'is-ignored':''}"><div class="isl-391"><div><span class="isl-392" data-color="${color}">${f.severity}</span><code class="isl-393">${escHtml(f.vuln_id)}</code>${f.ignored ? '<span class="isl-394">(ignored: '+escHtml(f.ignore_reason||'')+')</span>' : ''}</div><div class="isl-395">${escHtml(f.published || '')}</div></div><div class="isl-396"><strong>${escHtml(f.package)}</strong> <span class="c-muted">${escHtml(f.version)}</span>${f.fixed_version ? ` → fixed in <span class="c-green">${escHtml(f.fixed_version)}</span>` : ''}</div>${f.summary ? `<div class="hint-mb6">${escHtml(f.summary)}</div>` : ''}<div class="isl-397">${aliasesHtml}${refsHtml}<button class="btn-icon isl-398" data-action="aiTriageCve" data-arg="${escAttr(f.vuln_id)}" data-arg2="${escAttr(f.package)}" data-arg3="${escAttr(f.version)}" data-arg4="${escAttr(devName)}" data-arg5="${escAttr(f.summary||'')}">${_icon('sparkles',14)} Triage</button>${!f.ignored ? `<button class="btn-icon isl-399" data-action="ignoreCVE" data-arg="${escAttr(f.vuln_id)}" data-arg2="${escAttr(devId)}" data-arg3="${escAttr(devName)}" >Ignore</button>` : ''}</div></div>`;
    }).join('');
  }
  document.getElementById('cve-detail-body').innerHTML = html;
}
// v2.4.11: CVE ignore used to use prompt() + confirm() — two native
// dialogs. After a handful of ignores in a row (exactly what doing a
// fleet-wide sweep looks like), browsers suppress repeated dialogs;
// prompt() then returns null, ignoreCVE() silently bailed, and every
// further click did nothing — no request, nothing in the server log,
// the UI apparently "locked". Replaced with an in-page modal, which
// browsers never throttle.
let _cveIgnoreCtx = null;

function ignoreCVE(vulnId, devId, devName) {
  _cveIgnoreCtx = {vulnId, devId, devName};
  document.getElementById('cve-ignore-vuln').textContent = vulnId;
  document.getElementById('cve-ignore-reason').value = '';
  const dev = document.querySelector('input[name="cve-ignore-scope"][value="device"]');
  if (dev) dev.checked = true;
  openModal('cve-ignore-modal');
}

async function _confirmCveIgnore() {
  if (!_cveIgnoreCtx) return;
  const {vulnId, devId, devName} = _cveIgnoreCtx;
  const reason = document.getElementById('cve-ignore-reason').value.trim();
  const scopeSel = document.querySelector('input[name="cve-ignore-scope"]:checked');
  const scope = (scopeSel && scopeSel.value === 'global') ? 'global' : devId;
  const btn = document.getElementById('cve-ignore-confirm');
  if (btn) btn.disabled = true;
  try {
    const result = await api('POST', '/cve/ignore', {vuln_id: vulnId, reason, scope});
    if (result && result.ok) {
      closeModal('cve-ignore-modal');
      toast(`${vulnId} ignored (${scope === 'global' ? 'fleet-wide' : 'this device'})`, 'success');
      openDeviceCVE(devId, devName);
      loadCVEReport();
    }
  } catch (e) {
    toast('Ignore failed: ' + (e.message || String(e)), 'error');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// ─── v1.8.0: Services ─────────────────────────────────────────────────────────
let servicesCurrentDeviceId = null;
let _servicesRegistered = false;

function _registerServicesTable() {
  // v1.11.5: tableCtl wires up filter, sort, and stale-state restoration.
  // Called once on first load — re-registering rebinds the listeners
  // unnecessarily and would double-fire change handlers.
  if (_servicesRegistered) return;
  _servicesRegistered = true;
  tableCtl.register({
    name: 'services',
    tbody: 'services-tbody',
    filterInput: 'services-filter',
    sortHeaders: 'services-thead',
    colspan: 7,
    columns: ['name', 'group', 'watched', 'up', 'down', 'last_report'],
    // Map record to sortable column values. 'watched' is total
    // unit-count; 'last_report' is unix epoch (numeric, sorts cleanly).
    getColumns: (d) => ({
      name:        d.name || '',
      group:       d.group || '',
      watched:     d.total || 0,
      up:          d.up || 0,
      down:        d.down || 0,
      last_report: d.updated_at || 0,
    }),
    match: (d, q) => {
      // Substring across the visible textual data plus unit names so
      // searching "nginx" finds devices whose nginx unit is being watched.
      if ((d.name || '').toLowerCase().includes(q)) return true;
      if ((d.group || '').toLowerCase().includes(q)) return true;
      for (const s of (d.services || [])) {
        if ((s.unit || '').toLowerCase().includes(q)) return true;
      }
      return false;
    },
    row: (d) => {
      const reportText = d.updated_at ? new Date(d.updated_at*1000).toLocaleString() : '<span class="meta-sm-nm">never</span>';
      const unitList = (d.services || []).map(s => {
        const color = s.active === 'active' ? 'var(--green)' : s.active === 'activating' ? 'var(--amber)' : 'var(--red)';
        return `<span class="isl-400"><span class="isl-401" data-color="${color}">●</span> ${escHtml(s.unit)}</span>`;
      }).join('');
      const watchedCell = d.total > 0 ? unitList : '<span class="meta-sm-nm">(none configured)</span>';
      const upCell   = d.up > 0 ? `<td class="isl-402">${d.up}</td>` : '<td class="isl-385">0</td>';
      const downCell = d.down > 0 ? `<td class="isl-403">${d.down}</td>` : '<td class="isl-385">0</td>';
      return `<tr data-action="openServiceDetail" data-arg="${escAttr(d.device_id)}" data-arg2="${escAttr(d.name)}" class="pointer">
        <td class="fw-500">${escHtml(d.name)}</td>
        <td class="hint">${d.group ? `<span class="group-badge">${escHtml(d.group)}</span>` : '—'}</td>
        <td>${watchedCell}</td>
        ${upCell}${downCell}
        <td class="meta-sm-nm">${reportText}</td>
        <td><button class="btn-icon cell-sm" data-stop-prop="1" data-action="editServicesConfig" data-arg="${escAttr(d.device_id)}" data-arg2="${escAttr(d.name)}" >Configure</button></td>
      </tr>`;
    },
    emptyMsg: 'No devices enrolled.',
    emptyMsgFiltered: 'No services match the filter.',
  });
}

async function loadServicesReport() {
  _registerServicesTable();
  const tbody = document.getElementById('services-tbody');
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr>';
  const data = await api('GET', '/services');
  if (!data) return;
  // Also fetch maintenance badge
  const maint = await api('GET', '/maintenance');
  const active = (maint?.windows || []).filter(w => w.active).length;
  if (active > 0) {
    // CSP L1: the badge's initial-hide lives in .isl-138 (CSS class);
    // setting `display = ''` would leave it hidden. Explicit value wins.
    document.getElementById('services-maint-badge').style.display = 'inline-block';
    document.getElementById('services-maint-count').textContent = active;
  } else {
    document.getElementById('services-maint-badge').style.display = 'none';
  }

  let totalUp = 0, totalDown = 0, totalUnits = 0, devsReporting = 0;
  for (const d of data.devices) {
    totalUp += d.up; totalDown += d.down; totalUnits += d.total;
    if (d.total > 0) devsReporting++;
  }
  document.getElementById('services-stat-up').textContent = totalUp;
  document.getElementById('services-stat-down').textContent = totalDown;
  document.getElementById('services-stat-devices').textContent = devsReporting;
  document.getElementById('services-stat-total').textContent = totalUnits;

  tableCtl.render('services', data.devices || []);
}

async function openServiceDetail(devId, devName) {
  servicesCurrentDeviceId = devId;
  document.getElementById('service-detail-title').textContent = `Services: ${devName}`;
  document.getElementById('service-detail-body').innerHTML = '<div class="empty-state">Loading…</div>';
  document.getElementById('service-edit-btn').onclick = () => { closeModal('service-detail-modal'); editServicesConfig(devId, devName); };
  openModal('service-detail-modal');
  const data = await api('GET', `/devices/${devId}/services`);
  if (!data) return;
  const updated = data.updated_at ? new Date(data.updated_at*1000).toLocaleString() : 'never';
  let html = `<div class="sysinfo-row mb-16"><div class="sysinfo-pill"><div class="label">Units watched</div><div class="value">${data.services.length}</div></div><div class="sysinfo-pill"><div class="label">Last report</div><div class="value fs-11">${updated}</div></div></div>`;
  if (!data.services.length) {
    html += '<div class="empty-state">No services configured. Click "Edit watched units" below.</div>';
  } else {
    html += data.services.map(s => {
      const color = s.active === 'active' ? 'var(--green)' : s.active === 'activating' ? 'var(--amber)' : 'var(--red)';
      const sinceText = s.since ? new Date(s.since*1000).toLocaleString() : '—';
      const histItems = (s.history || []).slice().reverse();
      const logItems  = (s.log_tail || []).slice(-20);

      const histBody = histItems.length
        ? histItems.map(h => `<div class="isl-404">${new Date(h.ts*1000).toLocaleString()}: ${escHtml(h.from||'?')} → ${escHtml(h.to||'?')}</div>`).join('')
        : '<div class="isl-405">No transitions recorded since enrollment.</div>';

      const logBody = logItems.length
        ? logItems.map(l => `<div class="journal-line">${escHtml(l.line || '')}</div>`).join('')
        : '<div class="isl-405">No logs captured yet. Agent submits every ~5 min; needs v1.8.0+ and journalctl access (run as root).</div>';

      const histLabel = `State history (${histItems.length})`;
      const logLabel  = `Recent logs (${logItems.length})`;

      // v2.1.5: AIDiagnose for units that aren't actively running.
      // Pure-prose summary "service is failed, here's what to check
      // next" — the operator still does the actual work.
      const isUnhealthy = s.active !== 'active' && s.active !== 'activating';
      const aiBtn = isUnhealthy
        ? `<button class="btn-icon isl-406" data-action-btn="_aiDiagnoseServiceFromStore" data-store-key="${_storeEvtData([s.unit, devName, s.active||'', s.sub||'', (s.log_tail || []).slice(-30).map(l => l.line || '')])}" title="AI: diagnose this service">${_icon('sparkles',14)} Diagnose</button>`
        : '';

      return `<div class="isl-379">
        <div class="isl-407">
          <div class="isl-408"><span class="isl-409" data-color="${color}">●</span> <code class="isl-410">${escHtml(s.unit)}</code> <span class="isl-411">${escHtml(s.active)}${s.sub?' / '+escHtml(s.sub):''}</span>${aiBtn}</div>
          <div class="meta-sm-nm">since: ${sinceText}</div>
        </div>
        <details${histItems.length ? ' open' : ''} class="mb-6"><summary class="isl-412">${histLabel}</summary><div class="isl-413">${histBody}</div></details>
        <details${logItems.length ? ' open' : ''}><summary class="isl-412">${logLabel}</summary><div class="journal-wrap isl-414">${logBody}</div></details>
      </div>`;
    }).join('');
  }
  document.getElementById('service-detail-body').innerHTML = html;
}

async function editServicesConfig(devId, devName) {
  const cfg = await api('GET', `/devices/${devId}/services/config`);
  if (!cfg) return;
  document.getElementById('service-edit-textarea').value = (cfg.services_watched || []).join('\n');
  document.getElementById('service-edit-save').onclick = async () => {
    const lines = document.getElementById('service-edit-textarea').value.split('\n').map(s => s.trim()).filter(Boolean);
    const result = await api('POST', `/devices/${devId}/services/config`, {services_watched: lines, log_watch: cfg.log_watch || []});
    if (result && result.ok) {
      toast(`Saved: ${result.services_watched.length} unit(s) for ${devName}`, 'success');
      closeModal('service-edit-modal');
      loadServicesReport();
    }
  };
  openModal('service-edit-modal');
}

// ─── v1.8.0: Maintenance ──────────────────────────────────────────────────────

// v1.11.6: maintenance windows get filter+sort via tableCtl.
let _maintRegistered = false;
function _registerMaintTable() {
  if (_maintRegistered) return;
  _maintRegistered = true;
  tableCtl.register({
    name: 'maintenance',
    tbody: 'maint-tbody',
    filterInput: 'maint-filter',
    sortHeaders: 'maint-thead',
    colspan: 7,
    columns: ['reason', 'scope', 'target', 'when', 'events', 'status'],
    getColumns: (w) => ({
      reason: w.reason || '',
      scope:  w.scope || '',
      target: w.target_name || w.target || '',
      // 'when' as a sortable thing is messy — for cron we sort by the
      // cron string; for fixed windows we sort by start. Good enough.
      when:   w.cron || w.start || '',
      events: (w.events || []).join(','),
      // active first when ascending → sort 'active' before 'scheduled'
      // alphabetically. Fine.
      status: w.active ? 'active' : 'scheduled',
    }),
    row: (w) => {
      const when = w.cron ? `<code class="fs-11">${escHtml(w.cron)}</code> for ${Math.round((w.duration||0)/60)}min`
                          : `${escHtml(w.start||'?')} → ${escHtml(w.end||'?')}`;
      const events = (w.events && w.events.length) ? w.events.join(', ') : '<em class="c-muted">all</em>';
      const status = w.active
        ? '<span class="c-amber-bold"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="12" height="12" aria-hidden="true"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg> ACTIVE</span>'
        : '<span class="c-muted">scheduled</span>';
      const target = w.scope === 'global' ? '—' : escHtml(w.target_name || w.target || '—');
      const winKey = _storeEvtData(w);
      return `<tr>
        <td class="fw-500">${escHtml(w.reason || '(no reason)')}</td>
        <td><span class="group-badge">${escHtml(w.scope)}</span></td>
        <td class="isl-415">${target}</td>
        <td class="fs-12">${when}</td>
        <td class="meta-sm-nm">${events}</td>
        <td class="ta-center">${status}</td>
        <td><button class="btn-icon isl-416" data-action-btn="_editMaintenanceBtn" data-store-key="${winKey}">Edit</button> <button class="btn-icon isl-416" data-action="deleteMaintenance" data-arg="${escAttr(w.id)}" >Delete</button></td>
      </tr>`;
    },
    emptyMsg: 'No maintenance windows defined.',
    emptyMsgFiltered: 'No windows match the filter.',
  });
}

async function loadMaintenance() {
  _registerMaintTable();
  const tbody = document.getElementById('maint-tbody');
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr>';
  const data = await api('GET', '/maintenance');
  if (!data) return;
  tableCtl.render('maintenance', data.windows || []);
}

async function loadMaintSuppressions() {
  const section = document.getElementById('maint-suppressions');
  section.style.display = 'block';
  const tbody = document.getElementById('maint-supp-tbody');
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="5"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="5"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="5"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="5"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="5"><div class="skeleton skeleton-line long"></div></td></tr>';
  const data = await api('GET', '/maintenance/suppressions');
  if (!data) return;
  if (!data.entries.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty-state-sm">No suppressions recorded.</td></tr>'; return; }
  tbody.innerHTML = data.entries.map(e => `<tr>
    <td class="hint-nowrap">${new Date(e.ts*1000).toLocaleString()}</td>
    <td><code class="fs-12">${escHtml(e.event)}</code></td>
    <td class="isl-341">${escHtml(e.device_id || '—')}</td>
    <td class="isl-417">${escHtml(e.window_id || '—')}</td>
    <td class="fs-12">${escHtml(e.reason || '')}</td>
  </tr>`).join('');
}

async function deleteMaintenance(winId) {
  if (!confirm('Delete this maintenance window?')) return;
  const result = await api('DELETE', `/maintenance/${winId}`);
  if (result && result.ok) { toast('Window deleted', 'success'); loadMaintenance(); }
}

// v3.3.0: maintenance modal carries an "editing" pointer so save can
// PUT instead of POST. Null = Add mode; the window's id = Edit mode.
let _maintEditingId = null;

async function openNewMaintModal() {
  _maintEditingId = null;
  const titleEl = document.querySelector('#new-maint-modal .modal-title');
  if (titleEl) titleEl.textContent = 'New maintenance window';
  // Populate device dropdown
  const devs = await api('GET', '/devices');
  const sel = document.getElementById('maint-target-device');
  sel.innerHTML = '';
  if (devs) {
    for (const d of (devs.devices || devs)) {
      const opt = document.createElement('option');
      opt.value = d.id || d.device_id;
      opt.textContent = (d.name || d.id) + (d.group ? ' ['+d.group+']' : '');
      sel.appendChild(opt);
    }
  }
  // Reset form
  document.getElementById('maint-reason').value = '';
  document.getElementById('maint-scope').value = 'device';
  document.getElementById('maint-type').value = 'oneshot';
  document.getElementById('maint-cron').value = '';
  document.getElementById('maint-duration').value = 60;
  document.querySelectorAll('.maint-event-cb').forEach(cb => cb.checked = false);
  // Default start/end: now+5min, now+65min
  const pad = n => n.toString().padStart(2,'0');
  const toLocal = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const now = new Date();
  const start = new Date(now.getTime() + 5*60000);
  const end = new Date(now.getTime() + 65*60000);
  document.getElementById('maint-start').value = toLocal(start);
  document.getElementById('maint-end').value = toLocal(end);
  onMaintScopeChange(); onMaintTypeChange();
  openModal('new-maint-modal');
}

async function _editMaintenanceBtn(btn) {
  const w = _evtData.get(btn.dataset.storeKey);
  if (!w) return;
  // First populate the device dropdown so we can select the right one.
  const devs = await api('GET', '/devices');
  const sel = document.getElementById('maint-target-device');
  sel.innerHTML = '';
  if (devs) {
    for (const d of (devs.devices || devs)) {
      const opt = document.createElement('option');
      opt.value = d.id || d.device_id;
      opt.textContent = (d.name || d.id) + (d.group ? ' ['+d.group+']' : '');
      sel.appendChild(opt);
    }
  }
  _maintEditingId = w.id;
  const titleEl = document.querySelector('#new-maint-modal .modal-title');
  if (titleEl) titleEl.textContent = 'Edit maintenance window';
  document.getElementById('maint-reason').value = w.reason || '';
  document.getElementById('maint-scope').value  = w.scope  || 'device';
  if (w.scope === 'device') sel.value = w.target || '';
  else if (w.scope === 'group') document.getElementById('maint-target-group').value = w.target || '';
  const isCron = !!(w.cron && w.duration);
  document.getElementById('maint-type').value = isCron ? 'cron' : 'oneshot';
  if (isCron) {
    document.getElementById('maint-cron').value     = w.cron || '';
    document.getElementById('maint-duration').value = String(Math.round((w.duration || 60) / 60));
  } else {
    const pad = n => n.toString().padStart(2,'0');
    const toLocal = iso => {
      if (!iso) return '';
      const d = new Date(iso);
      return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    };
    document.getElementById('maint-start').value = toLocal(w.start);
    document.getElementById('maint-end').value   = toLocal(w.end);
  }
  // Restore event-suppression tickboxes
  const wantedEvents = new Set(w.events || []);
  document.querySelectorAll('.maint-event-cb').forEach(cb => {
    cb.checked = wantedEvents.has(cb.value);
  });
  onMaintScopeChange(); onMaintTypeChange();
  openModal('new-maint-modal');
}

function onMaintScopeChange() {
  const scope = document.getElementById('maint-scope').value;
  const row = document.getElementById('maint-target-row');
  const selDev = document.getElementById('maint-target-device');
  const txtGrp = document.getElementById('maint-target-group');
  if (scope === 'global') { row.style.display = 'none'; return; }
  row.style.display = 'block';
  if (scope === 'device') { selDev.style.display = 'block'; txtGrp.style.display = 'none'; }
  else                    { selDev.style.display = 'none'; txtGrp.style.display = 'block'; }
}

function onMaintTypeChange() {
  const t = document.getElementById('maint-type').value;
  document.getElementById('maint-oneshot-row').style.display = (t === 'oneshot') ? '' : 'none';
  document.getElementById('maint-cron-row').style.display    = (t === 'cron')    ? '' : 'none';
}

async function saveMaintenance() {
  const reason = document.getElementById('maint-reason').value.trim();
  const scope  = document.getElementById('maint-scope').value;
  const type   = document.getElementById('maint-type').value;
  let target = '';
  if (scope === 'device') target = document.getElementById('maint-target-device').value;
  else if (scope === 'group') target = document.getElementById('maint-target-group').value.trim();
  const events = Array.from(document.querySelectorAll('.maint-event-cb'))
    .filter(cb => cb.checked).map(cb => cb.value);

  const body = {reason, scope, target, events};
  if (type === 'oneshot') {
    const s = document.getElementById('maint-start').value;
    const e = document.getElementById('maint-end').value;
    if (!s || !e) { toast('Start and end are required', 'error'); return; }
    // Convert local datetime-local → ISO UTC
    body.start = new Date(s).toISOString();
    body.end   = new Date(e).toISOString();
  } else {
    body.cron = document.getElementById('maint-cron').value.trim();
    body.duration = parseInt(document.getElementById('maint-duration').value) * 60;
  }
  const result = _maintEditingId
    ? await api('PUT',  `/maintenance/${_maintEditingId}`, body)
    : await api('POST', '/maintenance', body);
  if (result && result.ok) {
    toast(_maintEditingId ? 'Maintenance window updated' : 'Maintenance window created', 'success');
    _maintEditingId = null;
    closeModal('new-maint-modal');
    loadMaintenance();
  } else {
    toast(result?.error || 'Failed to save window', 'error');
  }
}

// ─── v1.8.1: Logs page ───────────────────────────────────────────────────────
let logsState = {
  timer:     null,        // interval id for live tail polling
  newestTs:  0,           // monotonic cursor for /api/logs/tail
  lines:     [],          // in-memory buffer of currently-displayed lines
  maxLines:  1000,        // client-side cap — keep DOM cheap
  searchMode: false,      // true = showing search results, false = live tail
  devicesCache: [],       // for filter dropdown
};

async function enterLogsPage() {
  // Populate device/unit dropdowns from current state
  await refreshLogsFilters();
  await loadLogRules();
  // Set the initial tab styling to match state (defaults to per-device)
  switchRulesTab(logsRulesTab);
  startLogsTail();
}

function leaveLogsPage() {
  if (logsState.timer) {
    clearInterval(logsState.timer);
    logsState.timer = null;
  }
}

async function refreshLogsFilters() {
  const devSel = document.getElementById('logs-device-filter');
  const prevDev = devSel.value;
  // Load devices list (reuse whatever api returns for /devices)
  const devs = await api('GET', '/devices');
  const list = devs?.devices || devs || [];
  logsState.devicesCache = list;
  devSel.innerHTML = '<option value="">All devices</option>' +
    list.map(d => `<option value="${escHtml(d.id || d.device_id)}">${escHtml(d.name || d.id)}${d.group ? ' ['+escHtml(d.group)+']' : ''}</option>`).join('');
  devSel.value = prevDev;
}

function startLogsTail() {
  logsState.searchMode = false;
  logsState.newestTs = 0;
  logsState.lines = [];
  document.getElementById('logs-viewer-title').textContent = 'Live tail — auto-refreshing every 30s';
  document.getElementById('logs-viewer').innerHTML = '<div class="isl-418">Fetching recent lines…</div>';
  // Initial pull: everything from last 10 min
  logsState.newestTs = Math.floor(Date.now()/1000) - 600;
  pollLogsTail(true);
  if (logsState.timer) clearInterval(logsState.timer);
  logsState.timer = setInterval(() => pollLogsTail(false), 30000);
}

async function pollLogsTail(initial) {
  if (logsState.searchMode) return;
  const qs = new URLSearchParams();
  qs.set('since', String(logsState.newestTs));
  const dev = document.getElementById('logs-device-filter').value;
  const unit = document.getElementById('logs-unit-filter').value;
  if (dev) qs.set('device', dev);
  if (unit) qs.set('unit', unit);
  qs.set('limit', '500');
  const data = await api('GET', `/logs/tail?${qs.toString()}`);
  if (!data) return;
  // Update stats
  document.getElementById('logs-stat-lines').textContent = data.stats.total_lines;
  document.getElementById('logs-stat-devices').textContent = data.stats.devices_reporting;

  if (data.lines.length) {
    logsState.newestTs = data.newest_ts;
    logsState.lines = logsState.lines.concat(data.lines);
    if (logsState.lines.length > logsState.maxLines) {
      logsState.lines = logsState.lines.slice(-logsState.maxLines);
    }
    const last = logsState.lines[logsState.lines.length - 1];
    document.getElementById('logs-stat-last').textContent = last ? relTime(last.ts) : '—';
    renderLogsViewer();
  } else if (initial) {
    // v1.8.2: three distinct empty states for clearer diagnosis
    let msg;
    if (data.stats.devices_reporting === 0) {
      msg = '<div class="empty-state">'
          + 'No devices are submitting logs yet.<br>'
          + '<span class="fs-11">1) Configure watched services on the <a href="#" data-action-btn="_homeNavAction" data-home-act="services" data-prevent-default class="c-accent">Services page</a>. '
          + '2) Agents submit every ~5 min. 3) Agent must be v1.8.0+ and have journalctl access.</span></div>';
    } else if (data.stats.total_lines === 0) {
      msg = `<div class="empty-state">`
          + `${data.stats.devices_reporting} device(s) are reporting, but watched units have been quiet.<br>`
          + `<span class="fs-11">This is normal for stable services. Logs appear here when agents capture something.</span></div>`;
    } else {
      msg = `<div class="empty-state">`
          + `${data.stats.total_lines} line(s) in the buffer, but none match the current filter.<br>`
          + `<span class="fs-11">Try clearing the device/unit filters above.</span></div>`;
    }
    document.getElementById('logs-viewer').innerHTML = msg;
  }

  // Refresh unit dropdown from discovered units
  const allUnits = new Set();
  for (const l of logsState.lines) allUnits.add(l.unit);
  const unitSel = document.getElementById('logs-unit-filter');
  const prevUnit = unitSel.value;
  if (allUnits.size) {
    const sorted = Array.from(allUnits).sort();
    if (unitSel.options.length - 1 !== sorted.length) {
      unitSel.innerHTML = '<option value="">All units</option>' +
        sorted.map(u => `<option value="${escHtml(u)}">${escHtml(u)}</option>`).join('');
      unitSel.value = prevUnit;
    }
  }
}

function renderLogsViewer() {
  const viewer = document.getElementById('logs-viewer');
  const wasAtBottom = (viewer.scrollHeight - viewer.scrollTop - viewer.clientHeight) < 30;
  viewer.innerHTML = logsState.lines.map(l => {
    const color = lineSeverityColor(l.line);
    const ts = new Date(l.ts*1000).toLocaleTimeString();
    return `<div class="isl-419" data-color="${color||''}">`
      + `<span class="c-muted">${ts}</span> `
      + `<span class="c-accent">${escHtml(l.name)}</span> `
      + `<span class="c-muted">${escHtml(l.unit)}</span>  `
      + escHtml(l.line)
      + `</div>`;
  }).join('');
  // Always-on polling (v1.8.2). Auto-scroll respects user's checkbox + whether
  // they were already at the bottom — so manual scroll-up to read older lines
  // still works within a poll window; next poll jumps them down again unless
  // they uncheck auto-scroll.
  const autoScroll = document.getElementById('logs-autoscroll').checked;
  if (autoScroll && wasAtBottom) {
    viewer.scrollTop = viewer.scrollHeight;
  }
}

function lineSeverityColor(line) {
  if (!line) return '';
  if (/(?:\b|_)(FATAL|CRITICAL|emergency|panic)(?:\b|_)/i.test(line)) return 'var(--red)';
  if (/(?:\b|_)(ERROR|ERR)(?:\b|_)|\berror:/i.test(line)) return '#f97316';
  if (/(?:\b|_)(WARN(?:ING)?)(?:\b|_)/i.test(line)) return 'var(--amber)';
  return '';
}

function relTime(ts) {
  if (!ts) return '—';
  const delta = Math.floor(Date.now()/1000 - ts);
  if (delta < 60) return `${delta}s ago`;
  if (delta < 3600) return `${Math.floor(delta/60)}m ago`;
  if (delta < 86400) return `${Math.floor(delta/3600)}h ago`;
  return `${Math.floor(delta/86400)}d ago`;
}

function onLogFilterChange() {
  // Changing a filter resets the tail so we don't show stale unfiltered lines
  if (!logsState.searchMode) startLogsTail();
}

async function runLogSearch() {
  const q = document.getElementById('logs-search-input').value.trim();
  if (!q) { clearLogSearch(); return; }
  logsState.searchMode = true;
  if (logsState.timer) { clearInterval(logsState.timer); logsState.timer = null; }
  const dev = document.getElementById('logs-device-filter').value;
  const qs = new URLSearchParams({q, limit: '500'});
  if (dev) qs.set('device', dev);
  document.getElementById('logs-viewer-title').textContent = `Search results for: ${q}`;
  document.getElementById('logs-viewer').innerHTML = '<div class="isl-418">Searching…</div>';
  const data = await api('GET', `/logs/search?${qs.toString()}`);
  if (!data) {
    document.getElementById('logs-viewer').innerHTML = '<div class="isl-420">Request failed — check the console.</div>';
    return;
  }
  // v3.0.2: 400 returns {error: '...'} with no results key — was throwing
  // TypeError on data.results.length and silently breaking the UI.
  if (data.error) {
    document.getElementById('logs-viewer').innerHTML =
      `<div class="isl-420">
        <div class="isl-421">Search failed</div>
        <div class="c-muted-13">${escHtml(data.error)}</div>
        <div class="isl-422">Common cause: bad regex. Try escaping special chars or use a plain substring.</div>
      </div>`;
    toast('Search error: ' + data.error, 'error');
    return;
  }
  if (!Array.isArray(data.results) || !data.results.length) {
    document.getElementById('logs-viewer').innerHTML = `<div class="empty-state">No matches for <code>${escHtml(q)}</code> in the current buffer.</div>`;
    return;
  }
  // Group by device (per user preference from planning)
  const byDev = {};
  for (const r of data.results) {
    if (!byDev[r.device_id]) byDev[r.device_id] = {name: r.name, lines: []};
    byDev[r.device_id].lines.push(r);
  }
  let html = `<div class="hint-mb">${data.count} match${data.count===1?'':'es'} across ${Object.keys(byDev).length} device${Object.keys(byDev).length===1?'':'s'}</div>`;
  for (const [dev_id, g] of Object.entries(byDev)) {
    html += `<details open class="mb-8"><summary class="isl-423">${escHtml(g.name)} <span class="meta-sm-nm">(${g.lines.length})</span></summary>`;
    html += g.lines.map(l => {
      const color = lineSeverityColor(l.line);
      return `<div class="isl-424" data-color="${color||''}"><span class="c-muted">${new Date(l.ts*1000).toLocaleString()}</span> <span class="c-muted">${escHtml(l.unit)}</span>  ${escHtml(l.line)}</div>`;
    }).join('');
    html += `</details>`;
  }
  document.getElementById('logs-viewer').innerHTML = html;
}

function clearLogSearch() {
  document.getElementById('logs-search-input').value = '';
  startLogsTail();
}

// ─── Alert rules (v1.8.2: per-device + fleet-wide tabs) ────────────────────
let logsRulesTab = 'device';  // 'device' | 'global'

function switchRulesTab(tab) {
  logsRulesTab = tab;
  // CSP L1 (v3.0.5): the Fleet-wide tab's wrapper has .d-none in its
  // initial markup (display:none from the utility class). Setting
  // style.display = '' only clears the inline attribute, leaving the
  // class rule in effect — the user reported "Fleet-wide tab not
  // loading". Use explicit 'block' to beat the class.
  document.getElementById('logs-rules-device-wrap').style.display = (tab === 'device') ? 'block' : 'none';
  document.getElementById('logs-rules-global-wrap').style.display = (tab === 'global') ? 'block' : 'none';
  // Style the active tab
  const dBtn = document.getElementById('logs-tab-device');
  const gBtn = document.getElementById('logs-tab-global');
  const active = 'background:var(--surface2);border-bottom:1px solid var(--surface2)';
  const inactive = 'background:var(--surface);border-bottom:1px solid var(--border)';
  dBtn.style.cssText = 'border-radius:6px 6px 0 0;' + (tab === 'device' ? active : inactive);
  gBtn.style.cssText = 'border-radius:6px 6px 0 0;' + (tab === 'global' ? active : inactive);
  if (tab === 'global') loadGlobalLogRules();
}

async function loadLogRules() {
  // Load both tables; one is hidden
  await Promise.all([loadPerDeviceLogRules(), loadGlobalLogRules()]);
}

async function loadPerDeviceLogRules() {
  const tbody = document.getElementById('logs-rules-tbody');
  const data = await api('GET', '/logs/rules');
  if (!data) return;
  const globalCount = parseInt(document.getElementById('logs-stat-rules').dataset.globalCount || '0');
  document.getElementById('logs-stat-rules').textContent = data.rules.length + globalCount;
  document.getElementById('logs-stat-rules').dataset.deviceCount = data.rules.length;
  if (!data.rules.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state-sm">No per-device rules configured.</td></tr>';
    return;
  }
  tbody.innerHTML = data.rules.map(r => {
    // Encode the rule's identifying fields into a single store key so
    // the Edit button can rehydrate the rule into the modal without a
    // second round-trip.
    const ruleKey = _storeEvtData({scope: 'device', rule: r});
    return `<tr>
      <td class="fw-500">${escHtml(r.device_name)}</td>
      <td>${r.group ? `<span class="group-badge">${escHtml(r.group)}</span>` : '<span class="c-muted">—</span>'}</td>
      <td><code class="fs-12">${escHtml(r.unit)}</code></td>
      <td><code class="isl-425">${escHtml(r.pattern)}</code></td>
      <td class="ta-center">≥ ${r.threshold}</td>
      <td><button class="btn-icon isl-416" data-action-btn="_editLogRuleBtn" data-store-key="${ruleKey}">Edit</button> <button class="btn-icon isl-416" data-action="deleteLogRule" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.unit)}" data-arg3="${escAttr(r.pattern)}" >Delete</button></td>
    </tr>`;
  }).join('');
}

async function loadGlobalLogRules() {
  const tbody = document.getElementById('logs-rules-global-tbody');
  const data = await api('GET', '/logs/rules/global');
  if (!data) return;
  const deviceCount = parseInt(document.getElementById('logs-stat-rules').dataset.deviceCount || '0');
  document.getElementById('logs-stat-rules').textContent = deviceCount + data.rules.length;
  document.getElementById('logs-stat-rules').dataset.globalCount = data.rules.length;
  if (!data.rules.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state-sm">No fleet-wide rules configured. Click "+ Add rule" above and switch to the Fleet-wide tab.</td></tr>';
    return;
  }
  tbody.innerHTML = data.rules.map(r => {
    const created = r.created_at ? new Date(r.created_at*1000).toLocaleDateString() : '—';
    const unitDisplay = r.unit === '*'
      ? '<code class="isl-426">* (any unit)</code>'
      : `<code class="fs-12">${escHtml(r.unit)}</code>`;
    const excludeCell = r.exclude_pattern
      ? `<code class="isl-425 c-muted" title="Excluded">≠ ${escHtml(r.exclude_pattern)}</code>`
      : '<span class="c-muted">—</span>';
    const ruleKey = _storeEvtData({scope: 'global', rule: r});
    return `<tr>
      <td>${unitDisplay}</td>
      <td><code class="isl-425">${escHtml(r.pattern)}</code></td>
      <td>${excludeCell}</td>
      <td class="ta-center">≥ ${r.threshold}</td>
      <td class="meta-sm-nm">${created} <span class="opacity-60">by ${escHtml(r.created_by || '?')}</span></td>
      <td><button class="btn-icon isl-416" data-action-btn="_editLogRuleBtn" data-store-key="${ruleKey}">Edit</button> <button class="btn-icon isl-416" data-action="deleteGlobalLogRule" data-arg="${escAttr(r.id)}" >Delete</button></td>
    </tr>`;
  }).join('');
}

// v3.3.0: state carried by the log-rule modal across the
// "Add" and "Edit" entry points. When editing, we remember the
// scope + identifying fields so saveLogRule() can do a replace
// instead of an append.
let _logRuleEditing = null;

async function openAddRuleModal() {
  _logRuleEditing = null;
  const isGlobal = (logsRulesTab === 'global');
  document.getElementById('log-rule-modal-title').textContent =
    isGlobal ? 'Add fleet-wide log alert rule' : 'Add per-device log alert rule';
  document.getElementById('log-rule-device-row').style.display = isGlobal ? 'none' : '';
  document.getElementById('log-rule-global-hint').style.display = isGlobal ? '' : 'none';
  document.getElementById('log-rule-unit-hint').style.display = isGlobal ? '' : 'none';
  if (!isGlobal) {
    const sel = document.getElementById('log-rule-device');
    sel.innerHTML = logsState.devicesCache.map(d => `<option value="${escHtml(d.id || d.device_id)}">${escHtml(d.name || d.id)}</option>`).join('');
  }
  document.getElementById('log-rule-unit').value = '';
  document.getElementById('log-rule-unit').placeholder = isGlobal ? 'sshd.service  (or *)' : 'nginx.service';
  document.getElementById('log-rule-pattern').value = '';
  document.getElementById('log-rule-threshold').value = '1';
  document.getElementById('log-rule-exclude').value = '';
  document.getElementById('log-rule-template').value = '';
  document.querySelector('input[name="log-rule-source"][value="unit"]').checked = true;
  _toggleLogRuleSource();
  _renderLogTemplatePreview();
  openModal('log-rule-modal');
}

// Open the same modal pre-filled from an existing rule. Wired from the
// Edit button next to each rule row.
function _editLogRuleBtn(btn) {
  const data = _evtData.get(btn.dataset.storeKey);
  if (!data || !data.rule) return;
  const r = data.rule;
  const isGlobal = data.scope === 'global';
  logsRulesTab = isGlobal ? 'global' : 'device';
  _logRuleEditing = {scope: data.scope, rule: r};
  document.getElementById('log-rule-modal-title').textContent =
    isGlobal ? 'Edit fleet-wide log alert rule' : 'Edit per-device log alert rule';
  document.getElementById('log-rule-device-row').style.display = isGlobal ? 'none' : '';
  document.getElementById('log-rule-global-hint').style.display = isGlobal ? '' : 'none';
  document.getElementById('log-rule-unit-hint').style.display = isGlobal ? '' : 'none';
  // Source toggle (unit vs file path)
  const isPath = !!r.path;
  document.querySelector(`input[name="log-rule-source"][value="${isPath ? 'path' : 'unit'}"]`).checked = true;
  _toggleLogRuleSource();
  if (!isGlobal) {
    const sel = document.getElementById('log-rule-device');
    sel.innerHTML = logsState.devicesCache.map(d => `<option value="${escHtml(d.id || d.device_id)}">${escHtml(d.name || d.id)}</option>`).join('');
    if (r.device_id) sel.value = r.device_id;
  }
  document.getElementById('log-rule-unit').value     = isPath ? '' : (r.unit || '');
  document.getElementById('log-rule-path').value     = r.path || '';
  document.getElementById('log-rule-pattern').value  = r.pattern || '';
  document.getElementById('log-rule-threshold').value = String(r.threshold || 1);
  document.getElementById('log-rule-severity').value = (r.severity || 'WARN');
  document.getElementById('log-rule-exclude').value  = r.exclude_pattern || '';
  document.getElementById('log-rule-template').value = r.display_template || '';
  _renderLogTemplatePreview();
  openModal('log-rule-modal');
}

async function saveLogRule() {
  const sourceType = document.querySelector('input[name="log-rule-source"]:checked')?.value || 'unit';
  const unit       = document.getElementById('log-rule-unit').value.trim();
  const path       = document.getElementById('log-rule-path').value.trim();
  const pattern    = document.getElementById('log-rule-pattern').value.trim();
  const threshold  = parseInt(document.getElementById('log-rule-threshold').value) || 1;
  const severity   = document.getElementById('log-rule-severity')?.value || 'WARN';
  if (sourceType === 'unit' && !unit) { toast('Unit is required', 'error'); return; }
  if (sourceType === 'path' && !path) { toast('File path is required', 'error'); return; }
  if (sourceType === 'path' && !path.startsWith('/')) { toast('File path must be absolute (start with /)', 'error'); return; }
  if (!pattern) { toast('Pattern is required', 'error'); return; }
  const excludePattern = document.getElementById('log-rule-exclude').value.trim();
  const displayTemplate = document.getElementById('log-rule-template').value.trim();
  // Validate regex client-side
  try { new RegExp(pattern); } catch(e) { toast('Invalid regex: '+e.message, 'error'); return; }
  if (excludePattern) {
    try { new RegExp(excludePattern); } catch(e) { toast('Invalid exclude regex: '+e.message, 'error'); return; }
  }
  // Validate template placeholders client-side; server validates again.
  if (displayTemplate) {
    const allowed = new Set(['device','unit','pattern','count','sample','sample0','sample1','sample2']);
    const bad = (displayTemplate.match(/\{([^{}]*)\}/g) || [])
      .map(s => s.slice(1, -1))
      .filter(t => !allowed.has(t));
    if (bad.length) { toast(`Unknown template placeholder: {${bad[0]}}`, 'error'); return; }
  }

  // Build the rule payload. Server validates either unit OR path.
  const rulePayload = sourceType === 'path'
    ? { path, pattern, threshold, severity }
    : { unit, pattern, threshold, severity };
  if (excludePattern) rulePayload.exclude_pattern = excludePattern;
  if (displayTemplate) rulePayload.display_template = displayTemplate;

  if (logsRulesTab === 'global') {
    // Fleet-wide rule. When editing, PUT against the rule's id;
    // otherwise POST to create.
    let result;
    if (_logRuleEditing && _logRuleEditing.scope === 'global' && _logRuleEditing.rule.id) {
      result = await api('PUT', `/logs/rules/global/${_logRuleEditing.rule.id}`, rulePayload);
    } else {
      result = await api('POST', '/logs/rules/global', rulePayload);
    }
    if (result && result.ok) {
      toast(_logRuleEditing ? 'Fleet-wide rule updated' : 'Fleet-wide rule added', 'success');
      _logRuleEditing = null;
      closeModal('log-rule-modal');
      loadGlobalLogRules();
    } else {
      toast(result?.error || 'Failed to save rule', 'error');
    }
    return;
  }

  // Per-device rule. For both add and edit, we POST the full
  // services-config back to the server.
  const devId = document.getElementById('log-rule-device').value;
  if (!devId) { toast('Device is required', 'error'); return; }
  const existing = await api('GET', `/devices/${devId}/services/config`);
  if (!existing) return;
  let log_watch = existing.log_watch || [];
  const effectiveUnit = sourceType === 'path' ? `file:${path}` : unit;
  const isEdit = !!(_logRuleEditing && _logRuleEditing.scope === 'device');
  if (isEdit) {
    // Replace the original rule by identifying-tuple match
    const orig = _logRuleEditing.rule;
    const origUnit    = orig.path ? `file:${orig.path}` : orig.unit;
    const origPattern = orig.pattern;
    log_watch = log_watch.filter(r => {
      const rUnit = r.path ? `file:${r.path}` : r.unit;
      return !(rUnit === origUnit && r.pattern === origPattern);
    });
  } else if (log_watch.some(r => (r.unit === effectiveUnit || (r.path && `file:${r.path}` === effectiveUnit)) && r.pattern === pattern)) {
    toast('Rule already exists', 'error');
    return;
  }
  log_watch.push(rulePayload);
  const watched = existing.services_watched || [];
  if (sourceType === 'unit' && unit !== '*' && !watched.includes(unit)) watched.push(unit);
  const result = await api('POST', `/devices/${devId}/services/config`, {
    services_watched: watched,
    log_watch,
  });
  if (result && result.ok) {
    toast(isEdit ? 'Rule updated' : 'Rule added', 'success');
    _logRuleEditing = null;
    closeModal('log-rule-modal');
    loadPerDeviceLogRules();
  } else {
    toast(result?.error || 'Failed to save rule', 'error');
  }
}

// v3.2.3 (#3): live preview of the display_template against synthetic
// sample data. Fires on every keystroke via data-input dispatch.
function _renderLogTemplatePreview() {
  const tmpl = (document.getElementById('log-rule-template')?.value || '').trim();
  const out = document.getElementById('log-rule-template-preview');
  if (!out) return;
  if (!tmpl) { out.innerHTML = ''; return; }
  const samples = [
    'Mar 12 09:11:42 host postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[1.2.3.4]: 550 5.1.1',
    'Mar 12 09:12:03 host postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[5.6.7.8]: 550 5.7.1',
    'Mar 12 09:12:55 host postfix/smtpd[12345]: NOQUEUE: reject: RCPT from unknown[9.10.11.12]: 550 5.1.1',
  ];
  const unit = document.getElementById('log-rule-unit')?.value.trim() || 'postfix.service';
  const pattern = document.getElementById('log-rule-pattern')?.value.trim() || 'reject';
  const repl = {
    device: 'pmg01.tvipper.com',
    unit, pattern, count: '14',
    sample: samples.slice(0, 3).join(' | '),
    sample0: samples[0],
    sample1: samples[1],
    sample2: samples[2],
  };
  const allowed = new Set(Object.keys(repl));
  let bad = '';
  const rendered = tmpl.replace(/\{([^{}]*)\}/g, (m, t) => {
    if (!allowed.has(t)) { bad = bad || t; return m; }
    return repl[t];
  });
  if (bad) {
    out.innerHTML = `<span class="c-red-bold">Unknown placeholder: <code>{${escHtml(bad)}}</code></span>`;
  } else {
    out.innerHTML = `Preview: <code>${escHtml(rendered.slice(0, 280))}</code>`;
  }
}

// v3.0.1: toggle visibility of unit vs path field in the log rule modal
function _toggleLogRuleSource() {
  const sourceType = document.querySelector('input[name="log-rule-source"]:checked')?.value || 'unit';
  document.getElementById('log-rule-unit-row').style.display = sourceType === 'unit' ? '' : 'none';
  document.getElementById('log-rule-path-row').style.display = sourceType === 'path' ? '' : 'none';
}

async function deleteLogRule(devId, unit, pattern) {
  if (!confirm(`Remove per-device rule for ${unit}?\n\nPattern: ${pattern}`)) return;
  const existing = await api('GET', `/devices/${devId}/services/config`);
  if (!existing) return;
  const log_watch = (existing.log_watch || []).filter(r => !(r.unit === unit && r.pattern === pattern));
  const result = await api('POST', `/devices/${devId}/services/config`, {
    services_watched: existing.services_watched || [],
    log_watch,
  });
  if (result && result.ok) { toast('Rule removed', 'success'); loadPerDeviceLogRules(); }
}

async function deleteGlobalLogRule(ruleId) {
  if (!confirm('Remove fleet-wide rule?')) return;
  const result = await api('DELETE', `/logs/rules/global/${ruleId}`);
  if (result && result.ok) { toast('Fleet-wide rule removed', 'success'); loadGlobalLogRules(); }
}

// v1.10.0: Audit log gets client-side filtering. The data is loaded once
// and re-rendered whenever the filter inputs change. Two filters: a free-
// text "search anywhere" box (matches against actor + action + detail) and
// an action-type dropdown that pulls its options from the distinct actions
// in the loaded data. Server-side filtering would be cleaner long-term but
// the audit log is small enough that client-side is fine.
let _auditLogCache = [];

let _auditRegistered = false;

function _registerAuditTable() {
  if (_auditRegistered) return;
  _auditRegistered = true;
  // v1.11.5: tableCtl handles the text filter and column sort. The action
  // dropdown filter stays separate (page-level filter, not generic) and
  // still triggers a re-render via renderAuditLog().
  tableCtl.register({
    name: 'audit',
    tbody: 'audit-tbody',
    filterInput: 'audit-filter-text',
    sortHeaders: 'audit-thead',
    colspan: 5,
    columns: ['ts', 'actor', 'action', 'detail', 'source_ip'],
    // v1.11.6: page composes a free-text filter with a per-action
    // dropdown — the dropdown isn't part of tableCtl's substring
    // match, so we route both through renderAuditLog().
    refresh: () => renderAuditLog(),
    getColumns: (e) => ({
      ts:        e.ts || 0,
      actor:     e.actor || '',
      action:    e.action || '',
      detail:    e.detail || '',
      source_ip: e.source_ip || '',
    }),
    match: (e, q) => {
      const hay = `${e.actor || ''} ${e.action || ''} ${e.detail || ''}`.toLowerCase();
      return hay.includes(q);
    },
    row: (e) => `<tr><td class="isl-345">${new Date(e.ts*1000).toLocaleString()}</td><td class="fw-500">${escHtml(e.actor)}</td><td><span class="cmd-badge ${e.action.includes('fail')?'shutdown':e.action.includes('login')?'update':'reboot'}">${escHtml(e.action)}</span></td><td class="isl-427">${escHtml(e.detail||'—')}</td><td class="isl-417">${escHtml(e.source_ip||'—')}</td></tr>`,
    emptyMsg: 'No audit entries yet.',
    emptyMsgFiltered: 'No entries match the current filter.',
  });
}

async function loadAuditLog() {
  _registerAuditTable();
  const tbody = document.getElementById('audit-tbody');
  tbody.innerHTML = '<tr><td colspan="5" class="empty-state-sm">Loading…</tbody>';
  const data = await api('GET', '/audit-log');
  _auditLogCache = Array.isArray(data) ? data : [];
  // Repopulate the action-filter dropdown with whatever actions appear in
  // the data. Sorted alphabetically so the order is stable across reloads.
  const sel = document.getElementById('audit-filter-action');
  if (sel) {
    const actions = [...new Set(_auditLogCache.map(e => e.action).filter(Boolean))].sort();
    const cur = sel.value;
    sel.innerHTML = '<option value="">All actions</option>'
      + actions.map(a => `<option value="${escHtml(a)}">${escHtml(a)}</option>`).join('');
    if (actions.includes(cur)) sel.value = cur;
  }
  renderAuditLog();
}

function renderAuditLog() {
  // The action-dropdown filter is page-specific (not part of tableCtl's
  // generic substring filter). Apply it first, then hand the surviving
  // rows to tableCtl, which applies the persisted text filter and sort.
  const action = document.getElementById('audit-filter-action')?.value || '';
  const rows = action
    ? _auditLogCache.filter(e => e.action === action)
    : _auditLogCache;
  tableCtl.render('audit', rows);
}
async function revokeAllSessions() { if (!confirm('Revoke ALL sessions? Everyone (including you) will need to log in again.')) return; const data = await api('POST', '/sessions/revoke', {}); if (data?.ok) { toast(`${data.revoked} sessions revoked — logging out`, 'success'); setTimeout(doLogout, 1500); } else toast(data?.error || 'Failed', 'error'); }
async function clearAuditLog() { if (!confirm('Clear the entire audit log? This cannot be undone.')) return; const data = await api('DELETE', '/audit-log'); if (data?.ok) { toast('Audit log cleared', 'success'); loadAuditLog(); } else toast(data?.error || 'Failed', 'error'); }

// ─── v3.2.0 (B1): Alerts inbox ──────────────────────────────────────────────

let _alertsCache = [];

async function loadAlerts() {
  const statusEl = document.getElementById('alerts-filter-status');
  const status = (statusEl && statusEl.value) || 'open';
  try {
    const data = await api('GET', `/alerts?status=${encodeURIComponent(status)}&limit=500`);
    _alertsCache = (data && data.alerts) || [];
    _renderAlertsSummary(data && data.summary);
    renderAlerts();
  } catch (e) {
    toast('Failed to load alerts', 'error');
  }
}

function _renderAlertsSummary(summary) {
  const el = document.getElementById('alerts-summary');
  if (!el) return;
  if (!summary) { el.innerHTML = ''; return; }
  const bs = summary.by_severity || {};
  el.innerHTML =
    `<span class="alerts-summary-pill">Open: <strong>${summary.open || 0}</strong></span>` +
    `<span class="alerts-summary-pill">Acknowledged: <strong>${summary.acknowledged || 0}</strong></span>` +
    `<span class="alerts-summary-pill">Resolved: <strong>${summary.resolved || 0}</strong></span>` +
    (bs.critical ? `<span class="alerts-summary-pill sev-pill sev-critical">Critical: ${bs.critical}</span>` : '') +
    (bs.high ? `<span class="alerts-summary-pill sev-pill sev-high">High: ${bs.high}</span>` : '');
}

function renderAlerts() {
  const filterEl = document.getElementById('alerts-filter-text');
  const q = ((filterEl && filterEl.value) || '').trim().toLowerCase();
  let rows = _alertsCache;
  if (q) {
    rows = rows.filter(a =>
      (a.title || '').toLowerCase().includes(q) ||
      (a.device_name || '').toLowerCase().includes(q) ||
      (a.event || '').toLowerCase().includes(q));
  }
  // v3.2.1: sortable. Default = ts desc (newest first), handled by inbox
  // ordering server-side, but operator can override.
  tableCtl.wireSortOnly('alerts-thead', 'alerts', renderAlerts);
  const _sevRank = { critical: 0, high: 1, medium: 2, low: 3 };
  rows = tableCtl.sortRows('alerts', rows, (a) => ({
    severity:        _sevRank[a.severity] ?? 99,
    ts:              a.ts || 0,
    title:           (a.title || '').toLowerCase(),
    device_name:     (a.device_name || '').toLowerCase(),
    acknowledged_by: a.acknowledged_by || '',
  }));
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No alerts in this view.</td></tr>';
    _updateBulkResolveBtn();
    return;
  }
  tbody.innerHTML = rows.map(a => {
    const isResolved = !!a.resolved_at;
    const ackBy = a.acknowledged_by ? _escapeHtml(a.acknowledged_by) : '—';
    const sev = (a.severity || 'medium');
    const sevPill = `<span class="sev-pill sev-${sev}">${sev}</span>`;
    const dev = a.device_name || a.device_id || '—';
    const ts = _formatTs(a.ts);
    let actions = '';
    if (!isResolved) {
      actions += `<button class="btn-icon btn-xs" data-action="aiInvestigateAlert" data-arg="${a.id}" title="AI: investigate this alert and suggest fixes">${_icon('sparkles',14)} Investigate</button> `;
      if (!a.acknowledged_at) {
        actions += `<button class="btn-icon btn-xs" data-action="ackAlert" data-arg="${a.id}">Ack</button> `;
      } else {
        actions += `<button class="btn-icon btn-xs" data-action="unackAlert" data-arg="${a.id}">Un-ack</button> `;
      }
      actions += `<button class="btn-icon btn-xs c-success" data-action="resolveAlert" data-arg="${a.id}">Resolve</button>`;
    } else {
      const byWho = a.resolved_by === 'auto' ? 'auto' : _escapeHtml(a.resolved_by || '');
      actions = `<span class="c-muted">resolved by ${byWho}</span>`;
    }
    const cb = isResolved ? '' :
      `<input type="checkbox" class="alerts-row-cb" data-id="${a.id}" data-action="updateBulkResolveBtn">`;
    return `<tr class="alerts-row${isResolved ? ' resolved' : ''}">
      <td>${cb}</td>
      <td>${sevPill}</td>
      <td class="nowrap">${ts}</td>
      <td>${_escapeHtml(a.title || a.event || '')}</td>
      <td>${_escapeHtml(dev)}</td>
      <td>${ackBy}</td>
      <td class="nowrap">${actions}</td>
    </tr>`;
  }).join('');
  _updateBulkResolveBtn();
}

function _formatTs(ts) {
  if (!ts) return '';
  const d = new Date(ts * 1000);
  return d.toLocaleString();
}

function _escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

async function ackAlert(id) {
  const r = await api('POST', `/alerts/${encodeURIComponent(id)}/ack`, {});
  if (r && r.ok) { toast('Alert acknowledged', 'success'); loadAlerts(); refreshAlertsBadge(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function unackAlert(id) {
  const r = await api('POST', `/alerts/${encodeURIComponent(id)}/unack`, {});
  if (r && r.ok) { loadAlerts(); refreshAlertsBadge(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function resolveAlert(id) {
  if (!confirm('Mark this alert resolved?')) return;
  const r = await api('POST', `/alerts/${encodeURIComponent(id)}/resolve`, {});
  if (r && r.ok) { toast('Alert resolved', 'success'); loadAlerts(); refreshAlertsBadge(); }
  else toast((r && r.error) || 'Failed', 'error');
}

function aiInvestigateAlert(id) {
  const a = (_alertsCache || []).find(x => x.id === id);
  if (!a) { toast('Alert not found', 'error'); return; }
  const lines = [
    `Severity: ${a.severity || 'unknown'}`,
    `Event: ${a.event || '—'}`,
  ];
  if (a.device_name || a.device_id) lines.push(`Device: ${a.device_name || a.device_id}`);
  if (a.ts) lines.push(`Time: ${new Date(a.ts * 1000).toISOString()}`);
  lines.push('', `Alert: ${a.title || a.event || ''}`);
  if (a.payload && typeof a.payload === 'object' && Object.keys(a.payload).length) {
    let payloadStr = '';
    try { payloadStr = JSON.stringify(a.payload, null, 2).slice(0, 3000); } catch (e) {}
    if (payloadStr) lines.push('', `Details:\n${payloadStr}`);
  }
  openAIModal({
    title:    'Investigate alert',
    system:   'investigate_alert',
    userMsg:  lines.join('\n'),
    context:  `alert:${a.event || a.id}`,
    maxTokens: 1200,
  });
}

function toggleAllAlerts(checked) {
  document.querySelectorAll('.alerts-row-cb').forEach(cb => { cb.checked = checked; });
  _updateBulkResolveBtn();
}

function updateBulkResolveBtn() { _updateBulkResolveBtn(); }
function _updateBulkResolveBtn() {
  const cbs = document.querySelectorAll('.alerts-row-cb:checked');
  const btn = document.getElementById('alerts-bulk-resolve-btn');
  if (!btn) return;
  if (cbs.length > 0) btn.classList.remove('d-none');
  else btn.classList.add('d-none');
}

async function bulkResolveAlerts() {
  const ids = Array.from(document.querySelectorAll('.alerts-row-cb:checked'))
    .map(cb => cb.dataset.id);
  if (!ids.length) return;
  if (!confirm(`Resolve ${ids.length} alert(s)?`)) return;
  const r = await api('POST', '/alerts/bulk-resolve', { ids });
  if (r && r.ok) { toast(`Resolved ${r.resolved}`, 'success'); loadAlerts(); refreshAlertsBadge(); }
  else toast((r && r.error) || 'Failed', 'error');
}

// v3.2.0 follow-up: bulk-purge resolved or all alerts
async function clearResolvedAlerts() {
  if (!confirm('Remove every alert in "resolved" state? Open and acknowledged rows stay.')) return;
  const r = await api('DELETE', '/alerts?scope=resolved');
  if (r && r.ok) {
    toast(`Cleared ${r.removed} resolved alert(s)`, 'success');
    loadAlerts(); refreshAlertsBadge();
  } else toast((r && r.error) || 'Failed', 'error');
}

async function clearAllAlerts() {
  if (!confirm('Remove EVERY alert — including open and acknowledged ones?\n\nThis cannot be undone. Use "Clear resolved" if you only want to purge resolved.')) return;
  const r = await api('DELETE', '/alerts?scope=all');
  if (r && r.ok) {
    toast(`Cleared ${r.removed} alert(s)`, 'success');
    loadAlerts(); refreshAlertsBadge();
  } else toast((r && r.error) || 'Failed', 'error');
}

async function refreshAlertsBadge() {
  try {
    const s = await api('GET', '/alerts/summary');
    const badge = document.getElementById('alerts-badge');
    if (!badge || !s) return;
    const n = s.open || 0;
    // v3.2.0: always visible — green at 0 (the "all clear" signal), red
    // when anything is open. The icon-only sidebar is misread as "nothing
    // to look at" without a present-tense indicator.
    badge.classList.remove('d-none');
    badge.textContent = n > 99 ? '99+' : String(n);
    badge.classList.toggle('nav-badge-ok', n === 0);
    badge.classList.toggle('nav-badge-alert', n > 0);
    badge.title = n === 0 ? 'No open alerts' :
                  n === 1 ? '1 open alert' :
                  `${n} open alerts`;
  } catch (_) { /* non-fatal */ }
}

// ─── v3.2.0 (A1): MCP Confirmations queue ──────────────────────────────────

async function loadConfirmations() {
  try {
    const data = await api('GET', '/confirmations');
    _renderConfirmations((data && data.confirmations) || []);
    refreshConfirmationsBadge();
  } catch (e) {
    toast('Failed to load confirmations', 'error');
  }
}

function _renderConfirmations(arr) {
  const tbody = document.getElementById('confirmations-tbody');
  if (!tbody) return;
  // v3.2.1: wire sort + apply current sort order
  tableCtl.wireSortOnly('confirmations-thead', 'confirmations', () => loadConfirmations());
  const _statusRank = {pending: 0, approved: 1, rejected: 2, failed: 3, expired: 4};
  arr = tableCtl.sortRows('confirmations', arr, (c) => ({
    status:        _statusRank[c.status] ?? 99,
    requested_at:  c.requested_at || 0,
    action:        c.action || '',
    device_name:   c.device_name || c.device_id || '',
    ai_host:       c.ai_host || '',
    ai_prompt:     c.ai_prompt || '',
  }));
  if (!arr.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No pending or recent MCP confirmations.</td></tr>';
    return;
  }
  tbody.innerHTML = arr.map(c => {
    const status = c.status || 'pending';
    const statusPill =
      status === 'pending'  ? '<span class="sev-pill sev-medium">pending</span>' :
      status === 'approved' ? '<span class="sev-pill sev-success">approved</span>' :
      status === 'rejected' ? '<span class="sev-pill sev-low">rejected</span>' :
      status === 'expired'  ? '<span class="sev-pill sev-low">expired</span>' :
      status === 'failed'   ? '<span class="sev-pill sev-critical">failed</span>' :
      `<span class="sev-pill sev-low">${_escapeHtml(status)}</span>`;
    const actionLabel = c.action === 'run_saved_script' && c.script_name
      ? `${_escapeHtml(c.action)} <span class="hint">(${_escapeHtml(c.script_name)})</span>`
      : _escapeHtml(c.action || '');
    let buttons = '';
    if (status === 'pending') {
      buttons = `<button class="btn-icon btn-xs c-success" data-action="approveConfirmation" data-arg="${c.id}">Approve</button> ` +
                `<button class="btn-icon btn-xs c-danger-outline" data-action="rejectConfirmation" data-arg="${c.id}">Reject</button>`;
    }
    return `<tr>
      <td>${statusPill}</td>
      <td class="hint nowrap">${_formatTs(c.requested_at)}</td>
      <td>${actionLabel}</td>
      <td>${_escapeHtml(c.device_name || c.device_id || '')}</td>
      <td><code>${_escapeHtml(c.ai_host || '—')}</code></td>
      <td class="hint">${_escapeHtml(c.ai_prompt || '')}</td>
      <td class="nowrap">${buttons}</td>
    </tr>`;
  }).join('');
}

async function approveConfirmation(id) {
  if (!confirm('Approve this MCP write action? The server will execute it now.')) return;
  const r = await api('POST', `/confirmations/${encodeURIComponent(id)}/approve`, {});
  if (r && r.ok) { toast('Approved — action queued', 'success'); loadConfirmations(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function rejectConfirmation(id) {
  const note = prompt('Reject this MCP write action. Optional note:') || '';
  const r = await api('POST', `/confirmations/${encodeURIComponent(id)}/reject`, { note });
  if (r && r.ok) { toast('Rejected', 'success'); loadConfirmations(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function clearConfirmations() {
  if (!confirm('Clear all resolved (approved / rejected / expired) entries? Pending entries are kept.')) return;
  const r = await api('DELETE', '/confirmations', {});
  if (r && r.ok) { toast(`Cleared ${r.removed} entr${r.removed === 1 ? 'y' : 'ies'}`, 'success'); loadConfirmations(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function refreshConfirmationsBadge() {
  try {
    const data = await api('GET', '/confirmations');
    const arr = (data && data.confirmations) || [];
    const pending = arr.filter(c => c.status === 'pending').length;
    const badge = document.getElementById('confirmations-badge');
    if (!badge) return;
    // v3.2.0: same green-at-zero pattern as the alerts badge — present
    // state is always visible; colour shows whether action is needed.
    badge.classList.remove('d-none');
    badge.textContent = pending > 99 ? '99+' : String(pending);
    badge.classList.toggle('nav-badge-ok', pending === 0);
    badge.classList.toggle('nav-badge-alert', pending > 0);
    badge.title = pending === 0 ? 'No pending MCP confirmations' :
                  pending === 1 ? '1 pending MCP confirmation' :
                  `${pending} pending MCP confirmations`;
  } catch (_) {
    // Viewers get 403 here — hide entirely rather than showing a confusing badge
    const badge = document.getElementById('confirmations-badge');
    if (badge) badge.classList.add('d-none');
  }
}

// ─── v3.2.0 (B2): inbound webhooks (Settings → Integrations) ────────────────

let _lastCreatedInboundWebhookUrl = '';

async function loadIntegrationsTab() {
  await loadInboundWebhooks();
  // Render OIDC redirect-URI hint based on current origin
  const hintEl = document.getElementById('oidc-redirect-hint');
  if (hintEl) {
    hintEl.innerHTML = `<strong>Redirect URI</strong> to register with your IdP: <code>${location.origin}/api/auth/oidc/callback</code>`;
  }
  // Populate the existing OIDC fields from config
  try {
    const cfg = await api('GET', '/config');
    if (cfg) {
      const setIf = (id, key, isCheck) => {
        const el = document.getElementById(id);
        if (!el) return;
        if (isCheck) el.checked = !!cfg[key];
        else el.value = cfg[key] || '';
      };
      setIf('oidc-enabled', 'oidc_enabled', true);
      setIf('oidc-issuer', 'oidc_issuer');
      setIf('oidc-client-id', 'oidc_client_id');
      setIf('oidc-scopes', 'oidc_scopes');
      setIf('oidc-admin-group', 'oidc_admin_group');
      // Don't populate the secret — it's stored hashed-server-side or simply
      // never re-read by the UI. Leave blank means "keep current".
    }
  } catch (_) { /* non-fatal */ }
}

async function loadInboundWebhooks() {
  try {
    const data = await api('GET', '/inbound-webhooks');
    _renderInboundWebhooks((data && data.tokens) || []);
  } catch (e) {
    toast('Failed to load inbound webhooks', 'error');
  }
}

function _renderInboundWebhooks(tokens) {
  const tbody = document.getElementById('inbound-webhooks-tbody');
  if (!tbody) return;
  // v3.2.1: wire sort
  tableCtl.wireSortOnly('inbound-webhooks-thead', 'inbound_webhooks', () => loadInboundWebhooks());
  tokens = tableCtl.sortRows('inbound_webhooks', tokens, (t) => ({
    label:      t.label || '',
    kind:       t.kind || 'alert',
    scope:      t.scope_device_id || t.scope_tag || 'any',
    hit_count:  t.hit_count || 0,
    last_seen:  t.last_seen || 0,
    enabled:    t.enabled ? 1 : 0,
  }));
  if (!tokens.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No inbound tokens yet.</td></tr>';
    return;
  }
  tbody.innerHTML = tokens.map(t => {
    const kind = t.kind || 'alert';
    const kindPill = kind === 'syslog'
      ? '<span class="sev-pill sev-medium">syslog</span>'
      : '<span class="sev-pill sev-low">alert</span>';
    const scope = t.scope_device_id ? `device ${_escapeHtml(t.scope_device_id)}` :
                  t.scope_tag ? `tag ${_escapeHtml(t.scope_tag)}` : 'any';
    const lastSeen = t.last_seen ? _formatTs(t.last_seen) : '<span class="c-muted">—</span>';
    const status = t.enabled ?
      '<span class="sev-pill sev-success">enabled</span>' :
      '<span class="sev-pill sev-low">disabled</span>';
    const toggle = t.enabled ?
      `<button class="btn-icon btn-xs" data-action="toggleInboundWebhook" data-arg="${t.id}" data-arg2="0">Disable</button>` :
      `<button class="btn-icon btn-xs" data-action="toggleInboundWebhook" data-arg="${t.id}" data-arg2="1">Enable</button>`;
    return `<tr>
      <td><strong>${_escapeHtml(t.label || '')}</strong></td>
      <td>${kindPill}</td>
      <td class="hint">${scope}</td>
      <td class="ff-mono fs-12">${_escapeHtml(t.token_preview || '')}</td>
      <td>${t.hit_count || 0}</td>
      <td class="hint nowrap">${lastSeen}</td>
      <td>${status}</td>
      <td class="nowrap">${toggle} <button class="btn-icon btn-xs" data-action-btn="_editInboundWebhookBtn" data-store-key="${_storeEvtData(t)}">Edit</button> <button class="btn-icon btn-xs c-danger-outline" data-action="revokeInboundWebhook" data-arg="${t.id}" data-arg2="${_escapeHtml(t.label||'')}">Revoke</button></td>
    </tr>`;
  }).join('');
}

// v3.3.0: edit an existing inbound token's label / scope / enabled.
// The token secret itself is immutable (rotate via revoke + create).
async function _editInboundWebhookBtn(btn) {
  const t = _evtData.get(btn.dataset.storeKey);
  if (!t) return;
  const curLabel  = t.label || '';
  const curScopeD = t.scope_device_id || '';
  const curScopeT = t.scope_tag || '';
  const newLabel = prompt(
    `Edit label for inbound webhook "${curLabel}"\n\n` +
    `(Leave blank to keep current.)`, curLabel);
  if (newLabel === null) return;  // operator cancelled
  const newScopeD = prompt(
    `Restrict to device_id? (current: ${curScopeD || '(any)'})\n\n` +
    `Blank = any device.`, curScopeD);
  if (newScopeD === null) return;
  const newScopeT = prompt(
    `Restrict to tag? (current: ${curScopeT || '(any)'})\n\n` +
    `Blank = any tag.`, curScopeT);
  if (newScopeT === null) return;
  const body = {
    label:           newLabel.trim(),
    scope_device_id: newScopeD.trim(),
    scope_tag:       newScopeT.trim(),
  };
  const r = await api('PATCH', '/inbound-webhooks/' + t.id, body);
  if (r?.ok) { toast('Inbound webhook updated', 'success'); loadInboundWebhooks(); }
  else { toast(r?.error || 'Failed', 'error'); }
}

function openInboundWebhookCreate() {
  document.getElementById('inbound-wh-label').value = '';
  document.getElementById('inbound-wh-kind').value = 'alert';
  // Populate the device dropdown
  const sel = document.getElementById('inbound-wh-device');
  if (sel) {
    const opts = ['<option value="">(any — match by body.device)</option>'];
    (window._devicesCache || devices || []).forEach(d => {
      const id = d.id || d.device_id || '';
      const nm = d.name || id;
      opts.push(`<option value="${_escapeHtml(id)}">${_escapeHtml(nm)}</option>`);
    });
    sel.innerHTML = opts.join('');
  }
  updateInboundWebhookKindHint();
  openModal('inbound-webhook-create-modal');
}

function updateInboundWebhookKindHint() {
  const kind = document.getElementById('inbound-wh-kind').value;
  const hint = document.getElementById('inbound-wh-kind-hint');
  const req = document.getElementById('inbound-wh-device-required');
  const devOpt = document.querySelector('#inbound-wh-device option[value=""]');
  if (kind === 'syslog') {
    if (hint) hint.textContent = 'Syslog tokens receive RFC 3164/5424 lines (JSON {lines:[...]} or plain text) and append to the device\'s log_watch under unit="syslog".';
    if (req) req.classList.remove('d-none');
    if (devOpt) devOpt.textContent = '— select device —';
  } else {
    if (hint) hint.textContent = 'Alert tokens receive JSON {severity,title,...} and land in the Alerts inbox.';
    if (req) req.classList.add('d-none');
    if (devOpt) devOpt.textContent = '(any — match by body.device)';
  }
}

async function createInboundWebhook() {
  const label = document.getElementById('inbound-wh-label').value.trim();
  if (!label) { toast('Label required', 'error'); return; }
  const kind = document.getElementById('inbound-wh-kind').value;
  const scope_device_id = document.getElementById('inbound-wh-device').value || null;
  if (kind === 'syslog' && !scope_device_id) {
    toast('Syslog tokens must be pinned to a device', 'error');
    return;
  }
  const r = await api('POST', '/inbound-webhooks', { label, scope_device_id, kind });
  if (r && r.ok && r.token) {
    closeModal('inbound-webhook-create-modal');
    const path = kind === 'syslog' ? '/api/syslog/in/' : '/api/webhook/in/';
    _lastCreatedInboundWebhookUrl = `${location.origin}${path}${r.token}`;
    document.getElementById('inbound-wh-url').textContent = _lastCreatedInboundWebhookUrl;
    document.getElementById('inbound-wh-show-title').textContent =
      kind === 'syslog' ? 'Syslog ingestion token created' : 'Alert webhook token created';
    const ex = document.getElementById('inbound-wh-example');
    if (kind === 'syslog') {
      ex.textContent =
        '# JSON form\n' +
        `curl -X POST '${_lastCreatedInboundWebhookUrl}' \\\n` +
        '  -H \'Content-Type: application/json\' \\\n' +
        '  -d \'{"lines":["<11>kernel: ERROR disk full","<14>sshd: Accepted root"]}\'\n\n' +
        '# Plain text — one syslog line per row (rsyslog omhttp default)\n' +
        `curl -X POST '${_lastCreatedInboundWebhookUrl}' \\\n` +
        '  -H \'Content-Type: text/plain\' \\\n' +
        '  --data-binary $\'<14>foo bar\\n<11>err line\\n\'';
    } else {
      ex.textContent =
        `curl -X POST '${_lastCreatedInboundWebhookUrl}' \\\n` +
        '  -H \'Content-Type: application/json\' \\\n' +
        '  -d \'{"severity":"high","title":"CPU 95% on web01","device":"web01","source":"grafana"}\'';
    }
    openModal('inbound-webhook-show-modal');
    loadInboundWebhooks();
  } else {
    toast((r && r.error) || 'Failed', 'error');
  }
}

function copyInboundWebhookUrl() {
  if (!_lastCreatedInboundWebhookUrl) return;
  navigator.clipboard.writeText(_lastCreatedInboundWebhookUrl)
    .then(() => toast('Copied', 'success'))
    .catch(() => toast('Copy failed — select and copy manually', 'error'));
}

async function toggleInboundWebhook(id, enabledStr) {
  const enabled = enabledStr === '1';
  const r = await api('PATCH', `/inbound-webhooks/${encodeURIComponent(id)}`, { enabled });
  if (r && r.ok) { toast(`Token ${enabled ? 'enabled' : 'disabled'}`, 'success'); loadInboundWebhooks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function revokeInboundWebhook(id, label) {
  if (!confirm(`Revoke inbound webhook "${label}"? The URL will stop working immediately.`)) return;
  const r = await api('DELETE', `/inbound-webhooks/${encodeURIComponent(id)}`);
  if (r && r.ok) { toast('Token revoked', 'success'); loadInboundWebhooks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

// v3.2.0: Test OIDC discovery — POST /api/auth/oidc/test
async function testOidcConfig() {
  const out = document.getElementById('oidc-test-result');
  if (out) out.innerHTML = '<span class="sev-pill sev-medium">testing</span> Fetching discovery document…';
  // Save first so we test what's actually on disk
  await saveOidcConfig();
  const r = await api('POST', '/auth/oidc/test', {});
  if (!out) return;
  if (!r || r.ok === false) {
    out.innerHTML = `<div class="sev-pill sev-critical">failed</div> ${_escapeHtml((r && r.error) || 'unknown error')}`;
    return;
  }
  const ep = r.endpoints || {};
  const warns = (r.warnings || []).map(w => `<li>${_escapeHtml(w)}</li>`).join('');
  out.innerHTML =
    `<div class="sev-pill sev-success">ok</div> Discovery succeeded.` +
    `<table class="fs-13 mt-8">` +
      `<tr><td class="c-muted-padded">Issuer</td><td><code>${_escapeHtml(r.issuer || '—')}</code></td></tr>` +
      `<tr><td class="c-muted-padded">Authorization</td><td><code>${_escapeHtml(ep.authorization || '—')}</code></td></tr>` +
      `<tr><td class="c-muted-padded">Token</td><td><code>${_escapeHtml(ep.token || '—')}</code></td></tr>` +
      `<tr><td class="c-muted-padded">Userinfo</td><td><code>${_escapeHtml(ep.userinfo || '—')}</code></td></tr>` +
      `<tr><td class="c-muted-padded">JWKS</td><td><code>${_escapeHtml(ep.jwks || '—')}</code></td></tr>` +
      `<tr><td class="c-muted-padded">Register redirect URI</td><td><code>${_escapeHtml(r.redirect_uri_needed || '—')}</code></td></tr>` +
    `</table>` +
    (warns ? `<div class="mt-8"><strong>Warnings:</strong><ul>${warns}</ul></div>` : '');
}

// OIDC config save is wired here so the Integrations tab is self-contained
async function saveOidcConfig() {
  const payload = {
    oidc_enabled:      document.getElementById('oidc-enabled').checked,
    oidc_issuer:       document.getElementById('oidc-issuer').value.trim(),
    oidc_client_id:    document.getElementById('oidc-client-id').value.trim(),
    oidc_scopes:       document.getElementById('oidc-scopes').value.trim() || 'openid profile email groups',
    oidc_admin_group:  document.getElementById('oidc-admin-group').value.trim(),
  };
  const secret = document.getElementById('oidc-client-secret').value;
  if (secret) payload.oidc_client_secret = secret;
  const r = await api('POST', '/config', payload);
  if (r && r.ok !== false) {
    toast('OIDC config saved', 'success');
    document.getElementById('oidc-client-secret').value = '';
  } else {
    toast((r && r.error) || 'Failed', 'error');
  }
}

// Refresh alert + confirmation badges on load and every 60s after
function _refreshTopBadges() {
  refreshAlertsBadge();
  refreshConfirmationsBadge();
}
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    _refreshTopBadges();
    setInterval(_refreshTopBadges, 60000);
  });
} else {
  _refreshTopBadges();
  setInterval(_refreshTopBadges, 60000);
}

// ─── v1.8.3: Calendar ────────────────────────────────────────────────────────
let calCurrentMonth = null;   // Date object pinned to the first of the displayed month
let calCurrentEvents = [];    // events fetched for the displayed range
let calEditingId = null;      // id of event currently being edited (or null = new)
let calSelectedColor = 'blue';

function calMonthBounds(d) {
  const start = new Date(d.getFullYear(), d.getMonth(), 1, 0, 0, 0);
  const end   = new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59);
  return [start, end];
}

function calFmtMonthTitle(d) {
  return d.toLocaleString(undefined, {month: 'long', year: 'numeric'});
}

function calNav(delta) {
  if (!calCurrentMonth) calCurrentMonth = new Date();
  if (delta === 0) {
    calCurrentMonth = new Date();
  } else {
    calCurrentMonth = new Date(
      calCurrentMonth.getFullYear(),
      calCurrentMonth.getMonth() + delta,
      1
    );
  }
  loadCalendar();
}

async function loadCalendar() {
  if (!calCurrentMonth) calCurrentMonth = new Date();
  document.getElementById('cal-title').textContent = calFmtMonthTitle(calCurrentMonth);

  // Fetch a wider window so events spanning into adjacent months still show
  const fetchStart = new Date(calCurrentMonth.getFullYear(), calCurrentMonth.getMonth() - 1, 1);
  const fetchEnd   = new Date(calCurrentMonth.getFullYear(), calCurrentMonth.getMonth() + 2, 0);
  const qs = new URLSearchParams({
    from: fetchStart.toISOString(),
    to:   fetchEnd.toISOString(),
  });
  const data = await api('GET', `/calendar?${qs.toString()}`);
  calCurrentEvents = (data && data.events) || [];
  renderCalendarGrid();
}

function renderCalendarGrid() {
  const grid = document.getElementById('cal-grid');
  if (!calCurrentMonth) calCurrentMonth = new Date();
  const year = calCurrentMonth.getFullYear();
  const month = calCurrentMonth.getMonth();
  const firstOfMonth = new Date(year, month, 1);
  // ISO weekday: Mon=1..Sun=7. JS getDay: Sun=0..Sat=6. Convert.
  const firstWeekday = (firstOfMonth.getDay() + 6) % 7;  // 0=Mon..6=Sun
  // Calendar grid starts on the Monday of the week containing the 1st
  const gridStart = new Date(year, month, 1 - firstWeekday);

  const today = new Date();
  const todayKey = `${today.getFullYear()}-${today.getMonth()}-${today.getDate()}`;

  // Index events by yyyy-m-d local-date key
  const byDay = {};
  for (const ev of calCurrentEvents) {
    let evStart, evEnd;
    try {
      evStart = new Date(ev.start);
      evEnd   = ev.end ? new Date(ev.end) : evStart;
    } catch { continue; }
    // Walk each day from start to end (inclusive)
    const cur = new Date(evStart.getFullYear(), evStart.getMonth(), evStart.getDate());
    const last = new Date(evEnd.getFullYear(), evEnd.getMonth(), evEnd.getDate());
    while (cur <= last) {
      const key = `${cur.getFullYear()}-${cur.getMonth()}-${cur.getDate()}`;
      if (!byDay[key]) byDay[key] = [];
      byDay[key].push(ev);
      cur.setDate(cur.getDate() + 1);
    }
  }

  // Render 6 weeks × 7 days = 42 cells
  let html = '';
  for (let i = 0; i < 42; i++) {
    const d = new Date(gridStart);
    d.setDate(gridStart.getDate() + i);
    const isToday = (d.getFullYear() === today.getFullYear()
                    && d.getMonth() === today.getMonth()
                    && d.getDate() === today.getDate());
    const isOtherMonth = d.getMonth() !== month;
    const key = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
    const events = byDay[key] || [];
    const eventsHtml = events.slice(0, 3).map(ev =>
      `<div class="cal-event color-${escHtml(ev.color || 'blue')}" data-stop-prop="1" data-action="openEventModal" data-arg="${escAttr(ev.id)}" title="${escHtml(ev.title)}">${ev.is_recurring ? '<span class="cal-recur-glyph"></span>' : ''}${escHtml(ev.title)}</div>`
    ).join('');
    const more = events.length > 3 ? `<div class="isl-428">+${events.length - 3} more</div>` : '';
    const dayDate = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    html += `<div class="cal-day${isOtherMonth ? ' other-month' : ''}${isToday ? ' today' : ''}" data-action="openEventModalForDay" data-arg="${dayDate}" >
      <div class="cal-day-num">${d.getDate()}</div>
      ${eventsHtml}${more}
    </div>`;
  }
  grid.innerHTML = html;
}

function openEventModal(eventId) {
  calEditingId = eventId || null;
  document.getElementById('event-modal-title').textContent = eventId ? 'Edit event' : 'New event';
  document.getElementById('event-delete-btn').style.display = eventId ? 'block' : 'none';
  // Wire the color swatches (idempotent)
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.onclick = () => {
      calSelectedColor = el.dataset.color;
      document.querySelectorAll('#event-color-picker .ev-color').forEach(x => x.style.borderColor = 'transparent');
      el.style.borderColor = 'var(--text)';
    };
  });

  let title = '', desc = '', color = 'blue', allDay = false, recur = 'none';
  let startVal = '', endVal = '';
  if (eventId) {
    const ev = calCurrentEvents.find(e => e.id === eventId);
    if (!ev) { toast('Event not found', 'error'); return; }
    title = ev.title; desc = ev.description || ''; color = ev.color || 'blue';
    allDay = !!ev.all_day; recur = ev.recur || 'none';
    startVal = isoToLocalInput(ev.start);
    endVal   = ev.end ? isoToLocalInput(ev.end) : startVal;
  } else {
    // Default: 1 hour from now, 1 hour duration
    const now = new Date();
    now.setMinutes(0, 0, 0);
    now.setHours(now.getHours() + 1);
    const later = new Date(now.getTime() + 3600 * 1000);
    startVal = dateToLocalInput(now);
    endVal   = dateToLocalInput(later);
  }
  document.getElementById('event-title').value = title;
  document.getElementById('event-description').value = desc;
  document.getElementById('event-start').value = startVal;
  document.getElementById('event-end').value = endVal;
  document.getElementById('event-all-day').checked = allDay;
  document.getElementById('event-recur').value = recur;
  // Update delete button label to reflect recurring vs one-off
  const delBtn = document.getElementById('event-delete-btn');
  if (delBtn) delBtn.textContent = (recur !== 'none') ? 'Delete all occurrences' : 'Delete';
  calSelectedColor = color;
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.style.borderColor = (el.dataset.color === color) ? 'var(--text)' : 'transparent';
  });
  openModal('event-modal');
}

function openEventModalForDay(dayStr) {
  // dayStr is "YYYY-MM-DD" in local time
  const [y, mo, d] = dayStr.split('-').map(Number);
  const start = new Date(y, mo - 1, d, 9, 0);
  const end   = new Date(y, mo - 1, d, 10, 0);
  calEditingId = null;
  document.getElementById('event-modal-title').textContent = 'New event';
  document.getElementById('event-delete-btn').style.display = 'none';
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.onclick = () => {
      calSelectedColor = el.dataset.color;
      document.querySelectorAll('#event-color-picker .ev-color').forEach(x => x.style.borderColor = 'transparent');
      el.style.borderColor = 'var(--text)';
    };
    el.style.borderColor = (el.dataset.color === 'blue') ? 'var(--text)' : 'transparent';
  });
  document.getElementById('event-title').value = '';
  document.getElementById('event-description').value = '';
  document.getElementById('event-start').value = dateToLocalInput(start);
  document.getElementById('event-end').value = dateToLocalInput(end);
  document.getElementById('event-all-day').checked = false;
  document.getElementById('event-recur').value = 'none';
  calSelectedColor = 'blue';
  openModal('event-modal');
}

function dateToLocalInput(d) {
  // Format Date as YYYY-MM-DDTHH:MM for <input type="datetime-local">
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function isoToLocalInput(iso) {
  try { return dateToLocalInput(new Date(iso)); }
  catch { return ''; }
}

async function saveEvent() {
  const title = document.getElementById('event-title').value.trim();
  if (!title) { toast('Title is required', 'error'); return; }
  const startLocal = document.getElementById('event-start').value;
  const endLocal   = document.getElementById('event-end').value;
  if (!startLocal) { toast('Start time is required', 'error'); return; }

  const body = {
    title,
    description: document.getElementById('event-description').value,
    start:       new Date(startLocal).toISOString(),
    end:         endLocal ? new Date(endLocal).toISOString() : new Date(startLocal).toISOString(),
    all_day:     document.getElementById('event-all-day').checked,
    color:       calSelectedColor,
    recur:       document.getElementById('event-recur').value || 'none',
  };
  let result;
  if (calEditingId) {
    result = await api('PUT', `/calendar/${calEditingId}`, body);
  } else {
    result = await api('POST', '/calendar', body);
  }
  if (result && result.ok) {
    toast(calEditingId ? 'Event updated' : 'Event created', 'success');
    closeModal('event-modal');
    loadCalendar();
  } else {
    toast(result?.error || 'Failed to save', 'error');
  }
}

async function deleteCurrentEvent() {
  if (!calEditingId) return;
  const ev = calCurrentEvents.find(e => e.id === calEditingId);
  const isRecurring = ev && (ev.recur && ev.recur !== 'none' || ev.is_recurring);
  const msg = isRecurring
    ? 'Delete this recurring event and all its occurrences?'
    : 'Delete this event?';
  if (!confirm(msg)) return;
  const result = await api('DELETE', `/calendar/${calEditingId}`);
  if (result && result.ok) {
    toast(isRecurring ? 'All occurrences deleted' : 'Event deleted', 'success');
    closeModal('event-modal');
    loadCalendar();
  } else {
    toast(result?.error || 'Failed to delete', 'error');
  }
}

// ─── v1.8.3: Tasks (kanban) ──────────────────────────────────────────────────
let tasksCache = [];
let taskEditingId = null;

async function loadTasks() {
  // Populate device filter with current devices (only on first load)
  const sel = document.getElementById('tasks-device-filter');
  if (sel.options.length <= 2) {
    const devs = await api('GET', '/devices');
    if (devs) {
      const list = devs.devices || devs;
      // Keep "All devices" + "No device linked" options at top
      for (const d of list) {
        const opt = document.createElement('option');
        opt.value = d.id || d.device_id;
        opt.textContent = d.name || d.id;
        sel.appendChild(opt);
      }
    }
  }
  const filterDev = sel.value;
  const qs = new URLSearchParams();
  if (filterDev === '__none__') {
    // Server doesn't have a "no device" filter; we fetch all and filter client-side
  } else if (filterDev) {
    qs.set('device', filterDev);
  }
  const data = await api('GET', `/tasks?${qs.toString()}`);
  if (!data) return;
  let tasks = data.tasks || [];
  if (filterDev === '__none__') {
    tasks = tasks.filter(t => !t.device_id);
  }
  tasksCache = tasks;
  renderKanban(tasks);
}

function renderKanban(tasks) {
  const states = ['upcoming', 'ongoing', 'pending', 'closed'];
  for (const s of states) {
    const col = document.getElementById(`tasks-col-${s}`);
    const filtered = tasks.filter(t => (t.state || 'upcoming') === s);
    document.getElementById(`tasks-count-${s}`).textContent = filtered.length;
    if (!filtered.length) {
      col.innerHTML = `<div class="isl-429">No tasks</div>`;
      continue;
    }
    col.innerHTML = filtered.map(t => renderTaskCard(t)).join('');
  }
}

function renderTaskCard(t) {
  const devBadge = t.device_id && t._device_name
    ? `<span class="kanban-card-device">${escHtml(t._device_name)}</span>`
    : '';
  const meta = [];
  if (t.created_by) meta.push(`by ${escHtml(t.created_by)}`);
  if (t.updated_at) {
    const ago = relTime(t.updated_at);
    meta.push(ago);
  }
  return `<div class="kanban-card" draggable="true"
              data-task-id="${escAttr(t.id)}"
              data-action="openTaskModal" data-arg="${escAttr(t.id)}" >
    <div class="kanban-card-title">${escHtml(t.title)}</div>
    <div class="kanban-card-meta">
      ${devBadge}
      <span class="offline">${meta.join(' · ')}</span>
    </div>
  </div>`;
}

function onTaskDragStart(e, taskId) {
  e.dataTransfer.setData('text/plain', taskId);
  e.dataTransfer.effectAllowed = 'move';
  e.target.classList.add('dragging');
}

function onTaskDragEnd(e) {
  e.target.classList.remove('dragging');
}

function onKanbanDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  e.currentTarget.classList.add('drag-over');
}

function onKanbanDragLeave(e) {
  e.currentTarget.classList.remove('drag-over');
}

async function onKanbanDrop(e, newState) {
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  const taskId = e.dataTransfer.getData('text/plain');
  if (!taskId) return;
  const task = tasksCache.find(t => t.id === taskId);
  if (!task || task.state === newState) return;
  // Optimistic update
  task.state = newState;
  renderKanban(tasksCache);
  const result = await api('PUT', `/tasks/${taskId}`, {state: newState});
  if (!result || !result.ok) {
    toast(result?.error || 'Failed to move task', 'error');
    loadTasks();  // resync from server
  }
}

async function openTaskModal(taskId) {
  taskEditingId = taskId || null;
  document.getElementById('task-modal-title').textContent = taskId ? 'Edit task' : 'New task';
  document.getElementById('task-delete-btn').style.display = taskId ? 'block' : 'none';

  // Populate device dropdown
  const devSel = document.getElementById('task-device');
  if (devSel.options.length <= 1) {
    const devs = await api('GET', '/devices');
    if (devs) {
      const list = devs.devices || devs;
      for (const d of list) {
        const opt = document.createElement('option');
        opt.value = d.id || d.device_id;
        opt.textContent = d.name || d.id;
        devSel.appendChild(opt);
      }
    }
  }

  const meta = document.getElementById('task-meta');
  if (taskId) {
    const t = tasksCache.find(x => x.id === taskId);
    if (!t) { toast('Task not found', 'error'); return; }
    document.getElementById('task-title').value = t.title;
    document.getElementById('task-description').value = t.description || '';
    document.getElementById('task-state').value = t.state || 'upcoming';
    document.getElementById('task-device').value = t.device_id || '';
    const created = t.created_at ? new Date(t.created_at*1000).toLocaleString() : '?';
    const updated = t.updated_at ? new Date(t.updated_at*1000).toLocaleString() : created;
    meta.style.display = 'block';
    meta.innerHTML = `Created ${escHtml(created)} by ${escHtml(t.created_by||'?')} · Updated ${escHtml(updated)}`;
  } else {
    document.getElementById('task-title').value = '';
    document.getElementById('task-description').value = '';
    document.getElementById('task-state').value = 'upcoming';
    document.getElementById('task-device').value = '';
    meta.style.display = 'none';
  }
  openModal('task-modal');
}

async function saveTask() {
  const title = document.getElementById('task-title').value.trim();
  if (!title) { toast('Title is required', 'error'); return; }
  const body = {
    title,
    description: document.getElementById('task-description').value,
    state:       document.getElementById('task-state').value,
    device_id:   document.getElementById('task-device').value,
  };
  let result;
  if (taskEditingId) {
    result = await api('PUT', `/tasks/${taskEditingId}`, body);
  } else {
    result = await api('POST', '/tasks', body);
  }
  if (result && result.ok) {
    toast(taskEditingId ? 'Task updated' : 'Task created', 'success');
    closeModal('task-modal');
    loadTasks();
  } else {
    toast(result?.error || 'Failed to save', 'error');
  }
}

async function deleteCurrentTask() {
  if (!taskEditingId) return;
  if (!confirm('Delete this task?')) return;
  const result = await api('DELETE', `/tasks/${taskEditingId}`);
  if (result && result.ok) {
    toast('Task deleted', 'success');
    closeModal('task-modal');
    loadTasks();
  } else {
    toast(result?.error || 'Failed to delete', 'error');
  }
}
let notificationsEnabled = false;
function requestNotifications() { if (!('Notification' in window)) return; if (Notification.permission === 'granted') { notificationsEnabled = true; return; } if (Notification.permission !== 'denied') Notification.requestPermission().then(p => { notificationsEnabled = (p === 'granted'); }); }
function sendNotification(title, body) { if (!notificationsEnabled) return; try { new Notification(title, {body, icon: '/favicon.ico'}); } catch(e) {} }
let previousDeviceStates = {};
function checkDeviceNotifications(newDevices) { if (!notificationsEnabled) return; for (const d of newDevices) { const prev = previousDeviceStates[d.id]; if (prev !== undefined && prev !== d.online) sendNotification(`RemotePower: ${d.name}`, d.online ? 'Device came online' : 'Device went offline'); previousDeviceStates[d.id] = d.online; } }
// v1.8.4: fetch unauthenticated public info (server name, remember-me default)
async function loadPublicInfo() {
  try {
    const resp = await fetch('/api/public-info');
    if (!resp.ok) return;
    const info = await resp.json();
    if (info.server_name) {
      // Update page title and the login header
      document.title = info.server_name;
      const loginTitle = document.querySelector('.login-title');
      if (loginTitle) loginTitle.textContent = info.server_name;
    }
    const rememberCb = document.getElementById('login-remember');
    if (rememberCb) rememberCb.checked = !!info.remember_me_default;
    // v2.0: show demo banner when running as a public read-only sandbox.
    // The banner stays visible across page navigation (it lives outside
    // the .page containers) so visitors always see "this is a demo".
    if (info.read_only) {
      _readOnlyMode = true;
      const banner = document.getElementById('demo-banner');
      if (banner) banner.style.display = 'block';
    }
    // v3.2.0 (B3): reveal the OIDC sign-in button if configured
    if (info.oidc_enabled) {
      const btn = document.getElementById('login-oidc-btn');
      if (btn) btn.classList.remove('d-none');
    }
  } catch (e) { /* ignore */ }
}

// v3.2.0 (B3): pick up an OIDC redirect carrying a fresh session token in the
// URL hash. Hash fragments never reach the server (no log exposure), the SPA
// parses them on load and treats them like a normal post-login state.
function _consumeOidcHashToken() {
  if (!location.hash || location.hash.indexOf('oidc_token=') < 0) return;
  const params = new URLSearchParams(location.hash.slice(1));
  const token = params.get('oidc_token');
  const role = params.get('role') || 'viewer';
  const username = params.get('username') || '';
  if (!token) return;
  try {
    localStorage.setItem('rp_token', token);
    localStorage.setItem('rp_role', role);
    localStorage.setItem('rp_username', username);
  } catch (_) { /* private mode — non-fatal */ }
  // Clean the hash so a refresh doesn't replay the token
  history.replaceState(null, '', location.pathname);
  location.reload();
}
_consumeOidcHashToken();

// Surface an OIDC error returned in the query string (?oidc_error=...)
(function() {
  const qs = new URLSearchParams(location.search);
  const err = qs.get('oidc_error');
  if (!err) return;
  const target = document.getElementById('login-oidc-error');
  if (target) {
    target.textContent = 'SSO sign-in failed: ' + err;
    target.classList.remove('d-none');
  }
  // Clean the URL
  history.replaceState(null, '', location.pathname);
})();

// v2.0: read-only mode flag — set from /api/public-info on load. The
// API client uses this to surface a nicer error toast on 403 instead
// of letting the raw "Demo mode" body bubble up to the user as a
// generic alert.
let _readOnlyMode = false;

// ── v1.9.0: CMDB ─────────────────────────────────────────────────────────────
// All state is per-tab; the derived vault key is held in a single closure
// variable and zeroed on logout/page reload.
let _cmdbVaultKey   = null;     // hex string when unlocked
let _cmdbVaultMeta  = null;     // {configured, ...}
let _cmdbAssetCache = null;     // last full list response
let _cmdbCurrent    = null;     // {device_id, ...} — asset currently in the modal
let _cmdbSearchTimer = null;

// Send the vault key on every CMDB credential request that needs it.
async function cmdbApi(method, path, body, sendKey) {
  const opts = {method, headers: {'X-Token': getToken()}};
  if (sendKey && _cmdbVaultKey) opts.headers['X-RP-Vault-Key'] = _cmdbVaultKey;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) {
    // Could be auth expiry OR vault locked — only auth-401 should log out.
    let payload = null;
    try { payload = await r.clone().json(); } catch (e) {}
    if (payload && payload.code === 'vault_locked') {
      _cmdbVaultKey = null;
      cmdbRenderVaultBar();
      alert('Vault is locked — please unlock and retry.');
      return null;
    }
    doLogout();
    return null;
  }
  let data;
  try { data = await r.json(); } catch (e) { data = null; }
  return {ok: r.ok, status: r.status, data};
}

function enterCMDB() {
  cmdbRefreshVaultStatus().then(() => cmdbReloadList());
  cmdbLoadServerFunctions();
}

async function cmdbRefreshVaultStatus() {
  const res = await cmdbApi('GET', '/cmdb/vault/status');
  if (!res || !res.data) return;
  _cmdbVaultMeta = res.data;
  cmdbRenderVaultBar();
}

function cmdbRenderVaultBar() {
  const stateEl  = document.getElementById('cmdb-vault-state');
  const iconEl   = document.getElementById('cmdb-vault-icon');
  const actionEl = document.getElementById('cmdb-vault-action');
  const lockEl   = document.getElementById('cmdb-vault-lock');
  const rotateEl = document.getElementById('cmdb-vault-rotate');
  if (!_cmdbVaultMeta) {
    stateEl.textContent = 'Vault status unknown';
    return;
  }
  if (!_cmdbVaultMeta.configured) {
    iconEl.innerHTML = _icon('settings', 16);
    stateEl.textContent = 'Vault not yet configured. Set a passphrase to start storing credentials.';
    actionEl.style.display = 'inline-block';
    actionEl.textContent = 'Set up vault';
    actionEl.onclick = cmdbOpenSetupModal;
    rotateEl.style.display = 'none';
    lockEl.style.display = 'none';
    return;
  }
  if (_cmdbVaultKey) {
    iconEl.innerHTML = _icon('unlock', 16);
    stateEl.textContent = 'Vault unlocked. Credential operations enabled in this tab only.';
    actionEl.style.display = 'none';
    rotateEl.style.display = 'inline-block';
    lockEl.style.display = 'inline-block';
  } else {
    iconEl.innerHTML = _icon('lock', 16);
    stateEl.textContent = 'Vault is configured but locked. Unlock to manage credentials.';
    actionEl.style.display = 'inline-block';
    actionEl.textContent = 'Unlock vault';
    actionEl.onclick = cmdbOpenUnlockModal;
    rotateEl.style.display = 'none';
    lockEl.style.display = 'none';
  }
}

function cmdbVaultAction() { /* dispatch through actionEl.onclick — no-op fallback */ }
function cmdbOpenSetupModal() {
  document.getElementById('cmdb-vault-setup-pw').value  = '';
  document.getElementById('cmdb-vault-setup-pw2').value = '';
  openModal('cmdb-vault-setup-modal');
  setTimeout(() => document.getElementById('cmdb-vault-setup-pw').focus(), 50);
}
function cmdbOpenUnlockModal() {
  document.getElementById('cmdb-vault-unlock-pw').value = '';
  openModal('cmdb-vault-unlock-modal');
  setTimeout(() => document.getElementById('cmdb-vault-unlock-pw').focus(), 50);
}
function cmdbOpenRotateModal() {
  document.getElementById('cmdb-vault-rotate-old').value  = '';
  document.getElementById('cmdb-vault-rotate-new').value  = '';
  document.getElementById('cmdb-vault-rotate-new2').value = '';
  openModal('cmdb-vault-rotate-modal');
}

async function cmdbVaultSetup() {
  const pw  = document.getElementById('cmdb-vault-setup-pw').value;
  const pw2 = document.getElementById('cmdb-vault-setup-pw2').value;
  if (pw !== pw2) { alert('Passphrases do not match.'); return; }
  const res = await cmdbApi('POST', '/cmdb/vault/setup', {passphrase: pw});
  if (!res) return;
  if (!res.ok) { alert('Vault setup failed: ' + (res.data && res.data.error || res.status)); return; }
  _cmdbVaultKey = res.data.key;
  closeModal('cmdb-vault-setup-modal');
  await cmdbRefreshVaultStatus();
  cmdbRenderVaultBar();
}

async function cmdbVaultUnlock() {
  const pw = document.getElementById('cmdb-vault-unlock-pw').value;
  const res = await cmdbApi('POST', '/cmdb/vault/unlock', {passphrase: pw});
  if (!res) return;
  if (!res.ok) { alert('Unlock failed: ' + (res.data && res.data.error || res.status)); return; }
  _cmdbVaultKey = res.data.key;
  closeModal('cmdb-vault-unlock-modal');
  cmdbRenderVaultBar();
  // If a credentials tab is open, reload it now
  if (_cmdbCurrent) cmdbLoadCreds(_cmdbCurrent.device_id);
}

async function cmdbVaultRotate() {
  const oldPw = document.getElementById('cmdb-vault-rotate-old').value;
  const newPw = document.getElementById('cmdb-vault-rotate-new').value;
  const new2  = document.getElementById('cmdb-vault-rotate-new2').value;
  if (newPw !== new2) { alert('New passphrases do not match.'); return; }
  const res = await cmdbApi('POST', '/cmdb/vault/change',
    {old_passphrase: oldPw, new_passphrase: newPw});
  if (!res) return;
  if (!res.ok) { alert('Rotation failed: ' + (res.data && res.data.error || res.status)); return; }
  _cmdbVaultKey = res.data.key;
  closeModal('cmdb-vault-rotate-modal');
  alert('Passphrase rotated. ' + res.data.rotated + ' credential(s) re-encrypted.');
  cmdbRenderVaultBar();
}

function cmdbLockVault() {
  _cmdbVaultKey = null;
  cmdbRenderVaultBar();
}

// ── Asset list / search ──────────────────────────────────────────────────────

function cmdbDebounceSearch() {
  clearTimeout(_cmdbSearchTimer);
  _cmdbSearchTimer = setTimeout(cmdbReloadList, 200);
}

async function cmdbReloadList() {
  const q  = encodeURIComponent(document.getElementById('cmdb-search').value || '');
  const fn = encodeURIComponent(document.getElementById('cmdb-func-filter').value || '');
  const res = await cmdbApi('GET', `/cmdb?q=${q}&function=${fn}`);
  if (!res || !res.ok) return;
  _cmdbAssetCache = res.data;
  cmdbRenderTable(res.data);
}

function cmdbRenderTable(rows) {
  const tbody = document.getElementById('cmdb-tbody');
  // v3.2.1: sortable
  tableCtl.wireSortOnly('cmdb-thead', 'cmdb', () => cmdbRenderTable(_cmdbAssetCache || rows));
  rows = tableCtl.sortRows('cmdb', rows || [], (r) => ({
    name:            (r.name || '').toLowerCase(),
    asset_id:        r.asset_id || '',
    server_function: r.server_function || '',
    os:              r.os || '',
    ip:              r.ip || '',
    hypervisor_url:  r.hypervisor_url || '',
    docs_count:      r.has_documentation ? 1 : 0,
    creds_count:     r.credential_count || 0,
  }));
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No matching assets.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const hyp = r.hypervisor_url
      ? `<a href="${_cmdbEsc(r.hypervisor_url)}" target="_blank" rel="noopener" class="c-accent-12">open ↗</a>`
      : '<span class="hint">—</span>';
    const fn = r.server_function
      ? `<span class="tag-pill">${_cmdbEsc(r.server_function)}</span>`
      : '<span class="hint">—</span>';
    // v3.3.0: clicking the Name cell opens the asset (same as the Open
    // button). The button stays in the actions column for discoverability.
    return `<tr>
      <td class="fw-500 pointer" data-action="cmdbOpenAsset" data-arg="${_cmdbEsc(r.device_id)}">${osIcon(r.os, 14)} ${_cmdbEsc(r.name)}</td>
      <td class="mono-12">${_cmdbEsc(r.asset_id) || '<span class="c-muted">—</span>'}</td>
      <td>${fn}</td>
      <td class="hint">${_cmdbEsc(r.os) || '—'}</td>
      <td class="mono-12">${_cmdbEsc(r.ip) || '—'}</td>
      <td>${hyp}</td>
      <td class="ta-center">${r.has_documentation ? '<span class="c-green">●</span>' : '<span class="c-muted">○</span>'}</td>
      <td class="isl-430">${r.credential_count}</td>
      <td><button class="btn-icon" data-action="cmdbOpenAsset" data-arg="${_cmdbEsc(r.device_id)}" >Open</button></td>
    </tr>`;
  }).join('');
}

async function cmdbLoadServerFunctions() {
  const res = await cmdbApi('GET', '/cmdb/server-functions');
  if (!res || !res.ok) return;
  const list = res.data || [];
  const dl = document.getElementById('cmdb-func-datalist');
  dl.innerHTML = list.map(v => `<option value="${_cmdbEsc(v)}">`).join('');
  const sel = document.getElementById('cmdb-func-filter');
  const cur = sel.value;
  sel.innerHTML = '<option value="">All functions</option>' +
    list.map(v => `<option value="${_cmdbEsc(v)}">${_cmdbEsc(v)}</option>`).join('');
  sel.value = cur;
}

// ── Asset detail modal ───────────────────────────────────────────────────────

async function cmdbOpenAsset(deviceId) {
  const res = await cmdbApi('GET', '/cmdb/' + encodeURIComponent(deviceId));
  if (!res || !res.ok) { alert('Failed to load asset.'); return; }
  _cmdbCurrent = res.data;
  document.getElementById('cmdb-asset-title').textContent = res.data.name + ' — CMDB';
  document.getElementById('cmdb-asset-deviceid').value = deviceId;
  document.getElementById('cmdb-asset-id').value         = res.data.asset_id || '';
  document.getElementById('cmdb-asset-function').value   = res.data.server_function || '';
  document.getElementById('cmdb-asset-vlan').value       = res.data.vlan || '';
  document.getElementById('cmdb-asset-hypervisor').value = res.data.hypervisor_url || '';
  document.getElementById('cmdb-asset-ssh-port').value   = res.data.ssh_port || 22;
  document.getElementById('cmdb-asset-hostname').textContent = res.data.hostname || '—';
  document.getElementById('cmdb-asset-os').textContent       = res.data.os || '—';
  document.getElementById('cmdb-asset-ip').textContent       = res.data.ip || '—';
  document.getElementById('cmdb-asset-mac').textContent      = res.data.mac || '—';
  document.getElementById('cmdb-asset-group').textContent    = res.data.group || '—';
  // v2.0: render the docs list. Server returns docs[] migrated from the
  // legacy single 'documentation' field if needed.
  cmdbRenderDocs(res.data.docs || []);
  cmdbSwitchTab('props');
  openModal('cmdb-asset-modal');
}

function cmdbSwitchTab(tab) {
  document.querySelectorAll('.cmdb-tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === tab);
  });
  document.getElementById('cmdb-tab-props').style.display = tab === 'props' ? 'block' : 'none';
  document.getElementById('cmdb-tab-docs').style.display  = tab === 'docs'  ? 'block' : 'none';
  document.getElementById('cmdb-tab-creds').style.display = tab === 'creds' ? 'block' : 'none';
  const snmpPane = document.getElementById('cmdb-tab-snmp');
  if (snmpPane) snmpPane.style.display = tab === 'snmp' ? 'block' : 'none';
  if (tab === 'creds') cmdbLoadCreds(_cmdbCurrent ? _cmdbCurrent.device_id : null);
  if (tab === 'snmp')  cmdbLoadSnmp(_cmdbCurrent ? _cmdbCurrent.device_id : null);
}

// v3.2.0 (B5): SNMP config + latest poll for the asset modal
async function cmdbLoadSnmp(deviceId) {
  if (!deviceId) return;
  try {
    const r = await api('GET', `/devices/${encodeURIComponent(deviceId)}/snmp`);
    if (!r) return;
    const cfg = r.config || {};
    document.getElementById('cmdb-snmp-enabled').checked = !!cfg.enabled;
    document.getElementById('cmdb-snmp-port').value = cfg.port || 161;
    document.getElementById('cmdb-snmp-community').value = '';
    document.getElementById('cmdb-snmp-community').placeholder =
      cfg.has_community ? `(keep current — preview: ${cfg.community_preview || '…'})` : 'public';
    _renderCmdbSnmpData(r.data);
  } catch (e) {
    toast('Failed to load SNMP config', 'error');
  }
}

function _renderCmdbSnmpData(data) {
  const el = document.getElementById('cmdb-snmp-data');
  if (!el) return;
  if (!data || (!data.last_ok && !data.last_error)) {
    el.innerHTML = '<span class="c-muted">No data yet — save the config and click "Poll now".</span>';
    return;
  }
  if (data.last_error && !data.last_ok) {
    el.innerHTML = `<div class="sev-pill sev-critical">poll failed</div> <code>${_escapeHtml(data.last_error)}</code>`;
    return;
  }
  const upDays = data.sysUpTime ? Math.floor(data.sysUpTime / 100 / 86400) : '?';
  el.innerHTML =
    `<div><strong>Last successful poll:</strong> ${_formatTs(data.last_ok)}</div>` +
    `<div><strong>sysDescr:</strong> ${_escapeHtml(data.sysDescr || '—')}</div>` +
    `<div><strong>sysName:</strong> ${_escapeHtml(data.sysName || '—')}</div>` +
    `<div><strong>sysLocation:</strong> ${_escapeHtml(data.sysLocation || '—')}</div>` +
    `<div><strong>sysContact:</strong> ${_escapeHtml(data.sysContact || '—')}</div>` +
    `<div><strong>sysObjectID:</strong> <code>${_escapeHtml(data.sysObjectID || '—')}</code></div>` +
    `<div><strong>sysUpTime:</strong> ${data.sysUpTime || '?'} (≈ ${upDays}d)</div>` +
    (data.last_error ? `<div class="c-muted mt-12"><em>Note: most recent error — ${_escapeHtml(data.last_error)}</em></div>` : '');
}

async function saveCmdbSnmp() {
  const deviceId = document.getElementById('cmdb-asset-deviceid').value;
  if (!deviceId) return;
  const enabled = document.getElementById('cmdb-snmp-enabled').checked;
  const portRaw = document.getElementById('cmdb-snmp-port').value;
  const comm = document.getElementById('cmdb-snmp-community').value;

  // Client-side validation — server validates too, but a clear message
  // before the round trip is much friendlier than a 400 toast.
  const port = parseInt(portRaw, 10) || 161;
  if (port < 1 || port > 65535) {
    _showSnmpInlineError('UDP port must be 1..65535.');
    return;
  }
  if (enabled) {
    // If enabling for the first time, community is required. We can't tell
    // from the client whether one already exists; rely on the server's
    // explicit error if it's missing (returns 400 with a clear message).
    if (comm && /\s/.test(comm)) {
      _showSnmpInlineError('Community string cannot contain whitespace.');
      return;
    }
  }
  const body = { enabled, port };
  if (comm) body.community = comm;
  _showSnmpInlineNotice('Saving…');
  const r = await api('PATCH', `/devices/${encodeURIComponent(deviceId)}/snmp`, body);
  if (r && r.ok) {
    toast('SNMP config saved', 'success');
    _showSnmpInlineNotice('Config saved.', 'success');
    document.getElementById('cmdb-snmp-community').value = '';
    cmdbLoadSnmp(deviceId);
  } else {
    _showSnmpInlineError((r && r.error) || 'Save failed');
  }
}

async function pollCmdbSnmp() {
  const deviceId = document.getElementById('cmdb-asset-deviceid').value;
  if (!deviceId) return;
  const enabled = document.getElementById('cmdb-snmp-enabled').checked;
  if (!enabled) {
    _showSnmpInlineError('SNMP is disabled on this device. Tick "Enable SNMP polling" and Save first.');
    return;
  }
  // Disable the button + show in-progress so the user knows we're working
  const btn = document.querySelector('[data-action="pollCmdbSnmp"]');
  const prevText = btn ? btn.textContent : 'Poll now';
  if (btn) { btn.disabled = true; btn.textContent = 'Polling…'; }
  _showSnmpInlineNotice('Polling SNMP target (up to 4 s)…');
  try {
    const r = await api('POST', `/devices/${encodeURIComponent(deviceId)}/snmp/poll`, {});
    if (r && r.ok) {
      _renderCmdbSnmpData(r.data);
      if (r.data && r.data.last_ok) {
        toast('Polled OK — see Latest poll below', 'success');
        _showSnmpInlineNotice(`Last successful poll: ${_formatTs(r.data.last_ok)}`, 'success');
      } else {
        toast('Poll failed — see error below', 'error');
        _showSnmpInlineError(r.data && r.data.last_error ? r.data.last_error
                                                          : 'Unknown error');
      }
    } else {
      const msg = (r && r.error) || 'Poll request failed';
      toast(msg, 'error');
      _showSnmpInlineError(msg);
    }
  } catch (e) {
    _showSnmpInlineError(`Network error: ${e && e.message ? e.message : e}`);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = prevText; }
  }
}

function _showSnmpInlineError(msg) {
  const el = document.getElementById('cmdb-snmp-data');
  if (!el) return;
  el.innerHTML = `<div class="sev-pill sev-critical">error</div> <span>${_escapeHtml(msg)}</span>`;
}
function _showSnmpInlineNotice(msg, kind) {
  const el = document.getElementById('cmdb-snmp-data');
  if (!el) return;
  const pillCls = kind === 'success' ? 'sev-pill sev-success' : 'sev-pill sev-medium';
  el.innerHTML = `<div class="${pillCls}">${kind || 'info'}</div> <span>${_escapeHtml(msg)}</span>`;
}

// ── v2.0: multi-doc list ─────────────────────────────────────────────────────
//
// _cmdbCurrent.docs holds the canonical list. cmdbRenderDocs() repaints the
// .cmdb-docs-list container; per-doc add/edit/delete operations mutate the
// list in place after a successful API response, then re-render. We don't
// re-fetch the whole asset for each change — the modal stays open and
// responsive.

function cmdbRenderDocs(docs) {
  const list  = document.getElementById('cmdb-docs-list');
  const empty = document.getElementById('cmdb-docs-empty');
  if (!docs || docs.length === 0) {
    list.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  // Each doc is a <details> card so the body collapses by default —
  // an asset with 10 docs shouldn't take 10 screens of vertical space.
  // The first doc is open by default (most common case is "show me
  // the runbook" without a click).
  list.innerHTML = docs.map((doc, idx) => {
    const created = doc.created_at ? new Date(doc.created_at * 1000).toISOString().split('T')[0] : '';
    const updated = doc.updated_at ? new Date(doc.updated_at * 1000).toISOString().split('T')[0] : '';
    const meta = (created === updated || !created)
      ? (updated ? `updated ${updated}` : '')
      : `created ${created}, updated ${updated}`;
    return `<details class="cmdb-doc-card isl-431" ${idx === 0 ? 'open' : ''}>
      <summary class="isl-432">
        <span class="meta-sm-nm">▸</span>
        <span class="isl-433">${cmdbEscHtml(doc.title || '(untitled)')}</span>
        <span class="hint">${meta}</span>
        <button class="btn-icon isl-434" data-stop-prop="1" data-prevent-default="1" data-action="cmdbDocEditOpen" data-arg="${doc.id}" >Edit</button>
        <button class="btn-icon isl-435" data-stop-prop="1" data-prevent-default="1" data-action="cmdbDocDelete" data-arg="${doc.id}" >Delete</button>
      </summary>
      <div class="isl-436">
        ${cmdbRenderMarkdown(doc.body || '')}
      </div>
    </details>`;
  }).join('');
}

function cmdbEscHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function cmdbDocAddOpen() {
  document.getElementById('cmdb-doc-modal-mode').value = 'add';
  document.getElementById('cmdb-doc-modal-docid').value = '';
  document.getElementById('cmdb-doc-modal-deviceid').value =
    _cmdbCurrent ? _cmdbCurrent.device_id : '';
  document.getElementById('cmdb-doc-modal-title').textContent = 'Add document';
  document.getElementById('cmdb-doc-modal-title-input').value = '';
  document.getElementById('cmdb-doc-modal-body').value = '';
  cmdbDocModalSwitch('edit');
  openModal('cmdb-doc-edit-modal');
  setTimeout(() => document.getElementById('cmdb-doc-modal-title-input').focus(), 60);
}

function cmdbDocEditOpen(docId) {
  if (!_cmdbCurrent) return;
  const doc = (_cmdbCurrent.docs || []).find(d => d.id === docId);
  if (!doc) return;
  document.getElementById('cmdb-doc-modal-mode').value = 'edit';
  document.getElementById('cmdb-doc-modal-docid').value = docId;
  document.getElementById('cmdb-doc-modal-deviceid').value = _cmdbCurrent.device_id;
  document.getElementById('cmdb-doc-modal-title').textContent = 'Edit document';
  document.getElementById('cmdb-doc-modal-title-input').value = doc.title || '';
  document.getElementById('cmdb-doc-modal-body').value = doc.body || '';
  cmdbDocModalSwitch('edit');
  openModal('cmdb-doc-edit-modal');
}

function cmdbDocModalSwitch(mode) {
  const ta = document.getElementById('cmdb-doc-modal-body');
  const pv = document.getElementById('cmdb-doc-modal-preview');
  document.getElementById('cmdb-doc-modal-edit-btn').classList.toggle('active', mode === 'edit');
  document.getElementById('cmdb-doc-modal-preview-btn').classList.toggle('active', mode === 'preview');
  if (mode === 'edit') {
    ta.style.display = 'block';
    pv.style.display = 'none';
  } else {
    ta.style.display = 'none';
    pv.style.display = 'block';
    pv.innerHTML = cmdbRenderMarkdown(ta.value || '');
  }
}

async function cmdbDocSave() {
  const mode    = document.getElementById('cmdb-doc-modal-mode').value;
  const devId   = document.getElementById('cmdb-doc-modal-deviceid').value;
  const docId   = document.getElementById('cmdb-doc-modal-docid').value;
  const title   = document.getElementById('cmdb-doc-modal-title-input').value.trim();
  const body    = document.getElementById('cmdb-doc-modal-body').value;

  if (!title) {
    alert('Title is required.');
    return;
  }
  let res;
  if (mode === 'add') {
    res = await cmdbApi('POST', `/cmdb/${encodeURIComponent(devId)}/docs`,
                        { title, body });
  } else {
    res = await cmdbApi('PUT',
                        `/cmdb/${encodeURIComponent(devId)}/docs/${encodeURIComponent(docId)}`,
                        { title, body });
  }
  if (!res) return;
  if (!res.ok) {
    alert('Save failed: ' + (res.data && res.data.error || res.status));
    return;
  }
  // Update _cmdbCurrent.docs in place — promotes legacy doc id if the
  // server changed it (the 'legacy' → real-id swap during edit).
  const newDoc = res.data;
  if (mode === 'add') {
    if (!_cmdbCurrent.docs) _cmdbCurrent.docs = [];
    _cmdbCurrent.docs.push(newDoc);
  } else {
    const idx = _cmdbCurrent.docs.findIndex(d => d.id === docId);
    if (idx >= 0) _cmdbCurrent.docs[idx] = newDoc;
  }
  cmdbRenderDocs(_cmdbCurrent.docs);
  closeModal('cmdb-doc-edit-modal');
  // Refresh the list view's "has docs" indicator on the next list refresh
  cmdbReloadList();
}

async function cmdbDocDelete(docId) {
  if (!_cmdbCurrent) return;
  const doc = (_cmdbCurrent.docs || []).find(d => d.id === docId);
  if (!doc) return;
  if (!confirm(`Delete document "${doc.title}"?`)) return;
  const res = await cmdbApi('DELETE',
    `/cmdb/${encodeURIComponent(_cmdbCurrent.device_id)}/docs/${encodeURIComponent(docId)}`);
  if (!res) return;
  if (!res.ok) {
    alert('Delete failed: ' + (res.data && res.data.error || res.status));
    return;
  }
  _cmdbCurrent.docs = (_cmdbCurrent.docs || []).filter(d => d.id !== docId);
  cmdbRenderDocs(_cmdbCurrent.docs);
  cmdbReloadList();
}

// Tiny Markdown renderer — headings, bold, italic, code, links, lists.
// Deliberately conservative: anything not matched stays as escaped text.
function cmdbRenderMarkdown(src) {
  if (!src) return '<div class="c-muted">No content.</div>';
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const lines = src.split('\n');
  const out = [];
  let inCode = false, inList = false;
  for (let raw of lines) {
    if (raw.startsWith('```')) {
      if (inCode) { out.push('</code></pre>'); inCode = false; }
      else        { out.push('<pre class="isl-437"><code>'); inCode = true; }
      continue;
    }
    if (inCode) { out.push(esc(raw)); continue; }
    if (/^- /.test(raw)) {
      if (!inList) { out.push('<ul class="isl-438">'); inList = true; }
      out.push('<li>' + cmdbInlineMd(esc(raw.slice(2))) + '</li>');
      continue;
    } else if (inList) { out.push('</ul>'); inList = false; }

    if (/^### /.test(raw))      out.push('<h4 class="isl-439">' + cmdbInlineMd(esc(raw.slice(4))) + '</h4>');
    else if (/^## /.test(raw))  out.push('<h3 class="isl-440">' + cmdbInlineMd(esc(raw.slice(3))) + '</h3>');
    else if (/^# /.test(raw))   out.push('<h2 class="isl-441">' + cmdbInlineMd(esc(raw.slice(2))) + '</h2>');
    else if (raw.trim() === '') out.push('<br>');
    else out.push('<div>' + cmdbInlineMd(esc(raw)) + '</div>');
  }
  if (inList) out.push('</ul>');
  if (inCode) out.push('</code></pre>');
  return out.join('\n');
}

function cmdbInlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, '<code class="isl-442">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,
             '<a href="$2" target="_blank" rel="noopener" class="c-accent">$1</a>');
}

async function cmdbAssetSave() {
  const deviceId = document.getElementById('cmdb-asset-deviceid').value;
  // v2.0: docs are managed via their own CRUD endpoints (cmdbDocSave /
  // cmdbDocDelete), not bundled into this asset PUT. The legacy
  // 'documentation' field is no longer sent — server-side back-compat
  // still accepts it, so old clients keep working, but new clients
  // route doc edits through the dedicated endpoints which support
  // multiple titled docs per asset.
  const body = {
    asset_id:        document.getElementById('cmdb-asset-id').value.trim(),
    server_function: document.getElementById('cmdb-asset-function').value.trim(),
    vlan:            document.getElementById('cmdb-asset-vlan').value.trim(),
    hypervisor_url:  document.getElementById('cmdb-asset-hypervisor').value.trim(),
    ssh_port:        parseInt(document.getElementById('cmdb-asset-ssh-port').value, 10) || 22,
  };
  const res = await cmdbApi('PUT', '/cmdb/' + encodeURIComponent(deviceId), body);
  if (!res) return;
  if (!res.ok) { alert('Save failed: ' + (res.data && res.data.error || res.status)); return; }
  closeModal('cmdb-asset-modal');
  cmdbReloadList();
  cmdbLoadServerFunctions();
}

// ── Credentials sub-tab ──────────────────────────────────────────────────────

async function cmdbLoadCreds(deviceId) {
  if (!deviceId) return;
  const warn = document.getElementById('cmdb-creds-locked-warning');
  const addBtn = document.getElementById('cmdb-creds-add-btn');
  const locked = !_cmdbVaultKey;
  warn.style.display = (locked && _cmdbVaultMeta && _cmdbVaultMeta.configured) ? 'block' : 'none';
  addBtn.disabled = locked;
  addBtn.style.opacity = locked ? '0.5' : '1';

  const res = await cmdbApi('GET', '/cmdb/' + encodeURIComponent(deviceId) + '/credentials');
  if (!res || !res.ok) return;
  const creds = (res.data && res.data.credentials) || [];
  const list = document.getElementById('cmdb-creds-list');
  if (creds.length === 0) {
    list.innerHTML = '<div class="isl-232">No credentials yet.</div>';
    return;
  }
  list.innerHTML = creds.map(c => {
    const note = c.note ? `<div class="isl-69">${_cmdbEsc(c.note)}</div>` : '';
    // v1.10.0: per-credential SSH link. Builds ssh://user@host:port for the
    // anchor + plain `ssh user@host -p port` for the copy button. Host comes
    // from the current asset's hostname (preferred) falling back to its IP.
    // The ssh:// URI deliberately omits the password — the password lives in
    // the reveal modal where it belongs, not in browser history.
    const sshHost = (_cmdbCurrent && (_cmdbCurrent.hostname || _cmdbCurrent.ip)) || '';
    const sshPort = (_cmdbCurrent && _cmdbCurrent.ssh_port) || 22;
    const sshUser = c.username || '';
    let sshButtons = '';
    if (sshHost && sshUser) {
      const portFrag = sshPort && sshPort !== 22 ? `:${sshPort}` : '';
      const sshUri = `ssh://${encodeURIComponent(sshUser)}@${sshHost}${portFrag}`;
      const sshCmd = sshPort && sshPort !== 22
        ? `ssh ${sshUser}@${sshHost} -p ${sshPort}`
        : `ssh ${sshUser}@${sshHost}`;
      sshButtons =
        `<a class="btn-icon isl-443" href="${_cmdbEsc(sshUri)}" title="Open ssh:// link in your default handler">SSH</a>
         <button class="btn-icon" title="Copy: ${_cmdbEsc(sshCmd)}" data-action="cmdbSshCopy" data-arg="${_cmdbEsc(sshCmd)}" >Copy</button>`;
    }
    return `<div class="isl-444">
      <div class="isl-445">
        <div class="fw-600">${_cmdbEsc(c.label)}</div>
        <div class="isl-328">user: ${_cmdbEsc(c.username) || '—'}</div>
        ${note}
      </div>
      <div class="isl-446">
        ${sshButtons}
        <button class="btn-icon" ${locked ? 'disabled' : ''} data-action="cmdbCredReveal" data-arg="${_cmdbEsc(deviceId)}" data-arg2="${_cmdbEsc(c.id)}" >Reveal</button>
        <button class="btn-icon" ${locked ? 'disabled' : ''} data-action="cmdbCredEditOpen" data-arg="${_cmdbEsc(deviceId)}" data-arg2="${_cmdbEsc(c.id)}" data-arg3="${_cmdbEsc(c.label)}" data-arg4="${_cmdbEsc(c.username)}" data-arg5="${_cmdbEsc(c.note || '')}">Edit</button>
        <button class="btn-icon c-red" data-action="cmdbCredDelete" data-arg="${_cmdbEsc(deviceId)}" data-arg2="${_cmdbEsc(c.id)}" >Delete</button>
      </div>
    </div>`;
  }).join('');
}

function cmdbSshCopy(cmd) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(
      () => toast && toast('SSH command copied', 'success'),
      () => alert('Copy failed — your browser may block clipboard access on http://')
    );
  } else {
    const ta = document.createElement('textarea');
    ta.value = cmd; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); if (typeof toast === 'function') toast('SSH command copied', 'success'); }
    catch (e) { alert('Copy failed.'); }
    document.body.removeChild(ta);
  }
}

function cmdbCredAddOpen() {
  if (!_cmdbVaultKey) { alert('Unlock the vault first.'); return; }
  if (!_cmdbCurrent)  return;
  document.getElementById('cmdb-cred-modal-mode').value = 'add';
  document.getElementById('cmdb-cred-modal-deviceid').value = _cmdbCurrent.device_id;
  document.getElementById('cmdb-cred-modal-credid').value = '';
  document.getElementById('cmdb-cred-modal-title').textContent = 'Add credential';
  document.getElementById('cmdb-cred-label').value    = '';
  document.getElementById('cmdb-cred-username').value = '';
  document.getElementById('cmdb-cred-password').value = '';
  document.getElementById('cmdb-cred-note').value     = '';
  openModal('cmdb-cred-add-modal');
}

function cmdbCredEditOpen(deviceId, credId, label, username, note) {
  if (!_cmdbVaultKey) { alert('Unlock the vault first.'); return; }
  document.getElementById('cmdb-cred-modal-mode').value = 'edit';
  document.getElementById('cmdb-cred-modal-deviceid').value = deviceId;
  document.getElementById('cmdb-cred-modal-credid').value = credId;
  document.getElementById('cmdb-cred-modal-title').textContent = 'Edit credential';
  document.getElementById('cmdb-cred-label').value    = label || '';
  document.getElementById('cmdb-cred-username').value = username || '';
  document.getElementById('cmdb-cred-password').value = '';
  document.getElementById('cmdb-cred-password').placeholder = '(leave empty to keep current)';
  document.getElementById('cmdb-cred-note').value     = note || '';
  openModal('cmdb-cred-add-modal');
}

async function cmdbCredSave() {
  const mode     = document.getElementById('cmdb-cred-modal-mode').value;
  const deviceId = document.getElementById('cmdb-cred-modal-deviceid').value;
  const credId   = document.getElementById('cmdb-cred-modal-credid').value;
  const body = {
    label:    document.getElementById('cmdb-cred-label').value.trim(),
    username: document.getElementById('cmdb-cred-username').value,
    note:     document.getElementById('cmdb-cred-note').value,
  };
  const pw = document.getElementById('cmdb-cred-password').value;
  if (mode === 'add') {
    if (!pw) { alert('Password required.'); return; }
    body.password = pw;
    const res = await cmdbApi('POST',
      '/cmdb/' + encodeURIComponent(deviceId) + '/credentials',
      body, true);
    if (!res || !res.ok) { alert('Save failed: ' + (res && res.data && res.data.error || '?')); return; }
  } else {
    if (pw) body.password = pw;
    const res = await cmdbApi('PUT',
      '/cmdb/' + encodeURIComponent(deviceId) + '/credentials/' + encodeURIComponent(credId),
      body, !!pw);
    if (!res || !res.ok) { alert('Save failed: ' + (res && res.data && res.data.error || '?')); return; }
  }
  closeModal('cmdb-cred-add-modal');
  cmdbLoadCreds(deviceId);
  cmdbReloadList();
}

async function cmdbCredDelete(deviceId, credId) {
  if (!confirm('Delete this credential? The encrypted password will be permanently removed.')) return;
  const res = await cmdbApi('DELETE',
    '/cmdb/' + encodeURIComponent(deviceId) + '/credentials/' + encodeURIComponent(credId));
  if (!res || !res.ok) { alert('Delete failed.'); return; }
  cmdbLoadCreds(deviceId);
  cmdbReloadList();
}

async function cmdbCredReveal(deviceId, credId) {
  if (!_cmdbVaultKey) { alert('Unlock the vault first.'); return; }
  const res = await cmdbApi('POST',
    '/cmdb/' + encodeURIComponent(deviceId) + '/credentials/' + encodeURIComponent(credId) + '/reveal',
    null, true);
  if (!res || !res.ok) {
    alert('Reveal failed: ' + (res && res.data && res.data.error || '?'));
    return;
  }
  document.getElementById('cmdb-cred-reveal-label').textContent    = res.data.label || '—';
  document.getElementById('cmdb-cred-reveal-username').textContent = res.data.username || '—';
  document.getElementById('cmdb-cred-reveal-password').textContent = res.data.password || '';
  const noteWrap = document.getElementById('cmdb-cred-reveal-note-wrap');
  if (res.data.note) {
    noteWrap.style.display = 'block';
    document.getElementById('cmdb-cred-reveal-note').textContent = res.data.note;
  } else {
    noteWrap.style.display = 'none';
  }
  openModal('cmdb-cred-reveal-modal');
}

function cmdbCredRevealClose() {
  // Wipe DOM nodes so the plaintext doesn't linger in the markup.
  document.getElementById('cmdb-cred-reveal-label').textContent    = '—';
  document.getElementById('cmdb-cred-reveal-username').textContent = '—';
  document.getElementById('cmdb-cred-reveal-password').textContent = '—';
  document.getElementById('cmdb-cred-reveal-note').textContent     = '—';
  closeModal('cmdb-cred-reveal-modal');
}

function cmdbCredCopy(elId) {
  const el = document.getElementById(elId);
  const txt = el && el.textContent;
  if (!txt || txt === '—') return;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(txt);
  } else {
    // Fallback for older browsers / non-HTTPS dev environments
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }
}

// ── v1.10.0: Update logs viewer ──────────────────────────────────────────────
// Independent of the CMDB system — this hangs off the device dropdown menu
// and shows the rolling buffer of package-upgrade output captured by the
// agent. Each run is collapsed by default; the most recent is auto-expanded.
let _updateLogsCurrent = null;     // {id, name}

async function openUpdateLogs(deviceId, name) {
  _updateLogsCurrent = {id: deviceId, name: name};
  document.getElementById('update-logs-title').textContent = `Update history — ${name}`;
  document.getElementById('update-logs-body').innerHTML =
    '<div class="empty-state">Loading…</div>';
  openModal('update-logs-modal');
  await reloadUpdateLogs();
}

async function reloadUpdateLogs() {
  if (!_updateLogsCurrent) return;
  const r = await api('GET', `/devices/${encodeURIComponent(_updateLogsCurrent.id)}/update-logs`);
  const body = document.getElementById('update-logs-body');
  if (!r) return;   // api() handled 401
  document.getElementById('update-logs-capacity').textContent = r.capacity || 10;
  const logs = (r.logs || []).slice().reverse();   // newest first
  if (!logs.length) {
    body.innerHTML = '<div class="empty-state">No update runs captured yet. Run "Upgrade packages" on this device — the output will land here on the next heartbeat (~60s).</div>';
    return;
  }
  // v2.8.1: deduplicate — suppress consecutive runs with identical output
  // (agents often send the same "0 upgraded" result every scan cycle)
  const dedupedLogs = [];
  let lastOutput = null;
  for (const entry of logs) {
    const out = (entry.output || '').trim();
    if (out !== lastOutput || entry.exit_code !== 0) {
      dedupedLogs.push(entry);
      lastOutput = out;
    }
  }
  body.innerHTML = dedupedLogs.map((entry, idx) => {
    const ok = entry.exit_code === 0;
    const status = ok
      ? '<span class="c-green">● success</span>'
      : `<span class="c-red">● failed (rc=${entry.exit_code})</span>`;
    const when = entry.finished_at
      ? new Date(entry.finished_at * 1000).toLocaleString()
      : '—';
    const duration = (entry.finished_at && entry.started_at)
      ? `${Math.max(0, entry.finished_at - entry.started_at)}s`
      : '?';
    const pm = entry.package_manager || 'unknown';
    const out = entry.output || '(no output captured)';
    const open = idx === 0 ? 'open' : '';
    return `<details ${open} class="isl-447">
      <summary class="isl-448">
        <span class="fw-500">${escHtml(when)}</span>
        <span class="hint">${escHtml(pm)} · ${escHtml(duration)}</span>
        <span class="isl-12">${status}</span>
      </summary>
      <pre class="isl-449">${escHtml(out)}</pre>
    </details>`;
  }).join('');
}


// ══════════════════════════════════════════════════════════════════════════════
// v1.11.0: Containers / Network map / TLS monitor / Agentless devices
// ══════════════════════════════════════════════════════════════════════════════

// ── Containers ───────────────────────────────────────────────────────────────
let _containersOverview = [];
// v1.11.4: id of the device whose detail modal is currently open. Used by
// the "Clear data" button to know which device's containers.json entry to
// wipe.
let _containersOpenDeviceId = null;

async function enterContainers() {
  await loadContainersOverview();
  // v3.3.4: image-update freshness for the agent-reported containers.
  loadImageUpdates();
  // v3.3.4: operator-uploaded compose stacks.
  loadComposeStacks();
  // v2.3.0: also pull Proxmox LXC containers (section self-hides if
  // Proxmox isn't configured).
  loadProxmoxLXC();
}

// ── v3.3.4: container image-update detection ───────────────────────────────
let _imageUpdates = [];

async function loadImageUpdates() {
  // Eager sort wire-up so the ↕ indicators show before data arrives.
  _registerImageUpdatesTable();
  const tbody = document.getElementById('image-updates-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="empty-state-sm">Loading…</td></tr>';
  const data = await api('GET', '/image-updates');
  _imageUpdates = (data && data.images) || [];
  _renderImageUpdatesMeta(data && data.summary);
  renderImageUpdates();
}

function _renderImageUpdatesMeta(summary) {
  const el = document.getElementById('image-updates-meta');
  if (!el) return;
  if (!summary) { el.textContent = ''; return; }
  const bits = [];
  if (summary.updates_available) bits.push(`${summary.updates_available} update(s) available`);
  if (summary.unchecked) bits.push(`${summary.unchecked} not yet checked`);
  if (summary.local) bits.push(`${summary.local} local`);
  if (summary.ignored) bits.push(`${summary.ignored} ignored`);
  if (!summary.enabled) bits.push('detection disabled');
  if (summary.last_full_scan) bits.push(`last scan ${new Date(summary.last_full_scan * 1000).toLocaleString()}`);
  el.textContent = bits.length ? `— ${bits.join(' · ')}` : '';
}

let _imageUpdatesRegistered = false;
function _registerImageUpdatesTable() {
  if (_imageUpdatesRegistered) return;
  _imageUpdatesRegistered = true;
  tableCtl.register({
    name: 'image-updates',
    tbody: 'image-updates-tbody',
    filterInput: 'image-updates-search',
    sortHeaders: 'image-updates-thead',
    colspan: 7,
    columns: ['image', 'tag', 'hosts', 'status', 'registry', 'checked'],
    getColumns: (r) => ({
      image:    r.image || '',
      tag:      r.tag || '',
      hosts:    (r.hosts || []).length,
      // Sort rank mirrors the server: update(0) < unchecked(1) <
      // up-to-date(2) < local(3) < ignored(4).
      status:   r.update_available ? 0 : (r.ignored ? 4 : (r.local ? 3 : (r.registry_digest ? 2 : 1))),
      registry: r.registry || '',
      checked:  r.last_checked || 0,
    }),
    match: (r, q) =>
      (r.image || '').toLowerCase().includes(q) ||
      (r.tag || '').toLowerCase().includes(q) ||
      (r.registry || '').toLowerCase().includes(q),
    row: (r) => {
      let statusCell;
      if (r.ignored) {
        statusCell = `<span class="patch-badge" title="${escAttr(r.ignore_reason || 'Accepted — not alerting')}">Ignored</span>`;
      } else if (r.local) {
        statusCell = `<span class="c-muted" title="Locally-built or loaded image — no registry to compare against">Local</span>`;
      } else if (r.update_available) {
        statusCell = `<span class="patch-badge warn">Update available</span>`;
      } else if (r.registry_digest) {
        statusCell = `<span class="patch-badge ok">Up to date</span>`;
      } else if (r.last_error) {
        statusCell = `<span class="c-muted" title="${escAttr(r.last_error)}">Unknown</span>`;
      } else {
        statusCell = `<span class="c-muted">Not checked</span>`;
      }
      const hosts = (r.hosts || []);
      const hostTitle = hosts.map(h => `${h.device_name}${h.stale ? ' (stale)' : ''}`).join(', ');
      const checked = (r.local || !r.last_checked) ? '—' : new Date(r.last_checked * 1000).toLocaleString();
      const action = r.ignored
        ? `<button class="btn-icon" data-action="unignoreImageUpdate" data-arg="${escAttr(r.ref)}" title="Resume alerting on updates for this image">Un-ignore</button>`
        : `<button class="btn-icon c-muted" data-action="ignoreImageUpdate" data-arg="${escAttr(r.ref)}" title="Accept the current version and stop alerting until a newer one ships">Ignore</button>`;
      return `<tr>
        <td class="fw-500">${escHtml(r.image)}</td>
        <td class="mono-12">${escHtml(r.tag)}</td>
        <td title="${escAttr(hostTitle)}">${hosts.length}</td>
        <td>${statusCell}</td>
        <td class="hint">${escHtml(r.registry || '—')}</td>
        <td class="hint-nowrap">${checked}</td>
        <td class="nowrap">${action}</td>
      </tr>`;
    },
    emptyMsg: 'No container images reported yet. The agent reports image digests with each container sweep (~5 min when Docker/Podman is installed); the server then checks each unique image against its registry.',
    emptyMsgFiltered: 'No images match the filter.',
  });
}

function renderImageUpdates() {
  _registerImageUpdatesTable();
  tableCtl.render('image-updates', _imageUpdates || []);
}

async function scanImageUpdatesNow(btn) {
  const original = btn ? btn.innerHTML : '';
  if (btn) { btn.disabled = true; btn.innerHTML = 'Scanning…'; }
  try {
    const r = await api('POST', '/image-updates/scan', {});
    if (r && r.ok) {
      toast(`Checked ${r.checked} image(s)`, 'success');
      await loadImageUpdates();
    } else {
      toast((r && r.error) || 'Scan failed', 'error');
    }
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = original; }
  }
}

async function ignoreImageUpdate(ref) {
  const reason = window.prompt(
    `Accept the current version of "${ref}" and stop alerting until a newer one ships?\n\nReason (optional):`, '');
  if (reason === null) return;   // cancelled
  const r = await api('POST', '/image-updates/ignore', { ref, reason });
  if (r && r.ok) { toast('Image ignored', 'success'); loadImageUpdates(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function unignoreImageUpdate(ref) {
  const r = await api('DELETE', '/image-updates/ignore', { ref });
  if (r && r.ok) { toast('Resumed update alerts', 'success'); loadImageUpdates(); }
  else toast((r && r.error) || 'Failed', 'error');
}

// ── v3.3.4: compose stacks ─────────────────────────────────────────────────
let _composeStacks = [];

async function loadComposeStacks() {
  _registerComposeStacksTable();
  const tbody = document.getElementById('compose-stacks-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="empty-state-sm">Loading…</td></tr>';
  const data = await api('GET', '/compose/stacks');
  _composeStacks = (data && data.stacks) || [];
  renderComposeStacks();
}

let _composeStacksRegistered = false;
function _registerComposeStacksTable() {
  if (_composeStacksRegistered) return;
  _composeStacksRegistered = true;
  tableCtl.register({
    name: 'compose-stacks',
    tbody: 'compose-stacks-tbody',
    sortHeaders: 'compose-stacks-thead',
    colspan: 5,
    columns: ['name', 'device', 'status', 'last'],
    getColumns: (s) => ({
      name:   s.name || '',
      device: s.device_name || '',
      status: s.status || '',
      last:   s.last_action_ts || 0,
    }),
    row: (s) => {
      const statusMap = {
        up:        '<span class="patch-badge ok">Up</span>',
        down:      '<span class="c-muted">Down</span>',
        deploying: '<span class="patch-badge warn">Deploying…</span>',
        error:     '<span class="c-red">Error</span>',
        created:   '<span class="c-muted">Not deployed</span>',
      };
      const statusCell = statusMap[s.status] || `<span class="c-muted">${escHtml(s.status || '?')}</span>`;
      const last = s.last_action_ts
        ? `${escHtml(s.last_action || '')} · ${new Date(s.last_action_ts * 1000).toLocaleString()}`
        : '—';
      const view = `<button class="btn-icon badge-xs" data-action="viewComposeStack" data-arg="${escAttr(s.id)}">View</button>`;
      const del = `<button class="btn-icon badge-xs c-danger-outline" data-action="deleteComposeStack" data-arg="${escAttr(s.id)}" data-arg2="${escAttr(s.name)}">Delete</button>`;
      let actions;
      if (s.compose_enabled) {
        actions =
          `<button class="btn-icon badge-xs" data-action="composeStackAction" data-arg="${escAttr(s.id)}" data-arg2="up" title="docker compose up -d">Up</button>` +
          `<button class="btn-icon badge-xs" data-action="composeStackAction" data-arg="${escAttr(s.id)}" data-arg2="down" title="docker compose down">Down</button>` +
          `<button class="btn-icon badge-xs" data-action="composeStackAction" data-arg="${escAttr(s.id)}" data-arg2="redeploy" title="docker compose pull + up -d">Redeploy</button>` +
          view + del;
      } else {
        actions =
          `<span class="hint">deploys off</span> ` +
          `<button class="btn-icon badge-xs" data-action="enableComposeOnDevice" data-arg="${escAttr(s.device_id)}" data-arg2="${escAttr(s.device_name)}" title="Allow compose deploys on this device">Enable</button>` +
          view + del;
      }
      return `<tr>
        <td class="fw-500">${escHtml(s.name)}</td>
        <td class="hint">${escHtml(s.device_name)}</td>
        <td>${statusCell}</td>
        <td class="hint-nowrap">${last}</td>
        <td class="nowrap">${actions}</td>
      </tr>`;
    },
    emptyMsg: 'No compose stacks yet. Click "New stack" to upload a docker-compose file and deploy it to a device.',
  });
}

function renderComposeStacks() {
  _registerComposeStacksTable();
  tableCtl.render('compose-stacks', _composeStacks || []);
}

async function openComposeCreate() {
  const sel = document.getElementById('compose-create-device');
  const devs = await api('GET', '/devices');
  const list = Array.isArray(devs) ? devs : (devs && devs.devices) || [];
  sel.innerHTML = list
    .filter(d => !d.agentless)
    .map(d => `<option value="${escAttr(d.id)}">${escHtml(d.name)}${d.compose_enabled ? '' : ' (deploys off)'}</option>`)
    .join('') || '<option value="">No agent devices</option>';
  document.getElementById('compose-create-name').value = '';
  document.getElementById('compose-create-yaml').value = '';
  openModal('compose-create-modal');
}

async function submitComposeStack() {
  const name = document.getElementById('compose-create-name').value.trim();
  const device_id = document.getElementById('compose-create-device').value;
  const yaml = document.getElementById('compose-create-yaml').value;
  if (!name || !device_id || !yaml.trim()) {
    toast('Name, device, and compose file are all required', 'error'); return;
  }
  const r = await api('POST', '/compose/stacks', { name, device_id, yaml });
  if (r && r.ok) { toast('Stack created', 'success'); closeModal('compose-create-modal'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function composeStackAction(stackId, action) {
  if (action === 'down' && !confirm('Run `docker compose down` for this stack?')) return;
  const r = await api('POST', `/compose/stacks/${encodeURIComponent(stackId)}/action`, { action });
  if (r && r.ok) { toast(`${action} queued — runs on the device's next heartbeat (~60s)`, 'success'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function deleteComposeStack(stackId, name) {
  if (!confirm(`Delete stack "${name}"?\n\nThis only removes it from RemotePower — it does NOT stop running containers. Run "Down" first if you want to tear it down.`)) return;
  const r = await api('DELETE', `/compose/stacks/${encodeURIComponent(stackId)}`);
  if (r && r.ok) { toast('Stack deleted', 'success'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function enableComposeOnDevice(deviceId, deviceName) {
  if (!confirm(`Enable compose deploys on "${deviceName}"?\n\nThis lets RemotePower run uploaded compose files as root on that host.`)) return;
  const r = await api('PATCH', `/devices/${encodeURIComponent(deviceId)}/compose_enabled`, { compose_enabled: true });
  if (r && r.ok) { toast('Compose deploys enabled', 'success'); loadComposeStacks(); }
  else toast((r && r.error) || 'Failed', 'error');
}

async function viewComposeStack(stackId) {
  const body = document.getElementById('compose-view-body');
  body.innerHTML = '<div class="empty-state">Loading…</div>';
  openModal('compose-view-modal');
  const s = await api('GET', `/compose/stacks/${encodeURIComponent(stackId)}`);
  if (!s || s.error) { body.innerHTML = `<div class="c-red">${escHtml((s && s.error) || 'Failed')}</div>`; return; }
  document.getElementById('compose-view-title').textContent = `Stack — ${s.name || ''}`;
  const out = s.last_output
    ? `<h4>Last run (${escHtml(s.last_action || '')}, rc=${s.last_rc != null ? s.last_rc : '?'})</h4><pre class="isl-514"><code>${escHtml(s.last_output)}</code></pre>`
    : '';
  body.innerHTML = `<h4>docker-compose.yml</h4><pre class="isl-514"><code>${escHtml(s.yaml || '')}</code></pre>${out}`;
}

async function loadContainersOverview() {
  const tbody = document.getElementById('containers-tbody');
  tbody.innerHTML = '<tr><td colspan="9" class="empty-state-sm">Loading…</tbody>';
  const data = await api('GET', '/containers');
  _containersOverview = Array.isArray(data) ? data : [];
  renderContainersOverview();
}

// v1.11.5: containers overview now goes through tableCtl. The existing
// containers-search input keeps working, but we also wire up sortable
// headers (data-col attrs in the <thead>), and the filter is persisted
// per-user. The old in-memory filter input keeps its existing behaviour
// — we wire it as the tableCtl filterInput so persistence is automatic.
let _containersOverviewRegistered = false;
function _registerContainersOverviewTable() {
  if (_containersOverviewRegistered) return;
  _containersOverviewRegistered = true;
  tableCtl.register({
    name: 'containers',
    tbody: 'containers-tbody',
    filterInput: 'containers-search',
    sortHeaders: 'containers-thead',
    colspan: 9,
    columns: ['name', 'os', 'total', 'running', 'stopped', 'restarting', 'runtimes', 'reported_at'],
    getColumns: (r) => {
      const s = r.summary || {};
      return {
        name:       r.name || '',
        os:         r.os || '',
        total:      s.total || 0,
        running:    s.running || 0,
        stopped:    s.stopped || 0,
        restarting: s.restarting || 0,
        // Concatenate runtime names so sorting groups same-runtime hosts
        runtimes:   Object.keys(s.by_runtime || {}).sort().join(','),
        reported_at: r.reported_at || 0,
      };
    },
    match: (r, q) => {
      if ((r.name || '').toLowerCase().includes(q)) return true;
      if ((r.os || '').toLowerCase().includes(q)) return true;
      return false;
    },
    row: (r) => {
      const s = r.summary || {total: 0, running: 0, stopped: 0, restarting: 0, by_runtime: {}};
      const runtimes = Object.entries(s.by_runtime || {})
        .map(([rt, n]) => `${escHtml(rt)}: ${n}`)
        .join(', ') || '—';
      const reported = r.reported_at ? new Date(r.reported_at * 1000).toLocaleString() : '—';
      const staleBadge = r.is_stale
        ? '<span class="isl-450">STALE</span>'
        : '';
      const restartingCell = s.restarting > 0
        ? `<span class="c-red">${s.restarting}</span>`
        : `<span class="c-muted">0</span>`;
      return `<tr${r.is_stale ? '' : ''} class="isl-451">
        <td class="fw-500">${osIcon(r.os, 14)} ${escHtml(r.name)}</td>
        <td class="hint">${escHtml(r.os || '—')}</td>
        <td class="fw-500">${s.total}</td>
        <td class="c-green">${s.running}</td>
        <td class="c-muted">${s.stopped}</td>
        <td>${restartingCell}</td>
        <td class="hint">${runtimes}</td>
        <td class="hint-nowrap">${reported}${staleBadge}</td>
        <td class="row-4">
          <button class="btn-icon" data-action="containersOpen" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.name)}" >View</button>
          <button class="btn-icon c-muted" title="Hide this device from the Containers page" data-action="ignoreContainerDevice" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.name)}" >×</button>
        </td>
      </tr>`;
    },
    emptyMsg: 'No devices have reported containers yet. The agent reports every 5 polls (~5 minutes) when Docker, Podman, or Kubernetes is installed. Stale rows are flagged automatically.',
    emptyMsgFiltered: 'No containers match the filter.',
  });
}

function renderContainersOverview() {
  _registerContainersOverviewTable();
  tableCtl.render('containers', _containersOverview || []);
}

async function containersOpen(deviceId, name) {
  _containersOpenDeviceId = deviceId;
  document.getElementById('containers-detail-title').textContent = `Containers — ${name}`;
  const body = document.getElementById('containers-detail-body');
  body.innerHTML = '<div class="empty-state">Loading…</div>';
  openModal('containers-detail-modal');
  const data = await api('GET', `/devices/${encodeURIComponent(deviceId)}/containers`);
  if (!data) return;
  const items = data.items || [];
  // v1.11.4: stale-data warning at the top of the modal.
  const reportedHuman = data.reported_at ? new Date(data.reported_at * 1000).toLocaleString() : 'never';
  const staleBanner = data.is_stale
    ? `<div class="isl-452">
         Container data is stale (last reported: ${escHtml(reportedHuman)}).
         Agent reports every ~5 min when a runtime is installed; check
         <code>journalctl -u remotepower-agent</code> on the device.
       </div>`
    : '';
  if (!items.length) {
    body.innerHTML = staleBanner + '<div class="empty-state">No containers reported.</div>';
    return;
  }
  body.innerHTML = staleBanner + items.map(c => {
    const statusLower = (c.status || '').toLowerCase();
    const statusColor = statusLower.includes('running') || statusLower.includes('up ')
      ? 'var(--green)'
      : statusLower.includes('exit') ? 'var(--red)' : 'var(--muted)';
    const ports = (c.ports || []).map(p => `<code class="isl-453">${escHtml(p)}</code>`).join(' ');
    const restart = c.restart_count > 0
      ? `<span class="isl-454 ${c.restart_count >= 5 ? 'c-red' : 'c-amber'}">restart×${c.restart_count}</span>`
      : '';
    const ns = c.namespace ? `<span class="c-muted">${escHtml(c.namespace)}/</span>` : '';
    // v2.2.6: container health badge — the agent parses (healthy)/
    // (unhealthy)/(starting) out of the docker status string.
    let healthBadge = '';
    if (c.health === 'healthy') {
      healthBadge = '<span class="status-pill ok isl-455">healthy</span>';
    } else if (c.health === 'unhealthy') {
      healthBadge = '<span class="status-pill critical isl-455">unhealthy</span>';
    } else if (c.health === 'starting') {
      healthBadge = '<span class="status-pill warn isl-455">starting</span>';
    }
    // v2.2.6: per-container CPU / memory from `docker stats`. Only
    // shown when the agent reported them (omitted for kubectl pods
    // and older agents).
    let resourceLine = '';
    if (c.cpu_percent != null || c.mem_percent != null) {
      const cpuTxt = c.cpu_percent != null ? `CPU ${c.cpu_percent}%` : '';
      const memTxt = c.mem_percent != null
        ? `MEM ${c.mem_percent}%${c.mem_usage ? ` (${escHtml(c.mem_usage)})` : ''}`
        : '';
      const memColor = c.mem_percent > 85 ? 'var(--red)'
                     : c.mem_percent > 70 ? 'var(--amber)' : 'var(--muted)';
      resourceLine = `<div class="isl-456">
        ${cpuTxt ? `<span>${cpuTxt}</span>` : ''}
        ${memTxt ? `<span class="isl-457" data-color="${memColor}">${memTxt}</span>` : ''}
      </div>`;
    }
    const cid = c.id || c.name || '';
    const runtime = (c.runtime || 'docker').toLowerCase();
    const actionable = (runtime === 'docker' || runtime === 'podman') && cid;
    const isRunning = statusLower.includes('running') || statusLower.includes('up ');
    const actions = actionable ? `
      <div class="isl-458">
        ${!isRunning ? `<button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="start" data-arg5="${escAttr(c.name||'')}">Start</button>` : ''}
        ${isRunning  ? `<button class="btn-icon isl-459" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="stop" data-arg5="${escAttr(c.name||'')}">Stop</button>` : ''}
        <button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="restart" data-arg5="${escAttr(c.name||'')}">Restart</button>
        <button class="btn-icon badge-xs" data-action="containerAction" data-arg="${escAttr(deviceId)}" data-arg2="${escAttr(runtime)}" data-arg3="${escAttr(cid)}" data-arg4="logs" data-arg5="${escAttr(c.name||'')}">Logs</button>
      </div>` : '';
    return `<div class="isl-460">
      <div class="isl-461">
        <div class="isl-462">${ns}${escHtml(c.name)}${healthBadge}</div>
        <div class="isl-463">
          <span class="isl-376" data-color="${statusColor}">${escHtml(c.status || '?')}</span>
          ${restart}
          <span class="cmd-badge ${escHtml(c.runtime)} isl-464">${escHtml(c.runtime)}</span>
        </div>
      </div>
      <div class="isl-465">${escHtml(c.image)}${c.tag ? ':' + escHtml(c.tag) : ''}</div>
      ${resourceLine}
      ${ports ? `<div class="isl-466">${ports}</div>` : ''}
      ${actions}
    </div>`;
  }).join('');
}

// v2.1.1: per-container action — start/stop/restart/logs. Goes through
// the agent's command queue (same path as compose actions), so output
// arrives on the next heartbeat. Stop and restart prompt for confirmation
// because they're disruptive; start and logs don't.
async function containerAction(deviceId, runtime, containerId, action, displayName) {
  const verb = action.charAt(0).toUpperCase() + action.slice(1);
  if ((action === 'stop' || action === 'restart') &&
      !confirm(`${verb} container ${displayName || containerId}?`)) return;
  const resp = await api('POST',
    '/devices/' + encodeURIComponent(deviceId) + '/containers/action',
    {runtime, action, container_id: containerId});
  if (!resp || resp.error) { toast(resp?.error || 'Failed', 'error'); return; }
  toast(`${verb} queued — runs on next heartbeat (~60s)`, 'success');
}

// v1.11.4: clear stored container data for the currently-open device.
// The agent will repopulate on its next heartbeat (~5 min by default), so
// this is safe to use during decommissioning or just to force a refresh
// after deliberately removing containers via `docker rm`.
async function containersClearCurrent() {
  if (!_containersOpenDeviceId) return;
  if (!confirm('Clear stored container data for this device?\n\nThis only clears the dashboard snapshot — it does NOT touch any actual containers on the host. The agent will repopulate the list on its next heartbeat (~5 min).')) {
    return;
  }
  const deviceId = _containersOpenDeviceId;
  const res = await api('DELETE', `/devices/${encodeURIComponent(deviceId)}/containers`);
  if (res?.ok) {
    toast(res.cleared ? 'Container data cleared' : 'Nothing to clear', 'success');
    closeModal('containers-detail-modal');
    // Refresh overview so the row disappears (or shows "—" until next report)
    await loadContainersOverview();
  } else {
    toast('Failed to clear container data', 'error');
  }
}

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
}

async function loadNetmap() {
  const data = await api('GET', '/network-map');
  if (!data) return;
  // v3.0.5: guard against the demo / read-only API path that returns
  // `{}` (or `{error: ...}`) instead of the full shape. Previously
  // `data.nodes.map(...)` would throw "can't access property 'map',
  // data.nodes is undefined" and the page would render blank.
  _netmapData = {
    nodes:   Array.isArray(data.nodes)   ? data.nodes   : [],
    edges:   Array.isArray(data.edges)   ? data.edges   : [],
    tunnels: Array.isArray(data.tunnels) ? data.tunnels : [],
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
  document.getElementById('netmap-stats').textContent =
    `${_netmapData.nodes.length} node(s), ${_netmapData.edges.length} link(s), ${_netmapData.tunnels.length} tunnel(s)`;
}

// SVG renderer — physical edges as solid lines, tunnels as dashed amber.
// Each node lives in a <g> that we can move with `transform=translate(...)`
// during drag, instead of regenerating innerHTML (which would orphan the
// pointer-captured element and limit drags to a single pointermove).
function renderNetmap() {
  const svg = document.getElementById('netmap-svg');
  if (!svg) return;
  if (!_netmapNodes.length) {
    svg.innerHTML = '<text x="50%" y="50%" fill="currentColor" opacity="0.6" font-size="14" text-anchor="middle">No devices yet. Enroll an agent or add an agentless device.</text>';
    return;
  }
  const lookup = Object.fromEntries(_netmapNodes.map(n => [n.id, n]));
  // Edges first so they're behind the nodes. We give each edge an id so
  // _netmapUpdateEdges() can locate and update its endpoints in place
  // during a drag without touching the node DOM.
  const edgeMarkup = (_netmapData.edges || []).map((e, i) => {
    const a = lookup[e.from], b = lookup[e.to];
    if (!a || !b) return '';
    return `<line data-edge-from="${escHtml(e.from)}" data-edge-to="${escHtml(e.to)}" data-edge-kind="phys" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--border)" stroke-width="1.5" opacity="0.65"/>`;
  }).join('');
  const tunnelMarkup = (_netmapData.tunnels || []).map((t, i) => {
    const a = lookup[t.endpoints[0]], b = lookup[t.endpoints[1]];
    if (!a || !b) return '';
    return `<line data-edge-from="${escHtml(t.endpoints[0])}" data-edge-to="${escHtml(t.endpoints[1])}" data-edge-kind="tun" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="var(--amber)" stroke-width="2" stroke-dasharray="6 4" opacity="0.85"><title>Tunnel: ${escHtml(a.name)} ↔ ${escHtml(b.name)}</title></line>`;
  }).join('');
  // Nodes — single <g class="netmap-node"> per device. The shapes inside use
  // coordinates relative to the node's centre (0,0); the <g> itself is
  // positioned via `transform="translate(x, y)"`. This way a drag updates
  // a single attribute instead of rewriting the whole subtree.
  const nodeMarkup = _netmapNodes.map(n => {
    const fill   = n.online ? 'var(--green)' : 'var(--red)';
    const stroke = n.agentless ? 'var(--amber)' : 'var(--accent)';
    const r = 14;
    return `<g class="netmap-node isl-467" data-node-id="${escHtml(n.id)}" transform="translate(${n.x}, ${n.y})">
      <circle cx="0" cy="0" r="${r}" fill="${fill}" fill-opacity="0.18" stroke="${stroke}" stroke-width="2"/>
      <text x="0" y="4" font-size="10" fill="currentColor" text-anchor="middle" font-weight="600" pointer-events="none">${escHtml((n.type || '?').slice(0,3).toUpperCase())}</text>
      <text x="0" y="${r + 14}" font-size="11" fill="currentColor" text-anchor="middle" pointer-events="none">${escHtml(n.name)}</text>
      <text x="0" y="${r + 28}" font-size="10" fill="currentColor" opacity="0.55" text-anchor="middle" pointer-events="none">${escHtml(n.ip || '')}</text>
    </g>`;
  }).join('');
  svg.innerHTML = edgeMarkup + tunnelMarkup + nodeMarkup;
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
  const nodes = _netmapData.nodes;
  if (!nodes.length) {
    body.innerHTML = '<div class="empty-state">No devices to link.</div>';
    openModal('netmap-edit-modal');
    return;
  }
  // Build an option list of all devices for the dropdowns
  const optsHtml = '<option value="">— none —</option>' +
    nodes.map(n => `<option value="${escHtml(n.id)}">${escHtml(n.name)} (${escHtml(n.type || 'host')})</option>`).join('');
  body.innerHTML = `<table class="w-full"><thead><tr class="isl-468"><th class="cell-m">Device</th><th class="cell-m">Type</th><th class="cell-m">Connected to (upstream)</th></tr></thead><tbody>${
    nodes.map(n => {
      const cur = (_netmapData.edges.find(e => e.from === n.id) || {}).to || '';
      // Build per-row options where the current value is selected and self-link is removed
      const rowOpts = '<option value="">— none —</option>' +
        nodes.filter(o => o.id !== n.id).map(o =>
          `<option value="${escHtml(o.id)}"${o.id === cur ? ' selected' : ''}>${escHtml(o.name)} (${escHtml(o.type || 'host')})</option>`
        ).join('');
      return `<tr>
        <td class="isl-469">${escHtml(n.name)}</td>
        <td class="isl-470">${escHtml(n.type || 'host')}</td>
        <td class="cell-m"><select class="form-input netmap-link-sel w-full" data-device-id="${escHtml(n.id)}" data-original="${escHtml(cur)}">${rowOpts}</select></td>
      </tr>`;
    }).join('')
  }</tbody></table>`;
  openModal('netmap-edit-modal');
}

async function netmapEditSaveAll() {
  const sels = Array.from(document.querySelectorAll('.netmap-link-sel'));
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
    <button class="btn-icon c-danger-outline" data-action="tunnelDelete" data-arg="${escAttr(t.id)}" >✕</button>
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
  if (!confirm('Delete this tunnel?')) return;
  const r = await api('DELETE', '/network-map/tunnels/' + encodeURIComponent(id));
  if (!r || !r.ok) { toast('Delete failed', 'error'); return; }
  await tunnelRenderList();
  await loadNetmap();
}

async function netmapResetPositions() {
  if (!confirm('Clear all manual positions and revert to auto-layout?')) return;
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
  tbody.innerHTML = '<tr><td colspan="8" class="empty-state-sm">Loading…</tbody>';
  const data = await api('GET', '/tls/targets');
  _tlsTargets = Array.isArray(data) ? data : [];
  renderTLS();
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
  if (!confirm(`Remove TLS target ${host}?`)) return;
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
      recordsHtml = `<table class="isl-480">
        <thead><tr class="isl-481">
          <th class="isl-44">Usage</th>
          <th class="isl-44">Selector</th>
          <th class="isl-44">Match</th>
          <th class="isl-44">Data</th>
        </tr></thead><tbody>
        ${t.dane_records.map(r => `<tr>
          <td class="isl-44">${r.usage}</td>
          <td class="isl-44">${r.selector}</td>
          <td class="isl-44">${r.matching_type}</td>
          <td class="isl-482">${escHtml(String(r.data || '').slice(0, 64))}${(r.data || '').length > 64 ? '…' : ''}</td>
        </tr>`).join('')}
        </tbody></table>`;
    }
    daneHtml = `<div class="isl-483">
      <div class="isl-421">DANE / TLSA</div>
      <div class="isl-484" data-color="${colour}">${escHtml(text)}</div>
      ${t.dane_error ? `<div class="isl-485">${escHtml(t.dane_error)}</div>` : ''}
      ${recordsHtml}
    </div>`;
  }

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
    ${daneHtml}
  `;
  openModal('tls-detail-modal');
}

// ── Agentless devices (modal opener used from Devices page) ──────────────────

async function agentlessAddOpen() {
  document.getElementById('al-name').value = '';
  document.getElementById('al-hostname').value = '';
  document.getElementById('al-ip').value = '';
  document.getElementById('al-mac').value = '';
  document.getElementById('al-group').value = '';
  document.getElementById('al-notes').value = '';
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
  return `<a href="${escHtml(l.url)}" target="_blank" rel="noopener noreferrer" class="isl-501">${cardInner}</a>`;
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
  if (!confirm(`Delete link "${title}"?`)) return;
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

// ─── v2.1.0: Script library + multi-select batch exec + docker-compose ────
//
// Three features that share UI plumbing:
//
//   * Scripts page (CRUD over /api/scripts).
//   * "Run script" button on the existing batch action bar — fans out to
//     /api/exec/batch and shows live job status via /api/exec/batch/<id>.
//   * Docker-compose dropdown on device cards: up/down/restart/pull/logs,
//     pointing only at projects the agent itself reported in its heartbeat.
//
// All three rendering paths use escHtml() for text and escAttr() for
// JS-in-onclick — see the comment on escAttr above. Mixing them up is
// the exact bug that triggered the 2.0.0 auto-refresh crash.

let _scriptsCache = [];

async function loadScripts() {
  const tbody = document.getElementById('scripts-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="6"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="6"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="6"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="6"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="6"><div class="skeleton skeleton-line long"></div></td></tr>';
  const data = await api('GET', '/scripts');
  _scriptsCache = Array.isArray(data) ? data : [];
  renderScriptsList();
}

function renderScriptsList() {
  const tbody = document.getElementById('scripts-tbody');
  if (!tbody) return;
  const term = (document.getElementById('scripts-filter')?.value || '').toLowerCase();
  let rows = _scriptsCache;
  if (term) {
    rows = rows.filter(s => (s.name||'').toLowerCase().includes(term) ||
                            (s.description||'').toLowerCase().includes(term));
  }
  // v3.2.1: sortable
  tableCtl.wireSortOnly('scripts-thead', 'scripts', renderScriptsList);
  rows = tableCtl.sortRows('scripts', rows, (s) => ({
    name:        (s.name || '').toLowerCase(),
    description: (s.description || '').toLowerCase(),
    size:        s.body_len || 0,
    updated:     s.updated || 0,
    flags:       s.dangerous ? 1 : 0,
  }));
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="empty-state">${_scriptsCache.length ? 'No matches' : 'No scripts yet. Click <b>New script</b> to create one.'}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(s => {
    const size = s.body_len < 1024 ? `${s.body_len} B` : `${(s.body_len/1024).toFixed(1)} KB`;
    const updated = s.updated ? timeAgo(s.updated) : '—';
    const dangerBadge = s.dangerous
      ? '<span class="patch-badge warn" title="Dry run flagged dangerous patterns">DANGER</span>'
      : '';
    return `<tr>
      <td class="fw-500">${escHtml(s.name||'—')}</td>
      <td class="hint">${escHtml(s.description||'')}</td>
      <td class="isl-328">${escHtml(size)}</td>
      <td class="hint">${escHtml(updated)}</td>
      <td>${dangerBadge}</td>
      <td class="nowrap">
        <button class="btn-icon isl-352" data-action="openScriptEdit" data-arg="${escAttr(s.id)}" >Edit</button>
        <button class="btn-icon isl-352" data-action="dryRunScript" data-arg="${escAttr(s.id)}" >Dry run</button>
        <button class="btn-icon isl-502" data-action="deleteScript" data-arg="${escAttr(s.id)}" data-arg2="${escAttr(s.name||'')}">Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function openScriptAdd() {
  document.getElementById('script-edit-id').value = '';
  document.getElementById('script-edit-title').textContent = 'New script';
  document.getElementById('script-edit-name').value = '';
  document.getElementById('script-edit-desc').value = '';
  document.getElementById('script-edit-body').value = '#!/usr/bin/env bash\nset -euo pipefail\n\n';
  document.getElementById('script-edit-lint').style.display = 'none';
  openModal('script-edit-modal');
  setTimeout(() => document.getElementById('script-edit-name').focus(), 50);
}

async function openScriptEdit(id) {
  const data = await api('GET', '/scripts/' + encodeURIComponent(id));
  if (!data || data.error) { toast(data?.error || 'Failed', 'error'); return; }
  document.getElementById('script-edit-id').value = data.id;
  document.getElementById('script-edit-title').textContent = `Edit script — ${data.name||''}`;
  document.getElementById('script-edit-name').value = data.name || '';
  document.getElementById('script-edit-desc').value = data.description || '';
  document.getElementById('script-edit-body').value = data.body || '';
  _renderLintIntoBox('script-edit-lint', data.last_lint || null);
  openModal('script-edit-modal');
}

function _renderLintIntoBox(boxId, lint) {
  const el = document.getElementById(boxId);
  if (!el) return;
  if (!lint) { el.style.display = 'none'; return; }
  let bg = 'rgba(34,197,94,0.12)';
  let fg = 'var(--green)';
  let head = '✓ Syntax OK';
  if (lint.syntax_error && lint.syntax_error !== '__skipped__') {
    bg = 'rgba(239,68,68,0.12)'; fg = 'var(--red)';
    head = '✗ ' + lint.syntax_error;
  } else if (lint.syntax_error === '__skipped__') {
    bg = 'rgba(245,158,11,0.12)'; fg = 'var(--amber)';
    head = 'bash -n not available server-side — syntax check skipped';
  }
  let body = head;
  if (lint.dangerous && lint.dangerous.length) {
    body += '\n\nDangerous patterns detected:';
    lint.dangerous.forEach(d => { body += '\n  • ' + d; });
  }
  el.style.background = bg;
  el.style.color = fg;
  el.textContent = body;
  el.style.display = 'block';
}

async function runScriptDryRunFromEditor() {
  const id = document.getElementById('script-edit-id').value;
  if (!id) {
    // Not saved yet — save first, then dry-run. Otherwise we have no
    // server-side body to lint and the operator would just see an empty
    // result. This also gives them an "id" they can later edit.
    await saveScriptFromEditor(/*reopen=*/true);
    return;
  }
  const data = await api('POST', '/scripts/' + encodeURIComponent(id) + '/dry-run');
  if (!data || data.error) { toast(data?.error || 'Dry run failed', 'error'); return; }
  _renderLintIntoBox('script-edit-lint', data.lint);
  toast('Dry run complete', 'info');
  // Refresh list cache (last_lint may have changed).
  loadScripts();
}

async function saveScriptFromEditor(reopenAfter) {
  const id   = document.getElementById('script-edit-id').value;
  const name = document.getElementById('script-edit-name').value.trim();
  const desc = document.getElementById('script-edit-desc').value;
  const body = document.getElementById('script-edit-body').value;
  if (!name) { toast('Name required', 'error'); return; }
  if (!body.trim()) { toast('Body required', 'error'); return; }
  let resp;
  if (id) {
    resp = await api('PUT', '/scripts/' + encodeURIComponent(id), {name, description: desc, body});
  } else {
    resp = await api('POST', '/scripts', {name, description: desc, body});
  }
  if (!resp || resp.error) { toast(resp?.error || 'Save failed', 'error'); return; }
  toast(id ? 'Script updated' : 'Script created', 'success');
  if (resp.lint) _renderLintIntoBox('script-edit-lint', resp.lint);
  // If this was a create, the server returned the new record — keep the
  // modal open in edit mode so the operator can immediately dry-run.
  if (!id && resp.script?.id) {
    document.getElementById('script-edit-id').value = resp.script.id;
    document.getElementById('script-edit-title').textContent = `Edit script — ${resp.script.name||''}`;
  }
  loadScripts();
  if (!reopenAfter && id) closeModal('script-edit-modal');
}

async function dryRunScript(id) {
  const data = await api('POST', '/scripts/' + encodeURIComponent(id) + '/dry-run');
  if (!data || data.error) { toast(data?.error || 'Dry run failed', 'error'); return; }
  const l = data.lint || {};
  let summary;
  if (l.syntax_error && l.syntax_error !== '__skipped__') {
    summary = '✗ Syntax error: ' + l.syntax_error.slice(0, 240);
  } else {
    summary = '✓ Syntax OK';
  }
  if (l.dangerous && l.dangerous.length) {
    summary += ` — ${l.dangerous.length} dangerous pattern${l.dangerous.length>1?'s':''}: ${l.dangerous.join(', ')}`;
  }
  toast(summary, l.syntax_error && l.syntax_error !== '__skipped__' ? 'error'
                : (l.dangerous && l.dangerous.length ? 'info' : 'success'));
  loadScripts();
}

async function deleteScript(id, name) {
  if (!confirm(`Delete script ${name || id}?`)) return;
  const data = await api('DELETE', '/scripts/' + encodeURIComponent(id));
  if (data?.ok) { toast('Script deleted', 'info'); loadScripts(); }
  else toast(data?.error || 'Failed', 'error');
}

// ── Run-script modal: single device OR batch (current selection) ──────────
async function openScriptRunForDevice(deviceId, deviceName) {
  document.getElementById('script-run-mode').value = 'single';
  document.getElementById('script-run-device-id').value = deviceId;
  document.getElementById('script-run-target').textContent = `Queue a saved script on ${deviceName}.`;
  document.getElementById('script-run-confirm-wrap').style.display = 'none';
  document.getElementById('script-run-confirm-dangerous').checked = false;
  document.getElementById('script-run-lint').style.display = 'none';
  await _populateScriptRunPicker();
  openModal('script-run-modal');
}
async function openScriptRunForBatch() {
  if (!selectedDevices.size) { toast('Select devices first', 'error'); return; }
  document.getElementById('script-run-mode').value = 'batch';
  document.getElementById('script-run-device-id').value = '';
  document.getElementById('script-run-target').textContent =
    `Queue a saved script on ${selectedDevices.size} selected device${selectedDevices.size===1?'':'s'}.`;
  document.getElementById('script-run-confirm-wrap').style.display = 'none';
  document.getElementById('script-run-confirm-dangerous').checked = false;
  document.getElementById('script-run-lint').style.display = 'none';
  await _populateScriptRunPicker();
  openModal('script-run-modal');
}
async function _populateScriptRunPicker() {
  const sel = document.getElementById('script-run-pick');
  sel.innerHTML = '<option value="">— Choose a saved script —</option>';
  const data = await api('GET', '/scripts');
  (Array.isArray(data) ? data : []).forEach(s => {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.name + (s.dangerous ? '  DANGER' : '');
    opt.dataset.dangerous = s.dangerous ? '1' : '';
    sel.appendChild(opt);
  });
}
function onScriptRunPick() {
  const sel = document.getElementById('script-run-pick');
  const opt = sel.options[sel.selectedIndex];
  const dangerous = opt?.dataset?.dangerous === '1';
  document.getElementById('script-run-confirm-wrap').style.display = dangerous ? 'block' : 'none';
  document.getElementById('script-run-confirm-dangerous').checked = false;
  document.getElementById('script-run-lint').style.display = 'none';
}
async function confirmScriptRun() {
  const sid = document.getElementById('script-run-pick').value;
  if (!sid) { toast('Pick a script first', 'error'); return; }
  const mode = document.getElementById('script-run-mode').value;
  const confirmDangerous = document.getElementById('script-run-confirm-dangerous').checked;
  let payload = {script_id: sid, confirm_dangerous: confirmDangerous};
  if (mode === 'single') {
    payload.device_ids = [document.getElementById('script-run-device-id').value];
  } else {
    payload.device_ids = [...selectedDevices];
  }
  const resp = await api('POST', '/exec/batch', payload);
  if (!resp || resp.error) {
    // Surface syntax / dangerous-pattern errors so the operator knows
    // what to fix rather than just "request failed".
    if (resp?.dangerous?.length) {
      _renderLintIntoBox('script-run-lint', {dangerous: resp.dangerous, syntax_error: null});
      toast('Script flagged as dangerous — tick the box to confirm', 'error');
      document.getElementById('script-run-confirm-wrap').style.display = 'block';
      return;
    }
    if (resp?.syntax_error) {
      _renderLintIntoBox('script-run-lint', {syntax_error: resp.syntax_error, dangerous: []});
      toast('Fix the syntax error first', 'error');
      return;
    }
    toast(resp?.error || 'Failed to queue', 'error');
    return;
  }
  closeModal('script-run-modal');
  if (mode === 'batch') clearSelection();
  toast(`Queued on ${resp.queued}/${resp.total} device${resp.total===1?'':'s'}`, 'success');
  if (resp.job_id) openBatchJobModal(resp.job_id);
}

// ── Batch job status modal — polls /api/exec/batch/<id> ───────────────────
let _batchJobTimer = null;
function openBatchJobModal(jobId) {
  document.getElementById('batch-job-id').value = jobId;
  document.getElementById('batch-job-body').innerHTML =
    '<div class="empty-state">Loading…</div>';
  document.getElementById('batch-job-title').textContent = 'Batch script run';
  document.getElementById('batch-job-sub').textContent = 'Polling for results…';
  openModal('batch-job-modal');
  refreshBatchJob();
  clearInterval(_batchJobTimer);
  _batchJobTimer = setInterval(refreshBatchJob, 10000);
}
function closeBatchJobModal() {
  clearInterval(_batchJobTimer);
  _batchJobTimer = null;
  closeModal('batch-job-modal');
}
async function refreshBatchJob() {
  const jobId = document.getElementById('batch-job-id').value;
  if (!jobId) return;
  const data = await api('GET', '/exec/batch/' + encodeURIComponent(jobId));
  if (!data || data.error) {
    document.getElementById('batch-job-body').innerHTML =
      `<div class="c-red-p20">${escHtml(data?.error||'Failed to load job')}</div>`;
    clearInterval(_batchJobTimer);
    return;
  }
  document.getElementById('batch-job-title').textContent =
    `Batch run: ${data.script_name || data.script_id}`;
  const entries = Object.entries(data.per_device || {});
  const done = entries.filter(([,e]) => e.status === 'done').length;
  const queued = entries.filter(([,e]) => e.queued).length;
  document.getElementById('batch-job-sub').textContent =
    `${done}/${queued} returned output — refreshes every 10s (close to stop)`;
  let body = '';
  for (const [devId, e] of entries) {
    const name = escHtml(e.name || devId);
    let pill = '<span class="patch-badge ok fs-11">pending</span>';
    let outBox = '';
    if (!e.queued) {
      pill = `<span class="patch-badge warn fs-11">${escHtml(e.reason||'skipped')}</span>`;
    } else if (e.status === 'done') {
      const ok = e.rc === 0;
      pill = `<span class="patch-badge ${ok ? 'ok' : 'warn'} fs-11">rc=${escHtml(String(e.rc))}</span>`;
      const finished = e.finished_at ? new Date(e.finished_at*1000).toLocaleTimeString() : '';
      outBox = `<pre class="isl-503">${escHtml(e.output||'(no output)')}</pre><div class="isl-504">finished ${escHtml(finished)}</div>`;
    }
    body += `<div class="isl-505">
      <div class="isl-506"><div class="fw-600">${name}</div>${pill}</div>
      ${outBox}
    </div>`;
  }
  if (!entries.length) body = '<div class="isl-507">No targets in this batch.</div>';
  document.getElementById('batch-job-body').innerHTML = body;
  // Stop polling once everyone has either returned output or was skipped.
  if (queued === 0 || done >= queued) {
    clearInterval(_batchJobTimer);
    _batchJobTimer = null;
    document.getElementById('batch-job-sub').textContent =
      `${done}/${queued} returned output — polling stopped (Refresh to re-check)`;
  }
}

// ── Docker-compose dropdown on device cards ───────────────────────────────
async function openComposeModal(deviceId, deviceName) {
  document.getElementById('compose-device-id').value = deviceId;
  document.getElementById('compose-title').textContent = `docker compose — ${deviceName}`;
  document.getElementById('compose-result').textContent =
    'Queue an action — output arrives on the next heartbeat (~60s).';
  const sel = document.getElementById('compose-project-pick');
  sel.innerHTML = '<option value="">Loading…</option>';
  openModal('compose-modal');
  const data = await api('GET', '/devices/' + encodeURIComponent(deviceId) + '/compose');
  if (!data || data.error) {
    sel.innerHTML = `<option value="">${escHtml(data?.error||'Failed to load')}</option>`;
    return;
  }
  const projects = data.projects || [];
  if (!projects.length) {
    sel.innerHTML = `<option value="">${data.docker_seen ? 'No projects found under /opt /home /docker /srv' : 'Device has not reported yet'}</option>`;
    return;
  }
  sel.innerHTML = projects.map(p =>
    `<option value="${escHtml(p.dir)}">${escHtml(p.name)} — ${escHtml(p.dir)}</option>`
  ).join('');
}
async function runCompose(action) {
  const deviceId = document.getElementById('compose-device-id').value;
  const dir = document.getElementById('compose-project-pick').value;
  if (!dir) { toast('Pick a project first', 'error'); return; }
  // Down is the most disruptive — confirm explicitly.
  if (action === 'down' && !confirm(`Run "docker compose down" in ${dir}?\nThis stops and removes the project's containers.`)) return;
  const resp = await api('POST', '/devices/' + encodeURIComponent(deviceId) + '/compose/action',
                         {action, dir});
  if (!resp || resp.error) { toast(resp?.error || 'Failed', 'error'); return; }
  toast(`compose ${action} queued — output arrives on next heartbeat`, 'success');
  document.getElementById('compose-result').textContent =
    `Queued: ${resp.queued}\nWaiting for the agent's next heartbeat (~60s)…\nResults appear on the device's System info → Command output panel.`;
}


document.addEventListener('DOMContentLoaded', () => {
  loadPublicInfo();
  // The login fields are now inside #login-form so Enter triggers the
  // form's submit naturally — no per-field keydown listeners required.
  // Keep the username → password focus-on-Enter so tab-less keyboards
  // (and operators who hit Enter after username) still flow through.
  document.getElementById('login-user').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('login-pass').focus();
    }
  });
  // v1.11.5: best-effort flush on tab close. Browsers limit what fetch()
  // can do in 'beforeunload', but a fire-and-forget request often makes
  // it out before the page is gone. The 600ms debounce already covers
  // every other case; this is just for "user closed the tab mid-typing".
  window.addEventListener('beforeunload', () => {
    if (_uiPrefsFlushTimer && _uiPrefsLoaded) {
      try { flushUiPrefs(); } catch(e) {}
    }
  });
  checkAuth();
});

// ─── v2.1.3: AI assistant ───────────────────────────────────────────────────
//
// Two surfaces:
//   1. Settings → AI assistant tab (loadAISettings / saveAISettings /
//      testAIConnection / onAIProviderChange)
//   2. Inline AIbuttons on command output, journal, scripts, CVE rows,
//      device cards, and notifications — all routed through openAIModal().
//
// openAIModal() is the single reusable component for every AIclick. It:
//   - shows a modal with a context summary at the top (what's being sent)
//   - posts to /api/ai/chat
//   - renders the response (one shot — no streaming in v1)
//   - shows token use + elapsed time so the operator can see what it cost
//   - supports Copy + Ask-followup, plus a Cancel that closes the modal

let _aiCfgCache = null;   // cached config from last loadAISettings()

async function loadAISettings() {
  const cfg = await api('GET', '/ai/config');
  if (!cfg) return;
  _aiCfgCache = cfg;
  document.getElementById('ai-enabled').value  = cfg.enabled ? '1' : '0';
  document.getElementById('ai-provider').value = cfg.provider || 'anthropic';
  document.getElementById('ai-model').value    = cfg.model    || '';
  document.getElementById('ai-base-url').value = cfg.base_url || '';
  // Show the masked key as placeholder; never put it in the value or
  // it gets re-submitted on every save.
  const keyInput = document.getElementById('ai-api-key');
  keyInput.value = '';
  keyInput.placeholder = cfg.api_key ? cfg.api_key : '(none — type to set)';
  const p = cfg.privacy || {};
  document.getElementById('ai-priv-hostnames').checked  = !!p.send_hostnames;
  document.getElementById('ai-priv-ips').checked        = !!p.send_ips;
  document.getElementById('ai-priv-journal').checked    = !!p.send_journal;
  document.getElementById('ai-priv-cmd-output').checked = p.send_cmd_output !== false;
  const lim = cfg.limits || {};
  document.getElementById('ai-max-tokens').value   = lim.max_tokens_per_response   ?? 4000;
  document.getElementById('ai-max-requests').value = lim.max_requests_per_user_day ?? 100;
  // v2.1.7: context toggles
  const ctx = cfg.context || {};
  document.getElementById('ai-ctx-project').checked = ctx.include_project_context !== false;
  document.getElementById('ai-ctx-fleet').checked   = ctx.include_fleet_context !== false;
  document.getElementById('ai-ctx-rag').checked     = ctx.include_rag !== false;
  // v3.4.0: RAG config
  const rag = cfg.rag || {};
  const rs  = rag.sources || {};
  document.getElementById('ai-rag-enabled').checked     = rag.enabled !== false;
  document.getElementById('ai-rag-src-docs').checked    = rs.docs !== false;
  document.getElementById('ai-rag-src-live').checked    = rs.live_state !== false;
  document.getElementById('ai-rag-src-cmdb').checked    = rs.cmdb !== false;
  document.getElementById('ai-rag-src-history').checked = !!rs.history;
  document.getElementById('ai-rag-embeddings').checked  = !!rag.embeddings_enabled;
  document.getElementById('ai-rag-embed-model').value   = rag.embedding_model || '';
  document.getElementById('ai-rag-max-chunks').value    = rag.max_chunks ?? 6;
  document.getElementById('ai-rag-history-days').value  = (rag.history_limits || {}).max_age_days ?? 14;
  onAIProviderChange();   // refresh per-provider hint
  loadRAGStatus();        // index freshness + counts
}

function onAIProviderChange() {
  const provider = document.getElementById('ai-provider').value;
  const defaults = (_aiCfgCache && _aiCfgCache._defaults) || {};
  const d = defaults[provider] || {};
  document.getElementById('ai-base-url').placeholder = d.base_url || '';
  document.getElementById('ai-base-url-hint').textContent =
    d.base_url ? `default: ${d.base_url}` : '';
  document.getElementById('ai-model').placeholder = d.model || '';
  document.getElementById('ai-model-hint').textContent =
    d.model ? `default: ${d.model}` : '';
  // Local providers don't need an API key; dim the field as a UX hint
  const local = (provider === 'ollama' || provider === 'localai');
  document.getElementById('ai-api-key').disabled = local;
  if (local) document.getElementById('ai-api-key').placeholder =
    '(not required for local providers)';
  // v3.4.0: embeddings availability + egress guidance per provider.
  const embChk  = document.getElementById('ai-rag-embeddings');
  const embHint = document.getElementById('ai-rag-embeddings-hint');
  if (embChk && embHint) {
    const supports = (provider === 'openai' || provider === 'ollama' || provider === 'localai');
    embChk.disabled = !supports;
    if (!supports) {
      embChk.checked = false;
      embHint.textContent = `${provider} has no embeddings endpoint — lexical (keyword) search is used. Run a local Ollama embedding model for semantic search.`;
      embHint.style.color = 'var(--muted)';
    } else if (local) {
      embHint.textContent = 'Local provider — embeddings stay on-prem, no data egress. Recommended.';
      embHint.style.color = 'var(--green)';
    } else {
      embHint.textContent = `Embeddings send indexed content to ${provider} (data egress). Leave off if that's a concern.`;
      embHint.style.color = 'var(--amber, var(--muted))';
    }
  }
}

// ── v3.4.0: RAG index controls ─────────────────────────────────────────────

function _ragFmtAge(builtAt) {
  if (!builtAt) return 'never built';
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - builtAt);
  if (secs < 60)    return 'just now';
  if (secs < 3600)  return `${Math.floor(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h ago`;
  return `${Math.floor(secs / 86400)} d ago`;
}

async function loadRAGStatus() {
  const el = document.getElementById('ai-rag-status');
  if (!el) return;
  const s = await api('GET', '/ai/rag/status');
  if (!s || s.error) { el.textContent = s?.error ? `(${s.error})` : ''; return; }
  const bits = [`${s.docs || 0} chunks indexed`, `built ${_ragFmtAge(s.built_at)}`];
  if (s.embedded)  bits.push(`${s.embedded} embedded (${s.emb_model || 'semantic'})`);
  if (s.stale)     bits.push('— sources changed since last build');
  el.textContent = bits.join(' · ');
  el.style.color = s.stale ? 'var(--amber, var(--muted))' : 'var(--muted)';
}

async function aiRagReindex() {
  const el = document.getElementById('ai-rag-status');
  if (el) { el.textContent = 'Rebuilding index…'; el.style.color = 'var(--muted)'; }
  // Persist any unsaved config first — reindex reads server-side config.
  const saved = await saveAISettings();
  if (!saved) { if (el) { el.textContent = '(save failed)'; el.style.color = 'var(--red)'; } return; }
  const r = await api('POST', '/ai/rag/reindex', {});
  if (r && r.ok) {
    let msg = `Rebuilt: ${r.docs} chunks in ${r.elapsed_ms} ms`;
    if (r.embedded) msg += ` · ${r.embedded} embedded`;
    if (r.embed_error) msg += ` · embeddings: ${r.embed_error}`;
    toast(msg, r.embed_error ? 'error' : 'success');
    loadRAGStatus();
  } else {
    toast('Reindex: ' + (r?.error || 'unknown error'), 'error');
    if (el) { el.textContent = '✗ ' + (r?.error || 'failed'); el.style.color = 'var(--red)'; }
  }
}

// Last search results, kept module-scoped so the sort re-render can re-use
// them without re-querying the server.
let _ragSearchRows = [];

async function aiRagTestSearch() {
  const query = document.getElementById('ai-rag-query').value.trim();
  const out = document.getElementById('ai-rag-search-result');
  if (!query) { out.innerHTML = ''; return; }
  out.innerHTML = '<div class="meta-sm">Searching…</div>';
  const r = await api('POST', '/ai/rag/search', { query });
  if (!r || r.error) { out.innerHTML = `<div class="meta-sm err-text">${escHtml(r?.error || 'search failed')}</div>`; return; }
  _ragSearchRows = r.results || [];
  if (!_ragSearchRows.length) {
    out.innerHTML = '<div class="meta-sm">No matching chunks. Try different terms, or rebuild the index if it looks stale.</div>';
    return;
  }
  _ragRenderSearch(r.semantic);
}

function _ragRenderSearch(semantic) {
  const out = document.getElementById('ai-rag-search-result');
  if (!out) return;
  // Apply the stored sort to the rows before building the table; the
  // thead is wired (with ↕ indicators) right after innerHTML below, since
  // this renderer rebuilds the whole table — header included — each call.
  const sorted = tableCtl.sortRows('ai-rag-results', _ragSearchRows, r => ({
    rank:   _ragSearchRows.indexOf(r),
    source: r.source || '',
    device: r.device || '',
    id:     r.id || '',
  }));
  const rows = sorted.map(r => `
    <tr>
      <td><code>${escHtml(r.id)}</code></td>
      <td>${escHtml(r.source || '')}</td>
      <td>${escHtml(r.device || '—')}</td>
      <td class="meta-sm">${escHtml((r.excerpt || '').slice(0, 240))}${(r.excerpt || '').length > 240 ? '…' : ''}</td>
    </tr>`).join('');
  out.innerHTML = `
    <div class="meta-sm isl-778">${_ragSearchRows.length} result(s) · ${semantic ? 'lexical + semantic (embeddings)' : 'lexical (keyword)'} retrieval</div>
    <table class="fs-13">
      <thead id="ai-rag-results-thead"><tr>
        <th data-col="id">Source id</th>
        <th data-col="source">Kind</th>
        <th data-col="device">Device</th>
        <th>Excerpt</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  tableCtl.wireSortOnly('ai-rag-results-thead', 'ai-rag-results', () => _ragRenderSearch(semantic));
}

async function saveAISettings() {
  const payload = {
    enabled:  document.getElementById('ai-enabled').value === '1',
    provider: document.getElementById('ai-provider').value,
    model:    document.getElementById('ai-model').value.trim(),
    base_url: document.getElementById('ai-base-url').value.trim(),
    privacy: {
      send_hostnames:  document.getElementById('ai-priv-hostnames').checked,
      send_ips:        document.getElementById('ai-priv-ips').checked,
      send_journal:    document.getElementById('ai-priv-journal').checked,
      send_cmd_output: document.getElementById('ai-priv-cmd-output').checked,
    },
    limits: {
      max_tokens_per_response:   parseInt(document.getElementById('ai-max-tokens').value, 10)   || 4000,
      max_requests_per_user_day: parseInt(document.getElementById('ai-max-requests').value, 10) || 100,
    },
    context: {
      include_project_context: document.getElementById('ai-ctx-project').checked,
      include_fleet_context:   document.getElementById('ai-ctx-fleet').checked,
      include_rag:             document.getElementById('ai-ctx-rag').checked,
    },
    rag: {
      enabled:            document.getElementById('ai-rag-enabled').checked,
      embeddings_enabled: document.getElementById('ai-rag-embeddings').checked,
      embedding_model:    document.getElementById('ai-rag-embed-model').value.trim(),
      max_chunks:         parseInt(document.getElementById('ai-rag-max-chunks').value, 10) || 6,
      sources: {
        docs:       document.getElementById('ai-rag-src-docs').checked,
        live_state: document.getElementById('ai-rag-src-live').checked,
        cmdb:       document.getElementById('ai-rag-src-cmdb').checked,
        history:    document.getElementById('ai-rag-src-history').checked,
      },
      history_limits: {
        max_age_days: parseInt(document.getElementById('ai-rag-history-days').value, 10) || 14,
      },
    },
  };
  // Only submit api_key if the user typed something — keeps the existing
  // key when the field is left blank. '__clear__' wipes the stored key.
  const k = document.getElementById('ai-api-key').value;
  if (k) payload.api_key = k;
  const resp = await api('POST', '/ai/config', payload);
  if (resp && !resp.error) {
    document.getElementById('ai-api-key').value = '';
    return true;
  }
  if (resp?.error) toast('AI: ' + resp.error, 'error');
  return false;
}

async function testAIConnection() {
  const out = document.getElementById('ai-test-result');
  out.textContent = '…';
  out.style.color = 'var(--muted)';
  // Save first if there are unsaved changes — the test endpoint reads
  // from server-side config, not whatever's in the form.
  const saved = await saveAISettings();
  if (!saved) { out.textContent = '(save failed)'; out.style.color = 'var(--red)'; return; }
  const resp = await api('POST', '/ai/test', {});
  if (resp && resp.ok) {
    out.textContent = `✓ ${resp.model || ''} responded (${resp.tokens_in}+${resp.tokens_out} tokens)`;
    out.style.color = 'var(--green)';
  } else {
    out.textContent = '✗ ' + (resp?.error || 'unknown error');
    out.style.color = 'var(--red)';
  }
}

// ─── Reusable AImodal ─────────────────────────────────────────────────────
//
// Every AIbutton on the dashboard funnels through this. Pass:
//   title    — visible header
//   system   — system prompt key (one of ai_provider.SYSTEM_PROMPTS keys)
//              OR a literal system prompt string
//   userMsg  — the user-role message content (already formatted, e.g.
//              "command: ...\noutput: ...\n")
//   context  — short label for the audit log (e.g. 'device:abc123')
//   onResult — optional callback(text) when the response arrives. The
//              Scripts page uses this to drop the result into the editor.

let _aiModalEl = null;

function _ensureAIModal() {
  if (_aiModalEl) return _aiModalEl;
  const wrap = document.createElement('div');
  wrap.className = 'modal-overlay';
  wrap.id = 'ai-modal';
  wrap.innerHTML = `
    <div class="modal isl-508">
      <div class="modal-header row-between">
        <div id="ai-modal-title" class="fw-600">AI</div>
        <button class="btn-icon isl-44" data-action="closeAIModal" >✕</button>
      </div>
      <div id="ai-modal-meta" class="isl-509">—</div>
      <div id="ai-modal-body" class="isl-510">
        <div class="c-muted">Thinking…</div>
      </div>
      <div class="isl-511">
        <button class="btn-icon" id="ai-modal-copy" data-action="aiModalCopy" disabled>Copy response</button>
        <button class="btn-icon d-none" id="ai-modal-action"></button>
        <div class="flex-1"></div>
        <button class="btn-icon" data-action="closeAIModal" >Close</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  _aiModalEl = wrap;
  return wrap;
}

function closeAIModal() {
  if (_aiModalEl) _aiModalEl.classList.remove('active');
}

function aiModalCopy() {
  const body = document.getElementById('ai-modal-body');
  navigator.clipboard.writeText(body.dataset.rawText || body.textContent || '');
  toast('Copied to clipboard', 'success');
}

async function openAIModal({title, system, userMsg, context, onResult, actionLabel, maxTokens}) {
  _ensureAIModal();
  _aiModalEl.classList.add('active');
  document.getElementById('ai-modal-title').textContent = title || 'AI';
  document.getElementById('ai-modal-meta').textContent  =
    `context: ${context || 'n/a'} — be aware the request content is sent to the configured AI provider`;
  const body = document.getElementById('ai-modal-body');
  body.innerHTML = `<div class="isl-512">${aiThinkingHtml()} <span>Thinking… <span id="ai-modal-elapsed" class="fs-11"></span></span></div>`;
  body.dataset.rawText = '';
  document.getElementById('ai-modal-copy').disabled = true;
  const actionBtn = document.getElementById('ai-modal-action');
  actionBtn.style.display = 'none';

  // Live "Xs elapsed" ticker so it doesn't look frozen during long
  // local-model thinks (smallthinker / qwq / deepseek-r1 etc.)
  const t0 = Date.now();
  const tickEl = document.getElementById('ai-modal-elapsed');
  const tick = setInterval(() => {
    const s = Math.floor((Date.now() - t0) / 1000);
    if (tickEl) tickEl.textContent = `(${s}s elapsed)`;
  }, 1000);

  const reqBody = {
    messages: [{role: 'user', content: userMsg}],
    system: system,
    context: context || '',
  };
  if (maxTokens) reqBody.max_tokens = maxTokens;

  const resp = await aiApi('POST', '/ai/chat', reqBody);
  clearInterval(tick);

  if (!resp.ok) {
    // aiApi() gives us a structured error even when the server returned
    // HTML or a timeout — show it intelligibly. Most common: nginx 504
    // because fastcgi_read_timeout is shorter than the model's actual
    // think time.
    body.innerHTML = `<div class="isl-513">${escHtml(resp.error)}</div>`;
    return;
  }
  // v2.1.5: render markdown so **bold** and # headers and `code`
  // don't show as literal punctuation. dataset.rawText keeps the
  // original for the Copy button.
  body.innerHTML = `<div class="ai-content">${renderMarkdown(resp.text || '(empty response)')}</div>`;
  body.dataset.rawText = resp.text || '';
  document.getElementById('ai-modal-copy').disabled = false;
  document.getElementById('ai-modal-meta').textContent =
    `${resp.model || '?'} · ${resp.tokens_in}+${resp.tokens_out} tokens · ${resp.elapsed_ms}ms` +
    (resp.daily_cap ? ` · ${resp.used_today}/${resp.daily_cap} today` : '');

  if (onResult && actionLabel) {
    actionBtn.style.display = 'block';
    actionBtn.textContent = actionLabel;
    actionBtn.onclick = () => { onResult(resp.text || ''); closeAIModal(); };
  }
}

// ─── Inline AItriggers ────────────────────────────────────────────────────
//
// Per-button max_tokens is tuned to the typical response length. Tighter
// budgets cut latency on slow local thinking models (smallthinker /
// qwq / deepseek-r1) — the server still respects the configured global
// cap, this just sets a lower per-call ceiling. Without this, a slow
// local model was sitting waiting for 4000 tokens worth of output and
// tripping nginx's fastcgi_read_timeout.

function aiExplainOutput(deviceName, command, output) {
  if (!output || !output.trim()) { toast('Nothing to explain', 'info'); return; }
  const userMsg = `Device: ${deviceName}\nCommand: ${command}\n\nOutput:\n${output}`;
  openAIModal({
    title:    'Explain command output',
    system:   'explain_output',
    userMsg:  userMsg,
    context:  `device:${deviceName}`,
    maxTokens: 1500,
  });
}

function aiFindProblemInJournal(deviceName, journalLines) {
  if (!journalLines || !journalLines.length) { toast('No journal lines', 'info'); return; }
  const lines = Array.isArray(journalLines) ? journalLines : String(journalLines).split('\n');
  const interestingIdx = new Set();
  const errorRe = /\b(error|err|warning|warn|critical|crit|fatal|fail|panic|denied|refused)\b/i;
  lines.forEach((line, i) => {
    if (errorRe.test(line)) {
      for (let j = Math.max(0, i - 2); j <= Math.min(lines.length - 1, i + 2); j++) {
        interestingIdx.add(j);
      }
    }
  });
  const sliced = Array.from(interestingIdx).sort((a, b) => a - b).map(i => lines[i]);
  const userText = sliced.length ? sliced.join('\n') : lines.slice(-50).join('\n');
  openAIModal({
    title:    'Find the problem',
    system:   'find_problem',
    userMsg:  `Device: ${deviceName}\n\nJournal slice:\n${userText}`,
    context:  `device:${deviceName}`,
    maxTokens: 1500,
  });
}

function aiExplainAlert(eventType, deviceName, message, samplePayload) {
  let payload = '';
  if (samplePayload && typeof samplePayload === 'object') {
    try { payload = JSON.stringify(samplePayload, null, 2).slice(0, 4000); } catch(e){}
  }
  openAIModal({
    title:    'Explain alert',
    system:   'explain_alert',
    userMsg:  `Event: ${eventType}\nDevice: ${deviceName}\nMessage: ${message}\n\nPayload:\n${payload}`,
    context:  `alert:${eventType}`,
    maxTokens: 800,           // alerts get a one-paragraph answer
  });
}

function aiTriageCve(cveId, packageName, version, deviceName, description) {
  openAIModal({
    title:    `Triage ${cveId}`,
    system:   'triage_cve',
    userMsg:  `CVE: ${cveId}\nDevice: ${deviceName}\nAffected package: ${packageName} ${version}\n\nDescription:\n${description || '(no description available — assess based on the CVE ID alone)'}`,
    context:  `cve:${cveId}`,
    maxTokens: 1000,
  });
}

function aiInvestigateDevice(devId, deviceName) {
  // v2.1.5 fix: there is NO top-level GET /api/devices/<id> route — the
  // detail data is split across /sysinfo, /output, etc. The old call
  // silently returned null, leading to "No data provided" from the
  // model. Now we fetch the right endpoints, in parallel, and bail
  // visibly if there's genuinely nothing to send.
  (async () => {
    const idEnc = encodeURIComponent(devId);
    const [sysData, outData, allDevs] = await Promise.all([
      api('GET', `/devices/${idEnc}/sysinfo`).catch(() => null),
      api('GET', `/devices/${idEnc}/output`).catch(() => null),
      api('GET', '/devices').catch(() => null),
    ]);

    const si = sysData?.sysinfo || {};
    const journal = sysData?.journal || [];
    const outputs = outData?.outputs || [];
    const dev = (allDevs?.devices || allDevs || []).find?.(d => d.id === devId) || {};

    // Top-level device facts (from the devices list, since they aren't
    // in /sysinfo). Skip lines we couldn't determine — emptiness is
    // an honest signal to the model, dont fake it.
    const facts = [];
    if (dev.last_seen) facts.push(`Last seen: ${new Date(dev.last_seen * 1000).toISOString()}`);
    if (dev.os)        facts.push(`OS: ${dev.os}`);
    if (dev.version)   facts.push(`Agent version: ${dev.version}`);
    if (dev.ip)        facts.push(`IP: ${dev.ip}`);
    if (dev.group)     facts.push(`Group: ${dev.group}`);
    if (typeof dev.online === 'boolean') facts.push(`Status: ${dev.online ? 'online' : 'offline'}`);

    // Recent commands: most useful for diagnostics, especially failures
    let recentCmds = '';
    if (outputs.length) {
      recentCmds = outputs.slice(-10).map(o =>
        `[rc=${o.rc}] ${new Date(o.ts*1000).toISOString()} — ${o.cmd}\n` +
        `${(o.output || '').slice(0, 400)}`
      ).join('\n---\n');
    }

    // Honest empty-data check: if we have nothing useful, say so and
    // skip the AI call. Better than asking the model to invent.
    const hasFacts   = facts.length > 0;
    const hasSysInfo = Object.keys(si).length > 0;
    const hasJournal = journal.length > 0;
    const hasCmds    = recentCmds.length > 0;
    if (!hasFacts && !hasSysInfo && !hasJournal && !hasCmds) {
      toast('No data available for this device yet — has the agent checked in?', 'info');
      return;
    }

    const sections = [`Device: ${deviceName}`];
    if (hasFacts)   sections.push(facts.join('\n'));
    if (hasSysInfo) sections.push('Sysinfo:\n' + JSON.stringify(si, null, 2).slice(0, 3000));
    if (hasJournal) sections.push(`Recent journal (last ${journal.slice(-30).length} lines):\n` + journal.slice(-30).join('\n').slice(0, 4000));
    if (hasCmds)    sections.push('Recent commands:\n' + recentCmds.slice(0, 4000));

    openAIModal({
      title:    `Investigate ${deviceName}`,
      system:   'investigate_device',
      userMsg:  sections.join('\n\n'),
      context:  `device:${devId}`,
      maxTokens: 2000,
    });
  })();
}

function aiExplainScript(scriptBody) {
  openAIModal({
    title:    'Explain script',
    system:   'explain_script',
    userMsg:  scriptBody,
    context:  'script',
    maxTokens: 1500,
  });
}

function aiAuditScript(scriptBody) {
  openAIModal({
    title:    'Audit script for risks',
    system:   'audit_script',
    userMsg:  scriptBody,
    context:  'script',
    maxTokens: 2000,
  });
}

function aiGenerateScript(prompt, targetElementId) {
  if (!prompt || !prompt.trim()) { toast('Describe what the script should do', 'info'); return; }
  openAIModal({
    title:    'Generate script',
    system:   'generate_script',
    userMsg:  prompt,
    context:  'script-generate',
    maxTokens: 4000,          // scripts can legitimately be long
    actionLabel: 'Insert into editor',
    onResult: (text) => {
      const el = document.getElementById(targetElementId);
      if (el) {
        let body = text.trim();
        body = body.replace(/^```(?:bash|sh)?\s*\n/, '').replace(/\n```\s*$/, '');
        el.value = body;
        el.dispatchEvent(new Event('input'));
        toast('Script inserted — review before saving', 'success');
      }
    },
  });
}

// ─── Script editor AIbuttons ──────────────────────────────────────────────

function scriptEditorAIGenerate() {
  const prompt = window.prompt('Describe what the script should do:', '');
  if (!prompt) return;
  aiGenerateScript(prompt, 'script-edit-body');
}

function scriptEditorAIExplain() {
  const body = document.getElementById('script-edit-body').value;
  if (!body.trim()) { toast('Nothing to explain — paste a script first', 'info'); return; }
  aiExplainScript(body);
}

function scriptEditorAIAudit() {
  const body = document.getElementById('script-edit-body').value;
  if (!body.trim()) { toast('Nothing to audit — paste a script first', 'info'); return; }
  aiAuditScript(body);
}

// ─── v2.1.5: tolerant fetch + AI page ──────────────────────────────────────
//
// `aiApi()` is `api()`'s tolerant cousin specifically for AI endpoints.
// AI calls are slow (15-180s on local thinking models), which routinely
// trips nginx's default fastcgi_read_timeout=60s and returns a 504
// Gateway Timeout HTML page. The default api() helper does r.json()
// which throws "SyntaxError: JSON.parse..." — the original bug the
// user reported. aiApi() reads raw text first and synthesises a
// structured error so the modal can show something useful.

// renderMarkdown — minimal, secure markdown→HTML for AI responses.
// Models love their **bold** and `code` and # headers, and showing them
// raw is jarring. The strategy is: escape HTML first (so any tags in
// the source become literal text), THEN apply the markdown transforms
// (which generate trusted HTML). No DOM injection vector — every user-
// supplied byte is escaped before any transform touches it.
//
// Supported: code fences, inline code, bold, italic, h1/h2/h3, bullet
// and numbered lists, blockquotes, paragraph breaks. Anything else
// (links, tables, images) falls through as escaped text on purpose —
// keeps the implementation tiny and avoids the bigger attack surface
// of a real Markdown lib.

function renderMarkdown(text) {
  if (!text) return '';
  // Step 1: HTML-escape everything. After this, every transform
  // operates on safe ground.
  let html = escHtml(String(text));

  // Step 2: extract code fences first (they should NOT receive any
  // further transforms). We replace each fence with a unique
  // placeholder, do the rest, then put them back. Stops `**bold**`
  // inside a code block from being interpreted.
  const codeBlocks = [];
  html = html.replace(/```(\w+)?\n?([\s\S]*?)```/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(
      `<pre class="isl-514"><code>${code.replace(/^\n|\n$/g, '')}</code></pre>`
    );
    return `\x00CODEBLOCK${idx}\x00`;
  });

  // Inline code — same idea, hold placeholders so `**` inside backticks
  // doesn't turn into a <strong>.
  const inlineCodes = [];
  html = html.replace(/`([^`\n]+)`/g, (_, code) => {
    const idx = inlineCodes.length;
    inlineCodes.push(
      `<code class="isl-515">` +
      `${code}</code>`
    );
    return `\x00INLINE${idx}\x00`;
  });

  // Headers — only at the start of a line. The big-three are enough.
  html = html.replace(/^### +(.+)$/gm,
    '<div class="isl-516">$1</div>');
  html = html.replace(/^## +(.+)$/gm,
    '<div class="isl-517">$1</div>');
  html = html.replace(/^# +(.+)$/gm,
    '<div class="isl-518">$1</div>');

  // Bold (**foo**) and italic (*foo*). Run bold first so we don't
  // eat the inner asterisks of bold inside italic.
  html = html.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/(^|[^*])\*([^*\n]+)\*(?!\*)/g, '$1<em>$2</em>');
  // Same with underscores — some models prefer those.
  html = html.replace(/__([^_\n]+)__/g, '<strong>$1</strong>');
  html = html.replace(/(^|[^_])_([^_\n]+)_(?!_)/g, '$1<em>$2</em>');

  // Lists — collect contiguous `- foo` / `* foo` / `1. foo` runs
  // into <ul> or <ol> blocks. Process line-by-line so we get
  // proper grouping; one big regex would be hairy.
  const lines = html.split('\n');
  const out = [];
  let listType = null;          // 'ul', 'ol', or null
  function closeList() {
    if (listType) { out.push(`</${listType}>`); listType = null; }
  }
  for (const line of lines) {
    const bullet = line.match(/^(?:[-*]) +(.+)$/);
    const numbered = line.match(/^\d+\.\s+(.+)$/);
    if (bullet) {
      if (listType !== 'ul') { closeList(); out.push('<ul class="isl-519">'); listType = 'ul'; }
      out.push(`<li>${bullet[1]}</li>`);
    } else if (numbered) {
      if (listType !== 'ol') { closeList(); out.push('<ol class="isl-519">'); listType = 'ol'; }
      out.push(`<li>${numbered[1]}</li>`);
    } else {
      closeList();
      out.push(line);
    }
  }
  closeList();
  html = out.join('\n');

  // Blockquotes
  html = html.replace(/^&gt; (.+)$/gm,
    '<div class="isl-520">$1</div>');

  // Paragraphs: turn blank-line-separated chunks into <p>, single newlines
  // into <br>. Don't wrap content that's already block-level (lists,
  // headers, code blocks, blockquotes).
  const blocks = html.split(/\n{2,}/).map(b => {
    const trimmed = b.trim();
    if (!trimmed) return '';
    if (/^<(?:div|ul|ol|pre|h[1-6]|blockquote)/i.test(trimmed)) return trimmed;
    return `<p class="isl-521">${trimmed.replace(/\n/g, '<br>')}</p>`;
  });
  html = blocks.join('\n');

  // Step 3: restore code placeholders
  html = html.replace(/\x00CODEBLOCK(\d+)\x00/g, (_, i) => codeBlocks[i]);
  html = html.replace(/\x00INLINE(\d+)\x00/g, (_, i) => inlineCodes[i]);

  return html;
}

async function aiApi(method, path, body) {
  const opts = {method, headers: {'X-Token': getToken()}};
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  let r, text = '';
  try {
    r = await fetch('/api' + path, opts);
  } catch (e) {
    // Network-level failure (DNS, refused, aborted). The browser already
    // distinguishes these from HTTP error responses.
    return {ok: false, error: `Network error: ${String(e)}`};
  }
  if (r.status === 401) { doLogout(); return {ok: false, error: 'Not authenticated'}; }
  try { text = await r.text(); } catch (e) {
    return {ok: false, error: `Failed to read response body: ${String(e)}`};
  }
  // Try to parse the body as JSON. Most failures come back here as an
  // nginx/fcgiwrap HTML error page — we surface the status + first
  // bit of the body so the operator can see what actually happened.
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (e) { /* not JSON */ }
  if (!parsed) {
    const snippet = text.slice(0, 240).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    let hint = '';
    if (r.status === 504 || /timeout|timed.?out/i.test(text)) {
      hint = '\n\nLikely cause: nginx fastcgi_read_timeout is shorter than the model needed to think. ' +
             'Set `fastcgi_read_timeout 300s` in the /api/ai/ location block of your nginx config and reload nginx.';
    } else if (r.status === 502 || r.status === 503) {
      hint = '\n\nLikely cause: the CGI script crashed or the upstream provider is unreachable. ' +
             'Check the server\'s nginx error log and the AI provider\'s liveness.';
    } else if (r.status === 0) {
      hint = '\n\nLikely cause: the connection was dropped before any response was received.';
    }
    return {ok: false, error: `HTTP ${r.status || '?'} — response was not JSON.${hint}\n\nFirst 240 chars: ${snippet || '(empty)'}`};
  }
  // JSON parsed. The server returns {error: "..."} on failure (any
  // 4xx/5xx with valid JSON body); promote that to ok:false.
  if (parsed.error && parsed.ok !== true) {
    return {ok: false, error: parsed.error, _status: r.status, ...parsed};
  }
  // Server response shape already has ok:true on success; pass through.
  return parsed.ok ? parsed : {ok: true, ...parsed};
}

// ─── AI Assistant page ────────────────────────────────────────────────────

let _aiPageConv = [];            // [{role: 'user'|'assistant', content: '...'}]
const _AI_PAGE_STORAGE_KEY = 'rp.ai.conv';
const _AI_PAGE_MAX_TURNS = 40;   // bounded so localStorage doesn't grow forever

function _aiPageLoadConv() {
  try {
    const raw = localStorage.getItem(_AI_PAGE_STORAGE_KEY);
    _aiPageConv = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(_aiPageConv)) _aiPageConv = [];
  } catch (e) { _aiPageConv = []; }
}

function _aiPageSaveConv() {
  // Trim to the last N turns so we don't blow out localStorage on long
  // sessions, and so we don't send the entire history with every request.
  if (_aiPageConv.length > _AI_PAGE_MAX_TURNS) {
    _aiPageConv = _aiPageConv.slice(-_AI_PAGE_MAX_TURNS);
  }
  try { localStorage.setItem(_AI_PAGE_STORAGE_KEY, JSON.stringify(_aiPageConv)); } catch (e) {}
}

function _aiPageRenderConv() {
  const wrap = document.getElementById('ai-page-history');
  if (!wrap) return;
  if (!_aiPageConv.length) {
    wrap.innerHTML = '<div class="isl-117">' +
      'No messages yet — type a prompt below.<br>' +
      '<span class="fs-11">Conversation history is kept in your browser (localStorage) — not on the server. ' +
      'Clearing the conversation clears only your view.</span></div>';
    return;
  }
  wrap.innerHTML = _aiPageConv.map(m => {
    const isUser = m.role === 'user';
    const isPending = m.pending;
    const bg = isUser ? 'rgba(59,126,255,0.08)' : 'var(--surface)';
    const border = isUser ? 'rgba(59,126,255,0.25)' : 'var(--border)';
    const label = isUser ? 'You' : (m.model ? `Assistant · ${escHtml(m.model)}` : 'Assistant');
    const meta = m.meta ? `<div class="isl-522">${escHtml(m.meta)}</div>` : '';
    // v2.1.5: render markdown for assistant turns. User turns stay
    // plain — what the user typed shouldn't be re-interpreted.
    let content;
    if (isPending) {
      content = '<div class="c-muted">Thinking… <span class="ai-page-elapsed" data-start="' + Date.now() + '">(0s elapsed)</span></div>';
    } else if (isUser) {
      content = `<div class="isl-523">${escHtml(m.content || '')}</div>`;
    } else {
      content = `<div class="ai-content">${renderMarkdown(m.content || '')}</div>`;
    }
    return `<div class="mb-12"><div class="isl-524">${label}</div>` +
           `<div class="isl-525" data-bg="${bg}" data-bd="${border}">${content}${meta}</div></div>`;
  }).join('');
  wrap.scrollTop = wrap.scrollHeight;
}

let _aiPageStatsRefreshing = false;

async function aiPageRefreshStats() {
  if (_aiPageStatsRefreshing) return;
  _aiPageStatsRefreshing = true;
  try {
    const stats = await aiApi('GET', '/ai/stats');
    if (!stats.ok) {
      document.getElementById('ai-page-stat-status').innerHTML =
        '<span class="c-red">● Error</span>';
      document.getElementById('ai-page-stat-provider').textContent = '—';
      return;
    }
    document.getElementById('ai-page-stat-provider').textContent = stats.provider || '—';
    document.getElementById('ai-page-stat-baseurl').textContent  = stats.base_url || '';
    document.getElementById('ai-page-stat-version').textContent  = stats.version || (stats.local ? 'unknown' : '(cloud)');
    document.getElementById('ai-page-stat-status').innerHTML = stats.reachable
      ? '<span class="c-green">● Reachable</span>'
      : '<span class="c-amber">● Unreachable</span>';
    const loadedEl = document.getElementById('ai-page-stat-loaded');
    if (Array.isArray(stats.loaded_models) && stats.loaded_models.length) {
      loadedEl.innerHTML = stats.loaded_models.map(m =>
        `<div><strong>${escHtml(m.name)}</strong>` +
        (m.vram_mb ? ` <span class="c-muted">· ${m.vram_mb} MB VRAM</span>` : '') +
        (m.expires_at ? ` <span class="meta-sm-nm">· expires ${escHtml(String(m.expires_at).slice(0,19).replace('T',' '))}</span>` : '') +
        '</div>'
      ).join('');
    } else if (stats.local) {
      loadedEl.innerHTML = '<span class="c-muted">No models currently loaded (will load on first request)</span>';
    } else {
      loadedEl.innerHTML = '<span class="c-muted">(cloud provider — no introspection)</span>';
    }
  } finally {
    _aiPageStatsRefreshing = false;
  }
}

async function _aiPageLoadModels() {
  const sel = document.getElementById('ai-page-model');
  const cur = sel.value;
  const models = await aiApi('GET', '/ai/models');
  if (!models.ok) {
    sel.innerHTML = `<option value="">(configured default)</option><option disabled>error: ${escHtml(models.error.slice(0,60))}</option>`;
    return;
  }
  const list = models.models || [];
  let html = '<option value="">(configured default)</option>';
  for (const m of list) {
    const size = m.size_bytes ? ` — ${(m.size_bytes / (1024*1024*1024)).toFixed(1)} GB` : '';
    const param = m.param_size ? ` (${escHtml(m.param_size)})` : '';
    html += `<option value="${escAttr(m.name)}">${escHtml(m.name)}${size}${param}</option>`;
  }
  sel.innerHTML = html;
  if (cur) sel.value = cur;   // preserve user's pick across reloads
  if (models.note) {
    // best-effort surface — visible only in console; not worth a toast
    console.info('ai/models:', models.note);
  }
}

async function loadAIPage() {
  _aiPageLoadConv();
  _aiPageRenderConv();

  const cfg = await aiApi('GET', '/ai/config');
  // CSP L1 (v3.0.4): the initial-hide for these elements is now a CSS
  // class with `display: none` (auto-generated from the original
  // inline style="display:none"). `element.style.display = ''` removes
  // only the *inline* property — the class rule keeps the element
  // hidden. Reveal must use an explicit display value (same lesson as
  // the v3.0.3 #pwa-install-btn fix).
  if (!cfg.ok && cfg.error && /disabled/i.test(cfg.error)) {
    document.getElementById('ai-page-disabled').style.display = 'block';
    document.getElementById('ai-page-status').style.display = 'none';
    document.getElementById('ai-page-chat-wrap').style.display = 'none';
    document.getElementById('ai-page-tools').style.display = 'none';
    return;
  }
  if (!cfg.ok || !cfg.enabled) {
    document.getElementById('ai-page-disabled').style.display = 'block';
    document.getElementById('ai-page-status').style.display = 'none';
    document.getElementById('ai-page-chat-wrap').style.display = 'none';
    document.getElementById('ai-page-tools').style.display = 'none';
    return;
  }
  document.getElementById('ai-page-disabled').style.display = 'none';
  document.getElementById('ai-page-status').style.display = 'block';
  document.getElementById('ai-page-chat-wrap').style.display = 'block';
  document.getElementById('ai-page-tools').style.display = 'block';

  // Fire these in parallel — they don't depend on each other
  aiPageRefreshStats();
  _aiPageLoadModels();
}

function aiPageInputKey(ev) {
  // Ctrl/⌘+Enter sends; plain Enter inserts a newline (standard chat UX)
  if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
    ev.preventDefault();
    aiPageSend();
  }
}

function aiPageClear() {
  if (_aiPageConv.length && !confirm('Clear the conversation? This wipes the local history; the audit log on the server is untouched.')) {
    return;
  }
  _aiPageConv = [];
  _aiPageSaveConv();
  _aiPageRenderConv();
}

async function aiPageSend() {
  const inp = document.getElementById('ai-page-input');
  const txt = (inp.value || '').trim();
  if (!txt) return;
  const sendBtn = document.getElementById('ai-page-send');
  sendBtn.disabled = true;
  sendBtn.textContent = '…';
  inp.value = '';

  _aiPageConv.push({role: 'user', content: txt});
  _aiPageConv.push({role: 'assistant', content: '', pending: true});
  _aiPageSaveConv();
  _aiPageRenderConv();

  // Live elapsed ticker
  const tickHandles = [];
  const tickFn = () => {
    document.querySelectorAll('.ai-page-elapsed').forEach(el => {
      const s = Math.floor((Date.now() - parseInt(el.dataset.start || '0', 10)) / 1000);
      el.textContent = `(${s}s elapsed)`;
    });
  };
  const tick = setInterval(tickFn, 1000);
  tickHandles.push(tick);

  // Build the messages list to send — strip 'pending' flag, model, meta
  const sendMessages = _aiPageConv
    .filter(m => !m.pending)
    .map(m => ({role: m.role, content: m.content}));

  const modelSel = document.getElementById('ai-page-model').value;
  const reqBody = {
    messages: sendMessages,
    system:   'free_form',
    context:  'ai-page',
  };
  if (modelSel) reqBody.model = modelSel;

  const resp = await aiApi('POST', '/ai/chat', reqBody);
  clearInterval(tick);

  // Replace the pending placeholder with the result (or the error)
  const last = _aiPageConv[_aiPageConv.length - 1];
  if (resp.ok) {
    last.content = resp.text || '(empty response)';
    last.pending = false;
    last.model = resp.model;
    last.meta = `${resp.tokens_in}+${resp.tokens_out} tokens · ${(resp.elapsed_ms/1000).toFixed(1)}s` +
                (resp.daily_cap ? ` · ${resp.used_today}/${resp.daily_cap} today` : '');
  } else {
    last.content = `${resp.error}`;
    last.pending = false;
    last.meta = 'error';
  }
  _aiPageSaveConv();
  _aiPageRenderConv();
  sendBtn.disabled = false;
  sendBtn.textContent = 'Send';
  inp.focus();
}

// ─── v2.1.5: compact grouped device dropdown ───────────────────────────────
//
// The pre-2.1.5 dropdown listed 22 items vertically — taller than most
// device cards, which made it spill off the screen on a busy device
// list. This version groups items into four logical buckets:
//
//   Power     (most-used: shut down, reboot, WoL, upgrade packages)
//   Inspect   (read-only diagnostics)
//   Operate   (interactive: terminal, exec, compose, agent update)
//   Configure (settings: tags, group, allowlist, intervals, etc.)
//
// Power is always visible at the top. The other three are collapsible
// via native <details> — closed by default, click to expand. Footprint
// drops from ~22 items to 6 visible, expanding only what's needed.
// Native <details> means no JS for the collapse logic; the only cost
// is a one-time style nudge to make the disclosure triangles fit.
//
// "Remove device" stays at the bottom in its own danger zone.

function deviceDropdownHtml(d, isMonitored) {
  const idEsc   = d.id;
  const nameEsc = escAttr(d.name);
  // v2.9.0: ⋮ opens the device drawer on Actions & Settings tab.
  return `<button class="btn-icon isl-526" title="Actions &amp; Settings"
    data-stop-prop="1" data-action="openDeviceDrawer" data-arg="${idEsc}" data-arg2="${nameEsc}" data-arg3="actions" >⋮</button>`;
}
function aiDiagnoseService(serviceName, deviceName, state, subState, recentLogs) {
  const logs = Array.isArray(recentLogs) ? recentLogs.join('\n') : (recentLogs || '');
  openAIModal({
    title:    `Diagnose ${serviceName}`,
    system:   'diagnose_service',
    userMsg:  `Service: ${serviceName}\nDevice: ${deviceName}\nState: ${state || '?'}/${subState || '?'}\n\nRecent journal:\n${logs.slice(0, 6000)}`,
    context:  `service:${serviceName}`,
    maxTokens: 1500,
  });
}

function aiExplainTls(host, port, expiryEpoch, issuer, extraContext) {
  const now = Math.floor(Date.now() / 1000);
  const daysLeft = expiryEpoch ? Math.floor((expiryEpoch - now) / 86400) : '?';
  const lines = [
    `Host: ${host}:${port || 443}`,
    `Expires: ${expiryEpoch ? new Date(expiryEpoch * 1000).toISOString() : '?'} (${daysLeft} days from now)`,
    issuer ? `Issuer: ${issuer}` : '',
    extraContext || '',
  ].filter(Boolean);
  openAIModal({
    title:    `Triage cert for ${host}`,
    system:   'explain_tls',
    userMsg:  lines.join('\n'),
    context:  `tls:${host}`,
    maxTokens: 800,
  });
}

function aiPrioritisePatches(deviceName, packageList) {
  // packageList: either a string of one-per-line or array of {name, version}
  let listText = '';
  if (Array.isArray(packageList)) {
    listText = packageList.map(p =>
      typeof p === 'string' ? p : `${p.name || '?'} ${p.version || ''}`.trim()
    ).join('\n');
  } else {
    listText = String(packageList || '');
  }
  if (!listText.trim()) { toast('No pending packages to prioritise', 'info'); return; }
  openAIModal({
    title:    `Prioritise updates for ${deviceName}`,
    system:   'prioritise_patches',
    userMsg:  `Device: ${deviceName}\n\nPending updates:\n${listText.slice(0, 6000)}`,
    context:  `patches:${deviceName}`,
    maxTokens: 1500,
  });
}

function aiPrioritiseCves(deviceName, cveListText) {
  if (!cveListText.trim()) { toast('No CVE findings to prioritise', 'info'); return; }
  openAIModal({
    title:    `Prioritise CVEs for ${deviceName}`,
    system:   'prioritise_cves',
    userMsg:  `Device: ${deviceName}\n\nCVE findings:\n${cveListText.slice(0, 6000)}`,
    context:  `cves:${deviceName}`,
    maxTokens: 1500,
  });
}

async function aiPrioritiseCvesForDevice(devId, devName, btn) {
  const originalLabel = btn ? btn.innerHTML : null;
  if (btn) { btn.disabled = true; btn.innerHTML = '…'; btn.title = 'Fetching CVE findings…'; }
  const restore = () => {
    if (btn) { btn.disabled = false; btn.innerHTML = originalLabel; btn.title = "AI: prioritise this device's CVEs"; }
  };
  let data;
  try {
    data = await api('GET', `/devices/${encodeURIComponent(devId)}/cve`);
  } finally {
    restore();
  }
  if (!data) return;  // api() already toasted the error
  const findings = (data.findings || []).filter(f => !f.ignored);
  if (!findings.length) { toast('No active CVE findings to prioritise', 'info'); return; }
  const listText = findings.map(f =>
    `${(f.severity || 'unknown').toUpperCase()} ${f.vuln_id} — ${f.package} ${f.version}` +
    (f.fixed_version ? ` (fixed in ${f.fixed_version})` : ' (no fix listed)')
  ).join('\n');
  aiPrioritiseCves(devName, listText);
}

function aiExplainContainerLogs(containerName, image, logs) {
  if (!logs || !logs.trim()) { toast('No logs to explain', 'info'); return; }
  openAIModal({
    title:    `Explain ${containerName} logs`,
    system:   'explain_container_logs',
    userMsg:  `Container: ${containerName}\nImage: ${image || '?'}\n\nLogs:\n${logs.slice(0, 8000)}`,
    context:  `container:${containerName}`,
    maxTokens: 1500,
  });
}

async function aiPrioritisePatchesForDevice(devId, devName, btn) {
  // v3.0.4: show visible button feedback during the API call. The
  // previous version toasted silently on the negative paths; operators
  // reported the button felt unresponsive ("I clicked it, nothing
  // happened"). Now the button visibly disables, shows a spinner glyph
  // while the request is in flight, and restores on completion.
  //
  // v3.0.4 (iter 2): when patch_history doesn't yet contain an upgrade
  // listing, the previous version pointed the operator at "Force
  // re-scan packages" — but that flag only re-syncs the upgradable
  // COUNT, not the listing (the agent's get_patch_info() discards `out`
  // and only keeps len()). The only path that populates patch_history
  // with a real listing is an operator-triggered exec command. Rather
  // than make the operator dig for that, AInow queues the right
  // listing command for the device's package manager automatically.
  // One click → next click in ~60s → AI engages.
  const originalLabel = btn ? btn.innerHTML : null;
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '…';
    btn.title = 'Fetching patch history…';
  }
  const restore = () => {
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = originalLabel;
      btn.title = 'AI: prioritise these updates';
    }
  };
  let data;
  try {
    data = await api('GET', `/patch-report/device/${encodeURIComponent(devId)}`);
  } finally {
    restore();
  }
  if (!data) return;   // api() already toasted the error

  // Happy path: listing exists, hand it to the AI.
  const listing = (data.patch_history || []).slice().reverse().find(o =>
    /upgradable|check-update|list-upgrades|outdated|pacman -Qu/i.test(o.cmd) && o.output
  );
  if (listing) {
    aiPrioritisePatches(devName, listing.output);
    return;
  }

  // No listing — figure out which command WOULD produce one for this
  // package manager, then offer to queue it on the device. The result
  // arrives in CMD_OUTPUT_FILE on the next heartbeat (~60s) and shows
  // up in patch_history on subsequent /patch-report/device fetches.
  const LISTING_CMD_FOR = {
    apt:    'apt list --upgradable',
    dnf:    'dnf check-update',
    pacman: 'pacman -Qu',
  };
  const pkgManager = data.pkg_manager;
  const listingCmd = LISTING_CMD_FOR[pkgManager];

  if (!listingCmd) {
    toast(`No upgrade listing in patch history, and no built-in listing `
          + `command for "${pkgManager || 'unknown'}". Run an appropriate `
          + `"list upgradable packages" command via Run Command, then `
          + `click again.`, 'info');
    return;
  }

  if (!confirm(
        `No upgrade listing recorded for ${devName} yet.\n\n`
      + `Queue "${listingCmd}" on the device now?\n\n`
      + `Output arrives in ~60s. Click again after that to get the `
      + `AI's upgrade-prioritisation summary.`)) {
    return;
  }

  const r = await api('POST', '/exec', {device_id: devId, cmd: listingCmd});
  if (r?.ok) {
    toast(`Queued ${listingCmd} on ${devName}. Click again in ~60s `
          + `to get the AI analysis.`, 'success');
  } else {
    toast(r?.error || 'Failed to queue the listing command', 'error');
  }
}

// ─── v2.1.7: Device runbooks ───────────────────────────────────────────────
//
// Two surfaces:
//   1. AIGenerate runbook — entry in the device dropdown. Opens a
//      modal, fires POST /api/devices/<id>/runbook/generate, displays
//      the resulting Markdown via renderMarkdown(). Sync — the modal
//      shows an elapsed-time ticker so a slow local model doesn't look
//      frozen.
//   2. Runbook section on the device detail modal — auto-loaded by
//      openDetail() when there's a saved runbook. Shows the Markdown
//      with a "Regenerate" + "Delete" button.

let _runbookModalEl = null;

function _ensureRunbookModal() {
  if (_runbookModalEl) return _runbookModalEl;
  const wrap = document.createElement('div');
  wrap.className = 'modal-overlay';
  wrap.id = 'runbook-modal';
  wrap.innerHTML = `
    <div class="modal isl-527">
      <div class="modal-header row-between">
        <div id="runbook-modal-title" class="fw-600">Runbook</div>
        <button class="btn-icon isl-44" data-action="closeRunbookModal" >✕</button>
      </div>
      <div id="runbook-modal-meta" class="isl-509">—</div>
      <div id="runbook-modal-body" class="isl-528">
        <div class="c-muted">Generating runbook…</div>
      </div>
      <div class="isl-529">
        <button class="btn-icon" id="runbook-modal-copy" data-action="runbookModalCopy"  disabled>Copy markdown</button>
        <button class="btn-icon d-none" id="runbook-modal-regen" data-action="runbookModalRegen" >Regenerate</button>
        <div class="flex-1"></div>
        <button class="btn-icon" data-action="closeRunbookModal" >Close</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  _runbookModalEl = wrap;
  return wrap;
}

function closeRunbookModal() {
  if (_runbookModalEl) _runbookModalEl.classList.remove('active');
}

function runbookModalCopy() {
  const body = document.getElementById('runbook-modal-body');
  navigator.clipboard.writeText(body.dataset.rawText || body.textContent || '');
  toast('Runbook copied as Markdown', 'success');
}

let _runbookCurrentDevice = null;   // {id, name} for the Regenerate button

function runbookModalRegen() {
  if (!_runbookCurrentDevice) return;
  if (!confirm('Regenerate the runbook? Sends the device snapshot to the configured AI provider again.')) return;
  aiGenerateRunbook(_runbookCurrentDevice.id, _runbookCurrentDevice.name);
}

async function aiGenerateRunbook(devId, deviceName) {
  _ensureRunbookModal();
  _runbookModalEl.classList.add('active');
  _runbookCurrentDevice = {id: devId, name: deviceName};
  document.getElementById('runbook-modal-title').textContent = `Runbook — ${deviceName}`;
  document.getElementById('runbook-modal-meta').textContent =
    'Gathering device snapshot and asking the AI to write a runbook — this can take 30–120 s on slow local models.';
  const body = document.getElementById('runbook-modal-body');
  body.innerHTML = '<div class="c-muted">Thinking… <span id="runbook-modal-elapsed" data-start="' + Date.now() + '">(0s elapsed)</span></div>';
  body.dataset.rawText = '';
  document.getElementById('runbook-modal-copy').disabled = true;
  document.getElementById('runbook-modal-regen').style.display = 'none';

  // Tick elapsed time so the modal doesn't look frozen during the
  // 30-120s round-trip on slow local models.
  const tick = setInterval(() => {
    const el = document.getElementById('runbook-modal-elapsed');
    if (!el) return;
    const s = Math.floor((Date.now() - parseInt(el.dataset.start || '0', 10)) / 1000);
    el.textContent = `(${s}s elapsed)`;
  }, 1000);

  const resp = await aiApi('POST', `/devices/${encodeURIComponent(devId)}/runbook/generate`, {});
  clearInterval(tick);

  if (!resp.ok) {
    body.innerHTML = `<div class="isl-513">${escHtml(resp.error)}</div>`;
    return;
  }
  body.innerHTML = `<div class="ai-content">${renderMarkdown(resp.content || '(empty)')}</div>`;
  body.dataset.rawText = resp.content || '';
  document.getElementById('runbook-modal-copy').disabled = false;
  document.getElementById('runbook-modal-regen').style.display = 'flex';
  const when = resp.generated_at ? new Date(resp.generated_at * 1000).toLocaleString() : '—';
  document.getElementById('runbook-modal-meta').textContent =
    `${resp.model || '?'} · ${resp.tokens_in}+${resp.tokens_out} tokens · ${(resp.elapsed_ms/1000).toFixed(1)}s · generated ${when}`;

  // If the device detail modal is open, refresh its runbook section.
  if (typeof refreshDetailRunbookSection === 'function') {
    refreshDetailRunbookSection(devId);
  }
}

// View an existing runbook (used by the device detail modal's
// "View runbook" button when there's a stored one already).
async function aiViewRunbook(devId, deviceName) {
  _ensureRunbookModal();
  _runbookModalEl.classList.add('active');
  _runbookCurrentDevice = {id: devId, name: deviceName};
  document.getElementById('runbook-modal-title').textContent = `Runbook — ${deviceName}`;
  document.getElementById('runbook-modal-meta').textContent = 'Loading…';
  const body = document.getElementById('runbook-modal-body');
  body.innerHTML = '<div class="c-muted">Loading…</div>';
  document.getElementById('runbook-modal-copy').disabled = true;
  document.getElementById('runbook-modal-regen').style.display = 'flex';

  const resp = await aiApi('GET', `/devices/${encodeURIComponent(devId)}/runbook`);
  if (!resp.ok) {
    body.innerHTML = `<div class="c-red">${escHtml(resp.error)}</div>`;
    return;
  }
  if (!resp.exists) {
    body.innerHTML = '<div class="empty-state">No runbook generated yet. Click <strong>Regenerate</strong> to create one.</div>';
    document.getElementById('runbook-modal-meta').textContent = 'No runbook stored.';
    return;
  }
  body.innerHTML = `<div class="ai-content">${renderMarkdown(resp.content || '(empty)')}</div>`;
  body.dataset.rawText = resp.content || '';
  document.getElementById('runbook-modal-copy').disabled = false;
  const when = resp.generated_at ? new Date(resp.generated_at * 1000).toLocaleString() : '—';
  document.getElementById('runbook-modal-meta').textContent =
    `${resp.model || '?'} · ${resp.tokens_in}+${resp.tokens_out} tokens · generated ${when} by ${resp.generated_by || '?'}`;
}

async function aiDeleteRunbook(devId) {
  if (!confirm('Delete the stored runbook? You can always regenerate.')) return;
  const resp = await aiApi('DELETE', `/devices/${encodeURIComponent(devId)}/runbook`);
  if (resp.ok) {
    toast('Runbook deleted', 'success');
    if (typeof refreshDetailRunbookSection === 'function') {
      refreshDetailRunbookSection(devId);
    }
  } else {
    toast('Delete failed: ' + (resp.error || '?'), 'error');
  }
}

// Refresh the runbook section inside the device detail modal — called
// after generate / delete so the view stays in sync. Implementation
// below is just a hook; the detail modal renders its own runbook
// section via openDetail().
async function refreshDetailRunbookSection(devId) {
  const el = document.getElementById('detail-runbook-section');
  if (!el) return;   // detail modal not open or no runbook section
  const resp = await aiApi('GET', `/devices/${encodeURIComponent(devId)}/runbook`);
  el.innerHTML = _renderRunbookSectionHtml(devId, resp);
}

function _renderRunbookSectionHtml(devId, resp) {
  // Shared between openDetail() and refreshDetailRunbookSection()
  if (!resp || !resp.ok) return '';
  if (!resp.exists) {
    return `<div class="isl-530">
      <div class="isl-93">
        <div class="isl-433">Runbook</div>
        <button class="btn-icon badge-xs" data-action="aiGenerateRunbook" data-arg="${escAttr(devId)}" data-arg2="${escAttr(_lastOpenDeviceName||'')}">${_icon('sparkles',14)} Generate runbook</button>
      </div>
      <div class="hint">No runbook generated yet for this device.</div>
    </div>`;
  }
  const when = resp.generated_at ? new Date(resp.generated_at * 1000).toLocaleString() : '—';
  return `<div class="isl-530">
    <div class="isl-531">
      <div>
        <div class="isl-433">Runbook</div>
        <div class="meta-sm-nm">${escHtml(resp.model || '?')} · generated ${escHtml(when)} by ${escHtml(resp.generated_by || '?')}</div>
      </div>
      <div class="row-6">
        <button class="btn-icon badge-xs" data-action="aiViewRunbook" data-arg="${escAttr(devId)}" data-arg2="${escAttr(_lastOpenDeviceName||'')}">Open full</button>
        <button class="btn-icon badge-xs" data-action="aiGenerateRunbook" data-arg="${escAttr(devId)}" data-arg2="${escAttr(_lastOpenDeviceName||'')}">${_icon('sparkles',14)} Regenerate</button>
        <button class="btn-icon isl-459" data-action="aiDeleteRunbook" data-arg="${escAttr(devId)}" >Delete</button>
      </div>
    </div>
    <div class="ai-content isl-532">${renderMarkdown(resp.content || '')}</div>
  </div>`;
}

// Track the last device name so we don't have to thread it through the
// callbacks above. Set when openDetail runs.
let _lastOpenDeviceName = '';

// ─── v2.2.0: Configuration drift detection ─────────────────────────────────
//
// Fleet-wide drift overview page + per-device drift modal. The agent
// hashes a list of watched files every few heartbeats; the server stores
// baselines and fires `drift_detected` webhooks when a current hash
// diverges. This UI surfaces both views without ever touching file content
// (which is the security property of the whole feature — no /etc/sudoers
// contents ever travel across the wire on routine polling).

let _driftLastResponse = null;
let _driftDeviceModal = null;

async function loadDrift() {
  const tbody = document.getElementById('drift-tbody');
  const summary = document.getElementById('drift-summary');
  if (!tbody) return;
  tbody.innerHTML = '<tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line med"></div></td></tr><tr class="skeleton-row"><td colspan="7"><div class="skeleton skeleton-line long"></div></td></tr>';
  try {
    const data = await api('GET', '/drift');
    _driftLastResponse = data;
    _renderDrift(data.devices || []);
    const totalDrift = (data.devices || []).reduce((s, d) => s + (d.drifted || 0), 0);
    const totalMissing = (data.devices || []).reduce((s, d) => s + (d.missing || 0), 0);
    summary.textContent = `${(data.devices || []).length} devices reporting · ${totalDrift} files drifted · ${totalMissing} files missing`;
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="isl-533">Failed to load: ${escHtml(String(e))}</td></tr>`;
  }
}

function _renderDrift(rows) {
  const tbody = document.getElementById('drift-tbody');
  const filter = (document.getElementById('drift-filter')?.value || '').toLowerCase().trim();
  let visible = rows.filter(r =>
    !filter ||
    (r.device_name || '').toLowerCase().includes(filter) ||
    (r.group || '').toLowerCase().includes(filter)
  );
  // v3.2.1: sortable
  tableCtl.wireSortOnly('drift-thead', 'drift', () => _renderDrift(_driftLastResponse?.devices || []));
  visible = tableCtl.sortRows('drift', visible, (r) => ({
    name:       (r.device_name || '').toLowerCase(),
    group:      r.group || '',
    watched:    r.total || 0,
    drift:      r.drifted || 0,
    missing:    r.missing || 0,
    last_check: r.last_check || 0,
  }));
  if (visible.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="isl-534">No drift data yet. Wait for the first agent heartbeat with v2.2.0+ and drift enabled.</td></tr>';
    return;
  }
  tbody.innerHTML = visible.map(r => {
    const lastCheck = r.last_check ? new Date(r.last_check * 1000).toLocaleString() : '—';
    const driftColor = r.drifted > 0 ? 'var(--amber)' : 'var(--muted)';
    const missingColor = r.missing > 0 ? 'var(--red)' : 'var(--muted)';
    return `<tr>
      <td class="fw-500">${escHtml(r.device_name)}</td>
      <td class="hint">${escHtml(r.group || '—')}</td>
      <td>${r.total}</td>
      <td class="isl-535 ${r.drifted > 0 ? 'fw-600' : ''}" data-color="${driftColor}">${r.drifted}</td>
      <td class="isl-536" data-color="${missingColor}">${r.missing}</td>
      <td class="hint">${lastCheck}</td>
      <td><button class="btn-icon cell-sm" data-action="openDriftDetail" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.device_name)}">Detail</button></td>
    </tr>`;
  }).join('');
}

// Re-render when filter changes
document.addEventListener('input', e => {
  if (e.target && e.target.id === 'drift-filter' && _driftLastResponse) {
    _renderDrift(_driftLastResponse.devices || []);
  }
});

function _ensureDriftModal() {
  if (_driftDeviceModal) return _driftDeviceModal;
  const wrap = document.createElement('div');
  wrap.className = 'modal-overlay';
  wrap.id = 'drift-detail-modal';
  wrap.innerHTML = `
    <div class="modal isl-537">
      <div class="modal-header row-between">
        <div id="drift-detail-title" class="fw-600">Drift detail</div>
        <button class="btn-icon isl-44" data-action="closeDriftDetail" >✕</button>
      </div>
      <div id="drift-detail-body" class="isl-538">
        <div class="c-muted">Loading…</div>
      </div>
      <div class="isl-529">
        <button class="btn-icon d-none" id="drift-accept-all" data-action="driftAcceptAll" >Accept all current as new baseline</button>
        <div class="flex-1"></div>
        <button class="btn-icon" data-action="closeDriftDetail" >Close</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  _driftDeviceModal = wrap;
  return wrap;
}

let _driftCurrentDevice = null;

function closeDriftDetail() {
  if (_driftDeviceModal) _driftDeviceModal.classList.remove('active');
}

async function openDriftDetail(devId, devName) {
  _ensureDriftModal();
  _driftDeviceModal.classList.add('active');
  _driftCurrentDevice = {id: devId, name: devName};
  document.getElementById('drift-detail-title').textContent = `Drift detail — ${devName}`;
  const body = document.getElementById('drift-detail-body');
  body.innerHTML = '<div class="c-muted">Loading…</div>';
  document.getElementById('drift-accept-all').style.display = 'none';

  try {
    const data = await api('GET', `/devices/${encodeURIComponent(devId)}/drift`);
    const files = data.files || {};
    const watched = data.watched_files || [];
    const fileKeys = Object.keys(files).sort();

    if (fileKeys.length === 0) {
      body.innerHTML = `<div class="empty-p20">
        No drift report received yet for this device.<br>
        <span class="fs-12">The agent submits hashes for ${watched.length} watched ${watched.length === 1 ? 'file' : 'files'} every few heartbeats once the device has checked in.</span>
      </div>`;
      return;
    }

    const anyDrifted = fileKeys.some(p =>
      files[p].current_hash !== files[p].baseline_hash);
    if (anyDrifted) {
      document.getElementById('drift-accept-all').style.display = 'flex';
    }

    let html = `<div class="isl-539">
      Watched: ${watched.length} ${watched.length === 1 ? 'path' : 'paths'} · Reported: ${fileKeys.length}
    </div>`;

    html += '<table class="isl-540"><thead><tr class="isl-468"><th class="cell-pad">Path</th><th class="cell-pad">Status</th><th class="cell-pad">Last check</th><th class="cell-pad">Drift count</th><th></th></tr></thead><tbody>';

    for (const p of fileKeys) {
      const f = files[p];
      const drifted = f.current_hash !== f.baseline_hash;
      const missing = !f.exists;
      const ignored = !!f.ignored;          // v2.3.4
      const dormant = !!f.dormant;
      const lastCheck = f.last_check ? new Date(f.last_check * 1000).toLocaleString() : '—';

      // v2.3.4: an ignored file renders muted regardless of its
      // underlying drift/missing state — it's been explicitly marked
      // non-critical. Its real state is still shown in parentheses so
      // the operator knows what they ignored.
      let statusHtml;
      if (ignored) {
        const underlying = missing ? 'missing' : (drifted ? 'drifted' : 'baseline');
        statusHtml = `<span class="c-muted">○ Ignored <span class="fs-10">(${underlying})</span></span>`;
      } else if (missing) {
        statusHtml = '<span class="c-red">● Missing</span>';
      } else if (dormant) {
        statusHtml = '<span class="c-muted">○ Dormant</span>';
      } else if (drifted) {
        statusHtml = '<span class="c-amber">● Drifted</span>';
      } else {
        statusHtml = '<span class="c-green">● Baseline</span>';
      }

      const acceptBtn = (drifted && !ignored)
        ? `<button class="btn-icon isl-464" data-action="driftAcceptPath" data-arg="${escAttr(p)}" >Accept as baseline</button>`
        : '';

      // v2.3.4: per-file ignore toggle. Marking a file ignored makes
      // it non-critical (drops out of drift/missing counts, no red
      // status) — the fix for drift false positives like a watched
      // file legitimately absent on this host.
      const ignoreBtn = ignored
        ? `<button class="btn-icon isl-541" data-action-btn="_driftSetIgnoreFalse" data-arg="${escAttr(p)}">Un-ignore</button>`
        : `<button class="btn-icon isl-541" data-action-btn="_driftSetIgnoreTrue" data-arg="${escAttr(p)}">Ignore</button>`;

      const DENYLIST = new Set(['/etc/shadow','/etc/gshadow','/etc/shadow-','/etc/gshadow-']);
      const isDenylist = DENYLIST.has(p);
      const diffBtn = (drifted && !missing && !isDenylist && !ignored)
        ? `<button class="btn-icon isl-541" data-action="openDriftDiff" data-arg="${escAttr(_driftCurrentDevice.id)}" data-arg2="${escAttr(p)}" >Show diff</button>`
        : (isDenylist
          ? `<span title="Content retrieval refused for sensitive files" class="isl-542">no content</span>`
          : '');

      const rowStyle = ignored
        ? 'border-bottom:1px solid var(--border);opacity:0.55'
        : 'border-bottom:1px solid var(--border)';
      html += `<tr class="isl-543">
        <td class="isl-544">${escHtml(p)}</td>
        <td class="cell-pad">${statusHtml}</td>
        <td class="isl-545">${lastCheck}</td>
        <td class="cell-pad">${f.drift_count || 0}</td>
        <td class="isl-546">${diffBtn}${ignoreBtn}${acceptBtn}</td>
      </tr>`;
      if (ignored && f.ignore_reason) {
        html += `<tr class="isl-547"><td colspan="5" class="isl-548">Ignore reason: ${escHtml(f.ignore_reason)}</td></tr>`;
      }

      if (drifted && f.history && f.history.length > 0) {
        html += `<tr><td colspan="5" class="isl-549"><details><summary class="isl-550">History (${f.history.length} ${f.history.length === 1 ? 'change' : 'changes'})</summary>
          <div class="isl-551">
          ${f.history.slice().reverse().slice(0, 10).map(h =>
            `${new Date(h.ts * 1000).toLocaleString()}: ${(h.hash || '').substring(0, 24)}… ${h.exists === false ? ' [missing]' : ''}`
          ).join('<br>')}
          </div></details></td></tr>`;
      }
    }
    html += '</tbody></table>';

    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = `<div class="c-red-p20">Failed to load: ${escHtml(String(e))}</div>`;
  }
}

async function driftAcceptPath(path) {
  if (!_driftCurrentDevice) return;
  if (!confirm(`Accept current hash as new baseline for:\n${path}\n\nFuture changes from this hash will count as drift.`)) return;
  try {
    await api('POST', `/devices/${encodeURIComponent(_driftCurrentDevice.id)}/drift/baseline`,
              {paths: [path]});
    toast('Baseline updated', 'success');
    openDriftDetail(_driftCurrentDevice.id, _driftCurrentDevice.name);
  } catch (e) {
    toast('Failed: ' + e, 'error');
  }
}

// v2.3.4: mark a watched file as ignored (or un-ignore it). An
// ignored file is non-critical — it drops out of the drift / missing
// counts and stops driving a red status, but stays visible in this
// detail view. Used to silence drift false positives, e.g. a watched
// file that's legitimately absent on a particular host.
async function driftSetIgnore(path, ignored) {
  if (!_driftCurrentDevice) return;
  let reason = '';
  if (ignored) {
    reason = prompt(`Ignore drift for:\n${path}\n\nOptional reason (why this is expected):`, '');
    if (reason === null) return;   // operator cancelled
  }
  try {
    await api('POST', `/devices/${encodeURIComponent(_driftCurrentDevice.id)}/drift/ignore`,
              {path: path, ignored: ignored, reason: reason || ''});
    toast(ignored ? 'File ignored' : 'File no longer ignored', 'success');
    openDriftDetail(_driftCurrentDevice.id, _driftCurrentDevice.name);
  } catch (e) {
    toast('Failed: ' + e, 'error');
  }
}

async function driftAcceptAll() {
  if (!_driftCurrentDevice) return;
  if (!confirm('Accept current hashes as new baseline for all drifted files on this device?\n\nFuture changes from these new baselines will count as drift.')) return;
  try {
    await api('POST', `/devices/${encodeURIComponent(_driftCurrentDevice.id)}/drift/baseline`,
              {all: true});
    toast('All drifted baselines updated', 'success');
    openDriftDetail(_driftCurrentDevice.id, _driftCurrentDevice.name);
  } catch (e) {
    toast('Failed: ' + e, 'error');
  }
}

// ═══════════════════════════════════════════════════════════════════════
// v2.2.1 — Design polish JS infrastructure
//
// Adds:
//   getDistroIcon(osString) → SVG string for the matching distro logo
//   renderSparkline(values, opts) → SVG string for a small line chart
//   renderSkeleton(target, kind) → fill `target` with shimmer placeholders
//   renderStatusStripe(history) → 7-day status visualisation
//   renderDiff(baseline, current) → unified diff with line markers
//   loadIndex() / renderIndexDashboard() → home page summary
// ═══════════════════════════════════════════════════════════════════════

// ─── Distro logos ────────────────────────────────────────────────────────
// 14×14 inline SVGs, picked from each distro's brand mark. Operator sees
// "Ubuntu orange" or "Debian red swirl" next to the device name without
// having to read the OS string.

const DISTRO_ICONS = {
  // Each entry: {match: [regex strings tested against OS field], svg}
  // First match wins. 14×14 viewBox. Inline coloured fill, no external refs.
  ubuntu: {
    match: ['ubuntu'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#E95420"><circle cx="12" cy="12" r="11" opacity="0.15"/><circle cx="12" cy="12" r="2.5"/><circle cx="19" cy="12" r="2"/><circle cx="8.5" cy="6" r="2"/><circle cx="8.5" cy="18" r="2"/></svg>'
  },
  debian: {
    match: ['debian'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#A81D33"><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c4.4 0 8.2-2.9 9.5-7-.8 2.4-2.8 3.7-4.9 3.7-2.7 0-4.9-2.2-4.9-4.9 0-2.4 1.7-4.3 4-4.8-1.2-.8-2.7-.4-3.5.8-1.1-2.2-.5-4.8 1.7-5.9.7-.4 1.5-.5 2.3-.5C14.7 2.4 13.4 2 12 2z"/></svg>'
  },
  arch: {
    match: ['arch', 'cachy'],   // CachyOS is Arch-based; uses same blue chevron
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#1793D1"><path d="M12 2L2 22h20L12 2zm0 4.8L18.5 19h-13L12 6.8zM12 11l-2.5 5h5L12 11z"/></svg>'
  },
  cachy: {
    match: ['cachyos'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#19A98F"><path d="M12 2L2 22h20L12 2zm0 4.8L18.5 19h-13L12 6.8z"/><circle cx="12" cy="15" r="2.5" fill="#1793D1"/></svg>'
  },
  fedora: {
    match: ['fedora'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#3C6EB4"><circle cx="12" cy="12" r="10"/><path d="M14 7v6h-3a2 2 0 0 0 0 4h1v-2h-1a0 0 0 0 1 0 0h3v-6h2V7h-2z" fill="white"/></svg>'
  },
  rhel: {
    match: ['rhel', 'red hat', 'redhat', 'red-hat', 'rocky', 'alma', 'almalinux', 'centos'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#EE0000"><path d="M16 11c0-3-2-5-5-5-3 0-5 2-5 5 0 1 0 2 1 3l-3 1c-1 1-1 2 0 2 4 1 9 2 13 0 1 0 1-1 0-2l-3-1c1-1 1-2 1-3zm-5 8c-3 0-6-1-7-2 1-1 3-2 7-2s6 1 7 2c-1 1-4 2-7 2z"/></svg>'
  },
  suse: {
    match: ['suse', 'opensuse', 'open suse'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#73BA25"><circle cx="12" cy="12" r="10"/><path d="M8 10c0-1 1-2 2-2s2 1 2 2v4c0 1-1 2-2 2s-2-1-2-2v-4zm6 0c0-1 1-2 2-2v6c-1 0-2-1-2-2v-2z" fill="white"/></svg>'
  },
  alpine: {
    match: ['alpine'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#0D597F"><circle cx="12" cy="12" r="10"/><path d="M7 16l3-4 2 2 4-6 3 8H7z" fill="white"/></svg>'
  },
  gentoo: {
    match: ['gentoo'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#54487A"><ellipse cx="12" cy="12" rx="9" ry="6" transform="rotate(-30 12 12)"/></svg>'
  },
  nixos: {
    match: ['nixos', 'nix os'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#5277C3"><path d="M12 2l3 5h-2l-1-2-3 5h4l3 5h-2l-1-2-3 5-3-5h2l1 2 3-5H8L5 5h2l1 2L12 2z"/></svg>'
  },
  raspbian: {
    match: ['raspbian', 'raspberry'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#C51A4A"><circle cx="9" cy="11" r="3"/><circle cx="15" cy="11" r="3"/><path d="M9 14c0 3 2 5 3 5s3-2 3-5"/></svg>'
  },
  // BSDs (RemotePower might end up watching BSD hosts via agentless mode)
  freebsd: {
    match: ['freebsd'],
    svg: '<svg class="distro-icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#AB2B28"><circle cx="12" cy="12" r="10"/><path d="M8 9l3 3-2 4 5-2 3 3-1-5 3-2-5-1-2-5-2 4-4 1z" fill="white"/></svg>'
  },
  // Fallback: generic Linux penguin silhouette in muted accent
  linux: {
    match: ['linux'],
    svg: '<svg class="distro-icon c-muted" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><circle cx="12" cy="9" r="4"/><path d="M8 13c0 4 1 7 4 7s4-3 4-7c-1 1-3 1.5-4 1.5S9 14 8 13z"/><circle cx="10" cy="8" r="1" fill="white"/><circle cx="14" cy="8" r="1" fill="white"/></svg>'
  },
  // Unknown OS: simple terminal-block icon
  unknown: {
    match: [],
    svg: '<svg class="distro-icon c-muted" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="currentColor"><rect x="3" y="5" width="18" height="14" rx="2" stroke="currentColor" fill="none" stroke-width="2"/><path d="M7 9l3 3-3 3M12 15h5" stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round"/></svg>'
  },
};

function getDistroIcon(osField) {
  // Pick the distro icon best matching the OS field. Case-insensitive
  // substring match. CachyOS resolves to its own icon first; if absent
  // falls back to the Arch chevron (same family). RHEL family (Rocky,
  // Alma, CentOS) all resolve to the RHEL mark.
  const os = String(osField || '').toLowerCase();
  if (!os) return DISTRO_ICONS.unknown.svg;
  // Order matters: try the more specific matches first.
  const probeOrder = ['cachy', 'ubuntu', 'debian', 'fedora', 'rhel',
                      'suse', 'alpine', 'gentoo', 'nixos', 'raspbian',
                      'arch', 'freebsd', 'linux'];
  for (const key of probeOrder) {
    const entry = DISTRO_ICONS[key];
    if (!entry) continue;
    for (const pat of entry.match) {
      if (os.includes(pat)) return entry.svg;
    }
  }
  return DISTRO_ICONS.unknown.svg;
}

// ─── Sparkline mini-charts ──────────────────────────────────────────────
// Pure SVG line chart, ~60×16 px. Used inline with metric values.
// values: array of numbers (any length); shorter arrays use available
//         points only. Returns SVG string ready to inject.
// opts.color, opts.width, opts.height, opts.fill (boolean), opts.lastDot
//
// Picks colour automatically from the last value vs the dataset min/max
// if no color is passed: trending-up gets accent, trending-down gets
// amber for capacity metrics (caller can override).

function renderSparkline(values, opts) {
  opts = opts || {};
  const w = opts.width || 60;
  const h = opts.height || 16;
  const arr = (values || []).filter(v => typeof v === 'number' && !isNaN(v));
  if (arr.length < 2) {
    // Empty / single-point: render an empty box (keeps layout stable)
    return `<svg class="sparkline" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg"></svg>`;
  }
  const min = Math.min(...arr);
  const max = Math.max(...arr);
  const range = (max - min) || 1;
  const stepX = w / (arr.length - 1);
  // 1px top/bottom padding so the stroke isn't clipped at the edge
  const yPad = 1.5;
  const yScale = (h - 2 * yPad) / range;

  const points = arr.map((v, i) => {
    const x = i * stepX;
    const y = h - yPad - (v - min) * yScale;
    return [x, y];
  });

  const linePath = 'M' + points.map(p => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(' L');

  let color = opts.color;
  if (!color) {
    // Heuristic: if last value > median, "rising"; for capacity metrics
    // (disk/mem) that's amber; for general metrics it's accent.
    const last = arr[arr.length - 1];
    const median = arr.slice().sort((a, b) => a - b)[Math.floor(arr.length / 2)];
    if (last > median * 1.15) color = 'var(--amber)';
    else if (last < median * 0.85) color = 'var(--green)';
    else color = 'var(--accent)';
  }

  let svg = `<svg class="sparkline" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg">`;

  if (opts.fill !== false) {
    const areaPath = linePath + ` L${(w).toFixed(1)},${h} L0,${h} Z`;
    svg += `<path class="area" d="${areaPath}" fill="${color}"/>`;
  }
  svg += `<path d="${linePath}" stroke="${color}"/>`;
  if (opts.lastDot !== false) {
    const last = points[points.length - 1];
    svg += `<circle class="dot" cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="1.6" fill="${color}"/>`;
  }
  svg += '</svg>';
  return svg;
}

// ─── Skeleton loader helpers ─────────────────────────────────────────────
// Three kinds of skeleton: row (for tables), card (for device tiles),
// and lines (for blocks of text content).

function renderSkeletonRows(colspan, n) {
  n = n || 5;
  let html = '';
  for (let i = 0; i < n; i++) {
    html += `<tr class="skeleton-row"><td colspan="${colspan}">
      <div class="skeleton skeleton-line ${i % 2 ? 'med' : 'long'}"></div>
    </td></tr>`;
  }
  return html;
}

function renderSkeletonCards(n) {
  n = n || 4;
  let html = '';
  for (let i = 0; i < n; i++) {
    html += `<div class="skeleton-card">
      <div class="skeleton skeleton-line short"></div>
      <div class="skeleton skeleton-line long"></div>
      <div class="skeleton skeleton-line med"></div>
    </div>`;
  }
  return html;
}

// ─── 7-day status stripe ─────────────────────────────────────────────────
// Renders the GitHub-contribution-graph-style horizontal cells. Each cell
// represents one day's online state. Input: array of state strings, oldest
// first. Each entry: 'up' | 'partial' | 'down' | 'unknown'.

function renderStatusStripe(states) {
  states = states || [];
  // Pad/truncate to 7 days
  while (states.length < 7) states.unshift('unknown');
  states = states.slice(-7);
  const labels = ['7d ago', '6d ago', '5d ago', '4d ago', '3d ago', '2d ago', 'Yesterday'];
  return '<span class="status-stripe">' +
    states.map((s, i) =>
      `<span class="cell ${s}" title="${labels[i]}: ${s}"></span>`
    ).join('') + '</span>';
}

// ─── Unified diff renderer ───────────────────────────────────────────────
// Pure JS, no library. Used by the drift detail modal when the operator
// clicks "Show diff" on a drifted file. Two-stage:
//   1. LCS to compute the longest common subsequence between baseline
//      and current lines.
//   2. Walk the LCS to produce add/del/context markers.
//
// Output is an array of {type, line, baselineLn, currentLn} objects which
// renderDiff() turns into HTML. Hunks (consecutive non-context lines plus
// 3 lines of context on each side) are highlighted with a hunk header.

function _diffLCS(a, b) {
  // Standard dynamic-programming LCS. Returns 2D array of common-length
  // counts; the actual subsequence is reconstructed by walking back.
  const m = a.length, n = b.length;
  const lcs = Array(m + 1);
  for (let i = 0; i <= m; i++) lcs[i] = new Int32Array(n + 1);
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      lcs[i][j] = (a[i-1] === b[j-1])
        ? lcs[i-1][j-1] + 1
        : Math.max(lcs[i-1][j], lcs[i][j-1]);
    }
  }
  return lcs;
}

function computeDiff(baselineText, currentText) {
  const a = (baselineText || '').split('\n');
  const b = (currentText || '').split('\n');
  const lcs = _diffLCS(a, b);
  const ops = [];
  let i = a.length, j = b.length;
  while (i > 0 && j > 0) {
    if (a[i-1] === b[j-1]) {
      ops.unshift({type: 'ctx', line: a[i-1], al: i, bl: j});
      i--; j--;
    } else if (lcs[i-1][j] >= lcs[i][j-1]) {
      ops.unshift({type: 'del', line: a[i-1], al: i, bl: null});
      i--;
    } else {
      ops.unshift({type: 'add', line: b[j-1], al: null, bl: j});
      j--;
    }
  }
  while (i > 0) { ops.unshift({type: 'del', line: a[i-1], al: i, bl: null}); i--; }
  while (j > 0) { ops.unshift({type: 'add', line: b[j-1], al: null, bl: j}); j--; }
  return ops;
}

function renderDiff(baselineText, currentText) {
  // If either side is empty, simplify the rendering
  if (!baselineText && !currentText) {
    return '<div class="empty-state-body">(both versions empty)</div>';
  }
  if (!baselineText) {
    // Entire file is new
    return '<div class="diff-view">' +
      (currentText || '').split('\n').map((l, i) =>
        `<div class="diff-line add"><span class="ln">${i+1}</span><span class="marker">+</span>${escHtml(l)}</div>`
      ).join('') + '</div>';
  }
  if (!currentText) {
    // Entire file is deleted (or unreadable)
    return '<div class="diff-view">' +
      (baselineText || '').split('\n').map((l, i) =>
        `<div class="diff-line del"><span class="ln">${i+1}</span><span class="marker">-</span>${escHtml(l)}</div>`
      ).join('') + '</div>';
  }

  const ops = computeDiff(baselineText, currentText);

  // Build hunks: any add/del with 3 lines of context on either side.
  const HUNK_CTX = 3;
  const hunkMarks = new Array(ops.length).fill(false);
  for (let k = 0; k < ops.length; k++) {
    if (ops[k].type !== 'ctx') {
      for (let m = Math.max(0, k - HUNK_CTX); m <= Math.min(ops.length - 1, k + HUNK_CTX); m++) {
        hunkMarks[m] = true;
      }
    }
  }

  let html = '<div class="diff-view">';
  let lastWasHunkBreak = true;
  for (let k = 0; k < ops.length; k++) {
    if (!hunkMarks[k]) {
      if (!lastWasHunkBreak) {
        html += `<div class="diff-line hunk"><span class="ln"></span><span class="marker">⋯</span> </div>`;
        lastWasHunkBreak = true;
      }
      continue;
    }
    lastWasHunkBreak = false;
    const op = ops[k];
    const cls = op.type;
    const marker = op.type === 'add' ? '+' : op.type === 'del' ? '-' : ' ';
    const lineNo = op.type === 'add' ? op.bl : op.type === 'del' ? op.al : op.al;
    html += `<div class="diff-line ${cls}"><span class="ln">${lineNo || ''}</span><span class="marker">${marker}</span>${escHtml(op.line)}</div>`;
  }
  html += '</div>';
  return html;
}

// ─── v2.2.1: Home dashboard ─────────────────────────────────────────────
//
// Composes a "fleet at a glance" summary from existing endpoints —
// devices, drift, CVEs, patches, webhook log. No new server endpoint
// needed. Refresh implicit (re-runs on every visit to the page).

// v2.9.1: module-scope so audit drawer and activity feed share the same map
const EVENT_CLASS = {
  'device_offline': 'critical', 'device_online': 'ok',
  'monitor_down': 'critical', 'monitor_up': 'ok',
  'service_down': 'critical', 'service_up': 'ok',
  'cve_found': 'warn', 'patch_alert': 'warn',
  'drift_detected': 'warn',
  'metric_warning': 'warn', 'metric_critical': 'critical',
  'metric_recovered': 'ok',
  'container_stopped': 'warn', 'container_restarting': 'warn',
  'containers_stale': 'warn',
  'log_alert': 'warn',
  'mailbox_threshold': 'warn',
  'command_queued': 'info', 'command_executed': 'info',
  'brute_force_detected': 'critical', 'ssh_key_added': 'warn',
  'new_port_detected': 'warn', 'backup_stale': 'warn',
  'tls_expiry': 'warn', 'snapshot_old': 'warn',
  'reboot_required': 'warn', 'custom_script_fail': 'critical',
  'custom_script_recover': 'ok', 'config_drift': 'warn',
};

async function loadHome() {
  // v3.3.0: was 7 parallel /api/* requests per 60s refresh — under CGI
  // that's 7 fresh Python processes per dashboard tick per operator.
  // /api/home bundles devices (slim), drift summary, CVE counts, fleet
  // events, mailwatch, links, attention digest, and the handful of
  // config flags Home actually reads, into one round-trip.
  const home = await api('GET', '/home').catch(() => null);
  if (!home) {
    _renderHomeTiles([], {}, {}, {});
    return;
  }
  const devs        = home.devices      || [];
  const drift       = home.drift        || {};
  const cves        = home.cves         || {};
  const fleetEvents = home.fleet_events || [];
  const mailwatch   = home.mailwatch    || {};
  const linksResp   = {links: home.links || []};
  // The attention payload is embedded so _renderHomeAttention can use
  // it directly without re-fetching /api/attention.
  _renderHomeTiles(devs, drift, cves, mailwatch);
  _renderHomeAttention(home.attention);
  _renderHomeActivity(fleetEvents);
  _renderHomeFleet(devs);
  _renderHomeLinks(linksResp.links);
}

function _renderHomeLinks(links) {
  const card = document.getElementById('home-links');
  const body = document.getElementById('home-links-body');
  if (!card || !body) return;
  if (!links.length) {
    card.classList.add('d-none');
    return;
  }
  card.classList.remove('d-none');

  // Compact grid: group by category, show title + hostname
  const byCat = {};
  for (const l of links) {
    const cat = l.category || 'Other';
    (byCat[cat] = byCat[cat] || []).push(l);
  }
  const cats = Object.keys(byCat).sort((a, b) => {
    if (a === 'Uncategorised') return 1;
    if (b === 'Uncategorised') return -1;
    return a.toLowerCase().localeCompare(b.toLowerCase());
  });

  body.innerHTML = cats.map(cat => {
    const items = byCat[cat];
    const cards = items.map(l => {
      const isInternal = l.scope === 'internal';
      const borderColor = isInternal ? 'var(--amber)' : 'var(--accent)';
      const borderStyle = isInternal ? 'dashed' : 'solid';
      let displayHost = l.url;
      try { displayHost = new URL(l.url).hostname; } catch (e) { /* keep full url */ }
      return `<a href="${escHtml(l.url)}" target="_blank" rel="noopener noreferrer" class="isl-763">
        <div class="isl-764" data-bd-style="${borderStyle}" data-bd-color="${borderColor}" title="${escHtml(l.description || l.url)}">
          <div class="isl-765">${escHtml(l.title)}</div>
          <div class="isl-766">${escHtml(displayHost)}</div>
        </div>
      </a>`;
    }).join('');
    return `<div class="isl-767">
      <div class="isl-768">${escHtml(cat)}</div>
      <div class="isl-769">${cards}</div>
    </div>`;
  }).join('');
}

function _renderHomeTiles(devs, drift, cves, mailwatch) {
  const target = document.getElementById('home-tiles');
  if (!target) return;
  // The "Devices online" tile counts only monitored devices — a
  // device set to monitored:false is silenced everywhere else (the
  // attention digest, the alert pipeline, the fleet roster), so an
  // unmonitored host must not inflate the fleet count or be reported
  // as "offline" here either.
  const counted = devs.filter(d => d.monitored !== false);
  const total = counted.length;
  const online = counted.filter(d => d.online).length;
  const offline = total - online;
  let pending = 0, criticalPending = 0;
  // v3.0.2: iterate `counted` (monitored only), not `devs`. Pending updates
  // tile should reflect what an operator actually needs to act on —
  // unmonitored devices (decommissioning, broken, migration in progress)
  // are explicitly silenced and shouldn't inflate the badge.
  counted.forEach(d => {
    const u = (d.sysinfo && d.sysinfo.packages && d.sysinfo.packages.upgradable) || 0;
    pending += u;
    if (u >= 20) criticalPending++;
  });
  const driftDevs = (drift.devices || []);
  // v3.0.2: dashboard tiles only report monitored devices. Backend returns
  // all of them (the Drift / CVE pages need the full list with explicit
  // markers), so we filter here. Build a Set of monitored ids once.
  const monitoredIds = new Set(counted.map(d => d.id));
  const driftDevsMon = driftDevs.filter(d => monitoredIds.has(d.device_id));
  const driftedFiles = driftDevsMon.reduce((s, d) => s + (d.drifted || 0), 0);
  // CVE tile: critical count is the headline; high is the sub-label.
  // Medium and low are shown only in the detail page — too noisy here.
  const cveDevsMon = ((cves && cves.devices) || []).filter(d => monitoredIds.has(d.device_id));
  // Recompute the summary from monitored devices only — backend's
  // `cves.summary` aggregates the whole fleet.
  const cveSummary = cveDevsMon.reduce((acc, d) => {
    const c = d.counts || {};
    acc.critical += c.critical || 0;
    acc.high     += c.high     || 0;
    acc.medium   += c.medium   || 0;
    acc.low      += c.low      || 0;
    return acc;
  }, {critical: 0, high: 0, medium: 0, low: 0});
  const criticalCves = cveSummary.critical || 0;
  const highCves     = cveSummary.high     || 0;
  const totalCves    = criticalCves + highCves +
                       (cveSummary.medium || 0) + (cveSummary.low || 0);

  const tiles = [
    {
      label: 'Devices online',
      value: `${online}<span class="isl-552"> / ${total}</span>`,
      sub: offline === 0 ? 'All devices reporting in' :
           offline === 1 ? '1 device offline' : `${offline} devices offline`,
      cls: offline > 0 ? 'warn' : 'ok',
    },
    {
      label: 'Pending updates',
      value: pending,
      sub: criticalPending > 0
        ? `${criticalPending} device${criticalPending === 1 ? '' : 's'} with 20+ pending`
        : pending === 0 ? 'Fleet fully patched' : 'Across monitored devices',
      cls: criticalPending > 0 ? 'warn' : pending === 0 ? 'ok' : '',
    },
    {
      label: 'Drift events',
      value: driftedFiles,
      sub: driftedFiles === 0
        ? 'All watched files at baseline'
        : `${driftDevsMon.filter(d => d.drifted > 0).length} device${driftDevsMon.filter(d => d.drifted > 0).length === 1 ? '' : 's'} affected`,
      cls: driftedFiles > 0 ? 'warn' : 'ok',
    },
    {
      label: 'Critical CVEs',
      value: criticalCves,
      sub: criticalCves > 0
        ? `${highCves} high · ${totalCves - criticalCves - highCves} med/low`
        : highCves > 0
          ? `${highCves} high · ${totalCves - highCves} med/low`
          : totalCves > 0 ? `${totalCves} total (med/low only)` : 'No active CVEs',
      cls: criticalCves > 0 ? 'alert' : highCves > 0 ? 'warn' : 'ok',
    },
  ];

  // v2.4.4: mailbox monitor tile — same style/size as the others.
  // Only added when at least one device is promoted to the dashboard.
  const mwDevs = ((mailwatch && mailwatch.devices) || []).filter(d => d.dashboard);
  if (mwDevs.length) {
    let unread = 0, reported = 0, mailboxes = 0;
    mwDevs.forEach(d => {
      const counts = d.counts || {};
      const paths = Object.keys(counts);
      mailboxes += paths.length || (d.paths || []).length;
      paths.forEach(p => {
        const c = counts[p];
        if (c && typeof c.count === 'number') { unread += c.count; reported++; }
      });
    });
    tiles.push({
      label: 'Unread mail',
      value: reported ? unread : '—',
      sub: !reported
        ? 'Waiting for first agent report'
        : `Across ${mailboxes} mailbox${mailboxes === 1 ? '' : 'es'}`,
      cls: '',
    });
  }

  target.innerHTML = tiles.map(t =>
    `<div class="tile ${t.cls}">
      <div class="tile-label">${t.label}</div>
      <div class="tile-value">${t.value}</div>
      <div class="tile-subtle">${t.sub}</div>
    </div>`
  ).join('');
}

// v2.4.7: the Needs Attention digest is now computed server-side by
// /api/attention — one source of truth, and it includes signals the
// old client-side version missed (CVE findings, mailbox threshold
// breaches) on top of offline devices, patch pileups and drift.
async function _renderHomeAttention(preloaded) {
  const target = document.getElementById('home-attention');
  if (!target) return;
  // v3.3.0: when loadHome() passes the attention payload in directly
  // (bundled with /api/home), skip the extra /api/attention round-trip.
  let data = preloaded;
  if (!data) {
    try {
      data = await api('GET', '/attention');
    } catch (e) {
      target.innerHTML = '<div class="empty-state isl-553">'
        + '<div class="empty-state-body">Could not load the digest.</div></div>';
      return;
    }
  }
  const items = (data && data.items) || [];
  if (!items.length) {
    target.innerHTML = `<div class="empty-state isl-553">
      <div class="empty-state-icon">✓</div>
      <div class="empty-state-title">All clear</div>
      <div class="empty-state-body">No offline monitored devices, no critical CVE
      findings, no patch backlog, no drift, no mailbox alerts.</div>
    </div>`;
    return;
  }
  // Map a digest item kind → the page to jump to when clicked.
  // The page name must match a `page-<name>` element id — the CVE
  // page is `cve`, not `cves` (this mismatch sent clicks to a blank
  // page in 2.4.7–2.4.11).
  const PAGE_FOR = {
    offline: 'devices', patches: 'patches', cve: 'cve',
    drift: 'drift', mailbox: 'devices',
    // v3.0.1 attention audit: route new kinds to sensible pages
    service_down:       'devices',   // device drawer shows services
    monitor_down:       'monitor',
    custom_script_fail: 'monitor',   // custom scripts live on Monitor page
    backup:             'devices',
    snapshot:           'devices',
    brute_force:        'devices',
    reboot:             'devices',
    disk:               'devices',
    tls:                'tls',
    agent_version:      'devices',
    // v3.0.1 iteration 3: transient critical events from fleet_events
    log_alert:          'logs',      // jump to Logs page to see the matches
    new_port:           'devices',   // device drawer has the port baseline
    ssh_key:            'devices',
    // v3.0.2: new NA kinds — surface metric thresholds (memory/swap/cpu)
    // and container state, parallel to disk above. ACME failures route
    // to the TLS section where the acme.sh table lives.
    memory:             'devices',
    swap:               'devices',
    cpu:                'devices',
    container:          'containers',
    acme:               'tls',
  };
  const PILL = {critical: 'critical', warning: 'warn', info: 'info'};
  target.innerHTML = items.slice(0, 10).map(i => {
    const page = PAGE_FOR[i.kind] || 'home';
    const pill = PILL[i.severity] || 'info';
    const key  = i._ignore_key || '';
    const lbl  = `${i.device} — ${i.summary}`;
    // v3.0.1: show an Investigate button when server reported a mitigation_kind
    const mitBtn = (i.mitigation_kind && i.device_id) ?
      `<button class="btn-icon isl-554" title="Investigate with diagnostic + AI suggestion"
         data-action="openMitigateModal" data-stop-prop="1" data-arg="${escAttr(i.device_id)}" data-arg2="${escAttr(i.mitigation_kind)}" data-arg3="${escAttr(i.mitigation_target || '')}" data-arg4="${escAttr(i.device)}">${_icon('search',14)}</button>` : '';
    // v3.2.3: for log_alert cards, expose all captured sample lines +
    // the rule pattern in a hover tooltip. The summary itself already
    // shows sample[0] truncated; the tooltip lets the operator see the
    // full match set without leaving the dashboard.
    let cardTitle = 'Click for details';
    if (i.kind === 'log_alert' && Array.isArray(i.samples) && i.samples.length) {
      const sampleList = i.samples.map((s, n) => `${n + 1}. ${s}`).join('\n');
      cardTitle = `Pattern: ${i.pattern || '(unknown)'}\n\nMatches:\n${sampleList}`;
    }
    // v3.2.3 (#4) / v3.3.0 icon refresh: inline actions are SVG now
    // — the prior emoji set looked AI-ratchet next to the sidebar
    // SVGs. snoozeBtn = bell-off (Lucide); logsBtn = file-text. ×
    // remains text for the permanent-ignore button (different
    // weight, intentional).
    const snoozeIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M8.7 3A6 6 0 0 1 18 8a21.3 21.3 0 0 0 .6 5"/><path d="M17 17H3s3-2 3-9a4.67 4.67 0 0 1 .3-1.7"/><path d="M9 17v1a3 3 0 0 0 6 0v-1"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    const logsIcon   = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>';
    const snoozeBtn = key
      ? `<button class="btn-icon isl-556" title="Snooze for 24h (returns automatically)" data-stop-prop="1" data-action="snoozeAttention" data-arg="${escAttr(key)}" data-arg2="${escAttr(lbl)}" >${snoozeIcon}</button>`
      : '';
    const logsBtn = (i.kind === 'log_alert' && i.device_id)
      ? `<button class="btn-icon isl-556" title="Open Logs filtered to this device + unit" data-stop-prop="1" data-action="openLogsForLogAlert" data-arg="${escAttr(i.device_id)}" data-arg2="${escAttr(i.unit || '')}" >${logsIcon}</button>`
      : '';
    return `<div class="dash-feed-item isl-156" title="${escAttr(cardTitle)}">
      <div
           data-action-btn="_showPageBtn" data-page="${page}" class="isl-555">
        <span class="status-pill ${pill}">${escHtml(i.kind)}</span>
        <strong>${escHtml(i.device)}</strong> — ${escHtml(i.summary)}
      </div>
      ${mitBtn}
      ${logsBtn}
      ${snoozeBtn}
      <button class="btn-icon isl-556" title="Ignore this alert permanently (review later in Settings → Ignored items)" data-stop-prop="1" data-action="ignoreAttention" data-arg="${escAttr(key)}" data-arg2="${escAttr(lbl)}" >×</button>
    </div>`;
  }).join('');
}

async function ignoreAttention(key, label) {
  if (!key) return;
  const r = await api('POST', '/ignored', { category: 'needs_attention', key, label });
  if (r?.ok) {
    toast('Hidden from Needs Attention', 'success');
    _renderHomeAttention();
  } else {
    toast(r?.error || 'Failed', 'error');
  }
}

// v3.2.3 (#4): snooze for 24h — server stores expires_at, the alert
// returns automatically when the snooze expires. Same endpoint as
// permanent ignore; the absence of expires_at is what makes × permanent.
async function snoozeAttention(key, label) {
  if (!key) return;
  const expires_at = Math.floor(Date.now() / 1000) + 86400;
  const r = await api('POST', '/ignored', {
    category: 'needs_attention', key, label, expires_at,
  });
  if (r?.ok) {
    toast('Snoozed for 24h', 'success');
    _renderHomeAttention();
  } else {
    toast(r?.error || 'Failed', 'error');
  }
}

// v3.2.3 (#4): jump to Logs page with device + unit filters pre-set.
// Builds on openLogsForDevice() — same poll-for-options pattern.
function openLogsForLogAlert(devId, unit) {
  const navBtn = document.querySelector('.nav-btn[data-page="logs"]');
  if (navBtn) showPage('logs', navBtn); else return;
  setTimeout(() => {
    const devSel = document.getElementById('logs-device-filter');
    const unitSel = document.getElementById('logs-unit-filter');
    if (!devSel) return;
    let attempts = 0;
    const tryApply = () => {
      attempts++;
      const devOpt = Array.from(devSel.options).find(o => o.value === devId);
      if (devOpt) {
        devSel.value = devId;
        if (unitSel && unit) {
          const unitOpt = Array.from(unitSel.options).find(o => o.value === unit);
          if (unitOpt) unitSel.value = unit;
        }
        if (typeof onLogFilterChange === 'function') onLogFilterChange();
      } else if (attempts < 12) {
        setTimeout(tryApply, 150);
      }
    };
    tryApply();
  }, 100);
}

let _activityClearedAt = parseInt(sessionStorage.getItem('rp_activity_cleared') || '0', 10);

function clearHomeActivity() {
  _activityClearedAt = Math.floor(Date.now() / 1000);
  sessionStorage.setItem('rp_activity_cleared', String(_activityClearedAt));
  const target = document.getElementById('home-activity');
  if (target) target.innerHTML = `<div class="empty-state isl-553">
    <div class="empty-state-icon">○</div>
    <div class="empty-state-title">Activity cleared</div>
    <div class="empty-state-body">New fleet events will appear here as they fire.</div>
  </div>`;
}

function _renderHomeActivity(fleetEvents) {
  const target = document.getElementById('home-activity');
  if (!target) return;
  // v2.2.4: fleet event log payload shape is {ts, event, payload: {…}}
  // — server returns a flat list newest-first. The /fleet/events
  // endpoint filters out 'test' events already (test events aren't
  // recorded in the fleet log at all), but we keep the FLEET_EVENTS
  // allowlist for defence-in-depth + so a future event added on the
  // server doesn't silently appear without dashboard recognition.
  const FLEET_EVENTS = new Set([
    'device_offline', 'device_online',
    'monitor_down', 'monitor_up',
    'patch_alert', 'cve_found',
    'service_down', 'service_up',
    'log_alert',
    'container_stopped', 'container_restarting', 'containers_stale',
    'metric_warning', 'metric_critical', 'metric_recovered',
    'command_queued', 'command_executed',
    'drift_detected', 'mailbox_threshold', 'custom_script_fail', 'custom_script_recover',
    'config_drift', 'tls_expiry', 'reboot_required', 'snapshot_old',
    'new_port_detected', 'ssh_key_added', 'brute_force_detected', 'backup_stale',
    // v3.2.0 (B5): SNMP polling state transitions
    'snmp_unreachable', 'snmp_dead', 'snmp_recover',
    // v3.2.0 (A1 follow-up): silent MCP confirmation timeout
    'mcp_confirmation_expired',
    // v3.4.0: hardware health
    'smart_failure', 'kernel_outdated',
  ]);
  let entries = [];
  if (Array.isArray(fleetEvents)) {
    entries = fleetEvents;
  } else if (fleetEvents && Array.isArray(fleetEvents.events)) {
    entries = fleetEvents.events;
  }
  // Filter then de-duplicate then slice — order matters.
  //  - filter first so unrecognised events don't occupy a slot.
  //  - v2.4.8: de-duplicate before slicing. A noisy host (e.g. a
  //    postfix unit throwing the same log_alert every hour) would
  //    otherwise fill all 8 rows with the same entry and bury every
  //    other host. We collapse repeated entries that share the same
  //    (event, host, subject) to their single most-recent occurrence
  //    — entries arrive newest-first, so the first one kept is the
  //    latest. This is a DISPLAY concern only: the server fleet event
  //    log still records every individual event for the audit trail;
  //    this just keeps the dashboard feed readable.
  //  - slice last, so the feed shows 8 *distinct* recent things.
  const _seenActivity = new Set();
  entries = entries
    .filter(e => !_activityClearedAt || (e.ts || 0) > _activityClearedAt)
    .filter(e => FLEET_EVENTS.has(e.event))
    .filter(e => {
      const p = e.payload || {};
      const host = p.device_id || p.device_name || p.name || p.host || '';
      // The subject is whatever identifies the specific thing the
      // event is about — the same fields the row renderer shows.
      const subject = p.path || p.unit || p.metric || p.cve_id
                      || p.pattern || p.command || '';
      const key = `${e.event}|${host}|${subject}`;
      if (_seenActivity.has(key)) return false;
      _seenActivity.add(key);
      return true;
    })
    .slice(0, 8);
  if (entries.length === 0) {
    target.innerHTML = `<div class="empty-state isl-553">
      <div class="empty-state-icon">○</div>
      <div class="empty-state-title">No recent fleet events</div>
      <div class="empty-state-body">Fleet events (device offline, drift detected, CVE found, etc.) show up here as they fire — regardless of whether any webhook or email destination is configured.</div>
    </div>`;
    return;
  }
  // EVENT_CLASS is now module-scope (v2.9.1)
  target.innerHTML = entries.map(ev => {
    const ts = ev.ts ? timeAgo(ev.ts) : '—';
    const cls = EVENT_CLASS[ev.event] || 'info';
    const label = (ev.event || '').replace(/_/g, ' ');
    const p = ev.payload || {};
    const dev = p.device_name || p.name || p.host || '';
    // v2.8.1: show rich detail for security and monitoring events
    let detail = '';
    switch (ev.event) {
      case 'brute_force_detected':
        if (p.source_ip && p.count) {
          detail = `${p.count} failed attempts from ${p.source_ip} on ${p.unit || 'ssh'}`;
        } else if (p.unit) {
          detail = `suspicious activity on ${p.unit}`;
        } else {
          detail = 'failed login attempts detected';
        }
        break;
      case 'ssh_key_added':
        detail = `${p.user}: ${p.fingerprint||'new key'}`; break;
      case 'new_port_detected':
        detail = `${p.proto||'tcp'}/${p.port}${p.process ? ` (${p.process})` : ''}`; break;
      case 'backup_stale':
        detail = `"${p.label||p.path}" ${p.age_hours ? `${p.age_hours}h old` : 'missing'}`; break;
      case 'tls_expiry':
        detail = `${p.host}: ${p.days_left}d left`; break;
      case 'snapshot_old':
        detail = `${p.vm_name}: "${p.snap_name}" ${p.days_old}d old`; break;
      case 'log_alert':
        // Show the actual matched log line, not the pattern regex
        detail = (p.sample && p.sample[0])
          ? `${p.unit}: ${String(p.sample[0]).substring(0, 100)}`
          : `${p.unit}: ${p.count || 1} match(es)`; break;
      case 'drift_detected':
        detail = p.path || p.unit || ''; break;
      case 'config_drift':
        detail = (p.sections||[]).slice(0,3).join(', '); break;
      default:
        detail = p.path || p.unit || p.metric || p.cve_id || p.pattern || '';
        if (!detail && p.upgradable) detail = `${p.upgradable} updates`;
        if (!detail && p.critical)   detail = `${p.critical} critical`;
    }
    const actAttrs = _homeActivityAttrs(ev.event, p);
    return `<div class="dash-feed-item pointer" data-action-btn="_homeNavAction" ${actAttrs} title="Click for details">
      <div class="flex-1"><span class="status-pill ${cls}">${escHtml(label)}</span> ${dev ? `<strong>${escHtml(dev)}</strong>` : ''} ${detail ? `<span class="hint">${escHtml(String(detail).substring(0,80))}</span>` : ''}</div>
      <span class="ts">${ts}</span>
    </div>`;
  }).join('');
}

// v2.2.5 (CSP L1 refactor): returns data-attribute string for _homeNavAction.
function _homeActivityAttrs(event, p) {
  const devId   = escAttr(p.device_id || '');
  const devName = escAttr(p.device_name || p.host || '');
  const base = `data-dev-id="${devId}" data-dev-name="${devName}"`;
  switch (event) {
    case 'device_offline': case 'device_online':
    case 'mailbox_threshold': case 'reboot_required':
    case 'new_port_detected': case 'ssh_key_added':
    case 'brute_force_detected': case 'backup_stale':
      return `${base} data-home-act="${devId ? 'detail' : 'devices'}"`;
    case 'drift_detected':
      return `${base} data-home-act="drift"`;
    case 'cve_found':      return `${base} data-home-act="cve"`;
    case 'patch_alert':    return `${base} data-home-act="patches"`;
    case 'monitor_down':   case 'monitor_up':
    case 'metric_warning': case 'metric_critical': case 'metric_recovered':
    case 'custom_script_fail': case 'custom_script_recover':
      return `${base} data-home-act="monitor"`;
    case 'service_down':   case 'service_up':
      return `${base} data-home-act="services"`;
    case 'container_stopped': case 'container_restarting': case 'containers_stale':
      return `${base} data-home-act="containers"`;
    case 'log_alert':      return `${base} data-home-act="logs"`;
    case 'command_queued': case 'command_executed':
      return `${base} data-home-act="history"`;
    case 'config_drift':   return `${base} data-home-act="devices"`;
    case 'tls_expiry':     return `${base} data-home-act="tls"`;
    case 'snapshot_old':   return `${base} data-home-act="virtualization"`;
    case 'snmp_unreachable': case 'snmp_dead': case 'snmp_recover':
      // SNMP events surface on agentless device cards; clicking opens the
      // device drawer if we have an id, else routes to Devices.
      return `${base} data-home-act="${devId ? 'detail' : 'devices'}"`;
    case 'mcp_confirmation_expired':
      // Click → MCP Confirmations admin page so the operator can see
      // what timed out
      return `${base} data-home-act="confirmations"`;
    case 'smart_failure': case 'kernel_outdated':
      // v3.4.0: hardware-health alerts → device drawer (Health & Hardware)
      return `${base} data-home-act="${devId ? 'detail' : 'devices'}"`;
    default:
      return `${base} data-home-act="${devId ? 'detail' : ''}"`;
  }
}

async function _renderHomeFleet(devs) {
  const target = document.getElementById('home-fleet');
  if (!target) return;
  // Only monitored devices belong in the roster — a device set to
  // monitored:false is silenced everywhere else (attention digest,
  // alert pipeline), so it must not appear here either. The server's
  // /fleet/uptime7d already excludes them; this drops their rows too.
  devs = (devs || []).filter(d => d.monitored !== false);
  if (devs.length === 0) {
    target.innerHTML = `<div class="empty-state isl-553">
      <div class="empty-state-icon">${_icon('package',32)}</div>
      <div class="empty-state-title">No devices enrolled yet</div>
      <div class="empty-state-body">Once you enroll your first device, you'll see its 7-day status stripe here.</div>
    </div>`;
    return;
  }
  // v2.4.10: the 7-day stripe is now real — derived server-side from
  // uptime.json transition events. Before this it was hardcoded to
  // six 'unknown' cells plus today. Days RemotePower genuinely has no
  // record for still show 'unknown' (honest — history only builds up
  // from when uptime recording works; it cannot be known
  // retroactively), but real up/down now shows once data exists.
  let uptime = {};
  try {
    const r = await api('GET', '/fleet/uptime7d');
    uptime = (r && r.uptime) || {};
  } catch (e) { /* fall back to today-only below */ }

  target.innerHTML = devs.slice(0, 30).map(d => {
    const todayCell = d.online ? 'up' : 'down';
    // Use the server's 7-day array when present; otherwise show six
    // 'unknown' cells + today, the honest fallback.
    let history = uptime[d.id];
    if (!Array.isArray(history) || history.length !== 7) {
      history = ['unknown','unknown','unknown','unknown','unknown','unknown', todayCell];
    } else {
      // The server array's last cell is "today by recorded events";
      // the device's live online flag is fresher — trust it for today.
      history = history.slice(0, 6).concat([todayCell]);
    }
    return `<div class="isl-557">
      <div class="isl-558">
        ${getDistroIcon(d.os)}
        <a href="#" data-action="openDeviceDrawer" data-arg="${d.id}" data-arg2="${escAttr(d.name)}" data-arg3="audit" data-prevent-default class="isl-559">${escHtml(d.name)}</a>
        ${d.group ? `<span class="meta-sm-nm">${escHtml(d.group)}</span>` : ''}
      </div>
      <div>${renderStatusStripe(history)}</div>
      <div class="isl-560">
        ${d.online ? '<span class="c-green">● online</span>' : '<span class="c-red">● offline</span>'}
      </div>
    </div>`;
  }).join('');
}

// ─── v2.2.1: AIidentity extension ──────────────────────────────────────
//
// Stamps every AIbutton across the app with the .ai-btn class plus a
// provider-tinted variant (`.available` for cloud providers, `.local`
// for Ollama/LocalAI). The CSS adds a subtle animated glow.
//
// Cache the AI config so we don't fetch on every render; refresh once
// per app session, and on settings save.

window._aiConfigCache = null;

async function _getAiConfigCached() {
  if (window._aiConfigCache !== null) return window._aiConfigCache;
  try {
    const cfg = await api('GET', '/ai/config');
    if (cfg && cfg.enabled && cfg.provider) {
      // Local providers: ollama, localai, lmstudio, anything with a base_url
      // pointing to 127.0.0.1 / 10.* / 192.168.* / local hostnames.
      const provider = (cfg.provider || '').toLowerCase();
      const url = (cfg.base_url || '').toLowerCase();
      const isLocal = ['ollama', 'localai', 'lmstudio', 'llama.cpp'].includes(provider) ||
                      /127\.0\.0\.1|localhost|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\./.test(url);
      window._aiConfigCache = {enabled: true, isLocal};
    } else {
      window._aiConfigCache = {enabled: false, isLocal: false};
    }
  } catch (e) {
    window._aiConfigCache = {enabled: false, isLocal: false};
  }
  return window._aiConfigCache;
}

async function applyAiIdentity() {
  const cfg = await _getAiConfigCached();
  if (!cfg.enabled) return;
  // v3.3.0: was a text.indexOf('AI') sniff. Emoji are gone from the UI,
  // so we detect AI buttons by the action name pattern instead. Every
  // AI button's data-action / data-action-btn starts with "ai" or
  // contains "aiExplain" / "aiTriage" / "aiPrioritise" / etc., or
  // explicitly carries data-ai-btn="1". Idempotent — adding a class
  // twice is a no-op.
  const AI_ACTION_RX = /^(ai[A-Z]|_ai[A-Z]|scriptEditorAI|aiGenerateRunbook|aiInvestigate|aiViewRunbook|testAIConnection|csGenerateWithAI)/;
  document.querySelectorAll('button, .btn-icon').forEach(btn => {
    const act = btn.dataset.action || btn.dataset.actionBtn || '';
    if (btn.dataset.aiBtn === '1' || AI_ACTION_RX.test(act)) {
      btn.classList.add('ai-btn');
      btn.classList.add(cfg.isLocal ? 'local' : 'available');
    }
  });
}

// Hook into MutationObserver so any newly rendered content gets the
// treatment without callers having to remember to call applyAiIdentity.
// Throttled: at most once per 400ms, since renders can be bursty.
(function _setupAiIdentityObserver() {
  let pending = false;
  const trigger = () => {
    if (pending) return;
    pending = true;
    setTimeout(() => {
      pending = false;
      applyAiIdentity().catch(() => {});
    }, 400);
  };
  // Wait for DOM ready before attaching the observer
  const attach = () => {
    if (document.readyState !== 'loading' && document.body) {
      new MutationObserver(trigger).observe(document.body, {
        childList: true, subtree: true,
      });
      // Initial application
      applyAiIdentity().catch(() => {});
    } else {
      setTimeout(attach, 50);
    }
  };
  attach();
})();

// Helper: render the three-sparkle "thinking" indicator for AI loading
// states. Replaces the generic spinner in AI-aware modals.
function aiThinkingHtml() {
  // v3.3.0: emoji sparkle replaced with three pulsing dots that animate
  // via existing .sparkle-dot CSS (defined alongside .sparkle's
  // animation, fallback works without the CSS update).
  return '<span class="ai-thinking"><span class="sparkle">·</span><span class="sparkle">·</span><span class="sparkle">·</span></span>';
}

// ─── v2.2.1: helper used by per-row hover affordances ───────────────────
//
// "Logs" hover action: navigate to the Logs page, pre-set the device
// filter dropdown to the clicked device, and trigger a load. Falls
// back to opening the detail modal if the Logs page or filter aren't
// in the DOM (older HTML).

function openLogsForDevice(devId, devName) {
  // Click the Logs nav button so showPage's sidebar-expand logic fires
  const navBtn = document.querySelector('.nav-btn[data-page=\"logs\\"]');
  if (navBtn) {
    showPage('logs', navBtn);
  } else {
    // Fallback — open detail modal which shows journal too
    openDetail(devId, devName);
    return;
  }
  // Wait for the page to mount, then set the device filter to this device
  setTimeout(() => {
    const sel = document.getElementById('logs-device-filter');
    if (sel) {
      // The select is populated by enterLogsPage(); it may not have
      // the option yet on first paint. Poll briefly.
      let attempts = 0;
      const tryApply = () => {
        attempts++;
        const opt = Array.from(sel.options).find(o => o.value === devId);
        if (opt) {
          sel.value = devId;
          if (typeof onLogFilterChange === 'function') onLogFilterChange();
        } else if (attempts < 12) {
          setTimeout(tryApply, 150);
        }
      };
      tryApply();
    }
  }, 100);
}

// ─── v2.2.1: mobile nav burger toggle ───────────────────────────────────
//
// Mobile (<720px) hides the sidebar by default and reveals it via the
// burger button in the header. Toggle adds/removes a class on body;
// CSS handles the slide-in animation and the dimmed overlay.

function toggleMobileNav() {
  document.body.classList.toggle('mobile-nav-open');
}

// Closing on any nav-btn click — once you've picked a destination, the
// sidebar should get out of the way. Listen at document level so the
// hookup survives sidebar re-renders.
//
// v3.0.4 fix: previously the "tap outside to close" path required
// `e.target === document.body`, which only fired when the click bubbled
// up with body itself as target. With the scrim (`body::after`) catching
// pointer events at z-index 800, the actual target on mobile Chrome /
// PWA tended to be the underlying `<div id="app">` or `.app-content`
// instead. Result: collapse silently broken — only the nav-button-click
// close path worked. Burger-to-collapse also broken because the burger
// sits behind the scrim (header z-index 100 < scrim 800), so the
// burger's own onclick never fires when the drawer is open.
//
// New logic: when the drawer is open, ANY click that doesn't land inside
// the sidebar or on the burger closes the drawer. Robust to scrim
// targeting quirks, and the burger's now closed via this same path
// (since taps over the burger position hit the scrim, not the button).
document.addEventListener('click', e => {
  if (!document.body.classList.contains('mobile-nav-open')) return;

  // Tap on a nav button → close (and let the navigation continue)
  if (e.target.closest('.nav-btn')) {
    document.body.classList.remove('mobile-nav-open');
    return;
  }

  // Tap anywhere inside the open drawer (but not on a nav button)
  // → leave it open. Useful so taps on the sidebar's header, search
  // box, or scrollbar don't dismiss the menu.
  if (e.target.closest('.sidebar')) return;

  // Tap directly on the burger button (drawer just opened — possible
  // only when the user opened it via the burger, since when the drawer
  // is open the scrim sits in front of the header and intercepts taps
  // at the burger's position). toggleMobileNav's onclick has already
  // run and toggled the class; without this guard we'd double-toggle
  // and the drawer would close on the same tap that opened it.
  if (e.target.closest('.mobile-burger')) return;

  // Mobile-only: anything else dismisses the drawer. This includes
  // the scrim area, the burger button's screen location (which is
  // behind the scrim when open, so taps there hit the scrim — not
  // the button — and the closest('.mobile-burger') check above fails
  // through to here), and any content area the scrim covers.
  if (window.innerWidth <= 720) {
    document.body.classList.remove('mobile-nav-open');
  }
});

// ─── v2.2.1: Drift diff modal ──────────────────────────────────────────
//
// Opens a sub-modal over the drift detail modal. Shows the actual
// difference between two captured snapshots of a watched file.
//
// Flow:
//   - openDriftDiff(devId, path) appends the modal to body, calls GET
//     /drift/content?path=... to retrieve any already-captured content.
//   - If there are 2 captures: render diff between them immediately.
//   - If there's 1: show it as "Captured baseline" + offer "Fetch current".
//   - If there are 0: offer "Fetch content" (queues exec:cat <path>).
//   - Polling after fetch: every 5s up to 60s for the agent to phone
//     home with the output. The agent's poll_interval (default 60s)
//     dictates the realistic wait time.

let _driftDiffModal = null;

function _ensureDriftDiffModal() {
  if (_driftDiffModal) return _driftDiffModal;
  const wrap = document.createElement('div');
  wrap.className = 'modal-overlay';
  wrap.id = 'drift-diff-modal';
  wrap.style.zIndex = '1100';  // v2.2.6: nested-modal tier — above the
                               // base drift detail modal (1000)
  wrap.innerHTML = `
    <div class="modal isl-561">
      <div class="modal-header row-between">
        <div>
          <div id="drift-diff-title" class="fw-600">Drift diff</div>
          <div id="drift-diff-path" class="isl-562"></div>
        </div>
        <button class="btn-icon isl-44" data-action="closeDriftDiff" >✕</button>
      </div>
      <div id="drift-diff-body" class="isl-538">
        <div class="c-muted">Loading…</div>
      </div>
      <div class="isl-529">
        <button class="btn-icon" id="drift-diff-fetch-btn" data-action="driftFetchCurrent" >Fetch current content</button>
        <span id="drift-diff-status" class="hint"></span>
        <div class="flex-1"></div>
        <button class="btn-icon" data-action="closeDriftDiff" >Close</button>
      </div>
    </div>`;
  document.body.appendChild(wrap);
  _driftDiffModal = wrap;
  return wrap;
}

let _driftDiffCurrent = null;
let _driftDiffPollHandle = null;

function closeDriftDiff() {
  if (_driftDiffModal) _driftDiffModal.classList.remove('active');
  if (_driftDiffPollHandle) {
    clearInterval(_driftDiffPollHandle);
    _driftDiffPollHandle = null;
  }
  _driftDiffCurrent = null;
}

async function openDriftDiff(devId, path) {
  _ensureDriftDiffModal();
  _driftDiffModal.classList.add('active');
  _driftDiffCurrent = {devId, path, startedAt: Date.now()};
  document.getElementById('drift-diff-title').textContent = 'Drift diff';
  document.getElementById('drift-diff-path').textContent = path;
  document.getElementById('drift-diff-status').textContent = '';
  document.getElementById('drift-diff-fetch-btn').disabled = false;
  await _refreshDriftDiff();
}

async function _refreshDriftDiff() {
  if (!_driftDiffCurrent) return;
  const {devId, path} = _driftDiffCurrent;
  const body = document.getElementById('drift-diff-body');
  try {
    const data = await api('GET',
      `/devices/${encodeURIComponent(devId)}/drift/content?path=${encodeURIComponent(path)}`);
    if (!data) {
      body.innerHTML = '<div class="c-red-p20">Failed to load captures.</div>';
      return;
    }
    if (data.denied) {
      body.innerHTML = `<div class="empty-state">
        <div class="empty-state-icon">${_icon('lock',32)}</div>
        <div class="empty-state-title">Content retrieval refused</div>
        <div class="empty-state-body">${escHtml(data.error || 'Path is on the drift-content denylist.')}</div>
      </div>`;
      document.getElementById('drift-diff-fetch-btn').style.display = 'none';
      return;
    }
    const captures = data.captures || [];
    if (captures.length === 0) {
      body.innerHTML = `<div class="empty-state">
        <div class="empty-state-icon">○</div>
        <div class="empty-state-title">No content captured yet</div>
        <div class="empty-state-body">
          Click <strong>Fetch current content</strong> to queue a <code>cat ${escHtml(path)}</code>
          command on the device. After the agent's next heartbeat (typically within
          ~60 seconds) the output arrives and is stored for the diff.
          <br><br>
          The first fetch becomes the baseline. A second fetch after another change
          will give you a real before/after diff.
        </div>
      </div>`;
    } else if (captures.length === 1) {
      const c = captures[0];
      const ts = new Date(c.ts * 1000).toLocaleString();
      body.innerHTML = `
        <div class="isl-563">
          One capture so far · ${ts} · rc=${c.rc} · ${c.sha256.substring(0, 27)}…
          <br>
          Fetch again after another change to see a diff between the two captures.
        </div>
        <div class="diff-view">${c.content.split('\n').map((l, i) =>
          `<div class="diff-line"><span class="ln">${i+1}</span><span class="marker"> </span>${escHtml(l)}</div>`
        ).join('')}</div>`;
    } else {
      // ≥2 captures — diff the newest two
      const newer = captures[captures.length - 1];
      const older = captures[captures.length - 2];
      const olderTs = new Date(older.ts * 1000).toLocaleString();
      const newerTs = new Date(newer.ts * 1000).toLocaleString();
      body.innerHTML = `
        <div class="isl-564">
          <div><span class="c-red">− Older</span> · ${olderTs} · rc=${older.rc}<br>
            <code class="fs-10">${older.sha256.substring(0, 27)}…</code></div>
          <div><span class="c-green">+ Newer</span> · ${newerTs} · rc=${newer.rc}<br>
            <code class="fs-10">${newer.sha256.substring(0, 27)}…</code></div>
        </div>
        ${renderDiff(older.content, newer.content)}`;
    }
  } catch (e) {
    body.innerHTML = `<div class="c-red-p20">Failed to load: ${escHtml(String(e))}</div>`;
  }
}

async function driftFetchCurrent() {
  if (!_driftDiffCurrent) return;
  const {devId, path} = _driftDiffCurrent;
  const fetchBtn = document.getElementById('drift-diff-fetch-btn');
  const status   = document.getElementById('drift-diff-status');
  fetchBtn.disabled = true;
  status.textContent = 'Queued — waiting for agent…';
  try {
    const resp = await api('POST',
      `/devices/${encodeURIComponent(devId)}/drift/fetch_content`,
      {paths: [path]});
    if (!resp || !resp.ok) {
      status.textContent = 'Failed to queue fetch';
      fetchBtn.disabled = false;
      return;
    }
    if ((resp.denied || []).includes(path)) {
      status.textContent = 'Denied: ' + path + ' is on the content denylist';
      fetchBtn.style.display = 'none';
      return;
    }
    if ((resp.not_watched || []).includes(path)) {
      status.textContent = 'Path is not in the watched-files list for this device';
      fetchBtn.disabled = false;
      return;
    }

    // Poll until we have a new capture (or 90 s elapses). 5 s
    // intervals — matches typical agent heartbeat granularity.
    const startCaptures = await _captureCount(devId, path);
    let attempts = 0;
    const maxAttempts = 18;   // 18 × 5 s = 90 s
    if (_driftDiffPollHandle) clearInterval(_driftDiffPollHandle);
    _driftDiffPollHandle = setInterval(async () => {
      attempts++;
      const now = await _captureCount(devId, path);
      if (now > startCaptures) {
        clearInterval(_driftDiffPollHandle);
        _driftDiffPollHandle = null;
        status.textContent = 'Captured ✓';
        fetchBtn.disabled = false;
        _refreshDriftDiff();
      } else if (attempts >= maxAttempts) {
        clearInterval(_driftDiffPollHandle);
        _driftDiffPollHandle = null;
        status.textContent = 'Timed out — agent did not phone home in 90 s. Try again.';
        fetchBtn.disabled = false;
      } else {
        status.textContent = `Queued — waiting for agent… (${attempts * 5}s)`;
      }
    }, 5000);
  } catch (e) {
    status.textContent = 'Error: ' + String(e);
    fetchBtn.disabled = false;
  }
}

async function _captureCount(devId, path) {
  try {
    const data = await api('GET',
      `/devices/${encodeURIComponent(devId)}/drift/content?path=${encodeURIComponent(path)}`);
    return (data && data.captures && data.captures.length) || 0;
  } catch (e) {
    return 0;
  }
}

// ─── v2.2.6: host health telemetry block (device detail modal) ──────────
//
// Renders the extra signals the agent started collecting in 2.2.6:
// reboot-required, failed systemd units, logged-in users, listening
// ports, last boot. Each section is omitted entirely if the agent
// didn't report it (older agent, or the probe failed on the host) —
// so an older agent's detail modal just looks like it did before.

function _renderHostHealth(si) {
  si = si || {};
  let html = '';

  // Reboot required — loud amber banner when true
  if (si.reboot_required === true) {
    const reason = si.reboot_reason
      ? ` <span class="meta-sm-nm">(${escHtml(si.reboot_reason)})</span>`
      : '';
    html += `<div class="isl-565">
      ⟳ <strong>Reboot required</strong>${reason}
    </div>`;
  }

  // Failed systemd units
  if (Array.isArray(si.failed_units) && si.failed_units.length) {
    html += `<div class="isl-566">
      <div class="isl-567">${si.failed_units.length} failed systemd unit${si.failed_units.length === 1 ? '' : 's'}</div>
      <div class="isl-562">${si.failed_units.map(u => escHtml(u)).join(', ')}</div>
    </div>`;
  }

  // Logged-in users + last boot — info pills
  const pills = [];
  if (Array.isArray(si.logged_in)) {
    pills.push(`<div class="sysinfo-pill"><div class="label">Logged in</div><div class="value">${si.logged_in.length ? si.logged_in.map(u => escHtml(u)).join(', ') : '—'}</div></div>`);
  }
  if (si.last_boot) {
    pills.push(`<div class="sysinfo-pill"><div class="label">Booted</div><div class="value fs-11">${new Date(si.last_boot * 1000).toLocaleString()}</div></div>`);
  }
  if (pills.length) {
    html += `<div class="sysinfo-row mb-14">${pills.join('')}</div>`;
  }

  // Listening ports — compact table
  if (Array.isArray(si.listening_ports) && si.listening_ports.length) {
    const rows = si.listening_ports.map(p =>
      `<tr>
        <td class="isl-568">${escHtml(p.proto)}</td>
        <td class="isl-569">${p.port}</td>
        <td class="meta-sm-nm">${escHtml(p.process || '—')}</td>
      </tr>`
    ).join('');
    html += `<details class="mb-14">
      <summary class="isl-570">
        Listening ports (${si.listening_ports.length})
      </summary>
      <div class="table-card isl-571">
        <table><thead><tr><th>Proto</th><th>Port</th><th>Process</th></tr></thead>
        <tbody>${rows}</tbody></table>
      </div>
    </details>`;
  }

  return html;
}

// ═══════════════════════════════════════════════════════════════════════
// v2.3.0 — Proxmox virtualization
//
// The Virtualization page lists QEMU VMs; LXC containers render as an
// extra section on the Containers page. Both come from the RemotePower
// server polling the Proxmox API (no agent on the Proxmox node).
// ═══════════════════════════════════════════════════════════════════════

// Show/hide the Virtualization nav entry based on whether Proxmox is
// configured. Called once at startup.
async function refreshProxmoxNav() {
  // v2.3.3: the Virtualization nav entry is now ALWAYS visible — it
  // used to be hidden until Proxmox was enabled, which was a
  // discoverability dead-end (you configure Proxmox in Settings, but
  // couldn't find the feature without the nav entry). The
  // Virtualization page itself handles the not-configured state with
  // a "configure it under Settings -> Proxmox" message. This function
  // is kept as a harmless no-op so existing call sites don't break.
}

// Render one guest (VM or LXC) as a card. `kind` is 'qemu' or 'lxc'
// and decides which action endpoint the buttons hit.
function _renderProxmoxGuest(g, kind) {
  const running = (g.status || '').toLowerCase() === 'running';
  const statusColor = running ? 'var(--green)'
                     : (g.status === 'paused' ? 'var(--amber)' : 'var(--muted)');
  // Resource line — only when the guest is running and reported values
  const res = [];
  if (g.cpu_percent != null) res.push(`CPU ${g.cpu_percent}%`);
  if (g.mem_percent != null) res.push(`MEM ${g.mem_percent}%`);
  const resLine = (running && res.length)
    ? `<div class="isl-572">${res.join('  ·  ')}</div>`
    : '';
  const upLine = (running && g.uptime)
    ? `<span class="meta-sm-nm">up ${_fmtDuration(g.uptime)}</span>`
    : '';
  // Actions: start when stopped, graceful shutdown when running.
  // `stop` (hard) is intentionally not exposed in the UI.
  const ep = kind === 'qemu' ? 'qemu' : 'lxc';
  const actions = `
    <div class="isl-458">
      ${!running ? `<button class="btn-icon badge-sm" data-action="proxmoxAction" data-arg="${ep}" data-arg2="${g.vmid}" data-arg3="start" data-arg4="${escAttr(g.name)}">Start</button>` : ''}
      ${running  ? `<button class="btn-icon isl-573" data-action="proxmoxAction" data-arg="${ep}" data-arg2="${g.vmid}" data-arg3="shutdown" data-arg4="${escAttr(g.name)}">Shutdown</button>` : ''}
      <button class="btn-icon badge-sm" data-action="openSnapshots" data-arg="${ep}" data-arg2="${g.vmid}" data-arg3="${escAttr(g.name)}">Snapshots</button>
    </div>`;
  return `<div class="isl-460">
    <div class="isl-461">
      <div class="fw-600">
        <span class="isl-574">${g.vmid}</span>
        ${escHtml(g.name)}
        ${g.tags ? `<span class="isl-575">${escHtml(g.tags)}</span>` : ''}
      </div>
      <div class="row-8-center">
        ${upLine}
        <span class="isl-576" data-color="${statusColor}">${escHtml(g.status || '?')}</span>
      </div>
    </div>
    ${resLine}
    ${actions}
  </div>`;
}

function _fmtDuration(secs) {
  secs = parseInt(secs, 10) || 0;
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

// Load + render the Virtualization page (QEMU VMs).
async function loadVirtualization() {
  const body = document.getElementById('virtualization-body');
  const nodeLabel = document.getElementById('virtualization-node');
  if (!body) return;
  body.innerHTML = '<div class="isl-507">Loading…</div>';
  let data;
  try {
    data = await api('GET', '/proxmox/qemu');
  } catch (e) {
    body.innerHTML = `<div class="table-card isl-577">
      Could not reach Proxmox: ${escHtml(e.message || String(e))}</div>`;
    return;
  }
  if (!data || !data.enabled) {
    body.innerHTML = `<div class="table-card isl-578">
      Proxmox integration is not enabled. Configure it under Settings → Proxmox.</div>`;
    return;
  }
  if (!data.configured) {
    body.innerHTML = `<div class="table-card isl-578">
      Proxmox is enabled but not fully configured. Add the host, node and API token under Settings → Proxmox.</div>`;
    return;
  }
  if (nodeLabel) nodeLabel.textContent = data.node ? `node: ${data.node}` : '';
  const guests = data.guests || [];
  if (!guests.length) {
    body.innerHTML = '<div class="table-card isl-578">No QEMU VMs on this node.</div>';
    return;
  }
  // v2.4.12: keep the fetched guests so the search box can filter
  // them client-side without re-hitting the Proxmox API.
  _virtGuests = guests;
  _renderVirtualizationList();
}

// Module-level cache of the last-fetched QEMU guests, for filtering.
let _virtGuests = [];

function _renderVirtualizationList() {
  const body = document.getElementById('virtualization-body');
  if (!body) return;
  const q = (document.getElementById('virt-search')?.value || '')
              .trim().toLowerCase();
  const shown = q
    ? _virtGuests.filter(g =>
        String(g.name || '').toLowerCase().includes(q) ||
        String(g.vmid || '').includes(q))
    : _virtGuests;
  if (!shown.length) {
    body.innerHTML = `<div class="table-card isl-578">
      No VMs match "${escHtml(q)}".</div>`;
    return;
  }
  body.innerHTML = `<div class="table-card isl-579">
    ${shown.map(g => _renderProxmoxGuest(g, 'qemu')).join('')}
  </div>`;
}

// Called by the search box's oninput.
function filterVirtualization() {
  _renderVirtualizationList();
}

// Load + render the LXC section on the Containers page.
// focused=true: user navigated directly here — show a hint instead of hiding.
async function loadProxmoxLXC(focused = false) {
  const section = document.getElementById('containers-lxc-section');
  const body = document.getElementById('containers-lxc-body');
  if (!section || !body) return;
  let data;
  try {
    data = await api('GET', '/proxmox/lxc');
  } catch (_) {
    if (!focused) section.style.display = 'none';
    else body.innerHTML = '<p class="hint">Unable to reach the Proxmox API. Check <strong>Admin → Settings → Proxmox</strong>.</p>';
    return;
  }
  if (!data || !data.enabled || !data.configured) {
    if (!focused) {
      section.style.display = 'none';
    } else {
      body.innerHTML = '<p class="hint">Proxmox is not configured. Go to <strong>Admin → Settings → Proxmox</strong> to connect your node.</p>';
    }
    return;
  }
  section.style.display = 'block';
  const guests = data.guests || [];
  if (!guests.length) {
    body.innerHTML = '<div class="table-card isl-580">No LXC containers on the Proxmox node.</div>';
    return;
  }
  body.innerHTML = `<div class="table-card isl-579">
    ${guests.map(g => _renderProxmoxGuest(g, 'lxc')).join('')}
  </div>`;
}

// Perform a guest action then refresh whichever view is showing.
async function proxmoxAction(kind, vmid, action, name) {
  const verb = action === 'shutdown' ? 'Shut down' : 'Start';
  if (!confirm(`${verb} ${kind.toUpperCase()} ${vmid} (${name})?`)) return;
  try {
    await api('POST', `/proxmox/${kind}/${vmid}/${action}`, {});
    toast(`${verb} sent to ${name}`, 'success');
    // Proxmox actions are async on its side — give it a moment, then
    // refresh the relevant view.
    setTimeout(() => {
      if (kind === 'qemu') loadVirtualization();
      else loadProxmoxLXC();
    }, 1500);
  } catch (e) {
    toast(`Action failed: ${e.message || String(e)}`, 'error');
  }
}

// ─── v2.3.0: Proxmox settings save / test ───────────────────────────────

// Collect the Proxmox form fields into a config payload. The token
// secret is only included when the operator typed something — a blank
// field means "keep the saved secret" (same convention as SMTP).
function _collectProxmoxForm() {
  const payload = {
    proxmox_enabled:    document.getElementById('proxmox-enabled').value === '1',
    proxmox_host:       document.getElementById('proxmox-host').value.trim(),
    proxmox_node:       document.getElementById('proxmox-node').value.trim(),
    proxmox_token_id:   document.getElementById('proxmox-token-id').value.trim(),
    proxmox_verify_tls: document.getElementById('proxmox-verify-tls').value === '1',
  };
  const secret = document.getElementById('proxmox-token-secret').value;
  if (secret) payload.proxmox_token_secret = secret;
  return payload;
}

async function saveProxmoxSettings() {
  try {
    await api('POST', '/config', _collectProxmoxForm());
    toast('Proxmox settings saved', 'success');
    // Clear the secret field + refresh the masked placeholder state
    document.getElementById('proxmox-token-secret').value = '';
    refreshProxmoxNav();
    loadSettings();
  } catch (e) {
    toast(`Save failed: ${e.message || String(e)}`, 'error');
  }
}

async function testProxmoxConnection() {
  const resultEl = document.getElementById('proxmox-test-result');
  resultEl.textContent = 'Testing…';
  resultEl.style.color = 'var(--muted)';
  try {
    // Send the current form values so Test works before Save.
    const r = await api('POST', '/proxmox/test', _collectProxmoxForm());
    if (r && r.ok) {
      resultEl.textContent = '✓ ' + (r.message || 'Connected');
      resultEl.style.color = 'var(--green)';
    } else {
      resultEl.textContent = '✗ ' + ((r && r.message) || 'Connection failed');
      resultEl.style.color = 'var(--red)';
    }
  } catch (e) {
    resultEl.textContent = '✗ ' + (e.message || String(e));
    resultEl.style.color = 'var(--red)';
  }
}

// ═══════════════════════════════════════════════════════════════════════
// v2.4.0 — Proxmox snapshots
//
// A modal listing a guest's snapshots with create / rollback / delete.
// rollback and delete are destructive: rollback requires typing the
// guest name to confirm; delete uses a plain confirm dialog.
// ═══════════════════════════════════════════════════════════════════════

let _snapCtx = null;   // {kind, vmid, name} of the guest whose modal is open

async function openSnapshots(kind, vmid, guestName) {
  _snapCtx = { kind, vmid, name: guestName };
  let modal = document.getElementById('snapshot-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'snapshot-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
      <div class="modal isl-581">
        <div class="isl-582">
          <div id="snapshot-modal-title" class="fw-600">Snapshots</div>
          <button class="btn-icon" data-action="closeModal" data-arg="snapshot-modal" >✕</button>
        </div>
        <div class="isl-583">
          <div class="form-group form-group">
            <label class="form-label fs-11">New snapshot name</label>
            <input type="text" id="snapshot-new-name" class="form-input" placeholder="e.g. before_upgrade">
          </div>
          <div class="form-group isl-584">
            <label class="form-label fs-11">Description (optional)</label>
            <input type="text" id="snapshot-new-desc" class="form-input" placeholder="why">
          </div>
          <button class="btn-primary isl-40" data-action="snapshotCreate" >Create</button>
        </div>
        <div id="snapshot-list"></div>
      </div>`;
    document.body.appendChild(modal);
  }
  document.getElementById('snapshot-modal-title').textContent =
    `Snapshots — ${guestName} (${kind.toUpperCase()} ${vmid})`;
  document.getElementById('snapshot-new-name').value = '';
  document.getElementById('snapshot-new-desc').value = '';
  openModal('snapshot-modal');
  loadSnapshots();
}

async function loadSnapshots() {
  if (!_snapCtx) return;
  const list = document.getElementById('snapshot-list');
  list.innerHTML = '<div class="isl-585">Loading…</div>';
  let data;
  try {
    data = await api('GET', `/proxmox/snapshots?type=${_snapCtx.kind}&vmid=${_snapCtx.vmid}`);
  } catch (e) {
    list.innerHTML = `<div class="isl-586">${escHtml(e.message || String(e))}</div>`;
    return;
  }
  const snaps = (data && data.snapshots) || [];
  if (!snaps.length) {
    list.innerHTML = '<div class="isl-585">No snapshots.</div>';
    return;
  }
  list.innerHTML = `<table class="isl-540"><thead>
    <tr class="isl-468">
      <th class="cell-pad">Name</th><th class="cell-pad">Taken</th>
      <th class="cell-pad">Description</th><th></th></tr></thead><tbody>` +
    snaps.map(s => {
      const taken = s.snaptime ? new Date(s.snaptime * 1000).toLocaleString() : '—';
      return `<tr class="border-bottom">
        <td class="isl-587">${escHtml(s.name)}${s.vmstate ? ' <span class="isl-588">+RAM</span>' : ''}</td>
        <td class="isl-545">${taken}</td>
        <td class="isl-545">${escHtml(s.description || '—')}</td>
        <td class="isl-589">
          <button class="btn-icon isl-590" data-action="snapshotRollback" data-arg="${escAttr(s.name)}" >Rollback</button>
          <button class="btn-icon isl-591" data-action="snapshotDelete" data-arg="${escAttr(s.name)}" >Delete</button>
        </td></tr>`;
    }).join('') + '</tbody></table>';
}

async function snapshotCreate() {
  if (!_snapCtx) return;
  const name = document.getElementById('snapshot-new-name').value.trim();
  const desc = document.getElementById('snapshot-new-desc').value.trim();
  if (!name) { toast('Enter a snapshot name', 'error'); return; }
  try {
    await api('POST', '/proxmox/snapshot', {
      type: _snapCtx.kind, vmid: _snapCtx.vmid, action: 'create',
      name: name, description: desc,
    });
    toast('Snapshot creation started', 'success');
    document.getElementById('snapshot-new-name').value = '';
    document.getElementById('snapshot-new-desc').value = '';
    setTimeout(loadSnapshots, 1500);
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

async function snapshotRollback(name) {
  if (!_snapCtx) return;
  // Destructive — discards all state since the snapshot. Require the
  // operator to type the guest name to confirm (not just an OK click).
  const typed = prompt(
    `ROLLBACK is destructive — it discards ALL changes made to ` +
    `"${_snapCtx.name}" since snapshot "${name}" was taken.\n\n` +
    `To confirm, type the guest name exactly:`);
  if (typed === null) return;
  if (typed.trim() !== _snapCtx.name) {
    toast('Name did not match — rollback cancelled', 'error');
    return;
  }
  try {
    await api('POST', '/proxmox/snapshot', {
      type: _snapCtx.kind, vmid: _snapCtx.vmid, action: 'rollback', name: name,
    });
    toast('Rollback started', 'success');
    setTimeout(loadSnapshots, 1500);
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

async function snapshotDelete(name) {
  if (!_snapCtx) return;
  if (!confirm(`Delete snapshot "${name}"?\n\nThis is irreversible, but it ` +
               `does not affect the running guest.`)) return;
  try {
    await api('POST', '/proxmox/snapshot', {
      type: _snapCtx.kind, vmid: _snapCtx.vmid, action: 'delete', name: name,
    });
    toast('Snapshot deleted', 'success');
    setTimeout(loadSnapshots, 1000);
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

// ═══════════════════════════════════════════════════════════════════════
// v2.4.2 — SSH preferences + quick SSH link
// ═══════════════════════════════════════════════════════════════════════

// The per-user default SSH username lives in the ui_prefs document
// under the top-level key 'default_ssh_username' (round-tripped by the
// existing _uiPrefs machinery).
function getDefaultSshUsername() {
  const u = _uiPrefs && _uiPrefs.default_ssh_username;
  return (typeof u === 'string') ? u : '';
}

// Populate the Settings field. Called when the Security pane opens.
function loadSshUsername() {
  const el = document.getElementById('cfg-ssh-username');
  if (el) el.value = getDefaultSshUsername();
}

// v3.3.0: save IP allowlist + enabled flag in one POST. Server-side
// guard refuses to enable the allowlist if the caller's own IP would
// be excluded.
// v3.3.0: save Healthchecks.io watchdog config. Empty URL disables.
async function saveHealthchecks() {
  const url      = document.getElementById('cfg-healthchecks-url').value.trim();
  const interval = parseInt(document.getElementById('cfg-healthchecks-interval').value, 10) || 60;
  const r = await api('POST', '/config', {
    healthchecks_url: url,
    healthchecks_interval_seconds: interval,
  });
  if (r?.ok) {
    toast(url ? `Healthchecks watchdog enabled (every ${interval}s)` : 'Healthchecks watchdog disabled', 'success');
  } else {
    toast(r?.error || 'Failed', 'error');
  }
}

async function testHealthchecks() {
  const url = document.getElementById('cfg-healthchecks-url').value.trim();
  if (!url) { toast('Enter a URL first', 'error'); return; }
  // The server will fire the ping the next time the periodic check is
  // due. For an immediate test, fire it client-side as the operator —
  // confirms the URL is reachable from this browser at least.
  try {
    const r = await fetch(url, { method: 'GET', mode: 'no-cors' });
    toast('Test ping sent — check your Healthchecks.io dashboard', 'success');
  } catch (e) {
    toast('Test ping failed: ' + e.message, 'error');
  }
}

async function saveIpAllowlist() {
  const enabled = document.getElementById('cfg-ipal-enabled').checked;
  const raw     = document.getElementById('cfg-ipal-list').value || '';
  const list    = raw.split('\n').map(s => s.trim()).filter(Boolean);
  const r = await api('POST', '/config', {
    ip_allowlist:         list,
    ip_allowlist_enabled: enabled,
  });
  if (r && r.ok) {
    toast(enabled
      ? `IP allowlist enabled (${list.length} entr${list.length === 1 ? 'y' : 'ies'})`
      : 'IP allowlist saved (not enforced — toggle is off)',
      'success');
    loadSecurityDiag();
  } else {
    toast(r?.error || 'Failed to save IP allowlist', 'error');
  }
}

async function saveSshUsername() {
  const el = document.getElementById('cfg-ssh-username');
  if (!el) return;
  const val = el.value.trim();
  // Mirror the server-side rule so the user gets immediate feedback.
  if (val && !/^[A-Za-z0-9._-]{1,32}$/.test(val)) {
    toast('Username may use letters, digits, dot, dash, underscore (max 32)', 'error');
    return;
  }
  if (val) {
    _uiPrefs.default_ssh_username = val;
  } else {
    delete _uiPrefs.default_ssh_username;
  }
  try {
    await api('POST', '/ui-prefs', _uiPrefs);
    toast('SSH username saved', 'success');
  } catch (e) {
    toast('Save failed: ' + (e.message || String(e)), 'error');
  }
}

// Render the quick-SSH icon for a device row. The target host is the
// device's IP when known, else its hostname (the fallback the spec
// asked for). Returns '' when there's neither — nothing to connect to.
function sshLinkIcon(d) {
  const host = (d.ip || '').trim() || (d.hostname || '').trim();
  if (!host) return '';
  // escAttr the host since it goes into an onclick attribute.
  // v3.0.3: explicit color:var(--text) — without it the <a> takes the
  // browser's default link colour (blue), which is hard to read against
  // the dark sidebar/table. var(--text) resolves to near-white in dark
  // mode and near-black in light mode, so the icon stays visible in
  // both themes. The currentColor stroke on the SVG inherits this.
  return ` <a href="#" title="Quick SSH" data-action="quickSsh" data-arg="${escAttr(host)}" data-prevent-default` +
         ` class="isl-592">` +
         `<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" class="isl-593">` +
         `<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></a>`;
}

// Quick SSH action. A browser cannot open a terminal itself — it can
// only hand an ssh:// URL to the OS, which works only if the user's
// machine has registered an ssh:// handler (PuTTY, the OS, a terminal
// emulator). So we do BOTH: attempt the ssh:// hand-off, and always
// offer the plain `ssh user@host` string to copy, which works
// everywhere regardless of handler setup.
function quickSsh(host) {
  const user = getDefaultSshUsername();
  if (!user) {
    toast('Set a default SSH username first (Settings → Security → SSH preferences)', 'error');
    return;
  }
  const target = `${user}@${host}`;
  // Best-effort ssh:// hand-off to the OS.
  try {
    window.location.href = `ssh://${encodeURIComponent(user)}@${encodeURIComponent(host)}`;
  } catch (_) { /* no handler — the copy fallback below still helps */ }
  // Always-works fallback: copy the command to the clipboard.
  const cmd = `ssh ${target}`;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(
      () => toast(`Copied: ${cmd}` , 'success'),
      () => toast(`SSH command: ${cmd}`, 'info'));
  } else {
    toast(`SSH command: ${cmd}`, 'info');
  }
}

// ═══════════════════════════════════════════════════════════════════════
// v2.4.4 — Mailbox monitor configuration (Settings → Mailbox monitor)
//
// Moved here from the device detail view. Pick a device, set its
// mailbox paths and the dashboard-promotion flag, save.
// ═══════════════════════════════════════════════════════════════════════

let _mailwatchOverview = [];   // cached /api/mailwatch result

// Called when the Mailbox monitor settings tab opens. Populates the
// device dropdown and caches current mailbox config.
async function loadMailwatchSettings() {
  const sel = document.getElementById('mailwatch-device');
  if (!sel) return;
  let devs = [], mw = {devices: []};
  try {
    [devs, mw] = await Promise.all([
      api('GET', '/devices'),
      api('GET', '/mailwatch'),
    ]);
  } catch (e) {
    toast('Could not load devices', 'error');
    return;
  }
  _mailwatchOverview = (mw && mw.devices) || [];
  const prev = sel.value;
  sel.innerHTML = '<option value="">— select a device —</option>' +
    (devs || []).map(d =>
      `<option value="${escAttr(d.id)}">${escHtml(d.name || d.id)}</option>`
    ).join('');
  if (prev) { sel.value = prev; loadMailwatchForDevice(); }
}

// Fill the path box + checkbox for the selected device.
function loadMailwatchForDevice() {
  const sel = document.getElementById('mailwatch-device');
  const cfg = document.getElementById('mailwatch-config');
  if (!sel || !cfg) return;
  const devId = sel.value;
  if (!devId) { cfg.style.display = 'none'; return; }
  cfg.style.display = 'block';
  const state = _mailwatchOverview.find(d => d.device_id === devId);
  const paths = (state && state.paths) || [];
  document.getElementById('mailwatch-paths').value = paths.join('\n');
  document.getElementById('mailwatch-dashboard').checked =
    !!(state && state.dashboard);
  document.getElementById('mailwatch-threshold').value =
    (state && state.threshold) ? state.threshold : '';
  // Show the most recent counts, if any have been reported.
  const cur = document.getElementById('mailwatch-current');
  const counts = (state && state.counts) || {};
  const keys = Object.keys(counts);
  if (!keys.length) {
    cur.innerHTML = paths.length
      ? '<div class="hint">No agent report yet — counts appear a few minutes after the agent next heartbeats.</div>'
      : '';
    return;
  }
  cur.innerHTML = '<div class="isl-594">Latest counts</div>' +
    keys.map(p => {
      const info = counts[p] || {};
      let v = '—';
      if (info.error) v = `<span class="c-amber">${escHtml(info.error)}</span>`;
      else if (typeof info.count === 'number') v = `<strong>${info.count}</strong> files`;
      return `<div class="isl-595">
        <code class="fs-11">${escHtml(p)}</code><span>${v}</span></div>`;
    }).join('');
}

async function saveMailwatch() {
  const sel = document.getElementById('mailwatch-device');
  if (!sel || !sel.value) { toast('Select a device first', 'error'); return; }
  const devId = sel.value;
  const paths = document.getElementById('mailwatch-paths').value
    .split('\n').map(s => s.trim()).filter(Boolean);
  const bad = paths.find(p => !p.startsWith('/'));
  if (bad) { toast(`Not an absolute path: ${bad}`, 'error'); return; }
  const dashboard = document.getElementById('mailwatch-dashboard').checked;
  const tRaw = document.getElementById('mailwatch-threshold').value.trim();
  const threshold = tRaw ? parseInt(tRaw, 10) : 0;
  if (tRaw && (!Number.isFinite(threshold) || threshold < 1)) {
    toast('Threshold must be a positive whole number', 'error');
    return;
  }
  try {
    await api('POST', `/devices/${encodeURIComponent(devId)}/mailwatch`,
              {paths: paths, dashboard: dashboard, threshold: threshold});
    toast('Mailbox monitor saved — the agent picks it up on its next heartbeat', 'success');
    loadMailwatchSettings();   // refresh cache
  } catch (e) {
    toast('Save failed: ' + (e.message || String(e)), 'error');
  }
}

// v2.4.5: force an out-of-band package scan. Sets a one-shot flag;
// the device sends a fresh package inventory + patch count within a
// heartbeat or two (it does not happen instantly — the agent has to
// receive the request on its next heartbeat, then report on the one
// after).
async function forcePackageScan(devId, name, btn) {
  // Give immediate visual feedback on the button so the click is confirmed
  const _origText = btn ? btn.textContent : '';
  if (btn) {
    btn.disabled    = true;
    btn.textContent = 'Sending…';
    btn.style.cssText += ';opacity:0.7;cursor:wait';
  }
  try {
    const r = await api('POST', `/devices/${encodeURIComponent(devId)}/scan-packages`, {});
    const ok  = r?.ok || r?.message;
    const msg = r?.message || 'Package scan queued — fresh list within ~60s';
    if (btn) {
      btn.textContent    = ok ? '✓ Queued' : '✗ Failed';
      btn.style.color    = ok ? 'var(--green)' : 'var(--red)';
      btn.style.opacity  = '1';
      btn.style.cursor   = 'default';
      btn.disabled       = false;
      setTimeout(() => { if (btn.isConnected) { btn.textContent = _origText; btn.style.color = ''; } }, 4000);
    }
    toast(msg, ok ? 'success' : 'error');
  } catch (e) {
    if (btn) {
      btn.textContent    = '✗ Error';
      btn.style.color    = 'var(--red)';
      btn.style.opacity  = '1';
      btn.style.cursor   = 'default';
      btn.disabled       = false;
      setTimeout(() => { if (btn.isConnected) { btn.textContent = _origText; btn.style.color = ''; } }, 4000);
    }
    toast('Scan request failed: ' + (e.message || String(e)), 'error');
  }
}

// v2.4.7: status endpoint token management.
async function generateStatusToken() {
  if (!confirm('Generate a status token? Any previous token stops working.')) return;
  try {
    const r = await api('POST', '/status-token', {enabled: true});
    if (r && r.status_token) _renderStatusToken(r.status_token);
    toast('Status token generated', 'success');
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

async function revokeStatusToken() {
  if (!confirm('Disable the status endpoint? External dashboards will stop working.')) return;
  try {
    await api('POST', '/status-token', {enabled: false});
    const box = document.getElementById('status-token-box');
    if (box) box.innerHTML =
      '<button class="btn-primary" data-action="generateStatusToken" >Generate status token</button>';
    toast('Status endpoint disabled', 'success');
  } catch (e) {
    toast('Failed: ' + (e.message || String(e)), 'error');
  }
}

function _renderStatusToken(token) {
  const box = document.getElementById('status-token-box');
  if (!box) return;
  const url = `${location.origin}/api/status?token=${encodeURIComponent(token)}`;
  box.innerHTML = `
    <div class="hint-mb6">Poll this URL from your dashboard tool:</div>
    <input type="text" class="form-input isl-66" readonly value="${escAttr(url)}" data-self-select="1">
    <div class="isl-596">
      <button class="btn-icon" data-action="generateStatusToken" >Rotate token</button>
      <button class="btn-icon c-red" data-action="revokeStatusToken" >Disable endpoint</button>
    </div>`;
}

// ─── v2.5.0: Custom Monitoring Scripts ────────────────────────────────────────

let _csData = null;       // {results: [...], scripts: [...]} from server
let _csDevices = null;    // device list for the device picker

// Called by showPage('custom-scripts', ...)
function loadCustomScripts() {
  renderCustomScriptsLoading();
  Promise.all([
    api('GET', '/custom-scripts/results'),
    api('GET', '/devices'),
  ]).then(([resultsData, devicesData]) => {
    if (!resultsData) return;
    _csData = resultsData;
    _csDevices = devicesData ? (devicesData.devices || devicesData) : [];
    renderCustomScriptsPage();
  }).catch(() => {
    const tbody = document.getElementById('cs-results-tbody');
    if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="isl-597">Failed to load. Refresh to retry.</td></tr>';
  });
}

function renderCustomScriptsLoading() {
  const tbody = document.getElementById('cs-results-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="8" class="empty-state-sm">Loading…</td></tr>';
}

function renderCustomScriptsPage() {
  if (!_csData) return;
  const filterText = (document.getElementById('cs-filter')?.value || '').toLowerCase();
  const statusFilter = document.getElementById('cs-status-filter')?.value || 'all';

  let rows = _csData.results || [];
  if (filterText) {
    rows = rows.filter(r =>
      r.script_name.toLowerCase().includes(filterText) ||
      r.device_name.toLowerCase().includes(filterText) ||
      (r.group || '').toLowerCase().includes(filterText) ||
      (r.output || '').toLowerCase().includes(filterText)
    );
  }
  if (statusFilter === 'fail') rows = rows.filter(r => !r.ok);
  if (statusFilter === 'ok')   rows = rows.filter(r => r.ok);

  tableCtl.wireSortOnly('cs-results-thead', 'cs_results', renderCustomScriptsPage);
  rows = tableCtl.sortRows('cs_results', rows, (r) => ({
    script_name: (r.script_name || '').toLowerCase(),
    device_name: (r.device_name || '').toLowerCase(),
    group:       (r.group || '').toLowerCase(),
    ok:          r.ok ? 1 : 0,
    output:      (r.output || '').toLowerCase(),
    ran_at:      r.ran_at || 0,
    duration_ms: r.duration_ms || 0,
  }));

  // Stats
  const allRows = _csData.results || [];
  const failing = allRows.filter(r => !r.ok).length;
  const allOk   = allRows.filter(r => r.ok).length;
  const scripts  = _csData.scripts || [];

  document.getElementById('cs-stat-total').textContent   = scripts.length;
  document.getElementById('cs-stat-running').textContent = allRows.length;
  document.getElementById('cs-stat-fail').textContent    = failing;
  document.getElementById('cs-stat-ok').textContent      = allOk;

  const tbody = document.getElementById('cs-results-tbody');
  if (!tbody) return;

  // Also show scripts that have never run (no results yet) — always visible and deletable
  const allScripts = _csData.scripts || [];
  const scriptIdsWithResults = new Set(rows.map(r => r.script_id));
  const noResultRows = allScripts
    .filter(s => s.id && !scriptIdsWithResults.has(s.id))
    .filter(s => {
      const n = s.name || '';
      return !filterText || n.toLowerCase().includes(filterText);
    })
    .filter(() => statusFilter === 'all');

  const noResultHtml = noResultRows.map(s => {
    const sid = escAttr(s.id);   // safe: IDs are cs_hexhex, no special chars
    return `<tr class="isl-598">
      <td class="fw-500">${escHtml(s.name)}</td>
      <td colspan="5" class="isl-599">No results yet — waiting for next run cycle</td>
      <td></td>
      <td class="nowrap">
        <button class="btn-icon isl-600"
            data-action="openCustomScriptModal" data-arg="${sid}" >Edit</button>
        <button class="btn-icon isl-601"
            data-action="csDeleteScript" data-arg="${sid}" >Delete</button>
      </td>
    </tr>`;
  }).join('');

  if (!rows.length && !noResultRows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state">${
      filterText || statusFilter !== 'all' ? 'No results match the filter.' : 'No custom script results yet. Assign a script to a device and wait one run cycle (5 min).'
    }</td></tr>`;
    return;
  }

  tbody.innerHTML = noResultHtml + rows.map(r => {
    const statusBadge = r.ok
      ? '<span class="c-green-bold">● OK</span>'
      : '<span class="c-red-bold">● FAIL</span>';
    const output = (r.output || '').trim();
    const outputSnippet = output.length > 80
      ? escHtml(output.slice(0, 80)) + '<span class="c-muted">…</span>'
      : escHtml(output || '—');
    const ranAt = r.ran_at ? new Date(r.ran_at * 1000).toLocaleString() : '—';
    const dur   = r.duration_ms ? `${r.duration_ms} ms` : '—';
    const changedAgo = r.changed_at
      ? `<span title="Status changed ${new Date(r.changed_at*1000).toLocaleString()}" class="isl-602">changed ${_reltime(r.changed_at)}</span>`
      : '';
    return `<tr>
      <td class="fw-500">${escHtml(r.script_name)}</td>
      <td>${escHtml(r.device_name)}</td>
      <td class="hint">${r.group ? `<span class="group-badge">${escHtml(r.group)}</span>` : '—'}</td>
      <td class="ta-center">${statusBadge}<br>${changedAgo}</td>
      <td
          data-action-btn="_csOutputFromStore" data-store-key="${_storeEvtData([r.script_name, r.device_name, output])}"
          title="Click for full output" class="isl-603">${outputSnippet}</td>
      <td class="meta-sm-nm">${ranAt}</td>
      <td class="isl-604">${dur}</td>
      <td class="nowrap">
        <button class="btn-icon isl-600"
            data-action="openCustomScriptModal" data-arg="${escAttr(r.script_id)}" >Edit</button>
        <button class="btn-icon isl-601"
            data-action="csDeleteScript" data-arg="${escAttr(r.script_id)}" >Delete</button>
      </td>
    </tr>`;
  }).join('');
}

function renderCsDefinitions() { /* cards removed — table is the only view */ }

function openCsOutput(scriptName, deviceName, output) {
  document.getElementById('cs-output-title').textContent = `${scriptName} — ${deviceName}`;
  document.getElementById('cs-output-body').textContent = output || '(no output)';
  openModal('cs-output-modal');
}

// ── Script create / edit modal ─────────────────────────────────────────────

async function openCustomScriptModal(scriptId) {
  // Reset modal
  document.getElementById('cs-modal-title').textContent = scriptId ? 'Edit script' : 'New script';
  document.getElementById('cs-modal-id').value   = scriptId || '';
  document.getElementById('cs-modal-name').value  = '';
  document.getElementById('cs-modal-desc').value  = '';
  document.getElementById('cs-modal-body').value  = '';
  document.getElementById('cs-ai-prompt').value   = '';
  document.getElementById('cs-ai-status').textContent = '';
  document.getElementById('cs-modal-delete-btn').style.display = scriptId ? 'block' : 'none';

  // If editing, fetch the script body (list view omits it)
  if (scriptId) {
    const s = await api('GET', `/custom-scripts/${scriptId}`);
    if (s) {
      document.getElementById('cs-modal-name').value = s.name || '';
      document.getElementById('cs-modal-desc').value = s.description || '';
      document.getElementById('cs-modal-body').value = s.body || '';
    }
  }

  // Build device picker
  await _buildCsDevicePicker(scriptId);

  openModal('custom-script-modal');
}

async function _buildCsDevicePicker(scriptId) {
  const container = document.getElementById('cs-device-picker');
  if (!container) return;
  container.innerHTML = '<span class="hint">Loading devices…</span>';

  // Get assigned_devices for this script (if editing) — always fetch so
  // we don't need _csData to be loaded first.
  let assigned = [];
  if (scriptId) {
    try {
      const full = await api('GET', `/custom-scripts/${scriptId}`);
      if (full) assigned = full.assigned_devices || [];
    } catch (_) {}
  }

  // Use cached device list if available; otherwise fetch fresh.
  let devs = _csDevices;
  if (!devs || !devs.length) {
    try {
      const fetched = await api('GET', '/devices');
      devs = Array.isArray(fetched) ? fetched : (fetched && fetched.devices) ? fetched.devices : [];
      if (devs.length) _csDevices = devs; // cache for next time
    } catch (_) {
      devs = [];
    }
  }

  const agentDevs = (devs || []).filter(d => !d.agentless);
  if (!agentDevs.length) {
    container.innerHTML = '<span class="hint">No devices enrolled.</span>';
    return;
  }

  container.innerHTML = agentDevs.map(d => {
    const devId  = d.device_id || d.id;
    const checked = assigned.includes(devId) ? 'checked' : '';
    return `<label class="isl-605">
      <input type="checkbox" class="cs-device-cb isl-606" value="${escAttr(devId)}" ${checked}>
      ${escHtml(d.name || devId)}
      ${d.group ? `<span class="group-badge fs-10">${escHtml(d.group)}</span>` : ''}
    </label>`;
  }).join('');
}

async function saveCustomScript() {
  const sid   = document.getElementById('cs-modal-id').value;
  const name  = document.getElementById('cs-modal-name').value.trim();
  const desc  = document.getElementById('cs-modal-desc').value.trim();
  const body  = document.getElementById('cs-modal-body').value.trim();
  const assigned = [...document.querySelectorAll('.cs-device-cb:checked')].map(cb => cb.value);

  if (!name) { toast('Script name is required', 'error'); return; }
  if (!body) { toast('Script body is required', 'error'); return; }

  const payload = { name, description: desc, body, assigned_devices: assigned };
  let result;
  if (sid) {
    result = await api('PUT', `/custom-scripts/${sid}`, payload);
  } else {
    result = await api('POST', '/custom-scripts', payload);
  }
  if (!result) return;
  closeModal('custom-script-modal');
  toast(sid ? 'Script updated' : 'Script created', 'success');
  loadCustomScripts();
}

async function deleteCustomScript() {
  const sid  = document.getElementById('cs-modal-id').value;
  const name = document.getElementById('cs-modal-name').value;
  if (!sid) return;
  if (!confirm(`Delete script "${name}"? This removes it from all devices.`)) return;
  const r = await api('DELETE', `/custom-scripts/${sid}`);
  if (!r) return;
  closeModal('custom-script-modal');
  toast('Script deleted', 'success');
  loadCustomScripts();
}

// Standalone delete — called from table row buttons. Looks up name from cache.
async function csDeleteScript(sid) {
  const script = (_csData && _csData.scripts || []).find(s => s.id === sid);
  const name   = script ? script.name : sid;
  if (!confirm(`Delete script "${name}"? This removes it from all devices.`)) return;
  const r = await api('DELETE', `/custom-scripts/${sid}`);
  if (!r) return;
  toast('Script deleted', 'success');
  loadCustomScripts();
}

// ── AI generation ──────────────────────────────────────────────────────────

async function csGenerateWithAI() {
  const prompt = document.getElementById('cs-ai-prompt').value.trim();
  if (!prompt) { toast('Describe what the script should check', 'error'); return; }

  const btn    = document.getElementById('cs-ai-btn');
  const status = document.getElementById('cs-ai-status');
  btn.disabled = true;
  status.textContent = 'Generating…';
  status.style.color = 'var(--accent)';

  try {
    const resp = await api('POST', '/ai/chat', {
      system:     'generate_script',
      messages:   [{ role: 'user', content:
        `Write a bash monitoring script for RemotePower custom script checks.\n\n` +
        `Monitoring contract (MUST follow):\n` +
        `- Exit code 0 = OK (check passed)\n` +
        `- Exit code non-zero = FAIL (check failed)\n` +
        `- Runs as root on the agent host\n` +
        `- Hard timeout: 30 seconds — finish well within that\n` +
        `- stdout + stderr are merged and captured (max 4 KB shown)\n` +
        `- Print one clear status line so the operator knows what happened\n\n` +
        `Task: ${prompt}\n\n` +
        `Return ONLY the bash script. No markdown, no explanation, no code fences.`
      }],
      max_tokens: 1500,
      context:    'custom_script_generate',
    });
    if (!resp) throw new Error('No response');
    const text = (resp.text || resp.content || '').trim();
    if (!text) throw new Error('Empty response from AI');

    // Strip markdown code fences if the model wrapped despite instructions
    const cleaned = text.replace(/^```(?:bash|sh)?\n?/m, '').replace(/\n?```$/m, '').trim();
    document.getElementById('cs-modal-body').value = cleaned;
    status.textContent = '✓ Script generated — review before saving';
    status.style.color = 'var(--green)';
  } catch (e) {
    status.textContent = `✗ ${e.message || 'AI generation failed'}`;
    status.style.color = 'var(--red)';
  } finally {
    btn.disabled = false;
  }
}

function _reltime(ts) {
  if (!ts) return '';
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 60)   return 'just now';
  if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
  return `${Math.floor(diff/86400)}d ago`;
}

// ─── v2.6.0: Host Configuration Management ────────────────────────────────────

let _hcData    = null;   // {desired, current, drift, desired_at, current_collected_at}
let _hcDevId   = null;
let _hcDevName = null;
const HC_TEXT_SECTIONS    = ['repos','netplan','nmcli','resolv_conf','hosts','sudoers','motd','logrotate','cron'];
const HC_SPECIAL_SECTIONS = ['services','users','groups'];

// ── Open modal ─────────────────────────────────────────────────────────────

async function openHostConfigModal(devId, devName) {
  _hcDevId   = devId;
  _hcDevName = devName;
  document.getElementById('hc-device-name').textContent = devName;
  document.getElementById('hc-device-id').value         = devId;

  hcShowTab('repos', document.querySelector('.hc-tab'));
  _hcData = null;
  _hcClearAll();
  openModal('host-config-modal');

  const data = await api('GET', `/devices/${devId}/host-config`);
  if (!data) return;
  _hcData = data;

  const desired = data.desired || {};
  const current = data.current || {};

  // For each section: use desired if set, otherwise fall back to current
  // so the editor is always pre-filled if we have any data at all.
  const merged = {};
  const ALL_SECTIONS = ['repos','netplan','nmcli','resolv_conf','hosts',
                        'sudoers','motd','logrotate','cron','services','users','groups'];
  ALL_SECTIONS.forEach(s => {
    const d = desired[s];
    const c = current[s];
    const hasDesired = d !== undefined && d !== null &&
                       (Array.isArray(d) ? d.length > 0 : d !== '');
    merged[s] = hasDesired ? d : (c !== undefined ? c : d);
  });
  _hcPopulateAll(merged);
  _hcShowDrift(data.drift || {});

  // Show a subtle info note if we're showing current (no desired saved yet)
  const hasAnyDesired = Object.keys(desired).length > 0;
  if (!hasAnyDesired && Object.keys(current).length > 0) {
    const ts = data.current_collected_at
      ? new Date(data.current_collected_at * 1000).toLocaleString()
      : 'unknown time';
    const infoBanner = document.getElementById('hc-info-banner');
    if (infoBanner) {
      infoBanner.style.display = 'block';
      document.getElementById('hc-info-ts').textContent = ts;
    }
  }
}

function _hcClearAll() {
  HC_TEXT_SECTIONS.forEach(s => {
    const el = document.getElementById(`hc-text-${s}`);
    if (el) el.value = '';
    const d = document.getElementById(`hc-drift-${s}`);
    if (d) d.textContent = '';
  });
  document.getElementById('hc-text-services').value = '';
  document.getElementById('hc-drift-services').textContent = '';
  document.getElementById('hc-users-list').innerHTML = '';
  document.getElementById('hc-drift-users').textContent = '';
  document.getElementById('hc-groups-list').innerHTML = '';
  document.getElementById('hc-drift-groups').textContent = '';
  document.getElementById('hc-drift-banner').style.display = 'none';
  const infoBanner = document.getElementById('hc-info-banner');
  if (infoBanner) infoBanner.style.display = 'none';
}

function _hcPopulateAll(desired) {
  HC_TEXT_SECTIONS.forEach(s => {
    const el = document.getElementById(`hc-text-${s}`);
    if (el) el.value = desired[s] || '';
  });
  // Services: list → textarea (one per line)
  const svcEl = document.getElementById('hc-text-services');
  if (svcEl) svcEl.value = (desired.services || []).join('\n');
  // Users
  _hcRenderUsers(desired.users || []);
  // Groups
  _hcRenderGroups(desired.groups || []);
}

function _hcShowDrift(drift) {
  const sections = drift.sections || [];
  const banner   = document.getElementById('hc-drift-banner');
  if (sections.length) {
    banner.style.display = 'block';
    document.getElementById('hc-drift-sections').textContent = sections.join(', ');
    sections.forEach(s => {
      const el = document.getElementById(`hc-drift-${s}`);
      if (el) el.textContent = 'drift detected';
    });
  } else {
    banner.style.display = 'none';
  }
}

// ── Tab switching ──────────────────────────────────────────────────────────

function hcShowTab(section, btn) {
  document.querySelectorAll('.hc-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.hc-panel').forEach(p => p.style.display = 'none');
  if (btn) btn.classList.add('active');
  const panel = document.getElementById(`hc-panel-${section}`);
  // CSP L1 fallout: hc-panel-* (except the default) have `d-none`
  // in markup so they're hidden on initial paint. `style.display = ''`
  // would only clear the inline attribute; the d-none class would
  // keep the panel hidden. Use explicit 'block' to beat the class.
  if (panel) panel.style.display = 'block';
}

// ── Fetch current from agent ───────────────────────────────────────────────

async function hcFetchCurrent(section) {
  if (!_hcDevId) return;
  const data = await api('GET', `/devices/${_hcDevId}/host-config/current`);
  if (!data) return;
  const current = data.current || {};
  const val = current[section];
  if (val === undefined || val === null) {
    toast(`No current ${section} data yet — agent reports every 15 min`, 'info');
    return;
  }
  // Populate the appropriate editor
  if (HC_TEXT_SECTIONS.includes(section)) {
    document.getElementById(`hc-text-${section}`).value =
      typeof val === 'string' ? val : JSON.stringify(val, null, 2);
  } else if (section === 'services') {
    document.getElementById('hc-text-services').value =
      Array.isArray(val) ? val.join('\n') : '';
  } else if (section === 'users') {
    _hcRenderUsers(Array.isArray(val) ? val : []);
  } else if (section === 'groups') {
    _hcRenderGroups(Array.isArray(val) ? val : []);
  }
  const ts = data.current_collected_at
    ? new Date(data.current_collected_at * 1000).toLocaleTimeString()
    : 'unknown time';
  toast(`Loaded current ${section} from agent (collected ${ts})`, 'success');
}

// ── Users editor ───────────────────────────────────────────────────────────

function _hcRenderUsers(users) {
  const container = document.getElementById('hc-users-list');
  if (!container) return;
  container.innerHTML = '';
  (users || []).forEach((u, i) => {
    container.appendChild(_hcUserCard(u, i));
  });
}

function _hcUserCard(u, i) {
  const div = document.createElement('div');
  div.className = 'hc-user-card';
  div.dataset.idx = i;
  div.style.cssText = 'background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px;position:relative';
  div.innerHTML = `
    <button data-action="hcRemoveUser" data-arg="${i}" title="Remove user" class="isl-607">×</button>
    <div class="isl-608">
      <div><label class="isl-609">Username</label>
        <input class="form-input fs-12" value="${escAttr(u.name||'')}" data-field="name"></div>
      <div><label class="isl-609">Shell</label>
        <input class="form-input fs-12" value="${escAttr(u.shell||'/bin/bash')}" data-field="shell"></div>
    </div>
    <div class="isl-610"><label class="isl-609">Groups (comma-separated)</label>
      <input class="form-input fs-12" value="${escAttr((u.groups||[]).join(', '))}" data-field="groups"></div>
    <div><label class="isl-609">authorized_keys</label>
      <textarea class="form-textarea isl-611" data-field="authorized_keys">${escHtml(u.authorized_keys||'')}</textarea></div>`;
  return div;
}

function hcAddUser() {
  const container = document.getElementById('hc-users-list');
  const idx = container.querySelectorAll('.hc-user-card').length;
  container.appendChild(_hcUserCard({name:'',shell:'/bin/bash',groups:[],authorized_keys:''}, idx));
}

function hcRemoveUser(idx) {
  const cards = document.querySelectorAll('.hc-user-card');
  if (cards[idx]) cards[idx].remove();
  // Re-index remaining cards. After CSP L1, the remove button uses
  // data-action="hcRemoveUser" data-arg="${i}" instead of an inline
  // onclick, so re-indexing means updating the dataset arg, not the
  // attribute.
  document.querySelectorAll('.hc-user-card').forEach((c, i) => {
    c.dataset.idx = i;
    const btn = c.querySelector('button[data-action="hcRemoveUser"]');
    if (btn) btn.dataset.arg = i;
  });
}

function hcUserField(idx, el) {
  // Live update handled at save time — no-op here, just for symmetry
}

function _hcCollectUsers() {
  const users = [];
  document.querySelectorAll('.hc-user-card').forEach(card => {
    const get = (field) => {
      const el = card.querySelector(`[data-field="${field}"]`);
      return el ? el.value : '';
    };
    const name = get('name').trim();
    if (!name) return;
    const groupsRaw = get('groups').split(',').map(g => g.trim()).filter(Boolean);
    users.push({
      name,
      shell:           get('shell').trim() || '/bin/bash',
      groups:          groupsRaw,
      authorized_keys: get('authorized_keys'),
    });
  });
  return users;
}

// ── Groups editor ──────────────────────────────────────────────────────────

function _hcRenderGroups(groups) {
  const container = document.getElementById('hc-groups-list');
  if (!container) return;
  container.innerHTML = '';
  (groups || []).forEach((g, i) => container.appendChild(_hcGroupRow(g, i)));
}

function _hcGroupRow(g, i) {
  const div = document.createElement('div');
  div.className = 'hc-group-row';
  div.style.cssText = 'display:flex;gap:10px;align-items:center';
  div.innerHTML = `
    <input class="form-input isl-612" placeholder="groupname"
           value="${escAttr(g.name||'')}" data-field="name">
    <input class="form-input isl-613" placeholder="GID (opt)"
           value="${g.gid !== null && g.gid !== undefined ? g.gid : ''}" data-field="gid" type="number">
    <button data-remove-closest=".hc-group-row" class="isl-614">×</button>`;
  return div;
}

function hcAddGroup() {
  const container = document.getElementById('hc-groups-list');
  container.appendChild(_hcGroupRow({name:'', gid: null}, container.children.length));
}

function _hcCollectGroups() {
  const groups = [];
  document.querySelectorAll('.hc-group-row').forEach(row => {
    const name = row.querySelector('[data-field="name"]').value.trim();
    if (!name) return;
    const gidRaw = row.querySelector('[data-field="gid"]').value;
    groups.push({ name, gid: gidRaw ? parseInt(gidRaw) : null });
  });
  return groups;
}

// ── Save ───────────────────────────────────────────────────────────────────

async function saveHostConfig() {
  if (!_hcDevId) return;
  const desired = {};

  HC_TEXT_SECTIONS.forEach(s => {
    const el = document.getElementById(`hc-text-${s}`);
    if (el && el.value.trim()) desired[s] = el.value;
  });

  // Services: textarea → list
  const svcEl = document.getElementById('hc-text-services');
  if (svcEl && svcEl.value.trim()) {
    desired.services = svcEl.value.split('\n').map(l => l.trim()).filter(Boolean);
  }

  const users = _hcCollectUsers();
  if (users.length) desired.users = users;

  const groups = _hcCollectGroups();
  if (groups.length) desired.groups = groups;

  const r = await api('PUT', `/devices/${_hcDevId}/host-config`, desired);
  if (!r) return;
  closeModal('host-config-modal');
  toast('Host config saved — agent will apply on next heartbeat (~60s)', 'success');
}

// Trigger agent to collect and send all current config sections via exec command
async function hcFetchAllCurrent() {
  if (!_hcDevId) return;
  const btn = document.getElementById('hc-fetch-all-btn');
  btn.disabled = true;
  btn.textContent = '⌛ Requesting…';
  // Queue command via the standard exec endpoint
  const r = await api('POST', '/exec', {
    device_id: _hcDevId,
    cmd: 'remotepower-agent send_current_configs',
  });
  if (!r || !r.ok) {
    toast(r?.error || 'Failed to queue command', 'error');
    btn.disabled = false;
    btn.textContent = '⬇ Collect all current';
    return;
  }
  btn.textContent = '✓ Queued — refreshing in 75s…';
  toast('Command queued — agent will collect and send config in ~60s', 'success');
  // After one full poll cycle the agent should have run and sent back the data
  setTimeout(async () => {
    const data = await api('GET', `/devices/${_hcDevId}/host-config`);
    if (data) {
      _hcData = data;
      // Populate from current data (what the agent just collected)
      const current = data.current || {};
      if (Object.keys(current).length > 0) {
        _hcPopulateAll(current);
        toast('Current config loaded — review and click Save to apply as desired', 'success');
      } else {
        _hcPopulateAll(data.desired || {});
        toast('Current config loaded from agent', 'success');
      }
      _hcShowDrift(data.drift || {});
    }
    btn.disabled = false;
    btn.textContent = '⬇ Collect all current';
  }, 75000);
}

// ── v2.8.1: Listening Ports — Monitor page ───────────────────────────────────

let _portsGrouped = [];

async function loadListeningPorts() {
  const el = document.getElementById('ports-container');
  if (!el) return;
  el.innerHTML = '<span class="c-muted-fs13">Loading…</span>';
  const devs = await api('GET', '/devices');
  if (!Array.isArray(devs)) { el.textContent = 'Failed to load'; return; }

  const monitored = devs.filter(d => d.monitored !== false && !d.agentless && d.online);
  if (!monitored.length) {
    _portsGrouped = [];
    el.textContent = 'No online monitored devices.';
    return;
  }

  // v3.3.0: batch sysinfo fetch via /api/devices/sysinfo?ids=… (one
  // CGI process instead of N+1). Falls back to empty ports per device
  // if a particular id is missing from the response.
  const idsParam = monitored.map(d => encodeURIComponent(d.id)).join(',');
  const batch = await api('GET', `/devices/sysinfo?ids=${idsParam}`)
    .catch(() => ({ sysinfo: {} }));
  const sysmap = (batch && batch.sysinfo) || {};
  const portData = monitored.map(d => ({
    id: d.id, name: d.name,
    ports: (sysmap[d.id] && sysmap[d.id].listening_ports) || [],
  }));

  const rows = portData.flatMap(d =>
    d.ports.map(p => ({ device: d.name, dev_id: d.id, proto: p.proto||'tcp', port: p.port||0, process: p.process||'' }))
  ).sort((a,b) => a.port - b.port || a.device.localeCompare(b.device));

  if (!rows.length) {
    _portsGrouped = [];
    el.textContent = 'No listening port data yet — agent reports ports with sysinfo (every ~10 min).';
    return;
  }

  // Group by port for fleet-wide view
  const byPort = {};
  for (const r of rows) {
    const key = `${r.proto}/${r.port}`;
    if (!byPort[key]) byPort[key] = { proto: r.proto, port: r.port, hosts: [] };
    byPort[key].hosts.push({ device: r.device, process: r.process });
  }

  _portsGrouped = Object.values(byPort).sort((a,b) => a.port - b.port);
  _renderPortsFiltered();
}

function _renderPortsFiltered() {
  const el = document.getElementById('ports-container');
  if (!el || !_portsGrouped.length) return;
  const q = (document.getElementById('ports-filter')?.value || '').trim().toLowerCase();
  const filtered = q ? _portsGrouped.filter(e => {
    const procs = e.hosts.map(h => h.process).join(' ').toLowerCase();
    const devs  = e.hosts.map(h => h.device).join(' ').toLowerCase();
    return `${e.proto}/${e.port}`.includes(q) || procs.includes(q) || devs.includes(q);
  }) : _portsGrouped;

  if (!filtered.length) {
    el.innerHTML = '<span class="c-muted-fs13">No ports match filter.</span>';
    return;
  }

  // v3.2.1: sortable
  const _sortedFiltered = tableCtl.sortRows('ports', filtered, (e) => {
    const procs = [...new Set(e.hosts.map(h => h.process).filter(Boolean))].join(', ');
    return {
      port: e.port || 0,                            // numeric — sorts by port number
      process: (procs || '').toLowerCase(),
      devices: e.hosts.length,
    };
  });
  const visible = _sortedFiltered.slice(0, 10);
  const hidden  = _sortedFiltered.slice(10);
  el.innerHTML = `
    <div class="table-card">
      <table>
        <thead id="ports-thead"><tr>
          <th data-col="port">Port</th><th data-col="process">Process</th><th data-col="devices">Devices</th>
        </tr></thead>
        <tbody id="ports-table-body">
          ${visible.map(e => {
            const procs = [...new Set(e.hosts.map(h => h.process).filter(Boolean))];
            const devLinks = e.hosts.map(h =>
              `<span class="cmd-badge" title="${escHtml(h.device)}">${escHtml(h.device)}</span>`
            ).join(' ');
            return `<tr>
              <td><code class="fs-12">${escHtml(e.proto)}/${e.port}</code></td>
              <td class="hint">${escHtml(procs.join(', ') || '—')}</td>
              <td class="fs-12">${devLinks}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>` +
    (hidden.length ? `<button class="btn-secondary isl-55"
       data-action-btn="_expandPortsFromStore" data-store-key="${_storeEvtData(hidden)}">Show ${hidden.length} more ports</button>` : '');
  // Wire after the DOM is in place — thead is built by innerHTML above
  tableCtl.wireSortOnly('ports-thead', 'ports', _renderPortsFiltered);
}


// ── Top Processes fleet view ──────────────────────────────────────────────────

let _processRows = [];

async function loadProcesses() {
  const tbody = document.getElementById('processes-tbody');
  if (!tbody) return;
  // Wire sort indicators eagerly so the ↕ arrows appear even before data
  // arrives (and in empty / failure states). Other Monitoring tables do
  // the same — keeps the column UX consistent.
  tableCtl.wireSortOnly('processes-thead', 'processes', _renderProcessesFiltered);
  tbody.innerHTML = '<tr><td colspan="5" class="c-muted-padded">Loading…</td></tr>';
  const devs = await api('GET', '/devices');
  if (!Array.isArray(devs)) { tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Failed to load.</td></tr>'; return; }

  const monitored = devs.filter(d => d.monitored !== false && !d.agentless && d.online);
  if (!monitored.length) {
    _processRows = [];
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No online monitored devices.</td></tr>';
    return;
  }

  // v3.3.0: batch sysinfo fetch (one CGI process for N devices).
  const idsParam = monitored.map(d => encodeURIComponent(d.id)).join(',');
  const batch = await api('GET', `/devices/sysinfo?ids=${idsParam}`)
    .catch(() => ({ sysinfo: {} }));
  const sysmap = (batch && batch.sysinfo) || {};
  const procData = monitored.map(d => ({
    id: d.id, name: d.name,
    procs: (sysmap[d.id] && sysmap[d.id].top_processes) || [],
  }));

  _processRows = procData.flatMap(d =>
    d.procs.map(p => ({ device: d.name, dev_id: d.id, name: p.name || '', pid: p.pid || 0, cpu: p.cpu || 0, mem: p.mem || 0 }))
  );

  if (!_processRows.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No process data yet — requires psutil on the agent. Updates every ~60 s.</td></tr>';
    return;
  }
  _renderProcessesFiltered();
}

function _renderProcessesFiltered() {
  const tbody = document.getElementById('processes-tbody');
  if (!tbody) return;
  tableCtl.wireSortOnly('processes-thead', 'processes', _renderProcessesFiltered);
  const q = (document.getElementById('processes-filter')?.value || '').toLowerCase();
  let rows = q ? _processRows.filter(r => r.name.toLowerCase().includes(q) || r.device.toLowerCase().includes(q)) : _processRows;
  rows = tableCtl.sortRows('processes', rows, r => ({ name: r.name.toLowerCase(), pid: r.pid, device: r.device.toLowerCase(), cpu: r.cpu, mem: r.mem }));
  if (!rows.length) { tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No matches.</td></tr>'; return; }
  tbody.innerHTML = rows.map(r => `<tr>
    <td class="fw-500">${escHtml(r.name)}</td>
    <td class="hint">${r.pid}</td>
    <td>${escHtml(r.device)}</td>
    <td class="ta-right">${r.cpu > 0 ? `<span class="${r.cpu > 50 ? 'c-red-bold' : r.cpu > 20 ? 'c-amber' : ''}">${r.cpu.toFixed(1)}%</span>` : '<span class="c-muted">—</span>'}</td>
    <td class="ta-right">${r.mem > 0 ? `<span class="${r.mem > 20 ? 'c-amber' : ''}">${r.mem.toFixed(1)}%</span>` : '<span class="c-muted">—</span>'}</td>
  </tr>`).join('');
}

// ── v2.8.1: Settings → Dashboard personalisation ─────────────────────────────

// v3.2.3: canonical kind list moved server-side (CHANNEL_KINDS in api.py).
// The matrix UI reads /api/dashboard/kinds — no more duplicated arrays here.

async function loadDashboardSettings() {
  const cfg = await api('GET', '/config');
  if (!cfg) return;

  const hiddenAttn = new Set(cfg.dashboard_hidden_attention_kinds || []);
  const hiddenAct  = new Set(cfg.dashboard_hidden_activity_events || []);

  // Brute force settings
  const bfEnabled   = cfg.brute_force_enabled !== false;
  const bfThreshold = cfg.brute_force_threshold || 20;
  const bfWindow    = Math.round((cfg.brute_force_window_seconds || 300) / 60);

  document.getElementById('dash-bf-enabled').checked  = bfEnabled;
  document.getElementById('dash-bf-threshold').value  = bfThreshold;
  document.getElementById('dash-bf-window').value     = bfWindow;

  // v3.2.3: channel routing matrix — replaces the two legacy
  // kind/activity panes. Server is the source of truth for the kind
  // roster; we just render the table and POST diffs back.
  loadChannelMatrix();

  // Backup monitors
  renderBackupMonitors(cfg.backup_monitors || []);
}

// v3.2.3: channel routing matrix. The server is canonical for the kind
// roster (CHANNEL_KINDS in api.py) and the labels for each channel —
// frontend just renders the table and POSTs a single-row diff per click.
const CHANNEL_LABELS = {
  needs_attention: 'Needs Attention',
  recent_activity: 'Recent Activity',
  alerts:          'Alerts',
  webhook:         'Webhook',
};
let _channelMatrixCache = null;

async function loadChannelMatrix() {
  const el = document.getElementById('dash-channel-matrix');
  if (!el) return;
  const data = await api('GET', '/dashboard/kinds');
  if (!data || !data.kinds) {
    el.innerHTML = '<div class="hint">Failed to load channel routing.</div>';
    return;
  }
  _channelMatrixCache = data;
  const channels = data.channels || ['needs_attention', 'recent_activity', 'alerts', 'webhook'];
  // Header
  const head = `<thead><tr>
    <th class="ta-left">Kind</th>
    ${channels.map(c => `<th class="ta-center">${escHtml(CHANNEL_LABELS[c] || c)}</th>`).join('')}
  </tr></thead>`;
  // Group by group field
  const groups = {};
  for (const k of data.kinds) {
    (groups[k.group || 'other'] ||= []).push(k);
  }
  const groupOrder = ['operational', 'informational', 'other'];
  const groupTitle = {operational: 'Operational alerts', informational: 'Informational', other: 'Other'};
  let body = '';
  let first = true;
  for (const g of groupOrder) {
    if (!groups[g]) continue;
    if (!first) {
      body += `<tr><td colspan="${channels.length + 1}">&nbsp;</td></tr>`;
    }
    first = false;
    body += `<tr class="c-muted"><td colspan="${channels.length + 1}" class="fw-500">${escHtml(groupTitle[g] || g)}</td></tr>`;
    for (const k of groups[g]) {
      body += `<tr>
        <td class="fw-500">${escHtml(k.label)}<div class="meta-sm c-muted">${escHtml((k.events || []).join(', '))}</div></td>
        ${channels.map(c => `<td class="ta-center"><input type="checkbox" ${k.channels[c] ? 'checked' : ''} data-change="toggleChannelRoute" data-change-arg="${k.kind}|${c}"></td>`).join('')}
      </tr>`;
    }
  }
  el.innerHTML = `<div class="table-card"><table>${head}<tbody>${body}</tbody></table></div>`;
}

async function toggleChannelRoute(arg, on) {
  // Dispatcher only passes one custom arg, so kind+channel are joined
  // with '|' in the data-change-arg attribute.
  const [kind, channel] = String(arg).split('|');
  if (!kind || !channel || !_channelMatrixCache) return;
  // Optimistic update so the UI feels instant; rollback on failure.
  const row = _channelMatrixCache.kinds.find(k => k.kind === kind);
  if (!row) return;
  const prev = row.channels[channel];
  row.channels[channel] = !!on;
  const payload = {channel_routing: {[kind]: {[channel]: !!on}}};
  const r = await api('POST', '/dashboard/kinds', payload);
  if (!r || !r.ok) {
    row.channels[channel] = prev;
    toast(r?.error || 'Failed to update routing', 'error');
    loadChannelMatrix();
  }
}

async function saveBruteForceSettings() {
  const enabled   = document.getElementById('dash-bf-enabled').checked;
  const threshold = parseInt(document.getElementById('dash-bf-threshold').value, 10);
  const windowMin = parseInt(document.getElementById('dash-bf-window').value, 10);
  const r = await api('POST', '/config', {
    brute_force_enabled:        enabled,
    brute_force_threshold:      threshold,
    brute_force_window_seconds: windowMin * 60,
  });
  if (r?.ok) toast('Brute-force settings saved', 'success');
  else toast(r?.error || 'Failed', 'error');
}

// ── Backup monitors CRUD ──────────────────────────────────────────────────────

let _backupMonitors = [];

// v3.3.0: backup monitor in-place edit. -1 = not editing (Add button
// creates a new entry); ≥0 = the index in _backupMonitors being edited
// (Add button morphs into Save and replaces the row at that index).
let _backupEditIdx = -1;

function renderBackupMonitors(monitors) {
  _backupMonitors = monitors || [];
  const el = document.getElementById('backup-monitors-list');
  if (!el) return;
  // Refresh the Add/Save button label to reflect current mode
  const addBtn = document.querySelector('[data-action="addBackupMonitor"]');
  if (addBtn) addBtn.textContent = _backupEditIdx >= 0 ? 'Save' : 'Add';
  if (!_backupMonitors.length) {
    el.innerHTML = '<div class="isl-616">No backup monitors configured.</div>';
    return;
  }
  el.innerHTML = _backupMonitors.map((m, i) => `
    <div class="isl-617">
      <span class="isl-618"><code>${escHtml(m.path)}</code></span>
      <span class="hint">${escHtml(m.label||m.path)}</span>
      <span class="cmd-badge">${m.max_age_hours}h</span>
      <button class="btn-icon" data-action="editBackupMonitor" data-arg="${i}">Edit</button>
      <button class="btn-icon c-red" data-action="removeBackupMonitor" data-arg="${i}">✕</button>
    </div>`).join('');
}

function editBackupMonitor(idx) {
  const m = _backupMonitors[idx];
  if (!m) return;
  document.getElementById('bm-path').value  = m.path  || '';
  document.getElementById('bm-label').value = m.label || '';
  document.getElementById('bm-hours').value = String(m.max_age_hours || 24);
  _backupEditIdx = idx;
  renderBackupMonitors(_backupMonitors);  // re-render so the button flips to "Save"
  document.getElementById('bm-path').focus();
}

async function addBackupMonitor() {
  const path  = document.getElementById('bm-path').value.trim();
  const label = document.getElementById('bm-label').value.trim();
  const hours = parseInt(document.getElementById('bm-hours').value, 10) || 24;
  if (!path) { toast('Path required', 'error'); return; }
  const entry = {path, label: label || path, max_age_hours: hours};
  if (_backupEditIdx >= 0 && _backupEditIdx < _backupMonitors.length) {
    _backupMonitors[_backupEditIdx] = entry;
  } else {
    _backupMonitors.push(entry);
  }
  const wasEdit = _backupEditIdx >= 0;
  const r = await api('POST', '/config', {backup_monitors: _backupMonitors});
  if (r?.ok) {
    toast(wasEdit ? 'Backup monitor updated' : 'Backup monitor added', 'success');
    document.getElementById('bm-path').value = document.getElementById('bm-label').value = '';
    document.getElementById('bm-hours').value = '24';
    _backupEditIdx = -1;
    renderBackupMonitors(_backupMonitors);
  } else toast(r?.error || 'Failed', 'error');
}

async function removeBackupMonitor(idx) {
  _backupMonitors.splice(idx, 1);
  if (_backupEditIdx === idx) _backupEditIdx = -1;
  else if (_backupEditIdx > idx) _backupEditIdx -= 1;
  const r = await api('POST', '/config', {backup_monitors: _backupMonitors});
  if (r?.ok) { renderBackupMonitors(_backupMonitors); toast('Removed', 'info'); }
  else toast('Failed', 'error');
}

// ══ v2.9.0: Device Drawer ═════════════════════════════════════════════════════
// Full-screen drawer replacing detail-modal + ⋮ dropdown.
// Tabs: "Actions & Settings" and "Audit".
// ══════════════════════════════════════════════════════════════════════════════

let _drawerDeviceId   = null;
let _drawerDeviceName = null;
let _drawerDeviceData = null;          // cached device object from /api/devices
let _drawerAuditLoaded = {};           // which audit sections have been fetched

// ── Open / close ──────────────────────────────────────────────────────────────

async function openDeviceDrawer(id, name, defaultTab = 'actions') {
  _drawerDeviceId   = id;
  _drawerDeviceName = name;
  _drawerAuditLoaded = {};

  document.getElementById('drawer-device-name').textContent = name;
  document.getElementById('drawer-device-sub').textContent  = 'Loading…';

  const drawer = document.getElementById('device-drawer');
  drawer.classList.add('open');
  document.body.style.overflow = 'hidden';

  // Fetch device data for status badge + settings form
  try {
    const devs = await api('GET', '/devices');
    _drawerDeviceData = (devs || []).find(d => d.id === id) || {};
    const online = _drawerDeviceData.online;
    const status = online ? '● Online' : '○ Offline';
    const color  = online ? 'var(--green)' : 'var(--red)';
    document.getElementById('drawer-device-sub').innerHTML =
      `<span class="isl-401" data-color="${color}">${status}</span>` +
      (_drawerDeviceData.group ? ` · ${escHtml(_drawerDeviceData.group)}` : '');
  } catch(e) {
    _drawerDeviceData = {};
    document.getElementById('drawer-device-sub').textContent = '';
  }

  _renderDrawerActions();
  _renderDrawerSettings();
  switchDrawerTab(defaultTab);
}

function closeDeviceDrawer() {
  const drawer = document.getElementById('device-drawer');
  drawer.classList.remove('open');
  document.body.style.overflow = '';
  _drawerDeviceId   = null;
  _drawerDeviceName = null;
  _drawerAuditLoaded = {};
}

// Close on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && _drawerDeviceId) closeDeviceDrawer();
});

function switchDrawerTab(tab) {
  // CSP L1 fallout (v3.0.5): the drawer-tab-audit panel has the d-none
  // utility class for its initial-hide; setting style.display = '' to
  // show it only clears the inline attribute and leaves the class
  // hiding the panel. Use explicit 'block' so the inline value beats
  // the class. Same bug pattern as the AI page reveal.
  ['actions', 'audit'].forEach(t => {
    const panel = document.getElementById(`drawer-tab-${t}`);
    if (panel) panel.style.display = (t === tab) ? 'block' : 'none';
    document.getElementById(`drawer-tab-btn-${t}`)?.classList.toggle('active', t === tab);
  });
  if (tab === 'audit' && _drawerDeviceId) _renderDrawerAuditSections();
}

// ── Actions tab ───────────────────────────────────────────────────────────────

// v3.3.0: inline Lucide-style SVG icons (matches the left sidebar).
// Replaces the prior emoji set in the drawer + everywhere else. Each
// entry is just the inner <path>/<circle>/<line>/<polyline>/<rect>
// markup — the outer <svg> wrapper with currentColor stroke is
// applied by _icon() below. New icons should be added with body-only
// markup from https://lucide.dev/icons/.
const _ICONS = {
  terminal:    '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  refresh:     '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10"/><path d="M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  power:       '<path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/>',
  radio:       '<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/>',
  package:     '<path d="m7.5 4.27 9 5.15"/><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
  search:      '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
  monitor:     '<rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
  fileCode:    '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5z"/><polyline points="14 2 14 8 20 8"/><path d="m9 18-2-2 2-2"/><path d="m13 18 2-2-2-2"/>',
  download:    '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  zap:         '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  unplug:      '<path d="m19 5 3-3"/><path d="m2 22 3-3"/><path d="M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z"/><path d="m7.5 13.5 2.5-2.5"/><path d="m10.5 16.5 2.5-2.5"/><path d="m12 6 6 6 2.3-2.3a2.4 2.4 0 0 0 0-3.4l-2.6-2.6a2.4 2.4 0 0 0-3.4 0Z"/>',
  ship:        '<path d="M2 21c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1s1.2 1 2.5 1c2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/><path d="M19.38 20A11.6 11.6 0 0 0 21 14l-9-4-9 4c0 2.9.94 5.34 2.81 7.76"/><path d="M19 13V7a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v6"/>',
  settings:    '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
  sparkles:    '<path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z"/>',
  clipboard:   '<path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect width="8" height="4" x="8" y="2" rx="1" ry="1"/><line x1="8" y1="12" x2="16" y2="12"/><line x1="8" y1="16" x2="16" y2="16"/>',
  bookOpen:    '<path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>',
  wrench:      '<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>',
  clock:       '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  trash:       '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/>',
  // v3.3.0: extra icons for device-icon palette + status pills
  laptop:      '<rect x="2" y="4" width="20" height="12" rx="2"/><line x1="2" y1="20" x2="22" y2="20"/>',
  smartphone:  '<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/>',
  printer:     '<polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>',
  globe:       '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  server:      '<rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
  hardDrive:   '<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>',
  gamepad:     '<line x1="6" y1="12" x2="10" y2="12"/><line x1="8" y1="10" x2="8" y2="14"/><line x1="15" y1="13" x2="15.01" y2="13"/><line x1="18" y1="11" x2="18.01" y2="11"/><rect x="2" y="6" width="20" height="12" rx="2"/>',
  tv:          '<rect x="2" y="7" width="20" height="15" rx="2" ry="2"/><polyline points="17 2 12 7 7 2"/>',
  home:        '<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  building:    '<rect x="4" y="2" width="16" height="20" rx="2" ry="2"/><line x1="9" y1="22" x2="9" y2="2"/><line x1="15" y1="22" x2="15" y2="2"/>',
  factory:     '<path d="M2 20a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V8l-7 5V8l-7 5V4a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2Z"/><path d="M17 18h1"/><path d="M12 18h1"/><path d="M7 18h1"/>',
  cloud:       '<path d="M17.5 19H9a7 7 0 1 1 6.71-9h1.79a4.5 4.5 0 1 1 0 9Z"/>',
  shield:      '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  lock:        '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  unlock:      '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
  edit:        '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
  partyPopper: '<path d="M5.8 11.3 2 22l10.7-3.79"/><path d="M4 3h.01"/><path d="M22 8h.01"/><path d="M15 2h.01"/><path d="M22 20h.01"/><path d="m22 2-2.24.75a2.9 2.9 0 0 0-1.96 3.12c.1.86-.57 1.63-1.45 1.63h-.38c-.86 0-1.6.6-1.76 1.44L14 10"/><path d="m22 13-1.53.84a2.91 2.91 0 0 1-3.18-.13c-.86-.6-2.08-.55-2.86.13l-.51.43"/><path d="M5 5c2 0 5 1 5 6 0 0 .35.21.61.34"/><path d="M3 21c.6-3.6 4-7 7-7"/>',
};

function _icon(name, size) {
  const body = _ICONS[name];
  if (!body) return '';
  const sz = size || 16;
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="${sz}" height="${sz}" aria-hidden="true">${body}</svg>`;
}

function _renderDrawerActions() {
  const id   = _drawerDeviceId;
  const name = _drawerDeviceName;
  const d    = _drawerDeviceData || {};
  const agentless = d.agentless;

  // Icon name (Lucide), label, fn (closure), danger flag, hidden flag
  const actions = [
    ['terminal',  'Run command',     () => { closeDeviceDrawer(); openExecModal(id, name); },                                                                                    false, agentless],
    ['refresh',   'Reboot',          () => { rebootTarget = id; closeDeviceDrawer(); openModal('reboot-modal'); document.getElementById('reboot-name').textContent = name; },    false, agentless],
    ['power',     'Shut down',       () => { shutdownTarget = id; closeDeviceDrawer(); openModal('shutdown-modal'); document.getElementById('shutdown-name').textContent = name; }, false, agentless],
    ['radio',     'Wake on LAN',     () => _wolWithMacCheck(id, name),                                                                                                            false, false],
    ['package',   'Upgrade packages', () => { closeDeviceDrawer(); upgradePackages(id, name); },                                                                                  false, agentless],
    ['search',    'Scan packages',   () => forcePackageScan(id, name, null),                                                                                                      false, agentless],
    ['monitor',   'Web terminal',    () => { closeDeviceDrawer(); openWebTerm(id, name); },                                                                                       false, agentless],
    ['fileCode',  'Run script',      () => { closeDeviceDrawer(); openScriptRunForDevice(id, name); },                                                                            false, agentless],
    ['download',  'Update agent',    () => { closeDeviceDrawer(); sendUpdate(id, name); },                                                                                        false, agentless],
    ['zap',       'Force-upgrade',   () => { closeDeviceDrawer(); forceAgentUpgrade(id, name); },                                                                                 true,  agentless],
    ['unplug',    'Uninstall agent', () => { closeDeviceDrawer(); uninstallAgent(id, name); },                                                                                    true,  agentless],
    ['ship',      'Docker compose',  () => { closeDeviceDrawer(); openComposeModal(id, name); },                                                                                  false, agentless],
    ['settings',  'Host config',     () => { closeDeviceDrawer(); openHostConfigModal(id, name); },                                                                               false, agentless],
    ['sparkles',  'AI Investigate',  () => aiInvestigateDevice(id, name),                                                                                                         false, false],
    ['clipboard', 'CMDB',            () => { closeDeviceDrawer(); cmdbOpenAsset(id); },                                                                                           false, false],
    ['bookOpen',  'Runbook',         () => { closeDeviceDrawer(); aiViewRunbook(id, name); },                                                                                     false, false],
    ['wrench',    'Maintenance',     () => { closeDeviceDrawer(); openNewMaintModal(); },                                                                                         false, false],
    ['clock',     'Adjust poll',     () => _drawerAdjustPoll(),                                                                                                                   false, agentless],
    ['trash',     'Remove device',   () => { closeDeviceDrawer(); deleteDevice(id, name); },                                                                                      true,  false],
  ];

  _drawerActMap.clear();
  document.getElementById('drawer-actions-grid').innerHTML = actions
    .filter(([,,,, hidden]) => !hidden)
    .map(([iconName, label, fn, danger]) => {
      const key = `da_${Math.random().toString(36).slice(2)}`;
      _drawerActMap.set(key, fn);
      return `<button class="drawer-action-btn${danger ? ' danger' : ''}" data-drawer-act="${key}">
        <span class="drawer-action-icon">${_icon(iconName, 18)}</span>
        <span>${escHtml(label)}</span>
      </button>`;
    }).join('');
}

async function _drawerAdjustPoll() {
  const d = _drawerDeviceData || {};
  const cur = d.poll_interval || 60;
  const val = prompt(`Poll interval for ${_drawerDeviceName} (seconds, min 30):`, cur);
  if (!val) return;
  const n = parseInt(val, 10);
  if (isNaN(n) || n < 30) { toast('Must be ≥ 30 seconds', 'error'); return; }
  const r = await api('POST', `/devices/${_drawerDeviceId}`, {poll_interval: n});
  if (r?.ok) { toast('Poll interval updated', 'success'); if (_drawerDeviceData) _drawerDeviceData.poll_interval = n; }
  else toast(r?.error || 'Failed', 'error');
}

// ── Settings tab (form) ───────────────────────────────────────────────────────

function _renderDrawerSettings() {
  const d    = _drawerDeviceData || {};
  const id   = _drawerDeviceId;
  const isAgentless = !!d.agentless;

  const watched   = (d.watched_services || []).join(', ');
  const driftList = (d.watched_files    || []).join('\n');
  const allowList = (d.cmd_allowlist    || []).join('\n');
  const logRules  = (d.log_watch        || []).map(r =>
    `${r.unit || '*'} : ${r.pattern}`).join('\n');

  document.getElementById('drawer-settings-form').innerHTML = `
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">Group</span>
      <input class="form-input isl-619" id="ds-group" value="${escAttr(d.group||'')}">
    </div>
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">Tags</span>
      <input class="form-input isl-619" id="ds-tags" value="${escAttr((d.tags||[]).join(', '))}" placeholder="prod, web, linux">
    </div>
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">Icon</span>
      <input class="form-input isl-620" id="ds-icon" value="${escAttr(d.icon||'')}" placeholder="e.g. monitor, server, cloud">
    </div>
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">Monitored</span>
      <label class="click-row-6">
        <input type="checkbox" id="ds-monitored" ${d.monitored !== false ? 'checked' : ''}>
        <span class="fs-12">Active monitoring</span>
      </label>
    </div>
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">${_icon('shield',14)} Quarantine</span>
      <label class="click-row-6">
        <input type="checkbox" id="ds-quarantine" ${d.quarantined ? 'checked' : ''} data-change="toggleQuarantine" data-change-arg="${escAttr(id)}">
        <span class="fs-12">Disable exec / reboot / actions on this host</span>
      </label>
      <span class="hint">Enforced server-side: queued commands are dropped while quarantined (poll-interval changes still apply). Admin only.</span>
    </div>
    ${isAgentless ? `
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">Reachability</span>
      <select class="form-input isl-621" id="ds-reachability" data-change="onReachabilityModeChange">
        <option value="icmp" ${(d.reachability || 'icmp') === 'icmp' ? 'selected' : ''}>ICMP ping</option>
        <option value="manual" ${(d.reachability || 'icmp') === 'manual' ? 'selected' : ''}>Manual (set Up/Down)</option>
      </select>
      <label class="click-row-6 ${(d.reachability || 'icmp') === 'manual' ? '' : 'd-none'}" id="ds-manual-status-row">
        <input type="checkbox" id="ds-manual-status" ${d.manual_status !== false ? 'checked' : ''}>
        <span class="fs-12">Device is up</span>
      </label>
      <span class="hint">ICMP pings the host each sweep; switch to Manual for hosts that block ping.</span>
    </div>` : ''}
    <div class="drawer-setting-row">
      <span class="drawer-setting-label">Poll interval</span>
      <input class="form-input isl-621" id="ds-poll" type="number" value="${d.poll_interval||60}" min="30">
      <span class="hint">seconds</span>
    </div>
    <div class="drawer-setting-row isl-622">
      <span class="drawer-setting-label isl-623">Watched services</span>
      <input class="form-input isl-619" id="ds-services" value="${escAttr(watched)}" placeholder="nginx, sshd, postfix">
    </div>
    <div class="drawer-setting-row isl-622">
      <span class="drawer-setting-label isl-623">Log watch rules</span>
      <textarea class="form-input isl-624" id="ds-logrules" rows="3" placeholder="sshd : Failed password\nnginx : 5[0-9][0-9]">${escHtml(logRules)}</textarea>
    </div>
    <div class="drawer-setting-row isl-622">
      <span class="drawer-setting-label isl-623">Drift watch files</span>
      <textarea class="form-input isl-624" id="ds-drift" rows="3" placeholder="/etc/nginx/nginx.conf\n/etc/hosts">${escHtml(driftList)}</textarea>
    </div>
    <div class="drawer-setting-row isl-622">
      <span class="drawer-setting-label isl-623">Command allowlist</span>
      <textarea class="form-input isl-624" id="ds-allowlist" rows="3" placeholder="systemctl status *\nnginx -t">${escHtml(allowList)}</textarea>
    </div>
    ${isAgentless ? `
    <!-- v3.2.0 (B5): SNMP polling — agentless devices only -->
    <div class="drawer-setting-row isl-622">
      <span class="drawer-setting-label isl-623">SNMP polling</span>
      <div id="ds-snmp-status" class="hint mb-8">Loading…</div>
      <label class="click-row-6">
        <input type="checkbox" id="ds-snmp-enabled">
        <span class="fs-12">Enable SNMPv2c polling (sys-group every 5 min)</span>
      </label>
    </div>
    <div class="drawer-setting-row isl-622">
      <span class="drawer-setting-label isl-623">Community / port</span>
      <div class="row-8-center">
        <input type="password" class="form-input isl-620" id="ds-snmp-community" placeholder="(keep current)" maxlength="128" autocomplete="off">
        <input type="number" class="form-input isl-621" id="ds-snmp-port" placeholder="161" min="1" max="65535">
        <button class="btn-icon" data-action="_drawerSnmpPollNow" type="button">Poll now</button>
      </div>
      <span class="hint">Community is write-only; the GET response shows only a 3-char preview.</span>
    </div>
    <div id="ds-snmp-feedback" class="mb-8"></div>
    ` : ''}
    <div class="isl-625">
      <button class="btn-primary isl-626" data-action="_drawerSaveSettings" >Save settings</button>
    </div>`;

  // Populate SNMP fields async (agentless only). Don't block the form
  // render on the round trip.
  if (isAgentless) _drawerLoadSnmpConfig(id);
}

async function _drawerLoadSnmpConfig(devId) {
  try {
    const r = await api('GET', `/devices/${encodeURIComponent(devId)}/snmp`);
    if (!r) return;
    const cfg = r.config || {};
    const data = r.data || {};
    const en = document.getElementById('ds-snmp-enabled');
    const port = document.getElementById('ds-snmp-port');
    const comm = document.getElementById('ds-snmp-community');
    const status = document.getElementById('ds-snmp-status');
    if (en)   en.checked = !!cfg.enabled;
    if (port) port.value = cfg.port || 161;
    if (comm) comm.placeholder = cfg.has_community
                ? `(keep current — preview: ${cfg.community_preview || '…'})`
                : 'public';
    if (status) {
      if (!cfg.enabled) {
        status.innerHTML = '<span class="c-muted">Disabled</span>';
      } else if (data.last_ok && !data.last_error) {
        status.innerHTML =
          `<span class="snmp-pill snmp-ok">SNMP OK</span> ` +
          `<span class="hint">${_formatTs(data.last_ok)} · sysName ${_escapeHtml(data.sysName || '?')}</span>`;
      } else if (data.last_error) {
        status.innerHTML =
          `<span class="snmp-pill snmp-fail">SNMP fail</span> ` +
          `<span class="hint">${_escapeHtml(data.last_error)}</span>`;
      } else {
        status.innerHTML = '<span class="hint">Enabled, never polled yet — click "Poll now"</span>';
      }
    }
  } catch (_) { /* viewer or transient — leave blank */ }
}

async function _drawerSnmpPollNow() {
  const id = _drawerDeviceId;
  if (!id) return;
  const fb = document.getElementById('ds-snmp-feedback');
  if (fb) fb.innerHTML = '<span class="sev-pill sev-medium">polling</span> Up to 4 s…';
  try {
    const r = await api('POST', `/devices/${encodeURIComponent(id)}/snmp/poll`, {});
    if (!r || !r.ok) {
      if (fb) fb.innerHTML = `<span class="sev-pill sev-critical">error</span> ${_escapeHtml((r && r.error) || 'unknown')}`;
      return;
    }
    if (r.data && r.data.last_ok) {
      if (fb) fb.innerHTML = `<span class="sev-pill sev-success">ok</span> sysName: ${_escapeHtml(r.data.sysName || '?')} · uptime ${r.data.sysUpTime}`;
      _drawerLoadSnmpConfig(id);   // refresh the status block
    } else {
      if (fb) fb.innerHTML = `<span class="sev-pill sev-critical">poll failed</span> ${_escapeHtml(r.data && r.data.last_error || 'unknown error')}`;
    }
  } catch (e) {
    if (fb) fb.innerHTML = `<span class="sev-pill sev-critical">error</span> ${_escapeHtml(e && e.message ? e.message : e)}`;
  }
}

async function _drawerSaveSettings() {
  const id = _drawerDeviceId;
  if (!id) return;

  const group    = document.getElementById('ds-group')?.value.trim() || '';
  const tagsRaw  = document.getElementById('ds-tags')?.value  || '';
  const icon     = document.getElementById('ds-icon')?.value.trim() || '';
  const monitored= document.getElementById('ds-monitored')?.checked;
  const poll     = parseInt(document.getElementById('ds-poll')?.value || '60', 10);
  const svcRaw   = document.getElementById('ds-services')?.value || '';
  const logRaw   = document.getElementById('ds-logrules')?.value || '';
  const driftRaw = document.getElementById('ds-drift')?.value || '';
  const allowRaw = document.getElementById('ds-allowlist')?.value || '';

  const tags     = tagsRaw.split(',').map(s=>s.trim()).filter(Boolean);
  const services = svcRaw.split(',').map(s=>s.trim()).filter(Boolean);
  const driftFiles = driftRaw.split('\n').map(s=>s.trim()).filter(s=>s.startsWith('/'));
  const allowlist  = allowRaw.split('\n').map(s=>s.trim()).filter(Boolean);

  // Parse log rules: "unit : pattern" per line
  const logWatch = logRaw.split('\n').map(l => {
    const [unit, ...rest] = l.split(':');
    return unit && rest.length ? {unit: unit.trim(), pattern: rest.join(':').trim()} : null;
  }).filter(Boolean);

  const body = {
    group, tags, icon, monitored,
    poll_interval: Math.max(30, poll),
    watched_services: services,
    log_watch: logWatch,
    watched_files: driftFiles,
    cmd_allowlist: allowlist,
  };

  // v3.3.4: agentless reachability mode + manual up/down (form only shows
  // these for agentless devices).
  const reachEl = document.getElementById('ds-reachability');
  if (reachEl) {
    body.reachability = reachEl.value;
    body.manual_status = !!document.getElementById('ds-manual-status')?.checked;
  }

  const r = await api('POST', `/devices/${id}`, body);
  if (r?.ok) toast('Settings saved', 'success');
  else { toast(r?.error || 'Failed to save', 'error'); return; }

  // v3.2.0 (B5): persist SNMP config too if the form has those inputs.
  // Separate endpoint because SNMP config is on the agentless device
  // record but has its own validation rules (community required when
  // enabled, port range 1..65535).
  const snmpEnabled = document.getElementById('ds-snmp-enabled');
  if (snmpEnabled) {
    const snmpBody = {
      enabled: snmpEnabled.checked,
      port:    parseInt(document.getElementById('ds-snmp-port')?.value || '161', 10),
    };
    const comm = document.getElementById('ds-snmp-community')?.value || '';
    if (comm) snmpBody.community = comm;
    const sr = await api('PATCH', `/devices/${id}/snmp`, snmpBody);
    if (sr?.ok) {
      toast('SNMP config saved', 'success');
      // Refresh the status block so the operator sees the new state
      _drawerLoadSnmpConfig(id);
      const c = document.getElementById('ds-snmp-community');
      if (c) c.value = '';
    } else {
      toast(sr?.error || 'SNMP save failed', 'error');
    }
  }
}

// ── Audit tab ─────────────────────────────────────────────────────────────────

// v3.3.0: audit-section icons now use Lucide SVGs via _icon(name).
// Each section's `icon` is a key from the _ICONS dictionary (defined
// near _renderDrawerActions). New section? Add an _ICONS entry too.
const _AUDIT_SECTIONS = [
  {key: 'sysinfo',   title: 'System Info',      icon: 'monitor'},
  {key: 'snmp',      title: 'SNMP',             icon: 'radio'},
  {key: 'ports',     title: 'Listening Ports',  icon: 'unplug'},
  {key: 'packages',  title: 'Packages',         icon: 'package'},
  {key: 'logs',      title: 'Logs',             icon: 'fileCode'},
  {key: 'commands',  title: 'Command History',  icon: 'terminal'},
  {key: 'events',    title: 'Fleet Events',     icon: 'radio'},
  {key: 'drift',     title: 'Drift State',      icon: 'search'},
  {key: 'cve',       title: 'CVE Summary',      icon: 'sparkles'},
  {key: 'containers',title: 'Containers',       icon: 'ship'},
  {key: 'metrics',   title: 'Metrics',          icon: 'clock'},
  {key: 'hostcfg',   title: 'Host Config',      icon: 'settings'},
  // v3.4.0
  {key: 'hardware',  title: 'Health & Hardware', icon: 'hardDrive'},
  {key: 'helm',      title: 'Helm Releases',    icon: 'cloud'},
];

function _renderDrawerAuditSections() {
  const el = document.getElementById('drawer-audit-sections');
  if (!el || el.dataset.rendered === _drawerDeviceId) return;
  el.dataset.rendered = _drawerDeviceId;

  // CSP L1 (v3.0.5 fix): the inline `onToggle="…"` attribute was
  // blocked by `script-src 'self'`. <details> has no `data-action`
  // equivalent through the delegated-click handler (toggle isn't a
  // click), so we attach the toggle listener directly after rendering.
  // v3.3.4: RouterOS (MikroTik) card — agentless devices only (that's how
  // routers are added); irrelevant on Linux agent hosts.
  const sections = _AUDIT_SECTIONS.slice();
  if (_drawerDeviceData && _drawerDeviceData.agentless) {
    sections.push({key: 'routeros', title: 'RouterOS (MikroTik)', icon: 'radio'});
    sections.push({key: 'opnsense', title: 'OPNsense', icon: 'shield'});
    sections.push({key: 'synology', title: 'Synology (DSM)', icon: 'server'});
  }
  el.innerHTML = sections.map(s =>
    `<details class="audit-section" id="audit-sec-${s.key}" data-audit-key="${s.key}">
      <summary>
        <span>${_icon(s.icon, 14)} ${s.title} <span class="audit-section-badge" id="audit-badge-${s.key}">collapsed</span></span>
      </summary>
      <div class="audit-section-body" id="audit-body-${s.key}">
        <div class="c-muted">Click to load…</div>
      </div>
    </details>`
  ).join('');
  // Wire the toggle event for each <details> after innerHTML.
  el.querySelectorAll('details[data-audit-key]').forEach(d => {
    d.addEventListener('toggle', () => _onAuditToggle(d.dataset.auditKey, d));
  });
}

function _onAuditToggle(key, el) {
  if (!el.open) return;
  if (_drawerAuditLoaded[key]) return;   // already loaded
  _drawerAuditLoaded[key] = true;
  _loadAuditSection(key);
}

async function _loadAuditSection(key) {
  const id   = _drawerDeviceId;
  const body = document.getElementById(`audit-body-${key}`);
  const badge= document.getElementById(`audit-badge-${key}`);
  if (!body || !id) return;
  body.innerHTML = '<div class="c-muted">Loading…</div>';

  try {
    switch (key) {

      case 'sysinfo': {
        const data = await api('GET', `/devices/${id}/sysinfo`);
        const si   = data?.sysinfo || {};
        const jrnl = data?.journal || [];
        if (!si.uptime && !jrnl.length) {
          body.innerHTML = '<div class="c-muted">No sysinfo yet — agent reports every ~10 min.</div>';
          return;
        }
        let h = '';
        const pills = [
          ['Uptime',    si.uptime],
          ['Platform',  si.platform],
          ['CPU count', si.cpu_count],
          ['Load avg',  si.loadavg],
          ['Last boot', si.last_boot ? new Date(si.last_boot*1000).toLocaleString() : null],
        ];
        h += `<div class="sysinfo-row isl-610">` +
          pills.filter(([,v])=>v!=null).map(([l,v])=>
            `<div class="sysinfo-pill"><div class="label">${l}</div><div class="value">${escHtml(String(v))}</div></div>`
          ).join('') + `</div>`;
        if ((si.network||[]).length) {
          h += `<div class="mb-8">` +
            si.network.map(n=>
              `<span class="cmd-badge fs-11">${escHtml(n.iface)}: ${escHtml(n.ip||'?')}</span> `
            ).join('') + `</div>`;
        }
        if ((si.mounts||[]).length) {
          h += `<table class="isl-627">
            <thead><tr class="c-muted"><th class="isl-628">Mount</th><th>Used</th><th>Total</th><th>%</th></tr></thead>
            <tbody>` + si.mounts.map(m=>
              `<tr><td class="isl-629"><code>${escHtml(m.path)}</code></td>
                   <td class="ta-center">${m.used_gb}GB</td>
                   <td class="ta-center">${m.total_gb}GB</td>
                   <td class="isl-630 ${m.percent>85?'c-red': m.percent>70?'c-amber': ''}">${m.percent}%</td></tr>`
            ).join('') + `</tbody></table>`;
        }
        if (jrnl.length) {
          h += `<div class="isl-631">Journal — last ${jrnl.length} lines</div>
                <div class="journal-wrap isl-632">${escHtml(jrnl.join('\n'))}</div>`;
        }
        body.innerHTML = h;
        badge.textContent = si.uptime || '';
        // AI investigate buttons
        if (jrnl.length) {
          const aiDiv = document.createElement('div');
          aiDiv.style.cssText = 'display:flex;gap:8px;margin-top:10px;flex-wrap:wrap';
          aiDiv.innerHTML = `
            <button class="btn-secondary fs-12"
              data-action-btn="_aiFindProblemBtn" data-dev-id="${escAttr(id)}" data-journal-sel=".journal-wrap" >
              ${_icon('sparkles',14)} Find the problem
            </button>
            <button class="btn-secondary fs-12"
              data-action="aiInvestigateDevice" data-arg="${escAttr(id)}" data-arg2="${escAttr(name)}" >
              ${_icon('sparkles',14)} Full investigation
            </button>`;
          body.appendChild(aiDiv);
        }
        break;
      }

      case 'ports': {
        const data = await api('GET', `/devices/${id}/sysinfo`);
        const ports = data?.sysinfo?.listening_ports || [];
        if (!ports.length) {
          body.innerHTML = '<div class="c-muted">No port data yet. Agent reports ports with sysinfo (~10 min).</div>';
          badge.textContent = 'none';
          return;
        }
        body.innerHTML = `
          <input class="audit-filter" placeholder="Filter ports…" data-input="_filterPorts" data-input-el="1" data-input-arg="${id}">
          <table class="ports-table isl-633" id="ports-tbl-${id}">
            <thead><tr class="isl-634">
              <th>Proto</th><th>Port</th><th>Process</th>
            </tr></thead>
            <tbody id="ports-body-${id}">
              ${ports.sort((a,b)=>a.port-b.port).map(p=>
                `<tr data-q="${escAttr(`${p.proto} ${p.port} ${p.process||''}`)}">
                  <td><code>${escHtml(p.proto)}</code></td>
                  <td><strong>${p.port}</strong></td>
                  <td class="c-muted">${escHtml(p.process||'—')}</td>
                </tr>`
              ).join('')}
            </tbody>
          </table>`;
        badge.textContent = `${ports.length} ports`;
        break;
      }

      case 'packages': {
        const data = await api('GET', `/devices/${id}/sysinfo`);
        const pkg  = data?.sysinfo?.packages || {};
        const upg  = pkg.upgradable ?? '?';
        body.innerHTML = `
          <div class="sysinfo-row isl-610">
            <div class="sysinfo-pill"><div class="label">Manager</div><div class="value">${escHtml(pkg.manager||'unknown')}</div></div>
            <div class="sysinfo-pill"><div class="label">Upgradable</div><div class="value isl-635 ${upg>0?'c-amber':'c-green'}">${upg}</div></div>
            <div class="sysinfo-pill"><div class="label">Last scan</div><div class="value">${data?.sysinfo?.pkg_scan_ts ? timeAgo(data.sysinfo.pkg_scan_ts) : '—'}</div></div>
          </div>
          <button class="btn-secondary fs-12" data-action-btn="_forcePackageScanBtn" data-dev-id="${id}" data-dev-name="${escAttr(_drawerDeviceName)}" >⟳ Scan now</button>`;
        badge.textContent = upg > 0 ? `${upg} upgradable` : 'up to date';
        break;
      }

      case 'logs': {
        const devs = await api('GET', '/devices');
        const dev  = (devs||[]).find(d=>d.id===id) || {};
        const units= Object.keys(dev.journal_units || {});
        if (!units.length) {
          // try fetching from sysinfo endpoint as fallback
          const data = await api('GET', `/devices/${id}/sysinfo`);
          const jrnl = data?.journal || [];
          if (!jrnl.length) {
            body.innerHTML = '<div class="c-muted">No log data yet.</div>';
            return;
          }
          body.innerHTML = `<div class="journal-wrap isl-636">${escHtml(jrnl.join('\n'))}</div>`;
          badge.textContent = `${jrnl.length} lines`;
          return;
        }
        // Fetch all unit logs and let user filter
        const logData = await api('GET', `/logs?device_id=${encodeURIComponent(id)}&limit=100`);
        const entries = logData?.entries || logData?.logs || [];
        badge.textContent = `${entries.length} entries`;
        body.innerHTML = `
          <input class="audit-filter" id="log-filter-${id}" placeholder="Filter by unit or text…"
                 data-input="_filterLogs" data-input-arg="${id}">
          <div id="log-lines-${id}" class="isl-637">
            ${entries.length
              ? entries.map(e=>
                  `<div class="log-line" data-unit="${escAttr(e.unit||'')}" data-line="${escAttr(e.line||e.msg||'')}">
                    <span class="log-unit-badge">${escHtml(e.unit||'—')}</span>
                    <span class="journal-wrap fs-11">${escHtml(e.line||e.msg||'')}</span>
                  </div>`
                ).join('')
              : '<div class="c-muted">No log entries.</div>'}
          </div>`;
        break;
      }

      case 'commands': {
        const data = await api('GET', `/devices/${id}/output`);
        const outputs = (data?.outputs || []).slice().reverse();
        if (!outputs.length) {
          body.innerHTML = '<div class="c-muted">No commands run yet.</div>';
          badge.textContent = 'none';
          return;
        }
        // Show last 5 by default (v2.9.0: collapsed, expand button)
        const recent = outputs.slice(0, 5);
        const older  = outputs.slice(5);
        const renderCmds = (cmds) => cmds.map((o, i) => {
          const rc    = o.rc ?? o.exit_code ?? '?';
          const ts    = o.ts ? new Date(o.ts*1000).toLocaleString() : '';
          const outTxt= o.output || o.stdout || '(no output)';
          return `<div class="audit-cmd-entry" id="cmd-entry-${id}-${i}">
            <div class="audit-cmd-summary" data-action="toggleAuditCmd" data-arg="${id}" data-arg2="${i}">
              <code class="isl-638">${escHtml(o.cmd||'?')}</code>
              <span class="isl-639">rc=${rc} · ${ts}</span>
              <span class="isl-640">▶</span>
            </div>
            <div class="audit-cmd-output">${escHtml(outTxt)}</div>
          </div>`;
        }).join('');
        body.innerHTML = renderCmds(recent) +
          (older.length
            ? `<div id="older-cmds-${id}" class="d-none">${renderCmds(older)}</div>
               <button class="btn-secondary isl-641" data-action="_showOlderCmds" data-arg="${id}" >Show ${older.length} older commands</button>`
            : '');
        badge.textContent = `${outputs.length} commands`;
        break;
      }

      case 'events': {
        const data = await api('GET', `/fleet/events?device_id=${encodeURIComponent(id)}&limit=30`);
        const evs  = Array.isArray(data) ? data : (data?.events || data?.items || []);
        if (!evs.length) {
          body.innerHTML = '<div class="c-muted">No fleet events for this device.</div>';
          badge.textContent = 'none';
          return;
        }
        badge.textContent = `${evs.length}`;
        body.innerHTML = evs.slice(0,30).map(ev => {
          const p = ev.payload || {};
          const cls = EVENT_CLASS[ev.event] || 'info';
          return `<div class="isl-642">
            <span class="activity-dot ${cls}"></span>
            <div class="isl-445">
              <div class="fs-12">${escHtml((ev.event||'').replace(/_/g,' '))}</div>
              <div class="meta-sm-nm">${ev.ts ? timeAgo(ev.ts) : ''}</div>
            </div>
          </div>`;
        }).join('');
        break;
      }

      case 'drift': {
        const data = await api('GET', '/drift');
        const devDrift = (data?.drifts || data || []).find?.(d=>d.device_id===id)
                      || (typeof data==='object' && data[id]) || null;
        if (!devDrift) {
          body.innerHTML = '<div class="c-muted">No drift state for this device.</div>';
          badge.textContent = 'clean';
          return;
        }
        const drifted = devDrift.drifted || devDrift.files || [];
        badge.textContent = drifted.length ? `${drifted.length} changed` : 'clean';
        body.innerHTML = !drifted.length
          ? '<div class="c-green">All watched files at baseline.</div>'
          : drifted.map(f =>
              `<div class="isl-643">
                <code class="c-amber">${escHtml(f.path||f)}</code>
                ${f.changed_at ? `<span class="meta-sm-nm"> · ${timeAgo(f.changed_at)}</span>` : ''}
               </div>`
            ).join('');
        break;
      }

      case 'cve': {
        // Use the per-device endpoint which returns the full findings list
        const data = await api('GET', `/devices/${id}/cve`);
        if (!data || data.error) {
          // Fallback: try fleet summary
          const fleet = await api('GET', '/cve/findings');
          const devCve = (fleet?.devices || []).find(d => d.device_id === id);
          if (!devCve) {
            body.innerHTML = '<div class="c-muted">No CVE data for this device yet.</div>';
            badge.textContent = 'none'; return;
          }
          const c = devCve.counts || {};
          badge.textContent = c.critical > 0 ? `${c.critical} critical` : c.high > 0 ? `${c.high} high` : 'clean';
          body.innerHTML = `<div class="sysinfo-row">` +
            ['critical','high','medium','low'].map(s =>
              `<div class="sysinfo-pill"><div class="label">${s}</div>
               <div class="value isl-644">${c[s]||0}</div></div>`
            ).join('') + '</div>';
          break;
        }
        const findings = data.findings || [];
        // Group by severity — correct accumulation
        const bySev = {};
        for (const f of findings) {
          const sev = f.severity || 'unknown';
          if (!bySev[sev]) bySev[sev] = [];
          bySev[sev].push(f);
        }
        const crit = (bySev.critical||[]).length;
        const high = (bySev.high||[]).length;
        badge.textContent = crit > 0 ? `${crit} critical` : high > 0 ? `${high} high` : findings.length ? `${findings.length} total` : 'clean';
        body.innerHTML = `
          <div class="sysinfo-row isl-610">
            ${['critical','high','medium','low'].map(sev =>
              `<div class="sysinfo-pill">
                <div class="label">${sev}</div>
                <div class="value isl-645">${(bySev[sev]||[]).length}</div>
              </div>`
            ).join('')}
          </div>` +
          ['critical','high','medium','low'].filter(s => bySev[s]?.length).map(sev => {
            const col = sev==='critical'?'var(--red)':sev==='high'?'var(--amber)':'var(--muted)';
            return `<div class="mb-6">
              <div class="isl-646" data-color="${col}">${sev}</div>
              ${bySev[sev].slice(0,5).map(f =>
                `<div class="isl-647">
                  <code class="isl-648" data-color="${col}">${escHtml(f.cve_id||f.vuln_id||f.id||'')}</code>
                  <span class="c-muted"> — ${escHtml(f.package||f.pkg||'')} ${escHtml(f.version||'')}</span>
                </div>`).join('')}
              ${bySev[sev].length>5 ? `<div class="meta-sm-nm">…and ${bySev[sev].length-5} more</div>` : ''}
            </div>`;
          }).join('') ||
          '<div class="c-green">No CVEs found.</div>';
        break;
      }

      case 'containers': {
        // Use per-device endpoint — returns {items:[...]} matching containersOpen()
        const data = await api('GET', `/devices/${id}/containers`);
        const ctrs = data?.items || data?.containers || [];
        if (!ctrs.length) {
          body.innerHTML = '<div class="c-muted">No container data for this device.</div>';
          badge.textContent = 'none'; return;
        }
        badge.textContent = `${ctrs.length} container${ctrs.length!==1?'s':''}`;
        body.innerHTML = `<table class="isl-649">
          <thead><tr class="c-muted">
            <th class="isl-650">Name</th>
            <th>Status</th><th>Image</th>
          </tr></thead>
          <tbody>
            ${ctrs.map(c => {
              const stat = (c.status || c.State || '').toLowerCase();
              const up   = stat.includes('up ') || stat.includes('running') || stat === 'running';
              const col  = up ? 'var(--green)' : stat.includes('exit') ? 'var(--red)' : 'var(--muted)';
              const img  = (c.image || c.Image || '—').split(':')[0];
              return `<tr class="border-top">
                <td class="isl-651"><code>${escHtml(c.name||c.Names||'?')}</code></td>
                <td class="isl-652" data-color="${col}">${escHtml(c.status||c.State||'?')}</td>
                <td class="isl-653">${escHtml(img)}</td>
              </tr>`;
            }).join('')}
          </tbody></table>`;
        break;
      }

      case 'metrics': {
        // Read from the devices list which always has fresh sysinfo metrics
        const devs  = await api('GET', '/devices');
        const dev   = (devs || []).find(d => d.id === id);
        const si    = dev?.sysinfo || {};
        const mst   = dev?.metric_state || {};
        const rootM = (si.mounts||[]).find(m => m.path === '/');
        const pairs = [
          ['CPU',    si.cpu_percent,   'cpu:'],
          ['Memory', si.mem_percent,   'memory:'],
          ['Swap',   si.swap_percent,  'swap:'],
          ['Load',   si.loadavg_1m,    'cpu:'],
          ['Disk /', rootM?.percent,   'disk:/'],
        ].filter(([,v]) => v != null && typeof v === 'number');
        if (!pairs.length) {
          body.innerHTML = '<div class="c-muted">No metric data yet — agent needs psutil.</div>';
          badge.textContent = 'none';
          return;
        }
        badge.textContent = 'loaded';
        body.innerHTML = `<div class="sysinfo-row">` +
          pairs.map(([k, v, sk]) => {
            const lv  = mst[sk] || 'ok';
            const col = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'inherit';
            return `<div class="sysinfo-pill">
              <div class="label">${escHtml(k)}</div>
              <div class="value isl-648">${v.toFixed(1)}%</div>
            </div>`;
          }).join('') + `</div>`;
        break;
      }

      case 'snmp': {
        // v3.2.0: deep SNMP read — sys-group, ifTable, Host Resources MIB,
        // vendor-specific (Mikrotik). Slower than the standard 5-min poll
        // (multiple round trips), so it's on-demand only.
        let data;
        try {
          data = await api('GET', `/devices/${id}/snmp/deep`);
        } catch (e) {
          body.innerHTML = `<div class="c-muted">SNMP not configured or unreachable.</div>`;
          badge.textContent = 'n/a';
          return;
        }
        if (!data || data.error) {
          body.innerHTML = `<div class="c-red">${escHtml((data && data.error) || 'request failed')}</div>`;
          badge.textContent = 'error';
          return;
        }
        const sysObj = (data.system || {}).sysObjectID || '';
        const isMikrotik = sysObj.startsWith('1.3.6.1.4.1.14988');
        let h = '';
        // Sys-group
        if (data.system) {
          h += '<h4 class="mt-0">System</h4><table class="fs-13">';
          for (const [k, v] of Object.entries(data.system)) {
            if (k === '_oids') continue;
            h += `<tr><td class="c-muted-padded">${escHtml(k)}</td><td>${escHtml(String(v ?? '—'))}</td></tr>`;
          }
          h += '</table>';
        }
        // Per-CPU load (hrProcessorTable — Mikrotik + Linux + BSD)
        if (Array.isArray(data.processors) && data.processors.length) {
          h += '<h4 class="mt-12">CPU load (per core)</h4>';
          h += '<div class="sysinfo-row">';
          for (const p of data.processors) {
            const v = p.load_pct;
            const col = (v ?? 0) > 80 ? 'var(--red)' : (v ?? 0) > 50 ? 'var(--amber)' : 'var(--green)';
            h += `<div class="sysinfo-pill">
              <div class="label">CPU ${p.index}</div>
              <div class="value isl-348" data-color="${col}">${v != null ? v + '%' : '—'}</div>
            </div>`;
          }
          h += '</div>';
        }
        // UCD-SNMP load averages + memory (net-snmp boxes)
        if (data.ucd_snmp && Object.keys(data.ucd_snmp).length) {
          const u = data.ucd_snmp;
          h += '<h4 class="mt-12">Load &amp; memory (UCD-SNMP)</h4>';
          if (u.laLoad_1m != null) {
            h += '<div class="sysinfo-row">' +
              `<div class="sysinfo-pill"><div class="label">Load 1m</div><div class="value">${u.laLoad_1m.toFixed(2)}</div></div>` +
              `<div class="sysinfo-pill"><div class="label">Load 5m</div><div class="value">${(u.laLoad_5m ?? 0).toFixed(2)}</div></div>` +
              `<div class="sysinfo-pill"><div class="label">Load 15m</div><div class="value">${(u.laLoad_15m ?? 0).toFixed(2)}</div></div>` +
              '</div>';
          }
          if (u.memTotalReal && u.memAvailReal) {
            const usedKb = u.memTotalReal - u.memAvailReal;
            const usedPct = (usedKb / u.memTotalReal * 100).toFixed(1);
            const col = usedPct > 90 ? 'var(--red)' : usedPct > 75 ? 'var(--amber)' : 'inherit';
            h += `<div class="mt-8 fs-13"><strong>Real memory:</strong> <span data-color="${col}">${(usedKb/1024).toFixed(0)} / ${(u.memTotalReal/1024).toFixed(0)} MB (${usedPct}%)</span></div>`;
          }
          if (u.memTotalSwap && u.memAvailSwap != null) {
            const swapUsedKb = u.memTotalSwap - u.memAvailSwap;
            const swapPct = u.memTotalSwap > 0 ? (swapUsedKb / u.memTotalSwap * 100).toFixed(1) : '0.0';
            h += `<div class="fs-13"><strong>Swap:</strong> ${(swapUsedKb/1024).toFixed(0)} / ${(u.memTotalSwap/1024).toFixed(0)} MB (${swapPct}%)</div>`;
          }
          if (u.ssCpuRawUser != null) {
            h += `<div class="hint mt-4">Raw CPU ticks (deltas tell you %): user=${u.ssCpuRawUser} system=${u.ssCpuRawSystem ?? '?'} idle=${u.ssCpuRawIdle ?? '?'} wait=${u.ssCpuRawWait ?? '?'}</div>`;
          }
        }
        // Vendor-specific — Mikrotik
        if (data.mikrotik && Object.keys(data.mikrotik).length) {
          h += '<h4 class="mt-12">Mikrotik vendor</h4><table class="fs-13">';
          const labels = {
            mtxrSystemVersion:  'RouterOS version',
            mtxrSystemUptime:   'Uptime (1/100 s)',
            mtxrHlCoreVoltage:  'Core voltage (mV)',
            mtxrHlTemperature:  'CPU temperature (°C)',
            mtxrHlBoardTemp:    'Board temperature (°C)',
            mtxrHlCpuFrequency: 'CPU frequency (MHz)',
          };
          for (const [k, v] of Object.entries(data.mikrotik)) {
            let display = String(v ?? '—');
            if (k === 'mtxrHlBoardTemp' && typeof v === 'number') display = (v / 10).toFixed(1) + ' °C';
            if (k === 'mtxrHlTemperature' && typeof v === 'number') display = (v / 10).toFixed(1) + ' °C';
            h += `<tr><td class="c-muted-padded">${escHtml(labels[k] || k)}</td><td>${escHtml(display)}</td></tr>`;
          }
          h += '</table>';
        }
        // Vendor-specific — Ubiquiti UniFi
        if (data.ubnt && Object.keys(data.ubnt).length) {
          h += '<h4 class="mt-12">Ubiquiti UniFi</h4><table class="fs-13">';
          const labels = {
            unifiApSystemModel:   'Model',
            unifiApSystemVersion: 'Firmware',
            airosVersion:         'AirOS version',
          };
          for (const [k, v] of Object.entries(data.ubnt)) {
            if (k === 'radios') continue;   // rendered separately
            h += `<tr><td class="c-muted-padded">${escHtml(labels[k] || k)}</td><td>${escHtml(String(v ?? '—'))}</td></tr>`;
          }
          h += '</table>';
          if (Array.isArray(data.ubnt.radios) && data.ubnt.radios.length) {
            h += '<table class="fs-13 mt-8"><thead><tr><th>Radio</th><th class="ta-right">Clients</th></tr></thead><tbody>';
            for (const r of data.ubnt.radios) {
              h += `<tr><td>${escHtml(r.name || `radio${r.index}`)}</td><td class="ta-right">${r.clients ?? 0}</td></tr>`;
            }
            h += '</tbody></table>';
          }
        }
        // Host Resources MIB
        if (data.host_resources && Object.keys(data.host_resources).length) {
          h += '<h4 class="mt-12">Host Resources MIB</h4><table class="fs-13">';
          const labels = {
            hrSystemUptime:     'Uptime (1/100 s)',
            hrSystemNumUsers:   'Logged-in users',
            hrSystemProcesses:  'Running processes',
            hrMemorySize:       'Physical memory (kB)',
          };
          for (const [k, v] of Object.entries(data.host_resources)) {
            h += `<tr><td class="c-muted-padded">${escHtml(labels[k] || k)}</td><td>${escHtml(String(v ?? '—'))}</td></tr>`;
          }
          h += '</table>';
        }
        // Storage table
        if (Array.isArray(data.storage) && data.storage.length) {
          h += '<h4 class="mt-12">Storage</h4><table class="fs-13"><thead><tr><th>Mount</th><th class="ta-right">Size</th><th class="ta-right">Used</th><th class="ta-right">%</th></tr></thead><tbody>';
          for (const s of data.storage) {
            const sizeMb = s.size_bytes ? (s.size_bytes / 1024 / 1024).toFixed(0) : '?';
            const usedMb = s.used_bytes != null ? (s.used_bytes / 1024 / 1024).toFixed(0) : '?';
            const pct = s.used_pct != null ? `${s.used_pct}%` : '—';
            const pctCls = (s.used_pct ?? 0) > 90 ? 'c-red' : (s.used_pct ?? 0) > 70 ? 'c-amber' : '';
            h += `<tr><td>${escHtml(s.descr || '?')}</td><td class="ta-right">${sizeMb} MB</td><td class="ta-right">${usedMb} MB</td><td class="ta-right ${pctCls}">${pct}</td></tr>`;
          }
          h += '</tbody></table>';
        }
        // v3.3.4: Synology DSM health (system + disks + RAID/volumes)
        if (data.synology && (data.synology.system || (data.synology.disks||[]).length)) {
          const syn = data.synology;
          const sy = syn.system || {};
          const okBadge = (v) => v === 'normal'
            ? '<span class="status-pill ok">normal</span>'
            : (v ? `<span class="status-pill critical">${escHtml(v)}</span>` : '—');
          h += '<h4 class="mt-12">Synology</h4>';
          h += `<div class="hint mb-6">${escHtml(sy.model || 'Synology')}${sy.dsm_version ? ' · ' + escHtml(sy.dsm_version) : ''}${sy.serial ? ' · ' + escHtml(sy.serial) : ''}</div>`;
          h += '<table class="fs-13"><tbody>';
          h += `<tr><td class="c-muted-padded">System</td><td>${okBadge(sy.system)}</td></tr>`;
          h += `<tr><td class="c-muted-padded">Power</td><td>${okBadge(sy.power)}</td></tr>`;
          h += `<tr><td class="c-muted-padded">Fan</td><td>${okBadge(sy.fan)}</td></tr>`;
          if (sy.temperature_c != null) {
            const tCls = sy.temperature_c > 65 ? 'c-red' : sy.temperature_c > 55 ? 'c-amber' : '';
            h += `<tr><td class="c-muted-padded">Temperature</td><td class="${tCls}">${sy.temperature_c}°C</td></tr>`;
          }
          if (sy.upgrade) h += `<tr><td class="c-muted-padded">DSM update</td><td>${sy.upgrade === 'available' ? '<span class="c-amber">available</span>' : escHtml(sy.upgrade)}</td></tr>`;
          h += '</tbody></table>';
          if ((syn.disks || []).length) {
            h += '<table class="fs-13 mt-6"><thead><tr><th>Disk</th><th>Model</th><th>Status</th><th class="ta-right">Temp</th></tr></thead><tbody>';
            for (const d of syn.disks) {
              const dCls = d.status && d.status !== 'normal' ? 'c-red' : '';
              const dt = d.temperature_c != null ? `${d.temperature_c}°C` : '—';
              h += `<tr><td><strong>${escHtml(d.id || '?')}</strong></td><td class="hint">${escHtml(d.model || '—')}</td><td class="${dCls}">${escHtml(d.status || '—')}</td><td class="ta-right">${dt}</td></tr>`;
            }
            h += '</tbody></table>';
          }
          if ((syn.volumes || []).length) {
            h += '<table class="fs-13 mt-6"><thead><tr><th>Volume</th><th>Status</th></tr></thead><tbody>';
            for (const v of syn.volumes) {
              const vCls = v.status && v.status !== 'normal' ? 'c-red' : '';
              h += `<tr><td><strong>${escHtml(v.name || '?')}</strong></td><td class="${vCls}">${escHtml(v.status || '—')}</td></tr>`;
            }
            h += '</tbody></table>';
          }
          h += '<div class="hint mt-6">DSM upgrade is in the <strong>Synology (DSM)</strong> section below.</div>';
        }
        // Interface table
        if (Array.isArray(data.interfaces) && data.interfaces.length) {
          h += `<h4 class="mt-12">Interfaces (${data.interfaces.length})</h4>`;
          h += '<table class="fs-13"><thead><tr><th>Name</th><th>Admin</th><th>Oper</th><th class="ta-right">Speed</th><th class="ta-right">In</th><th class="ta-right">Out</th><th class="ta-right">Errs</th></tr></thead><tbody>';
          for (const ifn of data.interfaces) {
            const speedMbps = ifn.speed_bps ? Math.round(ifn.speed_bps / 1e6) + ' Mbps' : '—';
            const upCls = ifn.oper === 'up' ? 'c-green' : 'c-muted';
            const fmtB = (b) => {
              if (!b || b < 1024) return String(b || 0);
              const u = ['B','KB','MB','GB','TB']; let i=0; let v=b;
              while (v >= 1024 && i < u.length-1) { v /= 1024; i++; }
              return v.toFixed(v < 10 ? 1 : 0) + u[i];
            };
            const errs = (ifn.in_errors || 0) + (ifn.out_errors || 0);
            const errCls = errs > 0 ? 'c-amber' : '';
            h += `<tr><td><strong>${escHtml(ifn.descr || `if${ifn.index}`)}</strong></td><td>${escHtml(ifn.admin)}</td><td class="${upCls}">${escHtml(ifn.oper)}</td><td class="ta-right">${speedMbps}</td><td class="ta-right">${fmtB(ifn.in_octets)}</td><td class="ta-right">${fmtB(ifn.out_octets)}</td><td class="ta-right ${errCls}">${errs}</td></tr>`;
          }
          h += '</tbody></table>';
        }
        // Errors
        if (data.errors && Object.keys(data.errors).length) {
          h += '<h4 class="mt-12">Partial errors</h4><ul class="hint">';
          for (const [k, v] of Object.entries(data.errors)) {
            h += `<li><code>${escHtml(k)}</code>: ${escHtml(v)}</li>`;
          }
          h += '</ul>';
        }
        const counts = [];
        if (data.interfaces?.length) counts.push(`${data.interfaces.length} if`);
        if (data.processors?.length) counts.push(`${data.processors.length} cpu`);
        if (data.storage?.length)    counts.push(`${data.storage.length} stor`);
        if (data.ucd_snmp && Object.keys(data.ucd_snmp).length) counts.push('ucd');
        if (data.mikrotik && Object.keys(data.mikrotik).length) counts.push('mikrotik');
        if (data.ubnt && Object.keys(data.ubnt).length) counts.push('ubnt');
        if (data.synology && (data.synology.disks || []).length) counts.push(`synology ${data.synology.disks.length}d`);
        else if (data.synology) counts.push('synology');
        badge.textContent = counts.join(' · ') || 'loaded';
        body.innerHTML = h || '<div class="c-muted">No SNMP data returned.</div>';
        break;
      }

      case 'routeros': {
        const data = await api('GET', `/devices/${id}/routeros`);
        _renderRouterosCard(body, badge, data || {});
        break;
      }

      case 'opnsense': {
        const data = await api('GET', `/devices/${id}/opnsense`);
        _renderOpnsenseCard(body, badge, data || {});
        break;
      }

      case 'synology': {
        await _renderSynologyCard(body, badge);
        break;
      }

      case 'hostcfg': {
        const data = await api('GET', `/devices/${id}/host-config`);
        const cfg  = data?.current || data || {};
        if (!cfg || !Object.keys(cfg).length) {
          body.innerHTML = '<div class="c-muted">No host config state collected yet.</div>';
          badge.textContent = 'none';
          return;
        }
        badge.textContent = 'loaded';
        body.innerHTML = `<pre class="isl-654">${escHtml(JSON.stringify(cfg, null, 2))}</pre>`;
        break;
      }

      // v3.4.0: SMART, kernel/livepatch, passive inventory, disk-fill
      // forecast, "what changed", plus on-demand speedtest + LAN discovery.
      case 'hardware': {
        const [hw, fc, ch] = await Promise.all([
          api('GET', `/devices/${id}/hardware`),
          api('GET', `/devices/${id}/forecast`).catch(() => ({})),
          api('GET', `/devices/${id}/changes?days=7`).catch(() => ({})),
        ]);
        body.innerHTML = _renderHardwareSection(id, hw || {}, fc || {}, ch || {});
        const disks = (hw && hw.smart) || [];
        const failed = disks.filter(d => d.health && d.health !== 'PASSED').length;
        badge.textContent = failed ? `${failed} disk alert${failed>1?'s':''}`
                          : (disks.length ? `${disks.length} disk${disks.length>1?'s':''}` : 'no data');
        if (disks.length) {
          tableCtl.wireSortOnly('hw-smart-thead', 'hw_smart',
            () => _loadAuditSectionForce('hardware'));
        }
        break;
      }

      case 'helm': {
        const data = await api('GET', `/devices/${id}/helm`);
        const rels = (data && data.releases) || [];
        if (!rels.length) {
          body.innerHTML = '<div class="c-muted">No Helm releases reported. The agent runs <code>helm list -A</code> when helm + a kubeconfig are present.</div>';
          badge.textContent = 'none';
          break;
        }
        tableCtl.wireSortOnly('helm-thead', 'helm', () => _loadAuditSectionForce('helm'));
        const rows = tableCtl.sortRows('helm', rels, r => ({
          name: r.name, namespace: r.namespace, chart: r.chart,
          status: r.status, revision: parseInt(r.revision, 10) || 0,
        }));
        body.innerHTML = `<table class="audit-table">
          <thead id="helm-thead"><tr>
            <th data-col="name">Release</th><th data-col="namespace">Namespace</th>
            <th data-col="chart">Chart</th><th data-col="status">Status</th>
            <th data-col="revision">Rev</th></tr></thead>
          <tbody>` + rows.map(r => {
            const ok = String(r.status).toLowerCase() === 'deployed';
            return `<tr><td>${escHtml(r.name)}</td><td>${escHtml(r.namespace)}</td>
              <td><code>${escHtml(r.chart)}</code></td>
              <td class="${ok?'c-green':'c-amber'}">${escHtml(r.status)}</td>
              <td class="ta-center">${escHtml(r.revision)}</td></tr>`;
          }).join('') + `</tbody></table>`;
        badge.textContent = `${rels.length} release${rels.length>1?'s':''}`;
        break;
      }

      default:
        body.innerHTML = `<div class="c-muted">Section "${key}" not implemented.</div>`;
    }
  } catch(err) {
    body.innerHTML = `<div class="c-red">Error loading: ${escHtml(String(err))}</div>`;
    if (_drawerAuditLoaded[key]) delete _drawerAuditLoaded[key]; // allow retry
  }
}

// v3.4.0: force a re-render of one audit section (used by sort + after an
// on-demand action completes).
function _loadAuditSectionForce(key) {
  _drawerAuditLoaded[key] = true;
  _loadAuditSection(key);
}

function _fmtDays(d) {
  if (d == null) return '—';
  if (d < 1)   return '<1 day';
  if (d < 60)  return `${Math.round(d)} days`;
  return `${(d/30).toFixed(1)} months`;
}

function _renderHardwareSection(id, hw, fc, ch) {
  let h = '';
  const k = hw.kernel || {};

  // ── Kernel / livepatch ────────────────────────────────────────────
  if (k.running) {
    const stale = k.reboot_for_kernel;
    h += `<div class="hw-block"><div class="hw-h">Kernel</div>
      <div class="sysinfo-row isl-610">
        <div class="sysinfo-pill"><div class="label">Running</div><div class="value"><code>${escHtml(k.running)}</code></div></div>
        ${k.latest_installed ? `<div class="sysinfo-pill"><div class="label">Newest installed</div><div class="value"><code>${escHtml(k.latest_installed)}</code></div></div>` : ''}
        <div class="sysinfo-pill"><div class="label">Reboot for kernel</div><div class="value ${stale?'c-amber':'c-green'}">${stale ? 'Yes — newer kernel installed' : 'No'}</div></div>
        ${k.livepatch ? `<div class="sysinfo-pill"><div class="label">Livepatch</div><div class="value">${escHtml(k.livepatch.provider||'')} ${k.livepatch.patched?'<span class="c-green">applied</span>':''}</div></div>` : ''}
      </div></div>`;
  }

  // ── SMART ──────────────────────────────────────────────────────────
  const disks = hw.smart || [];
  if (disks.length) {
    const sorted = tableCtl.sortRows('hw_smart', disks, d => ({
      device: d.device, health: d.health, model: d.model,
      realloc: d.reallocated_sectors || 0, pending: d.pending_sectors || 0,
      temp: d.temperature_c || 0, hours: d.power_on_hours || 0,
    }));
    h += `<div class="hw-block"><div class="hw-h">SMART disk health</div>
      <table class="audit-table"><thead id="hw-smart-thead"><tr>
        <th data-col="device">Device</th><th data-col="model">Model</th>
        <th data-col="health">Health</th><th data-col="realloc">Realloc</th>
        <th data-col="pending">Pending</th><th data-col="temp">Temp</th>
        <th data-col="hours">Power-on h</th></tr></thead><tbody>` +
      sorted.map(d => {
        const ok = d.health === 'PASSED';
        return `<tr><td><code>${escHtml(d.device)}</code></td>
          <td>${escHtml(d.model||'—')}</td>
          <td class="${ok?'c-green':'c-red'}">${escHtml(d.health||'?')}</td>
          <td class="ta-center ${(d.reallocated_sectors||0)>0?'c-red':''}">${d.reallocated_sectors??'—'}</td>
          <td class="ta-center ${(d.pending_sectors||0)>0?'c-red':''}">${d.pending_sectors??'—'}</td>
          <td class="ta-center">${d.temperature_c!=null?d.temperature_c+'°C':'—'}</td>
          <td class="ta-center">${d.power_on_hours??'—'}</td></tr>`;
      }).join('') + `</tbody></table></div>`;
  }

  // ── Forecast ───────────────────────────────────────────────────────
  const mounts = (fc && fc.mounts) || [];
  const risers = mounts.filter(m => m.days_to_full != null);
  if (risers.length) {
    h += `<div class="hw-block"><div class="hw-h">Disk-fill forecast <span class="c-muted fs-11">(${fc.sample_days||0} daily samples)</span></div>
      <table class="audit-table"><thead><tr>
        <th>Mount</th><th>Used</th><th>Trend</th><th>Fills in</th></tr></thead><tbody>` +
      risers.map(m => `<tr><td><code>${escHtml(m.path)}</code></td>
        <td class="ta-center">${m.current_percent}%</td>
        <td class="ta-center">${m.trend_gb_per_day} GB/day</td>
        <td class="ta-center ${m.days_to_full<14?'c-red':m.days_to_full<45?'c-amber':''}">${_fmtDays(m.days_to_full)}</td></tr>`
      ).join('') + `</tbody></table></div>`;
  }

  // ── What changed (7 days) ──────────────────────────────────────────
  const changes = (ch && ch.changes) || [];
  if (changes.length) {
    h += `<div class="hw-block"><div class="hw-h">What changed (last 7 days)</div>
      <ul class="hw-changes">` + changes.map(c => `<li>${escHtml(c)}</li>`).join('') + `</ul></div>`;
  }

  // ── Passive inventory ──────────────────────────────────────────────
  const inv = hw.hardware || {};
  if (inv.system || (inv.memory||[]).length || (inv.temps||[]).length || (inv.raid||[]).length) {
    h += `<div class="hw-block"><div class="hw-h">Inventory</div>`;
    if (inv.system) {
      h += `<div class="mb-8">${['manufacturer','product','serial'].filter(x=>inv.system[x]).map(x=>`<span class="cmd-badge fs-11">${x}: ${escHtml(inv.system[x])}</span>`).join(' ')}</div>`;
    }
    if ((inv.memory||[]).length) {
      h += `<div class="fs-11 c-muted mb-4">Memory (${inv.memory.length} module${inv.memory.length>1?'s':''})</div>
        <table class="audit-table"><thead><tr><th>Slot</th><th>Size</th><th>Type</th><th>Speed</th></tr></thead><tbody>` +
        inv.memory.map(d=>`<tr><td>${escHtml(d.locator||'—')}</td><td>${escHtml(d.size||'—')}</td><td>${escHtml(d.type||'—')}</td><td>${escHtml(d.speed||'—')}</td></tr>`).join('') +
        `</tbody></table>`;
    }
    if ((inv.raid||[]).length) {
      h += `<div class="fs-11 c-muted mb-4 mt-8">RAID</div>` +
        inv.raid.map(r=>`<span class="cmd-badge fs-11">${escHtml(r.name)} ${escHtml(r.level)} <span class="${/active|clean/i.test(r.state)?'c-green':'c-amber'}">${escHtml(r.state)}</span></span>`).join(' ');
    }
    if ((inv.temps||[]).length) {
      const hot = inv.temps.filter(t=>t.current_c>=75);
      h += `<div class="fs-11 c-muted mb-4 mt-8">Temperatures${hot.length?` — <span class="c-red">${hot.length} hot</span>`:''}</div>` +
        inv.temps.slice(0,16).map(t=>`<span class="cmd-badge fs-11 ${t.current_c>=75?'c-red':''}">${escHtml(t.label)}: ${t.current_c}°C</span>`).join(' ');
    }
    h += `</div>`;
  }

  // ── On-demand actions: speedtest + LAN discovery ───────────────────
  const st = (hw.speedtest || []).slice(-1)[0];
  const disc = hw.discovery || {};
  const unmanaged = (disc.hosts||[]).filter(x=>!x.managed);
  const dn = _drawerDeviceName || '';
  h += `<div class="hw-block"><div class="hw-h">On-demand diagnostics</div>
    <div class="hw-actions">
      <button class="btn-secondary fs-12" data-action="deviceSpeedtest" data-arg="${escAttr(id)}">${_icon('zap',14)} Run speed test</button>
      <button class="btn-secondary fs-12" data-action="deviceNetscan" data-arg="${escAttr(id)}">${_icon('search',14)} Scan LAN</button>
      <button class="btn-secondary fs-12" data-action="deviceRunbook" data-arg="${escAttr(id)}" data-arg2="${escAttr(dn)}">${_icon('bookOpen',14)} Suggest runbook</button>
      <button class="btn-secondary fs-12" data-action="deviceDocDraft" data-arg="${escAttr(id)}" data-arg2="${escAttr(dn)}">${_icon('sparkles',14)} Draft CMDB doc</button>
    </div>
    <div id="hw-diag-status" class="mt-8"></div>`;
  if (st) {
    h += st.ok
      ? `<div class="fs-12 mt-8">Last speed test: <b>${st.download_mbps}</b> Mbps down · <b>${st.upload_mbps}</b> Mbps up · ${st.ping_ms} ms ping <span class="c-muted">(${timeAgo(st.ts)})</span></div>`
      : `<div class="fs-12 mt-8 c-amber">Last speed test failed: ${escHtml(st.error||'')}</div>`;
  }
  if ((disc.hosts||[]).length) {
    h += `<div class="fs-12 mt-8">LAN scan (${escHtml(disc.method||'')}, ${timeAgo(disc.ts)}): ${disc.hosts.length} host${disc.hosts.length>1?'s':''}, <b>${unmanaged.length}</b> unmanaged.</div>`;
  }
  h += `</div>`;

  return h || '<div class="c-muted">No hardware data reported yet. The agent collects SMART / kernel / inventory every ~5 reports.</div>';
}

async function toggleQuarantine(id, on) {
  const r = await api('PATCH', `/devices/${id}/quarantine`, {quarantined: !!on});
  if (r && r.ok) {
    if (_drawerDeviceData) _drawerDeviceData.quarantined = r.quarantined;
    toast(r.quarantined ? 'Device quarantined — actions disabled.'
                        : 'Quarantine lifted.', 'success');
  } else {
    toast((r && r.error) || 'Failed', 'error');
    const cb = document.getElementById('ds-quarantine');
    if (cb) cb.checked = !on;   // revert on failure
  }
}

// v3.4.0: these queue a command the agent runs on its *next poll*, so the
// result isn't instant. Rather than a fire-and-forget toast (which felt like
// "nothing happened"), we show a live "running…" status under the buttons and
// poll the hardware endpoint until a fresh result lands or we time out.
async function deviceSpeedtest(id) {
  const status = document.getElementById('hw-diag-status');
  const base = await _diagBaselineTs(id, 'speedtest');
  const r = await api('POST', `/devices/${id}/speedtest`, {});
  if (!(r && r.ok)) { toast((r && r.error) || 'Failed to queue', 'error');
    if (status) status.innerHTML = `<div class="c-red">${escHtml((r && r.error) || 'Failed to queue')}</div>`;
    return; }
  toast('Speed test queued — running on the device…', 'success');
  if (status) status.innerHTML = `<div class="diag-pending">${_icon('clock',13)} Speed test queued — waiting for the agent to run it and report back (next poll)…</div>`;
  _awaitDiag(id, 'speedtest', base, 'Speed test');
}

async function deviceNetscan(id) {
  const status = document.getElementById('hw-diag-status');
  const base = await _diagBaselineTs(id, 'discovery');
  const r = await api('POST', `/devices/${id}/netscan`, {});
  if (!(r && r.ok)) { toast((r && r.error) || 'Failed to queue', 'error');
    if (status) status.innerHTML = `<div class="c-red">${escHtml((r && r.error) || 'Failed to queue')}</div>`;
    return; }
  toast('LAN scan queued — running on the device…', 'success');
  if (status) status.innerHTML = `<div class="diag-pending">${_icon('clock',13)} LAN scan queued — waiting for the agent to run it and report back (next poll)…</div>`;
  _awaitDiag(id, 'discovery', base, 'LAN scan');
}

async function _diagBaselineTs(id, kind) {
  try {
    const hw = await api('GET', `/devices/${id}/hardware`);
    if (kind === 'speedtest') { const a = (hw && hw.speedtest) || []; return a.length ? a[a.length-1].ts : 0; }
    return ((hw && hw.discovery) || {}).ts || 0;
  } catch (_) { return 0; }
}

// Poll until a result newer than `baseTs` shows up (or time out). Stops if the
// operator navigates away from this device's drawer.
function _awaitDiag(id, kind, baseTs, label) {
  let tries = 0;
  const maxTries = 50;          // ~5 min at 6s
  const tick = async () => {
    if (_drawerDeviceId !== id) return;   // drawer closed / switched device
    tries++;
    let hw = null;
    try { hw = await api('GET', `/devices/${id}/hardware`); } catch (_) {}
    let res = null, ts = 0;
    if (hw) {
      if (kind === 'speedtest') { const a = hw.speedtest || []; if (a.length) { res = a[a.length-1]; ts = res.ts; } }
      else { res = hw.discovery || {}; ts = res.ts || 0; }
    }
    const status = document.getElementById('hw-diag-status');
    if (ts && ts !== baseTs) {
      if (status) status.innerHTML = _renderDiagResult(kind, res);
      toast(`${label} finished`, 'success');
      return;
    }
    if (tries >= maxTries) {
      if (status) status.innerHTML = `<div class="c-amber">${label} still pending after 5 min — the device may be offline, polling slowly, or the required tool isn't installed. It'll appear here once it reports.</div>`;
      return;
    }
    setTimeout(tick, 6000);
  };
  setTimeout(tick, 6000);
}

function _renderDiagResult(kind, res) {
  if (kind === 'speedtest') {
    if (!res) return '';
    return res.ok
      ? `<div class="diag-done c-green">${_icon('zap',13)} <b>${res.download_mbps}</b> Mbps down · <b>${res.upload_mbps}</b> Mbps up · ${res.ping_ms} ms ping ${res.jitter_ms!=null?`· ${res.jitter_ms} ms jitter`:''} <span class="c-muted">(${timeAgo(res.ts)})</span></div>`
      : `<div class="diag-done c-amber">Speed test ran but failed: ${escHtml(res.error || 'unknown')} — is <code>librespeed-cli</code> installed on the host?</div>`;
  }
  const n = (res.hosts || []).length;
  const unmanaged = (res.hosts || []).filter(x => !x.managed).length;
  return `<div class="diag-done c-green">${_icon('search',13)} LAN scan (${escHtml(res.method||'')}): ${n} host(s), <b>${unmanaged}</b> unmanaged <span class="c-muted">(${timeAgo(res.ts)})</span>. See Network map → Unmanaged hosts.</div>`;
}

// ════════════════════════════════════════════════════════════════════════════
// v3.4.0 fleet-level UI: AI insight modal (runbook / doc draft), fleet anomaly
// scan + cron builder (AI page), network discovery (netmap), compliance report.
// ════════════════════════════════════════════════════════════════════════════

let _aiInsightLastMd = '';

function _openAiInsight(title) {
  document.getElementById('ai-insight-title').textContent = title;
  document.getElementById('ai-insight-body').innerHTML =
    '<div class="empty-state">Generating… this calls the AI provider and may take a few seconds.</div>';
  _aiInsightLastMd = '';
  openModal('ai-insight-modal');
}

function _fillAiInsight(md) {
  _aiInsightLastMd = md || '';
  document.getElementById('ai-insight-body').innerHTML = renderMarkdown(md || '_No content returned._');
}

function aiInsightCopy() {
  if (!_aiInsightLastMd) return;
  navigator.clipboard?.writeText(_aiInsightLastMd)
    .then(() => toast('Copied Markdown to clipboard', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

// #3 runbook suggestion (per-device, RAG-aware). Triggered from the drawer.
async function deviceRunbook(id, name) {
  const trigger = prompt(`Describe the issue / alert on ${name} to get a runbook:`);
  if (!trigger || !trigger.trim()) return;
  _openAiInsight(`Runbook — ${name}`);
  const r = await api('POST', `/devices/${id}/runbook`, {trigger: trigger.trim()});
  if (r && r.ok) _fillAiInsight(r.runbook);
  else { closeModal('ai-insight-modal'); toast((r && r.error) || 'Failed', 'error'); }
}

// #11 CMDB doc draft (per-device). Triggered from the drawer.
async function deviceDocDraft(id, name) {
  _openAiInsight(`Doc draft — ${name}`);
  const r = await api('POST', `/devices/${id}/doc-draft`, {});
  if (r && r.ok) _fillAiInsight(r.markdown);
  else { closeModal('ai-insight-modal'); toast((r && r.error) || 'Failed', 'error'); }
}

// #9 fleet anomaly scan (AI page).
async function aiAnomalyScan() {
  const btn = document.getElementById('ai-anomaly-btn');
  const out = document.getElementById('ai-anomaly-results');
  if (btn) btn.disabled = true;
  out.innerHTML = '<div class="c-muted">Scanning the fleet…</div>';
  const r = await api('POST', '/ai/anomaly', {});
  if (btn) btn.disabled = false;
  if (!r || !r.ok) { out.innerHTML = `<div class="c-red">${escHtml((r && r.error) || 'Failed')}</div>`; return; }
  const items = r.anomalies || [];
  if (!items.length) {
    out.innerHTML = `<div class="c-green">No anomalies stood out across ${r.scanned} device(s).</div>`;
    return;
  }
  const sevColor = s => s === 'high' ? 'c-red' : s === 'medium' ? 'c-amber' : 'c-muted';
  out.innerHTML = `<div class="fs-11 c-muted mb-6">${items.length} finding(s) across ${r.scanned} device(s)</div>` +
    items.map(a => `<div class="anomaly-row">
      <span class="anomaly-sev ${sevColor(a.severity)}">${escHtml(a.severity)}</span>
      <div><div class="anomaly-dev">${escHtml(a.device || '—')} — ${escHtml(a.finding)}</div>
      <div class="fs-12 c-muted">${escHtml(a.why)}</div></div></div>`).join('');
}

// #10 cron builder (AI page).
async function aiCronBuild() {
  const input = document.getElementById('ai-cron-input');
  const out = document.getElementById('ai-cron-result');
  const desc = (input.value || '').trim();
  if (!desc) { toast('Describe a schedule first', 'error'); return; }
  const btn = document.getElementById('ai-cron-btn');
  if (btn) btn.disabled = true;
  out.innerHTML = '<div class="c-muted">Thinking…</div>';
  const r = await api('POST', '/ai/cron', {description: desc});
  if (btn) btn.disabled = false;
  if (!r || !r.ok) { out.innerHTML = `<div class="c-red">${escHtml((r && r.error) || 'Failed')}</div>`; return; }
  if (!r.valid) {
    out.innerHTML = `<div class="c-amber">Couldn't build a valid expression: ${escHtml(r.explanation || r.error || '')}</div>`;
    return;
  }
  const runs = (r.next_runs || []).map(ts => new Date(ts * 1000).toLocaleString());
  out.innerHTML = `
    <div class="cron-result-expr"><code>${escHtml(r.cron)}</code>
      <button class="btn-icon fs-11" data-action="aiCronCopy" data-arg="${escAttr(r.cron)}">Copy</button></div>
    <div class="fs-12 mt-4">${escHtml(r.explanation || '')}</div>
    ${runs.length ? `<div class="fs-11 c-muted mt-6">Next runs:</div><ul class="cron-runs">${runs.map(x => `<li>${escHtml(x)}</li>`).join('')}</ul>` : ''}`;
}

function aiCronCopy(expr) {
  navigator.clipboard?.writeText(String(expr))
    .then(() => toast('Cron expression copied', 'success'))
    .catch(() => toast('Copy failed', 'error'));
}

// #5 network discovery aggregate (netmap page).
async function loadDiscovery() {
  const body = document.getElementById('discovery-body');
  if (!body) return;
  const r = await api('GET', '/discovery');
  const hosts = (r && r.hosts) || [];
  if (!hosts.length) {
    body.innerHTML = `<div class="c-muted">No unmanaged hosts found${r && r.scanned_by ? ` (${r.scanned_by} agent scan${r.scanned_by>1?'s':''} on record)` : ''}. Run a LAN scan from a device's Health &amp; Hardware card.</div>`;
    return;
  }
  tableCtl.wireSortOnly('discovery-thead', 'discovery', loadDiscovery);
  const rows = tableCtl.sortRows('discovery', hosts, h => ({
    ip: h.ip.split('.').map(n => String(n).padStart(3, '0')).join('.'),
    mac: h.mac, hostname: h.hostname, seen_by: (h.seen_by || []).join(','),
  }));
  body.innerHTML = `<div class="table-card"><table>
    <thead id="discovery-thead"><tr>
      <th data-col="ip">IP</th><th data-col="mac">MAC</th>
      <th data-col="hostname">Hostname</th><th data-col="seen_by">Seen by</th></tr></thead>
    <tbody>` + rows.map(h => `<tr>
      <td><code>${escHtml(h.ip)}</code></td>
      <td class="ff-mono fs-12">${escHtml(h.mac || '—')}</td>
      <td>${escHtml(h.hostname || '—')}</td>
      <td class="fs-12">${escHtml((h.seen_by || []).join(', '))}</td></tr>`).join('') +
    `</tbody></table></div>`;
}

// #14 compliance report (Compliance page).
async function loadCompliance() {
  const body = document.getElementById('compliance-body');
  if (!body) return;
  const fws = Array.from(document.querySelectorAll('.compliance-fw:checked')).map(c => c.value);
  body.innerHTML = '<div class="c-muted">Evaluating controls…</div>';
  const qs = fws.length ? `?frameworks=${fws.join(',')}` : '';
  const r = await api('GET', `/compliance${qs}`);
  if (!r || !r.frameworks) { body.innerHTML = '<div class="c-red">Failed to load compliance report.</div>'; return; }
  const sumColor = s => s === 'pass' ? 'c-green' : s === 'fail' ? 'c-red' : 'c-muted';
  let h = `<div class="compliance-summary">Overall: <span class="c-green">${r.summary.pass} pass</span> · <span class="c-red">${r.summary.fail} fail</span> · <span class="c-muted">${r.summary.na} N/A</span></div>`;
  for (const fw of Object.keys(r.frameworks)) {
    const f = r.frameworks[fw];
    h += `<div class="settings-section compliance-fw-card">
      <div class="compliance-fw-head">
        <div class="section-title">${escHtml(f.label)}</div>
        <div class="compliance-score ${f.score != null && f.score >= 80 ? 'c-green' : f.score != null && f.score >= 50 ? 'c-amber' : 'c-red'}">${f.score != null ? f.score + '%' : '—'}</div>
      </div>
      <div class="fs-11 c-muted mb-6">${f.pass} pass · ${f.fail} fail · ${f.na} N/A</div>
      <table class="audit-table"><thead><tr><th>Control</th><th>Status</th><th>Evidence</th></tr></thead><tbody>` +
      f.controls.map(c => `<tr>
        <td><strong>${escHtml(c.id)}</strong><div class="fs-11 c-muted">${escHtml(c.title)}</div></td>
        <td class="${sumColor(c.status)}">${escHtml(c.status.toUpperCase())}</td>
        <td class="fs-12">${escHtml(c.evidence)}${c.remediation ? `<div class="fs-11 c-amber mt-2">→ ${escHtml(c.remediation)}</div>` : ''}</td>
      </tr>`).join('') + `</tbody></table></div>`;
  }
  body.innerHTML = h;
}

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
    h += `<h4 class="mt-12">Interfaces (${ifs.length})</h4><table class="fs-13"><thead><tr><th>Name</th><th>Type</th><th>State</th><th class="ta-right">RX</th><th class="ta-right">TX</th><th></th></tr></thead><tbody>`;
    for (const i of ifs) {
      const state = i.disabled ? '<span class="c-muted">disabled</span>'
                  : (i.running ? '<span class="c-green">up</span>' : '<span class="c-amber">down</span>');
      const btn = i.disabled
        ? `<button class="btn-icon badge-xs" data-action="routerosAction" data-arg="enable_interface" data-arg2="${escAttr(i.id)}">Enable</button>`
        : `<button class="btn-icon badge-xs" data-action="routerosAction" data-arg="disable_interface" data-arg2="${escAttr(i.id)}">Disable</button>`;
      h += `<tr><td><strong>${escHtml(i.name || '?')}</strong></td><td class="hint">${escHtml(i.type || '')}</td><td>${state}</td><td class="ta-right">${fmtB(i.rx_byte)}</td><td class="ta-right">${fmtB(i.tx_byte)}</td><td class="nowrap">${btn}</td></tr>`;
    }
    h += '</tbody></table>';
  }

  const leases = ov.dhcp_leases || [];
  if (leases.length) {
    h += `<h4 class="mt-12">DHCP leases (${leases.length})</h4><table class="fs-13"><thead><tr><th>Address</th><th>MAC</th><th>Host</th><th>Status</th></tr></thead><tbody>`;
    for (const l of leases.slice(0, 100)) {
      h += `<tr><td class="mono-12">${escHtml(l.address || '')}</td><td class="mono-12">${escHtml(l.mac || '')}</td><td>${escHtml(l.hostname || '—')}</td><td class="hint">${escHtml(l.status || '')}${l.dynamic ? '' : ' · static'}</td></tr>`;
    }
    h += '</tbody></table>';
  }

  const wl = ov.wireless || [];
  if (wl.length) {
    h += `<h4 class="mt-12">Wireless clients (${wl.length})</h4><table class="fs-13"><thead><tr><th>Interface</th><th>MAC</th><th>Signal</th></tr></thead><tbody>`;
    for (const w of wl.slice(0, 100)) {
      h += `<tr><td>${escHtml(w.interface || '')}</td><td class="mono-12">${escHtml(w.mac || '')}</td><td class="hint">${escHtml(String(w.signal || '—'))}</td></tr>`;
    }
    h += '</tbody></table>';
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
  h += `<h4 class="mt-12">Filter rules (${f.length})</h4><table class="fs-13"><thead><tr><th>Interface</th><th>Action</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>Description</th><th></th></tr></thead><tbody>`;
  h += f.map(r => _ruleRow(r, 'filter', 'opnsense')).join('') || '<tr><td colspan="7" class="c-muted">No filter rules.</td></tr>';
  h += '</tbody></table>';

  h += `<h4 class="mt-12">NAT rules — outbound / source (${n.length})</h4><table class="fs-13"><thead><tr><th>Interface</th><th>Target</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>→ target:port</th><th>Description</th><th></th></tr></thead><tbody>`;
  h += n.map(r => _ruleRow(r, 'nat', 'opnsense')).join('') || '<tr><td colspan="8" class="c-muted">No NAT rules.</td></tr>';
  h += '</tbody></table>';

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
  let h = `<h4>Filter rules (${f.length})</h4><table class="fs-13"><thead><tr><th>Chain</th><th>Action</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>Comment</th><th></th></tr></thead><tbody>`;
  h += f.map(r => _ruleRow(r, 'filter')).join('') || '<tr><td colspan="7" class="c-muted">No filter rules.</td></tr>';
  h += '</tbody></table>';

  h += `<h4 class="mt-12">NAT rules (${n.length})</h4><table class="fs-13"><thead><tr><th>Chain</th><th>Action</th><th>Src</th><th>Dst</th><th>Proto:Port</th><th>→ to-addr:port</th><th>Comment</th><th></th></tr></thead><tbody>`;
  h += n.map(r => _ruleRow(r, 'nat')).join('') || '<tr><td colspan="8" class="c-muted">No NAT rules.</td></tr>';
  h += '</tbody></table>';

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

function routerosFirewallDraft() {
  const desc = window.prompt('Describe the rule in plain English (e.g. "block 192.168.2.50 from reaching the internet"):', '');
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
  let h = `<h4>Queues (${rows.length})</h4><table class="fs-13"><thead><tr><th>Name</th><th>Target / parent</th><th>Max limit</th><th>Rate</th></tr></thead><tbody>`;
  for (const q of rows) {
    h += `<tr class="${q.disabled ? 'c-muted' : ''}"><td><strong>${escHtml(q.name || '')}</strong>${q.disabled ? ' <span class="hint">(off)</span>' : ''}</td><td class="mono-12">${escHtml(q.target || '')}</td><td class="hint">${escHtml(q.max_limit || '')}</td><td class="hint">${escHtml(q.rate || '')}</td></tr>`;
  }
  h += '</tbody></table><div class="row-6 mt-6"><button class="btn-icon" data-action="routerosLiveRates">Live interface rates</button></div>';
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
  let h = `<h4>Live interface rates</h4><div class="hint mb-6">~1-second sample.</div><table class="fs-13"><thead><tr><th>Interface</th><th class="ta-right">RX</th><th class="ta-right">TX</th></tr></thead><tbody>`;
  if (!ifs.length) h += '<tr><td colspan="3" class="c-muted">No active traffic right now.</td></tr>';
  for (const i of ifs) {
    h += `<tr><td><strong>${escHtml(i.name)}</strong></td><td class="ta-right c-green">${fmt(i.rx_bps)}</td><td class="ta-right c-accent">${fmt(i.tx_bps)}</td></tr>`;
  }
  h += '</tbody></table><div class="row-6 mt-6"><button class="btn-icon" data-action="routerosLiveRates">Refresh</button><button class="btn-icon" data-action="loadRouterosQos">Queues</button></div>';
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

// ── Audit helpers ─────────────────────────────────────────────────────────────

function toggleAuditCmd(id, idx) {
  document.getElementById(`cmd-entry-${id}-${idx}`)?.classList.toggle('expanded');
}

function _showOlderCmds(id) {
  const el = document.getElementById(`older-cmds-${id}`);
  if (el) { el.style.display = 'block'; el.nextElementSibling?.remove(); }
}

function _filterPorts(input, id) {
  const q = input.value.toLowerCase();
  document.querySelectorAll(`#ports-body-${id} tr`).forEach(row => {
    row.style.display = row.dataset.q?.toLowerCase().includes(q) ? '' : 'none';
  });
}

function _filterLogs(id) {
  const q = document.getElementById(`log-filter-${id}`)?.value.toLowerCase() || '';
  document.querySelectorAll(`#log-lines-${id} .log-line`).forEach(row => {
    const unit = (row.dataset.unit||'').toLowerCase();
    const line = (row.dataset.line||'').toLowerCase();
    row.style.display = (!q || unit.includes(q) || line.includes(q)) ? '' : 'none';
  });
}

// ── Replace openDetail everywhere ─────────────────────────────────────────────


function expandPortsTable(hidden) {
  const tbody = document.getElementById('ports-table-body');
  if (!tbody) return;
  hidden.forEach(e => {
    const procs = [...new Set(e.hosts.map(h => h.process).filter(Boolean))];
    const devLinks = e.hosts.map(h =>
      `<span class="cmd-badge" title="${escHtml(h.device)}">${escHtml(h.device)}</span>`
    ).join(' ');
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code class="fs-12">${escHtml(e.proto)}/${e.port}</code></td>
      <td class="hint">${escHtml(procs.join(', ') || '—')}</td>
      <td class="fs-12">${devLinks}</td>`;
    tbody.appendChild(tr);
  });
  // Remove expand button
  const btn = document.querySelector('#ports-container .btn-secondary');
  if (btn) btn.remove();
}

// ── v2.9.1 drawer helpers ─────────────────────────────────────────────────────

// WoL — send magic packet; prompt for MAC only if server says none is stored
async function _wolWithMacCheck(id, name, btn) {
  // NOTE: do NOT closeDeviceDrawer() — the button must stay visible for feedback
  const _origText = btn?.textContent || 'Wake on LAN';
  if (btn) { btn.disabled = true; btn.textContent = 'Sending…'; }
  const _wolDone = (ok, msg) => {
    if (btn) {
      btn.textContent = ok ? '✓ Sent' : '✗ Failed';
      btn.style.color = ok ? 'var(--green)' : 'var(--red)';
      btn.disabled = false;
      setTimeout(() => { if (btn.isConnected) { btn.textContent = _origText; btn.style.color = ''; } }, 4000);
    }
    toast(msg, ok ? 'success' : 'error');
    dbg(`WoL ${ok ? 'success' : 'fail'}: ${msg}`);
  };
  try {
    dbg(`WoL request: device=${id} name=${name}`);
    let data = await api('POST', '/wol', { device_id: id });
    if (data?.ok) { _wolDone(true, `Magic packet sent to ${name} (${data.mac})`); return; }
    const errMsg = (data?.error || '').toLowerCase();
    if (!data || errMsg.includes('mac') || errMsg.includes('no mac')) {
      if (btn) { btn.textContent = _origText; btn.disabled = false; }
      const mac = prompt(
        `No MAC address stored for ${name}.\nEnter the MAC address (e.g. AA:BB:CC:DD:EE:FF):`, '');
      if (!mac || !mac.trim()) return;
      if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
      const save = await api('POST', `/devices/${id}`, { mac: mac.trim() });
      if (!save?.ok) { _wolDone(false, save?.error || 'Failed to save MAC'); return; }
      data = await api('POST', '/wol', { device_id: id });
      if (data?.ok) _wolDone(true, `Magic packet sent to ${name} (${data.mac})`);
      else _wolDone(false, data?.error || 'WoL failed after saving MAC');
    } else {
      _wolDone(false, data?.error || 'WoL request failed');
    }
  } catch (err) {
    _wolDone(false, 'WoL error: ' + (err?.message || String(err)));
  }
}

// v3.0.5: _addAiButtonsToSysinfo removed. It targeted the old hardcoded
// `#audit-sysinfo-body` element that lived in the duplicate device-drawer
// block in index.html (also removed in v3.0.5). The dynamic audit
// renderer builds the AI buttons inline inside _loadAuditSection's
// `sysinfo` case.

// ── v2.9.1: Log ignore patterns ───────────────────────────────────────────────

let _logIgnorePatterns = [];
// v3.3.0: -1 = adding; ≥0 = editing the pattern at that index. When
// editing, the input shows the existing pattern and Add becomes Save.
let _logIgnoreEditIdx = -1;

function _renderLogIgnoreList() {
  const el = document.getElementById('log-ignore-list');
  if (!el) return;
  if (!_logIgnorePatterns.length) {
    el.innerHTML = '<span class="c-muted">No patterns configured.</span>';
    const addBtn = document.querySelector('[data-action="addLogIgnorePattern"]');
    if (addBtn) addBtn.textContent = _logIgnoreEditIdx >= 0 ? 'Save' : 'Add';
    return;
  }
  el.innerHTML = _logIgnorePatterns.map((p, i) =>
    `<div class="isl-655">
       <code class="isl-656">${escHtml(p)}</code>
       <button class="btn-icon" data-action="editLogIgnorePattern" data-arg="${i}">Edit</button>
       <button class="btn-icon isl-657" data-action="removeLogIgnorePattern" data-arg="${i}">×</button>
     </div>`
  ).join('');
  const addBtn = document.querySelector('[data-action="addLogIgnorePattern"]');
  if (addBtn) addBtn.textContent = _logIgnoreEditIdx >= 0 ? 'Save' : 'Add';
}

function editLogIgnorePattern(idx) {
  const input = document.getElementById('log-ignore-input');
  if (!input) return;
  input.value = _logIgnorePatterns[idx] || '';
  _logIgnoreEditIdx = idx;
  _renderLogIgnoreList();
  input.focus();
}

async function addLogIgnorePattern() {
  const input = document.getElementById('log-ignore-input');
  const pat   = (input?.value || '').trim();
  if (!pat) return;
  // Validate regex client-side
  try { new RegExp(pat); } catch(e) { toast('Invalid regex: ' + e.message, 'error'); return; }
  const wasEdit = _logIgnoreEditIdx >= 0;
  const prev    = wasEdit ? _logIgnorePatterns[_logIgnoreEditIdx] : null;
  if (wasEdit && _logIgnoreEditIdx < _logIgnorePatterns.length) {
    _logIgnorePatterns[_logIgnoreEditIdx] = pat;
  } else {
    _logIgnorePatterns.push(pat);
  }
  const r = await api('POST', '/config', { log_ignore_patterns: _logIgnorePatterns });
  if (r?.ok) {
    toast(wasEdit ? 'Pattern updated' : 'Pattern added', 'success');
    if (input) input.value = '';
    _logIgnoreEditIdx = -1;
    _renderLogIgnoreList();
  } else {
    // Roll back the mutation
    if (wasEdit) _logIgnorePatterns[_logIgnoreEditIdx] = prev;
    else _logIgnorePatterns.pop();
    toast(r?.error || 'Failed', 'error');
  }
}

async function removeLogIgnorePattern(idx) {
  _logIgnorePatterns.splice(idx, 1);
  if (_logIgnoreEditIdx === idx) _logIgnoreEditIdx = -1;
  else if (_logIgnoreEditIdx > idx) _logIgnoreEditIdx -= 1;
  const r = await api('POST', '/config', { log_ignore_patterns: _logIgnorePatterns });
  if (r?.ok) { _renderLogIgnoreList(); toast('Removed', 'info'); }
  else toast('Failed', 'error');
}

// Extend loadDashboardSettings to populate log ignore patterns
const _origLoadDashboardSettings = loadDashboardSettings;
loadDashboardSettings = async function() {
  await _origLoadDashboardSettings();
  const cfg = await api('GET', '/config') || {};
  _logIgnorePatterns = cfg.log_ignore_patterns || [];
  _renderLogIgnoreList();
};

// CVE table button helper — stops propagation reliably then calls fn
function _cveBtn(event, fn) {
  event.stopPropagation();
  event.preventDefault();
  fn();
}

// ── v2.9.1: Global button press feedback ──────────────────────────────────────
// Gives every button a tactile scale-down on click so the user always knows
// their tap registered, independent of async results or toast visibility.
document.addEventListener('click', e => {
  const btn = e.target.closest('button:not([data-no-press])');
  if (!btn || btn.disabled) return;
  btn.style.transition = 'transform 0.08s ease';
  btn.style.transform  = 'scale(0.94)';
  setTimeout(() => {
    btn.style.transform  = '';
    btn.style.transition = '';
  }, 120);
}, { passive: true });

// ── v2.9.1: Debug logging ─────────────────────────────────────────────────────

async function saveDebugLogging(enabled) {
  const r = await api('POST', '/config', { debug_logging: enabled });
  if (r?.ok) {
    toast(enabled ? 'Debug logging enabled — logs at /var/lib/remotepower/debug.log' : 'Debug logging disabled', 'info');
    if (enabled) console.info('[RemotePower] Debug logging enabled. Server writes to debug.log; client logs to this console.');
  } else toast(r?.error || 'Failed', 'error');
}

function downloadDebugLog() {
  window.open('/api/debug-log', '_blank');
}

// Load debug logging state when Settings → Advanced is opened
const _origSwitchSettingsTab = typeof switchSettingsTab === 'function' ? switchSettingsTab : null;
if (_origSwitchSettingsTab) {
  window.switchSettingsTab = function(tab) {
    _origSwitchSettingsTab(tab);
    if (tab === 'advanced') {
      api('GET', '/config').then(cfg => {
        const el = document.getElementById('debug-logging-toggle');
        if (el && cfg) el.checked = !!cfg.debug_logging;
      });
    }
  };
}

// ══ v2.9.1: Client-side debug logging ════════════════════════════════════════
// When enabled in Settings → Advanced, all UI events (button clicks, API calls,
// toasts, errors) are batched and posted to /api/debug-log. The server appends
// them to /var/lib/remotepower/debug.log along with its own request log, giving
// a single unified timeline useful for diagnosing UI bugs.
// Enabled state lives in localStorage so it survives reloads and is read fresh
// on every check — no stale closure captures.
// ═════════════════════════════════════════════════════════════════════════════

function _dbgIsEnabled() {
  return localStorage.getItem('rp_debug') === '1';
}

let _dbgBuffer   = [];
let _dbgFlushing = false;
let _dbgFlushTimer = null;

function dbg(msg, tag = 'ui') {
  if (!msg || !_dbgIsEnabled()) return;
  const ts = new Date().toISOString().slice(0, 19);
  const entry = { ts, tag, msg: String(msg).slice(0, 1024) };
  console.log(`%c[dbg]%c [${tag}] ${msg}`, 'color:#888', '');
  _dbgBuffer.push(entry);
  // Debounce flushes so a burst of events makes one HTTP request
  if (_dbgFlushTimer) clearTimeout(_dbgFlushTimer);
  _dbgFlushTimer = setTimeout(_dbgFlush, 250);
}

async function _dbgFlush() {
  if (_dbgFlushing || !_dbgBuffer.length) return;
  _dbgFlushing = true;
  const batch = _dbgBuffer.splice(0, 50);
  try {
    // Use direct fetch with the real auth token — calling api() here would
    // recurse infinitely (since api() is instrumented to call dbg())
    await fetch('/api/debug-log', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Token':      (typeof getToken === 'function' ? getToken() : '')
      },
      body: JSON.stringify({ entries: batch }),
    });
  } catch (e) { /* swallow — no infinite recursion */ }
  finally { _dbgFlushing = false; }
}

// Sync localStorage with server config on page load
(async function _dbgInit() {
  try {
    const cfg = await api('GET', '/config');
    if (cfg?.debug_logging) {
      localStorage.setItem('rp_debug', '1');
      console.info('%c[RemotePower] Debug logging ON — events stream to /var/lib/remotepower/debug.log',
                   'color:#ffa726;font-weight:bold');
      dbg('Page loaded: ' + location.pathname, 'nav');
    } else {
      localStorage.removeItem('rp_debug');
    }
  } catch(_) {}
})();

// Secrets must never reach the debug log (console or /var/lib/remotepower/
// debug.log). Mask values of credential-shaped keys in request bodies and
// responses before they're stringified for logging. Covers api_secret /
// api_key (OPNsense), password (RouterOS, login, vault), community (SNMP),
// token, passphrase, private_key, etc. — case-insensitive, recursive.
const _DBG_SECRET_RX = /(password|passwd|secret|api_?key|token|passphrase|private_key|community|credential)/i;
function _dbgScrub(v, depth) {
  if (depth > 6 || v == null || typeof v !== 'object') return v;
  if (Array.isArray(v)) return v.map(x => _dbgScrub(x, depth + 1));
  const out = {};
  for (const k in v) {
    out[k] = _DBG_SECRET_RX.test(k) ? '<redacted>' : _dbgScrub(v[k], depth + 1);
  }
  return out;
}

// Instrument api() — wrap it to log every request and response
const _origApi = window.api;
if (typeof _origApi === 'function') {
  window.api = async function(method, path, body) {
    const t0 = performance.now();
    dbg(`→ ${method} ${path}` + (body ? ' body=' + JSON.stringify(_dbgScrub(body, 0)).slice(0,200) : ''), 'api');
    try {
      const r = await _origApi(method, path, body);
      const dt = Math.round(performance.now() - t0);
      const resp = JSON.stringify(_dbgScrub(r || {}, 0)).slice(0, 300);
      dbg(`← ${method} ${path} (${dt}ms) ${resp}`, 'api');
      return r;
    } catch (e) {
      dbg(`✗ ${method} ${path} threw: ${e?.message || e}`, 'api');
      throw e;
    }
  };
}

// Instrument toast() — log every toast shown
const _origToast = window.toast;
if (typeof _origToast === 'function') {
  window.toast = function(msg, type) {
    dbg(`toast(${type || 'info'}): ${msg}`, 'toast');
    return _origToast(msg, type);
  };
}

// Catch all uncaught errors & promise rejections
window.addEventListener('error', e => {
  dbg(`JS error: ${e.message} at ${e.filename}:${e.lineno}:${e.colno}`, 'error');
});
window.addEventListener('unhandledrejection', e => {
  dbg(`Unhandled rejection: ${e.reason?.message || e.reason}`, 'error');
});

// Log every button click (with target text/id for traceability)
document.addEventListener('click', e => {
  if (!_dbgIsEnabled()) return;
  const btn = e.target.closest('button, a.btn-primary, a.btn-secondary');
  if (!btn) return;
  const label = (btn.textContent || '').trim().slice(0, 40) ||
                btn.id || btn.className || 'unknown';
  dbg(`click: "${label}"`, 'click');
}, true);

// Replace saveDebugLogging on window so HTML onclick gets the new version that
// updates localStorage. Must be window.X = ..., not bare assignment, because
// the HTML attribute resolves against the global object.
window.saveDebugLogging = async function(enabled) {
  if (enabled) {
    localStorage.setItem('rp_debug', '1');
    dbg('Debug logging enabled via Settings', 'system');
  } else {
    dbg('Debug logging disabled via Settings', 'system');
    // Flush remaining buffer before disabling
    await _dbgFlush();
    localStorage.removeItem('rp_debug');
  }
  const r = await api('POST', '/config', { debug_logging: enabled });
  if (r?.ok) toast(enabled
    ? 'Debug logging enabled — open DevTools (F12) Console + tail /var/lib/remotepower/debug.log'
    : 'Debug logging disabled', 'info');
  else toast(r?.error || 'Failed', 'error');
};

// ══ v3.0.0: IaC Generator ════════════════════════════════════════════════════
// Three-step flow:
//   1. iacGenerate() → POST /api/iac/request → request_id
//   2. Poll /api/iac/status/<id> every 5s until ready (~60s typical)
//   3. POST /api/iac/generate → LLM call → render code in right pane
// ═════════════════════════════════════════════════════════════════════════════

const IAC_CATEGORIES = [
  {key:'os_identity', label:'OS & identity',                         source:'agent'},
  {key:'packages',    label:'Installed packages',                    source:'agent'},
  {key:'systemd',     label:'Systemd services (enabled)',            source:'agent'},
  {key:'users',       label:'Local users (uid≥1000)',                source:'agent'},
  {key:'groups',      label:'Groups (gid≥1000)',                     source:'agent'},
  {key:'ssh_keys',    label:'SSH authorized_keys (redact to variables)', source:'agent'},
  {key:'network',     label:'Network configuration',                 source:'agent'},
  {key:'fstab',       label:'Mounts (fstab)',                        source:'agent'},
  {key:'containers',  label:'Containers (Docker/Podman)',            source:'agent'},
  {key:'repos',       label:'Custom repos',                          source:'agent'},
  {key:'firewall',    label:'Firewall',                              source:'agent'},
  {key:'cron',        label:'Cron jobs (incl. RemotePower scheduled)', source:'agent'},
  {key:'tls',         label:'TLS certificates (paths only)',         source:'agent'},
  {key:'env',         label:'System environment (non-default)',      source:'agent'},
  {key:'snaps',       label:'Snaps (Ubuntu)',                        source:'agent'},
  {key:'kmod',        label:'Kernel modules (persistent)',           source:'agent'},
  {key:'sysctl',      label:'Sysctl parameters (non-default)',       source:'agent'},
  {key:'remotepower', label:'RemotePower-specific (tags, group, scripts, host-config)', source:'server'},
];

let _iacLastCode      = '';
let _iacLastFmt       = '';
let _iacLastDev       = '';
let _iacLastRequestId = '';   // v3.0.0: kept so user can re-run AI or download JSON later
let _iacLastConvo     = null; // v3.0.0: full system+user+assistant for the Conversation tab
let _iacPollTimer = null;

async function loadIacPage() {
  // Populate device dropdown
  const devs = await api('GET', '/devices');
  const sel  = document.getElementById('iac-device-select');
  if (sel && Array.isArray(devs)) {
    const stored = localStorage.getItem('rp_iac_last_device') || '';
    sel.innerHTML = '<option value="">— select a device —</option>' +
      devs.map(d => {
        const status = d.online ? '● online' : '○ offline';
        return `<option value="${escAttr(d.id)}" ${d.id===stored?'selected':''}>${escHtml(d.name)} (${status})</option>`;
      }).join('');
  }

  // Render category checkboxes
  // v3.0.1: default to NO categories selected. Previously all-on, which led
  // to massive payloads on first run before the user realised they could
  // narrow it down. Empty selection = user must pick at least one before
  // Generate is enabled (validated in _iacRequestGenerate).
  const storedCats = JSON.parse(localStorage.getItem('rp_iac_categories') || 'null');
  const defaultCats = Array.isArray(storedCats) ? storedCats : [];
  const list = document.getElementById('iac-categories');
  if (list) {
    list.innerHTML = IAC_CATEGORIES.map(c => `
      <label class="iac-cat-row">
        <input type="checkbox" value="${escAttr(c.key)}" ${defaultCats.includes(c.key)?'checked':''} data-change="_iacSavePref">
        <span>${escHtml(c.label)}</span>
        <span class="hint">${c.source}</span>
      </label>`).join('');
  }

  // Restore format
  const fmt = localStorage.getItem('rp_iac_format') || 'terraform';
  const fmtSel = document.getElementById('iac-format-select');
  if (fmtSel) fmtSel.value = fmt;

  // Restore custom user instructions
  const instr = localStorage.getItem('rp_iac_instructions') || '';
  const instrEl = document.getElementById('iac-user-instructions');
  if (instrEl) instrEl.value = instr;
}

function _iacSelectedCategories() {
  return Array.from(document.querySelectorAll('#iac-categories input:checked')).map(i => i.value);
}

function _iacSelectAll(on) {
  document.querySelectorAll('#iac-categories input[type=checkbox]').forEach(i => i.checked = on);
  _iacSavePref();
}

function _iacSavePref() {
  localStorage.setItem('rp_iac_categories', JSON.stringify(_iacSelectedCategories()));
  const fmt = document.getElementById('iac-format-select')?.value;
  if (fmt) localStorage.setItem('rp_iac_format', fmt);
  const dev = document.getElementById('iac-device-select')?.value;
  if (dev) localStorage.setItem('rp_iac_last_device', dev);
  const instr = document.getElementById('iac-user-instructions')?.value;
  if (instr != null) localStorage.setItem('rp_iac_instructions', instr);
}

function _iacStatus(msg, cls='') {
  const el = document.getElementById('iac-status');
  if (!el) return;
  el.style.display = msg ? '' : 'none';
  el.className = 'iac-status ' + cls;
  el.textContent = msg;
}

async function iacGenerate(btn, withAi) {
  // v3.0.1: withAi=false → skip the LLM call and just download the masked
  // JSON state as soon as the agent collects it. Useful for inspecting what
  // gets sent (or feeding into a different tool).
  if (withAi === undefined) withAi = true;
  const devId = document.getElementById('iac-device-select')?.value;
  const fmt   = document.getElementById('iac-format-select')?.value;
  const cats  = _iacSelectedCategories();

  if (!devId)       { toast('Select a device first', 'error'); return; }
  if (!cats.length) { toast('Select at least one category', 'error'); return; }
  if (!fmt)         { toast('Select an output format', 'error'); return; }

  // Check AI is configured before going further
  const aiCfg = await api('GET', '/ai/config').catch(() => null);
  if (!aiCfg?.enabled) {
    toast('AI provider not configured. Configure in Settings → AI.', 'error');
    return;
  }

  _iacSavePref();
  const origText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Requesting collection…';
  _iacStatus('Asking agent to collect data… (~60s on next heartbeat)');
  document.getElementById('iac-code-output').textContent = '';

  // Step 1: kick off the request
  const req = await api('POST', '/iac/request', { device_id: devId, categories: cats });
  if (!req?.ok || !req.request_id) {
    btn.disabled = false; btn.textContent = origText;
    _iacStatus(req?.error || 'Failed to start collection', 'error');
    return;
  }

  // Step 2: poll status
  let elapsed = 0;
  const POLL_MS = 5000;
  const TIMEOUT_MS = 180_000;   // 3 min
  if (_iacPollTimer) clearInterval(_iacPollTimer);

  _iacPollTimer = setInterval(async () => {
    elapsed += POLL_MS;
    if (elapsed > TIMEOUT_MS) {
      clearInterval(_iacPollTimer);
      btn.disabled = false; btn.textContent = origText;
      _iacStatus('Timeout waiting for agent — try again', 'error');
      return;
    }
    btn.textContent = `Collecting (${Math.floor(elapsed/1000)}s)…`;
    const status = await api('GET', `/iac/status/${encodeURIComponent(req.request_id)}`);
    if (!status) return;
    if (status.status === 'error') {
      clearInterval(_iacPollTimer);
      btn.disabled = false; btn.textContent = origText;
      _iacStatus('Collection error: ' + (status.error || 'unknown'), 'error');
      return;
    }
    if (status.status === 'ready') {
      clearInterval(_iacPollTimer);
      _iacLastRequestId = req.request_id;
      _iacLastDev       = devId;
      // v3.0.1: "Gather RAW JSON" path — fetch the masked state and download
      // it as a file. No LLM call, no token spend.
      if (!withAi) {
        _iacStatus('Data collected — preparing JSON download…');
        btn.textContent = 'Preparing…';
        const payload = await api('GET', `/iac/payload/${encodeURIComponent(req.request_id)}`);
        btn.disabled = false; btn.textContent = origText;
        if (!payload) { _iacStatus('Failed to fetch payload', 'error'); return; }
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url  = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `iac-state-${devId}-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        document.getElementById('iac-json-btn').disabled  = false;
        document.getElementById('iac-rerun-btn').disabled = false;
        _iacStatus(`Done — JSON downloaded (${(JSON.stringify(payload).length/1024).toFixed(1)} KB). Click "Re-run AI" to feed this same data to the LLM.`, 'done');
        return;
      }
      _iacStatus('Data collected — calling AI provider…');
      btn.textContent = 'Generating…';
      // Step 3: generate
      const instr = document.getElementById('iac-user-instructions')?.value || '';
      const gen = await api('POST', '/iac/generate', {
        request_id:        req.request_id,
        output_format:     fmt,
        categories:        cats,
        user_instructions: instr,
      });
      btn.disabled = false; btn.textContent = origText;
      if (!gen?.ok) {
        _iacStatus(gen?.error || 'Generation failed', 'error');
        return;
      }
      _iacLastCode      = gen.code || '';
      _iacLastFmt       = fmt;
      _iacLastDev       = devId;
      _iacLastRequestId = req.request_id;
      _iacLastConvo     = gen.conversation || null;
      const out = document.getElementById('iac-code-output');
      out.textContent = _iacLastCode;
      document.getElementById('iac-output-title').textContent =
        `${fmt} · ${gen.tokens_in||'?'} in / ${gen.tokens_out||'?'} out tokens`;
      document.getElementById('iac-copy-btn').disabled     = false;
      document.getElementById('iac-download-btn').disabled = false;
      document.getElementById('iac-json-btn').disabled     = false;
      document.getElementById('iac-rerun-btn').disabled    = false;
      _iacRenderConversation();
      const sizeKb = (_iacLastCode.length/1024).toFixed(1);
      if (gen.markers_used === false) {
        _iacStatus(`Model ignored the BEGIN_IAC/END_IAC markers — output may include reasoning prose. Try Re-run AI or check the Conversation tab. (${sizeKb} KB)`, 'error');
      } else {
        _iacStatus(`Done — ${sizeKb} KB of ${fmt}`, 'done');
      }
    }
  }, POLL_MS);
}

async function _iacCopy(btn) {
  if (!_iacLastCode) return;
  try {
    await navigator.clipboard.writeText(_iacLastCode);
    const orig = btn.textContent;
    btn.textContent = '✓ Copied';
    setTimeout(() => { btn.textContent = orig; }, 2000);
  } catch (e) {
    toast('Copy failed: ' + e.message, 'error');
  }
}

function _iacDownload() {
  if (!_iacLastCode) return;
  const ext = {
    'terraform':     'tf',
    'ansible':       'yml',
    'pulumi-python': 'py',
    'pulumi-ts':     'ts',
    'cloud-init':    'yml',
  }[_iacLastFmt] || 'txt';
  const blob = new Blob([_iacLastCode], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `iac-${_iacLastDev || 'device'}-${Date.now()}.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
}

// v3.0.0: download the raw masked JSON state — what would be sent to the LLM.
// Useful for verifying what data the LLM actually saw, or for feeding into a
// different tool entirely (jq pipeline, custom script, different AI provider).
async function _iacDownloadJson() {
  if (!_iacLastRequestId) return;
  const payload = await api('GET', `/iac/payload/${encodeURIComponent(_iacLastRequestId)}`);
  if (!payload) { toast('Failed to fetch JSON payload', 'error'); return; }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `iac-state-${_iacLastDev || 'device'}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

// v3.0.0: re-prompt the LLM with the SAME collected data — no agent wait.
// Useful when the first generation hallucinates or you want a different
// output format without re-collecting.
async function _iacRerunAi(btn) {
  if (!_iacLastRequestId) return;
  const fmt   = document.getElementById('iac-format-select')?.value;
  const cats  = _iacSelectedCategories();
  const instr = document.getElementById('iac-user-instructions')?.value || '';
  if (!fmt) { toast('Select an output format', 'error'); return; }
  const origText = btn.textContent;
  btn.disabled = true; btn.textContent = 'Re-prompting…';
  _iacStatus('Re-prompting AI with cached data…');
  try {
    const gen = await api('POST', '/iac/generate', {
      request_id:        _iacLastRequestId,
      output_format:     fmt,
      categories:        cats,
      user_instructions: instr,
    });
    if (!gen?.ok) {
      _iacStatus(gen?.error || 'Re-run failed', 'error');
      return;
    }
    _iacLastCode  = gen.code || '';
    _iacLastFmt   = fmt;
    _iacLastConvo = gen.conversation || null;
    document.getElementById('iac-code-output').textContent = _iacLastCode;
    document.getElementById('iac-output-title').textContent =
      `${fmt} · ${gen.tokens_in||'?'} in / ${gen.tokens_out||'?'} out tokens (re-run)`;
    _iacRenderConversation();
    _iacStatus(`Done — ${(_iacLastCode.length/1024).toFixed(1)} KB of ${fmt}`, 'done');
  } finally {
    btn.disabled = false; btn.textContent = origText;
  }
}

function _iacSwitchTab(tab) {
  document.getElementById('iac-code-output').style.display  = tab === 'code'  ? '' : 'none';
  document.getElementById('iac-convo-output').style.display = tab === 'convo' ? '' : 'none';
  document.getElementById('iac-tab-btn-code').classList.toggle('active',  tab === 'code');
  document.getElementById('iac-tab-btn-convo').classList.toggle('active', tab === 'convo');
}

function _iacRenderConversation() {
  const el = document.getElementById('iac-convo-output');
  if (!el) return;
  if (!_iacLastConvo) {
    el.innerHTML = '<div class="empty-state">No conversation yet.</div>';
    return;
  }
  const c = _iacLastConvo;
  el.innerHTML = `
    <div class="isl-658">
      Provider: <strong>${escHtml(c.provider||'?')}</strong> · Model: <strong>${escHtml(c.model||'?')}</strong>
    </div>
    <div class="iac-convo-block">
      <div class="iac-convo-role system">System prompt</div>
      <div class="iac-convo-content">${escHtml(c.system||'')}</div>
    </div>
    <div class="iac-convo-block">
      <div class="iac-convo-role user">User prompt</div>
      <div class="iac-convo-content">${escHtml(c.user||'')}</div>
    </div>
    <div class="iac-convo-block">
      <div class="iac-convo-role assistant">Assistant response (raw — before code-fence stripping)</div>
      <div class="iac-convo-content">${escHtml(c.assistant||'')}</div>
    </div>`;
}

// ══ v3.0.1: AI prompt customization (Settings → AI Assistant) ════════════════

async function loadAiPrompts() {
  const list = document.getElementById('ai-prompts-list');
  if (!list) return;
  list.innerHTML = '<div class="isl-78">Loading prompts…</div>';
  const [r, paramsResp] = await Promise.all([
    api('GET', '/ai/prompts'),
    api('GET', '/ai/params'),
  ]);
  if (!r?.prompts) {
    list.innerHTML = '<div class="isl-657">Failed to load prompts.</div>';
    return;
  }
  // Index params by key for easy lookup
  const paramsByKey = {};
  for (const p of (paramsResp?.params || [])) paramsByKey[p.key] = p;
  list.innerHTML = r.prompts.map(p => {
    const params = paramsByKey[p.key] || {};
    const hasParams = (params.temperature != null) || (params.top_p != null)
                   || (params.max_tokens != null)  || (params.num_ctx != null);
    return `
    <div class="prompt-card isl-659" data-key="${escAttr(p.key)}">
      <div class="isl-660">
        <div>
          <strong class="fs-14">${escHtml(p.label)}</strong>
          <span class="isl-640">${escHtml(p.key)}</span>
          ${p.is_customized ? '<span class="isl-661">● customized</span>' : ''}
          ${hasParams ? '<span class="isl-662">● tuned</span>' : ''}
        </div>
        <div class="row-6">
          <button class="btn-secondary badge-sm" data-action-btn="_saveAiPromptBtn" data-key="${escAttr(p.key)}" >Save prompt</button>
          <button class="btn-secondary badge-sm" data-action-btn="_resetAiPromptBtn" data-key="${escAttr(p.key)}" >Default</button>
        </div>
      </div>
      <textarea class="form-input prompt-textarea isl-663"
                data-default="${escAttr(p.default)}"
                placeholder="(empty = use default)">${escHtml(p.current)}</textarea>

      <details ${hasParams ? 'open' : ''} class="isl-26">
        <summary class="isl-664">Fine-tuning (temperature, top_p, tokens, context)</summary>
        <div class="isl-665">
          <div>
            <label class="isl-666">Temperature (0.0–2.0)</label>
            <input type="number" step="0.1" min="0" max="2" class="form-input prompt-temp fs-12" value="${params.temperature != null ? params.temperature : ''}" placeholder="default">
          </div>
          <div>
            <label class="isl-666">top_p (0.0–1.0)</label>
            <input type="number" step="0.05" min="0" max="1" class="form-input prompt-topp fs-12" value="${params.top_p != null ? params.top_p : ''}" placeholder="default">
          </div>
          <div>
            <label class="isl-666">max_tokens (1–16000)</label>
            <input type="number" step="100" min="1" max="16000" class="form-input prompt-maxtok fs-12" value="${params.max_tokens != null ? params.max_tokens : ''}" placeholder="default">
          </div>
          <div>
            <label class="isl-666">num_ctx (Ollama/LocalAI)</label>
            <input type="number" step="1024" min="512" max="131072" class="form-input prompt-numctx fs-12" value="${params.num_ctx != null ? params.num_ctx : ''}" placeholder="16384">
          </div>
        </div>
        <div class="isl-667">
          <button class="btn-secondary badge-sm" data-action-btn="_saveAiParamsBtn" data-key="${escAttr(p.key)}" >Save tuning</button>
          <button class="btn-secondary badge-sm" data-action-btn="_resetAiParamsBtn" data-key="${escAttr(p.key)}" >Reset tuning</button>
        </div>
      </details>
    </div>`;
  }).join('');
}

async function saveAiParams(key, btn) {
  const card = btn.closest('.prompt-card');
  if (!card) return;
  const _v = sel => {
    const el = card.querySelector(sel);
    const v = el ? el.value.trim() : '';
    return v === '' ? null : v;
  };
  const body = {
    key,
    temperature: _v('.prompt-temp'),
    top_p:       _v('.prompt-topp'),
    max_tokens:  _v('.prompt-maxtok'),
    num_ctx:     _v('.prompt-numctx'),
  };
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = '…';
  const r = await api('POST', '/ai/params', body);
  btn.disabled = false;
  if (r?.ok) {
    btn.textContent = '✓ Saved';
    toast(`Tuning saved for "${card.querySelector('strong')?.textContent || key}"`, 'success');
    setTimeout(() => { btn.textContent = orig; loadAiPrompts(); }, 1500);
  } else {
    btn.textContent = '✗';
    setTimeout(() => { btn.textContent = orig; }, 2000);
    toast(r?.error || 'Save failed', 'error');
  }
}

async function resetAiParams(key, btn) {
  const card = btn.closest('.prompt-card');
  const r = await api('POST', '/ai/params', { key });
  if (r?.ok) {
    toast(`Tuning reset for "${card?.querySelector('strong')?.textContent || key}"`, 'info');
    loadAiPrompts();
  } else {
    toast(r?.error || 'Reset failed', 'error');
  }
}

async function saveAiPrompt(key, btn) {
  const card = btn.closest('.prompt-card');
  const ta   = card?.querySelector('.prompt-textarea');
  if (!ta) return;
  const text     = ta.value.trim();
  const defaultV = ta.dataset.default || '';
  // If user typed the default exactly, treat that as a reset
  const payload  = (text && text !== defaultV) ? text : '';
  const label    = card?.querySelector('strong')?.textContent || key;
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Saving…';
  const r = await api('POST', '/ai/prompts', { key, text: payload });
  btn.disabled = false;
  if (r?.ok) {
    btn.textContent = '✓ Saved';
    toast(payload ? `Saved custom prompt for "${label}"` : `Reverted "${label}" to default`, 'success');
    setTimeout(() => { btn.textContent = orig; loadAiPrompts(); }, 1500);
  } else {
    btn.textContent = '✗ Failed';
    setTimeout(() => { btn.textContent = orig; }, 2000);
    toast(r?.error || 'Save failed', 'error');
  }
}

async function resetAiPrompt(key, btn) {
  const card = btn.closest('.prompt-card');
  const ta   = card?.querySelector('.prompt-textarea');
  if (!ta) return;
  const label = card?.querySelector('strong')?.textContent || key;
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = '…';
  const r = await api('POST', '/ai/prompts', { key, text: '' });
  btn.disabled = false;
  if (r?.ok) {
    ta.value = ta.dataset.default || '';
    btn.textContent = '✓ Reverted';
    toast(`"${label}" reverted to default`, 'info');
    setTimeout(() => { btn.textContent = orig; loadAiPrompts(); }, 1500);
  } else {
    btn.textContent = '✗ Failed';
    setTimeout(() => { btn.textContent = orig; }, 2000);
    toast(r?.error || 'Reset failed', 'error');
  }
}

// Hook into the existing settings tab switcher — load prompts when AI pane opens
const _origSwitchSettingsTab2 = typeof switchSettingsTab === 'function' ? switchSettingsTab : null;
if (_origSwitchSettingsTab2) {
  window.switchSettingsTab = function(tab) {
    _origSwitchSettingsTab2(tab);
    if (tab === 'ai') loadAiPrompts();
    // Note: 'ignored' tab loads via its inline onclick (loadIgnoredItems)
  };
}

// v3.0.1: per-item ignores ────────────────────────────────────────────────
async function ignoreContainerDevice(deviceId, name) {
  if (!confirm(`Hide "${name}" from the Containers page?\n\nRestore from Settings → Ignored items.`)) return;
  // Use the 'devices' category — it's a fleet-wide ignore of the device on
  // the Containers page, regardless of stale state.
  const r = await api('POST', '/ignored', {
    category: 'devices',
    id:       deviceId,
    label:    name,
  });
  if (r?.ok) {
    toast('Hidden (restore from Settings → Ignored items)', 'success');
    loadContainersOverview();
  } else {
    toast(r?.error || 'Failed', 'error');
  }
}

async function loadIgnoredItems() {
  const list = document.getElementById('ignored-items-list');
  if (!list) return;
  const data = await api('GET', '/ignored');
  if (!data) { list.innerHTML = '<div class="empty-state">Failed to load.</div>'; return; }
  const sections = [
    { key: 'needs_attention',  label: 'Needs Attention',  identify: e => e.key },
    { key: 'stale_containers', label: 'Stale containers', identify: e => `${e.device_id}/${e.container}` },
    { key: 'devices',          label: 'Devices',          identify: e => e.id },
  ];
  let html = '';
  for (const sec of sections) {
    const entries = data[sec.key] || [];
    html += `<div class="mb-16">
      <h4 class="isl-668">${sec.label} <span class="isl-74">(${entries.length})</span></h4>`;
    if (!entries.length) {
      html += '<div class="isl-616">— none —</div>';
    } else {
      html += entries.map(e => {
        const id = sec.identify(e);
        const when = e.ts ? new Date(e.ts * 1000).toLocaleString() : '';
        return `<div class="isl-669">
          <div class="isl-618">${escHtml(e.label || id)}<div class="meta-sm-nm">${escHtml(when)}</div></div>
          <button class="btn-secondary badge-sm" data-action-btn="_restoreIgnoredFromStore" data-store-key="${_storeEvtData([sec.key, e])}">Restore</button>
        </div>`;
      }).join('');
    }
    html += '</div>';
  }
  list.innerHTML = html;
}

async function restoreIgnored(category, entry) {
  const body = { category };
  if (category === 'needs_attention')  body.key = entry.key;
  if (category === 'stale_containers') { body.device_id = entry.device_id; body.container = entry.container; }
  if (category === 'devices')          body.id = entry.id;
  const r = await api('POST', '/ignored/remove', body);
  if (r?.ok) { toast('Restored', 'success'); loadIgnoredItems(); }
  else toast(r?.error || 'Failed', 'error');
}

// v3.0.1: force-upgrade agent — re-deploy the current bundled binary
// regardless of whether the agent already reports that version. Useful for:
//   - rolling out a rebuilt binary at the same version
//   - recovery after a corrupt/truncated previous update
//   - testing the self-update path
async function forceAgentUpgrade(deviceId, name) {
  if (!confirm(`Force-upgrade agent on "${name}"?\n\nThe agent will re-download and replace its binary on the next heartbeat, even if it already reports the current version. Use this for corrupt-binary recovery or to push a rebuild.`)) return;
  const r = await api('POST', `/devices/${encodeURIComponent(deviceId)}/agent/force-upgrade`, {});
  if (r?.ok) toast(r.message || 'Force-upgrade scheduled', 'success');
  else toast(r?.error || 'Failed', 'error');
}

// v3.0.1: collapsible sidebar — toggle and persist preference in localStorage
function toggleSidebarCollapse() {
  const collapsed = document.body.classList.toggle('sidebar-collapsed');
  localStorage.setItem('rp_sidebar_collapsed', collapsed ? '1' : '0');
  const ico = document.getElementById('sidebar-collapse-icon');
  if (ico) ico.textContent = collapsed ? '▶' : '◀';
}
// Restore preference on load. Use DOMContentLoaded so the class is applied
// before the first paint — avoids a flash of the expanded sidebar.
(function _initSidebarCollapse() {
  if (localStorage.getItem('rp_sidebar_collapsed') === '1') {
    document.body.classList.add('sidebar-collapsed');
    // The icon may not exist yet — patch it once DOM is ready
    document.addEventListener('DOMContentLoaded', () => {
      const ico = document.getElementById('sidebar-collapse-icon');
      if (ico) ico.textContent = '▶';
    });
  }
})();

// v3.0.1: short-window in-flight cache for GET /devices. Multiple pages
// (Monitor in particular) fan out to 3+ independent loaders that each call
// /devices; without this they all hit the server. Re-use a single promise
// for any /devices fetch that lands within 500 ms of an existing one.
(function _installDevicesCoalescer() {
  if (!window.api) return;            // api() must already be defined
  const _origApi = window.api;
  let _inflight = null;
  let _expires = 0;
  window.api = function(method, path, body, opts) {
    if (method === 'GET' && path === '/devices') {
      const now = Date.now();
      if (_inflight && now < _expires) return _inflight;
      _expires = now + 500;
      _inflight = _origApi(method, path, body, opts).finally(() => {
        // Let the next fetch through immediately after settlement so
        // subsequent independent loads (different page, manual refresh)
        // get a fresh response.
        _inflight = null;
      });
      return _inflight;
    }
    return _origApi(method, path, body, opts);
  };
})();

// ══ v3.0.1: ACME / acme.sh integration ════════════════════════════════════
// Fleet-wide cert table under the TLS/DNS page. Three modal flows:
//   1. loadAcme()         — refresh the table
//   2. acmeOpenIssue()    — 3-step wizard to issue a new cert (DNS-01)
//   3. acmeOpenDetail()   — per-cert overview / timeline / logs
// All backend calls go through /api/acme; the server queues acme.sh on the
// device via the standard exec: channel and captures output to acme_logs/.
// ════════════════════════════════════════════════════════════════════════════

let _acmeData = { devices: [], providers: {} };

// v3.3.0: DNS provider credential management. The Settings UI surfaces
// per-provider form cards; the server stores values under
// config.acme_dns_credentials[provider] and injects them as env vars
// when issuing certs. Blank input fields = "leave unchanged" (the
// server preserves existing values), so secrets never have to be
// re-entered to make a different change.
async function openAcmeDnsCreds() {
  openModal('acme-dns-creds-modal');
  const body = document.getElementById('acme-dns-creds-body');
  if (body) body.innerHTML = '<div class="isl-78">Loading…</div>';
  const data = await api('GET', '/acme/dns-credentials').catch(() => null);
  if (!data || !data.providers) {
    if (body) body.innerHTML = '<div class="hint">Failed to load credentials.</div>';
    return;
  }
  _renderAcmeDnsCreds(data.providers);
}

function _renderAcmeDnsCreds(providers) {
  const body = document.getElementById('acme-dns-creds-body');
  if (!body) return;
  // Sort: any provider with at least one field set first, then alphabetical.
  providers.sort((a, b) => {
    const aSet = (a.fields || []).some(f => f.set) ? 0 : 1;
    const bSet = (b.fields || []).some(f => f.set) ? 0 : 1;
    if (aSet !== bSet) return aSet - bSet;
    return a.label.localeCompare(b.label);
  });
  body.innerHTML = providers.map(p => {
    const anySet = (p.fields || []).some(f => f.set);
    const fields = (p.fields || []).map(f => `
      <div class="form-group">
        <label class="form-label">${escHtml(f.label)}${f.required ? ' <span class="c-red">*</span>' : ''}${f.set ? ' <span class="meta-sm c-green">(set)</span>' : ''}</label>
        <input type="${f.secret ? 'password' : 'text'}" class="form-input ff-mono"
               data-cred-field="${escAttr(f.name)}"
               placeholder="${f.set ? '••••••• (leave blank to keep)' : (f.hint || '')}"
               autocomplete="off">
        ${f.hint && !f.set ? `<div class="meta-sm c-muted">${escHtml(f.hint)}</div>` : ''}
      </div>
    `).join('');
    return `
      <details class="settings-section" ${anySet ? 'open' : ''} data-provider="${escAttr(p.provider)}">
        <summary><strong>${escHtml(p.label)}</strong>${anySet ? ' <span class="meta-sm c-green">(configured)</span>' : ''} <span class="meta-sm c-muted">${escHtml(p.provider)}</span></summary>
        ${fields}
        <div class="row-6">
          <button class="btn-primary" data-action="saveAcmeDnsCreds" data-arg="${escAttr(p.provider)}">Save</button>
          ${anySet ? `<button class="btn-secondary c-danger-outline" data-action="clearAcmeDnsCreds" data-arg="${escAttr(p.provider)}">Clear all</button>` : ''}
        </div>
      </details>
    `;
  }).join('');
}

async function saveAcmeDnsCreds(providerKey) {
  const block = document.querySelector(`[data-provider="${providerKey}"]`);
  if (!block) return;
  const creds = {};
  block.querySelectorAll('[data-cred-field]').forEach(inp => {
    const name = inp.dataset.credField;
    const v = (inp.value || '').trim();
    if (v) creds[name] = v;  // blank = leave unchanged
  });
  const r = await api('POST', '/acme/dns-credentials', {
    provider:    providerKey,
    credentials: creds,
  });
  if (r?.ok) {
    toast(`${providerKey} credentials saved`, 'success');
    openAcmeDnsCreds();  // refresh to pick up "set" flags
  } else {
    toast(r?.error || 'Failed to save', 'error');
  }
}

async function clearAcmeDnsCreds(providerKey) {
  if (!confirm(`Clear ALL stored credentials for ${providerKey}?\n\nFuture issuances/renewals will fall back to whatever the agent has in ~/.acme.sh/account.conf.`)) return;
  // Send explicit nulls for every field this provider declares so the
  // server clears them all in one call.
  const block = document.querySelector(`[data-provider="${providerKey}"]`);
  if (!block) return;
  const creds = {};
  block.querySelectorAll('[data-cred-field]').forEach(inp => {
    creds[inp.dataset.credField] = null;
  });
  const r = await api('POST', '/acme/dns-credentials', {
    provider:    providerKey,
    credentials: creds,
  });
  if (r?.ok) { toast(`${providerKey} credentials cleared`, 'info'); openAcmeDnsCreds(); }
  else toast(r?.error || 'Failed', 'error');
}

async function loadAcme() {
  const tbody = document.getElementById('acme-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="8" class="empty-state-sm">Loading…</td></tr>';
  const data = await api('GET', '/acme');
  if (!data) { tbody.innerHTML = '<tr><td colspan="8" class="isl-670">Failed to load.</td></tr>'; return; }
  _acmeData = data;
  _acmeRenderTable();
}

function _acmeRenderTable() {
  const tbody = document.getElementById('acme-tbody');
  const empty = document.getElementById('acme-empty');
  const card  = document.getElementById('acme-table-card');
  if (!tbody) return;
  // v3.2.1: wire sort. The thead is static (in index.html), so we
  // re-wire on every render just in case the table-card was toggled
  // hidden + back. _wireHeaders is idempotent on a given DOM node.
  tableCtl.wireSortOnly('acme-thead', 'acme', _acmeRenderTable);

  // Flatten devices → one row per cert. Devices without acme.sh installed
  // are skipped entirely (v3.0.2) — they were rendered as "acme.sh not
  // installed" rows but operators with most of their fleet on different
  // cert managers don't need to see one row per such device. The "no
  // certs yet" case (acme.sh present but no certs issued) is still shown
  // because that's actionable — operator can click "+ Issue" right there.
  const q = (document.getElementById('acme-filter')?.value || '').trim().toLowerCase();
  const rows = [];
  let suppressed_unavailable = 0;
  for (const dev of (_acmeData.devices || [])) {
    if (!dev.available) {
      suppressed_unavailable++;
      continue;
    }
    if (!dev.certs || !dev.certs.length) {
      if (!q || dev.device_name.toLowerCase().includes(q)) {
        rows.push({ _kind: 'no-certs', device_id: dev.device_id, device_name: dev.device_name, home: dev.home, version: dev.version });
      }
      continue;
    }
    for (const cert of dev.certs) {
      if (q) {
        const hay = `${dev.device_name} ${cert.domain || ''} ${cert.challenge || ''} ${cert.dns_provider_label || cert.dns_provider || ''}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }
      rows.push({ _kind: 'cert', device_id: dev.device_id, device_name: dev.device_name, ...cert });
    }
  }
  // Surface the suppressed count subtly so operators don't think the
  // table is broken when only N of M devices appear.
  const hint = document.getElementById('acme-suppressed-hint');
  if (hint) {
    if (suppressed_unavailable > 0) {
      hint.textContent = `${suppressed_unavailable} device${suppressed_unavailable === 1 ? '' : 's'} without acme.sh hidden`;
      hint.style.display = 'block';
    } else {
      hint.style.display = 'none';
    }
  }

  if (!rows.length) {
    if (card)  card.style.display = 'none';
    if (empty) empty.style.display = 'block';
    return;
  }
  if (card)  card.style.display = 'block';
  if (empty) empty.style.display = 'none';

  // v3.2.1: apply user's chosen sort order. getColumns maps each row
  // (cert or no-certs placeholder) into comparable values so device
  // rows without certs still sort by name alongside real cert rows.
  const _now = Math.floor(Date.now() / 1000);
  const sortedRows = tableCtl.sortRows('acme', rows, (r) => ({
    device_name: r.device_name || '',
    domain:      r.domain || '',
    challenge:   r.is_dns_challenge ? 'DNS-01' : (r.challenge || ''),
    provider:    r.dns_provider_label || r.dns_provider || '',
    created:     r.created_ts || 0,
    renew:       r.next_renew_ts || Infinity,
    // "status" sort key = days until renewal (negative = overdue)
    status:      r.next_renew_ts ? Math.round((r.next_renew_ts - _now) / 86400) : Infinity,
  }));

  const now = _now;
  const html = sortedRows.map(r => {
    if (r._kind === 'unavailable') {
      return `<tr class="isl-671">
        <td>${escHtml(r.device_name)}</td>
        <td colspan="6" class="isl-672">acme.sh not installed on this device</td>
        <td></td>
      </tr>`;
    }
    if (r._kind === 'no-certs') {
      return `<tr class="isl-673">
        <td>${escHtml(r.device_name)}</td>
        <td colspan="6" class="hint">acme.sh ${escHtml(r.version || '')} installed at <code>${escHtml(r.home)}</code> — no certs yet</td>
        <td class="row-4">
          <button class="btn-icon badge-sm" title="Issue a new cert" data-action="acmeOpenIssue" data-arg="${escAttr(r.device_id)}" >+ Issue</button>
          <button class="btn-icon badge-sm" title="Force agent to rescan ~/.acme.sh on next heartbeat (default cadence is hourly)" data-stop-prop="1" data-action="acmeForceRescan" data-arg="${escAttr(r.device_id)}" >Rescan</button>
        </td>
      </tr>`;
    }
    // Real cert row
    const days = r.next_renew_ts ? Math.round((r.next_renew_ts - now) / 86400) : null;
    let pillCls = 'acme-pill-info', pillText = 'unknown';
    if (days === null) { pillCls = 'acme-pill-info'; pillText = 'no schedule'; }
    else if (days < 0) { pillCls = 'acme-pill-crit'; pillText = `overdue ${-days}d`; }
    else if (days <= 3){ pillCls = 'acme-pill-crit'; pillText = `${days}d`; }
    else if (days <= 14){ pillCls = 'acme-pill-warn'; pillText = `${days}d`; }
    else { pillCls = 'acme-pill-ok'; pillText = `${days}d`; }
    const wildcardGlyph = r.is_wildcard ? '<span class="acme-wildcard-glyph" title="Wildcard cert">★</span>' : '';
    const altCount = (r.alt_names || []).filter(a => a !== r.domain).length;
    const altLabel = altCount ? `<span class="meta-sm-nm"> +${altCount} SAN</span>` : '';
    const challengeLabel = r.is_dns_challenge ? 'DNS-01' : (r.challenge || '—');
    const providerLabel  = r.dns_provider_label || (r.is_dns_challenge ? r.dns_provider : '—');
    const createdStr = r.created_ts ? new Date(r.created_ts * 1000).toLocaleDateString() : '—';
    const renewStr   = r.next_renew_ts ? new Date(r.next_renew_ts * 1000).toLocaleDateString() : '—';
    return `<tr class="acme-row" data-action="acmeOpenDetail" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.domain)}" >
      <td>${escHtml(r.device_name)}</td>
      <td>
        <code class="isl-674">${escHtml(r.domain)}</code>${wildcardGlyph}${altLabel}
      </td>
      <td><span class="acme-pill acme-pill-info">${challengeLabel}</span></td>
      <td class="hint">${escHtml(providerLabel)}</td>
      <td class="hint">${createdStr}</td>
      <td class="fs-12">${renewStr}</td>
      <td><span class="acme-pill ${pillCls}">${pillText}</span></td>
      <td data-stop-prop="1" class="nowrap">
        <button class="btn-icon badge-xs" title="Force renew now"
                data-action="acmeForceRenew" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.domain)}" >${_icon('refresh',14)}</button>
        <button class="btn-icon badge-xs c-danger-outline" title="Revoke and remove"
                data-action="acmeRevoke" data-arg="${escAttr(r.device_id)}" data-arg2="${escAttr(r.domain)}" >${_icon('trash',14)}</button>
      </td>
    </tr>`;
  }).join('');
  tbody.innerHTML = html;
}

// ── Force renew ──────────────────────────────────────────────────────────
async function acmeForceRenew(devId, domain) {
  if (!confirm(`Force-renew cert for ${domain}?\n\nLet's Encrypt rate-limits to 5 duplicates per week. Use sparingly.`)) return;
  const r = await api('POST', `/acme/${encodeURIComponent(devId)}/${encodeURIComponent(domain)}/renew`);
  if (r?.ok) {
    toast(`Renew queued — output in detail view (Logs tab)`, 'success');
    // Re-open detail so the user can follow along
    acmeOpenDetail(devId, domain);
  } else {
    toast(r?.error || 'Failed to queue renewal', 'error');
  }
}

// ── Revoke ───────────────────────────────────────────────────────────────
async function acmeRevoke(devId, domain) {
  if (!confirm(`Revoke and remove cert for ${domain}?\n\nThis tells Let's Encrypt the cert is no longer trusted, then deletes the local files. To issue a fresh one afterwards, use the "Issue new cert" wizard.`)) return;
  const r = await api('POST', `/acme/${encodeURIComponent(devId)}/${encodeURIComponent(domain)}/revoke`);
  if (r?.ok) {
    toast('Revoke + remove queued', 'success');
    setTimeout(loadAcme, 4000);
  } else {
    toast(r?.error || 'Failed to revoke', 'error');
  }
}

// ── Detail modal ─────────────────────────────────────────────────────────
let _acmeDetailContext = null;

async function acmeOpenDetail(devId, domain) {
  _acmeDetailContext = { devId, domain };
  document.getElementById('acme-detail-title').textContent = domain;
  document.getElementById('acme-detail-subtitle').textContent = '';
  document.getElementById('acme-detail-overview').innerHTML = '<div class="empty-p20">Loading…</div>';
  document.getElementById('acme-detail-timeline').innerHTML = '';
  document.getElementById('acme-detail-logs').innerHTML = '';
  acmeDetailTab('overview');
  openModal('acme-detail-modal');
  const r = await api('GET', `/acme/${encodeURIComponent(devId)}/${encodeURIComponent(domain)}`);
  if (!r || !r.cert) {
    document.getElementById('acme-detail-overview').innerHTML =
      `<div class="isl-676">${escHtml(r?.error || 'Cert not found in last scan')}</div>`;
    return;
  }
  _acmeRenderDetail(r);
}

function acmeDetailTab(tab) {
  document.querySelectorAll('#acme-detail-modal .drawer-tab-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.acmeTab === tab));
  document.querySelectorAll('.acme-detail-pane').forEach(p =>
    p.style.display = p.id === `acme-detail-${tab}` ? '' : 'none');
}

function _acmeRenderDetail(r) {
  const c = r.cert;
  const dev = (_acmeData.devices || []).find(d => d.device_id === _acmeDetailContext.devId);
  const devName = dev ? dev.device_name : _acmeDetailContext.devId;
  document.getElementById('acme-detail-subtitle').textContent =
    `on ${devName}${c.is_wildcard ? ' · wildcard' : ''} · ${c.is_dns_challenge ? c.dns_provider_label || c.dns_provider : c.challenge}`;

  // ─── Overview ─────────────────────────────────────────────────────────
  const now = Math.floor(Date.now() / 1000);
  const daysToRenew = c.next_renew_ts ? Math.round((c.next_renew_ts - now) / 86400) : null;
  const overview = `
    <div class="isl-677">
      ${_acmeStatPill('Primary domain', `<code>${escHtml(c.domain)}</code>`)}
      ${_acmeStatPill('Wildcard?', c.is_wildcard ? '<span class="isl-678">★ yes</span>' : 'no')}
      ${_acmeStatPill('Key length', escHtml(c.key_length || '—'))}
      ${_acmeStatPill('Challenge', c.is_dns_challenge ? `DNS-01 · ${escHtml(c.dns_provider_label || c.dns_provider)}` : escHtml(c.challenge || '—'))}
      ${_acmeStatPill('Created', c.created_str ? escHtml(c.created_str) : '—')}
      ${_acmeStatPill('Next renewal', c.next_renew_str ? `${escHtml(c.next_renew_str)}<br><span class="meta-sm-nm">${daysToRenew !== null ? `in ${daysToRenew}d` : ''}</span>` : '—')}
    </div>
    ${c.alt_names && c.alt_names.length ? `
      <div class="mb-14">
        <div class="isl-679">Subject Alternative Names</div>
        <div class="isl-680">
          ${c.alt_names.map(a => `<code class="isl-681">${escHtml(a)}</code>`).join('')}
        </div>
      </div>` : ''}
    ${c.reload_cmd ? `
      <div class="mb-14">
        <div class="isl-679">Post-renewal hook (Le_ReloadCmd)</div>
        <pre class="isl-259">${escHtml(c.reload_cmd)}</pre>
        <div class="meta-sm">Managed by acme.sh — not modified by RemotePower.</div>
      </div>` : `
      <div class="isl-682">No reload hook configured for this cert.</div>`}
    ${c.cert_path ? `
      <div class="isl-683">
        <div>Cert: <code>${escHtml(c.cert_path)}</code></div>
        ${c.fullchain_path ? `<div>Fullchain: <code>${escHtml(c.fullchain_path)}</code></div>` : ''}
        ${c.key_path ? `<div>Key: <code>${escHtml(c.key_path)}</code></div>` : ''}
      </div>` : ''}
    <div class="isl-265">
      <button class="btn-icon" data-action="acmeForceRenew" data-arg="${escAttr(_acmeDetailContext.devId)}" data-arg2="${escAttr(c.domain)}" >Force renew</button>
      <button class="btn-icon c-red" data-action="acmeRevoke" data-arg="${escAttr(_acmeDetailContext.devId)}" data-arg2="${escAttr(c.domain)}" >✗ Revoke + remove</button>
    </div>`;
  document.getElementById('acme-detail-overview').innerHTML = overview;

  // ─── Timeline ─────────────────────────────────────────────────────────
  const events = [];
  if (c.created_ts)    events.push({ ts: c.created_ts,    label: 'Cert issued',     state: 'ok' });
  if (c.next_renew_ts) events.push({ ts: c.next_renew_ts, label: 'Next renewal',    state: c.next_renew_ts < now ? 'fail' : 'pending' });
  for (const l of (r.logs || [])) {
    events.push({
      ts:    l.ts,
      label: l.action === 'renew' ? 'Force renewal' :
             l.action === 'issue' ? 'Issue command' :
             l.action === 'revoke'? 'Revoke command' : (l.action || 'action'),
      state: l.rc === 0 ? 'ok' : (l.rc === null || l.rc === undefined ? 'pending' : 'fail'),
      logId: l.id,
      rc:    l.rc,
    });
  }
  events.sort((a, b) => b.ts - a.ts);
  const timeline = events.length ? events.map(e => `
    <div class="acme-timeline-item">
      <div class="acme-timeline-dot ${e.state}"></div>
      <div class="flex-1">
        <div class="fw-500">${escHtml(e.label)}${e.rc !== undefined && e.rc !== null ? ` <span class="meta-sm-nm">(rc=${e.rc})</span>` : ''}</div>
        <div class="meta-sm-nm">${new Date(e.ts * 1000).toLocaleString()}</div>
        ${e.logId ? `<button class="btn-icon isl-684" data-action="acmeLoadLog" data-arg="${escAttr(e.logId)}" >View log</button>` : ''}
      </div>
    </div>`).join('') : '<div class="empty-p20">No timeline events yet.</div>';
  document.getElementById('acme-detail-timeline').innerHTML = timeline;

  // ─── Logs tab ─ list of recent log captures ───────────────────────────
  const logsHtml = (r.logs && r.logs.length) ? `
    <div class="isl-563">Captured stdout from acme.sh runs queued by RemotePower. Click any entry to view.</div>
    <div class="isl-201">
      ${r.logs.map(l => {
        const isPending   = l.rc === null || l.rc === undefined;
        const isCancelled = l.rc === -3 || l.rc === -4;
        let stateLabel;
        if (isCancelled) stateLabel = `<span class="c-muted">⊘ cancelled</span>`;
        else if (isPending) stateLabel = `<span class="c-amber">pending</span>`;
        else if (l.rc === 0) stateLabel = `<span class="c-green">✓ rc=0</span>`;
        else stateLabel = `<span class="c-red">✗ rc=${l.rc}</span>`;
        return `<div class="row-6-center">
          <button class="btn-secondary isl-685"
                  data-action="acmeLoadLog" data-arg="${escAttr(l.id)}" >
            <span>
              <strong>${escHtml(l.action || 'action')}</strong>
              <span class="isl-686">${new Date(l.ts * 1000).toLocaleString()}</span>
            </span>
            <span class="meta-sm-nm">
              ${stateLabel} · ${(l.size / 1024).toFixed(1)} KB
            </span>
          </button>
          ${isPending ? `<button class="btn-icon isl-687" title="Cancel — remove from queue if still pending" data-action="acmeCancelAction" data-arg="${escAttr(l.id)}" >⊘ Cancel</button>` : ''}
          <button class="btn-icon isl-688" title="Ignore — delete this row from the log list (does not affect cert state)" data-action="acmeIgnoreAction" data-arg="${escAttr(l.id)}" >× Ignore</button>
        </div>`;
      }).join('')}
    </div>
    <div id="acme-log-view" class="isl-70"></div>` : '<div class="empty-p20">No logs yet. Trigger a force renew to capture one.</div>';
  document.getElementById('acme-detail-logs').innerHTML = logsHtml;
}

function _acmeStatPill(label, valueHtml) {
  return `<div class="isl-689">
    <div class="isl-367">${escHtml(label)}</div>
    <div class="fs-13">${valueHtml}</div>
  </div>`;
}

async function acmeLoadLog(logId) {
  if (!_acmeDetailContext) return;
  const view = document.getElementById('acme-log-view');
  const target = view || document.getElementById('acme-detail-logs');
  target.innerHTML = '<div class="isl-690">Loading log…</div>';
  const r = await api('GET', `/acme/${encodeURIComponent(_acmeDetailContext.devId)}/log/${encodeURIComponent(logId)}`);
  if (!r) { target.innerHTML = '<div class="isl-691">Failed to load log</div>'; return; }
  target.innerHTML = `
    <div class="isl-692">Action <code>${escHtml(logId)}</code> · ${(r.size / 1024).toFixed(1)} KB</div>
    <pre class="isl-693">${escHtml(r.content)}</pre>`;
}

// ── Issue wizard ─────────────────────────────────────────────────────────
let _acmeIssueStep = 1;

function acmeOpenIssue(presetDeviceId) {
  // Populate device dropdown with devices that have acme.sh available
  const devSel = document.getElementById('acme-issue-device');
  const eligibleDevs = (_acmeData.devices || []).filter(d => d.available);
  if (!eligibleDevs.length) {
    toast('No devices have acme.sh installed. Install it on a device and wait for the next scan (~1 hour).', 'error');
    return;
  }
  devSel.innerHTML = eligibleDevs.map(d =>
    `<option value="${escAttr(d.device_id)}">${escHtml(d.device_name)}${d.version ? ` (${escHtml(d.version)})` : ''}</option>`).join('');
  if (presetDeviceId) devSel.value = presetDeviceId;

  // Populate DNS provider dropdown from server's provider map
  const dnsSel = document.getElementById('acme-issue-dns');
  const providers = _acmeData.providers || {};
  dnsSel.innerHTML = Object.entries(providers).map(([key, label]) =>
    `<option value="${escAttr(key)}">${escHtml(label)} (<code>${escHtml(key)}</code>)</option>`).join('');
  dnsSel.value = 'dns_cf';   // sensible default
  _acmeUpdateTokenHint();

  // Reset state
  document.getElementById('acme-issue-domain').value = '';
  document.getElementById('acme-issue-alt').value = '';
  document.getElementById('acme-issue-wildcard').checked = false;
  document.getElementById('acme-issue-keylen').value = '4096';
  _acmeIssueStep = 1;
  _acmeRenderStep();
  // Live preview of wildcard label as user types
  const domInput = document.getElementById('acme-issue-domain');
  domInput.oninput = () => {
    const d = domInput.value.trim() || 'example.com';
    document.getElementById('acme-issue-wildcard-preview').textContent = `*.${d}`;
  };
  dnsSel.onchange = _acmeUpdateTokenHint;
  openModal('acme-issue-modal');
  setTimeout(() => domInput.focus(), 50);
}

function _acmeUpdateTokenHint() {
  const dns = document.getElementById('acme-issue-dns').value;
  const hints = {
    'dns_cf':       'Cloudflare requires <code>CF_Token</code> + <code>CF_Account_ID</code> + <code>CF_Zone_ID</code> (or legacy <code>CF_Key</code>/<code>CF_Email</code>) exported in the agent\'s environment, or stored in <code>~/.acme.sh/account.conf</code>. acme.sh will fail in step 3 with a clear message if these are missing.',
    'dns_aws':      'AWS Route 53 requires <code>AWS_ACCESS_KEY_ID</code> + <code>AWS_SECRET_ACCESS_KEY</code>.',
    'dns_dgon':     'DigitalOcean requires <code>DO_API_KEY</code>.',
    'dns_he':       'Hurricane Electric requires <code>HE_Username</code> + <code>HE_Password</code>.',
    'dns_desec':    'deSEC requires <code>DEDYN_TOKEN</code>.',
    'dns_hetzner':  'Hetzner requires <code>HETZNER_Token</code>.',
    'dns_porkbun':  'Porkbun requires <code>PORKBUN_API_KEY</code> + <code>PORKBUN_SECRET_API_KEY</code>.',
  };
  document.getElementById('acme-issue-token-hint').innerHTML = hints[dns] ||
    'API credentials must be exported in the agent\'s environment or written to <code>~/.acme.sh/account.conf</code> on the device.';
}

function acmeIssueStep(delta) {
  // Validate before advancing
  if (delta > 0 && _acmeIssueStep === 1) {
    const d = document.getElementById('acme-issue-domain').value.trim();
    if (!d) { toast('Primary domain is required', 'error'); return; }
    // very loose client-side check; server re-validates
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(d)) { toast('Domain looks invalid', 'error'); return; }
  }
  _acmeIssueStep = Math.max(1, Math.min(3, _acmeIssueStep + delta));
  _acmeRenderStep();
}

function _acmeRenderStep() {
  document.querySelectorAll('.acme-step').forEach(el => {
    el.style.display = parseInt(el.dataset.step) === _acmeIssueStep ? '' : 'none';
  });
  document.querySelectorAll('.acme-step-pill').forEach(el => {
    const s = parseInt(el.dataset.step);
    el.classList.toggle('active', s === _acmeIssueStep);
    el.classList.toggle('done', s < _acmeIssueStep);
  });
  document.getElementById('acme-issue-back').style.display = _acmeIssueStep > 1 ? '' : 'none';
  document.getElementById('acme-issue-next').style.display = _acmeIssueStep < 3 ? '' : 'none';
  document.getElementById('acme-issue-go').style.display   = _acmeIssueStep === 3 ? '' : 'none';
  if (_acmeIssueStep === 3) _acmeRenderPreview();
}

function _acmeRenderPreview() {
  const domain = document.getElementById('acme-issue-domain').value.trim().toLowerCase();
  const wildcard = document.getElementById('acme-issue-wildcard').checked;
  const altRaw = document.getElementById('acme-issue-alt').value;
  const dns = document.getElementById('acme-issue-dns').value;
  const keylen = document.getElementById('acme-issue-keylen').value;
  const alts = altRaw.split('\n').map(s => s.trim()).filter(Boolean);
  const allDomains = [domain];
  if (wildcard) allDomains.push(`*.${domain}`);
  for (const a of alts) if (a !== domain && !allDomains.includes(a)) allDomains.push(a);
  const dArgs = allDomains.map(d => `-d '${d}'`).join(' ');
  document.getElementById('acme-issue-preview').textContent =
    `~/.acme.sh/acme.sh --issue --dns ${dns} ${dArgs} --keylength ${keylen}`;
}

async function acmeIssueSubmit() {
  const devId = document.getElementById('acme-issue-device').value;
  const domain = document.getElementById('acme-issue-domain').value.trim().toLowerCase();
  const wildcard = document.getElementById('acme-issue-wildcard').checked;
  const altRaw = document.getElementById('acme-issue-alt').value;
  const dns = document.getElementById('acme-issue-dns').value;
  const keylen = document.getElementById('acme-issue-keylen').value;
  const alts = altRaw.split('\n').map(s => s.trim()).filter(Boolean);
  if (wildcard) alts.push(`*.${domain}`);
  const body = {
    domain, alt_names: alts, dns_provider: dns, key_length: keylen,
  };
  const btn = document.getElementById('acme-issue-go');
  btn.disabled = true; btn.textContent = 'Queuing…';
  const r = await api('POST', `/acme/${encodeURIComponent(devId)}/issue`, body);
  btn.disabled = false; btn.textContent = 'Queue issue command';
  if (r?.ok) {
    toast(`Issue queued for ${domain} — output appears in the Logs tab once the agent runs it`, 'success');
    closeModal('acme-issue-modal');
    acmeOpenDetail(devId, domain);
    setTimeout(loadAcme, 5000);
  } else {
    toast(r?.error || 'Failed to queue', 'error');
  }
}

// Auto-load when the TLS page opens. enterTLS() already exists; wrap it so
// we also kick off the ACME table fetch without modifying its body.
const _origEnterTLS = typeof enterTLS === 'function' ? enterTLS : null;
if (_origEnterTLS) {
  window.enterTLS = function() {
    _origEnterTLS();
    loadAcme();
  };
}


// ── v3.0.1: Mitigation runner ─────────────────────────────────────────────
// Open from a Needs Attention card. Three tabs: Diagnostic (auto-runs on
// open), AI Analysis (auto-runs when diagnostic completes), Apply Fix
// (user-confirmed). All exec happens via the existing agent command queue,
// tagged so server captures the output to a dedicated log file.

let _mitigateCtx = null;           // { devId, kind, target, actionId, deviceName }
let _mitigatePollTimer = null;
let _mitigatePollAttempts = 0;
// v3.2.1 fix: 90 * 2s = 3 min was too tight for the disk diagnostic on
// busy servers (du walk can take 5+ min). Bumped to 180 * 2s = 6 min,
// which covers the agent's 300s exec timeout plus a heartbeat round
// trip. The agent itself kills the exec at 300s with rc=-1 so we never
// poll forever.
const _MITIGATE_POLL_MAX = 180;

const _MITIGATE_KIND_LABELS = {
  patches:      'Pending patches',
  disk:         'Disk pressure',
  drift:        'Config drift',
  service_down: 'Service down',
  reboot:       'Reboot required',
  brute_force:  'Brute-force attempts',
  // v3.0.4: metric playbooks. The server now has _MITIGATE_PLAYBOOKS
  // entries for memory/swap/cpu; without these labels the modal title
  // falls back to the raw kind string ("Investigate: swap" — usable
  // but ugly), and the gate below would refuse the click entirely.
  memory:       'Memory pressure',
  swap:         'Swap pressure',
  cpu:          'CPU load',
};

// Which attention kinds support mitigation. Mirrors _MITIGATE_PLAYBOOKS keys
// on the server. Used to decide whether to show the Investigate button on a card.
// v3.0.4: added memory/swap/cpu — these alerts always fired with no
// available playbook before. The two lists are intentionally separate
// (labels also need a label) and both have to mention every kind.
const MITIGATE_KINDS = new Set([
  'patches', 'disk', 'drift', 'service_down', 'reboot', 'brute_force',
  'memory', 'swap', 'cpu',
]);

function openMitigateModal(devId, kind, target, deviceName) {
  if (!MITIGATE_KINDS.has(kind)) {
    toast(`No mitigation playbook for "${kind}" yet`, 'info');
    return;
  }
  _mitigateCtx = { devId, kind, target: target || '', deviceName: deviceName || devId, actionId: null };
  document.getElementById('mitigate-title').textContent =
    `Investigate: ${_MITIGATE_KIND_LABELS[kind] || kind}`;
  document.getElementById('mitigate-subtitle').textContent =
    `on ${deviceName || devId}${target ? ` · target: ${target}` : ''}`;
  // Reset UI
  document.getElementById('mitigate-diag-meta').textContent = 'Queueing diagnostic command…';
  document.getElementById('mitigate-diag-output').textContent = '';
  document.getElementById('mitigate-ai-status').textContent = '';
  document.getElementById('mitigate-ai-summary').textContent = '';
  document.getElementById('mitigate-ai-fix').textContent = '';
  document.getElementById('mitigate-ai-fix-box').style.display = 'none';
  document.getElementById('mitigate-ai-use').style.display = 'none';
  document.getElementById('mitigate-ai-fix-warning').style.display = 'none';
  document.getElementById('mitigate-fix-cmd').value = '';
  document.getElementById('mitigate-fix-confirm').value = '';
  document.getElementById('mitigate-fix-confirm-row').style.display = 'none';
  document.getElementById('mitigate-fix-safety').innerHTML = '';
  document.getElementById('mitigate-fix-options').innerHTML = '';
  document.getElementById('mitigate-fix-result').innerHTML = '';
  mitigateTab('diagnostic');
  openModal('mitigate-modal');
  _mitigateKickoff();
}

function closeMitigateModal() {
  if (_mitigatePollTimer) { clearTimeout(_mitigatePollTimer); _mitigatePollTimer = null; }
  _mitigateCtx = null;
  closeModal('mitigate-modal');
}

function mitigateTab(tab) {
  document.querySelectorAll('#mitigate-modal .drawer-tab-btn').forEach(b =>
    b.classList.toggle('active', b.dataset.mitTab === tab));
  document.querySelectorAll('.mitigate-pane').forEach(p =>
    p.style.display = p.id === `mitigate-pane-${tab}` ? '' : 'none');
}

// Step 1: queue the diagnostic
async function _mitigateKickoff() {
  const r = await api('POST', `/mitigate/${encodeURIComponent(_mitigateCtx.devId)}/investigate`,
    { kind: _mitigateCtx.kind, target: _mitigateCtx.target });
  if (!r || !r.ok || !r.action_id) {
    document.getElementById('mitigate-diag-meta').textContent =
      r?.error || 'Failed to queue diagnostic';
    return;
  }
  _mitigateCtx.actionId = r.action_id;
  document.getElementById('mitigate-diag-meta').textContent =
    `Queued (action ${r.action_id}). Agent picks it up within 60s, then runs ~10–30s depending on the diagnostic.`;
  _mitigatePollAttempts = 0;
  _mitigatePollDiag();
}

// Step 2: poll for diagnostic completion
async function _mitigatePollDiag() {
  if (!_mitigateCtx || !_mitigateCtx.actionId) return;
  _mitigatePollAttempts++;
  const r = await api('GET',
    `/mitigate/${encodeURIComponent(_mitigateCtx.devId)}/status/${encodeURIComponent(_mitigateCtx.actionId)}`);
  if (!r) {
    document.getElementById('mitigate-diag-meta').textContent = 'Failed to read status';
    return;
  }
  if (r.content) document.getElementById('mitigate-diag-output').textContent = r.content;
  if (r.done) {
    document.getElementById('mitigate-diag-meta').textContent =
      `Done (rc=${r.rc}) — captured ${(r.size/1024).toFixed(1)} KB. ` +
      (r.rc === 0 ? 'Triggering AI analysis…' : 'Diagnostic exited non-zero — AI will still try to interpret.');
    // Auto-trigger AI on completion
    setTimeout(_mitigateRunAi, 400);
    return;
  }
  if (_mitigatePollAttempts >= _MITIGATE_POLL_MAX) {
    document.getElementById('mitigate-diag-meta').textContent =
      'Timed out waiting for diagnostic. Agent may be offline. Close and retry, or check the agent\'s journal.';
    return;
  }
  _mitigatePollTimer = setTimeout(_mitigatePollDiag, 2000);
}

// Step 3: AI analysis
async function _mitigateRunAi() {
  if (!_mitigateCtx || !_mitigateCtx.actionId) return;
  mitigateTab('ai');
  const statusEl = document.getElementById('mitigate-ai-status');
  document.getElementById('mitigate-ai-summary').textContent = '';
  document.getElementById('mitigate-ai-fix-box').style.display = 'none';

  // v3.2.1 fix: live elapsed-time counter and abortable fetch. Without
  // visible movement, an AI provider that takes 30-300s to respond
  // (Ollama on a cold GPU) makes the modal look frozen. The counter
  // refreshes every second; after 30s an Abort button appears.
  const startedAt = Date.now();
  let aborted = false;
  const controller = (typeof AbortController !== 'undefined') ? new AbortController() : null;
  function _renderStatus() {
    const elapsed = Math.floor((Date.now() - startedAt) / 1000);
    let msg = `Asking the model… ${elapsed}s elapsed`;
    if (elapsed > 90) {
      msg += ' — local models on a cold GPU often take 1–2 min. If your provider should be fast, check the AI config.';
    } else if (elapsed > 45) {
      msg += ' — still working. Large prompts + slow models take time.';
    }
    const abortHtml = (elapsed > 30 && controller && !aborted)
      ? ' <button class="btn-icon c-danger-outline btn-xs" data-action="abortMitigateAi">Abort</button>'
      : '';
    statusEl.innerHTML = msg + abortHtml;
  }
  // v3.2.1: wire the Abort button BEFORE the await so the data-action
  // handler can find the function. (Defining it after the await is
  // never reached if the AI call hangs.)
  window.abortMitigateAi = function() {
    aborted = true;
    if (controller) { try { controller.abort(); } catch (_) {} }
  };
  _renderStatus();
  const _tick = setInterval(_renderStatus, 1000);

  let r;
  try {
    const opts = controller ? { signal: controller.signal } : {};
    r = await api('POST',
      `/mitigate/${encodeURIComponent(_mitigateCtx.devId)}/ai/${encodeURIComponent(_mitigateCtx.actionId)}`,
      {}, opts);
  } catch (e) {
    clearInterval(_tick);
    window.abortMitigateAi = null;
    if (aborted) {
      statusEl.textContent = 'Aborted. Close and retry, or change the AI provider in Settings → AI Assistant.';
    } else {
      statusEl.textContent = `Network error contacting AI: ${e && e.message ? e.message : e}`;
    }
    return;
  }
  clearInterval(_tick);
  window.abortMitigateAi = null;
  if (!r) {
    statusEl.textContent = 'AI call failed (no response from server — check Settings → AI Assistant and the nginx error log).';
    return;
  }
  if (r.error) {
    statusEl.textContent = '';
    document.getElementById('mitigate-ai-summary').textContent = `Error: ${r.error}`;
    return;
  }
  statusEl.textContent = `Done in ${Math.floor((Date.now() - startedAt) / 1000)}s.`;
  document.getElementById('mitigate-ai-summary').textContent = r.summary || '(empty response)';
  _mitigateRenderFixOptions(r);
}

function mitigateRerunAi() { _mitigateRunAi(); }

function _mitigateRenderFixOptions(aiResult) {
  // Show the suggested fix in the AI pane.
  // CSP L1: explicit display values for everything that's hidden by a
  // CSS class with `display: none` (was inline `style="display:none"`
  // pre-migration). Empty string would just remove the inline attribute
  // and leave the class rule in effect.
  if (aiResult.suggested_fix) {
    document.getElementById('mitigate-ai-fix-box').style.display = 'block';
    document.getElementById('mitigate-ai-fix').textContent = aiResult.suggested_fix;
    const warn = document.getElementById('mitigate-ai-fix-warning');
    if (aiResult.denylist_match) {
      warn.style.display = 'block';
      warn.innerHTML = `<div class="isl-694">
        <strong>Refused — denylist match.</strong>
        ${escHtml(aiResult.denylist_reason || '')}
        <div class="isl-121">
          This command will not be executed by RemotePower. Copy it manually if you really need to.
        </div>
      </div>`;
      document.getElementById('mitigate-ai-use').style.display = 'none';
    } else if (aiResult.requires_confirmation) {
      warn.style.display = 'block';
      warn.innerHTML = `<div class="isl-695">
        <strong>Sensitive — requires explicit RUN confirmation</strong>
        <div class="isl-696">Click "Use this as fix command" to take it to the Apply Fix tab, where you'll need to type RUN.</div>
      </div>`;
      document.getElementById('mitigate-ai-use').style.display = 'inline-flex';
    } else {
      warn.style.display = 'none';
      document.getElementById('mitigate-ai-use').style.display = 'inline-flex';
    }
  } else {
    document.getElementById('mitigate-ai-fix-box').style.display = 'none';
    document.getElementById('mitigate-ai-use').style.display = 'none';
  }
  // Populate the Apply Fix tab's options. Two slots:
  //   1) Pre-approved playbook fix (if any) — green button
  //   2) AI-suggested fix (if any, not denylisted)
  const opts = [];
  if (aiResult.preapproved_fix) {
    opts.push({
      kind: 'preapproved',
      cmd:  aiResult.preapproved_fix,
      label: aiResult.preapproved_fix_label || 'Pre-approved fix',
    });
  }
  if (aiResult.suggested_fix && !aiResult.denylist_match) {
    opts.push({
      kind: 'ai',
      cmd:  aiResult.suggested_fix,
      label: 'AI-suggested fix',
      sensitive: aiResult.requires_confirmation,
    });
  }
  const optsHtml = opts.map((o, i) => `
    <label class="isl-697">
      <input type="radio" name="mitigate-fix-pick" value="${i}" data-change="_mitigateSelectFixOption" data-change-arg="${i}" class="isl-698">
      <div class="isl-445">
        <div class="isl-699 ${o.kind === 'preapproved' ? 'is-pre' : ''}">
          ${o.kind === 'preapproved' ? '✓ ' : ''}${escHtml(o.label)}
          ${o.sensitive ? '<span class="isl-700">(RUN required)</span>' : ''}
        </div>
        <code class="isl-701">${escHtml(o.cmd)}</code>
      </div>
    </label>`).join('');
  document.getElementById('mitigate-fix-options').innerHTML = optsHtml ||
    '<div class="isl-702">No fix options available. Either nothing to do (read-only diagnostic), or the AI returned no actionable suggestion. You can still type a command manually below.</div>';
  // Stash for selection
  window._mitigateFixOpts = opts;
}

function _mitigateSelectFixOption(idx) {
  const o = (window._mitigateFixOpts || [])[idx];
  if (!o) return;
  document.getElementById('mitigate-fix-cmd').value = o.cmd;
  _mitigateUpdateSafety();
}

function mitigateUseAiFix() {
  const cmd = document.getElementById('mitigate-ai-fix').textContent;
  document.getElementById('mitigate-fix-cmd').value = cmd;
  mitigateTab('fix');
  _mitigateUpdateSafety();
}

function _mitigateUpdateSafety() {
  // Client-side preview of whether confirmation will be required. Server is
  // authoritative — this just gives the user a heads-up so they aren't
  // surprised by the 400 response.
  const cmd = document.getElementById('mitigate-fix-cmd').value.trim();
  const safetyEl = document.getElementById('mitigate-fix-safety');
  const confirmRow = document.getElementById('mitigate-fix-confirm-row');
  if (!cmd) {
    safetyEl.innerHTML = '';
    confirmRow.style.display = 'none';
    return;
  }
  // Mirror server's regex set (loose, only for UI hint)
  const SENSITIVE_RX = [
    /\breboot\b/i, /\bshutdown\b/i, /\bhalt\b/i, /\bpoweroff\b/i,
    /\bkill\s+-9\b/i, /\bpkill\s+-9\b/i,
    /\bsystemctl\s+(?:stop|disable|mask)\b/i,
    /\biptables\s+-[FX]\b/i, /\bnft\s+flush\b/i,
    /\buserdel\b/i, /\bgroupdel\b/i,
    /\bapt-get\s+(?:purge|remove)\s+/i,
    /\bdnf\s+(?:remove|erase)\s+/i,
    /\bpacman\s+-R[^\s]*\s+/i,
    /\bcurl\s+[^\|]+\|\s*(?:bash|sh)\b/i,
    /\bwget\s+[^\|]+\|\s*(?:bash|sh)\b/i,
  ];
  const DENY_RX = [
    /\brm\s+-[rRf]+\s+\/(?:\s|$|\*)/,
    /\bdd\s+.*of=\/dev\/(?:sd|nvme|xvd|vd|hd)/i,
    /\bmkfs\b/i, /:\(\)\s*\{.*:\s*\|\s*:&/, /\bdrop\s+database\b/i,
    /\bchmod\s+(?:-R\s+)?(?:000|777)\s+\/(?:\s|$)/i,
  ];
  const denied  = DENY_RX.some(rx => rx.test(cmd));
  const sensitive = !denied && SENSITIVE_RX.some(rx => rx.test(cmd));
  if (denied) {
    safetyEl.innerHTML = `<div class="isl-703">
      <strong>This command appears to match the denylist.</strong> The server will refuse to run it. Edit the command, or run it manually on the host.
    </div>`;
    confirmRow.style.display = 'none';
    document.getElementById('mitigate-fix-go').disabled = true;
  } else if (sensitive) {
    safetyEl.innerHTML = `<div class="isl-704">
      <strong>Sensitive command.</strong> Type RUN in the confirmation field below.
    </div>`;
    confirmRow.style.display = 'block';
    document.getElementById('mitigate-fix-go').disabled = false;
  } else {
    safetyEl.innerHTML = `<div class="isl-705">
      Looks like a routine command. Will run as-is on the agent.
    </div>`;
    confirmRow.style.display = 'none';
    document.getElementById('mitigate-fix-go').disabled = false;
  }
}

// Wire the textarea change so safety updates live
document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('mitigate-fix-cmd');
  if (el) el.addEventListener('input', _mitigateUpdateSafety);
});

// CSP L1 fix: wire up all static HTML event handlers removed from index.html
document.addEventListener('DOMContentLoaded', () => {
  // Login submit (form-wrapped in v3.0.4 so the browser's password manager
  // can offer autofill — "[DOM] Password field is not contained in a form").
  // preventDefault on submit so the form doesn't try to navigate.
  document.getElementById('login-form')?.addEventListener('submit', e => {
    e.preventDefault();
    doLogin();
  });
  // The Change Password and Add User modals are also <form> elements so
  // browser password managers can offer to save/autofill credentials.
  // Their type="submit" button's data-action click handler runs the
  // actual API call; we just need to stop the form from doing its
  // default navigation.
  ['passwd-form', 'user-add-form'].forEach(id => {
    document.getElementById(id)?.addEventListener('submit', e => e.preventDefault());
  });

  // v3.0.6: admin-config password fields (SMTP / LDAP / Proxmox /
  // CMDB vault / etc.) are wrapped in tiny <form autocomplete="off"
  // data-csp-pw-form> elements so the browser silences the "[DOM]
  // Password field is not contained in a form" cosmetic warning AND
  // doesn't offer password-manager autofill for service-account
  // credentials. Pressing Enter inside one would otherwise navigate
  // (default form submit) — preventDefault here keeps the page put.
  document.addEventListener('submit', e => {
    if (e.target && e.target.matches('form[data-csp-pw-form]')) {
      e.preventDefault();
    }
  });

  // Header buttons
  document.querySelector('.theme-btn')?.addEventListener('click', toggleTheme);
  document.querySelector('.logout-btn')?.addEventListener('click', doLogout);
  document.getElementById('pwa-install-btn')?.addEventListener('click', () => window.pwaInstall?.());

  // Logo — navigate to Home
  document.querySelector('.logo-link')?.addEventListener('click', e => {
    e.preventDefault();
    showPage('home', document.querySelector('.nav-btn[data-page="home"]'));
  });

  // Settings → AI assistant deep-link
  document.getElementById('link-to-ai-settings')?.addEventListener('click', e => {
    e.preventDefault();
    showPage('settings', document.querySelector('.nav-btn[data-page="settings"]'));
    setTimeout(() => switchSettingsTab('ai'), 50);
  });

  // Mobile sidebar open/close
  document.querySelector('.mobile-burger')?.addEventListener('click', toggleMobileNav);
  document.querySelector('.sidebar-mobile-close')?.addEventListener('click', toggleMobileNav);

  // Sidebar collapse
  document.querySelector('.sidebar-collapse-btn')?.addEventListener('click', toggleSidebarCollapse);

  // Delegated listener on the sidebar nav for nav-btn and group-toggle clicks
  const sidebarNav = document.querySelector('nav.sidebar');
  if (sidebarNav) {
    sidebarNav.addEventListener('click', e => {
      const navBtn = e.target.closest('.nav-btn[data-page]');
      if (navBtn) { showPage(navBtn.dataset.page, navBtn); return; }

      const extBtn = e.target.closest('.nav-btn[data-open-href]');
      if (extBtn) { window.open(extBtn.dataset.openHref, '_blank'); return; }

      const groupToggle = e.target.closest('.sidebar-group-toggle');
      if (groupToggle) {
        const group = groupToggle.closest('.sidebar-group').dataset.group;
        toggleSidebarGroup(group);
      }
    });
  }

  // Specific buttons that pass `this` (the element) to their handler
  document.getElementById('btn-save-settings')?.addEventListener('click', function () { saveSettings(this); });
  document.getElementById('btn-trigger-cve-scan')?.addEventListener('click', function () { triggerCVEScan(undefined, this); });
  document.getElementById('iac-generate-btn')?.addEventListener('click', function () { iacGenerate(this, true); });
  document.getElementById('iac-rawjson-btn')?.addEventListener('click', function () { iacGenerate(this, false); });
  document.getElementById('iac-rerun-btn')?.addEventListener('click', function () { _iacRerunAi(this); });
  document.getElementById('iac-copy-btn')?.addEventListener('click', function () { _iacCopy(this); });

  // Device icon modal buttons
  document.getElementById('btn-device-icon-clear')?.addEventListener('click', () => saveDeviceIcon(''));
  document.getElementById('btn-device-icon-save')?.addEventListener('click', () => {
    saveDeviceIcon(document.getElementById('icon-custom').value);
  });

  // Kanban drag-drop — delegated on the board container.
  // v3.0.5: dragstart/dragend also wired here so the kanban-card markup
  // doesn't need inline `ondragstart=` / `ondragend=` (CSP-blocked).
  const kanbanBoard = document.querySelector('.kanban-board');
  if (kanbanBoard) {
    kanbanBoard.addEventListener('dragstart', e => {
      const card = e.target.closest('.kanban-card[data-task-id]');
      if (card) onTaskDragStart(e, card.dataset.taskId);
    });
    kanbanBoard.addEventListener('dragend', e => {
      const card = e.target.closest('.kanban-card');
      if (card) onTaskDragEnd(e);
    });
    kanbanBoard.addEventListener('dragover', e => {
      const col = e.target.closest('.kanban-column');
      if (col) onKanbanDragOver(e);
    });
    kanbanBoard.addEventListener('dragleave', e => {
      const col = e.target.closest('.kanban-column');
      if (col) onKanbanDragLeave(e);
    });
    kanbanBoard.addEventListener('drop', e => {
      const col = e.target.closest('[data-kanban-col]');
      if (col) onKanbanDrop(e, col.dataset.kanbanCol);
    });
  }

  // Keydown handlers (elements have IDs)
  document.getElementById('ai-page-input')?.addEventListener('keydown', aiPageInputKey);
  document.getElementById('logs-search-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') runLogSearch();
  });
});

// ── CSP L1: event data store for onclick args too large for data attributes ──
const _evtData = new Map();
let _evtDataSeq = 0;
function _storeEvtData(data) {
  const key = `d${++_evtDataSeq}`;
  _evtData.set(key, data);
  return key;
}

// ── CSP L1: drawer-action map (avoids onclick= in renderDrawerActions) ────────
const _drawerActMap = new Map();

// ── CSP L1: wrapper functions for this-passing and complex onclick= patterns ─
function _cveScanBtn(btn) {
  triggerCVEScan(btn.dataset.devId || undefined, btn);
}
function _forcePackageScanBtn(btn) {
  forcePackageScan(btn.dataset.devId, btn.dataset.devName || '', btn);
}
function _aiPrioritiseCvesBtn(btn) {
  aiPrioritiseCvesForDevice(btn.dataset.devId, btn.dataset.devName || '', btn);
}
function _aiPrioritisePatchesBtn(btn) {
  aiPrioritisePatchesForDevice(btn.dataset.devId, btn.dataset.devName || '', btn);
}
function _saveAiPromptBtn(btn) { saveAiPrompt(btn.dataset.key, btn); }
function _saveAiParamsBtn(btn) { saveAiParams(btn.dataset.key, btn); }
function _resetAiPromptBtn(btn) { resetAiPrompt(btn.dataset.key, btn); }
function _resetAiParamsBtn(btn) { resetAiParams(btn.dataset.key, btn); }
function _aiFindProblemBtn(btn) {
  const sel = btn.dataset.journalSel;
  const lines = sel ? (document.querySelector(sel)?.textContent?.split('\n') || []) : [];
  aiFindProblemInJournal(btn.dataset.devId, lines);
}
function _copySecretBtn(btn) {
  navigator.clipboard?.writeText(btn.dataset.secret);
  toast('Secret copied', 'success');
}
function _densityCtlBtn(btn) {
  densityCtl.set(btn.dataset.dname, btn.dataset.val, window[`__densityCb_${btn.dataset.dname}`]);
}
function _csOutputFromStore(btn) {
  const args = _evtData.get(btn.dataset.storeKey);
  if (args) openCsOutput(...args);
}
function _expandPortsFromStore(btn) {
  const data = _evtData.get(btn.dataset.storeKey);
  if (data) expandPortsTable(data);
}
function _restoreIgnoredFromStore(btn) {
  const args = _evtData.get(btn.dataset.storeKey);
  if (args) restoreIgnored(...args);
}
function closeBulkModal()  { document.getElementById('bulk-modal-overlay')?.remove(); }
function closeKbdCheat()   { document.getElementById('kbd-cheat-overlay')?.remove(); }
// v3.0.5: _filterAuditPorts / _loadAuditLogs removed alongside the
// duplicate device-drawer block in index.html (the old hardcoded audit
// markup that they targeted is gone). The new dynamic audit renderer
// has its own per-section filter logic.
function _setTagFilterClear()    { setTagFilter(null); }
function _aiExplainAlertWh(btn)  { aiExplainAlert(btn.dataset.arg, btn.dataset.arg2 || '', btn.dataset.arg3 || '', null); }
function _aiDiagnoseServiceFromStore(btn) {
  const args = _evtData.get(btn.dataset.storeKey);
  if (args) aiDiagnoseService(...args);
}
function _driftSetIgnoreTrue(btn)  { driftSetIgnore(btn.dataset.arg, true); }
function _driftSetIgnoreFalse(btn) { driftSetIgnore(btn.dataset.arg, false); }
function _showPageBtn(btn) {
  const page = btn.dataset.page;
  showPage(page, document.querySelector(`.nav-btn[data-page="${page}"]`));
}
function _homeNavAction(btn) {
  const act = btn.dataset.homeAct;
  const devId   = btn.dataset.devId   || '';
  const devName = btn.dataset.devName || '';
  switch (act) {
    case 'detail':
      if (devId) openDetail(devId, devName);
      else showPage('devices', document.querySelector('.nav-btn[data-page="devices"]'));
      break;
    case 'drift':
      showPage('drift', document.querySelector('.nav-btn[data-page="drift"]'));
      if (devId) setTimeout(() => openDriftDetail(devId, devName), 100);
      break;
    case 'cve':      showPage('cve',            document.querySelector('.nav-btn[data-page="cve"]')); break;
    case 'patches':  showPage('patches',         document.querySelector('.nav-btn[data-page="patches"]')); break;
    case 'monitor':  showPage('monitor',         document.querySelector('.nav-btn[data-section-page="monitor"]')); break;
    case 'services': showPage('services',        document.querySelector('.nav-btn[data-page="services"]')); break;
    case 'containers': showPage('containers',    document.querySelector('.nav-btn[data-section-page="containers"]')); break;
    case 'logs':     showPage('logs',            document.querySelector('.nav-btn[data-page="logs"]')); break;
    case 'history':  showPage('history',         document.querySelector('.nav-btn[data-page="history"]')); break;
    case 'tls':      showPage('tls',             document.querySelector('.nav-btn[data-section-page="tls"]')); break;
    case 'virtualization': showPage('virtualization', document.querySelector('.nav-btn[data-page="virtualization"]')); break;
    case 'self':     showPage('self',            document.querySelector('.nav-btn[data-page="self"]')); break;
    default:
      if (devId) openDetail(devId, devName);
      else showPage('devices', document.querySelector('.nav-btn[data-page="devices"]'));
  }
}

// Delegated click handler for page-level buttons using data-action / data-arg
document.addEventListener('click', e => {
  // data-remove-parent
  const rpEl = e.target.closest('[data-remove-parent]');
  if (rpEl) { rpEl.parentElement?.remove(); return; }

  // data-remove-closest
  const rcEl = e.target.closest('[data-remove-closest]');
  if (rcEl) { rcEl.closest(rcEl.dataset.removeClosest)?.remove(); return; }

  // data-self-select (e.g. <input data-self-select>)
  const ssEl = e.target.closest('[data-self-select]');
  if (ssEl && typeof ssEl.select === 'function') { ssEl.select(); return; }

  // data-set-icon-val: sets #icon-custom value
  const sivEl = e.target.closest('[data-set-icon-val]');
  if (sivEl) { const ic = document.getElementById('icon-custom'); if (ic) ic.value = sivEl.dataset.setIconVal; return; }

  // data-drawer-act: drawer action map
  const daEl = e.target.closest('[data-drawer-act]');
  if (daEl) { const fn = _drawerActMap.get(daEl.dataset.drawerAct); if (fn) fn(); return; }

  // data-action-btn: functions that need the element passed as first arg
  const btnEl = e.target.closest('[data-action-btn]');
  if (btnEl) {
    if (btnEl.dataset.stopProp) e.stopPropagation();
    if (btnEl.dataset.preventDefault) e.preventDefault();
    const fn = window[btnEl.dataset.actionBtn];
    if (!fn) return;
    const boolArg = btnEl.dataset.argBool;
    if (boolArg !== undefined) fn(btnEl, boolArg === 'true');
    else fn(btnEl);
    return;
  }

  // data-action: standard function call with 0–5 args
  const el = e.target.closest('[data-action]');
  if (!el) return;

  if (el.dataset.stopProp) e.stopPropagation();
  if (el.dataset.preventDefault) e.preventDefault();

  const fn = window[el.dataset.action];
  if (!fn) return;

  // Collect positional args from data-arg, data-arg2 … data-arg5
  const coerce = v => (v !== undefined && v !== '' && !isNaN(v)) ? Number(v) : v;
  const args = [];
  if (el.dataset.arg  !== undefined) args.push(coerce(el.dataset.arg));
  if (el.dataset.arg2 !== undefined) args.push(coerce(el.dataset.arg2));
  if (el.dataset.arg3 !== undefined) args.push(coerce(el.dataset.arg3));
  if (el.dataset.arg4 !== undefined) args.push(coerce(el.dataset.arg4));
  if (el.dataset.arg5 !== undefined) args.push(coerce(el.dataset.arg5));

  if (el.dataset.argBool !== undefined) args[0] = el.dataset.argBool === 'true';
  if (el.dataset.passBtn) args.push(el);

  fn(...args);

  if (el.dataset.action2) {
    const fn2 = window[el.dataset.action2];
    if (fn2) fn2();
  }
});

// Delegated change handler for data-change attributes
document.addEventListener('change', e => {
  const el = e.target;
  if (el.dataset.change) {
    const fn = window[el.dataset.change];
    if (!fn) return;
    if (el.dataset.changeArg !== undefined) {
      const a = el.dataset.changeArg;
      const coerced = (a !== '' && !isNaN(a)) ? Number(a) : a;
      fn(coerced, el.checked);
    } else if (el.dataset.changeChecked) {
      fn(el.checked);
    } else {
      fn();
    }
  }
});

// Delegated input handler for data-input attributes
document.addEventListener('input', e => {
  const el = e.target;
  if (el.dataset.input) {
    const fn = window[el.dataset.input];
    if (!fn) return;
    if (el.dataset.inputEl !== undefined) fn(el, el.dataset.inputArg);
    else if (el.dataset.inputArg !== undefined) fn(el.dataset.inputArg);
    else if (el.dataset.inputValue) fn(el.value);
    else fn();
  }
});

async function mitigateRunFix() {
  const cmd = document.getElementById('mitigate-fix-cmd').value.trim();
  if (!cmd) { toast('Enter a command first', 'error'); return; }
  const confirmation = document.getElementById('mitigate-fix-confirm').value.trim();
  const btn = document.getElementById('mitigate-fix-go');
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Queueing…';
  const r = await api('POST', `/mitigate/${encodeURIComponent(_mitigateCtx.devId)}/fix`, {
    kind:         _mitigateCtx.kind,
    target:       _mitigateCtx.target,
    command:      cmd,
    confirmation: confirmation,
  });
  btn.disabled = false; btn.textContent = orig;
  if (!r) {
    document.getElementById('mitigate-fix-result').innerHTML =
      '<div class="isl-706">Request failed</div>';
    return;
  }
  if (r.error) {
    document.getElementById('mitigate-fix-result').innerHTML =
      `<div class="isl-703">
        ${escHtml(r.error)}
        ${r.hint ? `<div class="isl-707">${escHtml(r.hint)}</div>` : ''}
      </div>`;
    return;
  }
  if (r.ok && r.action_id) {
    _mitigateCtx.actionId = r.action_id;
    document.getElementById('mitigate-fix-result').innerHTML =
      `<div class="isl-708">
        ✓ Queued (action ${escHtml(r.action_id)}). Polling for output…
        <pre id="mitigate-fix-output" class="isl-709"></pre>
      </div>`;
    _mitigatePollAttempts = 0;
    _mitigatePollFix();
  }
}

async function _mitigatePollFix() {
  if (!_mitigateCtx || !_mitigateCtx.actionId) return;
  _mitigatePollAttempts++;
  const r = await api('GET',
    `/mitigate/${encodeURIComponent(_mitigateCtx.devId)}/status/${encodeURIComponent(_mitigateCtx.actionId)}`);
  const out = document.getElementById('mitigate-fix-output');
  if (!r) return;
  if (out && r.content) out.textContent = r.content;
  if (r.done) {
    if (out) {
      out.textContent = r.content || '(no output)';
      out.insertAdjacentHTML('afterend',
        `<div class="isl-710">Done. rc=${r.rc} · ${(r.size/1024).toFixed(1)} KB</div>`);
    }
    return;
  }
  if (_mitigatePollAttempts >= _MITIGATE_POLL_MAX) {
    if (out) out.insertAdjacentHTML('afterend',
      '<div class="isl-711">Timed out waiting for output. Agent may be offline.</div>');
    return;
  }
  setTimeout(_mitigatePollFix, 2000);
}

// v3.0.1: Cancel a pending ACME action (still in queue or already dispatched)
async function acmeCancelAction(actionId) {
  if (!_acmeDetailContext) return;
  if (!confirm(`Cancel pending action ${actionId}?\n\nIf the agent hasn't picked it up yet, it'll be removed from the queue. If it's already running, the cancel only stops RemotePower from waiting — the agent may still finish what it started.`)) return;
  const r = await api('POST',
    `/acme/${encodeURIComponent(_acmeDetailContext.devId)}/cancel/${encodeURIComponent(actionId)}`);
  if (!r) { toast('Cancel request failed', 'error'); return; }
  if (r.error) { toast(r.error, 'error'); return; }
  toast(r.removed_from_queue
    ? 'Cancelled — was still in queue, never dispatched'
    : 'Cancelled — already dispatched, UI will stop polling but agent may finish', 'success');
  // Re-open detail to refresh log list
  acmeOpenDetail(_acmeDetailContext.devId, _acmeDetailContext.domain);
}

// v3.0.1: Ignore (= delete) an ACME action row. Use for stuck-pending entries
// that won't cancel cleanly. Doesn't touch cert state — only removes the log
// + meta files from disk so the row disappears.
async function acmeIgnoreAction(actionId) {
  if (!_acmeDetailContext) return;
  if (!confirm(`Remove this action row from the log list?\n\nThis deletes the captured output (if any) and the meta file. The actual cert state on the device is unaffected — this is purely a UI cleanup. Use Cancel instead if you want to stop a pending action from running.`)) return;
  const r = await api('POST',
    `/acme/${encodeURIComponent(_acmeDetailContext.devId)}/ignore/${encodeURIComponent(actionId)}`);
  if (!r) { toast('Ignore request failed', 'error'); return; }
  if (r.error) { toast(r.error, 'error'); return; }
  toast('Action row removed', 'success');
  acmeOpenDetail(_acmeDetailContext.devId, _acmeDetailContext.domain);
}

// ─── v3.0.2: Self-monitoring page ──────────────────────────────────────────
// Renders /api/self/status into expandable info cards.
function _selfFmtBytes(b) {
  if (b == null) return '—';
  const u = ['B','KB','MB','GB','TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return b.toFixed(b < 10 ? 1 : 0) + ' ' + u[i];
}
function _selfFmtAgo(ts) {
  if (!ts) return 'never';
  const s = Math.max(0, Math.floor(Date.now()/1000) - ts);
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}
async function loadSelfStatus() {
  const body = document.getElementById('self-status-body');
  body.innerHTML = '<div class="c-muted">Loading…</div>';
  const s = await api('GET', '/self/status');
  if (!s || s.error) {
    body.innerHTML = '<div class="c-red">Failed to load: ' + escHtml(s?.error || 'unknown') + '</div>';
    return;
  }
  // Devices freshness card
  const dev = s.devices || {};
  const offlineSev = dev.offline > 0 ? 'var(--red)' : 'var(--green)';
  // Webhook delivery card
  const w24 = (s.webhooks || {}).last_24h;
  const w7d = (s.webhooks || {}).last_7d;
  const _whHtml = w => {
    if (!w) return '<span class="c-muted">no log entries</span>';
    if (w.attempts === 0) {
      // v3.2.0 fix: distinguish "no deliveries attempted" (every event was
      // suppressed/filtered/disabled — fine!) from "deliveries failed".
      return `<span class="c-muted">no deliveries</span>` +
        (w.skipped ? ` <span class="hint">(${w.skipped} skipped — disabled/maintenance/filtered)</span>` : '');
    }
    const pct = (w.rate * 100).toFixed(1);
    const pctCls = w.rate >= 0.95 ? 'c-green' : w.rate >= 0.8 ? 'c-amber' : 'c-red';
    return `<strong>${w.success}</strong> / ${w.attempts} <span class="${pctCls}">(${pct}%)</span>` +
      (w.skipped ? ` <span class="hint">+${w.skipped} skipped</span>` : '');
  };
  // Disk usage
  const dd = s.data_dir || {};
  const diskPct = (dd.fs_free_bytes && dd.fs_total_bytes)
    ? Math.round((1 - dd.fs_free_bytes / dd.fs_total_bytes) * 100) : null;
  const bigFiles = (dd.big_files || []).map(f =>
    `<div class="isl-712">
       <code>${escHtml(f.name)}</code><span class="c-muted">${_selfFmtBytes(f.bytes)}</span>
     </div>`).join('');
  // Backup state
  const bk = s.backup || {};
  // v3.2.0: performance snapshot
  const perf = s.performance || {};
  const la = perf.load_avg || {};
  const mem = perf.memory || {};
  const sess = perf.sessions || {};
  const healthOk = perf.health === 'ok';
  const healthPill = healthOk
    ? '<span class="sev-pill sev-success">healthy</span>'
    : `<span class="sev-pill sev-medium">${(perf.health_flags || []).length} warning(s)</span>`;
  const memBar = mem.used_pct != null
    ? `<div class="perf-bar" title="${mem.used_pct}% used"><div class="perf-bar-fill" data-pct="${mem.used_pct}"></div></div>`
    : '';
  const onlinePct = perf.devices_online_pct;
  const onlinePctText = onlinePct != null ? `${onlinePct}%` : '—';
  const flagsHtml = (perf.health_flags || []).length
    ? `<details class="mt-8"><summary class="c-muted">View ${perf.health_flags.length} reason(s)</summary><ul class="mt-4">${perf.health_flags.map(f => `<li>${escHtml(f)}</li>`).join('')}</ul></details>`
    : '';
  body.innerHTML = `
    <div class="card p-16">
      <div class="fw-600-mb10">Site health ${healthPill}</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Server version</td><td>${escHtml(s.server_version || '?')}</td></tr>
        ${la['1m'] != null ? `<tr><td class="c-muted-padded">Load average</td><td>${la['1m'].toFixed(2)} · ${la['5m'].toFixed(2)} · ${la['15m'].toFixed(2)} <span class="c-muted">(1m · 5m · 15m)</span></td></tr>` : ''}
        ${mem.used_pct != null ? `<tr><td class="c-muted-padded">System memory</td><td>${mem.used_pct}% used · ${_selfFmtBytes((mem.total_kb - mem.available_kb)*1024)} of ${_selfFmtBytes(mem.total_kb*1024)} ${memBar}</td></tr>` : ''}
        ${s.process?.vmrss_kb ? `<tr><td class="c-muted-padded">CGI process RSS</td><td>${_selfFmtBytes(s.process.vmrss_kb*1024)}</td></tr>` : ''}
        ${sess.active != null ? `<tr><td class="c-muted-padded">Active sessions</td><td>${sess.active}</td></tr>` : ''}
        <tr><td class="c-muted-padded">Devices online</td><td>${onlinePctText}</td></tr>
        ${s.process?.pid ? `<tr><td class="c-muted-padded">PID</td><td>${s.process.pid}</td></tr>` : ''}
      </table>
      ${flagsHtml}
    </div>

    <div class="card p-16">
      <div class="fw-600-mb10">Devices</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Monitored</td><td>${dev.monitored ?? '—'}</td></tr>
        <tr><td class="c-muted-padded">Currently offline</td><td><span class="isl-713" data-color="${offlineSev}">${dev.offline ?? '—'}</span></td></tr>
        <tr><td class="c-muted-padded">Freshest heartbeat</td><td>${_selfFmtAgo(dev.freshest_seen)}</td></tr>
        <tr><td class="c-muted-padded">Oldest heartbeat</td><td>${_selfFmtAgo(dev.oldest_seen)}</td></tr>
        <tr><td class="c-muted-padded">Online TTL</td><td>${dev.online_ttl_s ?? '—'}s</td></tr>
      </table>
    </div>

    <div class="card p-16">
      <div class="fw-600-mb10">Webhook delivery — outbound</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Last 24h</td><td>${_whHtml(w24)}</td></tr>
        <tr><td class="c-muted-padded">Last 7 days</td><td>${_whHtml(w7d)}</td></tr>
        <tr><td class="c-muted-padded">Logged total</td><td>${(s.webhooks || {}).total_logged ?? '—'}</td></tr>
      </table>
    </div>

    ${(() => {
      // v3.2.0 follow-up: inbound webhooks + syslog hit log
      const iw = s.inbound_webhooks || {};
      const i24 = iw.last_24h, i7d = iw.last_7d;
      const _iwHtml = w => {
        if (!w) return '<span class="c-muted">no inbound hits yet</span>';
        const pct = (w.rate * 100).toFixed(1);
        const pctCls = w.rate >= 0.95 ? 'c-green' : w.rate >= 0.8 ? 'c-amber' : 'c-red';
        const kinds = w.by_kind || {};
        const kindsTxt = Object.keys(kinds).map(k => `${escHtml(k)}:${kinds[k]}`).join(' · ');
        return `<strong>${w.success}</strong> / ${w.attempts} <span class="${pctCls}">(${pct}%)</span>` +
               (kindsTxt ? ` <span class="hint">[${kindsTxt}]</span>` : '');
      };
      return `<div class="card p-16">
        <div class="fw-600-mb10">Inbound webhooks &amp; syslog</div>
        <table class="fs-13">
          <tr><td class="c-muted-padded">Last 24h</td><td>${_iwHtml(i24)}</td></tr>
          <tr><td class="c-muted-padded">Last 7 days</td><td>${_iwHtml(i7d)}</td></tr>
          <tr><td class="c-muted-padded">Logged total</td><td>${iw.total_logged ?? '—'}</td></tr>
        </table>
      </div>`;
    })()}

    <div class="card p-16">
      <div class="fw-600-mb10">Disk — <code>${escHtml(dd.path || '/var/lib/remotepower')}</code></div>
      <table class="isl-714">
        <tr><td class="c-muted-padded">RemotePower data</td><td>${_selfFmtBytes(dd.total_bytes)}</td></tr>
        ${diskPct != null ? `<tr><td class="c-muted-padded">Filesystem used</td><td>${diskPct}% (${_selfFmtBytes(dd.fs_total_bytes - dd.fs_free_bytes)} of ${_selfFmtBytes(dd.fs_total_bytes)})</td></tr>` : ''}
      </table>
      ${bigFiles ? `<details><summary class="isl-715">Largest files (>100KB)</summary><div class="mt-8">${bigFiles}</div></details>` : ''}
    </div>

    <div class="card p-16">
      <div class="fw-600-mb10">Audit log</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Active entries</td><td>${(s.audit_log || {}).entries ?? '—'}</td></tr>
        <tr><td class="c-muted-padded">Retention</td><td>${(s.audit_log || {}).retention_days ?? '—'} days</td></tr>
        ${(s.audit_log || {}).archive_bytes ? `<tr><td class="c-muted-padded">Archive (gzip)</td><td>${_selfFmtBytes(s.audit_log.archive_bytes)}</td></tr>` : ''}
      </table>
    </div>

    <div class="card p-16">
      <div class="fw-600-mb10">Backup</div>
      ${bk.last_run ? `
        <table class="fs-13">
          <tr><td class="c-muted-padded">Last run</td><td>${_selfFmtAgo(bk.last_run)} <span class="c-muted">(${escHtml(bk.triggered_by || 'scheduled')})</span></td></tr>
          <tr><td class="c-muted-padded">Last file</td><td><code class="fs-11">${escHtml(bk.last_file || '—')}</code></td></tr>
          <tr><td class="c-muted-padded">Size</td><td>${_selfFmtBytes(bk.last_bytes)}</td></tr>
          <tr><td class="c-muted-padded">Retention</td><td>${bk.retain_days ?? 14} days (last prune removed ${bk.pruned ?? 0})</td></tr>
        </table>` : '<div class="c-muted-fs13">No backup has run yet. The scheduled job runs once per 24h via the heartbeat hook; click "Run backup now" to trigger one immediately.</div>'}
    </div>

    <div class="card p-16">
      <div class="fw-600-mb10">Fleet events</div>
      <table class="fs-13">
        <tr><td class="c-muted-padded">Current log</td><td>${_selfFmtBytes((s.fleet_events || {}).bytes)}</td></tr>
        ${(s.fleet_events || {}).archive_bytes ? `<tr><td class="c-muted-padded">Archive (gzip)</td><td>${_selfFmtBytes(s.fleet_events.archive_bytes)}</td></tr>` : ''}
      </table>
    </div>
  `;
}
async function runBackupNow() {
  const btn = document.getElementById('self-backup-btn');
  if (!confirm('Run a backup snapshot of /var/lib/remotepower now? This may take a few seconds depending on data size.')) return;
  btn.disabled = true;
  btn.textContent = 'Running…';
  const r = await api('POST', '/self/backup-now');
  btn.disabled = false;
  btn.textContent = '↓ Run backup now';
  if (!r || r.error) { toast('Backup failed: ' + (r?.error || 'unknown'), 'error'); return; }
  if (r.skipped) { toast('Skipped: ' + (r.reason || ''), 'warning'); return; }
  toast(`Backup written: ${_selfFmtBytes(r.bytes)} (${r.pruned || 0} old files pruned)`, 'success');
  loadSelfStatus();
}

async function clearBackupState() {
  const btn = document.getElementById('self-backup-clear-btn');
  if (!confirm('Delete all backup archives (remotepower_data_*.tar.gz) and reset backup state?\n\nThis cannot be undone. The next scheduled or manual backup will create a fresh archive.')) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Clearing…'; }
  const r = await api('DELETE', '/self/backup-state');
  if (btn) { btn.disabled = false; btn.textContent = '✕ Clear backup archives'; }
  if (!r || r.error) { toast('Clear failed: ' + (r?.error || 'unknown'), 'error'); return; }
  toast(`Cleared ${r.deleted ?? 0} archive${r.deleted === 1 ? '' : 's'}`, 'success');
  loadSelfStatus();
}

// v3.0.2: Force ACME rescan — bypasses the hourly scan cadence.
async function acmeForceRescan(devId) {
  if (!confirm('Force the agent to rescan ~/.acme.sh on its next heartbeat?\n\nUseful after renewing/issuing via the CLI when you don\'t want to wait an hour for RemotePower to catch up.')) return;
  const r = await api('POST', `/devices/${encodeURIComponent(devId)}/acme/force-rescan`);
  if (!r) { toast('Force-rescan request failed', 'error'); return; }
  if (r.error) { toast(r.error, 'error'); return; }
  toast(r.message || 'ACME rescan queued', 'success');
}

// ─── v3.0.2: Global command palette / search ───────────────────────────────
// Press `/` or `Ctrl+K` to open. Searches devices, pages, audit-log actions,
// ACME domains, services. Enter to navigate, Esc to close.
let _palOpen = false;
let _palItems = [];      // [{label, kind, action: () => void}]
let _palCursor = 0;
function _palBuildIndex() {
  const items = [];
  // Static pages (sidebar destinations)
  const pages = [
    ['Home', 'home'], ['Devices', 'devices'], ['Containers', 'containers'],
    ['Virtualization', 'virtualization'], ['Monitoring', 'monitor'],
    ['History', 'history'], ['Schedule', 'schedule'], ['Calendar', 'calendar'],
    ['Tasks', 'tasks'], ['CMDB', 'cmdb'], ['Logs', 'logs'], ['CVEs', 'cve'],
    ['Patches', 'patches'], ['Drift', 'drift'], ['TLS', 'tls'],
    ['IaC', 'iac'], ['Network Map', 'netmap'], ['Audit', 'audit'],
    ['Server status', 'self'], ['Documentation', 'docs'],
    ['AI Assistant', 'ai'], ['Settings', 'settings'], ['Users', 'users'],
    ['API Keys', 'apikeys'], ['Scripts', 'scripts'], ['Command Library', 'cmdlib'],
    ['Maintenance', 'maintenance'], ['Services', 'services'], ['About', 'about'],
  ];
  for (const [label, page] of pages) {
    items.push({label, kind: 'page', sub: 'Go to page',
                action: () => showPage(page)});
  }
  // v3.0.2: actions, not just pages
  items.push({label: 'Bulk actions…', kind: 'action',
              sub: 'Fleet-wide upgrade / reboot / scan',
              action: openBulkActions});
  items.push({label: 'Keyboard shortcuts', kind: 'action',
              sub: 'Show cheat sheet (?)',
              action: showKeyboardShortcuts});
  items.push({label: 'Run backup now', kind: 'action',
              sub: 'Snapshot /var/lib/remotepower',
              action: () => { showPage('self'); setTimeout(runBackupNow, 400); }});
  // Devices — pulled live from the cached devices list if loaded
  const cached = window._devicesCache || [];
  for (const d of cached) {
    items.push({
      label: d.name || d.id,
      kind: 'device',
      sub: `${d.os || 'device'} · ${d.ip || ''}`,
      action: () => { showPage('devices'); setTimeout(() => openDeviceDrawer(d.id), 100); },
    });
  }
  return items;
}
function openCommandPalette() {
  if (_palOpen) return;
  _palOpen = true;
  // v3.0.2: prime the device cache if it's empty so the palette actually
  // surfaces devices when you open it cold (right after page load, before
  // visiting the Devices page).
  if (!window._devicesCache || !window._devicesCache.length) {
    // Best-effort: fire-and-forget. Palette will refresh once data lands.
    api('GET', '/devices').then(data => {
      if (data && Array.isArray(data)) {
        window._devicesCache = data;
        if (_palOpen) { _palItems = _palBuildIndex(); _palRender(); }
      }
    }).catch(() => {});
  }
  _palItems = _palBuildIndex();
  _palCursor = 0;
  const overlay = document.createElement('div');
  overlay.id = 'cmd-palette-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:99999;display:flex;justify-content:center;padding-top:80px';
  overlay.innerHTML = `
    <div class="isl-716">
      <input id="cmd-palette-input" type="text" placeholder="Search devices, pages, settings…" autocomplete="off" class="isl-717">
      <div id="cmd-palette-results" class="isl-718"></div>
      <div class="isl-719">
        <span><kbd class="isl-720">↑↓</kbd> navigate</span>
        <span><kbd class="isl-720">⏎</kbd> open</span>
        <span><kbd class="isl-720">esc</kbd> close</span>
      </div>
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) closeCommandPalette(); });
  document.body.appendChild(overlay);
  const input = document.getElementById('cmd-palette-input');
  input.addEventListener('input', _palRender);
  input.addEventListener('keydown', _palKeydown);
  input.focus();
  _palRender();
}
function closeCommandPalette() {
  _palOpen = false;
  document.getElementById('cmd-palette-overlay')?.remove();
}
function _palRender() {
  const q = (document.getElementById('cmd-palette-input')?.value || '').toLowerCase().trim();
  const filtered = q
    ? _palItems.filter(i => i.label.toLowerCase().includes(q) || i.sub?.toLowerCase().includes(q))
    : _palItems.slice(0, 20);
  if (_palCursor >= filtered.length) _palCursor = 0;
  const html = filtered.map((it, idx) => `
    <div class="cmd-palette-row ${idx === _palCursor ? 'cmd-palette-active' : ''} isl-721"
         data-idx="${idx}">
      <div>
        <div class="fs-13">${escHtml(it.label)}</div>
        ${it.sub ? `<div class="meta-sm-nm">${escHtml(it.sub)}</div>` : ''}
      </div>
      <span class="isl-722">${it.kind}</span>
    </div>`).join('') || '<div class="isl-723">No results</div>';
  document.getElementById('cmd-palette-results').innerHTML = html;
  document.querySelectorAll('.cmd-palette-row').forEach(el => {
    el.addEventListener('click', () => {
      const idx = parseInt(el.dataset.idx, 10);
      _palItems = filtered;  // remember filtered for activation
      _palActivate(idx);
    });
  });
  // Stash filtered so keyboard activation hits the right slice
  window._palFiltered = filtered;
}
function _palKeydown(e) {
  const f = window._palFiltered || [];
  if (e.key === 'Escape') { e.preventDefault(); closeCommandPalette(); return; }
  if (e.key === 'ArrowDown') { e.preventDefault(); _palCursor = Math.min(f.length - 1, _palCursor + 1); _palRender(); return; }
  if (e.key === 'ArrowUp')   { e.preventDefault(); _palCursor = Math.max(0, _palCursor - 1); _palRender(); return; }
  if (e.key === 'Enter')     { e.preventDefault(); _palActivate(_palCursor); return; }
}
function _palActivate(idx) {
  const f = window._palFiltered || [];
  const it = f[idx];
  if (!it) return;
  closeCommandPalette();
  try { it.action(); } catch(e) { console.error('palette action failed', e); }
}

// Global keybind: `/` or Ctrl-K opens the palette. Ignore when typing in an input.
document.addEventListener('keydown', e => {
  if (_palOpen) return;
  const tgt = e.target;
  const inField = tgt && (tgt.tagName === 'INPUT' || tgt.tagName === 'TEXTAREA' || tgt.isContentEditable);
  if (inField) return;
  if ((e.key === '/' && !e.ctrlKey && !e.metaKey) ||
      ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) {
    e.preventDefault();
    openCommandPalette();
  } else if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    showKeyboardShortcuts();
  }
});

// ─── v3.0.2: Keyboard shortcuts cheat sheet ────────────────────────────────
function showKeyboardShortcuts() {
  if (document.getElementById('kbd-cheat-overlay')) return;
  const o = document.createElement('div');
  o.id = 'kbd-cheat-overlay';
  o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:99998;display:flex;justify-content:center;align-items:center';
  o.innerHTML = `
    <div class="isl-724">
      <div class="isl-725">
        <h3 class="isl-726">Keyboard shortcuts</h3>
        <button class="btn-icon isl-727" data-action="closeKbdCheat">×</button>
      </div>
      <table class="isl-728">
        <tr><td class="cell-padl"><kbd class="code-pill">/</kbd></td><td>Open command palette</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">Ctrl-K</kbd></td><td>Open command palette</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">?</kbd></td><td>Show this cheat sheet</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">g h</kbd></td><td>Go to Home</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">g d</kbd></td><td>Go to Devices</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">g l</kbd></td><td>Go to Logs</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">g s</kbd></td><td>Go to Settings</td></tr>
        <tr><td class="cell-padl"><kbd class="code-pill">Esc</kbd></td><td>Close any modal</td></tr>
      </table>
    </div>`;
  o.addEventListener('click', e => { if (e.target === o) o.remove(); });
  document.body.appendChild(o);
}

// 'g' prefix shortcut handler — single-letter follow-up jumps to pages.
let _gPrefix = false;
let _gPrefixTimer = null;
document.addEventListener('keydown', e => {
  const tgt = e.target;
  const inField = tgt && (tgt.tagName === 'INPUT' || tgt.tagName === 'TEXTAREA' || tgt.isContentEditable);
  if (inField || _palOpen) return;
  if (e.key === 'g' && !e.ctrlKey && !e.metaKey && !e.altKey) {
    if (_gPrefix) return;
    _gPrefix = true;
    if (_gPrefixTimer) clearTimeout(_gPrefixTimer);
    _gPrefixTimer = setTimeout(() => { _gPrefix = false; }, 1500);
    return;
  }
  if (_gPrefix) {
    _gPrefix = false;
    if (_gPrefixTimer) clearTimeout(_gPrefixTimer);
    const map = {h:'home', d:'devices', l:'logs', s:'settings', c:'cve', m:'monitor', a:'audit', v:'self'};
    const dest = map[e.key.toLowerCase()];
    if (dest) { e.preventDefault(); showPage(dest); }
  }
});

// ─── v3.0.2: Settings page search bar — filters visible setting cards ──────
// Each .settings-section is searchable by its textContent. Results outside
// the active tab still need their parent .settings-pane to flip visible —
// so we update per-tab match badges, and auto-switch to the first matching
// tab when the current tab has zero matches.
function filterSettings(q) {
  q = (q || '').toLowerCase().trim();

  // Per-tab match counts. Reset on every keystroke since dynamic sections
  // (webhook destinations, etc.) can change textContent after first index.
  const tabCounts = {};
  const tabHasAny = {};

  document.querySelectorAll('#page-settings .settings-pane').forEach(pane => {
    // The tab id is the last segment of the pane id: settings-pane-<tab>
    const tab = (pane.id || '').replace(/^settings-pane-/, '');
    tabCounts[tab] = 0; tabHasAny[tab] = false;
    pane.querySelectorAll('.settings-section').forEach(sec => {
      const text = sec.textContent.toLowerCase();
      const hit  = !q || text.includes(q);
      sec.style.display = hit ? '' : 'none';
      if (q && hit) { tabCounts[tab]++; tabHasAny[tab] = true; }
      if (!q) tabHasAny[tab] = true;
    });
  });

  // Update tab badges + visually grey out tabs that have zero matches
  document.querySelectorAll('.settings-tab').forEach(btn => {
    const tab = btn.dataset.tab;
    // Strip any previous match badge
    btn.querySelector('.settings-search-badge')?.remove();
    if (q && tabCounts[tab] > 0) {
      const badge = document.createElement('span');
      badge.className = 'settings-search-badge';
      badge.textContent = ' ' + tabCounts[tab];
      badge.style.cssText = 'background:var(--accent);color:#fff;font-size:10px;padding:0 6px;border-radius:8px;margin-left:4px';
      btn.appendChild(badge);
    }
    if (q && !tabHasAny[tab]) {
      btn.style.opacity = '0.4';
    } else {
      btn.style.opacity = '';
    }
  });

  // If the active tab has 0 matches but another tab does, switch to that tab.
  // Avoids the "I typed something, the page went blank" experience.
  if (q) {
    const active = document.querySelector('.settings-tab.active');
    const activeTab = active?.dataset.tab;
    if (activeTab && !tabHasAny[activeTab]) {
      const firstMatch = Object.entries(tabCounts).find(([_, c]) => c > 0);
      if (firstMatch && typeof switchSettingsTab === 'function') {
        switchSettingsTab(firstMatch[0]);
      }
    }
  }

  // Top-of-page hint when search is active and produces zero hits anywhere
  let hint = document.getElementById('settings-search-hint');
  if (!hint) {
    hint = document.createElement('div');
    hint.id = 'settings-search-hint';
    hint.style.cssText = 'font-size:12px;color:var(--muted);margin:-6px 0 10px 0';
    const searchInput = document.getElementById('settings-search');
    if (searchInput && searchInput.parentNode) {
      searchInput.parentNode.insertBefore(hint, searchInput.nextSibling);
    }
  }
  const total = Object.values(tabCounts).reduce((a, b) => a + b, 0);
  if (!q) {
    hint.textContent = '';
  } else if (total === 0) {
    hint.innerHTML = `No settings match <code>${escHtml(q)}</code>. Try shorter or different terms.`;
  } else {
    hint.textContent = `${total} setting${total === 1 ? '' : 's'} match across ${Object.values(tabCounts).filter(c => c > 0).length} tab(s)`;
  }
}

// ─── v3.0.2: Bulk actions modal — fleet-wide operations ────────────────────
// Available from the command palette and from Settings → Advanced. Wraps the
// existing _queue_command_batch endpoint plus a few server-side helpers.
function openBulkActions() {
  const devs = window._devicesCache || [];
  if (!devs.length) { toast('No devices loaded — visit Devices first', 'warning'); return; }
  if (document.getElementById('bulk-modal-overlay')) return;
  const o = document.createElement('div');
  o.id = 'bulk-modal-overlay';
  o.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:99997;display:flex;justify-content:center;align-items:center';
  const groups = {};
  for (const d of devs) {
    const g = d.group || 'devices';
    (groups[g] = groups[g] || []).push(d);
  }
  const tagSet = new Set();
  devs.forEach(d => (d.tags || []).forEach(t => tagSet.add(t)));
  o.innerHTML = `
    <div class="isl-729">
      <div class="isl-725">
        <h3 class="isl-726">Bulk actions</h3>
        <button class="btn-icon isl-727" data-action="closeBulkModal">×</button>
      </div>
      <div class="isl-730">Run an operation across multiple devices at once. Select a filter, pick an action, confirm.</div>

      <div class="mb-14">
        <div class="hint-mb6">FILTER</div>
        <div id="bulk-filter-options" class="row-6-wrap">
          <label class="isl-731">
            <input type="radio" name="bulk-filter" value="all" checked> All monitored (${devs.length})
          </label>
          ${Object.entries(groups).map(([g, ds]) => `
            <label class="isl-731">
              <input type="radio" name="bulk-filter" value="group:${escAttr(g)}"> Group: <code>${escHtml(g)}</code> (${ds.length})
            </label>`).join('')}
          ${[...tagSet].slice(0, 12).map(t => {
            const ct = devs.filter(d => (d.tags || []).includes(t)).length;
            return `<label class="isl-731">
              <input type="radio" name="bulk-filter" value="tag:${escAttr(t)}"> Tag: <code>${escHtml(t)}</code> (${ct})
            </label>`;
          }).join('')}
        </div>
      </div>

      <div class="mb-14">
        <div class="hint-mb6">ACTION</div>
        <select id="bulk-action" class="form-input isl-732">
          <option value="upgrade">Upgrade packages — apt/dnf/yum/pacman</option>
          <option value="reboot">Reboot</option>
          <option value="shutdown">Shut down</option>
          <option value="force_pkg_scan">Force package scan (for CVE freshness)</option>
          <option value="force_acme_rescan">Force ACME rescan</option>
        </select>
      </div>

      <div id="bulk-preview" class="isl-733"></div>

      <div class="user-actions">
        <button class="btn-secondary" data-action="closeBulkModal">Cancel</button>
        <button class="btn-primary" data-action="runBulkAction" >Run</button>
      </div>
    </div>`;
  document.body.appendChild(o);
  o.addEventListener('click', e => { if (e.target === o) o.remove(); });
  document.querySelectorAll('input[name="bulk-filter"]').forEach(el => el.addEventListener('change', _bulkUpdatePreview));
  document.getElementById('bulk-action').addEventListener('change', _bulkUpdatePreview);
  _bulkUpdatePreview();
}
function _bulkResolveTargets() {
  const devs = window._devicesCache || [];
  const sel = document.querySelector('input[name="bulk-filter"]:checked')?.value || 'all';
  let targets = devs.filter(d => d.monitored !== false);
  if (sel.startsWith('group:')) {
    const g = sel.slice(6);
    targets = targets.filter(d => d.group === g);
  } else if (sel.startsWith('tag:')) {
    const t = sel.slice(4);
    targets = targets.filter(d => (d.tags || []).includes(t));
  }
  return targets;
}
function _bulkUpdatePreview() {
  const targets = _bulkResolveTargets();
  const action = document.getElementById('bulk-action')?.value || '?';
  const el = document.getElementById('bulk-preview');
  if (!el) return;
  el.innerHTML = `Will run <strong>${escHtml(action)}</strong> on ${targets.length} device(s):
    <div class="isl-734">
      ${targets.slice(0, 10).map(d => `<code>${escHtml(d.name || d.id)}</code>`).join(', ')}
      ${targets.length > 10 ? ` <span class="c-muted">+${targets.length - 10} more</span>` : ''}
    </div>`;
}
async function runBulkAction() {
  const targets = _bulkResolveTargets();
  const action  = document.getElementById('bulk-action')?.value;
  if (!targets.length) { toast('No targets', 'warning'); return; }
  // Destructive actions need explicit confirmation
  const destructive = ['reboot', 'shutdown'].includes(action);
  if (destructive) {
    const word = prompt(`Type RUN to confirm ${action} on ${targets.length} device(s).`);
    if (word !== 'RUN') { toast('Cancelled', 'info'); return; }
  } else {
    if (!confirm(`Run ${action} on ${targets.length} device(s)?`)) return;
  }
  const ids = targets.map(d => d.id);
  let endpoint, payload;
  if (['reboot', 'shutdown'].includes(action)) {
    endpoint = '/' + action;
    payload = { device_ids: ids };
  } else if (action === 'upgrade') {
    endpoint = '/upgrade';
    payload = { device_ids: ids };
  } else if (action === 'force_pkg_scan') {
    // Per-device endpoint, fan out
    document.getElementById('bulk-modal-overlay')?.remove();
    let ok = 0, fail = 0;
    for (const id of ids) {
      const r = await api('POST', `/devices/${encodeURIComponent(id)}/scan-packages`);
      if (r && !r.error) ok++; else fail++;
    }
    toast(`Package scan queued on ${ok} device(s)${fail ? ', ' + fail + ' failed' : ''}`,
          fail ? 'warning' : 'success');
    return;
  } else if (action === 'force_acme_rescan') {
    document.getElementById('bulk-modal-overlay')?.remove();
    let ok = 0, fail = 0;
    for (const id of ids) {
      const r = await api('POST', `/devices/${encodeURIComponent(id)}/acme/force-rescan`);
      if (r && !r.error) ok++; else fail++;
    }
    toast(`ACME rescan queued on ${ok} device(s)${fail ? ', ' + fail + ' failed' : ''}`,
          fail ? 'warning' : 'success');
    return;
  }
  const r = await api('POST', endpoint, payload);
  document.getElementById('bulk-modal-overlay')?.remove();
  if (!r || r.error) { toast(r?.error || 'Bulk action failed', 'error'); return; }
  toast(`Queued ${action} on ${ids.length} device(s)`, 'success');
}

// ─── v3.0.2: Multi-webhook destinations editor ─────────────────────────────
// Backend stores `config.webhook_urls: [{id, name, url, format, enabled, events?, min_priority?, pushover_*?}, ...]`.
// Pushover creds are write-once-and-redacted: the GET response gives
// `pushover_token_set: true/false` instead of the value; saving an empty
// field preserves the existing secret.
let _webhookDests = [];
const _WEBHOOK_FORMATS = [
  ['discord',   'Discord',        'https://discord.com/api/webhooks/...'],
  ['slack',     'Slack',          'https://hooks.slack.com/services/...'],
  ['pushover',  'Pushover',       'https://api.pushover.net/1/messages.json'],
  ['ntfy',      'ntfy.sh',        'https://ntfy.sh/your-topic'],
  ['teams',     'Microsoft Teams','https://outlook.office.com/webhook/...'],
  ['github',    'GitHub issues',  'https://api.github.com/repos/<owner>/<repo>/issues'],
  ['generic',   'Generic JSON',   'https://your-receiver.example.com/webhook'],
];
function renderWebhookDests() {
  const wrap = document.getElementById('webhook-dests');
  if (!wrap) return;
  if (!_webhookDests.length) {
    wrap.innerHTML = '<div class="isl-735">No destinations yet. Click "Add destination" to wire one up.</div>';
    return;
  }
  wrap.innerHTML = _webhookDests.map((d, idx) => {
    const fmtOpts = _WEBHOOK_FORMATS.map(([v, lbl]) =>
      `<option value="${v}" ${d.format === v ? 'selected' : ''}>${lbl}</option>`).join('');
    const isPushover = d.format === 'pushover';
    const isGithub   = d.format === 'github';
    const tokenSet = d.pushover_token_set;
    const userSet  = d.pushover_user_set;
    const githubTokenSet = d.token_set;
    return `
      <div class="webhook-dest-card isl-736" data-idx="${idx}">
        <div class="isl-737">
          <label class="isl-731">
            <input type="checkbox" data-field="enabled" ${d.enabled ? 'checked' : ''}>
            <strong>Enabled</strong>
          </label>
          <input type="text" data-field="name" class="form-input isl-738" placeholder="Label (e.g. Pushover crit-only)" value="${escAttr(d.name || '')}">
          <button class="btn-icon isl-739" title="Test — fire a 'test' event to this destination" data-action="testWebhookDest" data-arg="${idx}">Test</button>
          <button class="btn-icon isl-740" title="Remove" data-action="removeWebhookDest" data-arg="${idx}">×</button>
        </div>
        <div class="isl-741">
          <select data-field="format" class="form-input isl-742" data-change="updateWebhookDest" data-change-arg="${idx}">${fmtOpts}</select>
          <input type="url" data-field="url" class="form-input input-url-dest" placeholder="${escAttr(_WEBHOOK_FORMATS.find(f => f[0]===d.format)?.[2] || 'https://...')}" value="${escAttr(d.url || '')}">
        </div>
        ${isPushover ? `
          <div class="isl-741">
            <input type="text" data-field="pushover_token" class="form-input isl-743" placeholder="${tokenSet ? '••••••••••• (set — leave blank to keep)' : 'App token (apXXX...)'}">
            <input type="text" data-field="pushover_user"  class="form-input isl-743" placeholder="${userSet  ? '••••••••••• (set — leave blank to keep)' : 'User/group key (uXXX...)'}">
          </div>` : ''}
        ${isGithub ? `
          <div class="isl-741">
            <input type="text" data-field="token" class="form-input isl-743" placeholder="${githubTokenSet ? '••••••••••• (PAT set — leave blank to keep)' : 'GitHub PAT (fine-grained, issues:write)'}">
          </div>
          <div class="meta-sm-nm">Create a fine-grained PAT scoped to your target repo with <code>issues:write</code>. The URL is <code>https://api.github.com/repos/&lt;owner&gt;/&lt;repo&gt;/issues</code>.</div>` : ''}
        <details class="fs-12">
          <summary class="isl-744">Advanced — filter which events fire here</summary>
          <div class="isl-745">
            <label class="isl-746">
              Min severity:
              <select data-field="min_priority" class="form-input isl-747">
                <option value="" ${d.min_priority == null ? 'selected' : ''}>any</option>
                <option value="0" ${d.min_priority === 0 ? 'selected' : ''}>info+</option>
                <option value="1" ${d.min_priority === 1 ? 'selected' : ''}>warning+</option>
                <option value="2" ${d.min_priority === 2 ? 'selected' : ''}>critical only</option>
              </select>
            </label>
            <div class="meta-sm-nm">Or specify exact event names (one per line):</div>
            <textarea data-field="events" class="form-input isl-748" rows="3" placeholder="device_offline&#10;cve_found&#10;monitor_down">${escHtml((d.events || []).join('\n'))}</textarea>
          </div>
        </details>
      </div>`;
  }).join('');
  // Wire change handlers — copy DOM values back into _webhookDests on every edit
  wrap.querySelectorAll('.webhook-dest-card').forEach(card => {
    const idx = parseInt(card.dataset.idx, 10);
    card.querySelectorAll('[data-field]').forEach(el => {
      const ev = (el.tagName === 'TEXTAREA' || el.type === 'text' || el.type === 'url') ? 'input' : 'change';
      el.addEventListener(ev, () => _readWebhookDestCard(idx, card));
    });
  });
}
function _readWebhookDestCard(idx, card) {
  const d = _webhookDests[idx] || {};
  card.querySelectorAll('[data-field]').forEach(el => {
    const f = el.dataset.field;
    if (el.type === 'checkbox') d[f] = el.checked;
    else if (f === 'min_priority') d[f] = el.value === '' ? null : parseInt(el.value, 10);
    else if (f === 'events') d[f] = el.value.split('\n').map(s => s.trim()).filter(Boolean);
    else if (f === 'pushover_token' || f === 'pushover_user') {
      // Don't overwrite the placeholder unless the user typed something
      if (el.value) d[f] = el.value;
    }
    else d[f] = el.value;
  });
  _webhookDests[idx] = d;
}
function updateWebhookDest(idx) {
  // Format changed — re-render so the URL placeholder + creds fields update
  const card = document.querySelectorAll('.webhook-dest-card')[idx];
  if (card) _readWebhookDestCard(idx, card);
  renderWebhookDests();
}
function addWebhookDest() {
  _webhookDests.push({
    id: 'wh_' + Math.random().toString(36).slice(2, 10),
    name: '', url: '', format: 'discord', enabled: true,
  });
  renderWebhookDests();
}
function removeWebhookDest(idx) {
  if (!confirm('Remove this destination?')) return;
  _webhookDests.splice(idx, 1);
  renderWebhookDests();
}
async function testWebhookDest(idx) {
  // First sync any pending edits
  const card = document.querySelectorAll('.webhook-dest-card')[idx];
  if (card) _readWebhookDestCard(idx, card);
  const d = _webhookDests[idx];
  if (!d?.url) { toast('Set a URL first', 'warning'); return; }
  // Save current state so the test fires against persisted config
  toast('Saving and firing test event…', 'info');
  await saveWebhookDests();
  const r = await api('POST', '/webhook/test', {id: d.id});
  if (!r) { toast('Test failed (no response)', 'error'); return; }
  if (r.error) { toast(r.error, 'error'); return; }
  toast(`Test fired to "${d.name || d.url}". Check the webhook log below for the result.`, 'success');
  setTimeout(loadWebhookLog, 800);
}
async function saveWebhookDests() {
  // Strip the read-only "*_set" markers; backend doesn't want them on POST
  const cleaned = _webhookDests.map(d => {
    const c = {...d};
    delete c.pushover_token_set;
    delete c.pushover_user_set;
    return c;
  });
  const r = await api('POST', '/config', {webhook_urls: cleaned});
  if (!r || r.error) {
    toast('Save failed: ' + (r?.error || 'unknown'), 'error');
    return false;
  }
  return true;
}

// ── CSP L1: apply data-color / data-bg / data-bd attributes after innerHTML ──
// The auto-class generator dropped dynamic `color: ${...}` declarations
// because CSS can't carry JS expressions. Templates that used those
// classes now also carry `data-color="<value>"` and a MutationObserver
// applies the value via the CSP-safe element.style IDL setter.
const _dynColorObserver = new MutationObserver((muts) => {
  for (const m of muts) {
    for (const node of m.addedNodes) {
      if (node.nodeType !== 1) continue;
      if (node.dataset?.color) node.style.color = node.dataset.color;
      if (node.dataset?.bg) node.style.background = node.dataset.bg;
      if (node.dataset?.bd) node.style.border = '1px solid ' + node.dataset.bd;
      if (node.dataset?.bdStyle && node.dataset?.bdColor) {
        node.style.border = '1px ' + node.dataset.bdStyle + ' ' + node.dataset.bdColor;
      }
      // v3.2.0: data-pct → percentage width (Server Status performance bars)
      if (node.dataset?.pct) node.style.width = node.dataset.pct + '%';
      if (node.querySelectorAll) {
        node.querySelectorAll('[data-color]').forEach(el => { el.style.color = el.dataset.color; });
        node.querySelectorAll('[data-bg]').forEach(el => { el.style.background = el.dataset.bg; });
        node.querySelectorAll('[data-bd]').forEach(el => { el.style.border = '1px solid ' + el.dataset.bd; });
        node.querySelectorAll('[data-bd-style][data-bd-color]').forEach(el => {
          el.style.border = '1px ' + el.dataset.bdStyle + ' ' + el.dataset.bdColor;
        });
        node.querySelectorAll('[data-pct]').forEach(el => { el.style.width = el.dataset.pct + '%'; });
      }
    }
  }
});
_dynColorObserver.observe(document.documentElement, { childList: true, subtree: true });

