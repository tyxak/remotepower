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
        th.innerHTML = baseLabel + ' <span style="color:var(--muted);opacity:.3;font-size:10px">↕</span>';
      } else {
        const arrow = sort[idx].dir === 'asc' ? '▲' : '▼';
        // Multi-column: show the priority order as a small superscript
        const prio = sort.length > 1 ? `<sup style="font-size:9px;opacity:.7">${idx+1}</sup>` : '';
        th.innerHTML = baseLabel + ` <span style="color:var(--accent);font-size:10px">${arrow}${prio}</span>`;
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
      tbody.innerHTML = `<tr><td colspan="${colspan}" style="text-align:center;color:var(--muted);padding:40px">${msg}</td></tr>`;
      return;
    }
    tbody.innerHTML = filtered.map(opts.row).join('');
  }

  function getStoredFilter(name) {
    return (getTablePrefs(name).filter) || '';
  }

  return { register, render, getStoredFilter };
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
      return `<button onclick="densityCtl.set('${escAttr(name)}','${val}', window.__densityCb_${escAttr(name)})" title="${escHtml(title)}" style="padding:6px 10px;font-size:11px;font-weight:500;background:${sel ? 'var(--accent)' : 'var(--surface)'};color:${sel ? '#fff' : 'var(--muted)'};border:1px solid var(--border);cursor:pointer">${escHtml(label)}</button>`;
    };
    // Stash the callback under a deterministic global so the inline onclick
    // can find it. Slightly hacky, but avoids needing a UUID per control.
    window['__densityCb_' + name] = onChange;
    return `<div style="display:inline-flex;border-radius:6px;overflow:hidden;border:1px solid var(--border)">
      ${btn('minimal', '☰', 'Minimal — one device per line')}
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
  // Returns an inline SVG span sized to `sizePx` (default 16).
  const px = sizePx || 16;
  const svg = _OS_ICONS[osIconKey(osStr)] || _OS_ICONS.unknown;
  const sized = svg.replace(/<svg /, `<svg width="${px}" height="${px}" `);
  return `<span class="os-icon" title="${(osStr || 'Unknown OS').replace(/"/g,'&quot;')}" style="display:inline-flex;vertical-align:middle;line-height:0;color:var(--muted)">${sized}</span>`;
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
  loadDevices();
  startRefreshCycle();
  checkServerVersion();
  applyTheme();
  requestNotifications();
}
async function checkServerVersion() {
  try {
    const data = await api('GET', '/version');
    if (!data || !data.update_available) return;
    document.getElementById('update-banner')?.remove();
    const banner = document.createElement('div');
    banner.id = 'update-banner';
    banner.className = 'update-banner';
    banner.innerHTML = `⚡ RemotePower <strong>v${data.latest}</strong> is available (you have v${data.current}) — <a href="${data.release_url}" target="_blank">View release →</a>`;
    document.querySelector('header').insertAdjacentElement('afterend', banner);
  } catch(e) {}
}
function applyTheme() {
  const theme = localStorage.getItem('rp_theme') || 'dark';
  document.body.classList.toggle('light', theme === 'light');
  const btn = document.querySelector('.theme-btn');
  if (btn) btn.textContent = theme === 'light' ? '🌙' : '☀️';
}
function toggleTheme() {
  const isLight = document.body.classList.toggle('light');
  localStorage.setItem('rp_theme', isLight ? 'light' : 'dark');
  const btn = document.querySelector('.theme-btn');
  if (btn) btn.textContent = isLight ? '🌙' : '☀️';
}
async function api(method, path, body) {
  const opts = {method, headers: {'X-Token': getToken()}};
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
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
    // Default state per group: Security and Planning expanded (most-used);
    // Admin collapsed (admins know where it is, regular users don't need
    // it cluttering the view).
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
  if (name === 'monitor')  { runMonitor(); loadDeviceMetrics(); }
  if (name === 'history')  loadHistory();
  if (name === 'schedule') loadSchedule();
  if (name === 'users')    loadUsers();
  if (name === 'settings') { loadSettings(); loadTotpStatus(); loadWebhookLog(); }
  if (name === 'ai') { loadAIPage(); }
  if (name === 'about')    loadAbout();
  if (name === 'apikeys')  loadApiKeys();
  if (name === 'cmdlib')   loadCmdLib();
  if (name === 'scripts')  loadScripts();
  if (name === 'patches')  loadPatchReport();
  if (name === 'cve')      loadCVEReport();
  if (name === 'services') loadServicesReport();
  if (name === 'maintenance') loadMaintenance();
  if (name === 'logs')     enterLogsPage();
  else                     leaveLogsPage();
  if (name === 'calendar') loadCalendar();
  if (name === 'tasks')    loadTasks();
  if (name === 'cmdb')     enterCMDB();
  if (name === 'containers') enterContainers();
  if (name === 'netmap')   enterNetmap();
  if (name === 'tls')      enterTLS();
  if (name === 'links')    enterLinks();
  if (name === 'audit')    loadAuditLog();
}
async function loadDevices() {
  try {
    const data = await api('GET', '/devices');
    if (!data) return;
    devices = data;
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
    filterBar.innerHTML = allTags.map(t => `<button onclick="setTagFilter('${escAttr(t)}')" style="padding:3px 10px;border-radius:20px;font-size:11px;font-weight:500;cursor:pointer;border:1px solid;background:${activeTagFilter===t ? 'rgba(59,126,255,0.2)' : 'transparent'};color:${activeTagFilter===t ? 'var(--accent)' : 'var(--muted)'};border-color:${activeTagFilter===t ? 'var(--accent)' : 'var(--border)'};font-family:var(--font)">${escHtml(t)}</button>`).join('');
    if (activeTagFilter) filterBar.innerHTML += `<button onclick="setTagFilter(null)" style="padding:3px 10px;border-radius:20px;font-size:11px;cursor:pointer;border:1px solid var(--border);color:var(--muted);background:transparent;font-family:var(--font)">✕ clear</button>`;
  }
  let filtered = activeTagFilter ? devices.filter(d => (d.tags || []).includes(activeTagFilter)) : devices;
  const deviceSearchTerm = (document.getElementById('device-search-input')?.value || '').toLowerCase();
  if (deviceSearchTerm) filtered = filtered.filter(d => (d.name||'').toLowerCase().includes(deviceSearchTerm) || (d.hostname||'').toLowerCase().includes(deviceSearchTerm) || (d.ip||'').toLowerCase().includes(deviceSearchTerm) || (d.os||'').toLowerCase().includes(deviceSearchTerm) || (d.group||'').toLowerCase().includes(deviceSearchTerm) || (d.tags||[]).some(t => t.toLowerCase().includes(deviceSearchTerm)));
  const deviceStatusFilter = document.getElementById('device-status-filter')?.value || 'all';
  if (deviceStatusFilter === 'online') filtered = filtered.filter(d => d.online);
  else if (deviceStatusFilter === 'offline') filtered = filtered.filter(d => !d.online);
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
    const iconContent = d.icon ? `<span style="font-size:22px;line-height:1">${escHtml(d.icon)}</span>` : (isSel ? `<svg viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>` : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`);
    return `<div class="device-card ${isOnline ? 'online' : 'offline'}" style="${isSel ? 'border-color:var(--accent);box-shadow:0 0 0 2px rgba(59,126,255,0.2)' : ''}">
      <div class="device-header">
        <div class="device-info">
          <div class="device-icon" style="cursor:pointer" onclick="toggleSelect('${d.id}')" title="Select for batch action">${iconContent}</div>
          <div><div class="device-name">${escHtml(d.name)}${d.notes ? `<span class="notes-tip" title="${escHtml(d.notes)}" onclick="openNotesModal('${d.id}','${escAttr(d.notes)}')">📝</span>` : ''}</div><div class="device-hostname">${escHtml(d.hostname)}${d.group ? ` <span class="group-badge">${escHtml(d.group)}</span>` : ''}${isMonitored ? '' : ' <span style="font-size:10px;color:var(--muted);background:var(--surface2);padding:1px 5px;border-radius:4px">unmonitored</span>'}</div></div>
        </div>
        <div class="status-badge ${isOnline ? 'online' : 'offline'}"><div class="status-badge-dot"></div>${isOnline ? 'Online' : 'Offline'}${missedHtml}</div>
      </div>
      <div class="device-meta"><div class="meta-item"><div class="meta-label">OS</div><div class="meta-value">${osIcon(d.os, 14)} ${escHtml(d.os || '—')}</div></div><div class="meta-item"><div class="meta-label">IP</div><div class="meta-value">${escHtml(d.ip || '—')}</div></div><div class="meta-item"><div class="meta-label">Version</div><div class="meta-value">${escHtml(d.version || '—')} ${patchHtml}</div></div><div class="meta-item"><div class="meta-label">Poll / Enrolled</div><div class="meta-value">${d.poll_interval||60}s · ${d.enrolled ? timeAgo(d.enrolled) : '—'}</div></div></div>
      ${deviceDropdownHtml(d, isMonitored)}
      ${(d.tags||[]).length ? `<div style="margin-top:8px">${(d.tags||[]).map(t=>`<span class="tag-pill">${escHtml(t)}</span>`).join('')}</div>` : ''}
      <div class="last-seen">Last seen: ${lastSeen}</div>
    </div>`;
  }).join('');
}

// v1.11.7: render Devices as an aligned, sortable table. This is the new
// 'minimal' density layout — replaces the old flex-row hacky one that
// couldn't keep columns aligned when cell contents had different widths.
let _devicesMinimalRegistered = false;
function _registerDevicesMinimalTable() {
  if (_devicesMinimalRegistered) return;
  _devicesMinimalRegistered = true;
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
        patchHtml = ` <span class="patch-badge ${cls}" style="font-size:10px;padding:1px 5px">${pkg.upgradable}</span>`;
      }
      const groupHtml = d.group ? `<span class="group-badge" style="font-size:10px">${escHtml(d.group)}</span>` : '<span style="color:var(--muted)">—</span>';
      // v1.11.7: dropdown HTML is identical to the cards path — exact same
      // menu items, same handlers, same `dropdown-${d.id}` id so
      // toggleDropdown() works without changes. Just wrapped in a <td>.
      const dropdownHtml = `${deviceDropdownHtml(d, isMonitored)}`;
      // v1.12.1: leading checkbox cell mirrors the cards-mode batch-select
      // experience. Reuses the same selectedDevices Set so cards/minimal
      // share state — switch density mid-selection, your selection survives.
      const isSel = selectedDevices.has(d.id);
      return `<tr class="dev-row ${isOnline ? 'online' : 'offline'} ${isSel ? 'selected' : ''}" data-dev-id="${d.id}">
        <td style="text-align:center;padding:0 6px"><input type="checkbox" ${isSel ? 'checked' : ''} onclick="toggleSelect('${d.id}')" style="margin:0"></td>
        <td class="dev-status-cell"><span class="status-badge ${isOnline ? 'online' : 'offline'}" style="padding:1px 8px;font-size:10px"><div class="status-badge-dot"></div>${isOnline ? 'Online' : 'Offline'}</span></td>
        <td class="dev-name-cell"><a href="#" onclick="openDetail('${d.id}','${escAttr(d.name)}'); return false;" style="color:var(--text);text-decoration:none;font-weight:500">${escHtml(d.name)}</a>${isMonitored ? '' : ' <span style="font-size:9px;color:var(--muted);background:var(--surface2);padding:1px 4px;border-radius:3px">unmon</span>'}</td>
        <td class="dev-host-cell" style="font-size:12px;color:var(--muted)">${escHtml(d.hostname || '—')}</td>
        <td class="dev-group-cell">${groupHtml}</td>
        <td class="dev-os-cell" style="font-size:12px">${osIcon(d.os, 12)} ${escHtml(d.os || '—')}</td>
        <td class="dev-ip-cell" style="font-family:monospace;font-size:12px">${escHtml(d.ip || '—')}</td>
        <td class="dev-version-cell" style="font-size:12px">${escHtml(d.version || '—')}${patchHtml}</td>
        <td class="dev-lastseen-cell" style="font-size:12px;color:var(--muted)">${lastSeen}</td>
        <td class="dev-actions-cell" style="text-align:right">${dropdownHtml}</td>
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
  container.innerHTML = `<div class="devices-minimal-wrap">
    <table class="devices-minimal-table">
      <thead id="devices-minimal-thead">
        <tr>
          <th style="width:36px;text-align:center"><input type="checkbox" id="dev-min-select-all" onclick="toggleSelectAllMinimal(this)" title="Select all visible" style="margin:0"></th>
          <th data-col="status" style="width:90px">Status</th>
          <th data-col="name" style="width:190px">Name</th>
          <th data-col="hostname" style="width:160px">Hostname</th>
          <th data-col="group" style="width:100px">Group</th>
          <th data-col="os">OS</th>
          <th data-col="ip" style="width:130px">IP</th>
          <th data-col="version" style="width:90px">Version</th>
          <th data-col="last_seen" style="width:100px">Last seen</th>
          <th style="width:50px"></th>
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
const deviceIcons = ['🖥️','💻','🖲️','📱','🖨️','📡','🌐','🗄️','🔌','💾','📟','🎮','📺','🏠','🏢','🏭','☁️','🐳','🐧','🪟','🍎','🔴','🟢','🔵','🟡','⚡','🛡️','🔒','📦','🧪'];
function openIconModal(id, current) { document.getElementById('icon-device-id').value = id; document.getElementById('icon-custom').value = current || ''; const picker = document.getElementById('icon-picker'); picker.innerHTML = deviceIcons.map(e => `<button onclick="document.getElementById('icon-custom').value='${e}'" style="font-size:24px;padding:8px;border:1px solid var(--border);border-radius:8px;background:var(--surface2);cursor:pointer;transition:all 0.15s;min-width:44px;text-align:center" onmouseover="this.style.borderColor='var(--accent)'" onmouseout="this.style.borderColor='var(--border)'">${e}</button>`).join(''); openModal('icon-modal'); }
async function saveDeviceIcon(icon) { const id = document.getElementById('icon-device-id').value; const data = await api('PATCH', '/devices/' + id + '/icon', { icon }); if (data?.ok) { toast(icon ? `Icon set to ${icon}` : 'Icon cleared', 'success'); closeModal('icon-modal'); loadDevices(); } else toast(data?.error || 'Failed', 'error'); }
async function toggleMonitored(id, monitored) { const data = await api('PATCH', '/devices/' + id + '/monitored', { monitored }); if (data?.ok) { toast(monitored ? 'Monitoring enabled' : 'Monitoring disabled', 'success'); loadDevices(); } else toast(data?.error || 'Failed', 'error'); }
async function clearMonitorAlerts() { if (!confirm('Reset all monitor alert state? This allows alerts to re-fire.')) return; const data = await api('DELETE', '/monitor/alerts/clear'); if (data?.ok) toast('Monitor alert state cleared', 'success'); else toast(data?.error || 'Failed', 'error'); }
async function clearWebhookLog() { if (!confirm('Clear the webhook delivery log?')) return; const data = await api('DELETE', '/webhook/log'); if (data?.ok) { toast('Webhook log cleared', 'success'); loadWebhookLog(); } else toast(data?.error || 'Failed', 'error'); }
async function openDetail(id, name) { document.getElementById('detail-title').textContent = name; document.getElementById('detail-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>'; openModal('detail-modal'); const data = await api('GET', '/devices/' + id + '/sysinfo'); if (!data) return; const si = data.sysinfo || {}; const journal = data.journal || []; const pkg = si.packages || {}; let html = ''; if (si.uptime || pkg.manager) { html += `<div class="sysinfo-row">`; if (si.uptime) html += `<div class="sysinfo-pill"><div class="label">Uptime</div><div class="value">${escHtml(si.uptime)}</div></div>`; if (pkg.manager) html += `<div class="sysinfo-pill"><div class="label">Pkg manager</div><div class="value">${escHtml(pkg.manager)}</div></div>`; if (pkg.upgradable !== null && pkg.upgradable !== undefined) { const col = pkg.upgradable > 0 ? 'var(--amber)' : 'var(--green)'; html += `<div class="sysinfo-pill"><div class="label">Upgradable</div><div class="value" style="color:${col}">${pkg.upgradable} package${pkg.upgradable !== 1 ? 's' : ''}</div></div>`; } if (si.platform) html += `<div class="sysinfo-pill"><div class="label">Platform</div><div class="value" style="font-size:11px">${escHtml(si.platform)}</div></div>`; html += `</div>`; } html += `<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><div style="font-size:13px;font-weight:600;color:var(--muted)">Journal — last ${journal.length} lines</div><button class="btn-icon" style="font-size:11px;padding:3px 8px" onclick="aiFindProblemInJournal('${escAttr(name)}', ${journal.length ? "document.querySelector('.journal-wrap').textContent.split('\\n')" : '[]'})">✨ Find the problem</button></div><div class="journal-wrap">${escHtml(journal.join('\n'))}</div>`; if (!si.uptime && !journal.length) html = `<div style="color:var(--muted);text-align:center;padding:40px;font-size:14px">No data yet — the agent reports sysinfo every ~10 minutes.</div>`; document.getElementById('detail-body').innerHTML = html; try { const out = await api('GET', '/devices/' + id + '/output'); if (out?.outputs?.length) { let outHtml = `<div style="font-size:13px;font-weight:600;margin:16px 0 8px;color:var(--muted)">Command output — last ${out.outputs.length}</div>`; outHtml += out.outputs.slice().reverse().map(o => `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;gap:8px;flex-wrap:wrap"><code style="font-size:12px;color:var(--accent);overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0">${escHtml(o.cmd)}</code><div style="display:flex;gap:8px;align-items:center"><button class="btn-icon" style="font-size:11px;padding:2px 8px" onclick="aiExplainOutput('${escAttr(name)}','${escAttr(o.cmd)}','${escAttr(o.output||'')}')">✨ Explain</button><span style="font-size:11px;color:var(--muted);white-space:nowrap">${new Date(o.ts*1000).toLocaleString()} · rc=${o.rc}</span></div></div><div class="journal-wrap" style="max-height:120px">${escHtml(o.output||'(no output)')}</div></div>`).join(''); document.getElementById('detail-body').innerHTML += outHtml; } } catch(e) {} }
function openEnrollModal() { generateNewPin(); openModal('enroll-modal'); }
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
      return `<tr><td style="font-weight:500">${escHtml(m.label)}</td><td><span style="font-family:monospace;font-size:11px;background:var(--surface2);padding:2px 6px;border-radius:4px">${escHtml(m.type)}</span></td><td style="font-family:monospace;font-size:12px;color:var(--muted)">${escHtml(m.target)}</td><td><span class="mon-status ${m.ok ? 'up' : 'down'}">${m.ok ? '↑ up' : '↓ down'}</span></td><td style="font-size:12px;color:var(--muted)">${escHtml(m.detail || '—')}</td><td style="font-size:12px;color:var(--muted)">${m.checked ? timeAgo(m.checked) : '—'}</td><td style="display:flex;gap:6px"><button class="btn-icon" style="padding:4px 8px" onclick="openMonitorHistory('${escAttr(m.label)}')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></button><button class="btn-icon" style="padding:4px 8px" onclick="removeMonitor(${i})"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button></td></tr>`;
    },
    emptyMsg: 'No monitors configured.',
    emptyMsgFiltered: 'No monitors match the filter.',
  });
}
async function runMonitor() {
  _registerMonitorTable();
  const tbody = document.getElementById('monitor-tbody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">Checking…</td></tr>';
  const data = await api('GET', '/monitor');
  if (!data) return;
  const results = data.monitors || [];
  monitorTargets = results;
  // Set on window so the row builder can find indexes for the remove
  // button (its onclick uses the array index, not an id).
  window.monitorTargets = results;
  tableCtl.render('monitor', results);
}
function openMonitorAdd() { document.getElementById('mon-label').value = ''; document.getElementById('mon-type').value = 'ping'; document.getElementById('mon-target').value = ''; openModal('monitor-add-modal'); }
async function addMonitor() { const label = document.getElementById('mon-label').value.trim(); const type = document.getElementById('mon-type').value; const target = document.getElementById('mon-target').value.trim(); if (!target) { toast('Target is required', 'error'); return; } const cfg = await api('GET', '/config'); if (!cfg) return; const monitors = [...(cfg.monitors || []), {label: label || target, type, target}]; const res = await api('POST', '/config', {monitors}); if (res?.ok) { toast('Monitor added', 'success'); closeModal('monitor-add-modal'); runMonitor(); } else toast(res?.error || 'Failed', 'error'); }
async function removeMonitor(idx) { const cfg = await api('GET', '/config'); if (!cfg) return; const monitors = (cfg.monitors || []).filter((_, i) => i !== idx); const res = await api('POST', '/config', {monitors}); if (res?.ok) { toast('Removed', 'info'); runMonitor(); } else toast(res?.error || 'Failed', 'error'); }
async function openMonitorHistory(label) { document.getElementById('mon-history-title').textContent = `History: ${label}`; document.getElementById('mon-history-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>'; openModal('mon-history-modal'); const data = await api('GET', `/monitor/history?label=${encodeURIComponent(label)}`); if (!data) return; const history = data.history || []; if (!history.length) { document.getElementById('mon-history-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">No history yet — run a check first.</div>'; return; } const recent = history.slice(-20); const dots = recent.map(h => `<span title="${new Date(h.ts*1000).toLocaleString()} — ${h.detail||''}" style="display:inline-block;width:12px;height:12px;border-radius:50%;margin:2px;background:${h.ok ? 'var(--green)' : 'var(--red)'}"></span>`).join(''); const upCount = history.filter(h => h.ok).length; const pct = Math.round(upCount / history.length * 100); const lastCheck = history[history.length - 1]; document.getElementById('mon-history-body').innerHTML = `<div class="sysinfo-row" style="margin-bottom:16px"><div class="sysinfo-pill"><div class="label">Checks</div><div class="value">${history.length}</div></div><div class="sysinfo-pill"><div class="label">Uptime</div><div class="value" style="color:${pct>=90?'var(--green)':pct>=70?'var(--amber)':'var(--red)'}">${pct}%</div></div><div class="sysinfo-pill"><div class="label">Last status</div><div class="value" style="color:${lastCheck.ok?'var(--green)':'var(--red)'}">${lastCheck.ok ? '↑ up' : '↓ down'}</div></div></div><div style="font-size:12px;color:var(--muted);margin-bottom:8px">Last ${recent.length} checks (newest right)</div><div style="padding:8px 0">${dots}</div><div class="table-card" style="margin-top:16px;max-height:240px;overflow-y:auto"><table><thead><tr><th>Time</th><th>Status</th><th>Detail</th></tr></thead><tbody>${[...history].reverse().slice(0,50).map(h => `<tr><td style="font-size:12px;color:var(--muted)">${new Date(h.ts*1000).toLocaleString()}</td><td><span class="mon-status ${h.ok?'up':'down'}">${h.ok?'↑ up':'↓ down'}</span></td><td style="font-size:12px;color:var(--muted)">${escHtml(h.detail||'—')}</td></tr>`).join('')}</tbody></table></div>`; }
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
      return `<tr class="user-row"><td style="font-weight:600">${escHtml(u.username)}${u.username === me ? ' <span style="font-size:11px;color:var(--muted)">(you)</span>' : ''}</td><td style="color:var(--muted);font-size:12px">${u.created ? new Date(u.created * 1000).toLocaleDateString() : '—'}</td><td><span class="patch-badge ${u.role==='viewer'?'ok':'warn'}" style="font-size:11px">${escHtml(u.role||'admin')}</span></td><td><div class="user-actions"><button class="btn-icon" onclick="openPasswd('${escAttr(u.username)}')">Change pw</button><button class="btn-icon" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteUser('${escAttr(u.username)}')">Delete</button></div></td></tr>`;
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
function openPasswd(username) { document.getElementById('passwd-username').value = username; document.getElementById('passwd-old').value = ''; document.getElementById('passwd-new').value = ''; document.getElementById('passwd-old-wrap').style.display = 'block'; openModal('passwd-modal'); }
async function submitPasswd() { const username = document.getElementById('passwd-username').value; const old_pw = document.getElementById('passwd-old').value; const new_pw = document.getElementById('passwd-new').value; if (!new_pw) { toast('New password required', 'error'); return; } const data = await api('POST', '/users/passwd', {username, old_password: old_pw, new_password: new_pw}); if (data?.ok) { toast('Password updated', 'success'); closeModal('passwd-modal'); } else toast(data?.error || 'Failed', 'error'); }
// ─── v1.8.4: Settings tabs + new fields ─────────────────────────────────────
function switchSettingsTab(tab) {
  document.querySelectorAll('.settings-tab').forEach(b =>
    b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.settings-pane').forEach(p =>
    p.classList.toggle('active', p.id === `settings-pane-${tab}`));
  if (tab) location.hash = `settings/${tab}`;
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
      <th style="text-align:left;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;padding:8px;font-weight:500">Event</th>
      <th style="text-align:left;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;padding:8px;font-weight:500">Description</th>
      <th style="text-align:center;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;padding:8px;font-weight:500;width:70px">Webhook</th>
      <th style="text-align:center;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px;padding:8px;font-weight:500;width:70px">Email</th>
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
      extra = `<div class="event-extra" style="display:flex;align-items:center;gap:8px"><span style="font-size:12px;color:var(--muted)">Threshold:</span><input type="number" id="cfg-patch-threshold" min="0" placeholder="e.g. 10" style="width:100px;padding:4px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);font-size:12px"><span style="font-size:11px;color:var(--muted)">pending updates</span></div>`;
    } else if (ev === 'cve_found') {
      extra = `<div class="event-extra"><div style="font-size:12px;color:var(--muted);margin-bottom:4px">Severities to alert on:</div><div id="cfg-cve-severity-row" style="display:flex;gap:10px;flex-wrap:wrap"></div></div>`;
    }
    return `<tr>
      <td><code>${escHtml(ev)}</code></td>
      <td>${escHtml(desc)}${extra}</td>
      <td style="text-align:center"><input type="checkbox" class="toggle-switch toggle-webhook" data-event="${escHtml(ev)}" ${wh}></td>
      <td style="text-align:center"><input type="checkbox" class="toggle-switch toggle-email"   data-event="${escHtml(ev)}" ${email}></td>
    </tr>`;
  }).join('');
}

function renderCveSeverityRow(severities, current) {
  const row = document.getElementById('cfg-cve-severity-row');
  if (!row) return;
  row.innerHTML = severities.map(s => {
    const checked = current.includes(s) ? 'checked' : '';
    return `<label style="display:flex;align-items:center;gap:5px;cursor:pointer;font-size:12px"><input type="checkbox" class="cfg-cve-sev" value="${escHtml(s)}" ${checked} style="accent-color:var(--accent)">${escHtml(s)}</label>`;
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
}
function clearWebhook() { document.getElementById('cfg-webhook').value = ''; toast('Webhook URL cleared — click Save to apply', 'info'); }
async function saveSettings() {
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
  };
  // Only send password fields if the user typed something — empty string
  // would clear them on the server. Leave key out to preserve existing.
  const smtpPw = document.getElementById('cfg-smtp-password').value;
  if (smtpPw) payload.smtp_password = smtpPw;
  const ldapPw = document.getElementById('cfg-ldap-bind-password').value;
  if (ldapPw) payload.ldap_bind_password = ldapPw;

  const data = await api('POST', '/config', payload);
  if (data?.ok) {
    toast('Settings saved', 'success');
    // Clear password fields after save so they don't sit in the DOM
    document.getElementById('cfg-smtp-password').value = '';
    document.getElementById('cfg-ldap-bind-password').value = '';
    // v2.1.3: AI settings live in their own endpoint, save in parallel
    try { await saveAISettings(); } catch(e) {}
    loadSettings(); loadWebhookLog();
  } else {
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
      `<span style="font-family:monospace;font-size:11px">DN: ${escHtml(data.dn)}<br>` +
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
async function loadWebhookLog() { const tbody = document.getElementById('webhook-log-tbody'); const data = await api('GET', '/webhook/log'); if (!data) return; const entries = Array.isArray(data) ? data : []; if (!entries.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">No webhook deliveries yet. </td></tr>'; return; } tbody.innerHTML = entries.slice(0, 50).map(e => { const isOk = String(e.status).startsWith('2') || e.status === 200; const statusColor = isOk ? 'var(--green)' : 'var(--red)'; return `<tr><td style="font-size:12px;color:var(--muted);white-space:nowrap">${new Date(e.ts * 1000).toLocaleString()}</td><td><span class="cmd-badge" style="background:rgba(59,126,255,0.1);color:var(--accent)">${escHtml(e.event)}</span></td><td style="font-weight:600;color:${statusColor}">${escHtml(e.status)}</td><td style="font-size:12px;color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(e.detail)}">${escHtml(e.detail)}</td><td style="white-space:nowrap"><button class="btn-icon" style="font-size:11px;padding:2px 8px" onclick="aiExplainAlert('${escAttr(e.event)}','','${escAttr(e.detail||'')}',null)">✨ Explain</button></td></tr>`; }).join(''); }
// v2.1.0: refresh cycle pauses while a modal is open or the tab is in
// the background. The "auto-refresh closes browser window" bug had two
// independent triggers in 2.0.0:
//
//   1. escHtml didn't escape ' — see escAttr() above. A device name like
//      `O'Brien` injected literal apostrophes into onclick="fn('${name}')"
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
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }
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
function toast(msg, type = 'info') { const id = 'toast-' + (++toastId); const icons = {success: '✓', error: '✕', info: 'ℹ'}; const el = document.createElement('div'); el.className = `toast ${type}`; el.id = id; el.innerHTML = `<span class="toast-icon">${icons[type] || 'ℹ'}</span><span>${msg}</span>`; document.getElementById('toast-container').appendChild(el); requestAnimationFrame(() => el.classList.add('show')); setTimeout(() => { el.classList.remove('show'); setTimeout(() => el.remove(), 400); }, 3500); }
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
    row: (j) => `<tr><td style="font-weight:500">${escHtml(j.device_name)}</td><td><span class="cmd-badge ${escHtml(j.command)}">${escHtml(j.command)}</span></td><td style="font-family:monospace;font-size:12px">${j.recurring ? `<span style="color:var(--accent)">↻ ${escHtml(j.cron)}</span>` : new Date(j.run_at*1000).toLocaleString()}</td><td style="color:var(--muted);font-size:12px">${escHtml(j.actor)}</td><td><button class="btn-icon" style="padding:4px 8px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteJob('${escAttr(j.id)}')">✕</button></td></tr>`,
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
    row: (e) => `<tr><td style="color:var(--muted);font-size:12px;white-space:nowrap">${new Date(e.ts*1000).toLocaleString()}</td><td style="font-weight:500">${escHtml(e.actor)}</td><td style="font-family:monospace;font-size:12px">${escHtml(e.device_name)}</td><td><span class="cmd-badge ${escHtml(e.command)}">${escHtml(e.command)}</span></td></tr>`,
    emptyMsg: 'No commands logged yet.',
    emptyMsgFiltered: 'No commands match the filter.',
  });
}
async function loadHistory() {
  _registerHistoryTable();
  const tbody = document.getElementById('history-tbody');
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">Loading…</tbody>';
  const data = await api('GET', '/history');
  tableCtl.render('history', data || []);
}
async function addScheduleJob() { const dev_id = document.getElementById('sched-device').value; const command = document.getElementById('sched-command').value; const dt = document.getElementById('sched-datetime').value; const cron = document.getElementById('sched-cron').value.trim(); if (!dt && !cron) { toast('Provide a date/time or cron expression', 'error'); return; } const payload = {device_id: dev_id, command}; if (cron) payload.cron = cron; else payload.run_at = Math.floor(new Date(dt).getTime() / 1000); const data = await api('POST', '/schedule', payload); if (data?.ok) { toast(cron ? `Recurring ${command} scheduled (${cron})` : `${command} scheduled`, 'success'); closeModal('schedule-add-modal'); loadSchedule(); } else toast(data?.error || 'Failed', 'error'); }
async function deleteJob(id) { const data = await api('DELETE', '/schedule/' + id); if (data?.ok) { toast('Job cancelled', 'info'); loadSchedule(); } else toast(data?.error || 'Failed', 'error'); }
function openExecModal(id, name) { document.getElementById('exec-device-id').value = id; document.getElementById('exec-cmd').value = ''; document.querySelector('#exec-modal .modal-title').textContent = `Run command on ${name}`; api('GET', '/cmd-library').then(data => { const sel = document.getElementById('exec-library-pick'); sel.innerHTML = '<option value="">— Command library —</option>'; (data || []).forEach(s => { const opt = document.createElement('option'); opt.value = s.cmd; opt.textContent = s.name; sel.appendChild(opt); }); }).catch(() => {}); openModal('exec-modal'); }
function pickFromLibrary() { const val = document.getElementById('exec-library-pick').value; if (val) document.getElementById('exec-cmd').value = val; }
function openScheduleAdd() { const sel = document.getElementById('sched-device'); sel.innerHTML = devices.map(d => `<option value="${escHtml(d.id)}">${escHtml(d.name)}${d.online ? '' : ' (offline)'}</option>`).join(''); const dt = new Date(Date.now() + 3600000); const local = new Date(dt - dt.getTimezoneOffset()*60000).toISOString().slice(0,16); document.getElementById('sched-datetime').value = local; document.getElementById('sched-cron').value = ''; openModal('schedule-add-modal'); }
async function sendExecCmd() { const id = document.getElementById('exec-device-id').value; const cmd = document.getElementById('exec-cmd').value.trim(); if (!cmd) { toast('Enter a command', 'error'); return; } const data = await api('POST', '/exec', {device_id: id, cmd}); if (data?.ok) { toast('Command queued — output on next heartbeat (~60s)', 'success'); closeModal('exec-modal'); } else toast(data?.error || 'Failed', 'error'); }
async function loadAbout() { try { const v = await api('GET', '/version'); if (v) { document.getElementById('about-server-version').textContent = v.current || '—'; const latestEl = document.getElementById('about-latest-version'); if (v.latest) { latestEl.textContent = v.latest; if (v.update_available) { latestEl.style.color = 'var(--amber)'; latestEl.textContent += ' ⚡ update available'; } else { latestEl.style.color = 'var(--green)'; latestEl.textContent += ' ✓ up to date'; } } } } catch(e) {} try { const av = await api('GET', '/agent/version'); if (av && av.version) document.getElementById('about-agent-version').textContent = av.version; } catch(e) {} }
function openTagModal(id, currentTags) { document.getElementById('tag-device-id').value = id; document.getElementById('tag-input').value = currentTags; openModal('tag-modal'); }
async function saveTags() { const id = document.getElementById('tag-device-id').value; const raw = document.getElementById('tag-input').value; const tags = raw.split(',').map(t => t.trim()).filter(t => t.length > 0); const r = await fetch('/api/devices/' + id + '/tags', { method: 'PATCH', headers: {'Content-Type': 'application/json', 'X-Token': getToken()}, body: JSON.stringify({tags}) }); if (r.status === 401) { doLogout(); return; } const data = await r.json(); if (data?.ok) { toast(`Tags saved: ${tags.length ? tags.join(', ') : 'none'}`, 'success'); closeModal('tag-modal'); loadDevices(); } else toast(data?.error || 'Failed', 'error'); }
async function sendUpdate(id, name) { if (!confirm(`Push agent self-update to "${name}"?\nThe agent will update and restart within 60 seconds.`)) return; const data = await api('POST', '/update-device', {device_id: id}); if (data?.ok) toast(`Update queued for ${name}`, 'success'); else toast(data?.error || 'Failed', 'error'); }
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
  ['mem-warn','mem-crit','swap-warn','swap-crit','disk-warn','disk-crit','cpu-warn','cpu-crit']
    .forEach(k => document.getElementById('thr-' + k).value = '');
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
    <input type="text" class="form-input mount-path" placeholder="/var" value="${escHtml(path)}" style="font-family:monospace;font-size:12px">
    <input type="number" class="form-input mount-warn" placeholder="warn %" min="1" max="99" value="${warn === '' ? '' : warn}">
    <input type="number" class="form-input mount-crit" placeholder="crit %" min="1" max="99" value="${crit === '' ? '' : crit}">
    <button class="btn-icon" type="button" onclick="this.parentElement.remove()" style="color:var(--red);border-color:rgba(239,68,68,0.3);font-size:14px;padding:4px 8px">×</button>
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
      // Aggregate alert level: critical > warning > ok. We compute it
      // here so the row can sort by severity in addition to per-metric.
      let level = 'ok';
      for (const [, v] of Object.entries(state)) {
        if (v === 'critical') { level = 'critical'; break; }
        if (v === 'warning')  { level = 'warning'; }
      }
      return {
        name:   d.name || '',
        // sort: critical first when ascending
        status: level === 'critical' ? 'a-critical' : level === 'warning' ? 'b-warning' : 'c-ok',
        memory: si.mem_percent ?? -1,
        swap:   si.swap_percent ?? -1,
        // Sort CPU by ratio (load / cpus), not raw load — comparable across hosts
        cpu:    (si.loadavg_1m && si.cpu_count) ? si.loadavg_1m / si.cpu_count : -1,
        // Disks: highest mount usage of the device
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
      // Aggregate alert level
      let level = 'ok';
      for (const [, v] of Object.entries(state)) {
        if (v === 'critical') { level = 'critical'; break; }
        if (v === 'warning')  level = 'warning';
      }
      const levelBadge =
        level === 'critical' ? '<span class="patch-badge" style="background:rgba(239,68,68,0.18);color:var(--red);font-size:10px">CRIT</span>' :
        level === 'warning'  ? '<span class="patch-badge warn" style="font-size:10px">WARN</span>' :
        d.online ? '<span class="patch-badge ok" style="font-size:10px">OK</span>' : '<span style="color:var(--muted);font-size:11px">offline</span>';

      const fmtPct = (v, key) => {
        if (v === undefined || v === null) return '<span style="color:var(--muted)">—</span>';
        const lv = state[key] || 'ok';
        const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
        return `<span style="color:${color};font-family:monospace">${Number(v).toFixed(1)}%</span>`;
      };

      const memCell  = fmtPct(si.mem_percent,  'memory:');
      const swapCell = fmtPct(si.swap_percent, 'swap:');

      let cpuCell = '<span style="color:var(--muted)">—</span>';
      if (si.loadavg_1m !== undefined && si.cpu_count) {
        const ratio = si.loadavg_1m / si.cpu_count;
        const lv = state['cpu:'] || 'ok';
        const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
        cpuCell = `<span style="color:${color};font-family:monospace">${si.loadavg_1m.toFixed(2)} / ${si.cpu_count} (${ratio.toFixed(2)}×)</span>`;
      }

      // Disks: list each mount with its percent + alert state
      let diskCell = '<span style="color:var(--muted)">—</span>';
      const mounts = Array.isArray(si.mounts) ? si.mounts : [];
      if (mounts.length > 0) {
        const items = mounts.map(m => {
          const lv = state[`disk:${m.path}`] || 'ok';
          const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--muted)';
          return `<span style="color:${color};font-family:monospace;font-size:11px;margin-right:10px" title="${escHtml(m.path)} — ${m.used_gb}/${m.total_gb} GB">${escHtml(m.path.length > 14 ? '…' + m.path.slice(-13) : m.path)}: ${Number(m.percent).toFixed(0)}%</span>`;
        });
        diskCell = items.join('');
      } else if (si.disk_percent !== undefined) {
        // Pre-v1.11.10 agent: only legacy root disk
        const lv = state['disk:/'] || 'ok';
        const color = lv === 'critical' ? 'var(--red)' : lv === 'warning' ? 'var(--amber)' : 'var(--text)';
        diskCell = `<span style="color:${color};font-family:monospace">/ ${si.disk_percent.toFixed(1)}%</span>`;
      }

      return `<tr>
        <td style="font-weight:500"><a href="#" onclick="openDetail('${d.id}','${escAttr(d.name)}'); return false;" style="color:var(--text);text-decoration:none">${escHtml(d.name)}</a>${d.group ? ` <span class="group-badge" style="font-size:10px">${escHtml(d.group)}</span>` : ''}</td>
        <td>${levelBadge}</td>
        <td style="text-align:right">${memCell}</td>
        <td style="text-align:right">${swapCell}</td>
        <td style="text-align:right">${cpuCell}</td>
        <td>${diskCell}</td>
        <td style="white-space:nowrap"><button class="btn-icon" style="font-size:11px;padding:4px 8px;margin-right:4px" onclick="openMetrics('${d.id}','${escAttr(d.name)}')" title="Show metric trend over time">Trend</button><button class="btn-icon" style="font-size:11px;padding:4px 8px" onclick="openMetricThresholds('${d.id}','${escAttr(d.name)}')">Thresholds</button></td>
      </tr>`;
    },
    emptyMsg: 'No devices to show metrics for.',
    emptyMsgFiltered: 'No devices match the filter.',
  });
}

async function loadDeviceMetrics() {
  _registerDeviceMetricsTable();
  const data = await api('GET', '/devices');
  if (!data) return;
  // Update the global cache so other code paths see fresh sysinfo too
  if (typeof devices !== 'undefined') devices = data;

  // Summary line: count of devices in each alert level
  let warn = 0, crit = 0;
  for (const d of data) {
    const state = d.metric_state || {};
    let level = 'ok';
    for (const [, v] of Object.entries(state)) {
      if (v === 'critical') { level = 'critical'; break; }
      if (v === 'warning')  level = 'warning';
    }
    if (level === 'critical') crit++;
    else if (level === 'warning') warn++;
  }
  const summary = document.getElementById('device-metrics-summary');
  if (summary) {
    const parts = [];
    if (crit) parts.push(`<span style="color:var(--red);font-weight:600">${crit} critical</span>`);
    if (warn) parts.push(`<span style="color:var(--amber);font-weight:600">${warn} warning</span>`);
    if (!parts.length) parts.push(`<span style="color:var(--green)">all clear</span>`);
    summary.innerHTML = parts.join('  •  ');
  }
  tableCtl.render('device_metrics', data);
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
  // xterm.js + the fit addon. Versions pinned via SRI hash to detect
  // CDN tampering. Both files are tiny.
  return Promise.all([
    new Promise((resolve, reject) => {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css';
      link.crossOrigin = 'anonymous';
      link.onload = resolve;
      link.onerror = reject;
      document.head.appendChild(link);
    }),
    new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js';
      s.crossOrigin = 'anonymous';
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    }),
  ]).then(() => new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js';
    s.crossOrigin = 'anonymous';
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
    fontFamily: 'Menlo, Monaco, "Courier New", monospace',
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
async function openMetrics(id, name) { document.getElementById('metrics-title').textContent = `Metrics: ${name}`; document.getElementById('metrics-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>'; openModal('metrics-modal'); const data = await api('GET', '/devices/' + id + '/metrics'); if (!data || !data.metrics || !data.metrics.length) { document.getElementById('metrics-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">No metrics yet. Agent needs psutil installed for CPU/RAM/disk tracking.</div>'; return; } const metrics = data.metrics.slice(-60); function spark(key, color) { const vals = metrics.map(m => m[key]).filter(v => v !== null && v !== undefined); if (!vals.length) return '<span style="color:var(--muted);font-size:12px">no data</span>'; const w = 6; const h = 32; const bars = vals.map((v, i) => { const bh = Math.max(2, Math.round((v / 100) * h)); return `<rect x="${i*w}" y="${h-bh}" width="${w-1}" height="${bh}" fill="${color}" rx="1"/>`; }).join(''); const latest = vals[vals.length-1]; return `<svg width="${vals.length*w}" height="${h}" style="vertical-align:middle">${bars}</svg> <span style="font-weight:600;color:${color}">${latest.toFixed(1)}%</span>`; } document.getElementById('metrics-body').innerHTML = `<div class="sysinfo-row" style="margin-bottom:20px"><div class="sysinfo-pill"><div class="label">Points</div><div class="value">${metrics.length}</div></div><div class="sysinfo-pill"><div class="label">From</div><div class="value" style="font-size:11px">${new Date(metrics[0].ts*1000).toLocaleTimeString()}</div></div></div><div style="display:grid;gap:16px"><div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px"><div style="font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px">CPU</div>${spark('cpu','var(--accent)')}</div><div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px"><div style="font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px">Memory</div>${spark('mem','var(--green)')}</div><div style="background:var(--surface2);border:1px solid var(--border);border-radius:10px;padding:16px"><div style="font-size:12px;color:var(--muted);margin-bottom:8px;text-transform:uppercase;letter-spacing:.5px">Disk</div>${spark('disk','var(--amber)')}</div></div><p style="font-size:12px;color:var(--muted);margin-top:12px">Requires <code>psutil</code> on the client: <code>pip install psutil --break-system-packages</code></p>`; }
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
    row: (k) => `<tr><td style="font-weight:600">${escHtml(k.name)}</td><td><span class="patch-badge ${k.role==='admin'?'warn':'ok'}">${escHtml(k.role)}</span></td><td style="color:var(--muted);font-size:12px">${escHtml(k.user)}</td><td style="color:var(--muted);font-size:12px">${k.created ? new Date(k.created*1000).toLocaleDateString() : '—'}</td><td><button class="btn-icon" style="padding:4px 8px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteApiKey('${escAttr(k.id)}')">Delete</button></td></tr>`,
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
    row: (s) => `<tr><td style="font-weight:600">${escHtml(s.name)}</td><td style="font-family:monospace;font-size:12px;color:var(--accent)">${escHtml(s.cmd)}</td><td style="color:var(--muted);font-size:12px">${escHtml(s.description||'—')}</td><td style="display:flex;gap:6px"><button class="btn-icon" style="padding:4px 8px" onclick="useCmdSnippet('${escAttr(s.cmd)}')">Use</button><button class="btn-icon" style="padding:4px 8px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteCmdSnippet('${escAttr(s.id)}')">✕</button></tr>`,
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
function openCmdLibAdd() { document.getElementById('cmdlib-name').value = ''; document.getElementById('cmdlib-cmd').value = ''; document.getElementById('cmdlib-desc').value = ''; openModal('cmdlib-add-modal'); }
async function addCmdSnippet() { const name = document.getElementById('cmdlib-name').value.trim(); const cmd = document.getElementById('cmdlib-cmd').value.trim(); const desc = document.getElementById('cmdlib-desc').value.trim(); if (!name || !cmd) { toast('Name and command required', 'error'); return; } const data = await api('POST', '/cmd-library', {name, cmd, description: desc}); if (data?.ok) { toast('Snippet added', 'success'); closeModal('cmdlib-add-modal'); loadCmdLib(); } else toast(data?.error || 'Failed', 'error'); }
async function deleteCmdSnippet(id) { const data = await api('DELETE', '/cmd-library/' + id); if (data?.ok) { toast('Removed', 'info'); loadCmdLib(); } else toast(data?.error || 'Failed', 'error'); }
function useCmdSnippet(cmd) { document.getElementById('exec-cmd').value = cmd; closeModal('cmdlib-add-modal'); toast('Command pasted into exec modal', 'info'); }
function generateQRCode(containerId, text) { if (window.qrcode) { _renderQR(containerId, text); return; } const script = document.createElement('script'); script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js'; script.onload = () => _renderQR(containerId, text); script.onerror = () => { const el = document.getElementById(containerId); if (el) { const fallbackUrl = `https://api.qrserver.com/v1/create-qr-code/?size=160x160&data=${encodeURIComponent(text)}`; el.innerHTML = `<img src="${fallbackUrl}" width="160" height="160" style="display:block" onerror="this.parentElement.innerHTML='<div style=\\'padding:16px;color:#666;font-size:12px;text-align:center\\'>QR unavailable.<br>Enter secret manually.</div>'">`; } }; document.head.appendChild(script); }
function _renderQR(containerId, text) { const el = document.getElementById(containerId); if (!el || !window.qrcode) return; try { const qr = qrcode(0, 'M'); qr.addData(text); qr.make(); el.innerHTML = qr.createSvgTag(4, 0); const svg = el.querySelector('svg'); if (svg) { svg.style.display = 'block'; svg.style.width = '160px'; svg.style.height = '160px'; } } catch(e) { el.innerHTML = '<div style="padding:16px;color:#666;font-size:12px;text-align:center">QR generation failed.<br>Enter secret manually.</div>'; } }
async function loadTotpStatus() { const data = await api('GET', '/totp/status'); if (!data) return; const statusEl = document.getElementById('totp-status'); const setupEl = document.getElementById('totp-setup-area'); if (data.enabled) { statusEl.innerHTML = '<span style="color:var(--green);font-weight:600">✓ 2FA is enabled</span>'; setupEl.innerHTML = `<button class="btn-secondary" onclick="disableTotp()" style="color:var(--red);border-color:rgba(239,68,68,0.3)">Disable 2FA</button>`; } else { statusEl.innerHTML = '<span style="color:var(--muted)">2FA is not enabled</span>'; setupEl.innerHTML = `<button class="btn-primary" onclick="setupTotp()" style="max-width:200px">Enable 2FA</button>`; } }
async function setupTotp() { const data = await api('POST', '/totp/setup'); if (!data?.ok) { toast(data?.error || 'Failed', 'error'); return; } const setupEl = document.getElementById('totp-setup-area'); const qrContainerId = 'totp-qr-' + Date.now(); setupEl.innerHTML = `<div style="background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:16px"><div style="display:flex;gap:20px;align-items:flex-start;flex-wrap:wrap"><div id="${qrContainerId}" style="background:#fff;padding:8px;border-radius:8px;flex-shrink:0;min-width:168px;min-height:168px;display:flex;align-items:center;justify-content:center"><span style="color:#999;font-size:12px">Generating…</span></div><div style="flex:1;min-width:200px"><div style="font-size:13px;font-weight:600;margin-bottom:8px">Scan with your authenticator app</div><div style="font-size:12px;color:var(--muted);margin-bottom:12px">Google Authenticator, Authy, 1Password, Bitwarden, etc.</div><div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Or enter manually:</div><div style="font-family:monospace;font-size:14px;letter-spacing:2px;color:var(--accent);word-break:break-all;background:var(--surface2);padding:10px;border-radius:6px;cursor:pointer" onclick="navigator.clipboard?.writeText('${data.secret}');toast('Secret copied','success')" title="Click to copy">${data.secret}</div></div></div></div><div class="form-group"><label class="form-label">Verify — enter a code from your app</label><input type="text" id="totp-confirm-code" class="form-input" placeholder="123456" maxlength="6" inputmode="numeric" style="max-width:200px;text-align:center;font-size:18px;letter-spacing:4px"></div><button class="btn-primary" onclick="confirmTotp()" style="max-width:200px">Confirm & Enable</button>`; generateQRCode(qrContainerId, data.uri); }
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
      const recentCmds = (d.recent_patch_commands || []).slice(-2).map(c => `<div style="font-size:11px;font-family:monospace;color:var(--muted);margin-top:2px" title="${escHtml(c.output||'')}">${escHtml(c.cmd?.substring(0,30)||'')} (rc=${c.rc})</div>`).join('');
      // v2.1.5: ✨ Prioritise only on devices with pending updates
      const aiBtn = d.upgradable > 0
        ? `<button class="btn-icon" style="padding:4px 6px;font-size:11px" onclick="aiPrioritisePatchesForDevice('${d.device_id}','${escAttr(d.name)}')" title="AI: prioritise these updates">✨</button>`
        : '';
      return `<tr><td style="font-weight:500">${escHtml(d.name)}</td><td style="font-size:12px;color:var(--muted)">${escHtml(d.group||'—')}</td><td style="font-size:12px">${escHtml(d.os?.substring(0,25)||'—')}</td><td><span class="mon-status ${d.online?'up':'down'}">${d.online?'Online':'Offline'}</span></td><td style="font-family:monospace;font-size:12px">${escHtml(d.pkg_manager)}</td><td style="font-weight:600;color:${d.upgradable>0?'var(--amber)':d.upgradable===0?'var(--green)':'var(--muted)'}">${d.upgradable !== null && d.upgradable !== undefined ? d.upgradable : '—'}</td><td><span class="patch-badge ${statusCls}">${statusLabel}</span></td><td>${recentCmds || '<span style="color:var(--muted);font-size:11px">—</span>'}</td><td><div style="display:flex;gap:4px;align-items:center">${aiBtn}<button class="btn-icon" style="padding:4px 8px;font-size:11px" onclick="openDevicePatchReport('${d.device_id}','${escAttr(d.name)}')">Detail</button></div></td></tr>`;
    },
    emptyMsg: 'No devices match the current filter.',
    emptyMsgFiltered: 'No devices match the current filter.',
  });
}

async function loadPatchReport() { _registerPatchTable(); const tbody = document.getElementById('patch-tbody'); tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:24px">Loading…</tbody>'; const data = await api('GET', '/patch-report'); if (!data) return; patchReportData = data; const groups = [...new Set(data.devices.map(d => d.group).filter(g => g))].sort(); const gSel = document.getElementById('patch-group-filter'); const cur = gSel.value; gSel.innerHTML = '<option value="all">All groups</option>' + groups.map(g => `<option value="${escHtml(g)}">${escHtml(g)}</option>`).join(''); gSel.value = cur; const dSel = document.getElementById('patch-device-filter'); const curD = dSel.value; dSel.innerHTML = '<option value="all">All devices</option>' + data.devices.map(d => `<option value="${escHtml(d.device_id)}">${escHtml(d.name)}</option>`).join(''); dSel.value = curD; renderPatchTable(); }
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
async function openDevicePatchReport(devId, devName) { document.getElementById('device-patch-title').textContent = `Patch Report: ${devName}`; document.getElementById('device-patch-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>'; openModal('device-patch-modal'); const data = await api('GET', `/patch-report/device/${devId}`); if (!data) return; const statusColor = data.patch_status === 'fully_patched' ? 'var(--green)' : data.patch_status === 'patches_available' ? 'var(--amber)' : 'var(--muted)'; const statusLabel = data.patch_status === 'fully_patched' ? 'Fully Patched' : data.patch_status === 'patches_available' ? `${data.upgradable} patches pending` : 'No data'; let html = `<div class="sysinfo-row" style="margin-bottom:16px"><div class="sysinfo-pill"><div class="label">Status</div><div class="value" style="color:${statusColor}">${statusLabel}</div></div><div class="sysinfo-pill"><div class="label">OS</div><div class="value" style="font-size:11px">${escHtml(data.os||'—')}</div></div><div class="sysinfo-pill"><div class="label">Pkg Manager</div><div class="value">${escHtml(data.pkg_manager)}</div></div><div class="sysinfo-pill"><div class="label">Agent</div><div class="value">${escHtml(data.version||'—')}</div></div><div class="sysinfo-pill"><div class="label">Online</div><div class="value" style="color:${data.online?'var(--green)':'var(--red)'}">${data.online?'Yes':'No'}</div></div></div>`; if (data.uptime) html += `<div style="font-size:12px;color:var(--muted);margin-bottom:12px">Uptime: ${escHtml(data.uptime)}</div>`; if (data.group) html += `<div style="font-size:12px;color:var(--muted);margin-bottom:12px">Group: <span class="group-badge">${escHtml(data.group)}</span></div>`; html += '<div style="font-size:13px;font-weight:600;margin:16px 0 8px;color:var(--muted)">Patch Command History</div>'; if (data.patch_history && data.patch_history.length) { html += data.patch_history.slice().reverse().map(o => `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:8px"><div style="display:flex;justify-content:space-between;margin-bottom:6px"><code style="font-size:12px;color:var(--accent)">${escHtml(o.cmd)}</code><span style="font-size:11px;color:var(--muted)">${new Date(o.ts*1000).toLocaleString()} · rc=${o.rc}</span></div><div class="journal-wrap" style="max-height:120px">${escHtml(o.output||'(no output)')}</div></div>`).join(''); } else html += '<div style="color:var(--muted);font-size:13px;padding:12px">No patch commands recorded yet.</div>'; document.getElementById('device-patch-body').innerHTML = html; }

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
        'scanned':     '<span style="color:var(--green)">●</span>',
        'not_scanned': '<span style="color:var(--muted)">●</span> not scanned',
        'no_packages': '<span style="color:var(--muted)">●</span> no package list',
        'unsupported': '<span style="color:var(--amber)">●</span> unsupported',
      }[d.status] || d.status;
      const scanText = d.scanned_at ? new Date(d.scanned_at * 1000).toLocaleString() : statusBadge;
      const cell = (n, color) => n > 0 ? `<td style="text-align:center;color:${color};font-weight:600">${n}</td>` : '<td style="text-align:center;color:var(--muted)">0</td>';
      return `<tr style="cursor:pointer" onclick="openDeviceCVE('${escAttr(d.device_id)}','${escAttr(d.name)}')"><td style="font-weight:500">${escHtml(d.name)}</td><td style="font-size:12px;color:var(--muted)">${d.group ? `<span class="group-badge">${escHtml(d.group)}</span>` : '—'}</td><td style="font-size:12px;color:var(--muted);font-family:monospace">${escHtml(d.ecosystem)}</td>${cell(d.counts.critical, 'var(--red)')}${cell(d.counts.high, '#f97316')}${cell(d.counts.medium, 'var(--amber)')}${cell(d.counts.low, 'var(--muted)')}<td style="font-size:11px;color:var(--muted)">${scanText}</td><td><button class="btn-icon" style="padding:4px 8px;font-size:11px" onclick="event.stopPropagation();triggerCVEScan('${escAttr(d.device_id)}')">Scan</button></td></tr>`;
    },
    emptyMsg: 'No devices enrolled.',
    emptyMsgFiltered: 'No CVE rows match the filter.',
  });
}

async function loadCVEReport() {
  _registerCveTable();
  const tbody = document.getElementById('cve-tbody');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:24px">Loading…</td></tr>';
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
async function triggerCVEScan(devId) {
  const label = devId ? 'device' : 'all devices';
  toast(`Scanning ${label}… may take a minute`, 'info');
  const body = devId ? {device_id: devId} : {};
  const result = await api('POST', '/cve/scan', body);
  if (!result) return;
  const s = result.scanned?.length || 0, k = result.skipped?.length || 0, e = result.errors?.length || 0;
  toast(`Scan complete: ${s} scanned, ${k} skipped, ${e} errors`, e > 0 ? 'error' : 'success');
  loadCVEReport();
}
async function openDeviceCVE(devId, devName) {
  document.getElementById('cve-detail-title').textContent = `CVE Findings: ${devName}`;
  document.getElementById('cve-detail-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>';
  openModal('cve-detail-modal');
  const data = await api('GET', `/devices/${devId}/cve`);
  if (!data) return;
  const sevColor = {critical: 'var(--red)', high: '#f97316', medium: 'var(--amber)', low: 'var(--muted)', unknown: 'var(--muted)'};
  let html = `<div class="sysinfo-row" style="margin-bottom:16px"><div class="sysinfo-pill"><div class="label">Ecosystem</div><div class="value" style="font-size:12px">${escHtml(data.ecosystem)}</div></div><div class="sysinfo-pill"><div class="label">Packages</div><div class="value">${data.packages_count}</div></div><div class="sysinfo-pill"><div class="label">Last scan</div><div class="value" style="font-size:11px">${data.scanned_at ? new Date(data.scanned_at*1000).toLocaleString() : 'never'}</div></div><div class="sysinfo-pill"><div class="label">Findings</div><div class="value">${data.findings.length}</div></div></div>`;
  if (data.error) html += `<div style="background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);padding:12px;border-radius:8px;margin-bottom:16px;font-size:13px;color:var(--red)">${escHtml(data.error)}</div>`;
  if (!data.findings.length) { html += '<div style="color:var(--muted);text-align:center;padding:40px">No vulnerabilities found. 🎉</div>'; }
  else {
    html += data.findings.map(f => {
      const color = sevColor[f.severity] || 'var(--muted)';
      const refsHtml = (f.refs||[]).slice(0,2).map(r => { try { return `<a href="${escHtml(r)}" target="_blank" style="color:var(--accent)">${escHtml(new URL(r).hostname)}</a>`; } catch(e) { return ''; } }).filter(Boolean).join('');
      const aliasesHtml = (f.aliases||[]).map(a => `<code style="background:var(--surface2);padding:2px 6px;border-radius:4px">${escHtml(a)}</code>`).join('');
      return `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:8px;${f.ignored?'opacity:0.5':''}"><div style="display:flex;justify-content:space-between;gap:12px;margin-bottom:8px"><div><span style="background:${color};color:white;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;text-transform:uppercase">${f.severity}</span><code style="margin-left:8px;font-size:13px;color:var(--accent)">${escHtml(f.vuln_id)}</code>${f.ignored ? '<span style="margin-left:8px;font-size:11px;color:var(--muted)">(ignored: '+escHtml(f.ignore_reason||'')+')</span>' : ''}</div><div style="font-size:11px;color:var(--muted);white-space:nowrap">${escHtml(f.published || '')}</div></div><div style="font-size:13px;margin-bottom:6px"><strong>${escHtml(f.package)}</strong> <span style="color:var(--muted)">${escHtml(f.version)}</span>${f.fixed_version ? ` → fixed in <span style="color:var(--green)">${escHtml(f.fixed_version)}</span>` : ''}</div>${f.summary ? `<div style="font-size:12px;color:var(--muted);margin-bottom:6px">${escHtml(f.summary)}</div>` : ''}<div style="display:flex;gap:8px;font-size:11px;flex-wrap:wrap;align-items:center">${aliasesHtml}${refsHtml}<button class="btn-icon" style="padding:2px 6px;font-size:11px;margin-left:auto" onclick="aiTriageCve('${escAttr(f.vuln_id)}','${escAttr(f.package)}','${escAttr(f.version)}','${escAttr(devName)}','${escAttr(f.summary||'')}')">✨ Triage</button>${!f.ignored ? `<button class="btn-icon" style="padding:2px 6px;font-size:11px" onclick="ignoreCVE('${escAttr(f.vuln_id)}','${escAttr(devId)}','${escAttr(devName)}')">Ignore</button>` : ''}</div></div>`;
    }).join('');
  }
  document.getElementById('cve-detail-body').innerHTML = html;
}
async function ignoreCVE(vulnId, devId, devName) {
  const reason = prompt(`Ignore ${vulnId}? Enter a reason (accepted risk, false positive, etc.):`);
  if (reason === null) return;
  const scope = confirm('Ignore globally across ALL devices?\n\nOK = global\nCancel = this device only') ? 'global' : devId;
  const result = await api('POST', '/cve/ignore', {vuln_id: vulnId, reason, scope});
  if (result && result.ok) {
    toast(`${vulnId} ignored (${scope})`, 'success');
    openDeviceCVE(devId, devName);
    loadCVEReport();
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
      const reportText = d.updated_at ? new Date(d.updated_at*1000).toLocaleString() : '<span style="color:var(--muted);font-size:11px">never</span>';
      const unitList = (d.services || []).map(s => {
        const color = s.active === 'active' ? 'var(--green)' : s.active === 'activating' ? 'var(--amber)' : 'var(--red)';
        return `<span style="display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:12px;padding:2px 8px;font-size:11px;margin:1px;font-family:monospace"><span style="color:${color}">●</span> ${escHtml(s.unit)}</span>`;
      }).join('');
      const watchedCell = d.total > 0 ? unitList : '<span style="color:var(--muted);font-size:11px">(none configured)</span>';
      const upCell   = d.up > 0 ? `<td style="text-align:center;color:var(--green);font-weight:600">${d.up}</td>` : '<td style="text-align:center;color:var(--muted)">0</td>';
      const downCell = d.down > 0 ? `<td style="text-align:center;color:var(--red);font-weight:600">${d.down}</td>` : '<td style="text-align:center;color:var(--muted)">0</td>';
      return `<tr style="cursor:pointer" onclick="openServiceDetail('${escAttr(d.device_id)}','${escAttr(d.name)}')">
        <td style="font-weight:500">${escHtml(d.name)}</td>
        <td style="font-size:12px;color:var(--muted)">${d.group ? `<span class="group-badge">${escHtml(d.group)}</span>` : '—'}</td>
        <td>${watchedCell}</td>
        ${upCell}${downCell}
        <td style="font-size:11px;color:var(--muted)">${reportText}</td>
        <td><button class="btn-icon" style="padding:4px 8px;font-size:11px" onclick="event.stopPropagation();editServicesConfig('${escAttr(d.device_id)}','${escAttr(d.name)}')">Configure</button></td>
      </tr>`;
    },
    emptyMsg: 'No devices enrolled.',
    emptyMsgFiltered: 'No services match the filter.',
  });
}

async function loadServicesReport() {
  _registerServicesTable();
  const tbody = document.getElementById('services-tbody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">Loading…</td></tr>';
  const data = await api('GET', '/services');
  if (!data) return;
  // Also fetch maintenance badge
  const maint = await api('GET', '/maintenance');
  const active = (maint?.windows || []).filter(w => w.active).length;
  if (active > 0) {
    document.getElementById('services-maint-badge').style.display = '';
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
  document.getElementById('service-detail-body').innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>';
  document.getElementById('service-edit-btn').onclick = () => { closeModal('service-detail-modal'); editServicesConfig(devId, devName); };
  openModal('service-detail-modal');
  const data = await api('GET', `/devices/${devId}/services`);
  if (!data) return;
  const updated = data.updated_at ? new Date(data.updated_at*1000).toLocaleString() : 'never';
  let html = `<div class="sysinfo-row" style="margin-bottom:16px"><div class="sysinfo-pill"><div class="label">Units watched</div><div class="value">${data.services.length}</div></div><div class="sysinfo-pill"><div class="label">Last report</div><div class="value" style="font-size:11px">${updated}</div></div></div>`;
  if (!data.services.length) {
    html += '<div style="color:var(--muted);text-align:center;padding:40px">No services configured. Click "Edit watched units" below.</div>';
  } else {
    html += data.services.map(s => {
      const color = s.active === 'active' ? 'var(--green)' : s.active === 'activating' ? 'var(--amber)' : 'var(--red)';
      const sinceText = s.since ? new Date(s.since*1000).toLocaleString() : '—';
      const histItems = (s.history || []).slice().reverse();
      const logItems  = (s.log_tail || []).slice(-20);

      const histBody = histItems.length
        ? histItems.map(h => `<div style="font-size:11px;color:var(--muted);font-family:monospace">${new Date(h.ts*1000).toLocaleString()}: ${escHtml(h.from||'?')} → ${escHtml(h.to||'?')}</div>`).join('')
        : '<div style="font-size:11px;color:var(--muted);font-style:italic;padding:4px 0">No transitions recorded since enrollment.</div>';

      const logBody = logItems.length
        ? logItems.map(l => `<div class="journal-line">${escHtml(l.line || '')}</div>`).join('')
        : '<div style="font-size:11px;color:var(--muted);font-style:italic;padding:4px 0">No logs captured yet. Agent submits every ~5 min; needs v1.8.0+ and journalctl access (run as root).</div>';

      const histLabel = `State history (${histItems.length})`;
      const logLabel  = `Recent logs (${logItems.length})`;

      // v2.1.5: ✨ Diagnose for units that aren't actively running.
      // Pure-prose summary "service is failed, here's what to check
      // next" — the operator still does the actual work.
      const isUnhealthy = s.active !== 'active' && s.active !== 'activating';
      const aiBtn = isUnhealthy
        ? `<button class="btn-icon" style="font-size:11px;padding:2px 8px;margin-left:8px" onclick='aiDiagnoseService(${JSON.stringify(s.unit)}, ${JSON.stringify(devName)}, ${JSON.stringify(s.active||"")}, ${JSON.stringify(s.sub||"")}, ${JSON.stringify((s.log_tail || []).slice(-30).map(l => l.line || ""))})' title="AI: diagnose this service">✨ Diagnose</button>`
        : '';

      return `<div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px;margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:8px">
          <div style="display:flex;align-items:center;flex-wrap:wrap"><span style="color:${color};font-weight:600">●</span> <code style="font-size:13px;color:var(--accent);margin-left:6px">${escHtml(s.unit)}</code> <span style="margin-left:8px;font-size:12px;color:var(--muted)">${escHtml(s.active)}${s.sub?' / '+escHtml(s.sub):''}</span>${aiBtn}</div>
          <div style="font-size:11px;color:var(--muted)">since: ${sinceText}</div>
        </div>
        <details style="margin-bottom:6px"${histItems.length ? ' open' : ''}><summary style="font-size:12px;color:var(--muted);cursor:pointer">${histLabel}</summary><div style="padding-top:6px">${histBody}</div></details>
        <details${logItems.length ? ' open' : ''}><summary style="font-size:12px;color:var(--muted);cursor:pointer">${logLabel}</summary><div class="journal-wrap" style="max-height:200px;margin-top:6px">${logBody}</div></details>
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
      target: w.target || '',
      // 'when' as a sortable thing is messy — for cron we sort by the
      // cron string; for fixed windows we sort by start. Good enough.
      when:   w.cron || w.start || '',
      events: (w.events || []).join(','),
      // active first when ascending → sort 'active' before 'scheduled'
      // alphabetically. Fine.
      status: w.active ? 'active' : 'scheduled',
    }),
    row: (w) => {
      const when = w.cron ? `<code style="font-size:11px">${escHtml(w.cron)}</code> for ${Math.round((w.duration||0)/60)}min`
                          : `${escHtml(w.start||'?')} → ${escHtml(w.end||'?')}`;
      const events = (w.events && w.events.length) ? w.events.join(', ') : '<em style="color:var(--muted)">all</em>';
      const status = w.active
        ? '<span style="color:var(--amber);font-weight:600">🔧 ACTIVE</span>'
        : '<span style="color:var(--muted)">scheduled</span>';
      const target = w.scope === 'global' ? '—' : escHtml(w.target || '—');
      return `<tr>
        <td style="font-weight:500">${escHtml(w.reason || '(no reason)')}</td>
        <td><span class="group-badge">${escHtml(w.scope)}</span></td>
        <td style="font-size:12px;font-family:monospace;color:var(--muted)">${target}</td>
        <td style="font-size:12px">${when}</td>
        <td style="font-size:11px;color:var(--muted)">${events}</td>
        <td style="text-align:center">${status}</td>
        <td><button class="btn-icon" style="padding:4px 8px;font-size:11px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteMaintenance('${escAttr(w.id)}')">Delete</button></td>
      </tr>`;
    },
    emptyMsg: 'No maintenance windows defined.',
    emptyMsgFiltered: 'No windows match the filter.',
  });
}

async function loadMaintenance() {
  _registerMaintTable();
  const tbody = document.getElementById('maint-tbody');
  tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:24px">Loading…</td></tr>';
  const data = await api('GET', '/maintenance');
  if (!data) return;
  tableCtl.render('maintenance', data.windows || []);
}

async function loadMaintSuppressions() {
  const section = document.getElementById('maint-suppressions');
  section.style.display = '';
  const tbody = document.getElementById('maint-supp-tbody');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">Loading…</td></tr>';
  const data = await api('GET', '/maintenance/suppressions');
  if (!data) return;
  if (!data.entries.length) { tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">No suppressions recorded.</td></tr>'; return; }
  tbody.innerHTML = data.entries.map(e => `<tr>
    <td style="font-size:12px;color:var(--muted);white-space:nowrap">${new Date(e.ts*1000).toLocaleString()}</td>
    <td><code style="font-size:12px">${escHtml(e.event)}</code></td>
    <td style="font-family:monospace;font-size:11px">${escHtml(e.device_id || '—')}</td>
    <td style="font-family:monospace;font-size:11px;color:var(--muted)">${escHtml(e.window_id || '—')}</td>
    <td style="font-size:12px">${escHtml(e.reason || '')}</td>
  </tr>`).join('');
}

async function deleteMaintenance(winId) {
  if (!confirm('Delete this maintenance window?')) return;
  const result = await api('DELETE', `/maintenance/${winId}`);
  if (result && result.ok) { toast('Window deleted', 'success'); loadMaintenance(); }
}

async function openNewMaintModal() {
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

function onMaintScopeChange() {
  const scope = document.getElementById('maint-scope').value;
  const row = document.getElementById('maint-target-row');
  const selDev = document.getElementById('maint-target-device');
  const txtGrp = document.getElementById('maint-target-group');
  if (scope === 'global') { row.style.display = 'none'; return; }
  row.style.display = '';
  if (scope === 'device') { selDev.style.display = ''; txtGrp.style.display = 'none'; }
  else                    { selDev.style.display = 'none'; txtGrp.style.display = ''; }
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
  const result = await api('POST', '/maintenance', body);
  if (result && result.ok) {
    toast('Maintenance window created', 'success');
    closeModal('new-maint-modal');
    loadMaintenance();
  } else {
    toast(result?.error || 'Failed to create window', 'error');
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
  document.getElementById('logs-viewer').innerHTML = '<div style="text-align:center;color:var(--muted);padding:20px">Fetching recent lines…</div>';
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
      msg = '<div style="text-align:center;color:var(--muted);padding:40px">'
          + 'No devices are submitting logs yet.<br>'
          + '<span style="font-size:11px">1) Configure watched services on the <a href="#" onclick="showPage(\'services\',document.querySelector(\'.nav-btn[onclick*=services]\')); return false" style="color:var(--accent)">Services page</a>. '
          + '2) Agents submit every ~5 min. 3) Agent must be v1.8.0+ and have journalctl access.</span></div>';
    } else if (data.stats.total_lines === 0) {
      msg = `<div style="text-align:center;color:var(--muted);padding:40px">`
          + `${data.stats.devices_reporting} device(s) are reporting, but watched units have been quiet.<br>`
          + `<span style="font-size:11px">This is normal for stable services. Logs appear here when agents capture something.</span></div>`;
    } else {
      msg = `<div style="text-align:center;color:var(--muted);padding:40px">`
          + `${data.stats.total_lines} line(s) in the buffer, but none match the current filter.<br>`
          + `<span style="font-size:11px">Try clearing the device/unit filters above.</span></div>`;
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
    return `<div style="font-family:monospace;font-size:12px;line-height:1.5;padding:1px 4px;${color?'color:'+color+';':''}">`
      + `<span style="color:var(--muted)">${ts}</span> `
      + `<span style="color:var(--accent)">${escHtml(l.name)}</span> `
      + `<span style="color:var(--muted)">${escHtml(l.unit)}</span>  `
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
  document.getElementById('logs-viewer').innerHTML = '<div style="text-align:center;color:var(--muted);padding:20px">Searching…</div>';
  const data = await api('GET', `/logs/search?${qs.toString()}`);
  if (!data) return;
  if (!data.results.length) {
    document.getElementById('logs-viewer').innerHTML = `<div style="text-align:center;color:var(--muted);padding:40px">No matches for <code>${escHtml(q)}</code> in the current buffer.</div>`;
    return;
  }
  // Group by device (per user preference from planning)
  const byDev = {};
  for (const r of data.results) {
    if (!byDev[r.device_id]) byDev[r.device_id] = {name: r.name, lines: []};
    byDev[r.device_id].lines.push(r);
  }
  let html = `<div style="font-size:12px;color:var(--muted);margin-bottom:8px">${data.count} match${data.count===1?'':'es'} across ${Object.keys(byDev).length} device${Object.keys(byDev).length===1?'':'s'}</div>`;
  for (const [dev_id, g] of Object.entries(byDev)) {
    html += `<details open style="margin-bottom:8px"><summary style="font-size:13px;color:var(--accent);cursor:pointer;padding:4px 0">${escHtml(g.name)} <span style="color:var(--muted);font-size:11px">(${g.lines.length})</span></summary>`;
    html += g.lines.map(l => {
      const color = lineSeverityColor(l.line);
      return `<div style="font-family:monospace;font-size:12px;padding:1px 4px 1px 20px;${color?'color:'+color+';':''}"><span style="color:var(--muted)">${new Date(l.ts*1000).toLocaleString()}</span> <span style="color:var(--muted)">${escHtml(l.unit)}</span>  ${escHtml(l.line)}</div>`;
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
  document.getElementById('logs-rules-device-wrap').style.display = (tab === 'device') ? '' : 'none';
  document.getElementById('logs-rules-global-wrap').style.display = (tab === 'global') ? '' : 'none';
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
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">No per-device rules configured.</td></tr>';
    return;
  }
  tbody.innerHTML = data.rules.map(r => `<tr>
    <td style="font-weight:500">${escHtml(r.device_name)}</td>
    <td>${r.group ? `<span class="group-badge">${escHtml(r.group)}</span>` : '<span style="color:var(--muted)">—</span>'}</td>
    <td><code style="font-size:12px">${escHtml(r.unit)}</code></td>
    <td><code style="font-size:12px;background:var(--surface2);padding:2px 6px;border-radius:4px">${escHtml(r.pattern)}</code></td>
    <td style="text-align:center">≥ ${r.threshold}</td>
    <td><button class="btn-icon" style="padding:4px 8px;font-size:11px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteLogRule('${escAttr(r.device_id)}','${escAttr(r.unit)}','${escAttr(r.pattern)}')">Delete</button></td>
  </tr>`).join('');
}

async function loadGlobalLogRules() {
  const tbody = document.getElementById('logs-rules-global-tbody');
  const data = await api('GET', '/logs/rules/global');
  if (!data) return;
  const deviceCount = parseInt(document.getElementById('logs-stat-rules').dataset.deviceCount || '0');
  document.getElementById('logs-stat-rules').textContent = deviceCount + data.rules.length;
  document.getElementById('logs-stat-rules').dataset.globalCount = data.rules.length;
  if (!data.rules.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">No fleet-wide rules configured. Click "+ Add rule" above and switch to the Fleet-wide tab.</td></tr>';
    return;
  }
  tbody.innerHTML = data.rules.map(r => {
    const created = r.created_at ? new Date(r.created_at*1000).toLocaleDateString() : '—';
    const unitDisplay = r.unit === '*'
      ? '<code style="font-size:12px;color:var(--amber)">* (any unit)</code>'
      : `<code style="font-size:12px">${escHtml(r.unit)}</code>`;
    return `<tr>
      <td>${unitDisplay}</td>
      <td><code style="font-size:12px;background:var(--surface2);padding:2px 6px;border-radius:4px">${escHtml(r.pattern)}</code></td>
      <td style="text-align:center">≥ ${r.threshold}</td>
      <td style="font-size:11px;color:var(--muted)">${created} <span style="opacity:0.6">by ${escHtml(r.created_by || '?')}</span></td>
      <td><button class="btn-icon" style="padding:4px 8px;font-size:11px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteGlobalLogRule('${escAttr(r.id)}')">Delete</button></td>
    </tr>`;
  }).join('');
}

async function openAddRuleModal() {
  // Modal content depends on which tab is active
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
  openModal('log-rule-modal');
}

async function saveLogRule() {
  const unit    = document.getElementById('log-rule-unit').value.trim();
  const pattern = document.getElementById('log-rule-pattern').value.trim();
  const threshold = parseInt(document.getElementById('log-rule-threshold').value) || 1;
  if (!unit || !pattern) { toast('Unit and pattern are required', 'error'); return; }
  // Validate regex client-side
  try { new RegExp(pattern); } catch(e) { toast('Invalid regex: '+e.message, 'error'); return; }

  if (logsRulesTab === 'global') {
    // Fleet-wide rule
    const result = await api('POST', '/logs/rules/global', {unit, pattern, threshold});
    if (result && result.ok) {
      toast('Fleet-wide rule added', 'success');
      closeModal('log-rule-modal');
      loadGlobalLogRules();
    } else {
      toast(result?.error || 'Failed to save rule', 'error');
    }
    return;
  }

  // Per-device rule (unchanged from 1.8.1)
  const devId = document.getElementById('log-rule-device').value;
  if (!devId) { toast('Device is required', 'error'); return; }
  const existing = await api('GET', `/devices/${devId}/services/config`);
  if (!existing) return;
  const log_watch = existing.log_watch || [];
  if (log_watch.some(r => r.unit === unit && r.pattern === pattern)) {
    toast('Rule already exists', 'error');
    return;
  }
  log_watch.push({unit, pattern, threshold});
  // Also ensure the unit is in services_watched so the agent submits its logs
  const watched = existing.services_watched || [];
  if (unit !== '*' && !watched.includes(unit)) watched.push(unit);
  const result = await api('POST', `/devices/${devId}/services/config`, {
    services_watched: watched,
    log_watch,
  });
  if (result && result.ok) {
    toast('Rule added', 'success');
    closeModal('log-rule-modal');
    loadPerDeviceLogRules();
  } else {
    toast(result?.error || 'Failed to save rule', 'error');
  }
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
    row: (e) => `<tr><td style="color:var(--muted);font-size:12px;white-space:nowrap">${new Date(e.ts*1000).toLocaleString()}</td><td style="font-weight:500">${escHtml(e.actor)}</td><td><span class="cmd-badge ${e.action.includes('fail')?'shutdown':e.action.includes('login')?'update':'reboot'}">${escHtml(e.action)}</span></td><td style="font-size:12px;color:var(--muted);max-width:300px;overflow:hidden;text-overflow:ellipsis">${escHtml(e.detail||'—')}</td><td style="font-family:monospace;font-size:11px;color:var(--muted)">${escHtml(e.source_ip||'—')}</td></tr>`,
    emptyMsg: 'No audit entries yet.',
    emptyMsgFiltered: 'No entries match the current filter.',
  });
}

async function loadAuditLog() {
  _registerAuditTable();
  const tbody = document.getElementById('audit-tbody');
  tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">Loading…</tbody>';
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
      `<div class="cal-event color-${escHtml(ev.color || 'blue')}" onclick="event.stopPropagation();openEventModal('${escAttr(ev.id)}')" title="${escHtml(ev.title)}">${escHtml(ev.title)}</div>`
    ).join('');
    const more = events.length > 3 ? `<div style="font-size:10px;color:var(--muted);padding:0 4px">+${events.length - 3} more</div>` : '';
    const dayDate = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,'0')}-${String(d.getDate()).padStart(2,'0')}`;
    html += `<div class="cal-day${isOtherMonth ? ' other-month' : ''}${isToday ? ' today' : ''}" onclick="openEventModalForDay('${dayDate}')">
      <div class="cal-day-num">${d.getDate()}</div>
      ${eventsHtml}${more}
    </div>`;
  }
  grid.innerHTML = html;
}

function openEventModal(eventId) {
  calEditingId = eventId || null;
  document.getElementById('event-modal-title').textContent = eventId ? 'Edit event' : 'New event';
  document.getElementById('event-delete-btn').style.display = eventId ? '' : 'none';
  // Wire the color swatches (idempotent)
  document.querySelectorAll('#event-color-picker .ev-color').forEach(el => {
    el.onclick = () => {
      calSelectedColor = el.dataset.color;
      document.querySelectorAll('#event-color-picker .ev-color').forEach(x => x.style.borderColor = 'transparent');
      el.style.borderColor = 'var(--text)';
    };
  });

  let title = '', desc = '', color = 'blue', allDay = false;
  let startVal = '', endVal = '';
  if (eventId) {
    const ev = calCurrentEvents.find(e => e.id === eventId);
    if (!ev) { toast('Event not found', 'error'); return; }
    title = ev.title; desc = ev.description || ''; color = ev.color || 'blue';
    allDay = !!ev.all_day;
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
  if (!confirm('Delete this event?')) return;
  const result = await api('DELETE', `/calendar/${calEditingId}`);
  if (result && result.ok) {
    toast('Event deleted', 'success');
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
      col.innerHTML = `<div style="font-size:11px;color:var(--muted);padding:12px 4px;text-align:center;font-style:italic">No tasks</div>`;
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
              ondragstart="onTaskDragStart(event,'${escHtml(t.id)}')"
              ondragend="onTaskDragEnd(event)"
              onclick="openTaskModal('${escAttr(t.id)}')">
    <div class="kanban-card-title">${escHtml(t.title)}</div>
    <div class="kanban-card-meta">
      ${devBadge}
      <span style="opacity:0.7">${meta.join(' · ')}</span>
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
  document.getElementById('task-delete-btn').style.display = taskId ? '' : 'none';

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
    meta.style.display = '';
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
  } catch (e) { /* ignore */ }
}

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
    iconEl.textContent  = '⚙';
    stateEl.textContent = 'Vault not yet configured. Set a passphrase to start storing credentials.';
    actionEl.style.display = 'inline-block';
    actionEl.textContent = 'Set up vault';
    actionEl.onclick = cmdbOpenSetupModal;
    rotateEl.style.display = 'none';
    lockEl.style.display = 'none';
    return;
  }
  if (_cmdbVaultKey) {
    iconEl.textContent  = '🔓';
    stateEl.textContent = 'Vault unlocked. Credential operations enabled in this tab only.';
    actionEl.style.display = 'none';
    rotateEl.style.display = 'inline-block';
    lockEl.style.display = 'inline-block';
  } else {
    iconEl.textContent  = '🔒';
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
  if (!rows || rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:40px">No matching assets.</td></tr>';
    return;
  }
  tbody.innerHTML = rows.map(r => {
    const hyp = r.hypervisor_url
      ? `<a href="${_cmdbEsc(r.hypervisor_url)}" target="_blank" rel="noopener" style="color:var(--accent);font-size:12px">open ↗</a>`
      : '<span style="color:var(--muted);font-size:12px">—</span>';
    const fn = r.server_function
      ? `<span class="tag-pill">${_cmdbEsc(r.server_function)}</span>`
      : '<span style="color:var(--muted);font-size:12px">—</span>';
    return `<tr>
      <td style="font-weight:500">${osIcon(r.os, 14)} ${_cmdbEsc(r.name)}</td>
      <td style="font-family:monospace;font-size:12px">${_cmdbEsc(r.asset_id) || '<span style="color:var(--muted)">—</span>'}</td>
      <td>${fn}</td>
      <td style="font-size:12px;color:var(--muted)">${_cmdbEsc(r.os) || '—'}</td>
      <td style="font-family:monospace;font-size:12px">${_cmdbEsc(r.ip) || '—'}</td>
      <td>${hyp}</td>
      <td style="text-align:center">${r.has_documentation ? '<span style="color:var(--green)">●</span>' : '<span style="color:var(--muted)">○</span>'}</td>
      <td style="text-align:center;font-size:12px;color:var(--muted)">${r.credential_count}</td>
      <td><button class="btn-icon" onclick="cmdbOpenAsset('${_cmdbEsc(r.device_id)}')">Open</button></td>
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
  if (tab === 'creds') cmdbLoadCreds(_cmdbCurrent ? _cmdbCurrent.device_id : null);
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
    return `<details class="cmdb-doc-card" ${idx === 0 ? 'open' : ''} style="background:var(--surface2);border:1px solid var(--border);border-radius:8px">
      <summary style="padding:10px 14px;cursor:pointer;list-style:none;display:flex;align-items:center;gap:10px;user-select:none">
        <span style="color:var(--muted);font-size:11px">▸</span>
        <span style="font-weight:600;font-size:13px">${cmdbEscHtml(doc.title || '(untitled)')}</span>
        <span style="color:var(--muted);font-size:11px;margin-left:auto">${meta}</span>
        <button class="btn-icon" style="padding:3px 8px;font-size:11px" onclick="event.preventDefault();event.stopPropagation();cmdbDocEditOpen('${doc.id}');return false;">Edit</button>
        <button class="btn-icon" style="padding:3px 8px;font-size:11px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="event.preventDefault();event.stopPropagation();cmdbDocDelete('${doc.id}');return false;">Delete</button>
      </summary>
      <div style="padding:0 14px 14px;border-top:1px solid var(--border);font-size:13px;line-height:1.55">
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
  if (!src) return '<div style="color:var(--muted)">No content.</div>';
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const lines = src.split('\n');
  const out = [];
  let inCode = false, inList = false;
  for (let raw of lines) {
    if (raw.startsWith('```')) {
      if (inCode) { out.push('</code></pre>'); inCode = false; }
      else        { out.push('<pre style="background:var(--surface);padding:10px;border-radius:6px;overflow-x:auto"><code>'); inCode = true; }
      continue;
    }
    if (inCode) { out.push(esc(raw)); continue; }
    if (/^- /.test(raw)) {
      if (!inList) { out.push('<ul style="margin:6px 0 6px 22px">'); inList = true; }
      out.push('<li>' + cmdbInlineMd(esc(raw.slice(2))) + '</li>');
      continue;
    } else if (inList) { out.push('</ul>'); inList = false; }

    if (/^### /.test(raw))      out.push('<h4 style="margin:12px 0 6px">' + cmdbInlineMd(esc(raw.slice(4))) + '</h4>');
    else if (/^## /.test(raw))  out.push('<h3 style="margin:14px 0 6px">' + cmdbInlineMd(esc(raw.slice(3))) + '</h3>');
    else if (/^# /.test(raw))   out.push('<h2 style="margin:16px 0 8px">' + cmdbInlineMd(esc(raw.slice(2))) + '</h2>');
    else if (raw.trim() === '') out.push('<br>');
    else out.push('<div>' + cmdbInlineMd(esc(raw)) + '</div>');
  }
  if (inList) out.push('</ul>');
  if (inCode) out.push('</code></pre>');
  return out.join('\n');
}

function cmdbInlineMd(s) {
  return s
    .replace(/`([^`]+)`/g, '<code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-size:0.92em">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g,
             '<a href="$2" target="_blank" rel="noopener" style="color:var(--accent)">$1</a>');
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
    list.innerHTML = '<div style="color:var(--muted);text-align:center;padding:24px;font-size:13px">No credentials yet.</div>';
    return;
  }
  list.innerHTML = creds.map(c => {
    const note = c.note ? `<div style="font-size:12px;color:var(--muted);margin-top:4px">${_cmdbEsc(c.note)}</div>` : '';
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
        `<a class="btn-icon" href="${_cmdbEsc(sshUri)}" title="Open ssh:// link in your default handler" style="text-decoration:none">SSH</a>
         <button class="btn-icon" title="Copy: ${_cmdbEsc(sshCmd)}" onclick="cmdbSshCopy('${_cmdbEsc(sshCmd)}')">Copy</button>`;
    }
    return `<div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:8px;background:var(--surface2);display:flex;justify-content:space-between;align-items:flex-start;gap:10px">
      <div style="flex:1;min-width:0">
        <div style="font-weight:600">${_cmdbEsc(c.label)}</div>
        <div style="font-family:monospace;font-size:12px;color:var(--muted)">user: ${_cmdbEsc(c.username) || '—'}</div>
        ${note}
      </div>
      <div style="display:flex;gap:6px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end">
        ${sshButtons}
        <button class="btn-icon" ${locked ? 'disabled' : ''} onclick="cmdbCredReveal('${_cmdbEsc(deviceId)}','${_cmdbEsc(c.id)}')">Reveal</button>
        <button class="btn-icon" ${locked ? 'disabled' : ''} onclick="cmdbCredEditOpen('${_cmdbEsc(deviceId)}','${_cmdbEsc(c.id)}','${_cmdbEsc(c.label)}','${_cmdbEsc(c.username)}','${_cmdbEsc(c.note || '')}')">Edit</button>
        <button class="btn-icon" style="color:var(--red)" onclick="cmdbCredDelete('${_cmdbEsc(deviceId)}','${_cmdbEsc(c.id)}')">Delete</button>
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
    '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>';
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
    body.innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">No update runs captured yet. Run "Upgrade packages" on this device — the output will land here on the next heartbeat (~60s).</div>';
    return;
  }
  body.innerHTML = logs.map((entry, idx) => {
    const ok = entry.exit_code === 0;
    const status = ok
      ? '<span style="color:var(--green)">● success</span>'
      : `<span style="color:var(--red)">● failed (rc=${entry.exit_code})</span>`;
    const when = entry.finished_at
      ? new Date(entry.finished_at * 1000).toLocaleString()
      : '—';
    const duration = (entry.finished_at && entry.started_at)
      ? `${Math.max(0, entry.finished_at - entry.started_at)}s`
      : '?';
    const pm = entry.package_manager || 'unknown';
    const out = entry.output || '(no output captured)';
    const open = idx === 0 ? 'open' : '';
    return `<details ${open} style="border:1px solid var(--border);border-radius:6px;margin-bottom:8px;background:var(--surface2)">
      <summary style="padding:10px 12px;cursor:pointer;display:flex;gap:12px;align-items:center;flex-wrap:wrap">
        <span style="font-weight:500">${escHtml(when)}</span>
        <span style="color:var(--muted);font-size:12px">${escHtml(pm)} · ${escHtml(duration)}</span>
        <span style="margin-left:auto">${status}</span>
      </summary>
      <pre style="margin:0;padding:12px;background:var(--surface);border-top:1px solid var(--border);font-family:monospace;font-size:12px;line-height:1.5;overflow-x:auto;white-space:pre-wrap;word-wrap:break-word;max-height:400px;overflow-y:auto">${escHtml(out)}</pre>
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
}

async function loadContainersOverview() {
  const tbody = document.getElementById('containers-tbody');
  tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:24px">Loading…</tbody>';
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
        ? '<span style="display:inline-block;margin-left:6px;padding:1px 6px;border-radius:3px;font-size:10px;background:var(--amber);color:#000;font-weight:600">STALE</span>'
        : '';
      const restartingCell = s.restarting > 0
        ? `<span style="color:var(--red)">${s.restarting}</span>`
        : `<span style="color:var(--muted)">0</span>`;
      return `<tr${r.is_stale ? ' style="opacity:.75"' : ''}>
        <td style="font-weight:500">${osIcon(r.os, 14)} ${escHtml(r.name)}</td>
        <td style="font-size:12px;color:var(--muted)">${escHtml(r.os || '—')}</td>
        <td style="font-weight:500">${s.total}</td>
        <td style="color:var(--green)">${s.running}</td>
        <td style="color:var(--muted)">${s.stopped}</td>
        <td>${restartingCell}</td>
        <td style="font-size:12px;color:var(--muted)">${runtimes}</td>
        <td style="font-size:12px;color:var(--muted);white-space:nowrap">${reported}${staleBadge}</td>
        <td><button class="btn-icon" onclick="containersOpen('${escAttr(r.device_id)}','${escAttr(r.name)}')">View</button></td>
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
  body.innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>';
  openModal('containers-detail-modal');
  const data = await api('GET', `/devices/${encodeURIComponent(deviceId)}/containers`);
  if (!data) return;
  const items = data.items || [];
  // v1.11.4: stale-data warning at the top of the modal.
  const reportedHuman = data.reported_at ? new Date(data.reported_at * 1000).toLocaleString() : 'never';
  const staleBanner = data.is_stale
    ? `<div style="background:var(--amber);color:#000;padding:8px 12px;border-radius:6px;margin-bottom:12px;font-size:12px;font-weight:500">
         ⚠ Container data is stale (last reported: ${escHtml(reportedHuman)}).
         Agent reports every ~5 min when a runtime is installed; check
         <code>journalctl -u remotepower-agent</code> on the device.
       </div>`
    : '';
  if (!items.length) {
    body.innerHTML = staleBanner + '<div style="color:var(--muted);text-align:center;padding:40px">No containers reported.</div>';
    return;
  }
  body.innerHTML = staleBanner + items.map(c => {
    const statusLower = (c.status || '').toLowerCase();
    const statusColor = statusLower.includes('running') || statusLower.includes('up ')
      ? 'var(--green)'
      : statusLower.includes('exit') ? 'var(--red)' : 'var(--muted)';
    const ports = (c.ports || []).map(p => `<code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-size:11px">${escHtml(p)}</code>`).join(' ');
    const restart = c.restart_count > 0
      ? `<span style="color:${c.restart_count >= 5 ? 'var(--red)' : 'var(--amber)'}">restart×${c.restart_count}</span>`
      : '';
    const ns = c.namespace ? `<span style="color:var(--muted)">${escHtml(c.namespace)}/</span>` : '';
    // v2.1.1: per-container actions. The agent's allowlist accepts
    // start / stop / restart / pause / unpause / logs. Kubernetes pods
    // aren't actionable through docker/podman CLI, so we hide actions
    // for the kubectl runtime (kubectl listing reports runtime='kubectl').
    // We use the container ID (preferred) or fall back to the name —
    // server-side validation accepts whichever the agent reported.
    const cid = c.id || c.name || '';
    const runtime = (c.runtime || 'docker').toLowerCase();
    const actionable = (runtime === 'docker' || runtime === 'podman') && cid;
    const isRunning = statusLower.includes('running') || statusLower.includes('up ');
    const actions = actionable ? `
      <div style="display:flex;gap:4px;margin-top:8px;flex-wrap:wrap">
        ${!isRunning ? `<button class="btn-icon" style="font-size:11px;padding:3px 8px" onclick="containerAction('${escAttr(deviceId)}','${escAttr(runtime)}','${escAttr(cid)}','start','${escAttr(c.name||'')}')">Start</button>` : ''}
        ${isRunning  ? `<button class="btn-icon" style="font-size:11px;padding:3px 8px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="containerAction('${escAttr(deviceId)}','${escAttr(runtime)}','${escAttr(cid)}','stop','${escAttr(c.name||'')}')">Stop</button>` : ''}
        <button class="btn-icon" style="font-size:11px;padding:3px 8px" onclick="containerAction('${escAttr(deviceId)}','${escAttr(runtime)}','${escAttr(cid)}','restart','${escAttr(c.name||'')}')">Restart</button>
        <button class="btn-icon" style="font-size:11px;padding:3px 8px" onclick="containerAction('${escAttr(deviceId)}','${escAttr(runtime)}','${escAttr(cid)}','logs','${escAttr(c.name||'')}')">Logs</button>
      </div>` : '';
    return `<div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:8px;background:var(--surface2)">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap">
        <div style="font-weight:600">${ns}${escHtml(c.name)}</div>
        <div style="display:flex;gap:8px;align-items:center;font-size:12px">
          <span style="color:${statusColor}">${escHtml(c.status || '?')}</span>
          ${restart}
          <span class="cmd-badge ${escHtml(c.runtime)}" style="font-size:10px;padding:2px 6px">${escHtml(c.runtime)}</span>
        </div>
      </div>
      <div style="font-size:12px;color:var(--muted);margin-top:4px;font-family:monospace">${escHtml(c.image)}${c.tag ? ':' + escHtml(c.tag) : ''}</div>
      ${ports ? `<div style="margin-top:6px;display:flex;gap:4px;flex-wrap:wrap">${ports}</div>` : ''}
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
  _netmapData = data;
  _netmapDirty.clear();
  // Auto-layout for nodes without a saved position. We keep saved positions
  // exactly as the server returned them so a refresh shows the same picture.
  const w = document.getElementById('netmap-svg')?.clientWidth || 900;
  const byType = {};
  _netmapNodes = data.nodes.map(n => ({...n}));
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
    `${data.nodes.length} node(s), ${data.edges.length} link(s), ${(data.tunnels||[]).length} tunnel(s)`;
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
    return `<g class="netmap-node" data-node-id="${escHtml(n.id)}" transform="translate(${n.x}, ${n.y})" style="cursor:grab">
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
    body.innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px">No devices to link.</div>';
    openModal('netmap-edit-modal');
    return;
  }
  // Build an option list of all devices for the dropdowns
  const optsHtml = '<option value="">— none —</option>' +
    nodes.map(n => `<option value="${escHtml(n.id)}">${escHtml(n.name)} (${escHtml(n.type || 'host')})</option>`).join('');
  body.innerHTML = `<table style="width:100%"><thead><tr style="text-align:left;border-bottom:1px solid var(--border)"><th style="padding:6px 8px">Device</th><th style="padding:6px 8px">Type</th><th style="padding:6px 8px">Connected to (upstream)</th></tr></thead><tbody>${
    nodes.map(n => {
      const cur = (_netmapData.edges.find(e => e.from === n.id) || {}).to || '';
      // Build per-row options where the current value is selected and self-link is removed
      const rowOpts = '<option value="">— none —</option>' +
        nodes.filter(o => o.id !== n.id).map(o =>
          `<option value="${escHtml(o.id)}"${o.id === cur ? ' selected' : ''}>${escHtml(o.name)} (${escHtml(o.type || 'host')})</option>`
        ).join('');
      return `<tr>
        <td style="padding:6px 8px;font-weight:500">${escHtml(n.name)}</td>
        <td style="padding:6px 8px;color:var(--muted);font-size:12px">${escHtml(n.type || 'host')}</td>
        <td style="padding:6px 8px"><select class="form-input netmap-link-sel" data-device-id="${escHtml(n.id)}" data-original="${escHtml(cur)}" style="width:100%">${rowOpts}</select></td>
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
    list.innerHTML = '<div style="color:var(--muted);text-align:center;padding:24px">No tunnels yet.</div>';
    return;
  }
  // Build a name lookup for friendlier rendering
  const nameOf = id => {
    const n = _netmapData.nodes.find(x => x.id === id);
    return n ? n.name : id;
  };
  list.innerHTML = tunnels.map(t => `<div style="border:1px solid var(--border);border-radius:6px;padding:10px 12px;margin-bottom:8px;background:var(--surface2);display:flex;justify-content:space-between;align-items:center;gap:10px">
    <div style="font-weight:500">${escHtml(nameOf(t.endpoints[0]))} <span style="color:var(--amber)">↔</span> ${escHtml(nameOf(t.endpoints[1]))}</div>
    <button class="btn-icon" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="tunnelDelete('${escAttr(t.id)}')">✕</button>
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
  tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:24px">Loading…</tbody>';
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
        if (t.status === 'critical') return '<span style="color:var(--red);font-weight:600">● critical</span>';
        if (t.status === 'warning')  return '<span style="color:var(--amber);font-weight:600">● warn</span>';
        if (t.status === 'error')    return '<span style="color:var(--red)">● error</span>';
        if (t.status === 'ok')       return '<span style="color:var(--green)">● ok</span>';
        return '<span style="color:var(--muted)">— never scanned</span>';
      })();
      const daneBadge = (() => {
        if (!t.dane_check) return '';
        const s = t.dane_status || 'not_checked';
        const colours = { ok: 'var(--green)', mismatch: 'var(--amber)', insecure: 'var(--red)', error: 'var(--red)', missing: 'var(--muted)', not_checked: 'var(--muted)' };
        const labels  = { ok: 'DANE ok', mismatch: 'DANE mismatch', insecure: 'DANE insecure', error: 'DANE error', missing: 'DANE missing', not_checked: 'DANE pending' };
        return `<span style="color:${colours[s] || 'var(--muted)'};font-size:11px;margin-left:8px;background:rgba(255,255,255,0.04);padding:1px 5px;border-radius:3px">${labels[s] || s}</span>`;
      })();
      const expires = t.expires_at ? new Date(t.expires_at * 1000).toLocaleDateString() : '—';
      const lastChk = t.last_check ? new Date(t.last_check * 1000).toLocaleString() : '—';
      const days = (t.status === 'ok' || t.status === 'warning' || t.status === 'critical')
        ? `${t.days_left}d` : (t.dns_error ? 'DNS' : t.tls_error ? 'TLS' : '—');
      const issuer = (t.issuer || '').replace(/CN=/, '').split(',')[0] || '—';
      const labelHtml = t.label ? `<span style="color:var(--muted);font-size:11px;margin-left:6px">${escHtml(t.label)}</span>` : '';
      const connectHtml = t.connect_address ? `<div style="color:var(--muted);font-size:11px;margin-top:2px">via ${escHtml(t.connect_address)}</div>` : '';
      const starttlsHtml = (t.starttls && t.starttls !== 'none')
        ? `<span style="color:var(--accent);font-size:10px;margin-left:6px;background:rgba(59,126,255,0.12);padding:1px 5px;border-radius:3px;text-transform:uppercase">${escHtml(t.starttls)}</span>`
        : '';
      // v2.1.5: ✨ Triage only on warning/critical/error — no point asking
      // about cert lifecycle on a healthy 90-days-left target.
      const aiBtn = (t.status === 'warning' || t.status === 'critical' || t.status === 'error')
        ? `<button class="btn-icon" style="padding:2px 6px;font-size:11px;margin-right:6px" onclick="event.stopPropagation();aiExplainTls('${escAttr(t.host)}',${t.port||443},${t.expires_at||0},'${escAttr(t.issuer||'')}','starttls=${escAttr(t.starttls||'none')}')" title="AI: triage this cert">✨</button>`
        : '';
      return `<tr style="cursor:pointer" onclick="tlsDetailOpen('${escAttr(t.id)}')">
        <td>${statusBadge}${daneBadge}</td>
        <td style="font-family:monospace">${escHtml(t.host)}${labelHtml}${starttlsHtml}${connectHtml}</td>
        <td style="font-family:monospace;color:var(--muted)">${t.port}</td>
        <td style="font-weight:500">${days}</td>
        <td style="font-size:12px;color:var(--muted)">${expires}</td>
        <td style="font-size:12px;color:var(--muted)">${escHtml(issuer.slice(0,30))}</td>
        <td style="font-size:12px;color:var(--muted);white-space:nowrap">${lastChk}</td>
        <td onclick="event.stopPropagation()">${aiBtn}<button class="btn-icon" style="color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="tlsDelete('${escAttr(t.id)}','${escAttr(t.host)}')">✕</button></td>
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

function tlsAddOpen() {
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
  const r = await api('POST', '/tls/targets', body);
  if (!r || !r.ok) { toast(r?.error || 'Add failed', 'error'); return; }
  closeModal('tls-add-modal');
  toast('Target added — click "Scan now" to probe it', 'success');
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
  const fmt = (v, fallback) => v ? escHtml(v) : `<span style="color:var(--muted)">${fallback}</span>`;
  const sans = (t.san && t.san.length)
    ? t.san.map(s => `<code style="background:var(--surface);padding:1px 5px;border-radius:3px;font-size:11px;margin-right:4px">${escHtml(s)}</code>`).join('')
    : '<span style="color:var(--muted)">none</span>';
  const errs = [
    t.dns_error    ? `<div style="color:var(--red);margin-top:4px">DNS: ${escHtml(t.dns_error)}</div>`    : '',
    t.tls_error    ? `<div style="color:var(--red);margin-top:4px">TLS: ${escHtml(t.tls_error)}</div>`    : '',
    t.verify_error ? `<div style="color:var(--amber);margin-top:4px">Verification: ${escHtml(t.verify_error)}</div>` : '',
  ].join('');

  // v1.11.2: hostname-match indicator. Useful when probing by IP — helps
  // distinguish "wrong cert" from "right cert, wrong IP."
  const hostnameMatchHtml = (() => {
    if (t.hostname_match === null || t.hostname_match === undefined) {
      return '<span style="color:var(--muted)">—</span>';
    }
    return t.hostname_match
      ? '<span style="color:var(--green)">✓ matches</span>'
      : '<span style="color:var(--amber)">✗ no match</span>';
  })();

  // Connect-address row only renders when overridden — otherwise it's noise
  const connectAddrRow = t.connect_address
    ? `<div style="color:var(--muted)">Connect address</div><div style="font-family:monospace">${escHtml(t.connect_address)}</div>`
    : '';

  // STARTTLS row only renders when not 'none' — direct TLS doesn't need a label
  const starttlsRow = (t.starttls && t.starttls !== 'none')
    ? `<div style="color:var(--muted)">STARTTLS</div><div style="font-family:monospace">${escHtml(t.starttls.toUpperCase())}</div>`
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
      recordsHtml = `<table style="width:100%;margin-top:8px;font-family:monospace;font-size:11px;border-collapse:collapse">
        <thead><tr style="border-bottom:1px solid var(--border);text-align:left">
          <th style="padding:4px 8px">Usage</th>
          <th style="padding:4px 8px">Selector</th>
          <th style="padding:4px 8px">Match</th>
          <th style="padding:4px 8px">Data</th>
        </tr></thead><tbody>
        ${t.dane_records.map(r => `<tr>
          <td style="padding:4px 8px">${r.usage}</td>
          <td style="padding:4px 8px">${r.selector}</td>
          <td style="padding:4px 8px">${r.matching_type}</td>
          <td style="padding:4px 8px;word-break:break-all">${escHtml(String(r.data || '').slice(0, 64))}${(r.data || '').length > 64 ? '…' : ''}</td>
        </tr>`).join('')}
        </tbody></table>`;
    }
    daneHtml = `<div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border)">
      <div style="font-weight:600;margin-bottom:6px">DANE / TLSA</div>
      <div style="color:${colour};font-size:13px">${escHtml(text)}</div>
      ${t.dane_error ? `<div style="color:var(--red);font-size:12px;margin-top:4px">${escHtml(t.dane_error)}</div>` : ''}
      ${recordsHtml}
    </div>`;
  }

  const body = document.getElementById('tls-detail-body');
  body.innerHTML = `
    <div style="display:grid;grid-template-columns:140px 1fr;gap:8px 14px">
      <div style="color:var(--muted)">Host (SNI)</div><div style="font-family:monospace">${escHtml(t.host)}:${t.port}</div>
      ${connectAddrRow}
      ${starttlsRow}
      <div style="color:var(--muted)">Hostname match</div><div>${hostnameMatchHtml}</div>
      <div style="color:var(--muted)">Label</div><div>${fmt(t.label, '—')}</div>
      <div style="color:var(--muted)">Status</div><div>${escHtml(t.status)}</div>
      <div style="color:var(--muted)">Days left</div><div>${t.days_left}d</div>
      <div style="color:var(--muted)">Expires</div><div>${t.expires_at ? new Date(t.expires_at*1000).toLocaleString() : '—'}</div>
      <div style="color:var(--muted)">Issuer</div><div>${fmt(t.issuer, '—')}</div>
      <div style="color:var(--muted)">Subject</div><div>${fmt(t.subject, '—')}</div>
      <div style="color:var(--muted)">SAN</div><div>${sans}</div>
      <div style="color:var(--muted)">DNS A/AAAA</div><div style="font-family:monospace">${(t.addresses || []).map(escHtml).join(', ') || '—'}</div>
      <div style="color:var(--muted)">Warn / Critical</div><div>${t.warn_days}d / ${t.crit_days}d</div>
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
      grid.innerHTML = '<div style="color:var(--muted);text-align:center;padding:60px">No links yet. Click "+ Add link" to start.</div>';
    } else {
      grid.innerHTML = '<div style="color:var(--muted);text-align:center;padding:60px">No links match the current filter.</div>';
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
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <h3 style="margin:0;font-size:14px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.5px">${escHtml(cat)}</h3>
        <span style="font-size:11px;color:var(--muted);opacity:0.7">${items.length}</span>
        <div style="flex:1;height:1px;background:var(--border)"></div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(260px, 1fr));gap:12px">${cards}</div>
    </div>`;
  }).join('');
}

function _renderLinkCard(l) {
  const isInternal = l.scope === 'internal';
  const borderColor = isInternal ? 'var(--amber)' : 'var(--accent)';
  const borderStyle = isInternal ? 'dashed' : 'solid';
  const scopeBadge = isInternal
    ? '<span style="font-size:10px;color:var(--amber);background:rgba(245,158,11,0.12);padding:2px 6px;border-radius:3px;text-transform:uppercase;letter-spacing:0.5px;font-weight:600">Internal</span>'
    : '<span style="font-size:10px;color:var(--accent);background:rgba(59,126,255,0.12);padding:2px 6px;border-radius:3px;text-transform:uppercase;letter-spacing:0.5px;font-weight:600">External</span>';

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
    ? `<div style="display:flex;gap:6px;margin-top:8px;border-top:1px solid var(--border);padding-top:8px">
         <button class="btn-icon" style="font-size:11px;padding:3px 8px" onclick="event.stopPropagation();linkEditOpen('${escAttr(l.id)}')">Edit</button>
         <button class="btn-icon" style="font-size:11px;padding:3px 8px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="event.stopPropagation();linkDelete('${escAttr(l.id)}','${escAttr(l.title)}')">Delete</button>
       </div>`
    : '';

  // The whole card is the click target when not in edit mode. We use an
  // <a> wrapper rather than onclick=window.open so middle-click and
  // ctrl-click work naturally for power users.
  const cardInner = `<div style="border:1px ${borderStyle} ${borderColor};border-radius:8px;padding:12px 14px;background:var(--surface2);transition:background 0.1s;cursor:${_linksEditMode ? 'default' : 'pointer'};height:100%;display:flex;flex-direction:column;justify-content:space-between"
    onmouseover="this.style.background='var(--surface)'" onmouseout="this.style.background='var(--surface2)'"
    title="${escHtml(l.description || l.url)}">
    <div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:6px">
        <div style="font-weight:600;font-size:14px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(l.title)}</div>
        ${scopeBadge}
      </div>
      <div style="font-family:monospace;font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(displayUrl)}</div>
      ${l.description ? `<div style="font-size:12px;color:var(--muted);margin-top:6px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden">${escHtml(l.description)}</div>` : ''}
    </div>
    ${editButtons}
  </div>`;

  if (_linksEditMode) {
    // No anchor — clicks go through stopPropagation on edit buttons above.
    return cardInner;
  }
  return `<a href="${escHtml(l.url)}" target="_blank" rel="noopener noreferrer" style="text-decoration:none;color:inherit;display:block">${cardInner}</a>`;
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


// Make the bundle look professional — a tiny CSS hook for active tab styling.
(function _cmdbInjectCss() {
  const css = '.cmdb-tab-btn.active{background:rgba(59,126,255,0.12);border-color:var(--accent);color:var(--accent)}';
  const s = document.createElement('style'); s.textContent = css;
  document.head.appendChild(s);
})();

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
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:40px">Loading…</td></tr>';
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
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:40px">${_scriptsCache.length ? 'No matches' : 'No scripts yet. Click <b>New script</b> to create one.'}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(s => {
    const size = s.body_len < 1024 ? `${s.body_len} B` : `${(s.body_len/1024).toFixed(1)} KB`;
    const updated = s.updated ? timeAgo(s.updated) : '—';
    const dangerBadge = s.dangerous
      ? '<span class="patch-badge warn" title="Dry run flagged dangerous patterns">⚠ DANGER</span>'
      : '';
    return `<tr>
      <td style="font-weight:500">${escHtml(s.name||'—')}</td>
      <td style="color:var(--muted);font-size:12px">${escHtml(s.description||'')}</td>
      <td style="font-family:monospace;font-size:12px;color:var(--muted)">${escHtml(size)}</td>
      <td style="font-size:12px;color:var(--muted)">${escHtml(updated)}</td>
      <td>${dangerBadge}</td>
      <td style="white-space:nowrap">
        <button class="btn-icon" style="font-size:11px;padding:4px 8px" onclick="openScriptEdit('${escAttr(s.id)}')">Edit</button>
        <button class="btn-icon" style="font-size:11px;padding:4px 8px" onclick="dryRunScript('${escAttr(s.id)}')">Dry run</button>
        <button class="btn-icon" style="font-size:11px;padding:4px 8px;color:var(--red);border-color:rgba(239,68,68,0.3)" onclick="deleteScript('${escAttr(s.id)}','${escAttr(s.name||'')}')">Delete</button>
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
    head = '⚠ bash -n not available server-side — syntax check skipped';
  }
  let body = head;
  if (lint.dangerous && lint.dangerous.length) {
    body += '\n\n⚠ Dangerous patterns detected:';
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
    summary += ` — ⚠ ${l.dangerous.length} dangerous pattern${l.dangerous.length>1?'s':''}: ${l.dangerous.join(', ')}`;
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
    opt.textContent = s.name + (s.dangerous ? '  ⚠ DANGER' : '');
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
    '<div style="color:var(--muted);text-align:center;padding:40px">Loading…</div>';
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
      `<div style="color:var(--red);padding:20px">${escHtml(data?.error||'Failed to load job')}</div>`;
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
    let pill = '<span class="patch-badge ok" style="font-size:11px">pending</span>';
    let outBox = '';
    if (!e.queued) {
      pill = `<span class="patch-badge warn" style="font-size:11px">${escHtml(e.reason||'skipped')}</span>`;
    } else if (e.status === 'done') {
      const ok = e.rc === 0;
      pill = `<span class="patch-badge ${ok ? 'ok' : 'warn'}" style="font-size:11px">rc=${escHtml(String(e.rc))}</span>`;
      const finished = e.finished_at ? new Date(e.finished_at*1000).toLocaleTimeString() : '';
      outBox = `<pre style="margin-top:6px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;font-size:12px;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-word">${escHtml(e.output||'(no output)')}</pre><div style="font-size:11px;color:var(--muted);margin-top:2px">finished ${escHtml(finished)}</div>`;
    }
    body += `<div style="border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:10px;background:var(--surface)">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><div style="font-weight:600">${name}</div>${pill}</div>
      ${outBox}
    </div>`;
  }
  if (!entries.length) body = '<div style="color:var(--muted);padding:20px">No targets in this batch.</div>';
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
  document.getElementById('login-pass').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  document.getElementById('login-totp').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
  document.getElementById('login-user').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('login-pass').focus(); });
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
//   2. Inline ✨ buttons on command output, journal, scripts, CVE rows,
//      device cards, and notifications — all routed through openAIModal().
//
// openAIModal() is the single reusable component for every ✨ click. It:
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
  onAIProviderChange();   // refresh per-provider hint
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

// ─── Reusable ✨ modal ─────────────────────────────────────────────────────
//
// Every ✨ button on the dashboard funnels through this. Pass:
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
    <div class="modal" style="max-width:720px;width:92vw;max-height:88vh;display:flex;flex-direction:column">
      <div class="modal-header" style="display:flex;justify-content:space-between;align-items:center">
        <div style="font-weight:600" id="ai-modal-title">✨ AI</div>
        <button class="btn-icon" onclick="closeAIModal()" style="padding:4px 8px">✕</button>
      </div>
      <div style="padding:8px 16px;font-size:11px;color:var(--muted);border-bottom:1px solid var(--border)" id="ai-modal-meta">—</div>
      <div id="ai-modal-body" style="flex:1;overflow:auto;padding:14px 16px;font-size:13px;line-height:1.5;white-space:pre-wrap;font-family:ui-sans-serif,-apple-system,Segoe UI,sans-serif">
        <div style="color:var(--muted)">Thinking…</div>
      </div>
      <div style="padding:10px 16px;border-top:1px solid var(--border);display:flex;gap:8px;flex-wrap:wrap">
        <button class="btn-icon" id="ai-modal-copy" onclick="aiModalCopy()" disabled>Copy response</button>
        <button class="btn-icon" id="ai-modal-action" style="display:none"></button>
        <div style="flex:1"></div>
        <button class="btn-icon" onclick="closeAIModal()">Close</button>
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
  document.getElementById('ai-modal-title').textContent = title || '✨ AI';
  document.getElementById('ai-modal-meta').textContent  =
    `context: ${context || 'n/a'} — be aware the request content is sent to the configured AI provider`;
  const body = document.getElementById('ai-modal-body');
  body.innerHTML = '<div style="color:var(--muted)">Thinking… <span id="ai-modal-elapsed" style="font-size:11px"></span></div>';
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
    body.innerHTML = `<div style="color:var(--red);white-space:pre-wrap">${escHtml(resp.error)}</div>`;
    return;
  }
  // v2.1.5: render markdown so **bold** and # headers and `code`
  // don't show as literal punctuation. dataset.rawText keeps the
  // original for the Copy button.
  body.innerHTML = renderMarkdown(resp.text || '(empty response)');
  body.dataset.rawText = resp.text || '';
  document.getElementById('ai-modal-copy').disabled = false;
  document.getElementById('ai-modal-meta').textContent =
    `${resp.model || '?'} · ${resp.tokens_in}+${resp.tokens_out} tokens · ${resp.elapsed_ms}ms` +
    (resp.daily_cap ? ` · ${resp.used_today}/${resp.daily_cap} today` : '');

  if (onResult && actionLabel) {
    actionBtn.style.display = '';
    actionBtn.textContent = actionLabel;
    actionBtn.onclick = () => { onResult(resp.text || ''); closeAIModal(); };
  }
}

// ─── Inline ✨ triggers ────────────────────────────────────────────────────
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
    title:    '✨ Explain command output',
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
    title:    '✨ Find the problem',
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
    title:    '✨ Explain alert',
    system:   'explain_alert',
    userMsg:  `Event: ${eventType}\nDevice: ${deviceName}\nMessage: ${message}\n\nPayload:\n${payload}`,
    context:  `alert:${eventType}`,
    maxTokens: 800,           // alerts get a one-paragraph answer
  });
}

function aiTriageCve(cveId, packageName, version, deviceName, description) {
  openAIModal({
    title:    `✨ Triage ${cveId}`,
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
      title:    `✨ Investigate ${deviceName}`,
      system:   'investigate_device',
      userMsg:  sections.join('\n\n'),
      context:  `device:${devId}`,
      maxTokens: 2000,
    });
  })();
}

function aiExplainScript(scriptBody) {
  openAIModal({
    title:    '✨ Explain script',
    system:   'explain_script',
    userMsg:  scriptBody,
    context:  'script',
    maxTokens: 1500,
  });
}

function aiAuditScript(scriptBody) {
  openAIModal({
    title:    '✨ Audit script for risks',
    system:   'audit_script',
    userMsg:  scriptBody,
    context:  'script',
    maxTokens: 2000,
  });
}

function aiGenerateScript(prompt, targetElementId) {
  if (!prompt || !prompt.trim()) { toast('Describe what the script should do', 'info'); return; }
  openAIModal({
    title:    '✨ Generate script',
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

// ─── Script editor ✨ buttons ──────────────────────────────────────────────

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
      `<pre style="background:var(--surface2);border:1px solid var(--border);` +
      `padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:12px;` +
      `margin:8px 0;line-height:1.5"><code>${code.replace(/^\n|\n$/g, '')}</code></pre>`
    );
    return `\x00CODEBLOCK${idx}\x00`;
  });

  // Inline code — same idea, hold placeholders so `**` inside backticks
  // doesn't turn into a <strong>.
  const inlineCodes = [];
  html = html.replace(/`([^`\n]+)`/g, (_, code) => {
    const idx = inlineCodes.length;
    inlineCodes.push(
      `<code style="background:var(--surface2);padding:1px 5px;` +
      `border-radius:3px;font-size:90%;font-family:ui-monospace,monospace">` +
      `${code}</code>`
    );
    return `\x00INLINE${idx}\x00`;
  });

  // Headers — only at the start of a line. The big-three are enough.
  html = html.replace(/^### +(.+)$/gm,
    '<div style="font-size:14px;font-weight:600;margin:10px 0 4px">$1</div>');
  html = html.replace(/^## +(.+)$/gm,
    '<div style="font-size:15px;font-weight:600;margin:12px 0 6px;border-bottom:1px solid var(--border);padding-bottom:4px">$1</div>');
  html = html.replace(/^# +(.+)$/gm,
    '<div style="font-size:17px;font-weight:700;margin:14px 0 8px">$1</div>');

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
      if (listType !== 'ul') { closeList(); out.push('<ul style="margin:6px 0;padding-left:22px">'); listType = 'ul'; }
      out.push(`<li>${bullet[1]}</li>`);
    } else if (numbered) {
      if (listType !== 'ol') { closeList(); out.push('<ol style="margin:6px 0;padding-left:22px">'); listType = 'ol'; }
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
    '<div style="border-left:3px solid var(--border);padding:2px 10px;color:var(--muted);margin:6px 0">$1</div>');

  // Paragraphs: turn blank-line-separated chunks into <p>, single newlines
  // into <br>. Don't wrap content that's already block-level (lists,
  // headers, code blocks, blockquotes).
  const blocks = html.split(/\n{2,}/).map(b => {
    const trimmed = b.trim();
    if (!trimmed) return '';
    if (/^<(?:div|ul|ol|pre|h[1-6]|blockquote)/i.test(trimmed)) return trimmed;
    return `<p style="margin:6px 0;line-height:1.55">${trimmed.replace(/\n/g, '<br>')}</p>`;
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
    wrap.innerHTML = '<div style="color:var(--muted);text-align:center;padding:40px 12px">' +
      'No messages yet — type a prompt below.<br>' +
      '<span style="font-size:11px">Conversation history is kept in your browser (localStorage) — not on the server. ' +
      'Clearing the conversation clears only your view.</span></div>';
    return;
  }
  wrap.innerHTML = _aiPageConv.map(m => {
    const isUser = m.role === 'user';
    const isPending = m.pending;
    const bg = isUser ? 'rgba(59,126,255,0.08)' : 'var(--surface)';
    const border = isUser ? 'rgba(59,126,255,0.25)' : 'var(--border)';
    const label = isUser ? 'You' : (m.model ? `Assistant · ${escHtml(m.model)}` : 'Assistant');
    const meta = m.meta ? `<div style="font-size:10px;color:var(--muted);margin-top:6px">${escHtml(m.meta)}</div>` : '';
    // v2.1.5: render markdown for assistant turns. User turns stay
    // plain — what the user typed shouldn't be re-interpreted.
    let content;
    if (isPending) {
      content = '<div style="color:var(--muted)">Thinking… <span class="ai-page-elapsed" data-start="' + Date.now() + '">(0s elapsed)</span></div>';
    } else if (isUser) {
      content = `<div style="white-space:pre-wrap">${escHtml(m.content || '')}</div>`;
    } else {
      content = renderMarkdown(m.content || '');
    }
    return `<div style="margin-bottom:12px"><div style="font-size:11px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.5px">${label}</div>` +
           `<div style="background:${bg};border:1px solid ${border};border-radius:8px;padding:10px 14px;word-wrap:break-word">${content}${meta}</div></div>`;
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
        '<span style="color:var(--red)">● Error</span>';
      document.getElementById('ai-page-stat-provider').textContent = '—';
      return;
    }
    document.getElementById('ai-page-stat-provider').textContent = stats.provider || '—';
    document.getElementById('ai-page-stat-baseurl').textContent  = stats.base_url || '';
    document.getElementById('ai-page-stat-version').textContent  = stats.version || (stats.local ? 'unknown' : '(cloud)');
    document.getElementById('ai-page-stat-status').innerHTML = stats.reachable
      ? '<span style="color:var(--green)">● Reachable</span>'
      : '<span style="color:var(--amber)">● Unreachable</span>';
    const loadedEl = document.getElementById('ai-page-stat-loaded');
    if (Array.isArray(stats.loaded_models) && stats.loaded_models.length) {
      loadedEl.innerHTML = stats.loaded_models.map(m =>
        `<div><strong>${escHtml(m.name)}</strong>` +
        (m.vram_mb ? ` <span style="color:var(--muted)">· ${m.vram_mb} MB VRAM</span>` : '') +
        (m.expires_at ? ` <span style="color:var(--muted);font-size:11px">· expires ${escHtml(String(m.expires_at).slice(0,19).replace('T',' '))}</span>` : '') +
        '</div>'
      ).join('');
    } else if (stats.local) {
      loadedEl.innerHTML = '<span style="color:var(--muted)">No models currently loaded (will load on first request)</span>';
    } else {
      loadedEl.innerHTML = '<span style="color:var(--muted)">(cloud provider — no introspection)</span>';
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
  if (!cfg.ok && cfg.error && /disabled/i.test(cfg.error)) {
    // Show the "AI is disabled" banner and hide everything else
    document.getElementById('ai-page-disabled').style.display = '';
    document.getElementById('ai-page-status').style.display = 'none';
    document.getElementById('ai-page-chat-wrap').style.display = 'none';
    return;
  }
  if (!cfg.ok || !cfg.enabled) {
    document.getElementById('ai-page-disabled').style.display = '';
    document.getElementById('ai-page-status').style.display = 'none';
    document.getElementById('ai-page-chat-wrap').style.display = 'none';
    return;
  }
  document.getElementById('ai-page-disabled').style.display = 'none';
  document.getElementById('ai-page-status').style.display = '';
  document.getElementById('ai-page-chat-wrap').style.display = '';

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
    last.content = `⚠ ${resp.error}`;
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
  const idEsc = d.id;
  const nameEsc = escAttr(d.name);
  const dangerous = (d.version || '').match(/^2\.[1-9]/);   // compose support
  const composeSuffix = d.compose_projects_count > 0
    ? ` (${d.compose_projects_count})`
    : ' (scan pending…)';

  // Each section is a list of [label, onclick-snippet]. Keeps the
  // template tidy and makes it easy to add or move items.
  const power = [
    ['Shut down',       `requestShutdown('${idEsc}','${nameEsc}')`],
    ['Reboot',          `requestReboot('${idEsc}','${nameEsc}')`],
  ];
  if (d.mac) power.push(['Wake-on-LAN', `sendWol('${idEsc}','${nameEsc}')`]);
  power.push(['Upgrade packages', `upgradePackages('${idEsc}','${nameEsc}')`]);

  const inspect = [
    ['System info',     `openDetail('${idEsc}','${nameEsc}')`],
    ['✨ Investigate',  `aiInvestigateDevice('${idEsc}','${nameEsc}')`],
    ['Metrics',         `openMetrics('${idEsc}','${nameEsc}')`],
    ['Update history',  `openUpdateLogs('${idEsc}','${nameEsc}')`],
  ];

  const operate = [
    ['Web terminal',    `openWebTerm('${idEsc}','${nameEsc}')`],
    ['Custom command',  `openExecModal('${idEsc}','${nameEsc}')`],
    ['Run script…',     `openScriptRunForDevice('${idEsc}','${nameEsc}')`],
  ];
  if (!d.agentless && dangerous) {
    operate.push([`docker compose${composeSuffix}`,
                  `openComposeModal('${idEsc}','${nameEsc}')`]);
  }
  operate.push(['Agent update', `sendUpdate('${idEsc}','${nameEsc}')`]);

  const configure = [
    ['Edit tags',       `openTagModal('${idEsc}','${escAttr((d.tags||[]).join(','))}')`],
    ['Set group',       `openGroupModal('${idEsc}','${escAttr(d.group||'')}')`],
    ['Notes',           `openNotesModal('${idEsc}','${escAttr(d.notes||'')}')`],
    ['Poll interval',   `openPollModal('${idEsc}','${d.poll_interval||60}')`],
    ['Metric thresholds', `openMetricThresholds('${idEsc}','${nameEsc}')`],
    ['Allowlist',       `openAllowlistModal('${idEsc}')`],
    ['Icon',            `openIconModal('${idEsc}','${escAttr(d.icon||'')}')`],
    [`${isMonitored ? 'Disable' : 'Enable'} monitoring`,
                        `toggleMonitored('${idEsc}', ${isMonitored ? 'false' : 'true'})`],
  ];

  const itemsHtml = items =>
    items.map(([label, action]) =>
      `<a href="#" onclick="${action}; return false;">${label}</a>`).join('');

  // <details>/<summary> for collapsible groups; no JS needed.
  // The summary line uses the same styling as a regular item so the
  // visual rhythm doesn't break.
  const group = (label, items, opened) =>
    `<details class="dropdown-group"${opened ? ' open' : ''}>` +
      `<summary>${label}</summary>${itemsHtml(items)}</details>`;

  return `<div class="device-dropdown" id="dropdown-${idEsc}">` +
    `<button class="dropdown-btn" onclick="toggleDropdown('${idEsc}')">⋯</button>` +
    `<div class="dropdown-content compact">` +
      itemsHtml(power) +
      `<hr>` +
      group('Inspect',   inspect,   true) +    // open by default — most used
      group('Operate',   operate,   false) +
      group('Configure', configure, false) +
      `<hr>` +
      `<a href="#" onclick="removeDevice('${idEsc}'); return false;" ` +
         `style="color:var(--red)">Remove device</a>` +
    `</div></div>`;
}

// ─── v2.1.5: additional ✨ surfaces ────────────────────────────────────────

function aiDiagnoseService(serviceName, deviceName, state, subState, recentLogs) {
  const logs = Array.isArray(recentLogs) ? recentLogs.join('\n') : (recentLogs || '');
  openAIModal({
    title:    `✨ Diagnose ${serviceName}`,
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
    title:    `✨ Triage cert for ${host}`,
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
    title:    `✨ Prioritise updates for ${deviceName}`,
    system:   'prioritise_patches',
    userMsg:  `Device: ${deviceName}\n\nPending updates:\n${listText.slice(0, 6000)}`,
    context:  `patches:${deviceName}`,
    maxTokens: 1500,
  });
}

function aiExplainContainerLogs(containerName, image, logs) {
  if (!logs || !logs.trim()) { toast('No logs to explain', 'info'); return; }
  openAIModal({
    title:    `✨ Explain ${containerName} logs`,
    system:   'explain_container_logs',
    userMsg:  `Container: ${containerName}\nImage: ${image || '?'}\n\nLogs:\n${logs.slice(0, 8000)}`,
    context:  `container:${containerName}`,
    maxTokens: 1500,
  });
}

async function aiPrioritisePatchesForDevice(devId, devName) {
  // Pull the device's patch report and find the most recent upgrade-listing
  // command output (apt list --upgradable / dnf check-update / etc.) to
  // feed to the model. That output IS the package list.
  const data = await api('GET', `/patch-report/device/${encodeURIComponent(devId)}`);
  if (!data?.patch_history?.length) {
    toast('No patch-check output recorded yet — agent hasn\'t run one', 'info');
    return;
  }
  const listing = data.patch_history.slice().reverse().find(o =>
    /upgradable|check-update|list-upgrades|outdated|pacman -Qu/i.test(o.cmd) && o.output
  );
  if (!listing) {
    toast('No upgrade listing output in patch history', 'info');
    return;
  }
  aiPrioritisePatches(devName, listing.output);
}
