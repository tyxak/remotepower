// Public, standalone status page (v5.1.0). NOT the authenticated SPA — this
// file is loaded only by status.html, talks to exactly one endpoint
// (/api/public/status), and never touches app.js or any internal/admin route.
//
// CSP-safe by construction: external script (script-src 'self'), same-origin
// fetch, no inline handlers/styles. All dynamic text is inserted via the DOM
// API (textContent / createElement / appendChild) — never by building HTML
// strings from response data — so the page is XSS-safe even if the server is
// compromised. Wrapped in an IIFE so it leaks nothing into the global scope
// (avoids colliding with app.js globals under the shared js-load smoke test).
(function () {
  'use strict';

  var ENDPOINT = '/api/public/status';
  var REFRESH_MS = 60000;
  var SVG_NS = 'http://www.w3.org/2000/svg';

  var titleEl = document.getElementById('status-title');
  var bannerEl = document.getElementById('status-banner');
  var bodyEl = document.getElementById('status-body');
  var footEl = document.getElementById('status-foot');

  var refreshTimer = null;

  // ---- small DOM helpers ---------------------------------------------------
  function clear(node) {
    while (node && node.firstChild) { node.removeChild(node.firstChild); }
  }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) { n.className = cls; }
    if (text != null) { n.textContent = String(text); }
    return n;
  }
  // Lucide-style inline SVG icon (no emoji). `paths` is an array of <path d>.
  function icon(paths) {
    var svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    for (var i = 0; i < paths.length; i++) {
      var p = document.createElementNS(SVG_NS, 'path');
      p.setAttribute('d', paths[i]);
      svg.appendChild(p);
    }
    return svg;
  }

  // ---- formatting ----------------------------------------------------------
  function num(v) {
    return (typeof v === 'number' && isFinite(v)) ? v : null;
  }
  function fmtUptime(v) {
    var n = num(v);
    if (n == null) { return ''; }
    // trim to 2dp without trailing zero noise
    return (Math.round(n * 100) / 100) + '%';
  }
  function fmtAbs(ts) {
    var n = num(ts);
    if (!n) { return null; }
    try { return new Date(n * 1000).toLocaleString(); } catch (e) { return null; }
  }
  function fmtRelative(ts) {
    var n = num(ts);
    if (!n) { return 'just now'; }
    var diff = Math.floor(Date.now() / 1000) - n;
    if (diff < 0) { diff = 0; }
    if (diff < 60) { return diff + 's ago'; }
    if (diff < 3600) { return Math.floor(diff / 60) + 'm ago'; }
    if (diff < 86400) { return Math.floor(diff / 3600) + 'h ago'; }
    return Math.floor(diff / 86400) + 'd ago';
  }
  function fmtDuration(s) {
    var n = num(s);
    if (n == null || n < 0) { return ''; }
    if (n < 60) { return n + 's'; }
    var m = Math.floor(n / 60);
    if (m < 60) { return m + 'm'; }
    var h = Math.floor(m / 60);
    var rm = m % 60;
    if (h < 24) { return rm ? (h + 'h ' + rm + 'm') : (h + 'h'); }
    var d = Math.floor(h / 24);
    var rh = h % 24;
    return rh ? (d + 'd ' + rh + 'h') : (d + 'd');
  }

  // ---- status → presentation mapping --------------------------------------
  // Component/incident status words → pill class + label.
  function statusClass(word) {
    switch (String(word || '').toLowerCase()) {
      case 'operational': return 'sp-ok';
      case 'degraded':
      case 'partial_outage': return 'sp-degraded';
      case 'major_outage':
      case 'down':
      case 'offline': return 'sp-down';
      // W2-25 operator-posted incident states
      case 'resolved': return 'sp-ok';
      case 'monitoring': return 'sp-degraded';
      case 'investigating':
      case 'identified': return 'sp-down';
      default: return '';
    }
  }
  function statusLabel(word) {
    var w = String(word || '').toLowerCase();
    if (!w) { return 'Unknown'; }
    return w.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  // ---- overall banner ------------------------------------------------------
  var OVERALL = {
    operational: { cls: 'sp-ok', text: 'All systems operational',
      paths: ['M22 11.08V12a10 10 0 1 1-5.93-9.14', 'M22 4 12 14.01l-3-3'] },
    degraded: { cls: 'sp-degraded', text: 'Degraded performance',
      paths: ['M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
              'M12 9v4', 'M12 17h.01'] },
    major_outage: { cls: 'sp-down', text: 'Major outage',
      paths: ['M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z',
              'M12 9v4', 'M12 17h.01'] }
  };
  function renderBanner(overall) {
    clear(bannerEl);
    bannerEl.className = 'status-banner';
    var key = String(overall || 'operational').toLowerCase();
    var spec = OVERALL[key] || OVERALL.operational;
    bannerEl.classList.add(spec.cls);
    bannerEl.appendChild(icon(spec.paths));
    bannerEl.appendChild(el('span', null, spec.text));
  }

  // ---- pill element --------------------------------------------------------
  function pillEl(word) {
    var cls = statusClass(word);
    var p = el('span', 'status-pill' + (cls ? ' ' + cls : ''), statusLabel(word));
    return p;
  }

  // ---- components (grouped) ------------------------------------------------
  function renderComponents(components) {
    var section = el('section', 'status-section');
    section.appendChild(el('h2', 'status-section-title', 'Components'));

    // group preserving first-seen order
    var order = [];
    var groups = {};
    for (var i = 0; i < components.length; i++) {
      var c = components[i] || {};
      var g = (typeof c.group === 'string' && c.group) ? c.group : 'Components';
      if (!groups[g]) { groups[g] = []; order.push(g); }
      groups[g].push(c);
    }

    for (var j = 0; j < order.length; j++) {
      var gname = order[j];
      var gwrap = el('div', 'status-group');
      gwrap.appendChild(el('div', 'status-group-title', gname));
      var list = el('div', 'status-comp-list');
      var rows = groups[gname];
      for (var k = 0; k < rows.length; k++) {
        var comp = rows[k] || {};
        var row = el('div', 'status-comp-row');
        row.appendChild(el('div', 'status-comp-name', comp.name || comp.id || 'Component'));
        var right = el('div', 'status-comp-right');
        var up = fmtUptime(comp.uptime_pct);
        if (up) { right.appendChild(el('span', 'status-uptime', up)); }
        right.appendChild(pillEl(comp.status));
        row.appendChild(right);
        list.appendChild(row);
      }
      gwrap.appendChild(list);
      section.appendChild(gwrap);
    }
    return section;
  }

  // ---- summary fallback (devices + monitors) -------------------------------
  function renderSummary(data) {
    var section = el('section', 'status-section');
    var dev = data.devices || {};
    var mon = data.monitors || {};

    var cards = el('div', 'status-cards');
    var health = data.health || {};
    if (num(health.score) != null) {
      var hc = el('div', 'status-card');
      hc.appendChild(el('div', 'status-card-k', 'Health'));
      var hv = String(health.score);
      if (typeof health.grade === 'string' && health.grade) { hv += ' (' + health.grade + ')'; }
      hc.appendChild(el('div', 'status-card-v', hv));
      cards.appendChild(hc);
    }
    if (num(dev.total) != null) {
      var dc = el('div', 'status-card');
      dc.appendChild(el('div', 'status-card-k', 'Devices online'));
      dc.appendChild(el('div', 'status-card-v',
        (num(dev.online) != null ? dev.online : '?') + ' / ' + dev.total));
      cards.appendChild(dc);
    }
    if (num(mon.total) != null) {
      var mc = el('div', 'status-card');
      mc.appendChild(el('div', 'status-card-k', 'Monitors up'));
      mc.appendChild(el('div', 'status-card-v',
        (num(mon.up) != null ? mon.up : '?') + ' / ' + mon.total));
      cards.appendChild(mc);
    }
    // master-improvement-scoping #51: RemotePower's own observed uptime,
    // distinct from the fleet devices/monitors above.
    var cp = data.control_plane || {};
    var cpWin = (cp.windows && cp.windows['30d']) || (cp.windows && cp.windows['7d']);
    if (cpWin && num(cpWin.percent) != null) {
      var cc = el('div', 'status-card');
      cc.appendChild(el('div', 'status-card-k', 'This status page'));
      cc.appendChild(el('div', 'status-card-v', cpWin.percent + '% uptime'));
      cards.appendChild(cc);
    }
    if (cards.childNodes.length) { section.appendChild(cards); }

    var items = (mon && Array.isArray(mon.items)) ? mon.items : [];
    if (items.length) {
      section.appendChild(el('h2', 'status-section-title', 'Monitors'));
      var list = el('div', 'status-mon-list');
      for (var i = 0; i < items.length; i++) {
        var m = items[i] || {};
        var row = el('div', 'status-mon-row');
        row.appendChild(pillEl(m.up ? 'operational' : 'down'));
        row.appendChild(el('span', 'status-comp-name', m.label || 'Monitor'));
        list.appendChild(row);
      }
      section.appendChild(list);
    } else if (!section.childNodes.length) {
      section.appendChild(el('p', 'status-message', 'No status details are available yet.'));
    }
    return section;
  }

  // ---- incidents -----------------------------------------------------------
  function renderIncidents(incidents, windowDays) {
    var section = el('section', 'status-section');
    var heading = 'Incident history';
    if (num(windowDays) != null) { heading += ' (last ' + windowDays + ' days)'; }
    section.appendChild(el('h2', 'status-section-title', heading));

    var wrap = el('div', 'status-incidents');
    for (var i = 0; i < incidents.length; i++) {
      var inc = incidents[i] || {};
      var row = el('div', 'status-incident');

      var main = el('div', 'status-incident-main');
      main.appendChild(el('div', 'status-incident-name', inc.component || inc.group || 'Incident'));

      var started = fmtAbs(inc.started_ts);
      var resolved = fmtAbs(inc.resolved_ts);
      var range;
      if (started && resolved) { range = started + ' → ' + resolved; }
      else if (started) { range = started + ' → ongoing'; }
      else { range = 'ongoing'; }
      var dur = fmtDuration(inc.duration_s);
      if (dur) { range += ' · ' + dur; }
      main.appendChild(el('div', 'status-incident-meta', range));
      row.appendChild(main);

      row.appendChild(pillEl(inc.status));
      wrap.appendChild(row);
    }
    section.appendChild(wrap);
    return section;
  }

  // ---- operator-posted incidents -------------------------------------------
  function renderPostedIncidents(posted) {
    var section = el('section', 'status-section');
    section.appendChild(el('h2', 'status-section-title', 'Incidents'));
    var wrap = el('div', 'status-incidents');
    for (var i = 0; i < posted.length; i++) {
      var inc = posted[i] || {};
      var row = el('div', 'status-incident');
      var main = el('div', 'status-incident-main');
      main.appendChild(el('div', 'status-incident-name', inc.title || 'Incident'));
      var when = fmtAbs(inc.created_at);
      main.appendChild(el('div', 'status-incident-meta',
        (when ? when : '') + (inc.impact ? ' · ' + inc.impact : '')));
      // latest update body (textContent — never innerHTML)
      var ups = Array.isArray(inc.updates) ? inc.updates : [];
      if (ups.length && ups[ups.length - 1].body) {
        main.appendChild(el('div', 'status-incident-body', ups[ups.length - 1].body));
      }
      row.appendChild(main);
      row.appendChild(pillEl(inc.status));
      wrap.appendChild(row);
    }
    section.appendChild(wrap);
    return section;
  }

  // ---- whole-page render ---------------------------------------------------
  function render(data) {
    data = data || {};

    var pageTitle = (typeof data.title === 'string' && data.title) ? data.title
      : ((typeof data.server_name === 'string' && data.server_name) ? data.server_name : 'Status');
    titleEl.textContent = pageTitle;
    document.title = pageTitle;

    renderBanner(data.overall);

    clear(bodyEl);
    var posted = Array.isArray(data.posted_incidents) ? data.posted_incidents : [];
    if (posted.length) {
      bodyEl.appendChild(renderPostedIncidents(posted));
    }
    var components = Array.isArray(data.components) ? data.components : [];
    if (components.length) {
      bodyEl.appendChild(renderComponents(components));
    } else {
      bodyEl.appendChild(renderSummary(data));
    }

    var incidents = Array.isArray(data.incidents) ? data.incidents : [];
    if (incidents.length) {
      bodyEl.appendChild(renderIncidents(incidents, data.window_days));
    }

    clear(footEl);
    var when = fmtRelative(data.generated_ts);
    footEl.appendChild(el('span', null, 'Updated ' + when + ' · Powered by RemotePower'));
  }

  // ---- non-data message states --------------------------------------------
  function showMessage(text) {
    clear(bannerEl);
    bannerEl.className = 'status-banner';
    clear(bodyEl);
    bodyEl.appendChild(el('p', 'status-message', text));
    clear(footEl);
  }

  // ---- load ----------------------------------------------------------------
  function getToken() {
    try { return new URLSearchParams(location.search).get('token') || ''; }
    catch (e) { return ''; }
  }

  function load() {
    var token = getToken();
    if (!token) {
      showMessage('This status page link is missing its token.');
      return Promise.resolve();
    }
    return fetch(ENDPOINT + '?token=' + encodeURIComponent(token), {
      method: 'GET',
      credentials: 'omit',
      headers: { 'Accept': 'application/json' }
    }).then(function (resp) {
      if (resp.status === 401) {
        var err = new Error('unavailable');
        err.handled = true;
        showMessage('This status page is not available.');
        throw err;
      }
      if (!resp.ok) { throw new Error('http ' + resp.status); }
      return resp.json();
    }).then(function (data) {
      render(data);
    }).catch(function (e) {
      if (e && e.handled) { return; }            // 401 already messaged
      showMessage('Unable to load status.');
    });
  }

  // ---- boot + non-stacking, visibility-aware 60s refresh ------------------
  // Recursive setTimeout (schedule the next poll only AFTER the current one
  // settles) so a slow board fetch can't stack overlapping requests, and skip
  // polling entirely while the tab is backgrounded (a public NOC board left
  // open all day shouldn't keep hammering the heaviest aggregate endpoint).
  function start() {
    function schedule() {
      if (refreshTimer !== null) { return; }
      refreshTimer = setTimeout(function () {
        refreshTimer = null;
        if (document.hidden) { schedule(); return; }   // defer; recheck next cycle
        load().then(schedule, schedule);
      }, REFRESH_MS);
    }
    load().then(schedule, schedule);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start);
  } else {
    start();
  }
})();
