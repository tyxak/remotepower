/* Standalone Fleet Query print view (v4.1.0).
 *
 * Loaded by fleet-query.html in its own tab. Served under the normal strict CSP
 * (script-src 'self'; style-src 'self'; img-src 'self'), so EVERYTHING here is
 * external — no inline styles or handlers. It reuses the session token from
 * localStorage/sessionStorage (same origin) to re-run the query (the filters
 * arrive in this page's own query string) and renders a light, printable table.
 * Because it's a real same-origin page with its own light stylesheet, the app's
 * dark theme can't leak in — it prints black-on-white. Mirrors report.js. */
(function () {
  'use strict';

  function token() {
    try {
      return localStorage.getItem('rp_token') || sessionStorage.getItem('rp_token') || '';
    } catch (_) { return ''; }
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (ch) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch];
    });
  }

  function el(id) { return document.getElementById(id); }

  async function getJSON(path) {
    const r = await fetch(path, { headers: { 'X-Token': token() } });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  }

  function criteria() {
    // Echo the active filters (everything except format) so the printout is
    // self-describing.
    const parts = [];
    new URLSearchParams(location.search).forEach(function (v, k) {
      if (k !== 'format' && v) parts.push(k + '=' + v);
    });
    return parts.length ? 'Filters: ' + parts.join(', ') : 'Filters: none (all devices)';
  }

  function render(data) {
    const rows = data.devices || [];
    el('fq-meta').textContent = 'Generated ' + new Date().toLocaleString()
      + ' · ' + (data.total != null ? data.total : rows.length) + ' device(s)';
    el('fq-criteria').textContent = criteria();
    const head = '<tr><th>Device</th><th>Group</th><th>OS</th><th>Agent</th>'
      + '<th>Online</th><th>Pending</th><th>CPU%</th><th>Mem%</th><th>CVE</th></tr>';
    const body = rows.map(function (d) {
      return '<tr><td>' + esc(d.name) + '</td>'
        + '<td>' + esc(d.group || '—') + '</td>'
        + '<td>' + esc(d.os || '—') + '</td>'
        + '<td>' + esc(d.version || '—') + '</td>'
        + '<td>' + (d.online ? 'yes' : 'no') + '</td>'
        + '<td>' + (d.pending == null ? '—' : d.pending) + '</td>'
        + '<td>' + (d.cpu == null ? '—' : Math.round(d.cpu) + '%') + '</td>'
        + '<td>' + (d.mem == null ? '—' : Math.round(d.mem) + '%') + '</td>'
        + '<td>' + (d.cve_high == null ? '—' : d.cve_high) + '</td></tr>';
    }).join('');
    el('fq-table').innerHTML = rows.length
      ? '<table><thead>' + head + '</thead><tbody>' + body + '</tbody></table>'
      : '<p>No devices match the criteria.</p>';
    el('fq-foot').textContent =
      'RemotePower fleet query — generated on demand. '
      + 'Figures reflect the latest data RemotePower has collected.';
  }

  async function init() {
    el('fq-print').addEventListener('click', function () { window.print(); });
    if (!token()) {
      el('fq-status').textContent =
        'Not signed in. Open this report from the RemotePower dashboard.';
      return;
    }
    try {
      const data = await getJSON('/api/fleet/query' + location.search);
      el('fq-status').classList.add('hidden');
      el('fq-doc').classList.remove('hidden');
      render(data);
    } catch (e) {
      el('fq-status').textContent = 'Failed to load the report (' + e.message + ').';
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
