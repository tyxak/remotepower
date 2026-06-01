/* Standalone fleet posture report renderer.
 *
 * Loaded by report.html, which opens in its own tab. This page is served from
 * the web root under the normal nginx CSP (script-src 'self'; style-src 'self';
 * img-src 'self'), so EVERYTHING here must be external — no inline styles, no
 * inline handlers. It reuses the session token from localStorage/sessionStorage
 * (same origin as the app) to fetch the report JSON, renders a light document,
 * and offers Print / Save as PDF. Because it's a real same-origin page with its
 * own light stylesheet, the app's dark theme can't leak in — it prints
 * black-on-white. */
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

  function card(k, v, sub) {
    return '<div class="card"><div class="k">' + esc(k) + '</div>'
      + '<div class="v">' + esc(v) + '</div>'
      + '<div class="sub">' + esc(sub || '') + '</div></div>';
  }

  function render(rep, baseline) {
    const h = rep.health || {}, c = rep.cve || {}, p = rep.patches || {}, d = rep.devices || {};
    const fws = (rep.compliance && rep.compliance.frameworks) || {};
    const when = new Date((rep.generated_ts ? rep.generated_ts * 1000 : Date.now())).toLocaleString();

    el('pr-meta').textContent = 'Generated ' + when
      + (rep.server_version ? ' · RemotePower ' + rep.server_version : '');

    el('pr-cards').innerHTML =
        card('Health', (h.score != null ? h.score : '—') + '/100', h.grade || '')
      + card('Devices', (d.online || 0) + '/' + (d.total || 0), 'online')
      + card('Patches', p.total_pending || 0, (p.devices_with_patches || 0) + ' device(s)')
      + card('CVEs', (c.critical || 0) + (c.high || 0),
             (c.critical || 0) + ' crit · ' + (c.high || 0) + ' high');

    let html = '';
    const fwKeys = Object.keys(fws);
    if (fwKeys.length) {
      html += '<h2>Compliance frameworks</h2><table><thead><tr><th>Framework</th>'
        + '<th>Score</th></tr></thead><tbody>'
        + fwKeys.map(function (fw) {
            const s = fws[fw].score;
            return '<tr><td>' + esc(fw.toUpperCase()) + '</td><td>'
              + (s != null ? s + '%' : 'N/A') + '</td></tr>';
          }).join('')
        + '</tbody></table>';
    }
    if (baseline && Array.isArray(baseline.checks)) {
      html += '<h2>Configuration baseline'
        + (baseline.score != null ? ' — ' + baseline.score + '%' : '') + '</h2>'
        + '<table><thead><tr><th>Check</th><th>Severity</th><th>Pass</th><th>Fail</th>'
        + '<th>N/A</th></tr></thead><tbody>'
        + baseline.checks.map(function (ch) {
            const pa = ch.pass || 0, fa = ch.fail || 0;
            return '<tr><td>' + esc(ch.title) + '</td><td>' + esc(ch.severity) + '</td>'
              + '<td class="' + (pa ? 'ok' : '') + '">' + pa + '</td>'
              + '<td class="' + (fa ? 'bad' : '') + '">' + fa + '</td>'
              + '<td>' + (ch.na || 0) + '</td></tr>';
          }).join('')
        + '</tbody></table>';
    }
    el('pr-sections').innerHTML = html;
    el('pr-foot').textContent =
      'RemotePower fleet posture report — generated on demand. '
      + 'Figures reflect the latest data RemotePower has collected.';
    document.title = (rep.server_name || 'RemotePower') + ' — Fleet posture report';
  }

  async function init() {
    el('pr-print').addEventListener('click', function () { window.print(); });
    if (!token()) {
      el('pr-status').textContent =
        'Not signed in. Open this report from the RemotePower dashboard.';
      return;
    }
    try {
      const rep = await getJSON('/api/report/fleet');
      let baseline = null;
      try { baseline = await getJSON('/api/compliance/baseline'); } catch (_) { /* optional */ }
      el('pr-status').classList.add('hidden');
      el('pr-doc').classList.remove('hidden');
      render(rep, baseline);
    } catch (e) {
      el('pr-status').textContent = 'Failed to load the report (' + e.message + ').';
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
