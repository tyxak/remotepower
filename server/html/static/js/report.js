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

    // v6.4.2: white-label the printable report. An operator who set a brand name
    // still got "RemotePower" and the RemotePower logo on the artifact they hand
    // to a customer — the one surface where branding matters most. The server
    // now ships `brand` on both full and sectioned reports.
    const brand = (rep.brand && rep.brand.name) || '';
    const prod = brand || 'RemotePower';
    if (brand) {
      // Swap the wordmark for the operator's name rather than showing both.
      const logo = document.querySelector('.head img');
      if (logo) logo.classList.add('hidden');
      const h1 = document.querySelector('.head h1');
      if (h1) h1.textContent = brand + ' — Fleet posture report';
      const accent = (rep.brand && rep.brand.accent) || '';
      // A property assignment, not an inline style attribute — CSP-safe.
      if (accent) document.documentElement.style.setProperty('--pr-accent', accent);
    }

    el('pr-meta').textContent = 'Generated ' + when
      + (rep.server_version ? ' · ' + prod + ' ' + rep.server_version : '');

    el('pr-cards').innerHTML =
        card('Health', (h.score != null ? h.score : '—') + '/100', h.grade || '')
      + card('Devices', (d.online || 0) + '/' + (d.total || 0), 'online')
      + card('Patches', p.total_pending || 0, (p.devices_with_patches || 0) + ' device(s)')
      + card('CVEs', (c.critical || 0) + (c.high || 0),
             (c.critical || 0) + ' crit · ' + (c.high || 0) + ' high');

    let html = '';

    // v6.4.2: the narrative, first, above every figure. The reader this
    // document is printed for is usually the one who never logs in — they got
    // "Fleet health score: 82/100 · Patches: 9 device(s) pending" and no way to
    // tell whether that was good or what they were being asked to approve.
    const sm = rep.summary || {};
    if (sm.text) {
      html += '<h2>Summary</h2><p class="pr-summary">'
        + esc(sm.text).replace(/\n{2,}/g, '</p><p class="pr-summary">')
                      .replace(/\n/g, '<br>')
        + '</p>';
    }
    // v6.4.2: what changed over the window, not just where things stand.
    const per = rep.period || null;
    if (per) {
      const dur = function (s) {
        s = parseInt(s, 10) || 0;
        if (!s) return '—';
        const hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60);
        return hh ? hh + 'h' + String(mm).padStart(2, '0') : mm + 'm';
      };
      // 'n/a' rather than 0 when there is no comparable sample yet — a 0 would
      // read as "no change" when the truth is "not enough history".
      const dl = per.delta || {};
      const sgn = function (v, suffix) {
        if (v == null) return 'n/a';
        return (v > 0 ? '+' : '') + v + (suffix || '');
      };
      html += '<h2>Last ' + esc(String(per.days || 30)) + ' days</h2>'
        + '<table><tbody>'
        + '<tr><td>Alerts opened</td><td>' + (per.alerts_opened || 0) + '</td></tr>'
        + '<tr><td>Alerts resolved</td><td>' + (per.alerts_resolved || 0) + '</td></tr>'
        + '<tr><td>Median time to resolve</td><td>' + esc(dur(per.mttr_median)) + '</td></tr>'
        + '<tr><td>Mean time to acknowledge</td><td>' + esc(dur(per.mtta_mean)) + '</td></tr>'
        + '<tr><td>Update runs</td><td>' + (per.patches_applied_runs || 0) + '</td></tr>'
        + '<tr><td>Health score change</td><td>' + esc(sgn(dl.health_score)) + '</td></tr>'
        + '<tr><td>Compliance change</td><td>' + esc(sgn(dl.compliance_pct, ' pp')) + '</td></tr>'
        + '</tbody></table>';
    }
    // v6.4.2: host security posture — firewall, sshd hardening, encryption,
    // auto-update, each with its own reporting denominator so an absent signal
    // is never shown as a pass.
    const pos = rep.posture || {};
    const posRows = [
      ['Host firewall inactive', pos.firewall_off, pos.firewall_off_count, pos.firewall_reporting],
      ['Weak SSH configuration', pos.ssh_weak, pos.ssh_weak_count, pos.ssh_reporting],
      ['Automatic updates off', pos.autoupdate_off, pos.autoupdate_off_count, pos.autoupdate_reporting],
      ['Disk encryption off', pos.encryption_off, pos.encryption_off_count, pos.encryption_reporting],
    ].filter(function (r) { return (r[3] || 0) > 0; });
    if (posRows.length) {
      html += '<h2>Host security posture</h2><table><thead><tr><th>Finding</th>'
        + '<th>Affected / reporting</th><th>For example</th></tr></thead><tbody>'
        + posRows.map(function (r) {
            const n = r[2] || 0, rep_n = r[3] || 0;
            const ex = Array.isArray(r[1]) ? r[1].slice(0, 5).map(esc).join(', ') : '';
            return '<tr><td>' + esc(r[0]) + '</td>'
              + '<td class="' + (n ? 'bad' : 'ok') + '">' + n + ' / ' + rep_n + '</td>'
              + '<td>' + ex + '</td></tr>';
          }).join('')
        + '</tbody></table>';
    }
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
      prod + ' fleet posture report — generated on demand. '
      + 'Figures reflect the latest data ' + prod + ' has collected.';
    document.title = (brand || rep.server_name || 'RemotePower') + ' — Fleet posture report';
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
