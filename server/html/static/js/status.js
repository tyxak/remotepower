// v3.4.1: read-only public status page. Standalone (no app.js, no session) —
// reads ?token= from the URL and polls /api/public/status. CSP-safe: external
// script, fetch to same-origin, dynamic colour set via the CSSOM (not inline).
(function () {
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  var GRADE = { good: '#22c55e', fair: '#d4a017', poor: '#ff8c00', critical: '#ef4444' };
  var token = new URLSearchParams(location.search).get('token') || '';
  var body = document.getElementById('status-body');
  var title = document.getElementById('status-title');
  var foot = document.getElementById('status-foot');

  function pill(label, ok) {
    return '<span class="status-pill ' + (ok ? 'ok' : 'down') + '">' + esc(label) + '</span>';
  }

  async function load() {
    if (!token) {
      body.innerHTML = '<div class="status-err">Missing <code>?token=</code> in the URL.</div>';
      return;
    }
    var r;
    try {
      var resp = await fetch('/api/public/status?token=' + encodeURIComponent(token));
      if (!resp.ok) throw new Error('bad status');
      r = await resp.json();
    } catch (e) {
      body.innerHTML = '<div class="status-err">Status unavailable — check the token.</div>';
      return;
    }
    title.textContent = (r.server_name || 'RemotePower') + ' — Status';
    var g = (r.health && r.health.grade) || 'good';
    var col = GRADE[g] || '#64748b';
    var dev = r.devices || {};
    var mon = r.monitors || {};
    var monRows = (mon.items || []).map(function (m) {
      return '<div class="status-mon">' + pill(m.up ? 'UP' : 'DOWN', m.up) + ' ' + esc(m.label) + '</div>';
    }).join('') || '<div class="c-muted">No monitors configured.</div>';
    body.innerHTML =
      '<div class="status-score"><div class="status-num" id="sn">' + esc(r.health && r.health.score) + '</div>'
      + '<div class="status-grade" id="sg">' + esc(g) + '</div></div>'
      + '<div class="status-cards">'
      + '<div class="status-card"><div class="status-k">Devices online</div><div class="status-v">' + esc(dev.online) + ' / ' + esc(dev.total) + '</div></div>'
      + '<div class="status-card"><div class="status-k">Monitors up</div><div class="status-v">' + esc(mon.up) + ' / ' + esc(mon.total) + '</div></div>'
      + '</div>'
      + '<h2 class="status-h2">Monitors</h2>' + monRows;
    var sn = document.getElementById('sn');
    var sg = document.getElementById('sg');
    if (sn) sn.style.color = col;
    if (sg) sg.style.color = col;
    foot.textContent = 'Updated ' + new Date((r.generated_ts || 0) * 1000).toLocaleString();
  }
  load();
  setInterval(load, 60000);
})();
