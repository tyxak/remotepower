/* W6-28 customer portal — minimal vanilla JS, no shared code with the operator
 * app. Talks only to the closed /api/portal/* namespace; auth rides an HttpOnly
 * cookie the browser sends automatically (no token in JS). */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function api(method, path, body) {
    var opts = { method: method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    return fetch('/api/portal' + path, opts).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; });
    });
  }
  function show(id) { $(id).classList.remove('hidden'); }
  function hide(id) { $(id).classList.add('hidden'); }
  function fmt(ts) { return ts ? new Date(ts * 1000).toLocaleString() : ''; }

  // ── sign-in ────────────────────────────────────────────────────────────
  $('magic-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var st = $('magic-status'); st.className = 'status'; st.textContent = 'Sending…';
    api('POST', '/magic-link', { email: $('magic-email').value.trim() }).then(function (r) {
      st.className = 'status ok';
      st.textContent = (r.data && r.data.message) || 'If that email is registered, a link is on its way.';
    }).catch(function () { st.className = 'status err'; st.textContent = 'Could not send. Try again later.'; });
  });

  function adoptSession(token) {
    return api('POST', '/session', { token: token }).then(function (r) {
      if (!r.ok) { return false; }
      $('portal-who').textContent = 'Signed in as ' + esc(r.data.name || '');
      hide('portal-signin'); show('portal-app');
      history.replaceState(null, '', location.pathname);   // strip #token from the URL
      loadTickets();
      return true;
    });
  }

  $('portal-logout').addEventListener('click', function () {
    api('POST', '/logout').then(function () { location.reload(); });
  });

  // ── tickets ────────────────────────────────────────────────────────────
  function loadTickets() {
    hide('ticket-detail'); hide('new-ticket'); show('ticket-list');
    api('GET', '/tickets').then(function (r) {
      var box = $('ticket-list');
      if (!r.ok) { box.innerHTML = '<div class="hint">Could not load tickets.</div>'; return; }
      var ts = (r.data && r.data.tickets) || [];
      if (!ts.length) { box.innerHTML = '<div class="hint">No tickets yet.</div>'; return; }
      box.innerHTML = ts.map(function (t) {
        return '<div class="ticket-row" data-num="' + esc(t.number) + '">'
          + '<div><strong>#' + esc(t.number) + '</strong> ' + esc(t.subject) + '</div>'
          + '<span class="badge ' + esc(t.status) + '">' + esc(t.status) + '</span></div>';
      }).join('');
      Array.prototype.forEach.call(box.querySelectorAll('.ticket-row'), function (el) {
        el.addEventListener('click', function () { openTicket(el.getAttribute('data-num')); });
      });
    });
  }

  $('new-ticket-btn').addEventListener('click', function () { hide('ticket-list'); hide('ticket-detail'); show('new-ticket'); });
  $('nt-cancel').addEventListener('click', loadTickets);
  $('ticket-form').addEventListener('submit', function (e) {
    e.preventDefault();
    api('POST', '/tickets', { subject: $('nt-subject').value.trim(), message: $('nt-message').value.trim() }).then(function (r) {
      if (r.ok) { $('nt-subject').value = ''; $('nt-message').value = ''; loadTickets(); }
      else { alert((r.data && r.data.error) || 'Could not open ticket.'); }
    });
  });

  function openTicket(num) {
    api('GET', '/tickets/' + encodeURIComponent(num)).then(function (r) {
      if (!r.ok) { alert('Could not open ticket.'); return; }
      var t = r.data.ticket || {};
      hide('ticket-list'); hide('new-ticket'); show('ticket-detail');
      $('td-subject').textContent = '#' + num + ' ' + (t.subject || '');
      $('td-meta').textContent = (t.status || '') + ' · opened ' + fmt(t.created_at);
      $('td-thread').innerHTML = (t.messages || []).map(function (m) {
        return '<div class="msg ' + esc(m.from) + '"><div class="who">' + esc(m.from) + ' · ' + esc(fmt(m.at)) + '</div>'
          + esc(m.body) + '</div>';
      }).join('') || '<div class="hint">No messages yet.</div>';
      $('reply-form').onsubmit = function (e) {
        e.preventDefault();
        var msg = $('td-reply').value.trim();
        if (!msg) { return; }
        api('POST', '/tickets/' + encodeURIComponent(num) + '/reply', { message: msg }).then(function (rr) {
          if (rr.ok) { $('td-reply').value = ''; openTicket(num); }
          else { alert((rr.data && rr.data.error) || 'Could not send reply.'); }
        });
      };
    });
  }

  $('td-back').addEventListener('click', loadTickets);

  // ── boot: a #token in the URL means we arrived from a magic link ─────────
  (function boot() {
    var m = /[#&]token=([^&]+)/.exec(location.hash || '');
    if (m) { adoptSession(decodeURIComponent(m[1])).then(function (ok) { if (!ok) { $('magic-status').className = 'status err'; $('magic-status').textContent = 'That link is invalid or expired.'; } }); return; }
    // Maybe an existing session cookie is still valid — try listing tickets.
    api('GET', '/tickets').then(function (r) {
      if (r.ok) { hide('portal-signin'); show('portal-app'); loadTickets(); }
    });
  })();
})();
