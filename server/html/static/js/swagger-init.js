/* RemotePower — Swagger UI initialiser.
   Moved out of the inline <script> in swagger.html as part of CSP L1
   (no 'unsafe-inline'). Loaded after the swagger-ui-bundle script so
   `SwaggerUIBundle` is already defined when this runs. */
(function () {
  'use strict';

  // Pull the session token from wherever the main app stashed it. We support
  // both 'remember-me' (localStorage) and per-tab (sessionStorage) sessions.
  // Key name must match the dashboard exactly — see getToken() in app.js.
  function getToken() {
    return localStorage.getItem('rp_token')
        || sessionStorage.getItem('rp_token')
        || '';
  }

  var token = getToken();
  var statusEl = document.getElementById('rp-status');

  if (!token) {
    statusEl.textContent = 'Not logged in';
    statusEl.classList.add('bad');
    // Build the "Not logged in" placeholder via DOM API so the styling
    // comes from a class (CSP-safe) rather than an inline style="…".
    var wrap = document.getElementById('swagger-ui');
    wrap.replaceChildren();
    var box = document.createElement('div');
    box.className = 'swagger-login-required';
    var h = document.createElement('h2'); h.textContent = 'Not logged in';
    var p = document.createElement('p');
    p.appendChild(document.createTextNode('Log in to the '));
    var a = document.createElement('a'); a.href = '/'; a.textContent = 'main dashboard';
    p.appendChild(a);
    p.appendChild(document.createTextNode(', then return here.'));
    box.appendChild(h);
    box.appendChild(p);
    wrap.appendChild(box);
    return;
  }

  // Fetch the spec ourselves (rather than letting Swagger UI fetch it)
  // because we need to attach the X-Token header. Swagger UI doesn't send
  // auth on the *spec* fetch, only on Try-It-Out requests.
  fetch('/api/openapi.json', { headers: { 'X-Token': token } })
    .then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then(function (spec) {
      document.getElementById('rp-version').textContent = 'v' + spec.info.version;
      statusEl.textContent = 'Loaded';
      statusEl.classList.add('ok');
      // Build Swagger UI with a request interceptor that auto-attaches the
      // user's session token to every Try-It-Out request. This keeps the
      // UX consistent with the dashboard — no Authorize button needed for
      // the common case.
      window.ui = SwaggerUIBundle({
        spec: spec,
        dom_id: '#swagger-ui',
        deepLinking: true,
        tryItOutEnabled: true,
        defaultModelsExpandDepth: 0,
        docExpansion: 'list',
        requestInterceptor: function (req) {
          req.headers['X-Token'] = token;
          return req;
        },
        presets: [SwaggerUIBundle.presets.apis],
        plugins: [SwaggerUIBundle.plugins.DownloadUrl],
      });
    })
    .catch(function (err) {
      statusEl.textContent = 'Failed: ' + err.message;
      statusEl.classList.add('bad');
      // Fallback: surface a plain-text message — better than a blank screen
      // if the vendored Swagger UI assets are missing for some reason.
      var fb = document.getElementById('fallback');
      fb.style.display = 'block';
      fb.textContent = 'Could not render Swagger UI (' + err.message + ').\n\n'
        + 'The raw spec is still available at /api/openapi.json.';
    });
}());
