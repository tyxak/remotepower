/* Service Worker registration + PWA install prompt handling.
   Kept separate from app.js so the SW registers even if app.js fails.
   Moved from inline <script> in index.html as part of CSP L1 fix. */
(function () {
  'use strict';

  // ── Service Worker registration ───────────────────────────────────────────
  //
  // v3.0.4 (iter 2): hardened against `InvalidStateError: The document is in
  // an invalid state`. Chrome throws this when register() runs during a
  // transient document state — BFCache restore, navigation in progress,
  // partitioned-storage hiccup. The previous code waited for the `load`
  // event then registered once; on slow networks or back/forward navigation,
  // `load` could fire after the document state was already wrong, the
  // registration would throw, the old (v3.0.3) SW kept running, and the
  // browser kept serving stale cached assets. Operators reported "page
  // looks broken after deploy" — the giant unstyled icon symptom.
  //
  // Three changes: register on DOMContentLoaded instead of load (fires
  // earlier, less timing-sensitive); retry once on InvalidStateError;
  // and check existing registrations to nudge a stuck SW.
  if ('serviceWorker' in navigator) {
    var _swAttempts = 0;
    var _registerSW = function () {
      _swAttempts += 1;
      navigator.serviceWorker.register('/sw.js', { scope: '/' })
        .then(function (reg) {
          // Force a check for an updated SW on every page load — without
          // this, the browser may serve the cached SW indefinitely.
          reg.update();
        })
        .catch(function (err) {
          // InvalidStateError is transient; one retry usually clears it.
          // Anything else is a real failure and we just warn — the app
          // still works without offline / installability.
          if (err && err.name === 'InvalidStateError' && _swAttempts < 2) {
            setTimeout(_registerSW, 750);
            return;
          }
          console.warn('[RemotePower] SW registration failed:', err);
          // If a previous SW is still controlling the page and we can't
          // register the new one, surface a hint to the operator so they
          // can clear it. Once. Console-only — no user-visible toast since
          // most installs work fine.
          if (navigator.serviceWorker.controller) {
            console.warn('[RemotePower] An older Service Worker is still ' +
              'controlling this page. To clear: DevTools → Application → ' +
              'Service Workers → Unregister, then hard-reload.');
          }
        });
    };
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', _registerSW);
    } else {
      // DOM is already ready (script lives at the end of <body>, so this
      // is the typical path). Register synchronously.
      _registerSW();
    }
  }

  // ── PWA install prompt ────────────────────────────────────────────────────
  //
  // v3.0.3 — two bugs fixed:
  //
  //   1. The CSS rule `#pwa-install-btn { display: none; }` in the <head>
  //      (specificity 0,1,0,0) was overriding the JS reveal. Setting
  //      element.style.display = '' just removes the *inline* property,
  //      after which the stylesheet rule took effect and kept the button
  //      hidden. Removed the stylesheet rule; the inline style="display:none"
  //      handles the initial hidden state, and we now set the display to
  //      an explicit 'inline-flex' value when revealing.
  //
  //   2. beforeinstallprompt can fire BEFORE DOMContentLoaded in Chrome
  //      (especially on a warm reload where the manifest+SW are already
  //      cached). The old code grabbed the button reference in a
  //      DOMContentLoaded handler and just bailed if the reference was
  //      null when the event fired — silently never showing the button
  //      again because beforeinstallprompt only fires once per session.
  //      Now we look the button up lazily inside the event handler and
  //      stash a pending-show flag if the DOM isn't ready yet.
  //
  var _installPrompt = null;
  var _installBtn    = null;
  var _installPending = false;

  function _revealInstallBtn() {
    if (!_installBtn) _installBtn = document.getElementById('pwa-install-btn');
    if (!_installBtn) { _installPending = true; return; }
    // Explicit value beats any future stylesheet rule with ID specificity.
    _installBtn.style.display = 'inline-flex';
    _installPending = false;
  }

  function _hideInstallBtn() {
    if (!_installBtn) _installBtn = document.getElementById('pwa-install-btn');
    if (_installBtn) _installBtn.style.display = 'none';
    _installPending = false;
  }

  window.addEventListener('DOMContentLoaded', function () {
    _installBtn = document.getElementById('pwa-install-btn');
    if (_installPending && _installPrompt) _revealInstallBtn();
  });

  // Chrome / Brave / Edge fire this when the PWA install criteria are met.
  // We intercept and stash the event so we can trigger it on demand from
  // the header button rather than letting the browser show its own UI.
  window.addEventListener('beforeinstallprompt', function (e) {
    e.preventDefault();
    _installPrompt = e;
    _revealInstallBtn();
  });

  // Called when the user clicks the Install button in the header.
  window.pwaInstall = function () {
    if (!_installPrompt) return;
    _hideInstallBtn();
    _installPrompt.prompt();
    _installPrompt.userChoice.then(function (result) {
      if (result.outcome === 'accepted') {
        console.info('[RemotePower] PWA installed');
      }
      _installPrompt = null;
    });
  };

  // Hide the button if the user installs via the browser's own UI.
  window.addEventListener('appinstalled', function () {
    _installPrompt = null;
    _hideInstallBtn();
  });
}());
