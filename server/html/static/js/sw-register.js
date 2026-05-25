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
    // v3.0.4 (iter 4): persistent InvalidStateError. Earlier iterations
    // assumed the error was always transient. In practice a previous
    // SW registration can be stuck in a broken state (script 404'd at
    // some point, scope conflict, partitioned storage from an old tab)
    // and no retry chain alone fixes it — we have to unregister the
    // stuck worker first.
    //
    // Strategy:
    //   1. wait for `load` (document fully constructed)
    //   2. retry 4 × on InvalidStateError with linear backoff
    //   3. last-resort: unregister all existing SWs and try once more
    //   4. final failure → console.warn + remediation hint
    //   5. dedupe — `_kicked` guards against pageshow firing on both
    //      initial load AND BFCache restore (would otherwise queue two
    //      retry chains in parallel)
    //   6. log final failure only once even if multiple kicks slip past
    var _swAttempts = 0;
    var _swDone = false;
    var _unregisteredOnce = false;
    var _kicked = false;
    var _loggedFailure = false;
    var _logFinalFailure = function (err) {
      if (_loggedFailure) return;
      _loggedFailure = true;
      console.warn('[RemotePower] SW registration failed:', err);
      if (navigator.serviceWorker.controller) {
        console.warn('[RemotePower] An older Service Worker is still ' +
          'controlling this page. To clear: DevTools → Application → ' +
          'Service Workers → Unregister, then hard-reload.');
      }
    };
    var _registerSW = function () {
      if (_swDone) return;
      _swAttempts += 1;
      navigator.serviceWorker.register('/sw.js', { scope: '/' })
        .then(function (reg) {
          _swDone = true;
          reg.update();
        })
        .catch(function (err) {
          if (err && err.name === 'InvalidStateError' && _swAttempts < 4) {
            setTimeout(_registerSW, 750 * _swAttempts);
            return;
          }
          // Retry chain exhausted on InvalidStateError → assume a stuck
          // registration is blocking us. Unregister everything for our
          // scope and try once more from a clean slate. Once per
          // document so we can't loop.
          if (err && err.name === 'InvalidStateError' && !_unregisteredOnce) {
            _unregisteredOnce = true;
            navigator.serviceWorker.getRegistrations()
              .then(function (regs) {
                return Promise.all(regs.map(function (r) { return r.unregister(); }));
              })
              .then(function () {
                _swAttempts = 0;
                setTimeout(_registerSW, 500);
              })
              .catch(function () {
                _logFinalFailure(err);
              });
            return;
          }
          _logFinalFailure(err);
        });
    };
    var _kick = function () {
      if (_kicked) return;
      _kicked = true;
      if (document.readyState === 'complete') {
        _registerSW();
      } else {
        window.addEventListener('load', _registerSW, { once: true });
      }
    };
    // pageshow fires on both initial load and BFCache restore. _kicked
    // dedupes the synchronous _kick() vs the first pageshow event.
    window.addEventListener('pageshow', _kick);
    _kick();
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

  // Detect whether the app is installed.
  //
  // Three signals, any one of which counts as "installed":
  //   1. Currently loaded in standalone display mode (e.g. opened from
  //      the OS app launcher) — definitive for *this* page.
  //   2. iOS Safari's window.navigator.standalone (older API).
  //   3. localStorage flag set the first time we ever loaded in
  //      standalone mode — covers the case where the user installed,
  //      opened the PWA once (so the flag was written), and is now
  //      looking at the same origin in a normal browser tab. Chrome
  //      fires `beforeinstallprompt` again in that tab; we don't want
  //      to offer install when the user already has it.
  //
  // (3) is the only one that works in a regular browser tab — Chrome
  // doesn't expose "the user installed this PWA" to the page for
  // privacy reasons. We bootstrap the flag by writing it whenever the
  // PWA is opened in standalone (which happens at least once after
  // install since the OS launches the standalone window).
  var _PWA_INSTALLED_KEY = 'rp_pwa_installed';

  function _isStandalone() {
    try {
      if (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) return true;
      if (window.navigator.standalone === true) return true;
    } catch (_) {}
    return false;
  }

  function _isInstalledPwa() {
    if (_isStandalone()) return true;
    try {
      return localStorage.getItem(_PWA_INSTALLED_KEY) === '1';
    } catch (_) { return false; }
  }

  // Bootstrap: if we're currently loaded as standalone, the PWA is
  // installed — write the flag so future regular-tab loads on this
  // profile can suppress the install button.
  if (_isStandalone()) {
    try { localStorage.setItem(_PWA_INSTALLED_KEY, '1'); } catch (_) {}
  }

  function _revealInstallBtn() {
    if (_isInstalledPwa()) { _installPending = false; return; }
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
  // Persist the flag so the install button stays hidden on subsequent
  // page loads in a regular browser tab (Chrome will keep firing
  // beforeinstallprompt for the same profile, even after install).
  window.addEventListener('appinstalled', function () {
    _installPrompt = null;
    try { localStorage.setItem(_PWA_INSTALLED_KEY, '1'); } catch (_) {}
    _hideInstallBtn();
  });
}());
