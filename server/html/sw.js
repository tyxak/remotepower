/**
 * RemotePower — Service Worker (v2.4.15)
 *
 * Strategy:
 *   - App shell (HTML, JS, CSS, icons): cache-first with network fallback.
 *     Assets are fetched and cached on SW install so the app loads instantly
 *     after the first visit, even on flaky connections.
 *   - /api/* requests: network-only, NEVER cached.
 *     Fleet data is live; serving stale API responses would show stale device
 *     states and could mislead operations decisions.
 *   - Everything else: network-first with cache fallback.
 *
 * Security notes:
 *   - The SW is served with Cache-Control: no-store (see nginx config), so the
 *     browser always fetches the current version and detects upgrades within
 *     one page load.
 *   - We never cache responses that carry credentials (cookies, X-Token headers).
 *   - CACHE_NAME is versioned; on activation we delete all caches that don't
 *     match the current name, preventing stale-cache confusion after upgrades.
 */

const CACHE_NAME = 'remotepower-shell-v2.6.0';

// Files cached on install — the minimum set needed for the app to load.
// Paths must match what nginx actually serves at those URLs.
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/static/js/app.js',
  '/static/css/styles.css',
  '/static/img/logo-square.png',
  '/static/img/logo-primary.png',
  '/static/img/icon-192.png',
  '/static/img/icon-512.png',
  '/favicon.ico',
  '/favicon.png',
  '/manifest.json',
];

// ── Install: pre-cache the app shell ─────────────────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Use individual add() calls so one missing asset doesn't abort the
      // whole pre-cache. Errors are logged but installation proceeds.
      return Promise.allSettled(
        SHELL_ASSETS.map((url) =>
          cache.add(new Request(url, { credentials: 'same-origin' })).catch((err) => {
            console.warn('[SW] Pre-cache miss:', url, err.message);
          })
        )
      );
    }).then(() => self.skipWaiting())
  );
});

// ── Activate: delete stale caches from previous versions ─────────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => {
            console.info('[SW] Deleting stale cache:', key);
            return caches.delete(key);
          })
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: routing logic ──────────────────────────────────────────────────────
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // 1. Only intercept same-origin requests.
  if (url.origin !== self.location.origin) return;

  // 2. /api/* — network-only. Never serve stale fleet data from cache.
  //    If the network is down the app's own error handling shows "offline".
  if (url.pathname.startsWith('/api/')) return;

  // 3. Non-GET requests (POST, DELETE, PATCH) — pass through uncached.
  if (request.method !== 'GET') return;

  // 4. App shell assets — cache-first.
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;

      // Not in cache — fetch from network and cache the response.
      return fetch(request).then((response) => {
        // Only cache successful, opaque-free responses.
        if (!response || response.status !== 200 || response.type === 'error') {
          return response;
        }
        const toCache = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, toCache));
        return response;
      }).catch(() => {
        // Network failed and nothing in cache — return a minimal offline page
        // only for navigation requests; let sub-resources fail naturally.
        if (request.mode === 'navigate') {
          return caches.match('/index.html');
        }
      });
    })
  );
});
