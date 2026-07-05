/**
 * RemotePower — Service Worker (v3.0.3)
 *
 * Strategy:
 *   - HTML navigation requests: network-first with cache fallback.
 *     Guarantees refresh always shows the latest markup, eliminating the
 *     stale-cache icon flash on mobile pull-to-refresh.
 *   - Static assets (JS, CSS, icons): cache-first with network fallback.
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

const CACHE_NAME = 'remotepower-shell-v5.8.0-14';   // bump on every asset change

// Files cached on install — the minimum set needed for the app to load.
// Paths must match what nginx actually serves at those URLs.
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/static/js/i18n.js',
  '/static/js/app.js',
  '/static/js/app-calendar.js',
  '/static/js/app-cmdb.js',
  '/static/js/app-containers.js',
  '/static/js/app-network.js',
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
      // cache:'reload' bypasses the HTTP cache when pre-caching. The static
      // assets are served with Cache-Control: max-age, so the default fetch
      // mode would re-cache the STALE bundle from the browser HTTP cache on a
      // CACHE_NAME bump -- the edit then never reaches the user until the HTTP
      // entry expires. Forcing a network fetch makes the version bump reliable.
      return Promise.allSettled(
        SHELL_ASSETS.map((url) =>
          cache.add(new Request(url, { credentials: 'same-origin', cache: 'reload' })).catch((err) => {
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
    // v5.6.x perf: navigation preload — navigations are network-first below,
    // so without this the browser waits for SW startup before the request
    // even leaves. Preload starts it in parallel; the fetch handler consumes
    // event.preloadResponse. Optional-chained: not every engine supports it.
    ).then(() => self.registration.navigationPreload?.enable())
     .then(() => self.clients.claim())
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

  // 4. App shell assets — network-first for HTML navigation (prevents stale-cache
  //    flash on mobile refresh), cache-first for static assets (JS/CSS/images).
  if (request.mode === 'navigate') {
    // HTML pages: try network first so a refresh always gets the latest markup.
    // Fall back to cache only when offline. v5.6.x: consume the navigation-
    // preload response when present — that request was already in flight
    // before this handler even ran (see the activate hook).
    event.respondWith(
      Promise.resolve(event.preloadResponse)
        .then((preloaded) => preloaded || fetch(request))
        .then((response) => {
          if (response && response.status === 200) {
            const toCache = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, toCache));
          }
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match('/index.html')))
    );
    return;
  }

  // Static assets (JS, CSS, images) — cache-first for instant load.
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

// v3.14.0 #42: Web Push. The server sends {title, body, url}; show it, and on
// click focus an existing RemotePower tab (or open one) and navigate to url.
self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = {}; }
  const title = data.title || 'RemotePower';
  const options = {
    body: data.body || '',
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: data.tag || 'remotepower-alert',
    data: { url: data.url || '/' },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const c of clients) {
        if ('focus' in c) { c.focus(); if (target && 'navigate' in c) c.navigate(target); return; }
      }
      if (self.clients.openWindow) return self.clients.openWindow(target);
    })
  );
});
