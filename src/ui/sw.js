/**
 * Service worker.
 *
 * Deliberately narrow: it caches the application shell — the HTML, CSS and
 * JavaScript — and nothing else. It must NEVER cache an API response.
 *
 * Two reasons, and both are the product's whole argument:
 *
 * 1. A cached fact is a fact outside the walls. Read decisions depend on the
 *    reader's clearance, the folder's wall, legal holds and the kill switch,
 *    all evaluated at read time. A copy sitting in CacheStorage has escaped
 *    every one of them, survives a revocation, and would still be served after
 *    an erasure order was carried out.
 * 2. A cached kill-switch state is a lie at the worst possible moment. Someone
 *    checking on their phone during an incident must see the live state.
 *
 * So: offline, the shell loads and says it is offline. It does not show
 * yesterday's memory and call it today's.
 */
const SHELL = 'vault-shell-v1';
const ASSETS = ['/', '/index.html', '/app.css', '/app.js', '/i18n-bundle.js', '/manifest.json', '/icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(SHELL).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never touch the API. Not cache-first, not stale-while-revalidate, not at
  // all — go to the network and let a failure be a visible failure.
  if (url.pathname.startsWith('/api/')) return;

  // Shell assets: cache first for a fast cold start on a phone, with a network
  // update behind it so a deployed change is picked up on the next load.
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then((hit) => {
      const live = fetch(event.request)
        .then((res) => {
          if (res && res.ok) caches.open(SHELL).then((c) => c.put(event.request, res.clone()));
          return res;
        })
        .catch(() => hit);
      return hit || live;
    })
  );
});
