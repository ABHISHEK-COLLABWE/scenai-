/* SceneAI Service Worker — PWA offline shell */
const CACHE   = 'sceneai-v2';
const OFFLINE = '/offline.html';
const SHELL   = ['/', '/index.html', '/manifest.json', OFFLINE];

/* Install: pre-cache the app shell */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

/* Activate: remove old caches */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

/* Fetch strategy:
   - API calls: network-only (never cache video data)
   - App shell:  cache-first, fallback to network
   - Everything else: network-first, fallback to cache, fallback to offline page
*/
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  /* API and video streams — never cache, always network */
  if (url.pathname.startsWith('/api/')) {
    e.respondWith(
      fetch(e.request).catch(() =>
        new Response(JSON.stringify({ error: 'Offline — server not reachable' }), {
          headers: { 'Content-Type': 'application/json' },
          status:  503,
        })
      )
    );
    return;
  }

  /* App shell — cache first */
  if (SHELL.includes(url.pathname) || url.pathname === '/') {
    e.respondWith(
      caches.match(e.request).then(cached => cached || fetch(e.request))
    );
    return;
  }

  /* Everything else — network first with cache fallback */
  e.respondWith(
    fetch(e.request)
      .then(resp => {
        const clone = resp.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
        return resp;
      })
      .catch(() =>
        caches.match(e.request).then(cached => cached || caches.match(OFFLINE))
      )
  );
});
