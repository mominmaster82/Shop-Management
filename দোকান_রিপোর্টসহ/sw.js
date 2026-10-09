const CACHE_NAME = 'shop-management-pwa-v12';
const XLSX_URL = 'https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js';
const APP_SHELL = [
  './index.html',
  './gemini-code-1791165977457.html',
  './app.js',
  './manifest.webmanifest',
  './icon-192.svg',
  './icon-512.svg'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(async () => {
        try {
          const cache = await caches.open(CACHE_NAME);
          const request = new Request(XLSX_URL, { mode: 'no-cors' });
          await cache.put(request, await fetch(request));
        } catch (error) {
          console.warn('Excel library was not cached during install:', error);
        }
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(cacheNames => Promise.all(
        cacheNames
          .filter(cacheName => cacheName.startsWith('shop-management-pwa-') && cacheName !== CACHE_NAME)
          .map(cacheName => caches.delete(cacheName))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;

  if (request.url === XLSX_URL) {
    event.respondWith(
      caches.open(CACHE_NAME).then(async cache => {
        const cachedResponse = await cache.match(request);
        if (cachedResponse) return cachedResponse;
        const response = await fetch(request);
        await cache.put(request, response.clone());
        return response;
      }).catch(async () => (await caches.match(request)) || Response.error())
    );
    return;
  }

  if (new URL(request.url).origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then(response => {
          const cachedResponse = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(request, cachedResponse));
          return response;
        })
        .catch(async () => {
          const cachedPage = await caches.match(request);
          return cachedPage || caches.match('./gemini-code-1791165977457.html');
        })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then(cachedResponse => cachedResponse || fetch(request))
  );
});
