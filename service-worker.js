const CACHE_NAME = 'tekeze-maintenance-v1';
const urlsToCache = [
'/',
'manifest.json',
'/android-chrome-192x192.png',
'/android-chrome-512x512.png'
];

self.addEventListener('install', (event) => {
console.log('Service Worker: Installing...');
event.waitUntil(
caches.open(CACHE_NAME)
.then((cache) => {
console.log('Service Worker: Caching assets');
return cache.addAll(urlsToCache);
})
.catch((error) => {
console.error('Service Worker: Failed to cache assets:', error);
})
);
});

self.addEventListener('fetch', (event) => {
event.respondWith(
caches.match(event.request)
.then((response) => {
// Return the cached asset if it exists
if (response) {
return response;
}
// Otherwise, fetch from the network
return fetch(event.request);
})
);
});

self.addEventListener('activate', (event) => {
console.log('Service Worker: Activating...');
event.waitUntil(
caches.keys().then((cacheNames) => {
return Promise.all(
cacheNames.map((cacheName) => {
if (cacheName !== CACHE_NAME) {
console.log('Service Worker: Deleting old cache', cacheName);
return caches.delete(cacheName);
}
})
);
})
);
});