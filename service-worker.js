// A basic service worker for PWA functionality.
// This handles the installation and activation steps.
self.addEventListener('install', (event) => {
console.log('Service Worker installed');
self.skipWaiting();
});

self.addEventListener('activate', (event) => {
console.log('Service Worker activated');
event.waitUntil(clients.claim());
});

// An event listener for fetch requests.
// We are not adding any caching logic, so we will not interfere with network requests.
self.addEventListener('fetch', (event) => {
// If we wanted to add caching, we would put the logic here.
});