const CACHE_NAME = 'KixoGames-v8-pwa';
const OFFLINE_URL = '/static/offline.html';

const ASSETS_TO_CACHE = [
    OFFLINE_URL,
    '/static/manifest.json',
    '/static/icon-192.png',
    '/static/icon-512.png'
];

// 🚀 Install Event - Precache Assets
self.addEventListener('install', event => {
    self.skipWaiting(); // Force the new service worker to activate immediately
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Opened cache and precaching offline assets');
                return cache.addAll(ASSETS_TO_CACHE);
            })
    );
});

// 🚀 Activate Event - Clean up old caches
self.addEventListener('activate', event => {
    self.clients.claim(); // Take control of all open pages immediately
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheName !== CACHE_NAME) {
                        console.log('Old cache deleted:', cacheName);
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});

// 🚀 Fetch Event - ULTRA STRICT OFFLINE FALLBACK
self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;

    // 🎯 1. HTML Page Requests (Strictly serve network, or fallback to offline.html)
    if (event.request.mode === 'navigate') {
        event.respondWith(
            fetch(event.request).catch(() => {
                return caches.match(OFFLINE_URL);
            })
        );
        return; // Stop processing further for HTML pages
    }

    // 🎯 2. Other Assets (Images, CSS, JS) - Try network, then fallback to cache
    event.respondWith(
        fetch(event.request).catch(() => {
            return caches.match(event.request);
        })
    );
});

// =====================================
// PUSH NOTIFICATION LOGIC
// =====================================
self.addEventListener('push', function (event) {
    let data = {
        title: 'New Game Alert! 🎮',
        body: 'A brand new game is waiting for you on KixoGames!',
        url: '/',
        icon: '/static/icon-192.png'
    };

    if (event.data) {
        try {
            let parsedData = event.data.json();
            // Merge defaults with parsed data
            data = { ...data, ...parsedData };
        } catch (e) {
            data.body = event.data.text();
        }
    }

    const options = {
        body: data.body,
        icon: data.icon || '/static/icon-192.png',
        badge: '/static/icon-192.png',
        image: data.image || null, // 🚀 Standard or Rich Media Support
        vibrate: [100, 50, 100],
        data: {
            dateOfArrival: Date.now(),
            url: data.url || '/'
        }
    };

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

self.addEventListener('notificationclick', function (event) {
    event.notification.close();
    event.waitUntil(
        clients.matchAll({ type: 'window' }).then(windowClients => {
            for (let i = 0; i < windowClients.length; i++) {
                const client = windowClients[i];
                if (client.url === event.notification.data.url && 'focus' in client) {
                    return client.focus();
                }
            }
            if (clients.openWindow) {
                return clients.openWindow(event.notification.data.url);
            }
        })
    );
});