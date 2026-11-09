// Offline shell for the installed app; live data always comes from the server.
const CACHE = 'seagent-shell-v10';
const SHELL = ['/', '/ui/theme.css', '/ui/app.css', '/ui/pages.css', '/ui/devauth.js', '/ui/devsec.js', '/ui/app.js', '/ui/surfaces.js', '/ui/pages.js', '/ui/ops.js', '/ui/work.js', '/ui/chat_menu.js', '/ui/keys.js', '/ui/split.js', '/ui/chat_menu.css', '/ui/connectors.css', '/ui/connectors.js', '/ui/star.svg', '/ui/icon.svg', '/ui/icons/icon-192.png'];
self.addEventListener('install', (e) => e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL))));
self.addEventListener('activate', (e) => e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))));
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || !SHELL.includes(u.pathname)) return;
  e.respondWith(fetch(e.request).then((r) => { const c = r.clone(); caches.open(CACHE).then((x) => x.put(e.request, c)); return r; }).catch(() => caches.match(e.request)));
});
