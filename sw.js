// دفتر ع الفرازة — service worker: يفتح أسرع ويشتغل لو النت ضعيف
const V='fz-v1';
const CORE=['./','./index.html','./manifest.json','./icon-192.png','./icon-512.png','./logo-white.png','./config.js'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(V).then(c=>c.addAll(CORE)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{const r=e.request;if(r.method!=='GET')return;const u=new URL(r.url);if(u.origin!==location.origin)return;
  // الصفحة: من النت الأول عشان أي تحديث يوصل على طول، ولو النت مقطوع من الكاش
  e.respondWith(fetch(r).then(res=>{if(res.ok){const cp=res.clone();caches.open(V).then(c=>c.put(r,cp))}return res}).catch(()=>caches.match(r).then(m=>m||caches.match('./index.html'))))});
