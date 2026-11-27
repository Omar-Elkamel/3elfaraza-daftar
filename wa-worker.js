// ع الفرازة — واتساب ↔ الدفتر (Cloudflare Worker)
// يستقبل رسايل واتساب من Meta ويكتبها في Firestore، ويبعت ردود الدفتر، ويعرض الصور.
// الأسرار (بتتكتب في إعدادات الـ Worker، مش هنا):
//   APP_SECRET  : App secret بتاع تطبيق Meta
//   SA_JSON     : مفتاح service account من Firebase (JSON كامل)
// قيم عادية (vars):
//   APP_ID, VERIFY_TOKEN, PROJECT_ID=elfaraza, OWNERS=x.omar00@gmail.com,shahdkarawia4@gmail.com, GRAPH_V=v26.0
//   ALLOW_ORIGIN=https://omar-elkamel.github.io

const G = env => `https://graph.facebook.com/${env.GRAPH_V || 'v26.0'}`;
let fsTok = null, fsTokExp = 0, jwks = null, jwksExp = 0, cfg = null, cfgAt = 0;

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url), p = url.pathname.replace(/\/+$/, '') || '/';
    if (req.method === 'OPTIONS') return cors(env, req, new Response(null, { status: 204 }));
    try {
      if (p === '/webhook' && req.method === 'GET') {
        const q = url.searchParams;
        if (q.get('hub.mode') === 'subscribe' && q.get('hub.verify_token') === env.VERIFY_TOKEN) return new Response(q.get('hub.challenge') || '');
        return new Response('forbidden', { status: 403 });
      }
      if (p === '/webhook' && req.method === 'POST') {
        const raw = await req.text();
        if (!(await sigOk(env, raw, req.headers.get('x-hub-signature-256') || ''))) return new Response('bad signature', { status: 401 });
        ctx.waitUntil(handleHook(env, JSON.parse(raw)).catch(e => console.log('hook', e && e.stack || e)));
        return new Response('ok');
      }
      if (p === '/health') { const c = await getCfg(env).catch(() => null); return cors(env, req, json({ ok: true, connected: !!(c && c.token && c.phoneId) })) }
      if (p === '/send' && req.method === 'POST') { const u = await authUser(env, req); return cors(env, req, await send(env, await req.json(), u)) }
      if (p.startsWith('/media/') && req.method === 'GET') { await authUser(env, req); return cors(env, req, await media(env, decodeURIComponent(p.slice(7)))) }
      if (p === '/onboard' && req.method === 'POST') { const u = await authUser(env, req, true); return cors(env, req, await onboard(env, await req.json(), u)) }
      if (p === '/sync' && req.method === 'POST') { await authUser(env, req, true); return cors(env, req, await startSync(env)) }
      return new Response('ع الفرازة 🌿', { headers: { 'content-type': 'text/plain; charset=utf-8' } });
    } catch (e) {
      const st = e && e.status || 500; return cors(env, req, json({ error: String(e && e.message || e) }, st));
    }
  }
};

/* ---------- helpers ---------- */
const json = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json; charset=utf-8' } });
function cors(env, req, r) {
  const o = req.headers.get('origin') || '', allow = (env.ALLOW_ORIGIN || 'https://omar-elkamel.github.io').split(',');
  const h = new Headers(r.headers);
  if (allow.includes(o) || /^http:\/\/localhost(:\d+)?$/.test(o)) { h.set('access-control-allow-origin', o); h.set('vary', 'origin') }
  h.set('access-control-allow-headers', 'authorization, content-type'); h.set('access-control-allow-methods', 'GET, POST, OPTIONS');
  return new Response(r.body, { status: r.status, headers: h });
}
const err = (m, s) => Object.assign(new Error(m), { status: s });
const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uStr = s => b64u(new TextEncoder().encode(s));
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
async function sigOk(env, raw, sig) {
  if (!env.APP_SECRET || !sig.startsWith('sha256=')) return false;
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.APP_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = [...new Uint8Array(await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(raw)))].map(b => b.toString(16).padStart(2, '0')).join('');
  const a = sig.slice(7); if (a.length !== mac.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ mac.charCodeAt(i); return d === 0;
}
const docId = s => String(s).replace(/[\/#?]/g, '_').slice(0, 500);

/* ---------- Firestore (service account) ---------- */
async function fsToken(env) {
  if (fsTok && Date.now() < fsTokExp - 60000) return fsTok;
  const sa = JSON.parse(env.SA_JSON), now = Math.floor(Date.now() / 1000);
  const head = b64uStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' })), body = b64uStr(JSON.stringify({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/datastore', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = b64u(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(head + '.' + body)));
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + head + '.' + body + '.' + sig });
  const j = await r.json(); if (!j.access_token) throw err('firestore auth failed', 500);
  fsTok = j.access_token; fsTokExp = Date.now() + j.expires_in * 1000; return fsTok;
}
const fsBase = env => `https://firestore.googleapis.com/v1/projects/${env.PROJECT_ID || 'elfaraza'}/databases/(default)/documents`;
const fsName = (env, path) => `projects/${env.PROJECT_ID || 'elfaraza'}/databases/(default)/documents/${path}`;
function toF(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  if (typeof v === 'string') return { stringValue: v };
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toF) } };
  return { mapValue: { fields: Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => [k, toF(x)])) } };
}
function fromF(f) {
  if (!f) return undefined; if ('stringValue' in f) return f.stringValue; if ('integerValue' in f) return Number(f.integerValue); if ('doubleValue' in f) return f.doubleValue;
  if ('booleanValue' in f) return f.booleanValue; if ('nullValue' in f) return null; if ('arrayValue' in f) return (f.arrayValue.values || []).map(fromF);
  if ('mapValue' in f) return Object.fromEntries(Object.entries(f.mapValue.fields || {}).map(([k, x]) => [k, fromF(x)])); return undefined;
}
async function fsGet(env, path) {
  const r = await fetch(`${fsBase(env)}/${path}`, { headers: { authorization: 'Bearer ' + await fsToken(env) } });
  if (r.status === 404) return null; const j = await r.json(); if (!r.ok) throw err('fs get ' + r.status, 500);
  return Object.fromEntries(Object.entries(j.fields || {}).map(([k, x]) => [k, fromF(x)]));
}
// writes: [{path, data, merge:true|false, inc:{field:n}}]
async function fsCommit(env, writes) {
  for (let i = 0; i < writes.length; i += 450) {
    const ws = writes.slice(i, i + 450).map(w => {
      w = { ...w, data: Object.fromEntries(Object.entries(w.data).filter(([, x]) => x !== undefined)) };
      const o = { update: { name: fsName(env, w.path), fields: toF(w.data).mapValue.fields } };
      if (w.merge !== false) o.updateMask = { fieldPaths: Object.keys(w.data).map(k => /^[a-zA-Z_][a-zA-Z_0-9]*$/.test(k) ? k : '`' + k + '`') };
      if (w.inc) o.updateTransforms = Object.entries(w.inc).map(([k, n]) => ({ fieldPath: k, increment: { integerValue: String(n) } }));
      return o;
    });
    const r = await fetch(`${fsBase(env)}:commit`, { method: 'POST', headers: { authorization: 'Bearer ' + await fsToken(env), 'content-type': 'application/json' }, body: JSON.stringify({ writes: ws }) });
    if (!r.ok) throw err('fs commit ' + r.status + ' ' + (await r.text()).slice(0, 300), 500);
  }
}
async function getCfg(env) {
  if (cfg && Date.now() - cfgAt < 60000) return cfg;
  cfg = (await fsGet(env, 'wa_private/cfg')) || {}; cfgAt = Date.now(); return cfg;
}

/* ---------- auth (Firebase ID token من الدفتر) ---------- */
async function authUser(env, req, ownerOnly) {
  const t = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, ''); if (!t) throw err('login required', 401);
  const [h, b, s] = t.split('.'); if (!s) throw err('bad token', 401);
  const head = JSON.parse(new TextDecoder().decode(unb64u(h))), pl = JSON.parse(new TextDecoder().decode(unb64u(b)));
  if (!jwks || Date.now() > jwksExp) { const r = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'); jwks = (await r.json()).keys; jwksExp = Date.now() + 3600e3 }
  const jwk = jwks.find(k => k.kid === head.kid); if (!jwk) { jwks = null; throw err('unknown key', 401) }
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, unb64u(s), new TextEncoder().encode(h + '.' + b));
  const pid = env.PROJECT_ID || 'elfaraza', now = Date.now() / 1000;
  if (!ok || pl.aud !== pid || pl.iss !== 'https://securetoken.google.com/' + pid || pl.exp < now || !pl.email || !pl.email_verified) throw err('bad token', 401);
  const email = pl.email.toLowerCase(), owners = String(env.OWNERS || '').toLowerCase().split(',').map(x => x.trim()).filter(Boolean);
  if (owners.includes(email)) return { email, role: 'owner' };
  if (ownerOnly) throw err('owners only', 403);
  const u = await fsGet(env, 'users/' + encodeURIComponent(email)).catch(() => null);
  if (u && (u.role === 'owner' || u.role === 'staff')) return { email, role: u.role };
  throw err('not allowed', 403);
}

/* ---------- webhook ---------- */
function norm(m) {
  const t = m.type, o = { type: t, text: '' };
  if (t === 'text') o.text = m.text && m.text.body || '';
  else if (['image', 'video', 'audio', 'document', 'sticker'].includes(t)) { const x = m[t] || {}; o.media = x.id || ''; o.mime = x.mime_type || ''; o.text = x.caption || x.filename || ''; if (x.link) o.link = x.link }
  else if (t === 'location') { const l = m.location || {}; o.lat = l.latitude; o.lng = l.longitude; o.text = l.name || l.address || '' }
  else if (t === 'reaction') { o.text = m.reaction && m.reaction.emoji || ''; o.ref = m.reaction && m.reaction.message_id || '' }
  else if (t === 'button') { o.type = 'text'; o.text = m.button && m.button.text || '' }
  else if (t === 'interactive') { const i = m.interactive || {}; o.type = 'text'; o.text = (i.button_reply && i.button_reply.title) || (i.list_reply && i.list_reply.title) || '' }
  else if (t === 'contacts') { o.text = (m.contacts || []).map(c => c.name && c.name.formatted_name).filter(Boolean).join('، ') }
  else if (t === 'order') { o.type = 'text'; o.text = '🛒 طلب من الكتالوج' }
  else o.text = '';
  if (m.context && m.context.id) o.reply = m.context.id;
  return o;
}
const lastOf = (o, dir) => ({ dir, type: o.type, text: String(o.text || '').slice(0, 200) });

async function handleHook(env, body) {
  for (const en of body.entry || []) for (const ch of en.changes || []) {
    const v = ch.value || {}, field = ch.field, biz = String(v.metadata && v.metadata.display_phone_number || '').replace(/\D/g, '');
    if (field === 'messages') {
      const names = {}; (v.contacts || []).forEach(c => { if (c.wa_id) names[c.wa_id] = c.profile && c.profile.name || '' });
      for (const m of v.messages || []) await incoming(env, m, names[m.from] || '');
      for (const s of v.statuses || []) {
        const st = s.status; if (!['sent', 'delivered', 'read', 'failed'].includes(st)) continue;
        await fsCommit(env, [{ path: 'wa_msgs/' + docId(s.id), data: { st, ...(st === 'failed' && s.errors ? { err: String(s.errors[0] && (s.errors[0].title || s.errors[0].message) || '').slice(0, 200) } : {}) } }]).catch(() => { });
      }
    } else if (field === 'smb_message_echoes') {
      for (const m of v.message_echoes || []) await outgoingEcho(env, m);
    } else if (field === 'history') {
      for (const h of v.history || []) for (const th of h.threads || []) await history(env, th, biz);
    }
  }
}
async function incoming(env, m, name) {
  const chat = String(m.from), o = norm(m), at = Number(m.timestamp) * 1000 || Date.now();
  const cur = await fsGet(env, 'wa_chats/' + chat).catch(() => null) || {};
  const status = cur.status === 'ordered' ? 'ordered' : 'new';
  const writes = [{ path: 'wa_msgs/' + docId(m.id), data: { chat, dir: 'in', ...o, at, wamid: m.id } }];
  if (o.type !== 'reaction' || !cur.last) writes.push({ path: 'wa_chats/' + chat, data: { ...(name ? { name } : {}), last: lastOf(o, 'in'), lastAt: at, lastInAt: at, status }, inc: { unread: 1 } });
  else writes.push({ path: 'wa_chats/' + chat, data: { lastInAt: at, ...(name ? { name } : {}) } });
  await fsCommit(env, writes);
}
async function outgoingEcho(env, m) {
  const chat = String(m.to), o = norm(m), at = Number(m.timestamp) * 1000 || Date.now();
  const cur = await fsGet(env, 'wa_chats/' + chat).catch(() => null) || {};
  await fsCommit(env, [{ path: 'wa_msgs/' + docId(m.id), data: { chat, dir: 'out', ...o, at, via: 'app', st: 'sent', wamid: m.id } },
  { path: 'wa_chats/' + chat, data: { last: lastOf(o, 'out'), lastAt: Math.max(at, cur.lastAt || 0), unread: 0, ...(!cur.status || cur.status === 'new' ? { status: 'wait' } : {}) } }]);
}
async function history(env, th, biz) {
  const chat = String(th.id || ''); if (!chat) return; const ms = th.messages || []; if (!ms.length) return;
  const writes = []; let last = null, lastIn = 0;
  for (const m of ms) {
    const out = String(m.from || '') === biz || (m.from && String(m.from) !== chat), o = norm(m), at = Number(m.timestamp) * 1000 || 0;
    writes.push({ path: 'wa_msgs/' + docId(m.id), data: { chat, dir: out ? 'out' : 'in', ...o, at, via: out ? 'app' : undefined, st: out ? (m.history_context && m.history_context.status || 'read').toLowerCase() : undefined, wamid: m.id, hist: true } });
    if (!last || at > last.at) last = { at, o, dir: out ? 'out' : 'in' }; if (!out && at > lastIn) lastIn = at;
  }
  const cur = await fsGet(env, 'wa_chats/' + chat).catch(() => null);
  if (!cur || (cur.lastAt || 0) < last.at) writes.push({ path: 'wa_chats/' + chat, data: { last: lastOf(last.o, last.dir), lastAt: last.at, ...(lastIn && (!cur || (cur.lastInAt || 0) < lastIn) ? { lastInAt: lastIn } : {}), ...(!cur ? { status: 'done', unread: 0 } : {}) } });
  await fsCommit(env, writes);
}

/* ---------- send ---------- */
async function graph(env, path, opt = {}) {
  const c = await getCfg(env); if (!c.token) throw err('الواتساب لسه مش متربط', 409);
  const r = await fetch(G(env) + path, { ...opt, headers: { authorization: 'Bearer ' + c.token, ...(opt.headers || {}) } });
  const j = await r.json().catch(() => ({})); if (!r.ok) throw err((j.error && (j.error.error_user_msg || j.error.message)) || ('graph ' + r.status), r.status === 401 ? 502 : 400); return j;
}
async function send(env, b, u) {
  const c = await getCfg(env); if (!c.phoneId) throw err('الواتساب لسه مش متربط', 409);
  const to = String(b.to || '').replace(/\D/g, ''); if (to.length < 8) throw err('رقم غلط', 400);
  let msg, rec;
  if (b.text) { const t = String(b.text).slice(0, 4096); msg = { type: 'text', text: { body: t, preview_url: /https?:\/\//.test(t) } }; rec = { type: 'text', text: t } }
  else if (b.image) {
    const cap = String(b.caption || '').slice(0, 1024);
    if (b.image.link) { msg = { type: 'image', image: { link: b.image.link, caption: cap } }; rec = { type: 'image', link: b.image.link, text: cap } }
    else {
      const d = String(b.image.data || ''), raw = d.includes(',') ? d.split(',')[1] : d, mime = b.image.mime || 'image/jpeg';
      const bytes = Uint8Array.from(atob(raw), x => x.charCodeAt(0)); if (bytes.length > 5e6) throw err('الصورة كبيرة', 400);
      const fd = new FormData(); fd.append('messaging_product', 'whatsapp'); fd.append('type', mime); fd.append('file', new Blob([bytes], { type: mime }), 'photo.jpg');
      const up = await graph(env, `/${c.phoneId}/media`, { method: 'POST', body: fd });
      msg = { type: 'image', image: { id: up.id, caption: cap } }; rec = { type: 'image', media: up.id, mime, text: cap };
    }
  } else throw err('مافيش رسالة', 400);
  const r = await graph(env, `/${c.phoneId}/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messaging_product: 'whatsapp', recipient_type: 'individual', to, ...msg }) });
  const id = r.messages && r.messages[0] && r.messages[0].id || ('local' + Date.now()), at = Date.now();
  await fsCommit(env, [{ path: 'wa_msgs/' + docId(id), data: { chat: to, dir: 'out', ...rec, at, via: 'api', st: 'sent', by: u.email, wamid: id } },
  { path: 'wa_chats/' + to, data: { last: lastOf(rec, 'out'), lastAt: at, unread: 0 } }]);
  return json({ ok: true, id });
}
async function media(env, id) {
  if (!/^[\w.-]{1,80}$/.test(id)) throw err('bad id', 400);
  const c = await getCfg(env); const info = await graph(env, `/${id}`);
  const r = await fetch(info.url, { headers: { authorization: 'Bearer ' + c.token } }); if (!r.ok) throw err('media ' + r.status, 404);
  return new Response(r.body, { headers: { 'content-type': info.mime_type || r.headers.get('content-type') || 'application/octet-stream', 'cache-control': 'private, max-age=86400' } });
}

/* ---------- onboarding (Embedded Signup + Coexistence) ---------- */
async function onboard(env, b, u) {
  const code = String(b.code || ''), waba = String(b.waba_id || ''), phoneId = String(b.phone_number_id || '');
  if (!code || !waba) throw err('ناقص بيانات من فيسبوك', 400);
  const tr = await fetch(`${G(env)}/oauth/access_token?client_id=${encodeURIComponent(env.APP_ID)}&client_secret=${encodeURIComponent(env.APP_SECRET)}&code=${encodeURIComponent(code)}`);
  const tj = await tr.json(); if (!tj.access_token) throw err('فيسبوك مارجعش توكن: ' + JSON.stringify(tj.error || tj).slice(0, 200), 400);
  const token = tj.access_token;
  let pid = phoneId, disp = '';
  const pl = await (await fetch(`${G(env)}/${waba}/phone_numbers?fields=id,display_phone_number,verified_name`, { headers: { authorization: 'Bearer ' + token } })).json();
  if (pl.data && pl.data.length) { const x = pl.data.find(y => y.id === phoneId) || pl.data[0]; pid = x.id; disp = x.display_phone_number || '' }
  const sub = await (await fetch(`${G(env)}/${waba}/subscribed_apps`, { method: 'POST', headers: { authorization: 'Bearer ' + token } })).json();
  await fsCommit(env, [{ path: 'wa_private/cfg', data: { token, wabaId: waba, phoneId: pid, display: disp, by: u.email, at: Date.now() }, merge: false },
  { path: 'settings/main', data: { waLinked: { phone: disp, at: Date.now() } } }]);
  cfg = null;
  const sync = await startSync(env).then(r => r.json()).catch(e => ({ error: String(e.message || e) }));
  return json({ ok: true, phone: disp, subscribed: !!sub.success, sync });
}
async function startSync(env) {
  const c = await getCfg(env); const out = {};
  for (const t of ['smb_app_state_sync', 'history']) {
    try { out[t] = await graph(env, `/${c.phoneId}/smb_app_data`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ messaging_product: 'whatsapp', sync_type: t }) }) } catch (e) { out[t] = { error: String(e.message || e) } }
  }
  return json(out);
}
