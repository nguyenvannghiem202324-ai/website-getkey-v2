'use strict';
// GetKey server. Không cần npm install, chỉ cần Node 18+.   Chạy: node server.js
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// đọc file .env (KEY=VALUE mỗi dòng), biến môi trường thật vẫn được ưu tiên
try {
  for (const l of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !l.trim().startsWith('#') && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
} catch {}

// ───────────── cấu hình (đặt qua biến môi trường) ─────────────
const CFG = {
  port: +process.env.PORT || 3000,
  base: process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL                                    // Render tự cấp RENDER_EXTERNAL_URL
    || (process.env.CODESPACE_NAME ? `https://${process.env.CODESPACE_NAME}-${process.env.PORT || 3000}.${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN || 'app.github.dev'}` : 'http://localhost:3000'), // GitHub Codespaces
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'), // đặt cố định, không thì restart là mất phiên,
  dcId: process.env.DISCORD_CLIENT_ID,                           // FILL: discord.com/developers/applications
  dcSecret: process.env.DISCORD_CLIENT_SECRET,                   // FILL
  prod: process.env.NODE_ENV === 'production' || !!process.env.RENDER,
  trustProxy: process.env.TRUST_PROXY === '1' || !!process.env.RENDER, // Render chạy sau proxy
  keyTtl: +process.env.KEY_TTL_MS || 24 * 3600e3,                // mỗi key sống 24h
  l4Key: process.env.LINK4M_API_KEY || '6abb3a6daf162d46ec29b472',
  l4Api: process.env.LINK4M_API_URL || 'https://link4m.co/api-shorten/v2',
  minMs: +process.env.CP_MIN_MS || 15000,                        // vượt link nhanh hơn mức này = bypass, từ chối
  tokTtl: 15 * 60e3,                                             // mỗi link checkpoint sống 15 phút, dùng 1 lần
  steps: 3,
  db: path.join(process.env.DATA_DIR || __dirname, 'data.json'),  // có Render Disk thì đặt DATA_DIR=/var/data
  pub: path.join(__dirname, 'public'),
};
if (!process.env.SESSION_SECRET) console.warn('[warn] chưa đặt SESSION_SECRET, phiên đăng nhập sẽ mất mỗi lần restart');
if (CFG.prod && (!CFG.dcId || !CFG.l4Key)) { console.error('[fatal] thiếu biến môi trường: cần DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, LINK4M_API_KEY (đặt trong Render → Environment)'); process.exit(1); }

// ───────────── database: Upstash Redis (khuyên dùng trên Render free) hoặc file JSON ─────────────
// Render free không giữ file khi restart/deploy, nên cần Redis ngoài hoặc Render Disk.
let db = { users: {}, keys: {}, active: {}, prog: {}, issued: 0, week: 0, lb: {} };
const REDIS = process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN; // FILL: upstash.com → Redis → REST API
const RKEY = 'getkey:db';
const rcmd = cmd => fetch(process.env.UPSTASH_REDIS_REST_URL, {
  method: 'POST', headers: { Authorization: 'Bearer ' + process.env.UPSTASH_REDIS_REST_TOKEN },
  body: JSON.stringify(cmd), signal: AbortSignal.timeout(8000),
}).then(r => r.json());
async function loadDb() {
  if (REDIS) {
    try { const r = await rcmd(['GET', RKEY]); if (r.error) throw new Error(r.error); if (r.result) db = { ...db, ...JSON.parse(r.result) }; return; }
    catch (e) { console.error('[redis] không đọc được:', e.message); if (CFG.prod) process.exit(1); }   // không chạy với DB rỗng, tránh ghi đè mất dữ liệu
  }
  try { db = { ...db, ...JSON.parse(fs.readFileSync(CFG.db, 'utf8')) }; } catch {}
}
let dirty = false, flushing = false;
const save = () => { dirty = true; };
async function flush() {
  if (!dirty || flushing) return;
  dirty = false; flushing = true;
  try {
    const data = JSON.stringify(db);
    if (REDIS) { const r = await rcmd(['SET', RKEY, data]); if (r.error) throw new Error(r.error); }
    else { const tmp = CFG.db + '.tmp'; fs.writeFileSync(tmp, data); fs.renameSync(tmp, CFG.db); }
  } catch (e) { dirty = true; console.error('[db] lưu lỗi:', e.message); }
  flushing = false;
}
setInterval(flush, 3000).unref();
for (const sig of ['SIGINT', 'SIGTERM'])   // Render gửi SIGTERM khi deploy/restart: lưu xong rồi mới thoát
  process.on(sig, async () => { await Promise.race([flush(), new Promise(r => setTimeout(r, 4000))]); process.exit(0); });

// ───────────── phiên đăng nhập: cookie ký HMAC ─────────────
const sign = s => crypto.createHmac('sha256', CFG.secret).update(s).digest('base64url');
const mkSession = uid => {
  const p = Buffer.from(JSON.stringify({ uid, exp: Date.now() + 7 * 864e5 })).toString('base64url');
  return p + '.' + sign(p);
};
function readSession(tok) {
  if (!tok) return null;
  const [p, s] = tok.split('.');
  if (!p || !s) return null;
  const a = Buffer.from(sign(p)), b = Buffer.from(s);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o.uid : null; } catch { return null; }
}
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(c => c[0]));
const setCookie = (res, n, v, age) => {
  const prev = res.getHeader('Set-Cookie') || [];
  res.setHeader('Set-Cookie', [].concat(prev, `${n}=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${CFG.prod ? '; Secure' : ''}`));
};

// ───────────── logic key ─────────────
const now = () => Date.now();
const weekId = () => Math.floor(now() / (7 * 864e5));
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const block = () => Array.from({ length: 4 }, () => ALPHA[crypto.randomInt(ALPHA.length)]).join('');
const genKey = () => { let k; do k = `KEY-${block()}-${block()}-${block()}`; while (db.keys[k]); return k; };

// key còn hạn của user, hết hạn thì gỡ khỏi active để user được get lại
function activeKey(uid) {
  const k = db.active[uid];
  if (!k) return null;
  const r = db.keys[k];
  if (!r || r.exp <= now()) { delete db.active[uid]; save(); return null; }
  return { value: k, exp: r.exp };
}
function issue(uid) {
  const k = genKey(), t = now();
  db.keys[k] = { uid, created: t, exp: t + CFG.keyTtl };
  db.active[uid] = k;
  db.prog[uid] = { step: 0 };           // key mới thì phải làm lại 3 checkpoint
  db.issued++;
  if (db.week !== weekId()) { db.week = weekId(); db.lb = {}; }
  db.lb[uid] = (db.lb[uid] || 0) + 1;
  save();
  return { value: k, exp: db.keys[k].exp };
}
setInterval(() => {                      // dọn key hết hạn quá 1 giờ
  const cut = now() - 3600e3;
  for (const [k, r] of Object.entries(db.keys)) if (r.exp < cut) { delete db.keys[k]; save(); }
}, 60e3).unref();

// ───────────── tiện ích HTTP ─────────────
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const redirect = (res, to) => { res.writeHead(302, { Location: to }); res.end(); };
const ipOf = req => (CFG.trustProxy && req.headers['x-forwarded-for']?.split(',')[0].trim()) || req.socket.remoteAddress;
const hits = new Map();
function limited(ip, tag, max, perMs = 60e3) {
  const k = tag + ip, h = hits.get(k);
  if (!h || h.r < now()) { hits.set(k, { c: 1, r: now() + perMs }); return false; }
  return ++h.c > max;
}
setInterval(() => { for (const [k, h] of hits) if (h.r < now()) hits.delete(k); }, 60e3).unref();
const body = req => new Promise(ok => {
  let d = '';
  req.on('data', c => { d += c; if (d.length > 5e3) req.destroy(); });
  req.on('end', () => { try { ok(JSON.parse(d || '{}')); } catch { ok({}); } });
});
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
function serve(res, p) {
  const f = path.normalize(path.join(CFG.pub, p === '/' ? 'index.html' : p));
  if (!f.startsWith(CFG.pub)) return json(res, 403, { error: 'forbidden' });   // chặn ../
  fs.readFile(f, (e, buf) => {
    if (e) return json(res, 404, { error: 'not_found' });
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream' });
    res.end(buf);
  });
}

// ───────────── đăng nhập Discord ─────────────
function login(res, user) {
  db.users[user.id] = user; save();
  setCookie(res, 'sid', mkSession(user.id), 7 * 86400);
}
function authStart(req, res) {
  if (!CFG.dcId) {                       // chưa cấu hình Discord: đăng nhập tài khoản dev (chỉ khi không phải production)
    login(res, { id: 'dev', name: 'dev_user', avatar: null });
    return redirect(res, '/');
  }
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'st', state, 600);
  const q = new URLSearchParams({ client_id: CFG.dcId, response_type: 'code', redirect_uri: CFG.base + '/auth/callback', scope: 'identify', state });
  redirect(res, 'https://discord.com/oauth2/authorize?' + q);
}
async function authCb(u, ck, res) {
  const code = u.searchParams.get('code'), st = u.searchParams.get('state');
  if (!code || !st || st !== ck.st) return redirect(res, '/?e=auth');
  try {
    const tk = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CFG.dcId, client_secret: CFG.dcSecret, grant_type: 'authorization_code', code, redirect_uri: CFG.base + '/auth/callback' }),
    }).then(r => r.json());
    if (!tk.access_token) throw new Error('no token');
    const me = await fetch('https://discord.com/api/users/@me', { headers: { Authorization: 'Bearer ' + tk.access_token } }).then(r => r.json());
    if (!me.id) throw new Error('no user');
    setCookie(res, 'st', '', 0);
    login(res, { id: me.id, name: me.global_name || me.username, avatar: me.avatar });
    redirect(res, '/');
  } catch (e) { console.error('[auth]', e.message); redirect(res, '/?e=auth'); }
}

// ───────────── Link4M ─────────────
async function shorten(dest) {
  if (!CFG.l4Key) {                      // chưa có API key (dev): trả thẳng link đích để test luồng
    if (CFG.prod) throw new Error('thiếu LINK4M_API_KEY');
    return dest;
  }
  const r = await fetch(`${CFG.l4Api}?${new URLSearchParams({ api: CFG.l4Key, url: dest })}`, { signal: AbortSignal.timeout(8000) });
  const txt = (await r.text()).trim();
  let j; try { j = JSON.parse(txt); } catch {}
  const out = j?.shortenedUrl || j?.shortened_url || j?.data?.shortenedUrl || (/^https?:\/\/\S+$/.test(txt) ? txt : null);
  if (!out) throw new Error('phản hồi lạ: ' + txt.slice(0, 120));
  return out;
}
// Link4M đưa người dùng về đây sau khi vượt link xong
function cpDone(u, uid, res) {
  const pr = uid && db.prog[uid], tok = u.searchParams.get('t') || '';
  if (!pr || !pr.tok || pr.tok.length !== tok.length || !crypto.timingSafeEqual(Buffer.from(pr.tok), Buffer.from(tok)) || now() - pr.t > CFG.tokTtl)
    return redirect(res, '/?cp=bad');    // sai phiên / sai token / đã dùng / hết hạn
  const ok = pr.s === pr.step && now() - pr.t >= CFG.minMs;
  const fast = pr.s === pr.step && !ok;
  delete pr.tok; delete pr.url; delete pr.t; delete pr.s;   // token dùng 1 lần, dù đúng hay sai
  if (ok) pr.step = Math.min(CFG.steps, pr.step + 1);
  save();
  if (ok && pr.step >= CFG.steps && !activeKey(uid)) { issue(uid); return redirect(res, '/?cp=key'); }  // đủ 3 bước: cấp key ngay
  redirect(res, ok ? '/?cp=ok' : fast ? '/?cp=fast' : '/?cp=bad');
}

// ───────────── API ─────────────
async function api(req, res, p, u, uid) {
  const ip = ipOf(req);

  // công khai: app/script của bạn gọi để kiểm tra key
  if (p === '/api/validate') {
    if (limited(ip, 'v', 60)) return json(res, 429, { error: 'rate_limit' });
    const r = db.keys[(u.searchParams.get('key') || '').toUpperCase()];
    const left = r ? r.exp - now() : 0;
    return json(res, 200, { valid: left > 0, expiresIn: Math.max(0, Math.floor(left / 1000)) });
  }
  if (p === '/api/stats') {
    if (db.week !== weekId()) { db.week = weekId(); db.lb = {}; save(); }
    const leaderboard = Object.entries(db.lb).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .map(([id, count]) => ({ name: db.users[id]?.name || 'user', count }));
    const active = Object.keys(db.active).filter(id => activeKey(id)).length;
    return json(res, 200, { issued: db.issued, active, leaderboard });
  }

  const user = uid && db.users[uid];
  if (p === '/api/me') {
    const pr = db.prog[uid] || { step: 0 };
    return json(res, 200, { now: now(), user: user ? { id: user.id, name: user.name } : null, step: user ? pr.step : 0, key: user ? activeKey(uid) : null });
  }
  if (!user) return json(res, 401, { error: 'login' });
  if (req.method !== 'POST') return json(res, 405, { error: 'method' });

  if (p === '/api/logout') { setCookie(res, 'sid', '', 0); return json(res, 200, { ok: true }); }
  if (limited(ip, 'p', 40)) return json(res, 429, { error: 'rate_limit' });

  const pr = db.prog[uid] || (db.prog[uid] = { step: 0 });
  if (p === '/api/cp/start') {
    const { step } = await body(req);
    if (activeKey(uid)) return json(res, 409, { error: 'has_key' });     // còn key thì chưa được làm tiếp
    if (step !== pr.step) return json(res, 409, { error: 'bad_step' });  // phải đúng thứ tự
    if (pr.tok && pr.s === step && now() - pr.t < CFG.tokTtl) return json(res, 200, { url: pr.url }); // bấm lại: dùng link cũ, đỡ tốn quota API
    const tok = crypto.randomBytes(16).toString('hex');
    try {
      const url = await shorten(`${CFG.base}/cp/done?t=${tok}`);
      Object.assign(pr, { tok, url, s: step, t: now() }); save();
      return json(res, 200, { url });
    } catch (e) { console.error('[link4m]', e.message); return json(res, 502, { error: 'shortener' }); }
  }
  if (p === '/api/key') {
    const cur = activeKey(uid);
    if (cur) return json(res, 200, cur);                                  // idempotent: còn hạn thì trả lại key cũ
    if (pr.step < CFG.steps) return json(res, 403, { error: 'incomplete' });
    return json(res, 200, issue(uid));
  }
  json(res, 404, { error: 'not_found' });
}

// ───────────── server ─────────────
const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, CFG.base), p = u.pathname, ck = cookies(req), uid = readSession(ck.sid);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (p === '/healthz') return json(res, 200, { ok: true });   // Render health check / UptimeRobot
    if (p === '/auth/discord') return authStart(req, res);
    if (p === '/auth/callback') return await authCb(u, ck, res);
    if (p === '/cp/done') return cpDone(u, uid, res);
    if (p.startsWith('/api/')) {
      if (req.method === 'POST' && req.headers['x-gk'] !== '1') return json(res, 403, { error: 'csrf' });
      return await api(req, res, p, u, uid);
    }
    serve(res, p);
  } catch (e) { console.error(e); if (!res.headersSent) json(res, 500, { error: 'server' }); }
});
loadDb().then(() => server.listen(CFG.port, '0.0.0.0', () => console.log(`GetKey chạy tại ${CFG.base}  (${CFG.dcId ? 'Discord OAuth' : 'DEV login, chưa có Discord'} | Link4M: ${CFG.l4Key ? 'bật' : 'tắt, dùng link thẳng'} | DB: ${REDIS ? 'Upstash Redis' : CFG.db})`)));