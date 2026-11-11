// © 2026 AutomobileTeslas. All rights reserved.
require('dotenv').config();
for (const k of ['DATABASE_URL', 'BREVO_API_KEY', 'MAIL_FROM_EMAIL', 'RESEND_API_KEY', 'ADMIN_EMAIL', 'ADMIN_PASSWORD'])
  if (process.env[k]) process.env[k] = process.env[k].trim(); // removes stray spaces from pasted values

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY'); // other sites cannot embed ours
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});
app.set('trust proxy', 1);
const jsonSmall = express.json({ limit: '10kb' }), jsonBig = express.json({ limit: '1mb' }); // orders carry a receipt image
app.use((req, res, next) => (req.path === '/api/order' ? jsonBig : jsonSmall)(req, res, next));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 900 })); // general (the chat refreshes often)
const strict = rateLimit({ windowMs: 15 * 60 * 1000, max: 60 });     // sign-up, login, orders, messages
const adminLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }); // admin password tries
const couponLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 40 }); // coupon guessing
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ---- Storage: a PostgreSQL database when DATABASE_URL is set, otherwise a temporary file ----
let pool = null, dbReady = false;
if (process.env.DATABASE_URL) {
  try {
    const { Pool } = require('pg');
    const u = new URL(process.env.DATABASE_URL);
    u.searchParams.delete('channel_binding');
    pool = new Pool({ connectionString: u.toString(), max: 5, idleTimeoutMillis: 30000 });
    pool.on('error', (e) => console.error('Database error:', e.message));
  } catch (e) {
    console.error('Could not start the database connection:', e.message);
  }
}
const FILE_USERS = path.join(__dirname, 'data', 'users.json');
const FILE_ORDERS = path.join(__dirname, 'data', 'orders.json');
const FILE_MSGS = path.join(__dirname, 'data', 'messages.json');
const FILE_COUPONS = path.join(__dirname, 'data', 'coupons.json');
fs.mkdirSync(path.dirname(FILE_USERS), { recursive: true });
const readJson = (f, d) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : d);

async function initDb() {
  if (!pool) return;
  await pool.query('CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())');
  await pool.query('CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now(), email TEXT NOT NULL, data JSONB NOT NULL)');
  await pool.query('CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now(), email TEXT NOT NULL, sender TEXT NOT NULL, body TEXT NOT NULL, seen BOOLEAN NOT NULL DEFAULT false)');
  await pool.query('CREATE INDEX IF NOT EXISTS messages_email ON messages (email)');
  await pool.query('CREATE TABLE IF NOT EXISTS coupons (code TEXT PRIMARY KEY, percent INT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())');
  await pool.query("INSERT INTO coupons (code, percent) SELECT * FROM (VALUES ('WELCOME60', 60), ('KROEGER60', 60)) AS v(code, percent) WHERE NOT EXISTS (SELECT 1 FROM coupons)");
  dbReady = true;
}
async function getUser(email) {
  if (pool) {
    const r = await pool.query('SELECT email, name, password_hash FROM users WHERE email = $1', [email]);
    const u = r.rows[0];
    return u ? { email: u.email, name: u.name, passwordHash: u.password_hash } : null;
  }
  return readJson(FILE_USERS, {})[email] || null;
}
async function createUser(user) {
  if (pool) {
    const r = await pool.query('INSERT INTO users (email, name, password_hash) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING RETURNING email', [user.email, user.name, user.passwordHash]);
    return r.rowCount === 1;
  }
  const all = readJson(FILE_USERS, {});
  if (all[user.email]) return false;
  all[user.email] = user;
  fs.writeFileSync(FILE_USERS, JSON.stringify(all, null, 2));
  return true;
}
// ---- Support chat storage ----
async function addMessage(email, sender, body) {
  const m = { id: crypto.randomBytes(6).toString('hex'), email, sender, body, at: new Date().toISOString(), seen: false };
  if (pool) { await pool.query('INSERT INTO messages (id, email, sender, body, seen) VALUES ($1, $2, $3, $4, false)', [m.id, email, sender, body]); return m; }
  const all = readJson(FILE_MSGS, []); all.push(m); fs.writeFileSync(FILE_MSGS, JSON.stringify(all, null, 2)); return m;
}
async function threadFor(email) {
  if (pool) {
    const r = await pool.query('SELECT id, sender, body, created_at AS sent_at FROM messages WHERE email = $1 ORDER BY created_at ASC LIMIT 500', [email]);
    return r.rows.map((x) => ({ id: x.id, sender: x.sender, body: x.body, at: x.sent_at }));
  }
  return readJson(FILE_MSGS, []).filter((m) => m.email === email).map(({ id, sender, body, at }) => ({ id, sender, body, at }));
}
async function markSeen(email, sender) {
  if (pool) { await pool.query('UPDATE messages SET seen = true WHERE email = $1 AND sender = $2 AND seen = false', [email, sender]); return; }
  const all = readJson(FILE_MSGS, []); let changed = false;
  for (const m of all) if (m.email === email && m.sender === sender && !m.seen) { m.seen = true; changed = true; }
  if (changed) fs.writeFileSync(FILE_MSGS, JSON.stringify(all, null, 2));
}
async function unreadFor(email) {
  if (pool) { const r = await pool.query("SELECT count(*)::int AS n FROM messages WHERE email = $1 AND sender = 'support' AND NOT seen", [email]); return r.rows[0].n; }
  return readJson(FILE_MSGS, []).filter((m) => m.email === email && m.sender === 'support' && !m.seen).length;
}
async function conversations() {
  if (pool) {
    const r = await pool.query(`SELECT m.email, u.name,
        (array_agg(m.body ORDER BY m.created_at DESC))[1] AS last_body,
        (array_agg(m.sender ORDER BY m.created_at DESC))[1] AS last_sender,
        max(m.created_at) AS last_at,
        count(*) FILTER (WHERE m.sender = 'customer' AND NOT m.seen) AS unread
      FROM messages m LEFT JOIN users u ON u.email = m.email
      GROUP BY m.email, u.name ORDER BY last_at DESC LIMIT 200`);
    return r.rows.map((x) => ({ email: x.email, name: x.name || '', last: { sender: x.last_sender, body: x.last_body, at: x.last_at }, unread: Number(x.unread) }));
  }
  const users = readJson(FILE_USERS, {}), by = {};
  for (const m of readJson(FILE_MSGS, [])) {
    const c = by[m.email] || (by[m.email] = { email: m.email, name: (users[m.email] || {}).name || '', last: null, unread: 0 });
    c.last = { sender: m.sender, body: m.body, at: m.at };
    if (m.sender === 'customer' && !m.seen) c.unread++;
  }
  return Object.values(by).sort((a, b) => (a.last.at < b.last.at ? 1 : a.last.at > b.last.at ? -1 : 0));
}
// ---- Coupons (managed from the staff area) ----
const DEFAULT_COUPONS = { WELCOME60: 60, KROEGER60: 60 };
const readCoupons = () => readJson(FILE_COUPONS, DEFAULT_COUPONS);
async function listCoupons() {
  if (pool) { const r = await pool.query('SELECT code, percent FROM coupons ORDER BY code'); return r.rows.map((x) => ({ code: x.code, percent: x.percent })); }
  return Object.entries(readCoupons()).map(([code, percent]) => ({ code, percent })).sort((a, b) => (a.code < b.code ? -1 : 1));
}
async function couponPercent(code) {
  const c = String(code || '').trim().toUpperCase();
  if (!c) return null;
  if (pool) { const r = await pool.query('SELECT percent FROM coupons WHERE code = $1', [c]); return r.rows[0] ? r.rows[0].percent : null; }
  return readCoupons()[c] || null;
}
async function saveCoupon(code, percent) {
  if (pool) { await pool.query('INSERT INTO coupons (code, percent) VALUES ($1, $2) ON CONFLICT (code) DO UPDATE SET percent = EXCLUDED.percent', [code, percent]); return; }
  const all = readCoupons(); all[code] = percent; fs.writeFileSync(FILE_COUPONS, JSON.stringify(all, null, 2));
}
async function removeCoupon(code) {
  if (pool) { await pool.query('DELETE FROM coupons WHERE code = $1', [code]); return; }
  const all = readCoupons(); delete all[code]; fs.writeFileSync(FILE_COUPONS, JSON.stringify(all, null, 2));
}
// ---- Orders for the staff area ----
const publicOrder = ({ receipt, ...rest }) => ({ ...rest, hasReceipt: !!receipt });
async function allOrders() {
  if (pool) { const r = await pool.query('SELECT data FROM orders ORDER BY created_at DESC LIMIT 100'); return r.rows.map((x) => x.data); }
  return readJson(FILE_ORDERS, []).slice().reverse().slice(0, 100);
}
async function receiptOf(id) {
  if (pool) { const r = await pool.query("SELECT data->>'receipt' AS rc FROM orders WHERE id = $1", [id]); return r.rows[0] ? r.rows[0].rc : null; }
  const o = readJson(FILE_ORDERS, []).find((x) => x.id === id);
  return o ? o.receipt : null;
}
async function listOrders(email) {
  if (pool) {
    const r = await pool.query('SELECT data FROM orders WHERE email = $1 ORDER BY created_at DESC LIMIT 100', [email]);
    return r.rows.map((x) => x.data);
  }
  return readJson(FILE_ORDERS, []).filter((o) => o.email === email).reverse();
}
async function addOrder(entry) {
  if (pool) {
    await pool.query('INSERT INTO orders (id, email, data) VALUES ($1, $2, $3)', [entry.id, entry.email, JSON.stringify(entry)]);
    return;
  }
  const all = readJson(FILE_ORDERS, []);
  all.push(entry);
  fs.writeFileSync(FILE_ORDERS, JSON.stringify(all, null, 2));
}

// ---- Optional: email yourself each new order (needs ADMIN_EMAIL plus a Brevo or Resend key) ----
async function deliver(to, subject, text) {
  if (process.env.BREVO_API_KEY) {
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ sender: { name: 'AutomobileTeslas', email: process.env.MAIL_FROM_EMAIL }, to: [{ email: to }], subject, textContent: text }),
    });
    if (!r.ok) throw new Error(`Brevo error ${r.status}: ${await r.text()}`);
    return;
  }
  if (process.env.RESEND_API_KEY) {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: process.env.MAIL_FROM || 'AutomobileTeslas <onboarding@resend.dev>', to: [to], subject, text }),
    });
    if (!r.ok) throw new Error(`Resend error ${r.status}: ${await r.text()}`);
    return;
  }
  throw new Error('No email service is set up.');
}

const emailOk = (e) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
// ---- Login tokens (signed, expire after 30 days) so each person only sees their own orders ----
const SECRET = process.env.SESSION_SECRET || (process.env.DATABASE_URL ? crypto.createHash('sha256').update('sessions:' + process.env.DATABASE_URL).digest('hex') : crypto.randomBytes(32).toString('hex'));
const b64 = (v) => Buffer.from(v).toString('base64url');
const sign = (p) => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
function makeToken(email, ttl = 30 * 86400000) { const p = `${b64(email)}.${Date.now() + ttl}`; return `${p}.${sign(p)}`; }
function authEmail(req) {
  const h = String(req.headers.authorization || '');
  if (!h.startsWith('Bearer ')) return null;
  const [e, exp, sig] = h.slice(7).split('.');
  if (!e || !exp || !sig) return null;
  const good = sign(`${e}.${exp}`);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  if (Number(exp) < Date.now()) return null;
  return Buffer.from(e, 'base64url').toString();
}
const fail = (res, where, e) => { console.error(`${where} failed:`, e.message); res.status(500).json({ error: 'Something went wrong. Please try again.' }); };

// ---- Routes ----
app.post('/api/register', strict, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.length > 80) return res.status(400).json({ error: 'Enter your full name.' });
    if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (typeof password !== 'string' || password.length < 8 || password.length > 100) return res.status(400).json({ error: 'Use at least 8 characters for your password.' });
    const user = { email: email.trim().toLowerCase(), name: name.trim(), passwordHash: await bcrypt.hash(password, 10) };
    if (!(await createUser(user))) return res.status(409).json({ error: 'That email is already registered. Try logging in.' });
    res.json({ ok: true, name: user.name, token: makeToken(user.email) });
  } catch (e) { fail(res, 'Register', e); }
});

app.post('/api/login', strict, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await getUser(String(email || '').trim().toLowerCase());
    const ok = user && typeof password === 'string' && (await bcrypt.compare(password, user.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Wrong email or password.' });
    res.json({ ok: true, name: user.name, token: makeToken(user.email) });
  } catch (e) { fail(res, 'Login', e); }
});

app.post('/api/order', strict, async (req, res) => {
  try {
    const { order, address } = req.body || {};
    const key = authEmail(req);
    if (!key || !(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
    const a = address || {}, o = order || {};
    const ok = (v, n) => typeof v === 'string' && v.trim().length > 0 && v.trim().length <= n;
    const opt = (v, n) => v === undefined || v === null || v === '' || (typeof v === 'string' && v.trim().length <= n);
    const postal = String(a.postal || '').trim();
    const phone = String(a.phone || '').trim();
    const digits = phone.replace(/\D/g, '');
    if (!ok(a.name, 80) || !ok(a.street, 100) || !ok(a.city, 60) || !ok(a.country, 60) ||
        !opt(a.province, 60) || !opt(a.unit, 30) || !opt(a.notes, 300) ||
        !/^[A-Za-z0-9][A-Za-z0-9 -]{0,10}[A-Za-z0-9]$/.test(postal) ||
        !/^[+\d][\d\s().+-]{4,24}$/.test(phone) || digits.length < 6 || digits.length > 15)
      return res.status(400).json({ error: 'Please check your delivery details.' });
    if (!ok(o.car, 60) || !ok(o.trim, 60) || typeof o.total !== 'number' || !Number.isInteger(o.qty) || o.qty < 1 || o.qty > 3)
      return res.status(400).json({ error: 'Order details are missing.' });
    const rc = o.receipt;
    if (typeof rc !== 'string' || rc.length > 900000 || !/^data:image\/jpeg;base64,[A-Za-z0-9+/=]+$/.test(rc))
      return res.status(400).json({ error: 'Please upload your payment receipt.' });
    if (o.coupon && !(await couponPercent(o.coupon))) return res.status(400).json({ error: 'That coupon is no longer valid. Please apply your code again.' });

    const t = (v) => String(v || '').trim();
    const entry = {
      id: crypto.randomBytes(4).toString('hex'),
      at: new Date().toISOString(),
      email: key,
      order: { car: o.car, trim: o.trim, qty: o.qty, total: o.total, coupon: o.coupon || null, method: 'bitcoin' },
      receipt: rc,
      address: { name: t(a.name), street: t(a.street), unit: t(a.unit), city: t(a.city), province: t(a.province), postal, country: t(a.country), phone, notes: t(a.notes) },
    };
    await addOrder(entry);
    console.log(`[NEW ORDER] ${entry.id}: ${o.qty} x ${o.car} (${o.trim})`);
    if (process.env.ADMIN_EMAIL) {
      const d = entry.address;
      const text = `New order ${entry.id}\n\n${o.qty} x ${o.car} (${o.trim}) - total $${Math.round(o.total)}${o.coupon ? ` (coupon ${o.coupon})` : ''}\nCustomer: ${key}\n\nDeliver to:\n${d.name}\n${d.unit ? d.unit + '-' : ''}${d.street}\n${d.city}${d.province ? ', ' + d.province : ''} ${d.postal}\n${d.country}\nPhone: ${d.phone}\nNotes: ${d.notes || '-'}`;
      deliver(process.env.ADMIN_EMAIL, `New order ${entry.id}: ${o.car}`, text).catch((e) => console.error('Order email failed:', e.message));
    }
    res.json({ ok: true });
  } catch (e) { fail(res, 'Order', e); }
});

app.get('/api/orders', async (req, res) => {
  try {
    const key = authEmail(req);
    if (!key || !(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
    res.json({ ok: true, orders: (await listOrders(key)).map(publicOrder) });
  } catch (e) { fail(res, 'Orders', e); }
});

// ---- Customer support chat ----
const msgText = (v) => (typeof v === 'string' && v.trim().length > 0 && v.trim().length <= 1000 ? v.trim() : null);
app.get('/api/support', async (req, res) => {
  try {
    const key = authEmail(req);
    if (!key || !(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
    await markSeen(key, 'support');
    res.json({ ok: true, messages: await threadFor(key) });
  } catch (e) { fail(res, 'Support', e); }
});
app.get('/api/support/unread', async (req, res) => {
  try {
    const key = authEmail(req);
    if (!key || !(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
    res.json({ ok: true, count: await unreadFor(key) });
  } catch (e) { fail(res, 'Support', e); }
});
app.post('/api/support', strict, async (req, res) => {
  try {
    const key = authEmail(req);
    if (!key || !(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
    const text = msgText((req.body || {}).text);
    if (!text) return res.status(400).json({ error: 'Type a message first (up to 1000 characters).' });
    await addMessage(key, 'customer', text);
    res.json({ ok: true });
  } catch (e) { fail(res, 'Support', e); }
});

// ---- Staff inbox (protected by the ADMIN_PASSWORD you set in Render) ----
const sha = (v) => crypto.createHash('sha256').update(String(v || '')).digest();
const isAdmin = (req) => authEmail(req) === '__admin__';
app.post('/api/admin/login', adminLimit, (req, res) => {
  const pw = process.env.ADMIN_PASSWORD;
  if (!pw) return res.status(503).json({ error: 'The admin password has not been set on the server yet.' });
  if (!crypto.timingSafeEqual(sha((req.body || {}).password), sha(pw))) return res.status(401).json({ error: 'Wrong password.' });
  res.json({ ok: true, token: makeToken('__admin__', 12 * 3600000) });
});
app.get('/api/admin/conversations', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    res.json({ ok: true, conversations: await conversations() });
  } catch (e) { fail(res, 'Inbox', e); }
});
app.get('/api/admin/thread', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    const email = String(req.query.email || '').trim().toLowerCase();
    await markSeen(email, 'customer');
    const u = await getUser(email);
    res.json({ ok: true, name: u ? u.name : '', messages: await threadFor(email) });
  } catch (e) { fail(res, 'Inbox', e); }
});
app.post('/api/admin/reply', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    const text = msgText((req.body || {}).text);
    if (!text || !(await getUser(email))) return res.status(400).json({ error: 'Message or customer not valid.' });
    await addMessage(email, 'support', text);
    res.json({ ok: true });
  } catch (e) { fail(res, 'Inbox', e); }
});

// ---- Coupon check (customers) and coupon / order tools (staff) ----
app.post('/api/coupon', couponLimit, async (req, res) => {
  try {
    const key = authEmail(req);
    if (!key || !(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
    const code = String((req.body || {}).code || '').trim().toUpperCase();
    const percent = await couponPercent(code);
    if (!percent) return res.status(404).json({ error: 'That code is not valid.' });
    res.json({ ok: true, code, percent });
  } catch (e) { fail(res, 'Coupon', e); }
});
app.get('/api/admin/coupons', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    res.json({ ok: true, coupons: await listCoupons() });
  } catch (e) { fail(res, 'Coupons', e); }
});
app.post('/api/admin/coupons', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    const code = String((req.body || {}).code || '').trim().toUpperCase();
    const percent = Number((req.body || {}).percent);
    if (!/^[A-Z0-9_-]{3,20}$/.test(code)) return res.status(400).json({ error: 'Use 3 to 20 letters, numbers, hyphens or underscores for the code.' });
    if (!Number.isInteger(percent) || percent < 1 || percent > 100) return res.status(400).json({ error: 'The discount must be a whole number from 1 to 100.' });
    await saveCoupon(code, percent);
    res.json({ ok: true });
  } catch (e) { fail(res, 'Coupons', e); }
});
app.post('/api/admin/coupons/delete', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    await removeCoupon(String((req.body || {}).code || '').trim().toUpperCase());
    res.json({ ok: true });
  } catch (e) { fail(res, 'Coupons', e); }
});
app.get('/api/admin/orders', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    res.json({ ok: true, orders: (await allOrders()).map(publicOrder) });
  } catch (e) { fail(res, 'Orders', e); }
});
app.get('/api/admin/receipt', async (req, res) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ error: 'Locked.' });
    res.json({ ok: true, receipt: await receiptOf(String(req.query.id || '')) });
  } catch (e) { fail(res, 'Receipt', e); }
});

// Bitcoin price (cached for a minute) so the checkout can show an estimate
let rate = { usd: 0, at: 0 };
app.get('/api/btc-rate', async (req, res) => {
  try {
    if (Date.now() - rate.at > 60000) {
      const r = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd');
      const d = await r.json();
      if (!d.bitcoin || !d.bitcoin.usd) throw new Error('bad rate');
      rate = { usd: d.bitcoin.usd, at: Date.now() };
    }
    res.json({ usd: rate.usd });
  } catch (e) {
    res.status(502).json({ error: 'Rate unavailable' });
  }
});

// Shows how accounts are being saved (never shows any keys)
app.get('/api/health', (req, res) => {
  const storage = dbReady ? 'database (connected)' : pool ? 'database (NOT connected: check DATABASE_URL)' : 'temporary file (accounts are lost on restart)';
  res.json({ storage, adminInbox: process.env.ADMIN_PASSWORD ? 'ready' : 'password not set', orderEmails: process.env.ADMIN_EMAIL && (process.env.BREVO_API_KEY || process.env.RESEND_API_KEY) ? 'on' : 'off' });
});

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    if (pool) console.log('Storage: database connected');
    else console.warn('WARNING: no DATABASE_URL set. Accounts are saved in a temporary file and will be lost when the server restarts.');
  })
  .catch((e) => console.error('Database setup failed:', e.message))
  .finally(() => app.listen(PORT, () => console.log(`Car shop running on port ${PORT}`)));
