require('dotenv').config();
for (const k of ['DATABASE_URL', 'BREVO_API_KEY', 'MAIL_FROM_EMAIL', 'RESEND_API_KEY', 'ADMIN_EMAIL'])
  if (process.env[k]) process.env[k] = process.env[k].trim(); // removes stray spaces from pasted values

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 60 }));
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
fs.mkdirSync(path.dirname(FILE_USERS), { recursive: true });
const readJson = (f, d) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : d);

async function initDb() {
  if (!pool) return;
  await pool.query('CREATE TABLE IF NOT EXISTS users (email TEXT PRIMARY KEY, name TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now())');
  await pool.query('CREATE TABLE IF NOT EXISTS orders (id TEXT PRIMARY KEY, created_at TIMESTAMPTZ DEFAULT now(), email TEXT NOT NULL, data JSONB NOT NULL)');
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
const fail = (res, where, e) => { console.error(`${where} failed:`, e.message); res.status(500).json({ error: 'Something went wrong. Please try again.' }); };

// ---- Routes ----
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (typeof name !== 'string' || !name.trim() || name.length > 80) return res.status(400).json({ error: 'Enter your full name.' });
    if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (typeof password !== 'string' || password.length < 6 || password.length > 100) return res.status(400).json({ error: 'Use at least 6 characters for your password.' });
    const user = { email: email.trim().toLowerCase(), name: name.trim(), passwordHash: await bcrypt.hash(password, 10) };
    if (!(await createUser(user))) return res.status(409).json({ error: 'That email is already registered. Try logging in.' });
    res.json({ ok: true, name: user.name });
  } catch (e) { fail(res, 'Register', e); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await getUser(String(email || '').trim().toLowerCase());
    const ok = user && typeof password === 'string' && (await bcrypt.compare(password, user.passwordHash));
    if (!ok) return res.status(401).json({ error: 'Wrong email or password.' });
    res.json({ ok: true, name: user.name });
  } catch (e) { fail(res, 'Login', e); }
});

app.post('/api/order', async (req, res) => {
  try {
    const { email, order, address } = req.body || {};
    const key = String(email || '').trim().toLowerCase();
    if (!(await getUser(key))) return res.status(401).json({ error: 'Please log in again.' });
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

    const t = (v) => String(v || '').trim();
    const entry = {
      id: crypto.randomBytes(4).toString('hex'),
      at: new Date().toISOString(),
      email: key,
      order: { car: o.car, trim: o.trim, qty: o.qty, total: o.total, coupon: o.coupon || null },
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
  res.json({ storage, orderEmails: process.env.ADMIN_EMAIL && (process.env.BREVO_API_KEY || process.env.RESEND_API_KEY) ? 'on' : 'off' });
});

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => {
    if (pool) console.log('Storage: database connected');
    else console.warn('WARNING: no DATABASE_URL set. Accounts are saved in a temporary file and will be lost when the server restarts.');
  })
  .catch((e) => console.error('Database setup failed:', e.message))
  .finally(() => app.listen(PORT, () => console.log(`Car shop running on port ${PORT}`)));
