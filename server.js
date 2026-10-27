require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // needed on hosting services so limits work per visitor
app.use(express.json({ limit: '10kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 40 })); // slows down guessing
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ---- A simple file "database" (fine for a test; use a real database later) ----
const DB = path.join(__dirname, 'data', 'users.json');
fs.mkdirSync(path.dirname(DB), { recursive: true });
const load = () => (fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, 'utf8')) : {});
const save = (users) => fs.writeFileSync(DB, JSON.stringify(users, null, 2));

// ---- Settings for the verification code ----
const OTP_MINUTES = 10, MAX_TRIES = 5, RESEND_SECONDS = 30;
const hashCode = (c) => crypto.createHash('sha256').update(c).digest('hex');
const emailOk = (e) => typeof e === 'string' && e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

// ---- Email sending ----
const useSmtp = process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS;
const transporter = useSmtp
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_PORT === '465',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

async function sendCode(email, name, code) {
  const subject = 'Your Voltline Motors verification code';
  const text = `Hi ${name},\n\nYour verification code is ${code}. It expires in ${OTP_MINUTES} minutes.\n\nIf you did not sign up, you can ignore this email.`;
  if (process.env.BREVO_API_KEY) {
    // Brevo: free, sends to any address once your sender email is verified
    const r = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ sender: { name: 'Voltline Motors', email: process.env.MAIL_FROM_EMAIL }, to: [{ email }], subject, textContent: text }),
    });
    if (!r.ok) throw new Error(`Brevo error ${r.status}: ${await r.text()}`);
    return;
  }
  if (process.env.RESEND_API_KEY) {
    // Sends over HTTPS, which works on free hosting (free plans block SMTP email)
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ from: process.env.MAIL_FROM || 'Voltline Motors <onboarding@resend.dev>', to: [email], subject, text }),
    });
    if (!r.ok) throw new Error(`Resend error ${r.status}: ${await r.text()}`);
    return;
  }
  if (!transporter) {
    console.log(`\n[TEST MODE] Verification code for ${email}: ${code}\n`);
    return;
  }
  await transporter.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to: email, subject, text });
}

function issueCode(user) {
  const code = String(crypto.randomInt(100000, 1000000)); // 6 digits
  user.otp = { hash: hashCode(code), expires: Date.now() + OTP_MINUTES * 60000, tries: 0, sent: Date.now() };
  return code;
}

// ---- Routes ----
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (typeof name !== 'string' || !name.trim() || name.length > 80) return res.status(400).json({ error: 'Enter your full name.' });
  if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (typeof password !== 'string' || password.length < 6 || password.length > 100) return res.status(400).json({ error: 'Use at least 6 characters for your password.' });

  const users = load(), key = email.trim().toLowerCase();
  if (users[key] && users[key].verified) return res.status(409).json({ error: 'That email is already registered.' });

  const user = { name: name.trim(), email: key, passwordHash: await bcrypt.hash(password, 10), verified: false };
  const code = issueCode(user);
  users[key] = user;
  save(users);
  try {
    await sendCode(key, user.name, code);
    res.json({ ok: true });
  } catch (err) {
    console.error('Email failed:', err.message);
    res.status(500).json({ error: 'We could not send the email. Try again in a moment.' });
  }
});

app.post('/api/resend', async (req, res) => {
  const key = String((req.body || {}).email || '').trim().toLowerCase();
  const users = load(), user = users[key];
  if (!user || user.verified) return res.status(400).json({ error: 'Register first, then ask for a new code.' });
  const wait = RESEND_SECONDS - Math.floor((Date.now() - user.otp.sent) / 1000);
  if (wait > 0) return res.status(429).json({ error: `Please wait ${wait} seconds before asking for a new code.` });
  const code = issueCode(user);
  save(users);
  try {
    await sendCode(key, user.name, code);
    res.json({ ok: true });
  } catch (err) {
    console.error('Email failed:', err.message);
    res.status(500).json({ error: 'We could not send the email. Try again in a moment.' });
  }
});

app.post('/api/verify', (req, res) => {
  const { email, code } = req.body || {};
  const key = String(email || '').trim().toLowerCase();
  const users = load(), user = users[key];
  if (!user || user.verified || !user.otp) return res.status(400).json({ error: 'Register first to get a code.' });
  if (Date.now() > user.otp.expires) return res.status(400).json({ error: 'That code has expired. Tap Resend code.' });
  if (user.otp.tries >= MAX_TRIES) return res.status(429).json({ error: 'Too many wrong tries. Tap Resend code.' });

  const a = Buffer.from(hashCode(String(code || '')));
  const b = Buffer.from(user.otp.hash);
  if (!crypto.timingSafeEqual(a, b)) {
    user.otp.tries += 1;
    save(users);
    return res.status(400).json({ error: 'That code is not right. Check it and try again.' });
  }
  user.verified = true;
  delete user.otp;
  save(users);
  res.json({ ok: true, name: user.name });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const key = String(email || '').trim().toLowerCase();
  const user = load()[key];
  const ok = user && typeof password === 'string' && (await bcrypt.compare(password, user.passwordHash));
  if (!ok) return res.status(401).json({ error: 'Wrong email or password.' });
  if (!user.verified) return res.status(403).json({ error: 'Please verify your email first. We are sending you a new code.', needsVerify: true, name: user.name });
  res.json({ ok: true, name: user.name });
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Car shop running at http://localhost:${PORT}`);
  if (!transporter) console.log('No email settings found: codes will be printed here (test mode).');
});
