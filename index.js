// index.js
// GoldenSpaceAI — backend (Express + Google Auth + Paddle Webhooks + Gemini)
// Node 18+ required

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');

// === Env ===
const {
  NODE_ENV = 'production',
  PORT = 3000,
  SESSION_SECRET,
  FRONTEND_ORIGIN = 'https://goldenspace-ai.onrender.com',

  // Google OAuth
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL, // e.g. https://goldenspace-ai.onrender.com/auth/google/callback

  // Gemini
  GEMINI_API_KEY,

  // Paddle
  PADDLE_WEBHOOK_SECRET,
  // Price IDs (example names; use your real IDs from Paddle)
  PADDLE_PRICE_MOON,            // (optional, if you keep a free SKU)
  PADDLE_PRICE_EARTH,           // subscription
  PADDLE_PRICE_SUN,             // subscription
  PADDLE_PRICE_YOURSPACE,       // one-time or subscription per your setup
  PADDLE_PRICE_CHATAI,          // subscription

  // Optional test override (keep false in production)
  TEST_MODE = 'false'
} = process.env;

if (!SESSION_SECRET) {
  console.error('❌ Missing SESSION_SECRET in .env');
  process.exit(1);
}
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
  console.error('❌ Missing Google OAuth env (GOOGLE_CLIENT_ID/SECRET/CALLBACK_URL)');
  process.exit(1);
}
if (!PADDLE_WEBHOOK_SECRET) {
  console.error('❌ Missing PADDLE_WEBHOOK_SECRET in .env');
  process.exit(1);
}
if (!GEMINI_API_KEY) {
  console.error('❌ Missing GEMINI_API_KEY in .env');
  process.exit(1);
}

// === Minimal “db” (file-backed) to persist entitlements by email ===
const DATA_DIR = path.join(__dirname, 'data');
const ENTITLEMENTS_FILE = path.join(DATA_DIR, 'entitlements.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(ENTITLEMENTS_FILE)) fs.writeFileSync(ENTITLEMENTS_FILE, JSON.stringify({}), 'utf8');

const readEntitlements = () => JSON.parse(fs.readFileSync(ENTITLEMENTS_FILE, 'utf8'));
const writeEntitlements = (obj) => fs.writeFileSync(ENTITLEMENTS_FILE, JSON.stringify(obj, null, 2), 'utf8');

// entitlement shape:
// { "user@email.com": { plans: { earth: true, sun: true, yourspace: true, chatai: true }, updatedAt: "..." } }

// === Helper: map Paddle price IDs -> internal flags ===
const PRICE_MAP = {
  [PADDLE_PRICE_EARTH || '']: { key: 'earth', type: 'subscription' },
  [PADDLE_PRICE_SUN || '']: { key: 'sun', type: 'subscription' },
  [PADDLE_PRICE_YOURSPACE || '']: { key: 'yourspace', type: 'one_or_sub' },
  [PADDLE_PRICE_CHATAI || '']: { key: 'chatai', type: 'subscription' },
};

// === Express app ===
const app = express();
app.set('trust proxy', 1);

app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true,
}));
app.use(cookieParser());
app.use(bodyParser.json({ verify: rawBodyBuffer })); // keep raw body for HMAC
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    sameSite: 'lax',
    secure: NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
  },
}));

app.use(passport.initialize());
app.use(passport.session());

// === Passport: Google OAuth ===
passport.serializeUser((user, done) => {
  done(null, {
    id: user.id,
    email: user.email,
    name: user.name,
    photo: user.photo,
  });
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: GOOGLE_CALLBACK_URL,
}, (accessToken, refreshToken, profile, done) => {
  const email = (profile.emails && profile.emails[0] && profile.emails[0].value) || '';
  const photo = (profile.photos && profile.photos[0] && profile.photos[0].value) || '';
  const user = {
    id: profile.id,
    email,
    name: profile.displayName || 'User',
    photo
  };
  return done(null, user);
}));

// === Auth routes ===
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/?login=failed',
    session: true,
  }),
  (req, res) => {
    res.redirect('/?login=ok');
  }
);

app.get('/auth/logout', (req, res) => {
  req.logout?.(() => {});
  req.session.destroy(() => res.redirect('/'));
});

// === Utils ===
function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ error: 'Not authenticated' });
}

function rawBodyBuffer(req, res, buf) {
  // Save raw buffer on req for Paddle HMAC verification
  if (buf && buf.length) {
    req.rawBody = buf;
  }
}

// === Plans: evaluate effective features for a user ===
function getUserEntitlements(email) {
  const store = readEntitlements();
  const entry = store[email] || { plans: {} };
  // TEST_MODE support (leave false in prod)
  const testMode = (TEST_MODE || 'false').toLowerCase() === 'true';
  if (testMode) {
    return { ...entry, plans: { earth: true, sun: true, yourspace: true, chatai: true } };
  }
  return entry;
}

// Simple label of “main plan” (for your badge); Sun > Earth > Moon
function pickMainPlan(plans) {
  if (plans.sun) return 'sun';
  if (plans.earth) return 'earth';
  // Moon is your free baseline
  return 'moon';
}

// === Public: who am I? ===
app.get('/api/me', (req, res) => {
  const user = req.user || null;
  if (!user) return res.json({ loggedIn: false });

  const ent = getUserEntitlements(user.email);
  const plans = ent.plans || {};
  const mainPlan = pickMainPlan(plans);

  res.json({
    loggedIn: true,
    user,
    plan: mainPlan,
    entitlements: plans,
  });
});

// === Public: list plan price IDs (frontend uses these to start Paddle checkout) ===
app.get('/api/plan-prices', (_req, res) => {
  res.json({
    earth: PADDLE_PRICE_EARTH || null,
    sun: PADDLE_PRICE_SUN || null,
    yourspace: PADDLE_PRICE_YOURSPACE || null,
    chatai: PADDLE_PRICE_CHATAI || null,
  });
});

// === Paddle webhook ===
// Set your Paddle “Destination” URL to: https://YOUR_DOMAIN/webhooks/paddle
// Choose JSON format and copy the secret into PADDLE_WEBHOOK_SECRET
app.post('/webhooks/paddle', (req, res) => {
  try {
    // HMAC verification (SHA-256)
    const signature = req.get('Paddle-Signature') || req.get('Paddle-Signature-V2');
    if (!signature) {
      return res.status(400).send('Missing signature');
    }
    const hmac = crypto
      .createHmac('sha256', PADDLE_WEBHOOK_SECRET)
      .update(req.rawBody || JSON.stringify(req.body))
      .digest('hex');

    const provided = signature.replace(/^hmac=|^sha256=/, '');
    if (hmac !== provided) {
      return res.status(400).send('Invalid signature');
    }

    const event = req.body; // JSON
    // Paddle “event_type” (new) or “alert_name” (legacy). Support both.
    const type = event.event_type || event.alert_name || '';

    // We’ll read common bits safely:
    const customerEmail =
      event?.data?.customer?.email ||
      event?.customer?.email ||
      event?.data?.subscription?.customer_email ||
      event?.subscription?.customer_email ||
      event?.customer_email ||
      '';

    const priceId =
      event?.data?.items?.[0]?.price?.id ||
      event?.data?.order?.items?.[0]?.price?.id ||
      event?.data?.subscription?.items?.[0]?.price?.id ||
      event?.price_id ||
      '';

    // Handle subscription/one-time purchase activation/cancellation
    const store = readEntitlements();
    const now = new Date().toISOString();

    function enable(price) {
      const map = PRICE_MAP[price];
      if (!map || !customerEmail) return;
      const { key } = map;
      if (!store[customerEmail]) store[customerEmail] = { plans: {}, updatedAt: now };
      store[customerEmail].plans[key] = true;
      store[customerEmail].updatedAt = now;
      writeEntitlements(store);
    }

    function disable(price) {
      const map = PRICE_MAP[price];
      if (!map || !customerEmail) return;
      const { key } = map;
      if (!store[customerEmail]) store[customerEmail] = { plans: {}, updatedAt: now };
      store[customerEmail].plans[key] = false;
      store[customerEmail].updatedAt = now;
      writeEntitlements(store);
    }

    // Common events (v2 new names first, then legacy)
    switch (type) {
      // Purchase / enable
      case 'transaction.completed':
      case 'subscription.activated':
      case 'subscription.updated':
      case 'payment_succeeded':
      case 'subscription_created':
      case 'subscription_payment_succeeded':
        enable(priceId);
        break;

      // Cancellation / disable
      case 'subscription.cancelled':
      case 'subscription_paused':
      case 'payment_failed':
      case 'subscription_payment_failed':
        disable(priceId);
        break;

      default:
        // ignore other events
        break;
    }

    res.status(200).send('ok');
  } catch (e) {
    console.error('Webhook error', e);
    res.status(500).send('error');
  }
});

// === AI endpoints (Gemini) ===
// Keep them simple; frontend handles formatting.
const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

app.post('/ask', ensureAuth, async (req, res) => {
  try {
    const { prompt } = req.body || {};
    if (!prompt) return res.status(400).json({ error: 'Missing prompt' });
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
    const result = await model.generateContent(prompt);
    const text = result?.response?.text?.() || '';
    res.json({ text });
  } catch (e) {
    console.error('/ask error', e);
    res.status(500).json({ error: 'AI error' });
  }
});

app.post('/search-info', ensureAuth, async (req, res) => {
  try {
    const { query } = req.body || {};
    if (!query) return res.status(400).json({ error: 'Missing query' });
    // For now, call Gemini to “summarize” as a placeholder
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
    const result = await model.generateContent(
      `Summarize this for a user in 5 bullets with sources if known: ${query}`
    );
    const text = result?.response?.text?.() || '';
    res.json({ text });
  } catch (e) {
    console.error('/search-info error', e);
    res.status(500).json({ error: 'Search error' });
  }
});

app.post('/ai/physics-explain', ensureAuth, async (req, res) => {
  try {
    const { topic } = req.body || {};
    if (!topic) return res.status(400).json({ error: 'Missing topic' });
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });
    const result = await model.generateContent(
      `Explain "${topic}" to a high-school student with a short example and a tiny quiz at the end.`
    );
    res.json({ text: result?.response?.text?.() || '' });
  } catch (e) {
    console.error('/ai/physics-explain error', e);
    res.status(500).json({ error: 'AI error' });
  }
});

// === Protected content gating helpers ===
app.get('/gate/your-space', ensureAuth, (req, res) => {
  const ent = getUserEntitlements(req.user.email);
  if (ent.plans?.yourspace) return res.json({ allowed: true });
  return res.status(402).json({ allowed: false, needed: 'yourspace' });
});

app.get('/gate/chatai', ensureAuth, (req, res) => {
  const ent = getUserEntitlements(req.user.email);
  if (ent.plans?.chatai) return res.json({ allowed: true });
  return res.status(402).json({ allowed: false, needed: 'chatai' });
});

// === Static files (serve your frontend) ===
// If you deploy static files with Render’s static site, you can remove this block.
// If you serve from the same Node app, place your built/static files in /public.
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
}));

// === Fallback ===
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// === Start ===
app.listen(PORT, () => {
  console.log(`✅ GoldenSpaceAI server on :${PORT}`);
});
