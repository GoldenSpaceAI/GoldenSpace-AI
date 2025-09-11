// ---------------- core & libs ----------------
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import { GoogleGenerativeAI } from "@google/generative-ai";
import bodyParser from "body-parser";
import crypto from "crypto";
import { Pool } from "pg";

dotenv.config();

// ---------------- app & security ----------------
const app = express();
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

// ---------------- sessions ----------------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// ---------------- paths ----------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------- database (Postgres) ----------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render Postgres requires SSL in many regions:
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

async function runMigrations() {
  // Minimal, idempotent migrations for memory & planets
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      provider_id TEXT UNIQUE,       -- Google profile id
      email TEXT UNIQUE,
      name TEXT,
      photo TEXT,
      plan TEXT DEFAULT 'moon',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chats (
      id BIGSERIAL PRIMARY KEY,
      user_email TEXT NOT NULL,
      role TEXT NOT NULL,            -- 'user' | 'assistant'
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS chats_email_time ON chats(user_email, created_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS planets (
      id BIGSERIAL PRIMARY KEY,
      user_email TEXT NOT NULL,
      name TEXT,
      data JSONB NOT NULL,           -- full planet object
      created_at TIMESTAMP DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS planets_email_time ON planets(user_email, created_at DESC);
  `);
}
runMigrations().catch((e) => console.error("Migration error:", e));

// ---------------- plans & limits ----------------
const PLAN_LIMITS = {
  moon:   { ask: 10,  search: 5,  physics: 0,   learnPhysics: false, createPlanet: false },
  earth:  { ask: 30,  search: 20, physics: 5,   learnPhysics: true,  createPlanet: false },
  sun:    { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true },
  // (optional future packs)
  yourspace: { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: false, createPlanet: true },
  chatai:    { ask: Infinity, search: 0, physics: 0, learnPhysics: false, createPlanet: false },
};

// Daily counters in memory (reset by date)
const usage = {}; // { key: { date, ask, search, physics } }
const today = () => new Date().toISOString().slice(0, 10);

function getUserKey(req, res) {
  if (req.user?.id) return `u:${req.user.id}`;
  if (!req.cookies.gs_uid) {
    const uid = Math.random().toString(36).slice(2) + Date.now().toString(36);
    res.cookie("gs_uid", uid, {
      httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production",
    });
    return `g:${uid}`;
  }
  return `g:${req.cookies.gs_uid}`;
}
function getUsage(req, res) {
  const key = getUserKey(req, res);
  const d = today();
  if (!usage[key] || usage[key].date !== d)
    usage[key] = { date: d, ask: 0, search: 0, physics: 0 };
  return usage[key];
}

// Base plan from session/user
function basePlan(req) {
  return (req.user && (req.user.plan || req.session?.plan)) || req.session?.plan || "moon";
}

// --- Test unlock (admin only, controlled by env) ---
function effectivePlan(req) {
  const p = basePlan(req);
  const admin = process.env.ADMIN_EMAIL && req.user?.email?.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();
  if (process.env.TEST_UNLOCK === "1" && admin) {
    return "sun"; // unlock everything for testing
  }
  return p;
}
function enforceLimit(kind) {
  return (req, res, next) => {
    const planName = effectivePlan(req);
    const limits = PLAN_LIMITS[planName] || PLAN_LIMITS.moon;
    const u = getUsage(req, res);
    const allowed = limits[kind];
    if (allowed === 0)
      return res.status(403).json({ error: `Your plan does not allow ${kind}.` });
    if (Number.isFinite(allowed) && u[kind] >= allowed)
      return res.status(429).json({ error: `Daily ${kind} limit reached for ${planName} plan.` });
    if (Number.isFinite(allowed)) u[kind]++;
    next();
  };
}

// ---------------- helpers ----------------
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] || req.protocol || "https";
  const host  = (req.headers["x-forwarded-host"]  || "").toString().split(",")[0] || req.get("host");
  return `${proto}://${host}`;
}

// ---------------- Google OAuth ----------------
const DEFAULT_CALLBACK_PATH = "/auth/google/callback";
passport.use(
  new GoogleStrategy(
    {
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  DEFAULT_CALLBACK_PATH,
      proxy: true,
    },
    async (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value || "",
        photo: profile.photos?.[0]?.value || "",
        plan: "moon",
      };
      // upsert into DB
      try {
        if (user.email) {
          await pool.query(
            `INSERT INTO users (provider_id, email, name, photo, plan)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (email) DO UPDATE SET name=EXCLUDED.name, photo=EXCLUDED.photo`,
            [user.id, user.email, user.name, user.photo, user.plan],
          );
        }
      } catch (e) {
        console.error("user upsert error:", e);
      }
      return done(null, user);
    },
  ),
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get("/auth/google", (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google", { scope: ["profile", "email"], callbackURL })(req, res, next);
});
app.get(DEFAULT_CALLBACK_PATH, (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google", { failureRedirect: "/login.html", callbackURL })(req, res, () => res.redirect("/"));
});
app.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

// ---------------- public paths & guard ----------------
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(req) {
  const p = req.path;
  if (p === "/login.html") return true;
  if (p === "/terms.html") return true;
  if (p === "/privacy.html") return true;
  if (p === "/refund.html") return true;
  if (p === "/health") return true;
  if (p === "/webhooks/paddle") return true;
  if (p.startsWith("/auth/google")) return true;
  if (PUBLIC_FILE_EXT.test(p)) return true;
  if (p === "/favicon.ico") return true;
  return false;
}
function authRequired(req, res, next) {
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error: "Sign in required" });
}

// ---------------- Paddle webhook (PUBLIC) ----------------
const upgradesByEmail = {}; // in-memory signal of plan upgrades
app.post("/webhooks/paddle", bodyParser.raw({ type: "*/*" }), (req, res) => {
  try {
    const signature = req.header("Paddle-Signature") || req.header("paddle-signature");
    const secret = process.env.PADDLE_WEBHOOK_SECRET;
    if (!signature || !secret) return res.status(400).send("Missing signature or secret");

    const computed = crypto.createHmac("sha256", secret).update(req.body).digest("hex");
    if (signature !== computed && !signature.includes(computed)) {
      return res.status(401).send("Invalid signature");
    }

    const evt = JSON.parse(req.body.toString("utf8"));
    const type = evt?.event_type || evt?.type || "";

    const item = evt?.data?.items?.[0];
    const priceId = item?.price?.id || evt?.data?.price_id || null;
    const customPlan = item?.custom_data?.plan || evt?.data?.custom_data?.plan || null;

    let plan = null;
    if (customPlan && PLAN_LIMITS[customPlan]) plan = customPlan;
    else if (priceId === process.env.PADDLE_PRICE_EARTH) plan = "earth";
    else if (priceId === process.env.PADDLE_PRICE_SUN) plan = "sun";
    else if (priceId === process.env.PADDLE_PRICE_YOURSPACE) plan = "yourspace";
    else if (priceId === process.env.PADDLE_PRICE_CHATAI) plan = "chatai";

    const okEvent =
      type.includes("subscription.created") ||
      type.includes("subscription.activated") ||
      type.includes("transaction.completed");

    const email =
      evt?.data?.customer?.email ||
      evt?.data?.customer_email ||
      item?.customer?.email ||
      null;

    if (okEvent && plan && email) {
      upgradesByEmail[email.toLowerCase()] = plan;
      console.log(`Paddle: upgraded ${email} -> ${plan}`);
      // persist to DB
      pool.query(
        `UPDATE users SET plan=$2 WHERE LOWER(email)=LOWER($1)`,
        [email, plan],
      ).catch(e => console.error("plan persist error:", e));
    }

    return res.status(200).send("ok");
  } catch (err) {
    console.error("Paddle webhook error", err);
    return res.status(200).send("ok");
  }
});

// Mount guard after webhook
app.use(authRequired);

// ---------------- Legal redirects (optional) ----------------
app.get("/terms.html", (_req, res) => res.sendFile(path.join(__dirname, "terms.html")));
app.get("/privacy.html", (_req, res) => res.sendFile(path.join(__dirname, "privacy.html")));
app.get("/refund.html", (_req, res) => res.sendFile(path.join(__dirname, "refund.html")));

// ---------------- Gemini ----------------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------------- AI: Chat with memory ----------------
async function loadRecentMessages(email, limit = 10) {
  if (!email) return [];
  const { rows } = await pool.query(
    `SELECT role, content
       FROM chats
      WHERE user_email=$1
      ORDER BY created_at DESC
      LIMIT $2`,
    [email, limit * 2], // user+assistant pairs
  );
  return rows.reverse().map(r => ({ role: r.role, text: r.content }));
}
async function saveMessage(email, role, content) {
  if (!email) return;
  await pool.query(
    `INSERT INTO chats (user_email, role, content) VALUES ($1,$2,$3)`,
    [email, role, content],
  );
}

app.post("/ask", enforceLimit("ask"), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });

    const email = req.user?.email || null;
    const history = await loadRecentMessages(email, 10);

    const promptParts = [];
    if (history.length) {
      promptParts.push({ text: "Previous conversation (most recent last):\n" +
        history.map(m => `${m.role === 'assistant' ? 'Assistant' : 'User'}: ${m.text}`).join("\n") + "\n\n" });
    }
    promptParts.push({ text: `User: ${q}` });

    const result = await model.generateContent(promptParts);
    const answer = result.response.text() || "No response.";

    // persist new turn
    await saveMessage(email, "user", q);
    await saveMessage(email, "assistant", answer);

    res.json({ answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

// ---------------- AI: Search & Physics (unchanged logic) ----------------
app.post("/search-info", enforceLimit("search"), async (req, res) => {
  try {
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await model.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});
app.post("/ai/physics-explain", enforceLimit("physics"), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply: "Ask a physics question." });
    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly.\nQuestion: ${q}`;
    const result = await model.generateContent([{ text: prompt }]);
    const reply = result.response.text() || "No reply.";
    res.json({ reply });
  } catch (e) {
    console.error("physics error", e);
    res.status(500).json({ reply: "Physics error" });
  }
});

// ---------------- Plan sync + /api/me ----------------
app.get("/api/me", async (req, res) => {
  // apply webhook-upgrades in memory, also persist if needed
  if (req.user?.email) {
    const lower = req.user.email.toLowerCase();
    const up = upgradesByEmail[lower];
    if (up && (req.user.plan !== up || req.session?.plan !== up)) {
      req.user.plan = up;
      if (req.session) req.session.plan = up;
      // persist in DB
      pool.query(`UPDATE users SET plan=$2 WHERE LOWER(email)=LOWER($1)`, [req.user.email, up]).catch(()=>{});
    }
  }

  const planName = effectivePlan(req);
  const limits = PLAN_LIMITS[planName] || PLAN_LIMITS.moon;
  const u = getUsage(req, res);
  const remaining = {
    ask:     limits.ask     === Infinity ? Infinity : Math.max(0, limits.ask - u.ask),
    search:  limits.search  === Infinity ? Infinity : Math.max(0, limits.search - u.search),
    physics: limits.physics === Infinity ? Infinity : Math.max(0, limits.physics - u.physics),
  };

  res.json({
    loggedIn: !!req.user,
    user: req.user || null,
    plan: planName,
    limits,
    used: u,
    remaining,
    testUnlocked: process.env.TEST_UNLOCK === "1" && req.user?.email?.toLowerCase() === process.env.ADMIN_EMAIL?.toLowerCase(),
  });
});

// ---------------- Gated pages (unchanged) ----------------
app.get("/learn-physics.html", (req, res) => {
  const plan = effectivePlan(req);
  if (!PLAN_LIMITS[plan].learnPhysics) {
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
      <h2>🚀 Upgrade to the <span style="color:gold">Earth Pack</span> to unlock Learn Physics!</h2>
      <p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname, "learn-physics.html"));
});
app.get("/create-planet.html", (req, res) => {
  const plan = effectivePlan(req);
  if (!PLAN_LIMITS[plan].createPlanet) {
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
      <h2>🌍 Upgrade to the <span style="color:orange">Sun Pack</span> to unlock Create Planet!</h2>
      <p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname, "create-planet.html"));
});

// ---------------- Save & list planets (NEW) ----------------
app.post("/api/planets", async (req, res) => {
  try {
    if (!req.user?.email) return res.status(401).json({ error: "Sign in required" });
    const data = req.body?.planet;
    if (!data) return res.status(400).json({ error: "Missing planet payload" });
    const name = (data.name || "Untitled Planet").toString().slice(0, 120);
    await pool.query(
      `INSERT INTO planets (user_email, name, data) VALUES ($1,$2,$3)`,
      [req.user.email.toLowerCase(), name, data],
    );
    res.json({ ok: true });
  } catch (e) {
    console.error("save planet error:", e);
    res.status(500).json({ error: "Failed to save planet" });
  }
});

app.get("/api/planets", async (req, res) => {
  try {
    if (!req.user?.email) return res.status(401).json({ error: "Sign in required" });
    const { rows } = await pool.query(
      `SELECT id, name, data, created_at FROM planets WHERE user_email=$1 ORDER BY created_at DESC`,
      [req.user.email.toLowerCase()],
    );
    res.json({ items: rows });
  } catch (e) {
    console.error("list planets error:", e);
    res.status(500).json({ error: "Failed to load planets" });
  }
});

// ---------------- Select free (unchanged) ----------------
app.post("/api/select-free", (req, res) => {
  if (req.user) req.user.plan = "moon";
  if (req.session) req.session.plan = "moon";
  // persist
  if (req.user?.email) {
    pool.query(`UPDATE users SET plan='moon' WHERE LOWER(email)=LOWER($1)`, [req.user.email]).catch(()=>{});
  }
  res.json({ ok: true, plan: "moon" });
});

// ---------------- static & health ----------------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------------- start ----------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
