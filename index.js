// index.js — GoldenSpaceAI (OAuth + Supabase plan/usage + Gemini + OpenAI Advanced Assistant)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import multer from "multer";

// AI SDKs
import { GoogleGenerativeAI } from "@google/generative-ai";
import OpenAI from "openai";

// Supabase (server-side, service role)
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// ---------- App setup ----------
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------- Sessions ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Supabase ----------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

// Tables expected:
// users(id uuid pk, email text unique, plan text default 'moon', created_at timestamp default now())
// usage_daily(id uuid pk default gen_random_uuid(), user_id uuid fk, date date default CURRENT_DATE, ask_count int, search_count int)
// Unique index on (user_id, date)

async function upsertUserByEmail(email, defaults = {}) {
  // Ensure a row exists in public.users for this email
  const { data: existing, error: findErr } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .maybeSingle();
  if (findErr) throw findErr;

  if (existing) return existing;

  const { data: inserted, error: insErr } = await supabase
    .from("users")
    .insert([{ email, plan: "moon", ...defaults }])
    .select("*")
    .single();
  if (insErr) throw insErr;
  return inserted;
}

function todayUTC() {
  const d = new Date();
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()))
    .toISOString()
    .slice(0, 10); // YYYY-MM-DD
}

async function getOrCreateUsageRow(user_id) {
  const d = todayUTC();
  const { data: row, error } = await supabase
    .from("usage_daily")
    .select("*")
    .eq("user_id", user_id)
    .eq("date", d)
    .maybeSingle();
  if (error) throw error;

  if (row) return row;

  const { data: created, error: insErr } = await supabase
    .from("usage_daily")
    .insert([{ user_id, date: d, ask_count: 0, search_count: 0 }])
    .select("*")
    .single();
  if (insErr) throw insErr;
  return created;
}

// ---------- Plans & limits ----------
const LIMITS = {
  moon: { ask: 40, search: 20 },   // Chat AI / Search Info
  earth: { ask: Infinity, search: Infinity }, // unlimited
};

function getPlanLimits(plan) {
  return LIMITS[plan] || LIMITS["moon"];
}

// ---------- Helper: compute base URL ----------
function getBaseUrl(req) {
  const proto =
    (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] ||
    req.protocol ||
    "https";
  const host =
    (req.headers["x-forwarded-host"] || "").toString().split(",")[0] ||
    req.get("host");
  return `${proto}://${host}`;
}

// ---------- Google OAuth ----------
const DEFAULT_CALLBACK_PATH = "/auth/google/callback";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: DEFAULT_CALLBACK_PATH,
      proxy: true,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value || "";
        const name = profile.displayName || "";
        const photo = profile.photos?.[0]?.value || "";
        if (!email) return done(null, false);

        // Ensure user exists in Supabase
        const userRow = await upsertUserByEmail(email, { plan: "moon" });

        const user = {
          id: userRow.id, // Supabase UUID
          email,
          name,
          photo,
          plan: userRow.plan || "moon",
        };
        return done(null, user);
      } catch (e) {
        return done(e);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get("/auth/google", (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google", { scope: ["profile", "email"], callbackURL })(
    req,
    res,
    next
  );
});

app.get(DEFAULT_CALLBACK_PATH, (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google", {
    failureRedirect: "/login.html",
    callbackURL,
  })(req, res, async () => {
    // Refresh plan from DB every login
    try {
      const { data, error } = await supabase
        .from("users")
        .select("plan")
        .eq("id", req.user.id)
        .single();
      if (!error && data) req.user.plan = data.plan;
    } catch {}
    res.redirect("/");
  });
});

app.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

// ---------- PUBLIC / AUTH GATE ----------
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(req) {
  const p = req.path;
  if (p === "/login.html") return true;
  if (p === "/terms.html") return true;
  if (p === "/privacy.html") return true;
  if (p === "/refund.html") return true;
  if (p === "/health") return true;
  if (p.startsWith("/auth/google")) return true;
  if (p === "/favicon.ico") return true;
  if (PUBLIC_FILE_EXT.test(p)) return true;
  // Landing/home is public
  if (p === "/") return true;
  return false;
}
function authRequired(req, res, next) {
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html"))
    return res
      .status(401)
      .send(
        `<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
        <h2>🔒 Please <a href="/login.html">sign in with Google</a> to access this feature.</h2>
        <p><a href="/">Back to home</a></p></body></html>`
      );
  return res.status(401).json({ error: "Sign in required" });
}
app.use(authRequired);

// ---------- Login page (original look) ----------
app.get("/login.html", (req, res) => {
  const appName = "GoldenSpaceAI";
  const base = getBaseUrl(req);
  res.send(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${appName} — Log in or Sign up</title><link rel="icon" href="/favicon.ico"/>
<style>
:root{--bg:#0b0f1a;--card:#12182a;--gold:#f0c419;--text:#e6ecff;--muted:#9fb0d1}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,Segoe UI,Inter,Arial;background:radial-gradient(1200px 800px at 80% -10%,#1a2340 0%,#0b0f1a 60%,#070a12 100%);color:var(--text)}
.wrap{min-height:100dvh;display:grid;place-items:center;padding:24px}
.card{width:100%;max-width:520px;background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,.01));border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
h1{margin:0 0 6px;font-size:28px}.sub{margin:0 0 18px;font-size:14px;color:var(--muted)}
.features{margin:12px 0 22px;padding:0;list-style:none;display:grid;gap:10px}
.badge{display:inline-flex;gap:8px;background:rgba(240,196,25,.1);border:1px solid rgba(240,196,25,.35);padding:6px 10px;border-radius:999px;color:var(--gold);font-weight:600;font-size:12px;margin-bottom:10px}
.btn{display:flex;align-items:center;gap:10px;justify-content:center;width:100%;padding:12px 16px;border-radius:12px;border:none;font-size:16px;font-weight:700;cursor:pointer;background:var(--gold);color:#1a1a1a;transition:transform .06s ease, box-shadow .2s ease}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(240,196,25,.35)}
.google{background:#fff;color:#1f2937;border:1px solid rgba(0,0,0,.08)}
.or{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:12px;margin:12px 0}
.or:before,.or:after{content:"";flex:1;height:1px;background:rgba(255,255,255,.12)}
.fine{margin-top:14px;color:var(--muted);font-size:12px}
.links{display:flex;gap:16px;margin-top:10px}a{color:var(--text)}
</style></head><body><div class="wrap"><div class="card">
<div class="badge">✨ Welcome, explorer</div>
<h1>Log in or Sign up</h1>
<p class="sub">Access ${appName}: ask AI about space, learn physics, and create your own planets.</p>
<ul class="features"><li>🚀 Ask Advanced AI (limits by plan)</li><li>📚 Learn Physics</li><li>🪐 Create custom planets</li></ul>
<div class="or">continue</div>
<button class="btn google" onclick="window.location='${base}/auth/google'">
<img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" width="18" height="18" style="display:inline-block"/> Continue with Google
</button>
<p class="fine">By continuing, you agree to our <a href="/terms.html">Terms</a> and <a href="/privacy.html">Privacy</a>.</p>
<div class="links"><a href="/">Back to home</a><a href="/plans.html">See plans</a></div>
</div></div></body></html>`);
});

// ---------- Gemini (Chat AI & Search Info) ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// Enforce limit helper
async function enforceAndCount(req, res, kind) {
  // kind: "ask" or "search"
  if (!req.user?.id) {
    return res.status(401).json({ error: "Sign in required" });
  }
  // Load user + limits
  const { data: userRow, error: uErr } = await supabase
    .from("users")
    .select("id, plan")
    .eq("id", req.user.id)
    .single();
  if (uErr || !userRow) return res.status(401).json({ error: "User not found" });

  const limits = getPlanLimits(userRow.plan);
  if (limits[kind] === Infinity) {
    return { ok: true, userRow, unlimited: true };
  }

  // Get today's usage
  const usage = await getOrCreateUsageRow(userRow.id);
  const current = kind === "ask" ? usage.ask_count : usage.search_count;

  if (current >= limits[kind]) {
    res
      .status(429)
      .json({ error: `Daily ${kind} limit reached for ${userRow.plan} plan.` });
    return { ok: false };
  }

  // Increment
  const updates =
    kind === "ask"
      ? { ask_count: current + 1 }
      : { search_count: current + 1 };

  const { error: upErr } = await supabase
    .from("usage_daily")
    .update(updates)
    .eq("id", usage.id);
  if (upErr) {
    res.status(500).json({ error: "Usage tracking error" });
    return { ok: false };
  }
  return { ok: true, userRow, unlimited: false };
}

app.post("/ask", async (req, res) => {
  try {
    const check = await enforceAndCount(req, res, "ask");
    if (!check.ok) return;

    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });

    const result = await geminiFlash.generateContent([{ text: q }]);
    const answer = result.response.text() || "No response.";
    res.json({ answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

app.post("/search-info", async (req, res) => {
  try {
    const check = await enforceAndCount(req, res, "search");
    if (!check.ok) return;

    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });

    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});

// ---------- Advanced Assistant (OpenAI) ----------
const upload = multer(); // memory storage
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Keep last 20 messages in session per user
function pushHistory(req, role, content) {
  if (!req.session.chatHistory) req.session.chatHistory = [];
  req.session.chatHistory.push({ role, content });
  // trim to last 20
  if (req.session.chatHistory.length > 20) {
    req.session.chatHistory = req.session.chatHistory.slice(-20);
  }
}

app.post("/api/chat", upload.array("files"), async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ error: "Sign in required" });
    }
    // No limit for Advanced Assistant here; it’s covered if you put it behind a paid plan later.

    const userText = (req.body?.message || "").trim();
    if (!userText && (!req.files || req.files.length === 0)) {
      return res.json({ reply: "Please send a message or attach a file." });
    }

    pushHistory(req, "user", userText || "(file upload)");

    // Build messages with memory
    const messages = [
      {
        role: "system",
        content:
          "You are GoldenSpaceAI, a crisp, expert assistant. Keep answers concise and helpful.",
      },
      ...(req.session.chatHistory || []).map((m) => ({
        role: m.role,
        content: m.content,
      })),
    ];

    // If you want to include image files as input, you can use the Responses API with content parts.
    // Here we just mention filenames in the prompt; upgrade later to stream file bytes if needed.
    if (req.files?.length) {
      const names = req.files.map((f) => f.originalname).join(", ");
      messages.push({
        role: "user",
        content: `Attached files: ${names}. Consider them while answering.`,
      });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini", // cheap default
      messages,
      temperature: 0.3,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    pushHistory(req, "assistant", reply);
    res.json({ reply });
  } catch (e) {
    console.error("api/chat error", e);
    res.status(500).json({ error: "Advanced Assistant error" });
  }
});

// ---------- /api/me : expose plan + remaining ----------
app.get("/api/me", async (req, res) => {
  try {
    if (!req.user?.id) return res.json({ loggedIn: false });

    // Fetch plan
    const { data: userRow, error } = await supabase
      .from("users")
      .select("id, email, plan")
      .eq("id", req.user.id)
      .single();
    if (error || !userRow) return res.json({ loggedIn: false });

    // Usage for today
    const usage = await getOrCreateUsageRow(userRow.id);
    const limits = getPlanLimits(userRow.plan);

    const remaining = {
      ask:
        limits.ask === Infinity
          ? Infinity
          : Math.max(0, limits.ask - (usage.ask_count || 0)),
      search:
        limits.search === Infinity
          ? Infinity
          : Math.max(0, limits.search - (usage.search_count || 0)),
    };

    res.json({
      loggedIn: true,
      user: {
        id: userRow.id,
        email: userRow.email,
        name: req.user.name,
        picture: req.user.photo,
        plan: userRow.plan,
      },
      remaining,
    });
  } catch (e) {
    console.error("/api/me error", e);
    res.status(500).json({ loggedIn: false });
  }
});

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 GoldenSpaceAI running on ${PORT}`)
);
