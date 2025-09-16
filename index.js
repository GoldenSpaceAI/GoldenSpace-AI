// index.js — GoldenSpaceAI backend (Gemini + Google Login + Plans & Quotas)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();

/* ------------------------------ CORS ------------------------------ */
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

/* ---------------------------- JSON body --------------------------- */
app.use(express.json({ limit: "1mb" }));

/* --------------------------- Paths/static ------------------------- */
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/* --------------------------- Sessions ----------------------------- */
app.set("trust proxy", 1); // needed for secure cookies behind Replit proxy

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change_me_pls",
    resave: false,
    saveUninitialized: false,
    cookie: {
      sameSite: "lax",
      secure: true, // HTTPS on Replit
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

/* --------------------------- Passport ----------------------------- */
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

const BASE_URL =
  process.env.BASE_URL?.replace(/\/+$/, "") || "http://localhost:3000";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || "",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
      callbackURL: `${BASE_URL}/auth/google/callback`,
    },
    async (_accessToken, _refresh, profile, done) => {
      try {
        // Attach a plan to the session user (default = "moon")
        const user = {
          id: profile.id,
          name: profile.displayName,
          photo: profile.photos?.[0]?.value,
          email: profile.emails?.[0]?.value,
          provider: "google",
          plan: "moon", // default plan — you can upgrade via /plan endpoint or your billing flow
        };
        return done(null, user);
      } catch (e) {
        return done(e);
      }
    }
  )
);

/* --------------------------- Auth routes -------------------------- */
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (req, res) => res.redirect("/")
);

app.get("/auth/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect("/"));
  });
});

app.get("/me", (req, res) => {
  // Attach current usage/limits summary too
  const user = req.user || null;
  const plan = user?.plan || "guest";
  const summary = user ? usageSummary(user.id, plan) : null;
  res.json({ user, plan, usage: summary });
});

/* --------------------- Plans & daily quotas ----------------------- */
const PLANS = {
  moon:  {
    askPerDay: 20,  // AI chat
    searchPerDay: 5,
    physicsPerDay: 0,
    allowLearn: false,
    allowCreate: false,
  },
  earth: {
    askPerDay: 50,
    searchPerDay: 10,
    physicsPerDay: 5,
    allowLearn: true,
    allowCreate: false,
  },
  sun:   {
    askPerDay: Infinity,
    searchPerDay: Infinity,
    physicsPerDay: Infinity,
    allowLearn: true,
    allowCreate: true,
  },
};

// In-memory usage: { day:"YYYY-MM-DD", ask, search, physics }
const usageStore = new Map();

function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

function getPlan(req) {
  return (req.user?.plan || "moon").toLowerCase();
}

function getUserId(req) {
  return req.user?.id || null;
}

function getUsage(userId) {
  const day = todayUTC();
  const cur = usageStore.get(userId);
  if (!cur || cur.day !== day) {
    const fresh = { day, ask: 0, search: 0, physics: 0 };
    usageStore.set(userId, fresh);
    return fresh;
  }
  return cur;
}

function usageSummary(userId, planKey) {
  const plan = PLANS[planKey] || PLANS.moon;
  const u = usageStore.get(userId) || { day: todayUTC(), ask: 0, search: 0, physics: 0 };
  function rem(used, limit) {
    return Number.isFinite(limit) ? Math.max(0, limit - used) : Infinity;
    }
  return {
    day: u.day,
    limits: {
      ask: plan.askPerDay,
      search: plan.searchPerDay,
      physics: plan.physicsPerDay,
    },
    used: { ask: u.ask, search: u.search, physics: u.physics },
    remaining: {
      ask: rem(u.ask, plan.askPerDay),
      search: rem(u.search, plan.searchPerDay),
      physics: rem(u.physics, plan.physicsPerDay),
    },
  };
}

function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ error: "Sign in required" });
}

function ensureAccess(featureKey) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const conf = PLANS[plan] || PLANS.moon;
    if (featureKey === "learn" && !conf.allowLearn) {
      return res.redirect("/plans.html?upgrade=learn");
    }
    if (featureKey === "create" && !conf.allowCreate) {
      return res.redirect("/plans.html?upgrade=create");
    }
    next();
  };
}

// Check quota without consuming it (we'll consume on success)
function checkQuota(actionKey) {
  return (req, res, next) => {
    const planKey = getPlan(req);
    const plan = PLANS[planKey] || PLANS.moon;
    const userId = getUserId(req);
    if (!userId) return res.status(401).json({ error: "Sign in required" });

    const usage = getUsage(userId);
    const limit =
      actionKey === "ask"
        ? plan.askPerDay
        : actionKey === "search"
        ? plan.searchPerDay
        : actionKey === "physics"
        ? plan.physicsPerDay
        : 0;

    if (!Number.isFinite(limit)) return next(); // Infinity => allowed
    const used =
      actionKey === "ask" ? usage.ask : actionKey === "search" ? usage.search : usage.physics;

    if (used >= limit) {
      const summary = usageSummary(userId, planKey);
      return res.status(429).json({
        error: `Daily limit reached for ${actionKey}.`,
        plan: planKey,
        usage: summary,
      });
    }
    next();
  };
}

// Consume quota after a successful call
function consumeQuota(userId, actionKey) {
  const u = getUsage(userId);
  if (actionKey === "ask") u.ask++;
  else if (actionKey === "search") u.search++;
  else if (actionKey === "physics") u.physics++;
  usageStore.set(userId, u);
}

/* ----------- TEMP endpoint to change plan (for testing) ----------- */
/* In production, replace this with Stripe webhooks / admin flow.    */
app.post("/plan", requireAuth, (req, res) => {
  const plan = (req.body?.plan || "").toLowerCase();
  if (!["moon", "earth", "sun"].includes(plan)) {
    return res.status(400).json({ error: "Invalid plan. Use moon | earth | sun" });
  }
  req.user.plan = plan; // stored in session
  const summary = usageSummary(req.user.id, plan);
  res.json({ ok: true, plan, usage: summary });
});

/* --------------------------- Gemini setup -------------------------- */
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) console.error("❌ Missing GEMINI_API_KEY in .env");

const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

function fail(res, msg, code = 500) {
  res.status(code).json({ answer: msg, reply: msg });
}

/* ---------------------------- AI: /ask ----------------------------- */
const SYSTEM =
  "You are GoldenSpace Advanced AI. Be concise, accurate, and kind.\n" +
  "Use clear steps and bullet points when helpful.";

app.post("/ask", requireAuth, checkQuota("ask"), async (req, res) => {
  try {
    const q = (req.body?.question || "").toString().trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const prompt = `${SYSTEM}\n\nUser: ${q}`;

    const result = await model.generateContent([prompt]);
    const answer = result.response.text() || "No response.";

    // success => consume quota
    consumeQuota(req.user.id, "ask");
    res.json({ answer, usage: usageSummary(req.user.id, getPlan(req)) });
  } catch (err) {
    console.error("Gemini /ask error:", err);
    fail(res, "Oops—Gemini error. Try again.");
  }
});

/* ---------------------- AI: /search-info -------------------------- */
app.post("/search-info", requireAuth, checkQuota("search"), async (req, res) => {
  try {
    const query = (req.body?.query || "").toString().trim();
    if (!query) return res.json({ answer: "Type a topic to search." });

    const prompt =
      "You are GoldenSpace Knowledge. Explain clearly like a mini-encyclopedia.\n" +
      "Format:\n" +
      "- A 3–6 sentence overview (no fluff).\n" +
      "- 3 bullet key facts.\n" +
      "- Include numbers or dates if relevant.\n" +
      "Topic: " + query;

    const result = await model.generateContent([prompt]);
    const answer = result.response.text() || "No info found.";

    consumeQuota(req.user.id, "search");
    res.json({ answer, usage: usageSummary(req.user.id, getPlan(req)) });
  } catch (err) {
    console.error("Gemini /search-info error:", err);
    fail(res, "Search Info error. Try again.");
  }
});

/* ------------------ AI: /ai/physics-explain ----------------------- */
app.post("/ai/physics-explain", requireAuth, checkQuota("physics"), async (req, res) => {
  try {
    const q = (req.body?.question || "").toString().trim();
    if (!q) return res.json({ reply: "Ask a physics question to explain." });

    const prompt =
      "You are GoldenSpace Physics Tutor.\n" +
      "Explain clearly with correct units and simple math.\n" +
      "Format:\n" +
      "1) Short overview (2–3 lines)\n" +
      "2) Key formulas (define symbols + units)\n" +
      "3) Step-by-step solution if relevant\n" +
      "4) Tiny worked example (if no numbers, invent a simple one)\n" +
      "Keep it under ~180 words.\n\n" +
      "Question: " + q;

    const result = await model.generateContent([prompt]);
    const reply = result.response.text() || "No reply.";

    consumeQuota(req.user.id, "physics");
    res.json({ reply, usage: usageSummary(req.user.id, getPlan(req)) });
  } catch (err) {
    console.error("Gemini /ai/physics-explain error:", err);
    res.status(500).json({ reply: "Physics helper error. Try again." });
  }
});

/* --------------------- Page gating (HTML) -------------------------- */
// Put these BEFORE the static() so they override default file serving.
app.get("/learn-physics.html", requireAuth, ensureAccess("learn"), (req, res) => {
  res.sendFile(path.join(__dirname, "learn-physics.html"));
});
app.get("/create-planet.html", requireAuth, ensureAccess("create"), (req, res) => {
  res.sendFile(path.join(__dirname, "create-planet.html"));
});

/* -------------------------- Static last --------------------------- */
app.use(express.static(__dirname));

/* ------------------------- Health + Usage ------------------------- */
app.get("/usage", requireAuth, (req, res) => {
  res.json({ plan: getPlan(req), usage: usageSummary(req.user.id, getPlan(req)) });
});

app.get("/health", (_req, res) => res.json({ ok: true }));

/* --------------------------- Server start ------------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on ${BASE_URL.replace("http://localhost:3000", `http://localhost:${PORT}`)}`);
});
