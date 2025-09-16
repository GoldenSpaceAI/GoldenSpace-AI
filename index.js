// index.js — GoldenSpaceAI (OAuth + Plan Limits + TEMP dev plan switch)

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
import crypto from "crypto";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
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
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon:      { ask: 20, search: 5,  physics: 0,         learnPhysics: false, createPlanet: false, yourSpace: false },
  earth:     { ask: 50, search: 20, physics: 5,         learnPhysics: true,  createPlanet: false, yourSpace: false },
  sun:       { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true,  createPlanet: true,  yourSpace: false },
  universe:  { ask: Infinity, search: Infinity, physics: 0,         learnPhysics: false, createPlanet: true,  yourSpace: true  }, // Your Space Pack
  chatai:    { ask: Infinity, search: 50, physics: 0,   learnPhysics: false, createPlanet: false, yourSpace: false }, // Chat AI Pack
};

// ---------- Usage tracking (resets daily in memory) ----------
const usage = {}; // { userKey: { date, ask, search, physics } }
const today = () => new Date().toISOString().slice(0, 10);

function getUserKey(req, res) {
  if (req.user?.id) return `u:${req.user.id}`;
  if (!req.cookies.gs_uid) {
    const uid = Math.random().toString(36).slice(2) + Date.now().toString(36);
    res.cookie("gs_uid", uid, { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" });
    return `g:${uid}`;
  }
  return `g:${req.cookies.gs_uid}`;
}
function getPlan(req) {
  return (req.user?.plan || req.session?.plan || "moon").toLowerCase();
}
function getUsage(req, res) {
  const key = getUserKey(req, res);
  const d = today();
  if (!usage[key] || usage[key].date !== d) usage[key] = { date: d, ask: 0, search: 0, physics: 0 };
  return usage[key];
}
function enforceLimit(kind) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.moon;
    const u = getUsage(req, res);
    const allowed = limits[kind];

    if (allowed === 0) return res.status(403).json({ error: `Your plan does not allow ${kind}.` });
    if (Number.isFinite(allowed) && u[kind] >= allowed) {
      return res.status(429).json({ error: `Daily ${kind} limit reached for ${plan} plan.` });
    }
    if (Number.isFinite(allowed)) u[kind]++;
    next();
  };
}

// ---------- Helpers ----------
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] || req.protocol || "https";
  const host = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
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
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value || "",
        photo: profile.photos?.[0]?.value || "",
        plan: "moon", // default on first login
      };
      return done(null, user);
    }
  )
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

// ---------- PUBLIC paths / auth gate ----------
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(req) {
  const p = req.path;
  if (p === "/login.html") return true;
  if (p === "/terms.html") return true;
  if (p === "/privacy.html") return true;
  if (p === "/refund.html") return true;
  if (p === "/health") return true;
  if (p === "/webhooks/paddle") return true; // Paddle must reach this
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

// ---------- Paddle webhook (kept; used in production) ----------
const upgradesByEmail = {}; // { emailLower: "earth"|"sun"|"universe"|"chatai" }
app.post("/webhooks/paddle", bodyParser.raw({ type: "*/*" }), (req, res) => {
  try {
    const signature = req.header("Paddle-Signature") || req.header("paddle-signature");
    const secret = process.env.PADDLE_WEBHOOK_SECRET;
    if (!signature || !secret) return res.status(400).send("Missing signature or secret");

    const computed = crypto.createHmac("sha256", secret).update(req.body).digest("hex");
    if (signature !== computed && !signature.includes(computed)) return res.status(401).send("Invalid signature");

    const evt = JSON.parse(req.body.toString("utf8"));
    const type = evt?.event_type || evt?.type || "";
    const item = evt?.data?.items?.[0];
    const priceId = item?.price?.id || evt?.data?.price_id || null;
    const customPlan = item?.custom_data?.plan || evt?.data?.custom_data?.plan || null;

    let plan = null;
    if (["earth", "sun", "universe", "yourspace", "chatai"].includes((customPlan || "").toLowerCase())) {
      plan = (customPlan || "").toLowerCase() === "yourspace" ? "universe" : (customPlan || "").toLowerCase();
    } else {
      if (priceId === process.env.PADDLE_PRICE_EARTH) plan = "earth";
      else if (priceId === process.env.PADDLE_PRICE_SUN) plan = "sun";
      else if (priceId === process.env.PADDLE_PRICE_UNIVERSE) plan = "universe";
      else if (priceId === process.env.PADDLE_PRICE_CHATAI) plan = "chatai";
    }

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
    }
    return res.status(200).send("ok");
  } catch (err) {
    console.error("Paddle webhook error", err);
    return res.status(200).send("ok");
  }
});

// ---------- Mount auth gate AFTER webhook ----------
app.use(authRequired);

// ---------- Terms/Privacy/Refund redirects (alias) ----------
app.get("/terms.html", (_req, res) => res.redirect("/terms-of-service.html"));
app.get("/privacy.html", (_req, res) => res.redirect("/privacy.html"));
app.get("/refund.html", (_req, res) => res.redirect("/refund.html"));

// ---------- Gemini ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------- AI Routes ----------
app.post("/ask", enforceLimit("ask"), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const result = await model.generateContent([{ text: `User: ${q}` }]);
    const answer = result.response.text() || "No response.";
    res.json({ answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});
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

// ---------- TEMP DEV: instant plan switch (no payments) ----------
app.post("/api/dev/select-plan", express.json(), (req, res) => {
  // Toggle this with env if you want: if (process.env.ALLOW_DEV_PLAN !== "1") return res.status(403).json({ error: "disabled" });
  const raw = (req.body?.plan || "").toLowerCase();
  const map = { yourspace: "universe", universe: "universe", moon: "moon", earth: "earth", sun: "sun", chatai: "chatai" };
  const plan = map[raw];
  if (!plan) return res.status(400).json({ error: "Invalid plan" });
  if (req.user) req.user.plan = plan;
  if (req.session) req.session.plan = plan;
  return res.json({ ok: true, plan });
});

// ---------- Apply Paddle upgrades (when user hits API) ----------
app.get("/api/me", (req, res) => {
  // Pull Paddle-upgraded plan by email
  if (req.user?.email) {
    const up = upgradesByEmail[req.user.email.toLowerCase()];
    if (up && (req.user.plan !== up || req.session?.plan !== up)) {
      req.user.plan = up;
      if (req.session) req.session.plan = up;
    }
  }

  const plan = getPlan(req);
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.moon;
  const u = getUsage(req, res);

  const remaining = {
    ask: Number.isFinite(limits.ask) ? Math.max(0, limits.ask - u.ask) : Infinity,
    search: Number.isFinite(limits.search) ? Math.max(0, limits.search - u.search) : Infinity,
    physics: Number.isFinite(limits.physics) ? Math.max(0, limits.physics - u.physics) : Infinity,
  };

  const features = {
    learnPhysics: !!limits.learnPhysics,
    createPlanet: !!limits.createPlanet,
    yourSpace: !!limits.yourSpace,
  };

  res.json({
    loggedIn: !!req.user,
    user: req.user || null,
    plan,
    limits,
    used: u,
    remaining,
    features,
  });
});

// ---------- Gated pages ----------
app.get("/learn-physics.html", (req, res) => {
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].learnPhysics) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;margin-top:50px;color:#fff;background:#0b0f1a">
        <h2>🚀 Upgrade to the <span style="color:gold">Earth Pack</span> to unlock Learn Physics!</h2>
        <p><a href="/plans.html" style="color:#f6c64a;font-weight:800">See Plans</a></p>
      </body></html>
    `);
  }
  res.sendFile(path.join(__dirname, "learn-physics.html"));
});

app.get("/create-planet.html", (req, res) => {
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].createPlanet) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;margin-top:50px;color:#fff;background:#0b0f1a">
        <h2>🌍 Upgrade to the <span style="color:orange">Sun Pack</span> (create planets) or <span style="color:#f6c64a">Your Space Pack</span> (create + universe) to use this feature.</h2>
        <p><a href="/plans.html" style="color:#f6c64a;font-weight:800">See Plans</a></p>
      </body></html>
    `);
  }
  res.sendFile(path.join(__dirname, "create-planet.html"));
});

// Advanced builder (new)
app.get("/create-advanced-planet.html", (req, res) => {
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].createPlanet) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;margin-top:50px;color:#fff;background:#0b0f1a">
        <h2>🌍 Upgrade to the <span style="color:orange">Sun Pack</span> or <span style="color:#f6c64a">Your Space Pack</span> to create advanced planets.</h2>
        <p><a href="/plans.html" style="color:#f6c64a;font-weight:800">See Plans</a></p>
      </body></html>
    `);
  }
  res.sendFile(path.join(__dirname, "create-advanced-planet.html"));
});

// Optional: Universe hub page gate
app.get("/your-space.html", (req, res) => {
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].yourSpace) {
    return res.send(`
      <html><body style="font-family:sans-serif;text-align:center;margin-top:50px;color:#fff;background:#0b0f1a">
        <h2>🌌 Your Space requires the <span style="color:#f6c64a">Your Space Pack</span>.</h2>
        <p><a href="/plans.html" style="color:#f6c64a;font-weight:800">See Plans</a></p>
      </body></html>
    `);
  }
  res.sendFile(path.join(__dirname, "your-space.html"));
});

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${getBaseUrl({ headers:{}, protocol:'http', get:()=>`localhost:${PORT}` })}`));
