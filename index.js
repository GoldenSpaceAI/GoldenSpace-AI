// index.js — GoldenSpaceAI (Gemini + Google OAuth + Plan Limits)

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
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon: {
    ask: 20,
    search: 5,
    physics: 0,
    learnPhysics: false,
    createPlanet: false,
  },
  earth: {
    ask: 50,
    search: 10,
    physics: 5,
    learnPhysics: true,
    createPlanet: false,
  },
  sun: {
    ask: Infinity,
    search: Infinity,
    physics: Infinity,
    learnPhysics: true,
    createPlanet: true,
  },
};

// ---------- Usage tracking ----------
const usage = {}; // { userKey: { date, ask, search, physics } }
const today = () => new Date().toISOString().slice(0, 10);

function getUserKey(req, res) {
  if (req.user?.id) return `u:${req.user.id}`;
  if (!req.cookies.gs_uid) {
    const uid = Math.random().toString(36).slice(2) + Date.now().toString(36);
    res.cookie("gs_uid", uid, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
    });
    return `g:${uid}`;
  }
  return `g:${req.cookies.gs_uid}`;
}

function getPlan(req) {
  return req.user?.plan || "sun";
}

function getUsage(req, res) {
  const key = getUserKey(req, res);
  const d = today();
  if (!usage[key] || usage[key].date !== d) {
    usage[key] = { date: d, ask: 0, search: 0, physics: 0 };
  }
  return usage[key];
}

function enforceLimit(kind) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const limits = PLAN_LIMITS[plan];
    const u = getUsage(req, res);
    const used = u[kind];
    const allowed = limits[kind];

    if (allowed === 0) {
      return res
        .status(403)
        .json({ error: `Your plan does not allow ${kind}.` });
    }
    if (used >= allowed) {
      return res.status(429).json({
        error: `Daily ${kind} limit reached for ${plan} plan.`,
      });
    }

    // ✅ increment immediately so the next request counts properly
    u[kind]++;
    next();
  };
}

// ---------- Google OAuth ----------
const BASE_URL =
  process.env.BASE_URL?.replace(/\/$/, "") || "http://localhost:3000";

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${BASE_URL}/auth/google/callback`,
      proxy: true,
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value || "",
        photo: profile.photos?.[0]?.value || "",
        plan: "moon", // default
      };
      return done(null, user);
    },
  ),
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] }),
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (req, res) => res.redirect("/"),
);
app.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

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

// ---------- User info ----------
app.get("/api/me", (req, res) => {
  const plan = getPlan(req);
  const limits = PLAN_LIMITS[plan];
  const u = getUsage(req, res);
  res.json({
    loggedIn: !!req.user,
    user: req.user || null,
    plan,
    limits,
    used: u,
  });
});

// ---------- Page gating ----------
app.get("/learn-physics.html", (req, res) => {
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].learnPhysics) {
    return res.send(`
      <html><body style="font-family:sans-serif; text-align:center; margin-top:50px;">
        <h2>🚀 Upgrade to the <span style="color:gold">Earth Pack</span> to unlock Learn Physics!</h2>
        <p><a href="/plans.html">See Plans</a></p>
      </body></html>
    `);
  }
  res.sendFile(path.join(__dirname, "learn-physics.html"));
});

app.get("/create-planet.html", (req, res) => {
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].createPlanet) {
    return res.send(`
      <html><body style="font-family:sans-serif; text-align:center; margin-top:50px;">
        <h2>🌍 Upgrade to the <span style="color:orange">Sun Pack</span> to unlock Create Planet!</h2>
        <p><a href="/plans.html">See Plans</a></p>
      </body></html>
    `);
  }
  res.sendFile(path.join(__dirname, "create-planet.html"));
});

// ---------- Static ----------
app.use(express.static(__dirname));

// ---------- Health ----------
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on ${BASE_URL} (port ${PORT})`);
});
import Stripe from "stripe";
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

// Create a Checkout Session
app.post("/api/checkout", async (req, res) => {
  try {
    const { plan } = req.body; // "earth" | "sun"
    const priceId = plan === "earth" ? process.env.PRICE_EARTH
                 : plan === "sun"   ? process.env.PRICE_SUN
                 : null;
    if (!priceId) return res.status(400).json({ error: "Invalid plan" });

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${process.env.BASE_URL}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.BASE_URL}/plans.html`,
      // optional: attach a reference to your logged-in user
      // client_reference_id: req.user?.id || undefined,
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("Stripe checkout error", err);
    res.status(500).json({ error: "Stripe error" });
  }
});