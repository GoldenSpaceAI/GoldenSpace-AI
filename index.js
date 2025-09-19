// index.js — GoldenSpaceAI (full backend with Gemini + OpenAI + memory)

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
import multer from "multer";
import OpenAI from "openai";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

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
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon: { ask: 10, search: 5, physics: 0, learnPhysics: false, createPlanet: false },
  earth: { ask: 30, search: 20, physics: 5, learnPhysics: true, createPlanet: false },
  sun: { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true },
};

// ---------- Usage tracking ----------
const usage = {};
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
  return (req.user && req.user.plan) || req.session?.plan || "moon";
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
    const limits = PLAN_LIMITS[plan];
    const u = getUsage(req, res);
    const allowed = limits[kind];
    if (allowed === 0) return res.status(403).json({ error: `Your plan does not allow ${kind}.` });
    if (Number.isFinite(allowed) && u[kind] >= allowed)
      return res.status(429).json({ error: `Daily ${kind} limit reached for ${plan} plan.` });
    if (Number.isFinite(allowed)) u[kind]++;
    next();
  };
}

// ---------- Google OAuth ----------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
      proxy: true,
    },
    (accessToken, refreshToken, profile, done) => {
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails?.[0]?.value || "",
        photo: profile.photos?.[0]?.value || "",
        plan: "moon",
      };
      return done(null, user);
    },
  ),
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (req, res) => res.redirect("/"),
);

app.post("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

// ---------- Public Login Page ----------
app.get("/login.html", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

// ---------- Public / Auth Gate ----------
const PUBLIC_FILE_EXT = /\.(css|js|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(req) {
  const p = req.path;
  if (p === "/" || p === "/login.html") return true;
  if (p === "/terms.html" || p === "/privacy.html" || p === "/refund.html") return true;
  if (p.startsWith("/auth/google")) return true;
  if (p === "/favicon.ico" || p === "/health") return true;
  if (PUBLIC_FILE_EXT.test(p)) return true;
  return false;
}
function authRequired(req, res, next) {
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error: "Sign in required" });
}

// ---------- AI Clients ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Chat Memory ----------
const chatHistories = {}; // { userKey: { chatType: [messages...] } }

function getChatHistory(req, chatType) {
  const key = getUserKey(req);
  if (!chatHistories[key]) chatHistories[key] = {};
  if (!chatHistories[key][chatType]) chatHistories[key][chatType] = [];
  return chatHistories[key][chatType];
}
function addToChatHistory(req, chatType, role, content) {
  const history = getChatHistory(req, chatType);
  history.push({ role, content });
  if (history.length > 20) history.shift();
}

// ---------- AI Routes ----------

// Gemini Ask
app.post("/ask", enforceLimit("ask"), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const result = await geminiFlash.generateContent([{ text: `User: ${q}` }]);
    const answer = result.response.text() || "No response.";
    res.json({ answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

// Gemini Search
app.post("/search-info", enforceLimit("search"), async (req, res) => {
  try {
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

// Gemini Physics
app.post("/ai/physics-explain", enforceLimit("physics"), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply: "Ask a physics question." });
    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly.\nQuestion: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    const reply = result.response.text() || "No reply.";
    res.json({ reply });
  } catch (e) {
    console.error("physics error", e);
    res.status(500).json({ reply: "Physics error" });
  }
});

// Advanced Chat AI (chat-advancedai.html)
app.post("/chat-advanced-ai", async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ answer: "Ask me something." });

    addToChatHistory(req, "chat-advancedai", "user", q);
    const messages = getChatHistory(req, "chat-advancedai");

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini", // cheapest GPT-4o family
      messages,
    });

    const answer = completion.choices[0].message.content;
    addToChatHistory(req, "chat-advancedai", "assistant", answer);

    res.json({ model: "gpt-4o-mini", answer });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ answer: "Advanced AI error" });
  }
});

// Advanced AI (advanced-ai.html)
app.post("/api/advanced-ai", async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ answer: "Ask me something." });

    addToChatHistory(req, "advanced-ai", "user", q);
    const messages = getChatHistory(req, "advanced-ai");

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
    });

    const answer = completion.choices[0].message.content;
    addToChatHistory(req, "advanced-ai", "assistant", answer);

    res.json({ model: "gpt-4o-mini", answer });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ answer: "Advanced AI error" });
  }
});

// ---------- Me API ----------
app.get("/api/me", (req, res) => {
  const plan = getPlan(req);
  const limits = PLAN_LIMITS[plan];
  const u = getUsage(req, res);
  const remaining = {
    ask: limits.ask === Infinity ? Infinity : Math.max(0, limits.ask - u.ask),
    search: limits.search === Infinity ? Infinity : Math.max(0, limits.search - u.search),
    physics: limits.physics === Infinity ? Infinity : Math.max(0, limits.physics - u.physics),
  };
  res.json({ loggedIn: !!req.user, user: req.user || null, plan, limits, used: u, remaining });
});

// ---------- Static ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
