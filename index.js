// index.js — GoldenSpaceAI (GPT-4o-mini default, GPT-4o for advancedai.html, GPT-3.5-turbo for ChatAI pack)

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
import fs from "fs";
import OpenAI from "openai";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

// ---------- Core middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------- Sessions ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  }),
);

// Passport (Google) – still available, but NOT required for access right now
app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Simple plan map ----------
const PLAN_LIMITS = {
  moon: { ask: 40, search: 20 },
  earth: { ask: Infinity, search: Infinity },
  // 🔑 ChatAI pack → GPT-3.5-turbo (instead of GPT-4o-mini)
  chatai: { ask: Infinity, search: Infinity, model: "gpt-3.5-turbo" },
};

// ---------- Helper: compute base URL ----------
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
      clientID: process.env.GOOGLE_CLIENT_ID || "none",
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || "none",
      callbackURL: DEFAULT_CALLBACK_PATH,
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

// ---------- PUBLIC / AUTH ----------
function isPublicPath(req) {
  return true; // all unlocked for now
}
function authRequired(req, res, next) {
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error: "Sign in required" });
}

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- OpenAI ----------
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

function pushHistory(req, role, content) {
  if (!req.session.advHistory) req.session.advHistory = [];
  req.session.advHistory.push({ role, content });
  if (req.session.advHistory.length > 20) {
    req.session.advHistory = req.session.advHistory.slice(-20);
  }
}
function getHistory(req) {
  return (req.session.advHistory || []).map(m => ({ role: m.role, content: m.content }));
}

async function readTextIfPossible(filePath, mimetype) {
  try {
    const t = mimetype || "";
    if (t.startsWith("text/") || /\/(json|csv|html|xml)/i.test(t)) {
      return fs.readFileSync(filePath, "utf8").slice(0, 30000);
    }
    return null;
  } catch {
    return null;
  }
}

// ---------- Normal Routes (GPT-4o-mini) ----------
app.post("/ask", async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI. Always answer in a long, detailed way." },
        { role: "user", content: q },
      ],
    });

    const answer = completion.choices[0]?.message?.content || "No response.";
    res.json({ answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "OpenAI error" });
  }
});

// ---------- Advanced Chat AI (GPT-4o for advancedai.html) ----------
const upload = multer({ dest: "uploads/" });
app.post("/chat-advanced-ai", upload.single("file"), async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();

    const messages = [
      { role: "system", content: "You are GoldenSpaceAI Advanced Assistant. Always provide long, detailed answers." },
      ...getHistory(req),
    ];
    if (q) {
      messages.push({ role: "user", content: q });
      pushHistory(req, "user", q);
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4o", // ✅ stays GPT-4o
      messages,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    pushHistory(req, "assistant", reply);

    res.json({ model: "gpt-4o", reply });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});
