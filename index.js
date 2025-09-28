// index.js — GoldenSpaceAI (Node 22)
// Plans with access blocks + Google OAuth + Exam endpoints

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import multer from "multer";
import fs from "fs";
import OpenAI from "openai";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

// ---------- Core middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
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
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---------- Paths & static ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Plans & capabilities ----------
const CAPS = {
  CHAT: "chat",
  SEARCH_INFO: "search-info",
  PHYSICS: "physics",
  CREATE_PLANET: "create-planet",
  ADVANCED_CHAT: "advanced-chat",
  CREATE_ROCKET: "create-rocket",
  CREATE_SAT: "create-satellite",
  CREATE_UNIVERSE: "create-universe",
  EXAMS: "exams",
};

const PLAN_CAPS = {
  free: new Set([CAPS.CHAT]),
  starter: new Set([CAPS.CHAT, CAPS.SEARCH_INFO]),
  plus: new Set([CAPS.CHAT, CAPS.SEARCH_INFO, CAPS.PHYSICS, CAPS.CREATE_PLANET]),
  pro: new Set([
    CAPS.CHAT,
    CAPS.SEARCH_INFO,
    CAPS.PHYSICS,
    CAPS.CREATE_PLANET,
    CAPS.ADVANCED_CHAT,
    CAPS.CREATE_ROCKET,
    CAPS.CREATE_SAT,
    CAPS.CREATE_UNIVERSE,
    CAPS.EXAMS,
  ]),
  ultra: new Set(Object.values(CAPS)),
};

// Helpers
function getPlan(req) {
  return req.session.plan || "free";
}
function setPlan(req, plan) {
  req.session.plan = plan;
}
function requireCaps(...required) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const caps = PLAN_CAPS[plan] || new Set();
    for (const r of required) {
      if (!caps.has(r)) {
        return res.status(403).json({
          error: `Your plan (${plan}) does not allow this action. Contact goldenspaceais@gmail.com to upgrade.`,
        });
      }
    }
    next();
  };
}

// ---------- Google OAuth ----------
const HAVE_GOOGLE =
  !!(process.env.GOOGLE_CLIENT_ID && (process.env.GOOGLE_CLIENT_SECRET || process.env.Google_CLIENT_SECRET));

if (HAVE_GOOGLE) {
  const DEFAULT_CALLBACK_PATH = "/auth/google/callback";
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.Google_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: DEFAULT_CALLBACK_PATH,
        proxy: true,
      },
      (_accessToken, _refreshToken, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          photo: profile.photos?.[0]?.value || "",
        };
        return done(null, user);
      }
    )
  );
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((obj, done) => done(null, obj));
  app.use(passport.initialize());
  app.use(passport.session());

  app.get("/auth/google", (req, res, next) => {
    const callbackURL = `${req.protocol}://${req.get("host")}${DEFAULT_CALLBACK_PATH}`;
    passport.authenticate("google", { scope: ["profile", "email"], callbackURL })(req, res, next);
  });
  app.get(DEFAULT_CALLBACK_PATH, (req, res, next) => {
    const callbackURL = `${req.protocol}://${req.get("host")}${DEFAULT_CALLBACK_PATH}`;
    passport.authenticate("google", { failureRedirect: "/login.html", callbackURL })(req, res, () =>
      res.redirect("/")
    );
  });
  app.post("/logout", (req, res, next) => {
    req.logout?.((err) => {
      if (err) return next(err);
      req.session.destroy(() => res.json({ ok: true }));
    });
  });
}

// ---------- OpenAI client ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Uploads ----------
const uploadsDir = path.join(__dirname, "uploads");
try {
  fs.mkdirSync(uploadsDir, { recursive: true });
} catch {}
const upload = multer({ dest: uploadsDir });
const memoryUpload = multer({ storage: multer.memoryStorage() });

// ---------- Plan activation ----------
app.post("/plan/activate", (req, res) => {
  const plan = (req.body?.plan || "").toString().toLowerCase();
  if (!PLAN_CAPS[plan]) return res.status(400).json({ ok: false, error: "Unknown plan" });
  setPlan(req, plan);
  return res.json({ ok: true, plan });
});
app.post("/plan/unlock-by-email", (req, res) => {
  const email = (req.body?.email || "").toString().trim().toLowerCase();
  if (email === "goldenspaceais@gmail.com") {
    setPlan(req, "ultra");
    return res.json({ ok: true, plan: "ultra" });
  }
  return res.status(401).json({ ok: false, error: "Unauthorized" });
});

// ---------- /api/me ----------
app.get("/api/me", (req, res) => {
  const plan = getPlan(req);
  res.json({
    loggedIn: !!req.user,
    email: req.user?.email || null,
    name: req.user?.name || null,
    picture: req.user?.photo || null,
    plan,
    logoutUrl: "/logout",
  });
});

// ================== AI ROUTES ==================
// EXAMPLE: Basic Chat
app.post("/ask", requireCaps(CAPS.CHAT), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI. Always answer simply and shortly." },
        { role: "user", content: q },
      ],
      temperature: 0.3,
    });
    res.json({ answer: completion.choices[0]?.message?.content || "No response." });
  } catch (e) {
    res.status(500).json({ answer: "OpenAI error" });
  }
});

// (… keep the rest of your routes as they are, each with the right requireCaps check …)

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT} (plans enabled)`));
