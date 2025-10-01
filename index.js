// index.js — GoldenSpaceAI
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import fs from "fs";
import OpenAI from "openai";

dotenv.config();
const app = express();
app.set("trust proxy", 1);

// ---------- Middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
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

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ---------- Capabilities ----------
const CAPS = {
  CHAT: "chat",
  SEARCH_INFO: "search-info",
  PHYSICS: "physics",
  CREATE_PLANET: "create-planet",
  CREATE_ROCKET: "create-rocket",
  CREATE_SAT: "create-satellite",
  CREATE_UNIVERSE: "create-universe",
  ADVANCED_CHAT: "advanced-chat",
  HOMEWORK: "homework",
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
    CAPS.CREATE_ROCKET,
    CAPS.CREATE_SAT,
    CAPS.CREATE_UNIVERSE,
    CAPS.ADVANCED_CHAT,
    CAPS.HOMEWORK,
  ]),
  ultra: new Set(Object.values(CAPS)),
};

function getPlan(req) {
  return req.session.plan || "free";
}
function setPlan(req, plan) {
  req.session.plan = plan;
}
function requireCaps(...required) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const caps = PLAN_CAPS[plan] || PLAN_CAPS.free;
    for (const r of required) {
      if (!caps.has(r)) {
        return res.status(403).json({
          error: `This feature is reserved for the plan ${plan.toUpperCase()}`,
        });
      }
    }
    next();
  };
}

// ---------- Google OAuth (if enabled) ----------
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
        proxy: true,
      },
      (_at, _rt, profile, done) => {
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
  passport.serializeUser((u, d) => d(null, u));
  passport.deserializeUser((o, d) => d(null, o));
  app.use(passport.initialize());
  app.use(passport.session());

  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login.html" }), (req, res) => {
    res.redirect("/");
  });
  app.post("/logout", (req, res) => {
    req.logout?.(() => {
      req.session.destroy(() => res.json({ ok: true }));
    });
  });
}

// ---------- API: User info ----------
app.get("/api/me", (req, res) => {
  res.json({
    loggedIn: !!req.user,
    email: req.user?.email || null,
    picture: req.user?.photo || null,
    plan: getPlan(req),
  });
});

// ---------- API: Set plan manually ----------
app.post("/plan/activate", (req, res) => {
  const plan = (req.body?.plan || "").toLowerCase();
  if (!PLAN_CAPS[plan]) return res.status(400).json({ error: "Unknown plan" });
  setPlan(req, plan);
  res.json({ ok: true, plan });
});

// ---------- Blocked Pages ----------
function serveIfAllowed(cap, file) {
  return (req, res) => {
    const plan = getPlan(req);
    if (!PLAN_CAPS[plan].has(cap)) {
      return res
        .status(403)
        .send(`<script>alert("This feature is reserved for the plan ${plan.toUpperCase()}");window.location='/'</script>`);
    }
    res.sendFile(path.join(__dirname, file));
  };
}
app.get("/advanced-ai.html", serveIfAllowed(CAPS.ADVANCED_CHAT, "advanced-ai.html"));
app.get("/homework.html", serveIfAllowed(CAPS.HOMEWORK, "homework.html"));

// ---------- OpenAI ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// === Advanced AI (Pro and Ultra) ===
app.post("/chat-advanced-ai", requireCaps(CAPS.ADVANCED_CHAT), async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ reply: "Type something to ask me." });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI Advanced Assistant. Always reply in a long, professional, very detailed way with explanations, examples, and insights." },
        { role: "user", content: q },
      ],
      temperature: 0.5,
    });

    res.json({ reply: completion.choices[0]?.message?.content || "No response." });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});

// === Homework Helper (Pro and Ultra) ===
app.post("/chat-homework", requireCaps(CAPS.HOMEWORK), async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ reply: "Give me your homework question." });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI Homework Helper. Always provide long, step-by-step detailed answers, explain every step clearly, and give a final solution with reasoning." },
        { role: "user", content: q },
      ],
      temperature: 0.3,
    });

    res.json({ reply: completion.choices[0]?.message?.content || "No reply." });
  } catch (e) {
    console.error("homework error", e);
    res.status(500).json({ error: "Homework error" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
