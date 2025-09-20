// index.js — GoldenSpaceAI (Google OAuth + Supabase plans/blocks + OpenAI/Gemini)

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
import { createClient } from "@supabase/supabase-js";
import OpenAI from "openai";
import { GoogleGenerativeAI } from "@google/generative-ai";
import fs from "fs";

dotenv.config();
const app = express();
app.set("trust proxy", 1);

// ---------- Basics ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

// ---------- Supabase (for plans & usage) ----------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE
);

// Tables expected:
//   users(id uuid PK, email text unique, name text, photo text, plan text default 'moon', created_at timestamptz)
//   use_daily(id uuid PK, user_id uuid, date date, ask_count int4 default 0, search_count int4 default 0, unique(user_id, date))
const today = () => new Date().toISOString().slice(0, 10);

// ---------- Plans (BLOCKS) ----------
const PLAN_LIMITS = {
  moon:     { ask: 40,  search: 20,  adv: 0,        homework: 0, space: false },
  earth:    { ask: Infinity, search: Infinity, adv: 0, homework: 0, space: false },
  chatpack: { ask: Infinity, search: Infinity, adv: Infinity, homework: Infinity, space: false },
  yourspace:{ ask: 40,  search: 20,  adv: 0,        homework: 0, space: true  },
};

async function upsertUserFromProfile(profile) {
  const email = profile.emails?.[0]?.value?.toLowerCase() || "";
  const name  = profile.displayName || "";
  const photo = profile.photos?.[0]?.value || "";
  const id = profile.id;

  // ensure row exists & keep plan if already upgraded
  const { data: existing } = await supabase.from("users").select("id,plan").eq("id", id).maybeSingle();
  if (!existing) {
    await supabase.from("users").insert({ id, email, name, photo, plan: "moon" });
  } else {
    // keep existing plan
    await supabase.from("users").update({ email, name, photo }).eq("id", id);
  }
  return { id };
}

async function getPlan(userId) {
  const { data, error } = await supabase.from("users").select("plan").eq("id", userId).single();
  if (error || !data) return "moon";
  return data.plan || "moon";
}

async function countAndCheck(userId, kind) {
  // returns {ok, reason}
  const plan = await getPlan(userId);
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.moon;

  // feature block
  if (limits[kind] === 0) return { ok: false, reason: `Your plan does not allow ${kind}.` };
  if (limits[kind] === Infinity) return { ok: true };

  // daily counting for ask/search only
  const { data: row } = await supabase
    .from("use_daily")
    .select("*")
    .eq("user_id", userId)
    .eq("date", today())
    .maybeSingle();

  const field = kind === "ask" ? "ask_count" : "search_count";
  const current = row ? row[field] || 0 : 0;
  if (current >= limits[kind]) {
    return { ok: false, reason: `Daily ${kind} limit reached for your plan.` };
  }

  if (row) {
    await supabase.from("use_daily").update({ [field]: current + 1 }).eq("id", row.id);
  } else {
    await supabase.from("use_daily").insert({
      user_id: userId,
      date: today(),
      ask_count: kind === "ask" ? 1 : 0,
      search_count: kind === "search" ? 1 : 0,
    });
  }
  return { ok: true };
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
    async (_access, _refresh, profile, done) => {
      try {
        await upsertUserFromProfile(profile);
        const user = {
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          photo: profile.photos?.[0]?.value || "",
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
  passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get(DEFAULT_CALLBACK_PATH, (req, res, next) => {
  passport.authenticate("google", { failureRedirect: "/login.html" })(req, res, () => {
    res.redirect("/"); // after login we’ll still route to / which sends login.html (front-end will detect signed-in state and link onward)
  });
});

app.post("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

// ---------- Ensure real login page is first ----------
app.get("/", (_req, res) => {
  // Always serve the real login page first
  res.sendFile(path.join(__dirname, "login.html"));
});

// ---------- Auth gate ----------
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?|html)$/i;
const PUBLIC_PATHS = new Set([
  "/login.html",
  "/terms.html",
  "/privacy.html",
  "/refund.html",
  "/health",
  "/auth/google",
  DEFAULT_CALLBACK_PATH,
  "/",
]);

function isPublic(req) {
  if (PUBLIC_PATHS.has(req.path)) return true;
  if (PUBLIC_FILE_EXT.test(req.path)) return true;
  return false;
}

function requireAuth(req, res, next) {
  if (isPublic(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) {
    return res.send(
      `<!doctype html><html><body style="font-family:system-ui;text-align:center;padding:40px">
        <p>🔒 Please <a href="/auth/google">sign in with Google</a> to access this feature.</p>
        <p><a href="/">Back to login</a></p></body></html>`
    );
  }
  return res.status(401).json({ error: "Sign in required" });
}

app.use(requireAuth);

// ---------- AI clients ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------- /api/me (profile + plan + remaining) ----------
app.get("/api/me", async (req, res) => {
  if (!(req.isAuthenticated && req.isAuthenticated())) {
    return res.json({ loggedIn: false });
  }
  const user = req.user;
  const plan = await getPlan(user.id);
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.moon;

  // remaining only for finite
  let askRem = limits.ask;
  let searchRem = limits.search;
  if (Number.isFinite(limits.ask) || Number.isFinite(limits.search)) {
    const { data: row } = await supabase
      .from("use_daily")
      .select("ask_count,search_count")
      .eq("user_id", user.id)
      .eq("date", today())
      .maybeSingle();
    const usedAsk = row?.ask_count || 0;
    const usedSearch = row?.search_count || 0;
    askRem = Number.isFinite(limits.ask) ? Math.max(0, limits.ask - usedAsk) : Infinity;
    searchRem = Number.isFinite(limits.search) ? Math.max(0, limits.search - usedSearch) : Infinity;
  }

  res.json({
    loggedIn: true,
    user,
    plan,
    remaining: { ask: askRem, search: searchRem },
    blocks: {
      chatAdvanced: limits.adv !== 0,
      homework: limits.homework !== 0,
      space: limits.space,
    },
  });
});

// ---------- Gemini: Chat AI (ask) ----------
app.post("/ask", async (req, res) => {
  try {
    if (!(req.isAuthenticated && req.isAuthenticated()))
      return res.status(401).json({ error: "Sign in required" });

    const chk = await countAndCheck(req.user.id, "ask");
    if (!chk.ok) return res.status(403).json({ error: chk.reason });

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

// ---------- Gemini: Search info ----------
app.post("/search-info", async (req, res) => {
  try {
    if (!(req.isAuthenticated && req.isAuthenticated()))
      return res.status(401).json({ error: "Sign in required" });

    const chk = await countAndCheck(req.user.id, "search");
    if (!chk.ok) return res.status(403).json({ error: chk.reason });

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

// ---------- Advanced Chat (OpenAI) + file upload ----------
const upload = multer({ dest: "uploads/" });

app.post("/api/chat", upload.array("files"), async (req, res) => {
  try {
    if (!(req.isAuthenticated && req.isAuthenticated()))
      return res.status(401).json({ error: "Sign in required" });

    const plan = await getPlan(req.user.id);
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.moon;
    if (limits.adv === 0) return res.status(403).json({ error: "Your plan does not allow Advanced AI." });

    const text = (req.body?.message || "").trim();
    const files = req.files || [];

    // For demo: just pass text to OpenAI. (If you want to truly upload files to OpenAI, add their files API here.)
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI, a crisp, expert assistant." },
        { role: "user", content: text || (files.length ? "(I uploaded files)" : "") },
      ],
    });

    res.json({ model: "gpt-4o-mini", reply: completion.choices?.[0]?.message?.content || "No reply" });
  } catch (e) {
    console.error("api/chat error", e);
    res.status(500).json({ error: "Advanced AI error" });
  } finally {
    // optional: cleanup uploads
    (req.files || []).forEach(f => fs.existsSync(f.path) && fs.unlink(f.path, () => {}));
  }
});

// ---------- Homework (OpenAI vision) ----------
app.post("/api/homework", upload.single("file"), async (req, res) => {
  try {
    if (!(req.isAuthenticated && req.isAuthenticated()))
      return res.status(401).json({ error: "Sign in required" });

    const plan = await getPlan(req.user.id);
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.moon;
    if (limits.homework === 0)
      return res.status(403).json({ error: "Your plan does not allow homework solving." });

    const text = (req.body?.message || "").trim();
    const file = req.file;
    if (!file) return res.status(400).json({ error: "No image uploaded" });

    const base64 = fs.readFileSync(file.path, { encoding: "base64" });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "Solve carefully. Show steps. If ambiguous, ask for clarification." },
        { role: "user", content: text || "Please solve this homework from the image." },
        {
          role: "user",
          content: [
            {
              type: "image_url",
              image_url: { url: `data:${file.mimetype};base64,${base64}` },
            },
          ],
        },
      ],
    });

    res.json({ reply: completion.choices?.[0]?.message?.content || "No reply" });
  } catch (e) {
    console.error("homework error", e);
    res.status(500).json({ error: "Homework error" });
  } finally {
    if (req.file && fs.existsSync(req.file.path)) fs.unlink(req.file.path, () => {});
  }
});

// ---------- Space pages gating (Your Space Pack) ----------
function requireSpacePack(req, res, next) {
  if (!(req.isAuthenticated && req.isAuthenticated())) return res.redirect("/login.html");
  getPlan(req.user.id).then(plan => {
    if (!(PLAN_LIMITS[plan] || PLAN_LIMITS.moon).space) {
      return res.send(
        `<html><body style="font-family:system-ui;text-align:center;margin-top:50px;">
           <h2>🚀 Unlock <span style="color:gold">Your Space Pack</span> to access this feature</h2>
           <p><a href="/plans.html">See Plans</a></p></body></html>`
      );
    }
    next();
  });
}

app.get("/create-planet.html", requireSpacePack, (_req, res) =>
  res.sendFile(path.join(__dirname, "create-planet.html"))
);
app.get("/create-rocket.html", requireSpacePack, (_req, res) =>
  res.sendFile(path.join(__dirname, "create-rocket.html"))
);
app.get("/create-satellite.html", requireSpacePack, (_req, res) =>
  res.sendFile(path.join(__dirname, "create-satellite.html"))
);
app.get("/your-space.html", requireSpacePack, (_req, res) =>
  res.sendFile(path.join(__dirname, "your-space.html"))
);

// ---------- Static & health ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
