// index.js — GoldenSpaceAI (Fix 404s for OpenAI endpoints; no other changes)

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

dotenv.config();

// ---------- Env ----------
const {
  SESSION_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  GEMINI_API_KEY,
  OPENAI_API_KEY,
} = process.env;

if (!SESSION_SECRET) throw new Error("SESSION_SECRET missing");
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) throw new Error("Google OAuth envs missing");
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) throw new Error("Supabase envs missing");

// ---------- SDKs ----------
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------- App ----------
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "25mb" }));
app.use(cookieParser());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Sessions ----------
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Plans ----------
const PLAN_LIMITS = {
  moon: { ask: 40, search: 20 },
  earth: { ask: Infinity, search: Infinity },
  chatai: { ask: Infinity, search: Infinity }, // ChatAI pack
  spacepack: { ask: 40, search: 20 },         // no change to chat/search
};
const today = () => new Date().toISOString().slice(0, 10);

// ---------- Supabase helpers ----------
async function upsertUserFromGoogle(profile) {
  const email = profile.emails?.[0]?.value?.toLowerCase() || "";
  const name = profile.displayName || "";
  const photo = profile.photos?.[0]?.value || "";

  let { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("email", email)
    .maybeSingle();
  if (error) throw error;

  if (!user) {
    const ins = await supabase
      .from("users")
      .insert([{ email, name, photo, plan: "moon" }])
      .select()
      .single();
    if (ins.error) throw ins.error;
    user = ins.data;
  } else {
    await supabase.from("users").update({ name, photo }).eq("id", user.id);
  }
  return user;
}
async function getUserById(id) {
  const { data, error } = await supabase.from("users").select("*").eq("id", id).single();
  if (error) throw error;
  return data;
}
async function getOrInitUsage(user_id) {
  const d = today();
  let { data: row, error } = await supabase
    .from("usage_daily")
    .select("*")
    .eq("user_id", user_id)
    .eq("date", d)
    .maybeSingle();
  if (error) throw error;
  if (!row) {
    const ins = await supabase
      .from("usage_daily")
      .insert([{ user_id, date: d, ask_count: 0, search_count: 0 }])
      .select()
      .single();
    if (ins.error) throw ins.error;
    row = ins.data;
  }
  return row;
}
async function bumpUsage(user_id, field) {
  const cur = await getOrInitUsage(user_id);
  const next = (cur[field] || 0) + 1;
  const { error } = await supabase.from("usage_daily").update({ [field]: next }).eq("id", cur.id);
  if (error) throw error;
}
function planKey(user) {
  const k = (user?.plan || "moon").toLowerCase();
  return PLAN_LIMITS[k] ? k : "moon";
}

// ---------- OAuth ----------
const OAUTH_CALLBACK = "/auth/google/callback";

passport.use(
  new GoogleStrategy(
    { clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, callbackURL: OAUTH_CALLBACK, proxy: true },
    async (_a, _r, profile, done) => {
      try {
        const u = await upsertUserFromGoogle(profile);
        done(null, { id: u.id });
      } catch (e) {
        done(e);
      }
    }
  )
);
passport.serializeUser((u, d) => d(null, u));
passport.deserializeUser(async (obj, d) => {
  try { d(null, await getUserById(obj.id)); } catch (e) { d(e); }
});

function requireAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error: "Sign in required" });
}

function enforceLimit(kind) {
  return async (req, res, next) => {
    try {
      const pkey = planKey(req.user);
      const limits = PLAN_LIMITS[pkey];
      const usage = await getOrInitUsage(req.user.id);
      const used = kind === "ask" ? usage.ask_count : usage.search_count;
      const allowed = limits[kind];
      if (Number.isFinite(allowed) && used >= allowed) {
        return res.status(429).json({ error: `Daily ${kind} limit reached for ${pkey} plan.` });
      }
      await bumpUsage(req.user.id, kind === "ask" ? "ask_count" : "search_count");
      next();
    } catch (e) {
      console.error("limit error", e);
      res.status(500).json({ error: "Usage/limit error" });
    }
  };
}

// ---------- Static & root ----------
app.use(express.static(__dirname));

app.get("/", (req, res) => {
  // Keep your current behavior: show login if not authenticated; otherwise home
  if (req.isAuthenticated && req.isAuthenticated()) return res.sendFile(path.join(__dirname, "index.html"));
  return res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/login.html", (req, res) => res.sendFile(path.join(__dirname, "login.html")));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  OAUTH_CALLBACK,
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (_req, res) => res.redirect("/")
);

app.post("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

// ---------- Me ----------
app.get("/api/me", async (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  const pkey = planKey(req.user);
  const limits = PLAN_LIMITS[pkey];
  const usage = await getOrInitUsage(req.user.id);
  const remaining = {
    ask: Number.isFinite(limits.ask) ? Math.max(0, limits.ask - (usage.ask_count || 0)) : Infinity,
    search: Number.isFinite(limits.search) ? Math.max(0, limits.search - (usage.search_count || 0)) : Infinity,
  };
  res.json({
    loggedIn: true,
    user: { id: req.user.id, email: req.user.email, name: req.user.name, photo: req.user.photo, plan: pkey },
    remaining,
    today: today(),
  });
});

// ================= FEATURES =================

// Chat AI (Gemini) — ask limit
app.post("/ask", requireAuth, enforceLimit("ask"), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const result = await geminiFlash.generateContent([{ text: q }]);
    res.json({ answer: result.response.text() || "No response." });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

// Search info (Gemini) — search limit
app.post("/search-info", requireAuth, enforceLimit("search"), async (req, res) => {
  try {
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    res.json({ answer: result.response.text() || "No info found." });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});

// ---------- OpenAI: Advanced Chat & Homework (Fix 404s) ----------

const uploadMem = multer({ storage: multer.memoryStorage() });

/**
 * Unified handler that:
 * - accepts text and optional file(s)
 * - includes first image as vision input
 * - remembers last 20 messages in the user's session
 */
async function handleAdvancedChat(req, res) {
  try {
    // Ensure session history exists
    req.session.chatHistory ||= [];

    // Text from front-end
    const userText = (req.body?.message || req.body?.q || "").trim() || "Hello";

    // Find first image/* file to include as vision input
    let imagePart = null;
    for (const f of req.files || []) {
      if ((f.mimetype || "").startsWith("image/")) {
        const b64 = f.buffer.toString("base64");
        const dataUrl = `data:${f.mimetype};base64,${b64}`;
        imagePart = { type: "image_url", image_url: { url: dataUrl } };
        break;
      }
    }

    // Build latest user content block
    const latestUserContent = imagePart
      ? [{ type: "text", text: userText }, imagePart]
      : [{ type: "text", text: userText }];

    // Keep only the last 20 turns (text-only) in session history for continuity
    req.session.chatHistory.push({ role: "user", content: userText });
    req.session.chatHistory = req.session.chatHistory.slice(-20);

    // Call OpenAI
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI, concise and helpful." },
        ...req.session.chatHistory,
        // include the current message again, with the image if present
        { role: "user", content: latestUserContent }
      ],
      temperature: 0.3,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    req.session.chatHistory.push({ role: "assistant", content: reply });

    req.session.save(() => res.json({ reply, model: "gpt-4o-mini" }));
  } catch (e) {
    console.error("/api/chat error", e);
    res.status(500).json({ error: e?.message || "Chat error" });
  }
}

/**
 * Homework Vision (kept for compatibility with pages calling /api/homework)
 */
async function handleHomework(req, res) {
  try {
    const prompt = (req.body?.prompt || req.body?.message || "Solve this step by step.").slice(0, 4000);
    if (!req.file) return res.status(400).json({ error: "No image received" });

    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${req.file.mimetype};base64,${b64}`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: prompt },
            { type: "image_url", image_url: { url: dataUrl } },
          ],
        },
      ],
      temperature: 0.2,
    });

    const reply = completion.choices?.[0]?.message?.content || "No solution found.";
    res.json({ reply, model: "gpt-4o-mini" });
  } catch (e) {
    console.error("/api/homework error", e);
    res.status(500).json({ error: e?.message || "Homework solver error" });
  }
}

// ---- ROUTES (add both canonical paths and aliases to prevent 404) ----

// Canonical OpenAI chat endpoint used by chat-advancedai.html and other pages
app.post("/api/chat", requireAuth, uploadMem.array("files"), handleAdvancedChat);

// Backwards/alt alias some front-ends used
app.post("/chat-advanced-ai", requireAuth, uploadMem.array("files"), handleAdvancedChat);

// Canonical homework vision endpoint
app.post("/api/homework", requireAuth, uploadMem.single("image"), handleHomework);

// Backwards/alt alias
app.post("/homework", requireAuth, uploadMem.single("image"), handleHomework);

// --------- Gate pages (html files) ----------
function gate(file) {
  return (req, res) => {
    if (!req.isAuthenticated || !req.isAuthenticated())
      return res.redirect("/login.html");
    res.sendFile(path.join(__dirname, file));
  };
}
app.get("/advanced-ai.html", gate("advanced-ai.html"));
app.get("/chat-advancedai.html", gate("chat-advancedai.html"));
app.get("/homework-helper.html", gate("homework-helper.html"));
app.get("/learn-physics.html", gate("learn-physics.html"));
app.get("/create-planet.html", gate("create-planet.html"));
app.get("/create-rocket.html", gate("create-rocket.html"));
app.get("/create-satellite.html", gate("create-satellite.html"));
app.get("/your-space.html", gate("your-space.html"));

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
