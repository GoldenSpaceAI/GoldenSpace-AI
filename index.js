// index.js — GoldenSpaceAI (Gemini for search/lessons, OpenAI for advanced chat, robust uploads)

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
  NODE_ENV,
  PORT,
} = process.env;

if (!SESSION_SECRET) throw new Error("SESSION_SECRET missing");
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET)
  throw new Error("Google OAuth envs missing");
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY)
  throw new Error("Supabase envs missing");
if (!GEMINI_API_KEY) console.warn("⚠ GEMINI_API_KEY missing (Gemini endpoints will fail)");
if (!OPENAI_API_KEY) console.warn("⚠ OPENAI_API_KEY missing (OpenAI endpoints will fail)");

// ---------- SDKs ----------
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------- App ----------
const app = express();
app.set("trust proxy", 1);
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true }));
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
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Plans & usage ----------
const PLAN_LIMITS = {
  moon: { ask: 40, search: 20 },
  earth: { ask: Infinity, search: Infinity },
  chatai: { ask: Infinity, search: Infinity },
  spacepack: { ask: 40, search: 20 },
};
const today = () => new Date().toISOString().slice(0, 10);

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
  const { data, error } = await supabase
    .from("users")
    .select("*")
    .eq("id", id)
    .single();
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
  const { error } = await supabase
    .from("usage_daily")
    .update({ [field]: next })
    .eq("id", cur.id);
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
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: OAUTH_CALLBACK,
      proxy: true,
    },
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
  try {
    d(null, await getUserById(obj.id));
  } catch (e) {
    d(e);
  }
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
        return res
          .status(429)
          .json({ error: `Daily ${kind} limit reached for ${pkey} plan.` });
      }
      await bumpUsage(req.user.id, kind === "ask" ? "ask_count" : "search_count");
      next();
    } catch (e) {
      console.error("limit error", e);
      res.status(500).json({ error: "Usage/limit error" });
    }
  };
}

// ---------- Static ----------
app.use(express.static(__dirname));

// Show HOME first (not login)
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/login.html", (_req, res) => res.sendFile(path.join(__dirname, "login.html")));

// ---------- Auth routes ----------
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  OAUTH_CALLBACK,
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (req, res) => res.redirect("/")
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
    ask: Number.isFinite(limits.ask)
      ? Math.max(0, limits.ask - (usage.ask_count || 0))
      : Infinity,
    search: Number.isFinite(limits.search)
      ? Math.max(0, limits.search - (usage.search_count || 0))
      : Infinity,
  };
  res.json({
    loggedIn: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      photo: req.user.photo,
      plan: pkey,
    },
    remaining,
    today: today(),
  });
});

// ================= Upload helper =================
const uploadMem = multer({ storage: multer.memoryStorage() });

/**
 * Build a multimodal user "content" array for OpenAI Chat Completions.
 * Always returns at least one text block so the API never fails,
 * and images are sent as data URLs for vision models.
 */
async function buildUserMessageBlocks({ text, files }) {
  const blocks = [];

  if (text && String(text).trim()) {
    blocks.push({ type: "text", text: String(text).trim() });
  }

  if (files && files.length) {
    for (const f of files) {
      const mime = f.mimetype || "application/octet-stream";
      if (mime.startsWith("image/")) {
        const b64 = f.buffer.toString("base64");
        blocks.push({
          type: "image_url",
          image_url: { url: `data:${mime};base64,${b64}` },
        });
      } else if (
        mime.startsWith("text/") ||
        mime === "application/json" ||
        mime === "application/xml"
      ) {
        const content = f.buffer.toString("utf8").slice(0, 12000);
        blocks.push({
          type: "text",
          text: `Attached file "${f.originalname}" (${mime}) — first content bytes:\n\n${content}`,
        });
      } else {
        blocks.push({
          type: "text",
          text: `User attached a binary file "${f.originalname}" (${mime}, ${f.size} bytes). Summarize guidance for handling it based on the user's request.`,
        });
      }
    }
  }

  if (blocks.length === 0) {
    blocks.push({ type: "text", text: "Please analyze the attachment and/or respond helpfully." });
  }
  return blocks;
}

// ================== GEMINI FEATURES ==================

// Ask (advanced info via Gemini)
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

// Search info (Gemini)
app.post("/search-info", requireAuth, enforceLimit("search"), async (req, res) => {
  try {
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Provide an overview + 3 concise bullet facts.\nTopic: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    res.json({ answer: result.response.text() || "No info found." });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});

// NEW: Search lessons (Gemini) — returns bite-size lesson ideas
app.post("/search-lessons", requireAuth, enforceLimit("search"), async (req, res) => {
  try {
    const topic = (req.body?.topic || req.body?.query || "").trim();
    if (!topic) return res.json({ lessons: [], answer: "Give me a topic to build lessons." });
    const prompt = `Create 5 short lesson ideas for students about "${topic}". 
Return each with: title, 2-sentence summary, and 3 bullet learning steps. Be concise.`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    res.json({ answer: result.response.text() || "No lessons found." });
  } catch (e) {
    console.error("search-lessons error", e);
    res.status(500).json({ answer: "Lessons search error" });
  }
});

// Backwards-compatible aliases some pages might call
app.post("/api/advanced-ai", requireAuth, enforceLimit("ask"), async (req, res) => {
  try {
    const q = (req.body?.question || req.body?.prompt || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const result = await geminiFlash.generateContent([{ text: q }]);
    res.json({ answer: result.response.text() || "No response." });
  } catch (e) {
    console.error("advanced-ai alias error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

// ================== OPENAI FEATURES ==================

// Advanced Chat for chat-advancedai.html — supports text AND files (image/text/binary)
app.post("/api/chat", requireAuth, uploadMem.array("files"), async (req, res) => {
  try {
    const userBlocks = await buildUserMessageBlocks({
      text: req.body?.message || "",
      files: req.files || [],
    });

    // keep a small rolling history
    req.session.chatHistory ||= [];
    req.session.chatHistory.push({ role: "user", content: userBlocks });
    req.session.chatHistory = req.session.chatHistory.slice(-20);

    const model = (req.body?.model || "gpt-4o-mini").trim() || "gpt-4o-mini";

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        {
          role: "system",
          content:
            "You are GoldenSpaceAI. Be concise, helpful, and robust with files. If only an image or file is provided, analyze it directly before asking questions.",
        },
        ...req.session.chatHistory,
      ],
      temperature: 0.25,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    req.session.chatHistory.push({ role: "assistant", content: reply });
    req.session.save(() => res.json({ reply, model }));
  } catch (e) {
    console.error("/api/chat error", e);
    res.status(500).json({ error: e?.message || "Chat error" });
  }
});

// Homework Solver — image + optional text prompt; OpenAI Vision
app.post("/api/homework", requireAuth, uploadMem.single("image"), async (req, res) => {
  try {
    const prompt =
      (req.body?.prompt || "Solve this step by step and explain clearly.").slice(0, 4000);

    const files = req.file ? [req.file] : [];
    const blocks = await buildUserMessageBlocks({ text: prompt, files });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a careful tutor. Show working and reasoning. If an image is provided, read it first. If text only, still solve it.",
        },
        { role: "user", content: blocks },
      ],
      temperature: 0.2,
    });

    const reply = completion.choices?.[0]?.message?.content || "No solution found.";
    res.json({ reply, model: "gpt-4o-mini" });
  } catch (e) {
    console.error("/api/homework error", e);
    res.status(500).json({ error: e?.message || "Homework solver error" });
  }
});

// Lightweight text endpoint (optional camera frame as image)
app.post("/api/live-text", requireAuth, uploadMem.single("frame"), async (req, res) => {
  try {
    const text = (req.body?.message || "").toString();
    const files = req.file ? [req.file] : [];
    const blocks = await buildUserMessageBlocks({ text, files });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: blocks }],
      temperature: 0.3,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model: "gpt-4o-mini" });
  } catch (e) {
    console.error("/api/live-text error", e);
    res.status(500).json({ error: e?.message || "Live text error" });
  }
});

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
app.get("/chat-advancedai-voice.html", gate("chat-advancedai-voice.html"));
app.get("/homework-helper.html", gate("homework-helper.html"));
app.get("/learn-physics.html", gate("learn-physics.html"));
app.get("/create-planet.html", gate("create-planet.html"));
app.get("/create-rocket.html", gate("create-rocket.html"));
app.get("/create-satellite.html", gate("create-satellite.html"));
app.get("/your-space.html", gate("your-space.html"));

// Health
app.get("/health", (_req, res) => res.json({ ok: true }));
app.head("/health", (_req, res) => res.status(200).end());

// Start
const APP_PORT = PORT || 3000;
app.listen(APP_PORT, () =>
  console.log(`🚀 GoldenSpaceAI running on ${APP_PORT}`)
);
