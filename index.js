// index.js — GoldenSpaceAI (Home-first, Gemini Flash + OpenAI, true Realtime token)

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
  SESSION_SECRET = "dev_secret_change_me",
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  GEMINI_API_KEY,
  OPENAI_API_KEY,
  NODE_ENV,
  BASE_URL, // optional, for OAuth on Render
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn("⚠️ Supabase envs missing — plan/usage features will be limited.");
}
if (!GEMINI_API_KEY) console.warn("⚠️ GEMINI_API_KEY missing.");
if (!OPENAI_API_KEY) console.warn("⚠️ OPENAI_API_KEY missing.");
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.warn("⚠️ Google OAuth envs missing. /auth/google will show an error.");
}

// ---------- SDKs ----------
const supabase = (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY)
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
  : null;

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const geminiFlash = GEMINI_API_KEY
  ? genAI.getGenerativeModel({ model: "gemini-1.5-flash" })
  : null;

// ---------- App ----------
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
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
      maxAge: 1000 * 60 * 60 * 24 * 14,
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Basic user store in Supabase (optional) ----------
async function upsertUserFromGoogle(profile) {
  if (!supabase) return { id: "anon", email: profile.emails?.[0]?.value || "", name: profile.displayName || "" };

  const email = profile.emails?.[0]?.value?.toLowerCase() || "";
  const name = profile.displayName || "";
  const photo = profile.photos?.[0]?.value || "";

  let { data: user, error } = await supabase.from("users").select("*").eq("email", email).maybeSingle();
  if (error) throw error;

  if (!user) {
    const ins = await supabase.from("users")
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
  if (!supabase) return { id: "anon" };
  const { data, error } = await supabase.from("users").select("*").eq("id", id).single();
  if (error) throw error;
  return data;
}

// ---------- OAuth (still available, but not required for testing) ----------
const OAUTH_CALLBACK = "/auth/google/callback";
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID || "x",
      clientSecret: GOOGLE_CLIENT_SECRET || "y",
      callbackURL: BASE_URL ? `${BASE_URL}${OAUTH_CALLBACK}` : OAUTH_CALLBACK,
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
  try { d(null, await getUserById(obj.id)); } catch (e) { d(e); }
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get(
  OAUTH_CALLBACK,
  passport.authenticate("google", { failureRedirect: "/login.html" }),
  (_req, res) => res.redirect("/")
);

// ---------- Static ----------
app.use(express.static(__dirname));

// ---------- Home-first ----------
app.get("/", (_req, res) => {
  // Always show home (unlocked for testing)
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/me", (req, res) => {
  const u = req.user
    ? { loggedIn: true, id: req.user.id, email: req.user.email, name: req.user.name, photo: req.user.photo }
    : { loggedIn: false };
  res.json(u);
});

// ================= FEATURES =================

// 1) Chat AI (Gemini) — text Q&A
app.post("/ask", async (req, res) => {
  try {
    if (!geminiFlash) return res.status(500).json({ answer: "Gemini not configured." });
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const result = await geminiFlash.generateContent([{ text: q }]);
    res.json({ answer: result.response.text() || "No response." });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

// 2) Search info (Gemini) — summaries
app.post("/search-info", async (req, res) => {
  try {
    if (!geminiFlash) return res.status(500).json({ answer: "Gemini not configured." });
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

// 3) Learn physics (Gemini) — tutor style
app.post("/learn-physics", async (req, res) => {
  try {
    if (!geminiFlash) return res.status(500).json({ answer: "Gemini not configured." });
    const topic = (req.body?.topic || "Kinematics").trim();
    const prompt = `Teach ${topic} with a short explanation and 3 progressively harder practice problems with answers.`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    res.json({ answer: result.response.text() || "No lesson." });
  } catch (e) {
    console.error("learn-physics error", e);
    res.status(500).json({ answer: "Lesson error" });
  }
});

// 4) Advanced Chat (OpenAI) — model selector + documents
const uploadMem = multer({ storage: multer.memoryStorage() });

function normalizeChatModel(m) {
  // Map requested labels to real models
  const x = (m || "").toLowerCase();
  if (x === "gpt-5" || x === "gpt5" || x === "gpt-5-nano" || x === "gpt5nano") return "gpt-4o-mini";
  if (x === "gpt-4" || x === "gpt4") return "gpt-4o-mini";
  return "gpt-4o-mini";
}

app.post("/api/chat", uploadMem.array("files"), async (req, res) => {
  try {
    const text = (req.body?.message || "").trim() || "Hello";
    const model = normalizeChatModel(req.body?.model);
    // maintain last 20 messages in session
    req.session.chatHistory ||= [];
    req.session.chatHistory.push({ role: "user", content: text });
    req.session.chatHistory = req.session.chatHistory.slice(-20);

    // If images are attached, convert first to data URL & include as vision
    let userContent;
    const firstFile = (req.files || [])[0];
    if (firstFile && firstFile.mimetype?.startsWith("image/")) {
      const b64 = firstFile.buffer.toString("base64");
      const dataUrl = `data:${firstFile.mimetype};base64,${b64}`;
      userContent = [
        { type: "text", text },
        { type: "image_url", image_url: { url: dataUrl } },
      ];
    } else {
      userContent = text;
    }

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are GoldenSpaceAI, concise and helpful." },
        ...req.session.chatHistory,
        { role: "user", content: userContent },
      ],
      temperature: 0.3,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    req.session.chatHistory.push({ role: "assistant", content: reply });
    req.session.save(() => res.json({ reply, model }));
  } catch (e) {
    console.error("/api/chat error", e);
    res.status(500).json({ error: e?.message || "Chat error" });
  }
});

// 5) Homework Solver (OpenAI Vision, image + text)
app.post("/api/homework", uploadMem.single("image"), async (req, res) => {
  try {
    const prompt = (req.body?.prompt || "Solve this step by step.").slice(0, 4000);
    if (!req.file) return res.status(400).json({ error: "No image received" });

    const b64 = req.file.buffer.toString("base64");
    const dataUrl = `data:${req.file.mimetype};base64,${b64}`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a careful math & science tutor. Show steps clearly." },
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
    res.json({ reply });
  } catch (e) {
    console.error("/api/homework error", e);
    res.status(500).json({ error: e?.message || "Homework solver error" });
  }
});

// 6) LIVE voice/camera — Realtime ephemeral session token
// Frontend calls this, then connects to OpenAI Realtime (WebRTC/WebSocket) using the token.
// This is truly live (no polling). Your client page should hit this endpoint first.
app.post("/api/realtime-session", async (req, res) => {
  try {
    // Optional: let client request a specific realtime variant
    // For now, we standardize to gpt-4o-realtime-preview (closest to 4o-mini live).
    const requested = (req.body?.model || "").toLowerCase();
    const model = requested && requested.includes("mini")
      ? "gpt-4o-realtime-preview"  // map "mini live" to current realtime
      : "gpt-4o-realtime-preview";

    const session = await openai.realtime.sessions.create({
      model,
      voice: "verse",              // you can change the default voice later in the client
      // instructions: "You are GoldenSpaceAI ..." // optional system behavior
    });

    // Return ephemeral client secret the browser can use to start the Realtime session
    res.json({ client_secret: session.client_secret, model });
  } catch (e) {
    console.error("/api/realtime-session error", e);
    res.status(500).json({ error: e?.message || "Realtime session error" });
  }
});

// 7) Convenience aliases used by your UI earlier (to avoid 404s)
app.post("/api/live", uploadMem.single("image"), async (req, res) => {
  // Reuse vision for live single-frame calls if needed
  req.body.prompt = req.body.prompt || req.body.message || "Describe this image.";
  return app._router.handle(req, res, () => {}, "POST", "/api/homework");
});
app.post("/api/live-text", async (req, res) => {
  try {
    const text = (req.body?.q || req.body?.message || "").trim();
    if (!text) return res.status(400).json({ error: "Empty message" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI, concise and helpful." },
        { role: "user", content: text },
      ],
      temperature: 0.3,
    });
    res.json({ reply: completion.choices?.[0]?.message?.content || "No reply." });
  } catch (e) {
    console.error("/api/live-text error", e);
    res.status(500).json({ error: e?.message || "Chat error" });
  }
});

// ---------- Simple health ----------
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
