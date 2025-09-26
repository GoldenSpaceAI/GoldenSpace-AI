// index.js — GoldenSpaceAI (Home-first, Gemini + OpenAI, Model selector, Memory 20, File upload)

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
import { GoogleGenerativeAI } from "@google/generative-ai";

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

// ---------- Simple plan map (not enforced for now; pages unlocked) ----------
const PLAN_LIMITS = {
  moon:  { ask: 40, search: 20 },
  earth: { ask: Infinity, search: Infinity },
  chatai:{ ask: Infinity, search: Infinity }, // ChatAI pack (Advanced too)
};

// ---------- Helper: compute base URL ----------
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] || req.protocol || "https";
  const host = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
  return `${proto}://${host}`;
}

// ---------- Google OAuth (kept; optional) ----------
const DEFAULT_CALLBACK_PATH = "/auth/google/callback";
passport.use(new GoogleStrategy(
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
  }
));
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
  req.logout(err => { if (err) return next(err); req.session.destroy(() => res.json({ ok: true })); });
});

// ---------- PUBLIC / AUTH GATE ----------
// For testing: everything is open. (Keep legal pages public too.)
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?|html)$/i;
function isPublicPath(req) {
  return true; // <- UNLOCK EVERYTHING FOR NOW (testing)
}
// Leave middleware here for future re-locking
function authRequired(req, res, next) {
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error: "Sign in required" });
}

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Gemini ----------
import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
// ---------- OpenAI ----------
import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
// ---------- Memory helpers (session-scoped) ----------
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

// ---------- Utility: read small text-like docs to string ----------
async function readTextIfPossible(filePath, mimetype) {
  try {
    const t = mimetype || "";
    if (t.startsWith("text/") || /\/(json|csv|html|xml)/i.test(t)) {
      return fs.readFileSync(filePath, "utf8").slice(0, 30000); // cap to 30k chars
    }
    return null;
  } catch {
    return null;
  }
}

// ---------- ROUTES (Gemini) ----------
app.post("/ask", async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const result = await modelFlash.generateContent([{ text: `User: ${q}` }]);
    const answer = result.response.text() || "No response.";
    res.json({ answer });
  } catch (e) { console.error("ask error", e); res.status(500).json({ answer: "Gemini error" }); }
});

app.post("/search-info", async (req, res) => {
  try {
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await modelFlash.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  } catch (e) { console.error("search-info error", e); res.status(500).json({ answer: "Search error" }); }
});

app.post("/ai/physics-explain", async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply: "Ask a physics question." });
    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly.\nQuestion: ${q}`;
    const result = await modelFlash.generateContent([{ text: prompt }]);
    const reply = result.response.text() || "No reply.";
    res.json({ reply });
  } catch (e) { console.error("physics error", e); res.status(500).json({ reply: "Physics error" }); }
});

// ---------- Advanced Chat AI (OpenAI) ----------
const upload = multer({ dest: "uploads/" });

// NOTE: this route is used by chat-advancedai.html
app.post("/chat-advanced-ai", upload.single("file"), async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    const model = (req.body?.model || "gpt-4o-mini").trim();

    // Build message list with memory
    const messages = [
      { role: "system", content: "You are GoldenSpaceAI, a crisp expert assistant. Be concise and helpful." },
      ...getHistory(req),
    ];
    if (q) {
      messages.push({ role: "user", content: q });
      pushHistory(req, "user", q);
    }

    // If there's a file, attach it (image → vision; text-like → inline)
    let fileNote = "";
    if (req.file) {
      const filePath = req.file.path;
      const mime = req.file.mimetype || "application/octet-stream";

      if (mime.startsWith("image/")) {
        const b64 = fs.readFileSync(filePath).toString("base64");
        messages.push({
          role: "user",
          content: [
            { type: "text", text: q || "Please analyze this image together with my request." },
            { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } },
          ],
        });
        fileNote = ` (image: ${req.file.originalname})`;
      } else {
        const text = await readTextIfPossible(filePath, mime);
        if (text) {
          messages.push({ role: "user", content: `Attached file "${req.file.originalname}" content (truncated):\n\n${text}` });
          fileNote = ` (doc: ${req.file.originalname})`;
        } else {
          messages.push({ role: "user", content: `Attached file "${req.file.originalname}" (${mime}). If you need to reference it, ask me to upload as text or image.` });
          fileNote = ` (file: ${req.file.originalname})`;
        }
      }
      // cleanup temp file
      fs.unlink(filePath, () => {});
    }

    // Call OpenAI
    const completion = await openai.chat.completions.create({
      model,
      messages,
      temperature: 0.3,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    pushHistory(req, "assistant", reply);

    res.json({ model, reply, note: fileNote });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});
// ---------- Homework Solver (OpenAI vision) ----------
// Accepts:
//  - POST /api/chat           (legacy from your page)
//  - POST /api/homework       (alias to avoid 404)
// Fields:
//  - message or prompt (text)
//  - files[] OR image (first image used)
// Default model: gpt-4o-mini

async function handleHomework(req, res) {
  try {
    const message = (req.body?.message || req.body?.prompt || "").trim();
    const model = (req.body?.model || "gpt-4o-mini").trim();

    // Gather files from any field name
    const allFiles = [];
    if (req.files && Array.isArray(req.files)) allFiles.push(...req.files);
    if (req.file) allFiles.push(req.file); // in case of single("image")

    const parts = [];
    if (message) parts.push({ type: "text", text: message });

    // Pick first image if present
    const img = allFiles.find(f => (f.mimetype || "").startsWith("image/"));
    if (img) {
      const b64 = fs.readFileSync(img.path).toString("base64");
      parts.push({
        type: "image_url",
        image_url: { url: `data:${img.mimetype};base64,${b64}` },
      });
    }

    // Cleanup temp files
    for (const f of allFiles) { try { fs.unlinkSync(f.path); } catch {} }

    if (parts.length === 0) {
      return res.status(400).json({ error: "Provide an image or a message." });
    }

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        {
          role: "system",
          content:
            "You are GoldenSpaceAI Homework Helper. Explain step-by-step, show working, and verify the final answer.",
        },
        { role: "user", content: parts },
      ],
      temperature: 0.2,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ model, reply });
  } catch (e) {
    console.error("homework api error", e);
    res.status(500).json({ error: "Homework error" });
  }
}

// Accept any file field names on both endpoints
app.post("/api/chat",      upload.any(), handleHomework);
app.post("/api/homework",  upload.any(), handleHomework);
// ---------- /api/me (basic info for header pills, etc.) ----------
app.get("/api/me", (req, res) => {
  const plan = req.user?.plan || "moon";
  res.json({
    loggedIn: !!req.user,
    email: req.user?.email || null,
    name: req.user?.name || null,
    given_name: req.user?.name?.split(" ")?.[0] || null,
    picture: req.user?.photo || null,
    plan,
  });
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
