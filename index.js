// index.js — GoldenSpaceAI (Node 22 clean)
// Mongo-free sessions, plans, static hosting, GPT-4 tutor routes.

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

// ---------- Sessions (MemoryStore — no DB needed) ----------
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
  })
);

// ---------- Paths & static ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Plans & capabilities ----------
const PLAN_CODES = { earth: "33117722", space: "22116644", chatai: "444666333222" };
const CAPS = {
  CHAT: "chat",
  SEARCH_INFO: "search-info",
  LEARN_INFO: "learn-info",
  PHYSICS: "physics",
  CREATE_PLANET: "create-planet",
  CREATE_ROCKET: "create-rocket",
  CREATE_SAT: "create-satellite",
  CREATE_UNIVERSE: "create-universe",
  ADVANCED_CHAT: "advanced-chat",
  HOMEWORK: "homework",
  LESSON_SEARCH: "lesson-search",
};
const PLAN_CAPS = {
  moon: new Set([CAPS.SEARCH_INFO, CAPS.CHAT]),
  earth: new Set([CAPS.CHAT, CAPS.LEARN_INFO, CAPS.PHYSICS, CAPS.CREATE_PLANET]),
  space: new Set([
    CAPS.CHAT, CAPS.SEARCH_INFO, CAPS.ADVANCED_CHAT, CAPS.HOMEWORK, CAPS.LESSON_SEARCH,
    CAPS.LEARN_INFO, CAPS.PHYSICS, CAPS.CREATE_PLANET, CAPS.CREATE_ROCKET, CAPS.CREATE_SAT, CAPS.CREATE_UNIVERSE,
  ]),
  chatai: new Set([CAPS.CHAT, CAPS.SEARCH_INFO, CAPS.ADVANCED_CHAT, CAPS.HOMEWORK, CAPS.LESSON_SEARCH]),
};
const PLAN_LIMITS = {
  moon: { ask: 40, search: 20 },
  earth: { ask: Infinity, search: Infinity },
  chatai: { ask: Infinity, search: Infinity },
  space: { ask: Infinity, search: Infinity },
};

// ---------- Helpers ----------
function getBaseUrl(req) {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] || req.protocol || "https";
  const host = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
  return `${proto}://${host}`;
}
function getPlan(req) { return req.session.plan || "moon"; }
function setPlan(req, plan) { req.session.plan = plan; }
function requireCaps(...required) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const caps = PLAN_CAPS[plan] || PLAN_CAPS.moon;
    for (const r of required) {
      if (!caps.has(r)) return res.status(403).json({ error: `Your plan (${plan}) does not allow this action.` });
    }
    next();
  };
}

// ---------- Google OAuth (optional; only if env set) ----------
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
    const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
    passport.authenticate("google", { scope: ["profile", "email"], callbackURL })(req, res, next);
  });
  app.get(DEFAULT_CALLBACK_PATH, (req, res, next) => {
    const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
    passport.authenticate("google", { failureRedirect: "/login.html", callbackURL })(req, res, () => res.redirect("/"));
  });
  app.post("/logout", (req, res, next) => {
    req.logout?.((err) => {
      if (err) return next(err);
      req.session.destroy(() => res.json({ ok: true }));
    });
  });
}

// ---------- Public/auth gate (everything public for now) ----------
function isPublicPath(_req) { return true; }
function authRequired(req, res, next) {
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error: "Sign in required" });
}

// ---------- OpenAI client ----------
if (!process.env.OPENAI_API_KEY) {
  console.warn("⚠️ OPENAI_API_KEY is not set. Tutor endpoints will fail until you add it.");
}
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Uploads ----------
const uploadsDir = path.join(__dirname, "uploads");
try { fs.mkdirSync(uploadsDir, { recursive: true }); } catch {}
const upload = multer({ dest: uploadsDir });

// NEW: memory storage for AI endpoints (no leftover tmp files)
const memoryUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: (parseInt(process.env.MAX_UPLOAD_MB || "25", 10)) * 1024 * 1024, // default 25MB each
    files: parseInt(process.env.MAX_UPLOAD_FILES || "12", 10),
  },
});

// ---------- Plan activation ----------
app.post("/plan/activate", (req, res) => {
  const code = (req.body?.code || "").trim();
  if (!code) return res.status(400).json({ ok: false, error: "No code" });
  if (code === PLAN_CODES.earth) setPlan(req, "earth");
  else if (code === PLAN_CODES.space) setPlan(req, "space");
  else if (code === PLAN_CODES.chatai) setPlan(req, "chatai");
  else return res.status(401).json({ ok: false, error: "Invalid password. Contact support goldenspaceais@gmail.com for help." });
  return res.json({ ok: true, plan: getPlan(req) });
});

// ---------- /api/me ----------
app.get("/api/me", (req, res) => {
  const plan = getPlan(req);
  res.json({
    loggedIn: !!req.user,
    email: req.user?.email || null,
    name: req.user?.name || null,
    given_name: req.user?.name?.split(" ")?.[0] || null,
    picture: req.user?.photo || null,
    plan,
  });
});

// ================== AI ROUTES ==================

// Basic Chat (CHAT)
app.post("/ask", requireCaps(CAPS.CHAT), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });
    const plan = getPlan(req);
    const model = plan === "chatai" ? "gpt-3.5-turbo" : "gpt-4o-mini";
    const completion = await openai.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are GoldenSpaceAI. Always answer in a long, detailed way." },
        { role: "user", content: q },
      ],
      temperature: 0.3,
    });
    res.json({ model, answer: completion.choices[0]?.message?.content || "No response." });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "OpenAI error" });
  }
});

// Search Info (SEARCH_INFO)
app.post("/search-info", requireCaps(CAPS.SEARCH_INFO), async (req, res) => {
  try {
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Provide a concise overview followed by 3 bullet facts.\nTopic: ${q}`;
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.2,
    });
    res.json({ answer: completion.choices[0]?.message?.content || "No info found." });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});

// Learn Info (LEARN_INFO)
app.post("/learn-info", requireCaps(CAPS.LEARN_INFO), async (req, res) => {
  try {
    const q = (req.body?.topic || "").trim();
    if (!q) return res.json({ lesson: "Give me a topic to learn!" });
    const prompt = `Teach me about: ${q}\n- Definitions\n- Key concepts\n- Examples\n- A short quiz at the end`;
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
    });
    res.json({ lesson: completion.choices[0]?.message?.content || "No lesson." });
  } catch (e) {
    console.error("learn-info error", e);
    res.status(500).json({ lesson: "Learn error" });
  }
});

// Physics Explain (right-side quick box) — matches learn-physics.html
app.post("/api/physics-explain", requireCaps(CAPS.PHYSICS), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply: "Ask a physics question." });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a clear, concise physics explainer for high school to early undergrad. Use units, short steps, and add 1 quick practice at the end." },
        { role: "user", content: q },
      ],
      temperature: 0.2,
    });
    res.json({ reply: completion.choices[0]?.message?.content || "No reply." });
  } catch (e) {
    console.error("physics-explain error", e);
    res.status(500).json({ reply: "Physics error" });
  }
});

// Full Tutor chat (center chat) — matches learn-physics.html
app.post("/api/physics-tutor", requireCaps(CAPS.PHYSICS), async (req, res) => {
  try {
    const { question = "", topic = "Mechanics", mode = "Socratic" } = req.body || {};
    const modeInstr = {
      Socratic: "Start with 1–2 guiding questions, then outline steps, then final answer.",
      Steps: "Show the full derivation step-by-step with LaTeX-style equations inline.",
      Practice: "Generate 3 practice problems of increasing difficulty with brief solutions after a 'Solutions:' line.",
      Check: "Grade the student's work: identify errors, show corrected steps, and give a score /10."
    }[mode] || "Explain clearly.";
    const messages = [
      { role: "system", content: "You are GoldenSpaceAI, a rigorous but friendly physics tutor. Prefer step-by-step reasoning, dimensional analysis, and units checks. Keep answers compact but complete." },
      { role: "user", content: `Topic: ${topic}\nMode: ${mode}\nInstruction: ${modeInstr}\nStudent: ${question}` }
    ];
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      temperature: 0.2,
    });
    res.json({ reply: completion.choices[0]?.message?.content || "No reply." });
  } catch (e) {
    console.error("physics-tutor error", e);
    res.status(500).json({ reply: "Tutor error" });
  }
});

// --- Create Planet
app.post("/ai/create-planet", requireCaps(CAPS.CREATE_PLANET), async (req, res) => {
  try {
    const specs = req.body?.specs || {};
    const prompt = `Invent a realistic exoplanet with these preferences (JSON below). Return: name, star type, orbit, climate, continents, life likelihood, fun fact.\nSpecs:\n${JSON.stringify(specs, null, 2)}`;
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.6,
    });
    res.json({ planet: completion.choices[0]?.message?.content || "{}" });
  } catch (e) {
    console.error("create-planet error", e);
    res.status(500).json({ error: "Create planet error" });
  }
});

// --- Create Rocket
app.post("/ai/create-rocket", requireCaps(CAPS.CREATE_ROCKET), async (_req, res) => {
  try {
    const prompt = "Design a conceptual rocket (non-actionable). Provide: stages, payload class, propulsion overview, safety notes, and a 3-step launch profile (high level).";
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.6,
    });
    res.json({ rocket: completion.choices[0]?.message?.content || "No design." });
  } catch (e) {
    console.error("create-rocket error", e);
    res.status(500).json({ error: "Create rocket error" });
  }
});

// --- Create Satellite
app.post("/ai/create-satellite", requireCaps(CAPS.CREATE_SAT), async (_req, res) => {
  try {
    const prompt = "Design a conceptual Earth-observation satellite at a high level (non-operational): payload, orbit type, mission goals, ground segment overview.";
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.6,
    });
    res.json({ satellite: completion.choices[0]?.message?.content || "No design." });
  } catch (e) {
    console.error("create-satellite error", e);
    res.status(500).json({ error: "Create satellite error" });
  }
});

// --- Create Universe
app.post("/ai/create-universe", requireCaps(CAPS.CREATE_UNIVERSE), async (req, res) => {
  try {
    const theme = (req.body?.theme || "space opera").trim();
    const prompt = `Generate a fictional shared universe bible (creative and safe): era, factions, key planets, tech flavor, magic/science rules, 5 plot seeds.\nTheme: ${theme}`;
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.8,
    });
    res.json({ universe: completion.choices[0]?.message?.content || "No universe." });
  } catch (e) {
    console.error("create-universe error", e);
    res.status(500).json({ error: "Create universe error" });
  }
});

// --- Advanced Chat (vision/file aware)
const uploadAny = multer({ dest: uploadsDir });
function pushHistory(req, role, content) {
  if (!req.session.advHistory) req.session.advHistory = [];
  req.session.advHistory.push({ role, content });
  if (req.session.advHistory.length > 20) req.session.advHistory = req.session.advHistory.slice(-20);
}
function getHistory(req) {
  return (req.session.advHistory || []).map((m) => ({ role: m.role, content: m.content }));
}
async function readTextIfPossible(filePath, mimetype) {
  try {
    const t = mimetype || "";
    if (t.startsWith("text/") || /(\/|^)(json|csv|html|xml)$/i.test(t)) {
      return fs.readFileSync(filePath, "utf8").slice(0, 30000);
    }
    return null;
  } catch { return null; }
}

app.post("/chat-advanced-ai", requireCaps(CAPS.ADVANCED_CHAT), uploadAny.single("file"), async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    const sys = (req.body?.system || "You are GoldenSpaceAI Advanced Assistant. Always provide long, detailed answers.").toString();
    const messages = [{ role: "system", content: sys }, ...getHistory(req)];
    if (q) { messages.push({ role: "user", content: q }); pushHistory(req, "user", q); }

    // Attach file (image => vision, text-like => inline)
    if (req.file) {
      const filePath = req.file.path;
      const mime = req.file.mimetype || "application/octet-stream";
      if (mime.startsWith("image/")) {
        const b64 = fs.readFileSync(filePath).toString("base64");
        messages.push({
          role: "user",
          content: [
            { type: "text", text: q || "Analyze this image with my request." },
            { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } },
          ],
        });
      } else {
        const text = await readTextIfPossible(filePath, mime);
        messages.push({
          role: "user",
          content: text
            ? `Attached file "${req.file.originalname}" (truncated):\n\n${text}`
            : `Attached file "${req.file.originalname}" (${mime}).`,
        });
      }
      fs.unlink(filePath, () => {});
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages,
      temperature: 0.3,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    pushHistory(req, "assistant", reply);
    res.json({ model: "gpt-4o", reply });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});

// --- Homework (vision-capable input)
async function handleHomework(req, res) {
  try {
    const message = (req.body?.message || req.body?.prompt || "").trim();
    const model = "gpt-4o-mini";

    const allFiles = [];
    if (req.files && Array.isArray(req.files)) allFiles.push(...req.files);
    if (req.file) allFiles.push(req.file);

    const parts = [];
    if (message) parts.push({ type: "text", text: message });

    const img = allFiles.find((f) => (f.mimetype || "").startsWith("image/"));
    if (img) {
      const b64 = fs.readFileSync(img.path).toString("base64");
      parts.push({ type: "image_url", image_url: { url: `data:${img.mimetype};base64,${b64}` } });
    }

    for (const f of allFiles) { try { fs.unlinkSync(f.path); } catch {} }

    if (parts.length === 0) return res.status(400).json({ error: "Provide an image or a message." });

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are GoldenSpaceAI Homework Helper. Explain step-by-step, show working, and verify the final answer." },
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
app.post("/api/chat", requireCaps(CAPS.HOMEWORK), uploadAny.any(), handleHomework);
app.post("/api/homework", requireCaps(CAPS.HOMEWORK), uploadAny.any(), handleHomework);

// ================== NEW: Prepare/Grade Exam endpoints (for prepare-exam.html) ==================

// Utility: make data URL for any file buffer (image, pdf, docx...) — suitable for 'responses' API as input_image
function bufferToDataUrl(mime, buf) { return `data:${mime || "application/octet-stream"};base64,${buf.toString("base64")}`; }

function pickModelForExam() {
  // Small + cheap default; upgrade easily via env
  return process.env.EXAM_MODEL || "gpt-4o-mini";
}

function safeJson(text) {
  try { return JSON.parse(text); } catch {}
  // try to extract the first JSON object
  const m = text.match(/\{[\s\S]*\}/);
  if (m) { try { return JSON.parse(m[0]); } catch {} }
  return null;
}

// POST /api/prepare-exam — returns exam blueprint JSON
app.post("/api/prepare-exam", memoryUpload.array("files"), async (req, res) => {
  try {
    const options = (() => { try { return JSON.parse(req.body?.options || "{}"); } catch { return {}; } })();

    // Build content parts for the Responses API: one input_text + N input_image (data URLs)
    const content = [];
    const sys = [
      `You are an assessment designer. Create a rigorous exam based ONLY on the provided materials.`,
      `Subject: ${options.subject || "General"}`,
      `Level: ${options.level || "High School"}`,
      `Difficulty: ${options.difficulty || "Mixed"}`,
      `Count: ${options.count || 15}`,
      `Types: ${JSON.stringify(options.types || { mcq:true, short:true })}`,
      options.extra ? `Extra: ${options.extra}` : null,
      `Return STRICT JSON with keys: title, instructions, sections:[{title, questions:[{q, choices?, answer}]}]. No markdown.`
    ].filter(Boolean).join("\n");
    content.push({ type: "input_text", text: sys });

    for (const f of (req.files || [])) {
      const dataUrl = bufferToDataUrl(f.mimetype, f.buffer);
      content.push({ type: "input_image", image_url: dataUrl });
    }

    const model = pickModelForExam();

    // Prefer Responses API (handles mixed modal parts cleanly)
    let exam;
    try {
      const response = await openai.responses.create({
        model,
        input: [ { role: "user", content } ],
        temperature: 0.2,
        max_output_tokens: 2000,
        response_format: { type: "json_object" }
      });
      // Try multiple shapes produced by SDK versions
      const outText = response.output_text
        || response.output?.[0]?.content?.[0]?.text
        || response.output?.[0]?.content?.[0]?.text?.value
        || response.content?.[0]?.text
        || JSON.stringify(response);
      exam = safeJson(outText);
    } catch (e) {
      // Fallback to chat.completions (images only if image/*)
      const chatParts = [{ type: "text", text: sys }];
      for (const f of (req.files || [])) {
        if ((f.mimetype || "").startsWith("image/")) {
          chatParts.push({ type: "image_url", image_url: { url: bufferToDataUrl(f.mimetype, f.buffer) } });
        }
      }
      const completion = await openai.chat.completions.create({
        model,
        messages: [ { role: "user", content: chatParts } ],
        temperature: 0.2,
      });
      exam = safeJson(completion.choices?.[0]?.message?.content || "");
    }

    if (!exam || !Array.isArray(exam.sections)) {
      return res.status(500).send("Model did not return a valid exam JSON. Try different files or smaller batch.");
    }
    return res.json(exam);
  } catch (e) {
    console.error("prepare-exam error", e);
    res.status(500).send(e?.message || "Prepare exam error");
  }
});

// POST /api/grade-exam — returns grading report JSON
app.post("/api/grade-exam", memoryUpload.any(), async (req, res) => {
  try {
    const exam = (() => { try { return JSON.parse(req.body?.exam || "{}"); } catch { return {}; } })();
    const typed = (req.body?.typed || "").toString();

    if (!exam || !Array.isArray(exam.sections)) return res.status(400).send("Missing or invalid exam JSON.");

    const content = [];
    const instr = [
      `Grade the student's work strictly against the provided EXAM JSON.`,
      `Return STRICT JSON: { score:number, of:number, summary:string, items:[{ q:string, student:string, result:string, feedback:string, points:number }] }`,
      `Interpret MCQ/short answers exactly; for open-ended, award partial credit using a short rubric.`,
      `If typed answers are provided, prefer them; otherwise try to read from uploaded images/docs.`
    ].join("\n");

    content.push({ type: "input_text", text: instr });
    content.push({ type: "input_text", text: `EXAM JSON:\n${JSON.stringify(exam)}` });
    if (typed) content.push({ type: "input_text", text: `TYPED ANSWERS:\n${typed}` });

    // Attach any uploaded solved files (images, pdfs, docs)
    for (const f of (req.files || [])) {
      const dataUrl = bufferToDataUrl(f.mimetype, f.buffer);
      content.push({ type: "input_image", image_url: dataUrl });
    }

    const model = pickModelForExam();
    let report;
    try {
      const response = await openai.responses.create({
        model,
        input: [ { role: "user", content } ],
        temperature: 0.1,
        max_output_tokens: 2000,
        response_format: { type: "json_object" }
      });
      const outText = response.output_text
        || response.output?.[0]?.content?.[0]?.text
        || response.output?.[0]?.content?.[0]?.text?.value
        || response.content?.[0]?.text
        || JSON.stringify(response);
      report = safeJson(outText);
    } catch (e) {
      // Fallback to chat for image files only
      const chatParts = [{ type: "text", text: `${instr}\n\nEXAM JSON:\n${JSON.stringify(exam)}\n\nTYPED ANSWERS:\n${typed}` }];
      for (const f of (req.files || [])) {
        if ((f.mimetype || "").startsWith("image/")) {
          chatParts.push({ type: "image_url", image_url: { url: bufferToDataUrl(f.mimetype, f.buffer) } });
        }
      }
      const completion = await openai.chat.completions.create({
        model,
        messages: [ { role: "user", content: chatParts } ],
        temperature: 0.1,
      });
      report = safeJson(completion.choices?.[0]?.message?.content || "");
    }

    if (!report || typeof report.score !== "number") {
      return res.status(500).send("Model did not return a valid grading JSON.");
    }
    return res.json(report);
  } catch (e) {
    console.error("grade-exam error", e);
    res.status(500).send(e?.message || "Grade exam error");
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
