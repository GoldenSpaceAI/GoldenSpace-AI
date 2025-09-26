// index.js — GoldenSpaceAI
// Plans & locks, Mongo session store, GPT-4o/4o-mini/3.5-turbo routing

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

// Optional: Mongo-backed session store (fixes MemoryStore production warning)
import connectMongo from "connect-mongo";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

// ---------- Core middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------- Sessions (prefer Mongo) ----------
const MongoStore = connectMongo(session);
const useMongoStore = !!process.env.MONGODB_URI;
const sessionOptions = {
  secret: process.env.SESSION_SECRET || "super-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
  },
};

if (useMongoStore) {
  sessionOptions.store = MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    ttl: 60 * 60 * 24 * 14, // 14 days
    crypto: { secret: process.env.SESSION_SECRET || "super-secret" },
  });
} else {
  console.warn(
    "⚠️  Using MemoryStore (no MONGODB_URI). Not for production — may leak memory and won’t scale."
  );
}

app.use(session(sessionOptions));

// Passport (Google) – optional
app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Plans & capabilities ----------
const PLAN_CODES = {
  earth: "33117722",
  space: "22116644",
  chatai: "444666333222",
};
// Capabilities vocabulary we’ll use to guard routes
const CAPS = {
  CHAT: "chat", // /ask, basic chat
  SEARCH_INFO: "search-info", // /search-info
  LEARN_INFO: "learn-info", // /learn-info
  PHYSICS: "physics", // /ai/physics-explain
  CREATE_PLANET: "create-planet", // /ai/create-planet
  CREATE_ROCKET: "create-rocket", // /ai/create-rocket
  CREATE_SAT: "create-satellite", // /ai/create-satellite
  CREATE_UNIVERSE: "create-universe", // /ai/create-universe
  ADVANCED_CHAT: "advanced-chat", // /chat-advanced-ai
  HOMEWORK: "homework", // /api/chat + /api/homework
  LESSON_SEARCH: "lesson-search", // /lesson-search
};

// Which plan gets which caps
const PLAN_CAPS = {
  moon: new Set([CAPS.SEARCH_INFO, CAPS.CHAT]),
  earth: new Set([CAPS.CHAT, CAPS.LEARN_INFO, CAPS.PHYSICS, CAPS.CREATE_PLANET]),
  space: new Set([
    CAPS.CHAT,
    CAPS.SEARCH_INFO,
    CAPS.ADVANCED_CHAT,
    CAPS.HOMEWORK,
    CAPS.LESSON_SEARCH,
    CAPS.LEARN_INFO,
    CAPS.PHYSICS,
    CAPS.CREATE_PLANET,
    CAPS.CREATE_ROCKET,
    CAPS.CREATE_SAT,
    CAPS.CREATE_UNIVERSE,
  ]),
  chatai: new Set([
    CAPS.CHAT,
    CAPS.SEARCH_INFO,
    CAPS.ADVANCED_CHAT,
    CAPS.HOMEWORK,
    CAPS.LESSON_SEARCH,
  ]),
};

// Default plan limits/counts (if you want to enforce later)
const PLAN_LIMITS = {
  moon: { ask: 40, search: 20 },
  earth: { ask: Infinity, search: Infinity },
  chatai: { ask: Infinity, search: Infinity },
  space: { ask: Infinity, search: Infinity },
};

// ---------- Helper: compute base URL ----------
function getBaseUrl(req) {
  const proto =
    (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] ||
    req.protocol ||
    "https";
  const host =
    (req.headers["x-forwarded-host"] || "").toString().split(",")[0] ||
    req.get("host");
  return `${proto}://${host}`;
}

// ---------- Google OAuth (optional) ----------
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
      };
      return done(null, user);
    }
  )
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.get("/auth/google", (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google", {
    scope: ["profile", "email"],
    callbackURL,
  })(req, res, next);
});
app.get(DEFAULT_CALLBACK_PATH, (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google", {
    failureRedirect: "/login.html",
    callbackURL,
  })(req, res, () => res.redirect("/"));
});
app.post("/logout", (req, res, next) => {
  req.logout?.((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

// ---------- Public/auth gate (everything open now; you can lock later) ----------
function isPublicPath(_req) {
  return true; // keep open for now
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
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Session helpers (chat memory for advanced chat) ----------
function pushHistory(req, role, content) {
  if (!req.session.advHistory) req.session.advHistory = [];
  req.session.advHistory.push({ role, content });
  if (req.session.advHistory.length > 20) {
    req.session.advHistory = req.session.advHistory.slice(-20);
  }
}
function getHistory(req) {
  return (req.session.advHistory || []).map((m) => ({
    role: m.role,
    content: m.content,
  }));
}

// ---------- Small file helper ----------
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

// ---------- Plan utils ----------
function getPlan(req) {
  return req.session.plan || "moon";
}
function setPlan(req, plan) {
  req.session.plan = plan;
}
function requireCaps(...required) {
  return (req, res, next) => {
    const plan = getPlan(req);
    const caps = PLAN_CAPS[plan] || PLAN_CAPS.moon;
    for (const r of required) {
      if (!caps.has(r)) {
        return res
          .status(403)
          .json({ error: `Your plan (${plan}) does not allow this action.` });
      }
    }
    next();
  };
}

// ---------- Plan activation (from plans.html) ----------
app.post("/plan/activate", (req, res) => {
  const code = (req.body?.code || "").trim();
  if (!code) return res.status(400).json({ ok: false, error: "No code" });

  if (code === PLAN_CODES.earth) {
    setPlan(req, "earth");
  } else if (code === PLAN_CODES.space) {
    setPlan(req, "space");
  } else if (code === PLAN_CODES.chatai) {
    setPlan(req, "chatai");
  } else {
    return res
      .status(401)
      .json({
        ok: false,
        error:
          "Invalid password. Contact support goldenspaceais@gmail.com for help.",
      });
  }
  return res.json({ ok: true, plan: getPlan(req) });
});

// ---------- /api/me (show plan next to email on the home UI) ----------
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

// ---------- Upload (for advanced chat & homework) ----------
const upload = multer({ dest: "uploads/" });

// ========== ROUTES ==========

// --- Basic Chat (CHAT) — default GPT-4o-mini; ChatAI pack uses gpt-3.5-turbo
app.post("/ask", requireCaps(CAPS.CHAT), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });

    const plan = getPlan(req);
    const model =
      plan === "chatai" ? "gpt-3.5-turbo" : "gpt-4o-mini"; // per spec

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        {
          role: "system",
          content: "You are GoldenSpaceAI. Always answer in a long, detailed way.",
        },
        { role: "user", content: q },
      ],
      temperature: 0.3,
    });

    const answer = completion.choices[0]?.message?.content || "No response.";
    res.json({ model, answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "OpenAI error" });
  }
});

// --- Search Info (SEARCH_INFO) — brief overview + bullets
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

    const answer = completion.choices[0]?.message?.content || "No info found.";
    res.json({ answer });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});

// --- Learn Info (LEARN_INFO)
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

    const lesson = completion.choices[0]?.message?.content || "No lesson.";
    res.json({ lesson });
  } catch (e) {
    console.error("learn-info error", e);
    res.status(500).json({ lesson: "Learn error" });
  }
});

// --- Physics Explain (PHYSICS)
app.post("/ai/physics-explain", requireCaps(CAPS.PHYSICS), async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply: "Ask a physics question." });
    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly with steps.\nQuestion: ${q}`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.2,
    });

    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ reply });
  } catch (e) {
    console.error("physics error", e);
    res.status(500).json({ reply: "Physics error" });
  }
});

// --- Create Planet (CREATE_PLANET)
app.post("/ai/create-planet", requireCaps(CAPS.CREATE_PLANET), async (req, res) => {
  try {
    const specs = req.body?.specs || {};
    const prompt = `Invent a realistic exoplanet with these preferences (JSON below). Return: name, star type, orbit, climate, continents, life likelihood, fun fact.\nSpecs:\n${JSON.stringify(
      specs,
      null,
      2
    )}`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.6,
    });

    const data = completion.choices[0]?.message?.content || "{}";
    res.json({ planet: data });
  } catch (e) {
    console.error("create-planet error", e);
    res.status(500).json({ error: "Create planet error" });
  }
});

// --- Create Rocket (CREATE_ROCKET)
app.post("/ai/create-rocket", requireCaps(CAPS.CREATE_ROCKET), async (req, res) => {
  try {
    const prompt =
      "Design a conceptual rocket (non-actionable). Provide: stages, payload class, propulsion overview, safety notes, and a 3-step launch profile (high level).";
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.6,
    });
    const rocket = completion.choices[0]?.message?.content || "No design.";
    res.json({ rocket });
  } catch (e) {
    console.error("create-rocket error", e);
    res.status(500).json({ error: "Create rocket error" });
  }
});

// --- Create Satellite (CREATE_SAT)
app.post(
  "/ai/create-satellite",
  requireCaps(CAPS.CREATE_SAT),
  async (req, res) => {
    try {
      const prompt =
        "Design a conceptual Earth-observation satellite at a high level (non-operational): payload, orbit type, mission goals, ground segment overview.";
      const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.6,
      });
      const satellite = completion.choices[0]?.message?.content || "No design.";
      res.json({ satellite });
    } catch (e) {
      console.error("create-satellite error", e);
      res.status(500).json({ error: "Create satellite error" });
    }
  }
);

// --- Create Universe (CREATE_UNIVERSE) – creative worldbuilding
app.post(
  "/ai/create-universe",
  requireCaps(CAPS.CREATE_UNIVERSE),
  async (req, res) => {
    try {
      const theme = (req.body?.theme || "space opera").trim();
      const prompt = `Generate a fictional shared universe bible (creative and safe): era, factions, key planets, tech flavor, magic/science rules, 5 plot seeds.\nTheme: ${theme}`;
      const completion = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        temperature: 0.8,
      });
      const universe = completion.choices[0]?.message?.content || "No universe.";
      res.json({ universe });
    } catch (e) {
      console.error("create-universe error", e);
      res.status(500).json({ error: "Create universe error" });
    }
  }
);

// --- Advanced Chat (ADVANCED_CHAT) — always GPT-4o
app.post(
  "/chat-advanced-ai",
  requireCaps(CAPS.ADVANCED_CHAT),
  upload.single("file"),
  async (req, res) => {
    try {
      const q = (req.body?.q || "").trim();

      const messages = [
        {
          role: "system",
          content:
            "You are GoldenSpaceAI Advanced Assistant. Always provide long, detailed answers.",
        },
        ...getHistory(req),
      ];
      if (q) {
        messages.push({ role: "user", content: q });
        pushHistory(req, "user", q);
      }

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
              {
                type: "image_url",
                image_url: { url: `data:${mime};base64,${b64}` },
              },
            ],
          });
        } else {
          const text = await readTextIfPossible(filePath, mime);
          if (text) {
            messages.push({
              role: "user",
              content: `Attached file "${req.file.originalname}" (truncated):\n\n${text}`,
            });
          } else {
            messages.push({
              role: "user",
              content: `Attached file "${req.file.originalname}" (${mime}).`,
            });
          }
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
  }
);

// --- Homework solver (HOMEWORK) — vision capable input
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
      parts.push({
        type: "image_url",
        image_url: { url: `data:${img.mimetype};base64,${b64}` },
      });
    }

    for (const f of allFiles) {
      try {
        fs.unlinkSync(f.path);
      } catch {}
    }

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

app.post(
  "/api/chat",
  requireCaps(CAPS.HOMEWORK),
  upload.any(),
  handleHomework
);
app.post(
  "/api/homework",
  requireCaps(CAPS.HOMEWORK),
  upload.any(),
  handleHomework
);

// --- Lesson Search (LESSON_SEARCH)
app.post("/lesson-search", requireCaps(CAPS.LESSON_SEARCH), async (req, res) => {
  try {
    const query = (req.body?.query || "").trim();
    if (!query) return res.json({ results: [] });
    const prompt = `Create a short study plan (3 sections) and 5 reputable resources to learn: ${query}`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      temperature: 0.3,
    });

    const results = completion.choices[0]?.message?.content || "No results.";
    res.json({ results });
  } catch (e) {
    console.error("lesson-search error", e);
    res.status(500).json({ error: "Lesson search error" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
