// =============================================
// PART 1 — CORE SETUP & DATABASE
// GoldenSpaceAI — Clean & Optimized Core
// =============================================

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import cookieParser from "cookie-parser";
import OpenAI from "openai";
import multer from "multer";
import axios from "axios";
import fs from "fs";
import crypto from "crypto";

// ---------------------------------------------
// LOAD ENVIRONMENT
// ---------------------------------------------
dotenv.config();
const app = express();
app.set("trust proxy", 1);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------------------------------------------
// BASIC CONSTANTS
// ---------------------------------------------
const SITE_BASE_URL = "https://goldenspaceai.space";
const GOLDEN_DB_PATH = "./data/golden_database.json";
const BLOCKCYPHER_TOKEN = process.env.BLOCKCYPHER_TOKEN;   // << YOUR PAYMENT TOKEN
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// ---------------------------------------------
// ENSURE ENVIRONMENT VARIABLES
// ---------------------------------------------
function validateEnvironment() {
  const required = ["OPENAI_API_KEY", "SESSION_SECRET", "BLOCKCYPHER_TOKEN"];
  const missing = required.filter(k => !process.env[k]);

  if (missing.length > 0) {
    console.error("❌ Missing ENV variables:", missing);
    process.exit(1);
  }
  console.log("✅ Environment variables loaded");
}
validateEnvironment();

// ---------------------------------------------
// OPENAI CLIENT
// ---------------------------------------------
const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// ---------------------------------------------
// EXPRESS MIDDLEWARE
// ---------------------------------------------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ---------------------------------------------
// SESSION CONFIG
// ---------------------------------------------
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: true,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---------------------------------------------
// PASSPORT SERIALIZATION
// ---------------------------------------------
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

app.use(passport.initialize());
app.use(passport.session());

// ---------------------------------------------
// MULTER FILE UPLOAD (Images only)
// ---------------------------------------------
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files allowed"), false);
  },
});

// ---------------------------------------------
// DATABASE LOADING & SAVING
// ---------------------------------------------
function loadGoldenDB() {
  try {
    if (fs.existsSync(GOLDEN_DB_PATH)) {
      const raw = fs.readFileSync(GOLDEN_DB_PATH, "utf8");
      return raw.trim() ? JSON.parse(raw) : { users: {} };
    } else {
      const initial = { users: {} };
      fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify(initial, null, 2));
      return initial;
    }
  } catch (e) {
    console.error("DB read error:", e);
    return { users: {} };
  }
}

let saving = false;
async function saveGoldenDB(db) {
  if (saving) return;
  saving = true;

  try {
    fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify(db, null, 2));
  } catch (err) {
    console.error("DB save error:", err);
  }

  saving = false;
}

// ---------------------------------------------
// AUTH HELPERS
// ---------------------------------------------
function getUserIdentifier(req) {
  return req.user ? `${req.user.id}@${req.user.provider}` : null;
}

function authUser(req, res, next) {
  if (!req.user)
    return res.status(401).json({ error: "Login required" });
  next();
}

// ---------------------------------------------
// GOOGLE LOGIN
// ---------------------------------------------
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: `${SITE_BASE_URL}/auth/google/callback`,
        proxy: true,
      },
      (_access, _refresh, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          photo: profile.photos?.[0]?.value || "",
          provider: "google",
        };
        ensureUserExists(user);
        done(null, user);
      }
    )
  );

  app.get(
    "/auth/google",
    passport.authenticate("google", {
      scope: ["profile", "email"],
      prompt: "select_account",
    })
  );

  app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
      failureRedirect: "/login-signup.html",
      session: true,
    }),
    (req, res) => res.redirect("/")
  );
}

// ---------------------------------------------
// GITHUB LOGIN
// ---------------------------------------------
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: `${SITE_BASE_URL}/auth/github/callback`,
        proxy: true,
      },
      (_access, _refresh, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName || profile.username,
          email: profile.emails?.[0]?.value || `${profile.username}@github.user`,
          photo: profile.photos?.[0]?.value || "",
          provider: "github",
        };
        ensureUserExists(user);
        done(null, user);
      }
    )
  );

  app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));

  app.get(
    "/auth/github/callback",
    passport.authenticate("github", {
      failureRedirect: "/login-signup.html",
      session: true,
    }),
    (req, res) => res.redirect("/")
  );
}

// ---------------------------------------------
// USER CREATION (called on login)
// ---------------------------------------------
function ensureUserExists(user) {
  const db = loadGoldenDB();
  const id = `${user.id}@${user.provider}`;

  if (!db.users[id]) {
    db.users[id] = {
      email: user.email,
      name: user.name,
      photo: user.photo,
      golden_balance: user.email === "farisalmhamad3@gmail.com" ? 100000 : 0,
      subscriptions: {},
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      transactions: [],
    };
  } else {
    db.users[id].last_login = new Date().toISOString();
  }

  saveGoldenDB(db);
}
// =============================================
// PART 2 — USER SYSTEM (PROFILE, BALANCE, SUBSCRIPTIONS, TRANSFERS)
// =============================================

// Load database once at start
function getDB() {
  return loadGoldenDB();
}

// Save database
function saveDB(db) {
  saveGoldenDB(db);
}

// ---------------------------------------------
// BASIC USER INFO
// ---------------------------------------------
app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });

  const db = getDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];

  res.set("Cache-Control", "no-store");

  res.json({
    loggedIn: true,
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      photo: req.user.photo,
      provider: req.user.provider,
      isAdmin: req.user.email === "farisalmhamad3@gmail.com",
    },
    balance: user.golden_balance || 0,
    subscriptions: user.subscriptions || {},
  });
});

// ---------------------------------------------
// GOLDEN BALANCE ENDPOINT
// ---------------------------------------------
app.get("/api/golden-balance", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false, balance: 0 });

  const db = getDB();
  const user = db.users[getUserIdentifier(req)];

  res.json({
    loggedIn: true,
    balance: user?.golden_balance || 0,
  });
});

// ---------------------------------------------
// PRICES FOR FEATURE UNLOCK
// ---------------------------------------------
const FEATURE_PRICES = {
  search_info: 4,
  homework_helper: 20,
  chat_advancedai: 20,
  create_rocket: 4,
  create_satelite: 4,
  create_advanced_planet: 4,
  your_space: 4,
  learn_physics: 4,
  create_planet: 4,
  search_lessons: 10,
};

// ---------------------------------------------
// FEATURE LOCK MIDDLEWARE
// ---------------------------------------------
function requireFeature(feature) {
  return (req, res, next) => {
    if (!req.user)
      return res.status(401).json({ error: "Login required" });

    const db = getDB();
    const user = db.users[getUserIdentifier(req)];

    if (!user) return res.status(404).json({ error: "User not found" });

    const expiry = user.subscriptions?.[feature];

    if (expiry && new Date(expiry) > new Date()) {
      return next();
    }

    return res.status(403).json({
      error: "Feature locked",
      message: `This feature costs ${FEATURE_PRICES[feature]} Golden`,
      userBalance: user.golden_balance,
    });
  };
}

// ---------------------------------------------
// UNLOCK FEATURE (PAY GOLDEN)
// ---------------------------------------------
app.post("/api/unlock-feature", authUser, (req, res) => {
  const { feature } = req.body;

  if (!FEATURE_PRICES[feature]) {
    return res.status(400).json({ error: "Invalid feature" });
  }

  const db = getDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];

  const cost = FEATURE_PRICES[feature];

  // Admin gets everything free
  if (req.user.email !== "farisalmhamad3@gmail.com") {
    if (user.golden_balance < cost) {
      return res.status(400).json({ error: "Not enough Golden" });
    }
    user.golden_balance -= cost;
  }

  // Unlock for 30 days
  const expiry = new Date();
  expiry.setDate(expiry.getDate() + 30);

  user.subscriptions = user.subscriptions || {};
  user.subscriptions[feature] = expiry.toISOString();

  user.transactions = user.transactions || [];
  user.transactions.push({
    type: "unlock",
    amount: -cost,
    feature,
    timestamp: new Date().toISOString(),
  });

  saveDB(db);

  res.json({
    success: true,
    newBalance: user.golden_balance,
    expires: expiry.toISOString(),
  });
});

// ---------------------------------------------
// ADVANCED AI SUBSCRIPTION (20G / 30 days)
// ---------------------------------------------
const ADVANCED_AI_PRICE = 20;

app.get("/api/subscription-status", authUser, (req, res) => {
  const db = getDB();
  const user = db.users[getUserIdentifier(req)];

  const expiry = user.subscriptions?.chat_advancedai;
  const active = expiry && new Date(expiry) > new Date();

  res.json({
    active,
    expires: expiry || null,
    balance: user.golden_balance,
  });
});

app.post("/api/subscribe-advanced-ai", authUser, (req, res) => {
  const db = getDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];

  if (user.subscriptions.chat_advancedai && new Date(user.subscriptions.chat_advancedai) > new Date()) {
    return res.status(400).json({ error: "Already subscribed" });
  }

  if (user.golden_balance < ADVANCED_AI_PRICE) {
    return res.status(403).json({ error: "Not enough Golden (20G required)" });
  }

  user.golden_balance -= ADVANCED_AI_PRICE;

  const expiry = new Date();
  expiry.setDate(expiry.getDate() + 30);

  user.subscriptions.chat_advancedai = expiry.toISOString();

  user.transactions.push({
    type: "subscription",
    amount: -ADVANCED_AI_PRICE,
    timestamp: new Date().toISOString(),
  });

  saveDB(db);

  res.json({
    success: true,
    newBalance: user.golden_balance,
    expires: expiry.toISOString(),
  });
});

// ---------------------------------------------
// GOLDEN TRANSFER SYSTEM
// ---------------------------------------------
app.post("/api/transfer-golden", authUser, (req, res) => {
  const { recipientEmail, amount } = req.body;

  if (!recipientEmail || !amount || amount <= 0) {
    return res.status(400).json({ error: "Invalid transfer" });
  }

  const db = getDB();
  const senderId = getUserIdentifier(req);
  const sender = db.users[senderId];

  const fee = Math.ceil(amount * 0.05);
  const totalCost = amount + fee;

  if (sender.golden_balance < totalCost) {
    return res.status(400).json({ error: "Not enough Golden to pay +5% fee" });
  }

  const recipientEntry = Object.entries(db.users).find(
    ([_, u]) => u.email.toLowerCase() === recipientEmail.toLowerCase()
  );

  if (!recipientEntry) {
    return res.status(404).json({ error: "Recipient not found" });
  }

  const [recipientId, recipient] = recipientEntry;

  if (recipientId === senderId) {
    return res.status(400).json({ error: "Cannot send to yourself" });
  }

  // Deduct from sender
  sender.golden_balance -= totalCost;

  // Add to recipient
  recipient.golden_balance = (recipient.golden_balance || 0) + amount;

  const timestamp = new Date().toISOString();

  sender.transactions.push({
    type: "transfer_out",
    amount: -totalCost,
    to: recipientEmail,
    timestamp,
  });

  recipient.transactions.push({
    type: "transfer_in",
    amount,
    from: sender.email,
    timestamp,
  });

  saveDB(db);

  res.json({
    success: true,
    sent: amount,
    fee,
    totalCost,
    newBalance: sender.golden_balance,
  });
});
// =============================================
// PART 3 — AI SYSTEM (FREE, ADVANCED, IMAGE, HOMEWORK, LIVE, LESSONS)
// =============================================

// ---------------------------------------------
// FREE AI CHAT (gpt-4o-mini)
// ---------------------------------------------
app.post("/chat-free-ai", async (req, res) => {
  try {
    const prompt = req.body.q || req.body.question || "Hello!";
    const messages = [
      { role: "system", content: "You are GoldenSpaceAI's helpful free assistant." },
      { role: "user", content: prompt }
    ];

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      max_tokens: 1200,
      temperature: 0.7
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";

    res.json({ success: true, reply });
  } catch (error) {
    console.error("Free AI error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------
// ADVANCED AI ROUTES — 3 MODEL MODES (pro, flash, thinking)
// ---------------------------------------------------------

const modelRoutes = [
  { path: "pro", model: "gpt-4" },
  { path: "flash", model: "gpt-4o-mini" },
  { path: "thinking", model: "gpt-4" }
];

for (const { path, model } of modelRoutes) {
  app.post(`/api/generate-${path}`, requireFeature("chat_advancedai"), async (req, res) => {
    try {
      const { messages, prompt } = req.body;

      const completion = await openai.chat.completions.create({
        model,
        messages: messages || [{ role: "user", content: prompt }],
        max_tokens: 2000,
        temperature: 0.7
      });

      const reply = completion.choices?.[0]?.message?.content || "No reply.";

      res.json({
        success: true,
        text: reply,
        model: path,
        tokens_used: completion.usage?.total_tokens || 0
      });

    } catch (error) {
      console.error(`Advanced AI (${path}) error:`, error);
      res.status(500).json({ error: error.message });
    }
  });
}

// ---------------------------------------------------------
// LEGACY ADVANCED AI (image upload + chat)
// ---------------------------------------------------------
app.post("/chat-advancedai", requireFeature("chat_advancedai"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    const { q: prompt, model: selectedModel = "gpt-4", mode } = req.body;

    if (!prompt) return res.status(400).json({ error: "Missing prompt" });

    // For image generation
    if (mode === "image") {
      const dalle = await openai.images.generate({
        model: "dall-e-3",
        prompt,
        size: "1024x1024",
        n: 1
      });

      return res.json({
        reply: "Here is your generated image",
        imageUrl: dalle.data[0].url,
        model: "dall-e-3"
      });
    }

    // Normal AI chat
    const actualModel = selectedModel === "gpt-4-mini" ? "gpt-4o-mini" : "gpt-4";
    
    const completion = await openai.chat.completions.create({
      model: actualModel,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 2000,
      temperature: 0.7
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model: selectedModel });

  } catch (e) {
    console.error("Legacy AdvancedAI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, () => {});
  }
});

// ---------------------------------------------------------
// IMAGE GENERATION (DALL·E 3)
// ---------------------------------------------------------
app.post("/api/generate-image", authUser, async (req, res) => {
  try {
    const { prompt, size = "1024x1024", quality = "standard" } = req.body;

    if (!prompt) return res.status(400).json({ error: "Prompt is required" });

    const image = await openai.images.generate({
      model: "dall-e-3",
      prompt,
      size,
      quality,
      n: 1,
      response_format: "url"
    });

    res.json({
      success: true,
      imageUrl: image.data[0].url,
      prompt
    });

  } catch (error) {
    console.error("Image generation error:", error);

    let message = error.message.includes("safety")
      ? "Content violates safety rules."
      : error.message;

    res.status(500).json({ success: false, error: message });
  }
});

// ---------------------------------------------------------
// HOMEWORK HELPER (image + text)
// ---------------------------------------------------------
app.post("/homework-helper", requireFeature("homework_helper"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;

  try {
    if (!filePath) {
      return res.status(400).json({ error: "No image uploaded" });
    }

    const b64 = fs.readFileSync(filePath).toString("base64");
    const mime = req.file.mimetype;

    const messages = [
      { role: "system", content: "You are a careful tutor. Show all steps." },
      { role: "user", content: [
        { type: "text", text: "Solve this homework carefully." },
        { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } }
      ]}
    ];

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages,
      max_tokens: 1400,
      temperature: 0.4
    });

    const reply = completion.choices[0]?.message?.content || "No reply.";

    res.json({ success: true, reply });
  } catch (e) {
    console.error("Homework error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, () => {});
  }
});

// ---------------------------------------------------------
// AI SEARCH INFO (Google style)
// ---------------------------------------------------------
app.post("/ask", requireFeature("search_info"), async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a research engine. Give clean facts." },
        { role: "user", content: question }
      ],
      temperature: 0.7,
      max_tokens: 1200
    });

    res.json({
      success: true,
      answer: completion.choices[0]?.message?.content
    });

  } catch (error) {
    console.error("Search info error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------
// LESSON GENERATOR (education)
// ---------------------------------------------------------
app.post("/search-lessons", requireFeature("search_lessons"), async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You generate structured lessons with examples, exercises, and explanations." },
        { role: "user", content: query }
      ],
      max_tokens: 2000,
      temperature: 0.7
    });

    res.json({
      success: true,
      answer: completion.choices[0]?.message?.content
    });

  } catch (error) {
    console.error("Search lessons error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ---------------------------------------------------------
// LIVE CHAT (short quick replies)
// ---------------------------------------------------------
app.post("/live-chat-process", async (req, res) => {
  try {
    const { message, conversation } = req.body;

    if (!message)
      return res.status(400).json({ error: "Message is required" });

    const messages = [
      { role: "system", content: "You are a friendly, fast AI assistant." },
      ...conversation,
      { role: "user", content: message }
    ];

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      max_tokens: 150,
      temperature: 0.7,
    });

    res.json({
      success: true,
      reply: completion.choices[0]?.message?.content,
      tokens_used: completion.usage?.total_tokens || 0
    });

  } catch (error) {
    console.error("Live chat error:", error);
    res.status(500).json({ error: error.message });
  }
});
// =============================================
// PART 4 — STATIC PAGES, ROUTING & HEALTH CHECKS
// =============================================

// Serve main website pages
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/login", (_req, res) => {
  res.sendFile(path.join(__dirname, "login-signup.html"));
});

// Dynamic page loader (secure)
app.get("/:page.html", (req, res) => {
  const page = req.params.page.toLowerCase();

  // Security check
  if (!/^[a-z0-9\-]+$/i.test(page)) {
    return res.status(400).send("Invalid page");
  }

  const filePath = path.join(__dirname, `${page}.html`);
  if (fs.existsSync(filePath)) {
    return res.sendFile(filePath);
  }

  res.status(404).send("Page not found");
});

// Dedicated static routes
const staticPages = {
  "/plans": "plans.html",
  "/success": "success.html",
  "/FreeAI": "chat-free-ai.html",
  "/advancedAI": "chat-advancedai.html",
  "/homework-helper": "homework-helper.html",
  "/search-info": "search-info.html",
  "/search-educational-lessons": "search-lessons.html",
  "/create-your-universe": "your-space.html",
  "/create-your-rocket": "create-rocket.html",
  "/create-satellite": "create-satellite.html",
  "/create-planet": "create-planet.html",
  "/create-advanced-planet": "create-advanced-planet.html",
  "/privacy-policy": "privacy.html",
  "/terms-of-service": "terms.html",
  "/refund-policy": "refund.html",
  "/contact-page": "contact.html",
  "/about-us-page": "about-us.html",
  "/payment-cancel": "plans.html",
  "/admin-panel": "admin-page.12345432.html"
};

Object.entries(staticPages).forEach(([route, file]) => {
  app.get(route, (req, res) => {
    res.sendFile(path.join(__dirname, file));
  });
});

// ---------------------------------------------
// HEALTH CHECK ENDPOINT
// ---------------------------------------------
app.get("/health", (_req, res) => {
  const db = loadGoldenDB();
  res.json({
    status: "OK",
    users: Object.keys(db.users || {}).length,
    timestamp: new Date().toISOString()
  });
});

// ---------------------------------------------
// ERROR HANDLING
// ---------------------------------------------
app.use((err, req, res, next) => {
  console.error("Unhandled Error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});
// =============================================
// PART 5 — FULL AUTOMATIC BLOCKCHAIN PAYMENT ENGINE
// =============================================

// ---------------------------
// CONFIG
// ---------------------------
const BLOCKCYPHER_TOKEN = process.env.BLOCKCYPHER_TOKEN;

const PAYMENT_WALLETS = {
  btc: "bc1qz5wtz2d329xsm7gcs9e3jwls9supg2fk2hkxtd",
  eth: "0x8BEaCb38dF916F6644F81cA0De18C1F4996d32Ea",
  ltc: "LSNv8n6bZ2hR9KqD9q7B2n6X2gZ2hR9KqD9"
};

const GOLDEN_PLANS = {
  mini:  { priceUSD: 5,  golden: 20 },
  golden:{ priceUSD: 10, golden: 44 },
  ultra: { priceUSD: 20, golden: 90 }
};

// Save payments to JSON
const PAYMENTS_DB_PATH = "./data/payment_database.json";

function loadPaymentsDB() {
  try {
    if (!fs.existsSync(PAYMENTS_DB_PATH)) {
      fs.writeFileSync(PAYMENTS_DB_PATH, JSON.stringify({ payments: [] }, null, 2));
    }
    const file = fs.readFileSync(PAYMENTS_DB_PATH, "utf8");
    return JSON.parse(file);
  } catch (err) {
    console.error("Payment DB load error:", err);
    return { payments: [] };
  }
}

function savePaymentsDB(db) {
  fs.writeFileSync(PAYMENTS_DB_PATH, JSON.stringify(db, null, 2));
}

let paymentDB = loadPaymentsDB();

// Generate random ID
function randomId() {
  return crypto.randomBytes(12).toString("hex");
}

// =============================================
// CREATE PAYMENT REQUEST (USER SENDS CRYPTO)
// =============================================
app.post("/api/create-payment", authUser, async (req, res) => {
  try {
    const { plan, crypto } = req.body;

    if (!GOLDEN_PLANS[plan]) return res.status(400).json({ error: "Invalid plan" });
    if (!PAYMENT_WALLETS[crypto]) return res.status(400).json({ error: "Invalid crypto" });

    const userId = getUserIdentifier(req);
    const planData = GOLDEN_PLANS[plan];
    const wallet = PAYMENT_WALLETS[crypto];

    const payment = {
      id: randomId(),
      userId,
      userEmail: req.user.email,
      plan,
      crypto,
      wallet,
      expectedUSD: planData.priceUSD,
      expectedGolden: planData.golden,
      status: "pending",
      createdAt: new Date().toISOString(),
      txHash: null
    };

    // Save to DB
    paymentDB.payments.push(payment);
    savePaymentsDB(paymentDB);

    res.json({ success: true, paymentId: payment.id });

  } catch (error) {
    console.error("Create-payment error:", error);
    res.status(500).json({ error: "Failed to create payment" });
  }
});

// =============================================
// BLOCKCYPHER API — GET ADDRESS TRANSACTIONS
// =============================================
async function getAddressTxs(crypto, address) {
  try {
    const chain = crypto === "btc" ? "btc/main" :
                  crypto === "eth" ? "eth/main" :
                  crypto === "ltc" ? "ltc/main" : null;

    if (!chain) return null;

    const url = `https://api.blockcypher.com/v1/${chain}/addrs/${address}`;

    const { data } = await axios.get(url, {
      params: { token: BLOCKCYPHER_TOKEN }
    });

    return data.txrefs || data.unconfirmed_txrefs || [];

  } catch (err) {
    console.error("BlockCypher error:", err.message);
    return null;
  }
}

// =============================================
// WHEN CONFIRMED → ADD GOLDEN TO USER
// =============================================
function addGolden(payment) {
  const db = loadGoldenDB();
  const user = db.users[payment.userId];
  if (!user) return;

  const amount = GOLDEN_PLANS[payment.plan].golden;
  const prev = user.golden_balance;

  user.golden_balance += amount;
  user.total_golden_earned += amount;

  user.transactions = user.transactions || [];
  user.transactions.push({
    type: "crypto_purchase",
    amount,
    previous_balance: prev,
    new_balance: user.golden_balance,
    crypto: payment.crypto,
    txHash: payment.txHash,
    timestamp: new Date().toISOString()
  });

  saveGoldenDB(db);

  console.log(`💰 Auto-added ${amount}G to ${user.email}`);
}

// =============================================
// CHECK A PAYMENT (CONFIRMATION)
// =============================================
async function checkPayment(payment) {
  const txs = await getAddressTxs(payment.crypto, payment.wallet);
  if (!txs) return;

  for (const tx of txs) {
    if (tx.confirmations >= 1) {
      if (payment.status === "confirmed") return;

      payment.status = "confirmed";
      payment.txHash = tx.tx_hash;
      payment.confirmedAt = new Date().toISOString();
      savePaymentsDB(paymentDB);

      addGolden(payment);
      return;
    }
  }
}

// =============================================
// BACKGROUND LOOP — CHECK EVERY 20 SECONDS
// =============================================
setInterval(async () => {
  const pending = paymentDB.payments.filter(p => p.status === "pending");

  if (pending.length > 0) {
    console.log(`🔍 Checking ${pending.length} pending payments...`);
  }

  for (const pay of pending) {
    await checkPayment(pay);
  }
}, 20000); // 20 seconds
