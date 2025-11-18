// index.js — GoldenSpaceAI COMPLETE SYSTEM (ORGANIZED & FIXED - NO SUPABASE)
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
import axios from "axios";
import multer from "multer";
import fs from "fs";

// ============ CONFIGURATION ============
dotenv.config();
const app = express();
app.set("trust proxy", 1);

// Constants
const GOLDEN_DB_PATH = "./data/golden_database.json";
const PAYMENT_DB_PATH = "./data/payment_database.json";
const ADVANCED_AI_PRICE = 20;
const IMG_LIMIT_PER_MONTH = 20;
const SITE_BASE_URL = "https://goldenspaceai.space";

const GOLDEN_PACKAGES = {
  60: { priceUSD: 15 },
  100: { priceUSD: 20 },
  200: { priceUSD: 40 },
};

const FEATURE_PRICES = {
  search_info: 4,
  homework_helper: 20,
  chat_advancedai: 20,
  create_rocket: 4,
  create_satellite: 4,
  advanced_planet: 4,
  your_space: 4,
  learn_physics: 4,
  create_planet: 4,
  search_lessons: 10,
};

// ============ INITIALIZATION ============
validateEnvironment();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Initialize data directory
const dataDir = path.dirname(GOLDEN_DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// ============ MIDDLEWARE SETUP ============
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session Configuration
const sessionConfig = {
  secret: process.env.SESSION_SECRET || "super-secret-key-change-in-production",
  resave: false,
  saveUninitialized: false,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
};
app.use(session(sessionConfig));

// Passport Setup
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// File Upload
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith("image/")) {
      cb(null, true);
    } else {
      cb(new Error("Only image files are allowed"), false);
    }
  },
});

// Static Files
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ============ HELPER FUNCTIONS ============
function validateEnvironment() {
  const required = ["OPENAI_API_KEY", "SESSION_SECRET"];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    console.error("❌ Missing required environment variables:", missing);
    process.exit(1);
  }
  console.log("✅ Environment variables validated");
}

function loadGoldenDB() {
  try {
    if (fs.existsSync(GOLDEN_DB_PATH)) {
      const file = fs.readFileSync(GOLDEN_DB_PATH, "utf8");
      return file.trim() ? JSON.parse(file) : { users: {}, family_plans: {} };
    } else {
      const initial = { users: {}, family_plans: {} };
      fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify(initial, null, 2));
      return initial;
    }
  } catch (e) {
    console.error("DB load error:", e);
    return { users: {}, family_plans: {} };
  }
}

let saving = false;
async function saveGoldenDB(db) {
  try {
    if (saving) return;
    saving = true;
    fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error("DB save error:", e);
  } finally {
    saving = false;
  }
}

function getUserIdentifier(req) {
  return req.user ? `${req.user.id}@${req.user.provider}` : null;
}

function getUserGoldenBalance(userId) {
  const db = loadGoldenDB();
  return db.users[userId]?.golden_balance || 0;
}

function monthKey(d = new Date()) {
  return d.toISOString().slice(0, 7);
}

function addDays(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

function isExpired(date) {
  return new Date(date) < new Date();
}

// ============ AUTHENTICATION MIDDLEWARE ============
function authUser(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: "Login required" });
  }
  next();
}

function requireFeature(feature) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });

    const db = loadGoldenDB();
    const userId = getUserIdentifier(req);
    const user = db.users[userId];
    if (!user) return res.status(404).json({ error: "User not found" });

    const expiry = user.subscriptions?.[feature];
    if (expiry && new Date(expiry) > new Date()) return next();

    if (expiry && new Date(expiry) <= new Date()) {
      delete user.subscriptions[feature];
      saveGoldenDB(db);
    }

    const price = FEATURE_PRICES[feature];
    return res.status(403).json({
      error: "Feature locked",
      message: `This feature requires ${price} Golden`,
      requiredGolden: price,
      userBalance: user.golden_balance || 0,
    });
  };
}

// ============ USER MANAGEMENT ============
function ensureUserExists(user) {
  const db = loadGoldenDB();
  const id = `${user.id}@${user.provider}`;
  const isYourEmail = user.email === "farisalmhamad3@gmail.com";

  if (!db.users[id]) {
    db.users[id] = {
      email: user.email,
      name: user.name,
      golden_balance: isYourEmail ? 100000 : 0,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      subscriptions: {},
      total_golden_earned: isYourEmail ? 100000 : 0,
      total_golden_spent: 0,
      transactions: isYourEmail ? [{
        type: "auto_bonus",
        amount: 100000,
        previous_balance: 0,
        new_balance: 100000,
        reason: "Automatic 100K Golden for admin",
        timestamp: new Date().toISOString(),
      }] : [],
    };
    saveGoldenDB(db);
    if (isYourEmail) console.log(`🎉 Auto-created account with 100,000G for ${user.email}`);
  } else {
    if (isYourEmail && db.users[id].golden_balance < 100000) {
      const previousBalance = db.users[id].golden_balance;
      db.users[id].golden_balance = 100000;
      db.users[id].total_golden_earned = 100000;

      if (previousBalance < 100000) {
        db.users[id].transactions = db.users[id].transactions || [];
        db.users[id].transactions.push({
          type: "auto_fix",
          amount: 100000 - previousBalance,
          previous_balance: previousBalance,
          new_balance: 100000,
          reason: "Auto-corrected to 100K Golden",
          timestamp: new Date().toISOString(),
        });
        console.log(`🔄 Auto-corrected balance to 100,000G for ${user.email}`);
      }
    }
    db.users[id].last_login = new Date().toISOString();
    saveGoldenDB(db);
  }
}

// ============ AUTHENTICATION ROUTES ============
// Google OAuth
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${SITE_BASE_URL}/auth/google/callback`,
    proxy: true,
  }, (_accessToken, _refreshToken, profile, done) => {
    const user = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value || "",
      photo: profile.photos?.[0]?.value || "",
      provider: "google",
    };
    ensureUserExists(user);
    done(null, user);
  }));

  app.get("/auth/google", passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account",
  }));

  app.get("/auth/google/callback", passport.authenticate("google", {
    failureRedirect: "/login-signup.html",
    failureMessage: true,
    session: true,
  }), (_req, res) => res.redirect("/"));
}

// GitHub OAuth
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${SITE_BASE_URL}/auth/github/callback`,
    proxy: true,
  }, (_accessToken, _refreshToken, profile, done) => {
    const user = {
      id: profile.id,
      name: profile.displayName || profile.username,
      email: profile.emails?.[0]?.value || `${profile.username}@github.user`,
      photo: profile.photos?.[0]?.value || "",
      username: profile.username,
      provider: "github",
    };
    ensureUserExists(user);
    done(null, user);
  }));

  app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
  app.get("/auth/github/callback", passport.authenticate("github", {
    failureRedirect: "/login-signup.html",
    failureMessage: true,
    session: true,
  }), (_req, res) => res.redirect("/"));
}

// ============ BASIC ROUTES ============
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/login", (_req, res) => res.sendFile(path.join(__dirname, "login-signup.html")));

app.get("/:page.html", (req, res) => {
  const page = (req.params.page || "").toLowerCase();
  if (!/^[a-z0-9\-]+$/.test(page)) {
    return res.status(400).send("Invalid page");
  }
  const filePath = path.join(__dirname, `${page}.html`);
  fs.existsSync(filePath) ? res.sendFile(filePath) : res.status(404).send("Page not found");
});

app.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ ok: true, message: "Logged out successfully" });
    });
  });
});

// ============ USER API ROUTES ============
app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });

  const id = `${req.user.id}@${req.user.provider}`;
  const db = loadGoldenDB();
  const userData = db.users[id];
  
  if (!userData) {
    ensureUserExists(req.user);
    return res.json({ loggedIn: true, user: req.user, balance: 0 });
  }

  const isAdmin = req.user.email === "farisalmhamad3@gmail.com";

  res.set("Cache-Control", "no-store");
  res.json({
    loggedIn: true,
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      photo: req.user.photo,
      provider: req.user.provider,
      isAdmin,
    },
    balance: userData.golden_balance || 0,
    subscriptions: userData.subscriptions || {},
  });
});

app.get("/api/golden-balance", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false, balance: 0 });
  const b = getUserGoldenBalance(getUserIdentifier(req));
  res.set("Cache-Control", "no-store");
  res.json({ loggedIn: true, balance: b, user: req.user });
});

app.get("/api/golden-packages", (_req, res) => res.json(GOLDEN_PACKAGES));

// ============ FEATURE MANAGEMENT ============
app.use((req, _res, next) => {
  if (req.user) {
    const db = loadGoldenDB();
    const uid = getUserIdentifier(req);
    if (uid && db.users[uid]) {
      req.user.golden_balance = db.users[uid].golden_balance || 0;
      req.user.subscriptions = db.users[uid].subscriptions || {};
    }
  }
  next();
});

app.post("/api/unlock-feature", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature, cost } = req.body;

  if (!feature || FEATURE_PRICES[feature] == null) {
    return res.status(400).json({ error: "Invalid feature" });
  }
  if (FEATURE_PRICES[feature] !== Number(cost)) {
    return res.status(400).json({ error: "Mismatched cost" });
  }

  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];
  if (!u) return res.status(404).json({ error: "User not found" });

  const isFaris = req.user.email === "farisalmhamad3@gmail.com";
  if (!isFaris) {
    if ((u.golden_balance || 0) < cost) {
      return res.status(400).json({ error: "Not enough Golden" });
    }
    u.golden_balance -= cost;
    u.total_golden_spent = (u.total_golden_spent || 0) + cost;
  }

  const exp = new Date();
  exp.setDate(exp.getDate() + 30);
  u.subscriptions = u.subscriptions || {};
  u.subscriptions[feature] = exp.toISOString();

  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "unlock",
    amount: isFaris ? 0 : -cost,
    feature,
    timestamp: new Date().toISOString(),
  });

  saveGoldenDB(db);
  res.json({
    success: true,
    newBalance: u.golden_balance,
    freeUnlock: isFaris,
    expires_at: exp.toISOString(),
  });
});

app.get("/api/feature-status", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature } = req.query;
  if (!feature || FEATURE_PRICES[feature] == null) {
    return res.status(400).json({ error: "Invalid feature" });
  }

  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];

  if (!u?.subscriptions?.[feature]) {
    return res.json({
      feature,
      unlocked: false,
      price: FEATURE_PRICES[feature],
    });
  }

  const expiry = new Date(u.subscriptions[feature]);
  if (expiry <= new Date()) {
    delete u.subscriptions[feature];
    saveGoldenDB(db);
    return res.json({
      feature,
      unlocked: false,
      price: FEATURE_PRICES[feature],
    });
  }

  const msLeft = expiry - new Date();
  const remainingHours = Math.max(0, Math.floor(msLeft / (1000 * 60 * 60)));

  res.json({
    feature,
    unlocked: true,
    remainingHours,
    price: FEATURE_PRICES[feature],
    expires_at: expiry.toISOString(),
  });
});

// ============ ADVANCED AI SUBSCRIPTION SYSTEM ============
app.get("/api/subscription-status", authUser, (req, res) => {
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];
  
  if (!user) return res.status(404).json({ error: "User not found" });

  const sub = user.subscriptions?.chat_advancedai || null;
  const isActive = sub && new Date(sub) > new Date();

  res.json({
    active: isActive,
    expires: sub,
    balance: user.golden_balance || 0,
  });
});

app.post("/api/subscribe-advanced-ai", authUser, (req, res) => {
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];

  if (!user) return res.status(404).json({ error: "User not found" });

  // Check if already subscribed
  const currentSub = user.subscriptions?.chat_advancedai;
  if (currentSub && new Date(currentSub) > new Date()) {
    return res.status(400).json({ error: "Advanced AI is already active" });
  }

  // Check balance
  if (user.golden_balance < ADVANCED_AI_PRICE) {
    return res.status(403).json({ error: "Not enough Golden. Need 20G." });
  }

  // Deduct Golden and activate subscription
  user.golden_balance -= ADVANCED_AI_PRICE;
  user.total_golden_spent = (user.total_golden_spent || 0) + ADVANCED_AI_PRICE;

  const expiry = addDays(30);
  user.subscriptions = user.subscriptions || {};
  user.subscriptions.chat_advancedai = expiry;

  user.transactions = user.transactions || [];
  user.transactions.push({
    type: "subscription",
    amount: -ADVANCED_AI_PRICE,
    feature: "chat_advancedai",
    previous_balance: user.golden_balance + ADVANCED_AI_PRICE,
    new_balance: user.golden_balance,
    timestamp: new Date().toISOString(),
  });

  saveGoldenDB(db);

  res.json({
    success: true,
    message: "Advanced AI unlocked for 30 days",
    expires: expiry,
    newBalance: user.golden_balance
  });
});

// ============ ADVANCED AI CHAT ENDPOINTS ============
const modelRoutes = [
  { path: "pro", model: "gpt-4" },           // Friendly - GPT-4
  { path: "flash", model: "gpt-4o-mini" },   // Fast - GPT-4o Mini
  { path: "thinking", model: "gpt-4" }       // Thinking - GPT-4 (same as pro for now)
];

for (const { path, model } of modelRoutes) {
  app.post(`/api/generate-${path}`, requireFeature("chat_advancedai"), async (req, res) => {
    try {
      const { messages, prompt } = req.body;

      console.log(`➡️ [${path}] Sending to OpenAI`, {
        model,
        promptPreview: prompt?.slice(0, 100) || "(using messages array)"
      });

      const completion = await openai.chat.completions.create({
        model,
        messages: messages || [{ role: "user", content: prompt }],
        max_tokens: 2000,
        temperature: 0.7
      });

      const reply = completion.choices?.[0]?.message?.content || "No reply.";

      console.log(`✅ [${path}] Reply OK`, {
        model: completion.model,
        tokens_used: completion.usage?.total_tokens,
        preview: reply.slice(0, 120)
      });

      res.json({
        success: true,
        text: reply,
        model: path, // Return the path name (pro, flash, thinking)
        tokens_used: completion.usage?.total_tokens || 0
      });

    } catch (error) {
      console.error(`${path} generation error:`, error);
      res.status(500).json({ error: error.message });
    }
  });
}

// Legacy Advanced AI endpoint (for compatibility)
app.post("/chat-advancedai", requireFeature("chat_advancedai"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    const userId = getUserIdentifier(req);
    if (!userId) return res.status(401).json({ error: "Login required" });

    const { q: prompt, model: selectedModel = "gpt-4", mode } = req.body;
    if (!prompt) return res.status(400).json({ error: "Missing prompt" });

    // Handle image generation
    if (mode === "image") {
      const db = loadGoldenDB();
      const user = db.users[userId];
      
      user.usage = user.usage || {};
      user.usage.images = user.usage.images || { month: monthKey(), used: 0 };
      
      if (user.usage.images.month !== monthKey()) {
        user.usage.images = { month: monthKey(), used: 0 };
      }

      if (user.usage.images.used >= IMG_LIMIT_PER_MONTH) {
        return res.status(403).json({ error: "You've reached your 20-image monthly limit." });
      }

      const img = await openai.images.generate({
        model: "dall-e-3",
        prompt,
        size: "1024x1024",
        n: 1
      });
      const imageUrl = img.data[0].url;

      user.usage.images.used++;
      saveGoldenDB(db);

      return res.json({
        reply: `![Generated Image](${imageUrl})`,
        imageUrl,
        model: "dall-e-3"
      });
    }

    // Text completion
    const actualModel = selectedModel === "gpt-4-mini" ? "gpt-4o-mini" : "gpt-4";
    
    const completion = await openai.chat.completions.create({
      model: actualModel,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 2000,
      temperature: 0.7
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";

    res.json({ 
      reply, 
      model: selectedModel,
      tokens_used: completion.usage?.total_tokens || 0
    });

  } catch (e) {
    console.error("Advanced AI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, () => {});
  }
});

// ============ OTHER AI ENDPOINTS ============
// Free Chat AI
app.post("/chat-free-ai", async (req, res) => {
  try {
    const prompt = req.body.q || req.body.question || "Hello!";
    const model = "gpt-4o-mini";
    const messages = [
      { role: "system", content: "You are GoldenSpaceAI's helpful chat assistant." },
      { role: "user", content: prompt }
    ];
    const completion = await openai.chat.completions.create({ model, messages, max_tokens: 1200, temperature: 0.7 });
    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });
  } catch (e) {
    console.error("Free AI error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Search Info
app.post("/ask", requireFeature("search_info"), async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });
    
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are a helpful research assistant. Provide clear, concise, and informative answers." 
        },
        { role: "user", content: question }
      ],
      max_tokens: 1200,
      temperature: 0.7
    });
    
    const answer = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer });
  } catch (e) {
    console.error("Search info error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Search Lessons
app.post("/search-lessons", requireFeature("search_lessons"), async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });
    
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are an educational tutor. Create comprehensive lessons with introduction, explanations, examples, and practice questions." 
        },
        { role: "user", content: query }
      ],
      max_tokens: 2000,
      temperature: 0.7
    });
    
    const answer = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer });
  } catch (e) {
    console.error("Search lessons error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Homework Helper
app.post("/homework-helper", requireFeature("homework_helper"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    const model = "gpt-4o";
    const prompt = req.body.q || "Solve this homework step-by-step.";
    if (!filePath) return res.status(400).json({ error: "No image provided" });

    const b64 = fs.readFileSync(filePath).toString("base64");
    const mime = req.file.mimetype || "image/png";
    const messages = [
      { role: "system", content: "You are a careful, step-by-step homework solver." },
      { role: "user", content: [
        { type: "text", text: prompt },
        { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } }
      ]},
    ];

    const completion = await openai.chat.completions.create({ model, messages, max_tokens: 1400, temperature: 0.4 });
    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });
  } catch (e) {
    console.error("Homework AI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, () => {});
  }
});

// Live Chat
app.post("/live-chat-process", async (req, res) => {
  try {
    const { message, conversation, model = "gpt-4o-mini" } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });

    const messages = [
      { 
        role: "system", 
        content: "You are a friendly, conversational AI assistant. Keep responses natural and conversational." 
      },
      ...conversation,
      { role: "user", content: message }
    ];

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages,
      max_tokens: 150,
      temperature: 0.7,
    });

    const reply = completion.choices[0]?.message?.content || "I didn't get that. Could you repeat?";
    res.json({ success: true, reply, model, tokens_used: completion.usage?.total_tokens || 0 });
  } catch (error) {
    console.error("Live chat error:", error);
    res.status(500).json({ error: error.message });
  }
});

// ============ SUBSCRIPTION MANAGEMENT ============
app.get("/api/subscriptions", (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });

    const userId = getUserIdentifier(req);
    const db = loadGoldenDB();
    const user = db.users[userId];
    if (!user) return res.status(404).json({ error: "User not found" });

    const now = new Date();
    const subscriptions = [];
    const userSubs = user.subscriptions || {};

    Object.entries(FEATURE_PRICES).forEach(([feature, cost]) => {
      const expiryStr = userSubs[feature];
      if (expiryStr) {
        const expiry = new Date(expiryStr);
        const isActive = expiry > now;
        const msLeft = expiry - now;
        const daysLeft = isActive ? Math.ceil(msLeft / (1000 * 60 * 60 * 24)) : 0;

        subscriptions.push({ feature, cost, expiry: expiryStr, active: isActive, daysLeft });
      }
    });

    if (userSubs.chat_advancedai) {
      const expiryStr = userSubs.chat_advancedai;
      const expiry = new Date(expiryStr);
      const isActive = expiry > now;
      const msLeft = expiry - now;
      const daysLeft = isActive ? Math.ceil(msLeft / (1000 * 60 * 60 * 24)) : 0;

      subscriptions.push({
        feature: "chat_advancedai",
        cost: ADVANCED_AI_PRICE,
        expiry: expiryStr,
        active: isActive,
        daysLeft: daysLeft
      });
    }

    res.json({
      success: true,
      balance: user.golden_balance || 0,
      subscriptions: subscriptions.sort((a, b) => new Date(b.expiry) - new Date(a.expiry))
    });
  } catch (err) {
    console.error("Subscriptions fetch error:", err);
    res.status(500).json({ error: "Failed to load subscriptions" });
  }
});

app.post("/api/cancel-subscription", (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { feature } = req.body;
    if (!feature) return res.status(400).json({ error: "Feature required" });

    const userId = getUserIdentifier(req);
    const db = loadGoldenDB();
    const user = db.users[userId];
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.subscriptions && user.subscriptions[feature]) {
      delete user.subscriptions[feature];
      saveGoldenDB(db);
      console.log(`❌ Subscription canceled for ${userId}: ${feature}`);
      res.json({ success: true, message: "Subscription canceled. It will remain active until the expiry date." });
    } else {
      res.status(404).json({ error: "Subscription not found" });
    }
  } catch (err) {
    console.error("Cancel subscription error:", err);
    res.status(500).json({ error: "Failed to cancel subscription" });
  }
});

// ============ GOLDEN TRANSFER SYSTEM ============
app.post("/api/transfer-golden", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { recipientEmail, amount } = req.body;

    if (!recipientEmail || !amount || amount <= 0) {
      return res.status(400).json({ error: "Valid recipient email and amount required" });
    }

    const senderId = getUserIdentifier(req);
    const db = loadGoldenDB();
    const sender = db.users[senderId];
    if (!sender) return res.status(404).json({ error: "Sender account not found" });

    const fee = Math.ceil(amount * 0.05);
    const totalCost = amount + fee;
    const senderBalance = Number(sender.golden_balance || 0);

    if (senderBalance < totalCost) {
      return res.status(400).json({ 
        error: `Insufficient balance. Need ${totalCost}G (${amount}G + ${fee}G fee), but only have ${senderBalance}G` 
      });
    }

    const recipientEntry = Object.entries(db.users).find(([_, user]) => 
      user.email && user.email.toLowerCase() === recipientEmail.toLowerCase()
    );

    if (!recipientEntry) {
      return res.status(404).json({ error: "Recipient not found in our system" });
    }

    const [recipientId, recipient] = recipientEntry;
    if (senderId === recipientId) {
      return res.status(400).json({ error: "Cannot transfer to yourself" });
    }

    sender.golden_balance = senderBalance - totalCost;
    recipient.golden_balance = Number(recipient.golden_balance || 0) + amount;

    const timestamp = new Date().toISOString();
    
    sender.transactions = sender.transactions || [];
    sender.transactions.push({
      type: "transfer_out",
      amount: -totalCost,
      recipient: recipientEmail,
      net_amount: -amount,
      fee: fee,
      previous_balance: senderBalance,
      new_balance: sender.golden_balance,
      timestamp: timestamp
    });

    recipient.transactions = recipient.transactions || [];
    recipient.transactions.push({
      type: "transfer_in",
      amount: amount,
      sender: sender.email,
      previous_balance: recipient.golden_balance - amount,
      new_balance: recipient.golden_balance,
      timestamp: timestamp
    });

    sender.total_golden_spent = (sender.total_golden_spent || 0) + totalCost;
    recipient.total_golden_earned = (recipient.total_golden_earned || 0) + amount;

    saveGoldenDB(db);
    console.log(`💰 Transfer: ${sender.email} → ${recipientEmail} (${amount}G + ${fee}G fee)`);

    res.json({
      success: true,
      message: `Successfully transferred ${amount}G to ${recipientEmail}`,
      amount: amount,
      fee: fee,
      totalCost: totalCost,
      newBalance: sender.golden_balance
    });
  } catch (err) {
    console.error("Transfer error:", err);
    res.status(500).json({ error: "Internal server error during transfer" });
  }
});

// ============ STATIC PAGE ROUTES ============
const staticPages = {
  "/success": "success.html",
  "/plans": "plans.html",
  "/FreeAI": "chat-free-ai.html",
  "/advancedAI": "chat-advancedai.html",
  "/homework-helper": "homework-helper.html",
  "/search-info": "search-info.html",
  "/create-your-universe": "your-space.html",
  "/search-educational-lessons": "search-lessons.html",
  "/create-your-rocket": "create-rocket.html",
  "/payment-cancel": "plans.html",
  "/create-satellite": "create-satellite.html",
  "/create-planet": "create-planet.html",
  "/create-advanced-planet": "create-advanced-planet.html",
  "/privacy-policy": "privacy.html",
  "/terms-of-service": "terms.html",
  "/refund-policy": "refund.html",
  "/contact-page": "contact.html",
  "/about-us-page": "about-us.html",
};

Object.entries(staticPages).forEach(([route, file]) => {
  app.get(route, (req, res) => {
    res.sendFile(path.join(__dirname, file));
  });
});

// ============ CRYPTO PRICING ============
let lastPrices = {};
let lastPriceFetch = 0;

app.get("/api/crypto-prices", async (req, res) => {
  try {
    console.log("🔄 Fetching REAL crypto prices from CoinGecko...");
    
    const response = await axios.get(
      "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether,usd-coin,binancecoin,tron,solana,dogecoin&vs_currencies=usd&include_24hr_change=true",
      {
        timeout: 10000,
        headers: {
          'User-Agent': 'GoldenSpaceAI/1.0'
        }
      }
    );
    
    console.log("✅ Real crypto prices received:", Object.keys(response.data));
    
    lastPrices = response.data;
    lastPriceFetch = Date.now();
    
    res.json(response.data);
  } catch (error) {
    console.error("❌ Crypto price fetch error:", error.message);
    
    const fallbackPrices = {
      bitcoin: { usd: 43450.32, usd_24h_change: 2.15 },
      ethereum: { usd: 2380.15, usd_24h_change: 1.78 },
      tether: { usd: 1.00, usd_24h_change: 0.01 },
      "usd-coin": { usd: 1.00, usd_24h_change: 0.02 },
      binancecoin: { usd: 305.67, usd_24h_change: 3.42 },
      tron: { usd: 0.1056, usd_24h_change: -0.56 },
      solana: { usd: 102.45, usd_24h_change: 5.23 },
      dogecoin: { usd: 0.0856, usd_24h_change: 1.34 }
    };
    
    console.log("🔄 Using fallback prices due to API error");
    res.json(fallbackPrices);
  }
});

// ============ HEALTH & ERROR HANDLING ============
app.get("/health", (_req, res) => {
  const db = loadGoldenDB();
  res.json({ 
    status: "OK", 
    users: Object.keys(db.users || {}).length, 
    lastCheck: new Date().toISOString(),
    cryptoPrices: Object.keys(lastPrices).length > 0 ? "Live" : "Not loaded"
  });
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ============ SERVER START ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 GoldenSpaceAI LAUNCHED on port ${PORT}`);
  console.log(`✅ All systems ready for launch!`);
  console.log(`💰 Golden packages: 60G/$15, 100G/$20, 200G/$40`);
  console.log(`🤖 ADVANCED AI: 3 models (Friendly, Thinking, Fast)`);
  console.log(`🔐 Authentication: Google & GitHub OAuth`);
  console.log(`🌐 Domain: ${SITE_BASE_URL}`);
  console.log(`🎉 Special account: farisalmhamad3@gmail.com → 100,000G`);
  console.log(`🚀 Ready for production!`);
});
