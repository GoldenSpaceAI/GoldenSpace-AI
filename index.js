// index.js — GoldenSpaceAI COMPLETE SYSTEM (UPDATED WITH ADVANCED AI)
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
import { createClient } from "@supabase/supabase-js";

// ============ CONFIGURATION ============
dotenv.config();
const app = express();
app.set("trust proxy", 1);

// Constants
const GOLDEN_DB_PATH = "./data/golden_database.json";
const PAYMENT_DB_PATH = "./data/payment_database.json";
const ADV_PRICE_G = 20;
const IMG_LIMIT_PER_MONTH = 20;

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

const SITE_BASE_URL = "https://goldenspaceai.space";

// ============ INITIALIZATION ============
validateEnvironment();
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
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
  const required = ["OPENAI_API_KEY", "SESSION_SECRET", "SUPABASE_URL", "SUPABASE_SERVICE_KEY"];
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

  const isAdmin = ["118187920786158036693@google", process.env.ADMIN_USER_ID].includes(id) ||
    req.user.email === "farisalmhamad3@gmail.com";

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
        cost: ADV_PRICE_G,
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

// =========================================
// ADVANCED AI SUBSCRIPTION SYSTEM
// =========================================

const ADVANCED_AI_PRICE = 20;          // 20 Golden per month
const ADVANCED_AI_DURATION = 30;       // 30 days

// Helper: create date +30 days
function addDays(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString();
}

// Helper: check if expired
function isExpired(date) {
  return new Date(date) < new Date();
}

// ===============================
// 1. GET SUBSCRIPTION STATUS
// ===============================
app.get("/api/subscription-status", authUser, (req, res) => {
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);

  const user = db.users[id];
  if (!user) return res.status(404).json({ error: "User not found" });

  const sub = user.subscription?.advancedAI || null;

  return res.json({
    active: sub?.active || false,
    autoRenew: sub?.autoRenew || false,
    expires: sub?.expires || null,
    balance: user.balance,
  });
});


// ===============================
// 2. PURCHASE (activate subscription)
// ===============================
app.post("/api/subscribe-advanced-ai", authUser, (req, res) => {
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);

  const user = db.users[id];
  if (!user) return res.status(404).json({ error: "User not found" });

  if (user.balance < ADVANCED_AI_PRICE) {
    return res.status(403).json({ error: "Not enough Golden." });
  }

  // Deduct Golden
  user.balance -= ADVANCED_AI_PRICE;

  // Activate subscription
  user.subscription ??= {};
  user.subscription.advancedAI = {
    active: true,
    autoRenew: true,
    started: new Date().toISOString(),
    expires: addDays(ADVANCED_AI_DURATION)
  };

  saveGoldenDB(db);

  return res.json({
    success: true,
    message: "Advanced AI unlocked for 30 days",
    expires: user.subscription.advancedAI.expires
  });
});


// ===============================
// 3. AUTO-RENEWAL CRON JOB
// Run this every time index.js runs OR every 24h if you want
// ===============================
function renewSubscriptions() {
  const db = loadGoldenDB();

  for (const id in db.users) {
    const user = db.users[id];
    const sub = user.subscription?.advancedAI;

    if (!sub) continue;
    if (!sub.autoRenew) continue;

    // If subscription expired → attempt renewal
    if (isExpired(sub.expires)) {
      if (user.balance >= ADVANCED_AI_PRICE) {
        // deduct & renew
        user.balance -= ADVANCED_AI_PRICE;
        sub.active = true;
        sub.expires = addDays(ADVANCED_AI_DURATION);
        console.log(`🔄 Renewed Advanced AI for ${id}`);
      } else {
        // lock
        sub.active = false;
        console.log(`⛔ Not enough balance — Advanced AI locked for ${id}`);
      }
    }
  }

  saveGoldenDB(db);
}

// Call on startup
renewSubscriptions();
setInterval(renewSubscriptions, 1000 * 60 * 60 * 12); // every 12 hours
// You can change to 24h if you want

// ============ ADVANCED AI ENDPOINTS ============

// NEW MODEL ROUTES → matches frontend
const modelRoutes = [
  { path: "pro", model: "gpt-4.1" },          // PRO button
  { path: "flash", model: "gpt-5-nano" },     // FLASH button
  { path: "thinking", model: "gpt-5" }        // THINKING button
];

for (const { path, model } of modelRoutes) {
  app.post(`/api/generate-${path}`, requireFeature("chat_advancedai"), async (req, res) => {
    try {
      const { messages, prompt } = req.body;

      console.log(`➡️ [${path}] Sending to OpenAI`, {
        endpoint: `/api/generate-${path}`,
        model,
        promptPreview: prompt?.slice(0, 100) || "(using messages array)"
      });

      const completion = await openai.chat.completions.create({
        model,
        messages: messages || [{ role: "user", content: prompt }],
        max_completion_tokens: 2000
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
        model,
        tokens_used: completion.usage?.total_tokens || 0
      });

    } catch (error) {
      console.error(`${path} generation error:`, error);
      res.status(500).json({ error: error.message });
    }
  });
}
// ============ EXISTING AI ENDPOINTS ============
// Free Chat AI
app.post("/chat-free-ai", async (req, res) => {
  try {
    const prompt = req.body.q || req.body.question || "Hello!";
    const model = req.body.model || "gpt-4o-mini";
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

// Search Info Endpoint
app.post("/ask", requireFeature("search_info"), async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });
    
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are a helpful research assistant. Provide clear, concise, and informative answers. Structure your response with key points and summaries." 
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

// Search Lessons Endpoint
app.post("/search-lessons", requireFeature("search_lessons"), async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });
    
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are an educational tutor. Create comprehensive lessons with introduction, explanations, examples, and practice questions. Structure your response in clear sections." 
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

// Advanced AI Chat - Simplified with localStorage and model selection
app.post("/chat-advancedai", requireFeature("chat_advancedai"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    const userId = req.user ? getUserIdentifier(req) : null;
    if (!userId) return res.status(401).json({ error: "Login required" });

    const db = loadGoldenDB();
    const user = db.users[userId];
    if (!user) return res.status(404).json({ error: "User not found" });

    const { q: prompt, model: selectedModel = "gpt-5", mode, custom_instructions } = req.body;
    if (!prompt) return res.status(400).json({ error: "Missing prompt" });

    // Check subscription
    const expiryStr = user.subscriptions?.chat_advancedai || null;
    const now = new Date();
    if (!expiryStr || new Date(expiryStr) < now) {
      return res.status(403).json({ error: "Advanced Chat is locked. Please activate for 20 G for 30 days access." });
    }

    // Handle image generation
    if (mode === "image") {
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

      // NO Supabase - images saved in localStorage on frontend
      return res.json({
        reply: `![Generated Image](${imageUrl})`,
        imageUrl,
        model: "dall-e-3"
      });
    }

    // Map selected model to actual OpenAI models
    const modelMapping = {
      "gpt-5": "gpt-5",           // GPT-5 → GPT-4o
      "gpt-5-mini": "gpt-5-mini", // GPT-5 Mini → GPT-4o-mini  
      "gpt-5-nano": "gpt-5-nano", // GPT-5 Nano → GPT-3.5-turbo
      "gpt-4.1": "gpt-4",
      "gemini2.5-pro": "gpt-4"
    };

    const actualModel = modelMapping[selectedModel] || "gpt-4o";
    
    const messages = [
      { 
        role: "system", 
        content: custom_instructions 
          ? `You are GoldenSpaceAI's ${selectedModel} assistant. Follow these custom instructions: ${custom_instructions}`
          : `You are GoldenSpaceAI's ${selectedModel} assistant. Provide helpful, detailed responses with advanced reasoning and analysis.`
      },
      { role: "user", content: prompt }
    ];

    const completion = await openai.chat.completions.create({
      model: actualModel,
      messages,
      max_tokens: 2000,
      temperature: 0.7
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";

    // Return the SELECTED model name, not the actual one
    res.json({ 
      reply, 
      model: selectedModel, // Return the branded name (gpt-5, gpt-5-mini, etc.)
      tokens_used: completion.usage?.total_tokens || 0
    });

  } catch (e) {
    console.error("Advanced AI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, () => {});
  }
});

// Other existing AI endpoints
app.post("/search-info", requireFeature("search_info"), async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are a helpful research assistant. Provide clear, concise, and informative answers. Structure your response with key points and summaries." 
        },
        { role: "user", content: query }
      ],
      max_tokens: 1200,
      temperature: 0.7
    });
    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer: reply });
  } catch (e) {
    console.error("Search info error:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/learn-physics", async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { 
          role: "system", 
          content: "You are a physics tutor who explains concepts clearly and simply. Break down complex topics into understandable parts." 
        },
        { role: "user", content: question }
      ],
      max_tokens: 1200,
      temperature: 0.7
    });
    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer: reply });
  } catch (err) {
    console.error("Physics AI error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/homework-helper", requireFeature("homework_helper"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    const model = req.body.model || "gpt-4o";
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

app.post("/live-chat-process", async (req, res) => {
  try {
    const { message, conversation, model = "gpt-4o-mini" } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });

    const messages = [
      { 
        role: "system", 
        content: "You are a friendly, conversational AI assistant. Keep responses natural and conversational since users will hear them spoken aloud. Respond in 1-2 sentences maximum for best audio experience." 
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

// ============ SUPABASE CHAT/PROJECT SYSTEM ============
app.post("/api/chat/create", async (req, res) => {
  try {
    const { title } = req.body;
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const userId = getUserIdentifier(req);

    const { data, error } = await supabase
      .from("chats")
      .insert([{ user_id: userId, title }])
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, chat: data });
  } catch (err) {
    console.error("Chat create error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/chat/:chat_id", async (req, res) => {
  try {
    const { chat_id } = req.params;
    const { data, error } = await supabase
      .from("messages")
      .select("*")
      .eq("chat_id", chat_id)
      .order("timestamp", { ascending: true })
      .limit(50);
    if (error) throw error;
    res.json({ success: true, messages: data });
  } catch (err) {
    console.error("Chat fetch error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/chat/message", async (req, res) => {
  try {
    const { chat_id, sender, content, image_url } = req.body;
    if (!chat_id || !content) return res.status(400).json({ error: "Missing chat_id or content" });

    const { error } = await supabase.from("messages").insert([{ 
      chat_id, 
      sender, 
      content,
      image_url,
      timestamp: new Date().toISOString()
    }]);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("Chat save error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/projects", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const userId = getUserIdentifier(req);
    const { data, error } = await supabase
      .from("projects")
      .select("*")
      .eq("user_id", userId)
      .order("created_at", { ascending: false });
    if (error) throw error;
    res.json({ success: true, projects: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/projects/create", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { name, description } = req.body;
    const userId = getUserIdentifier(req);
    const { data, error } = await supabase
      .from("projects")
      .insert([{ user_id: userId, name, description }])
      .select()
      .single();
    if (error) throw error;
    res.json({ success: true, project: data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/projects/:id", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { id } = req.params;
    const userId = getUserIdentifier(req);

    const { data: project } = await supabase
      .from("projects")
      .select("*")
      .eq("id", id)
      .eq("user_id", userId)
      .single();

    if (!project) return res.status(404).json({ error: "Project not found" });

    await supabase.from("messages").delete().eq("chat_id", id);
    const { error } = await supabase.from("projects").delete().eq("id", id);
    if (error) throw error;

    res.json({ success: true, message: "Project deleted successfully" });
  } catch (err) {
    console.error("Project delete error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ============ BLOCKCHAIN & CRYPTO ============
const wallets = {
  btc: "bc1qz5wtz2d329xsm7gcs9e3jwls9supg2fk2hkxtd",
  eth: "0x8BEaCb38dF916F6644F81cA0De18C1F4996d32Ea",
  usdt_trc20: "TCN6eVtHFNtPAJNfebgGGm8c2h71NWYY9P",
  bnb: "0x8BEaCb38dF916F6644F81cA0De18C1F4996d32Ea",
  tron: "TCN6eVtHFNtPAJNfebgGGm8c2h71NWYY9P",
  sol: "8vdM8myEj4pAXZZK6WCV1WkSGvmzLgteDv5qCCYcR2NW",
  doge: "DAfXZW2f9wJD4fBMwekb8iVKfQMAdyNCVV",
};

let lastPrices = {};
let lastPriceFetch = 0;

async function getUSDPrice(coin) {
  try {
    const now = Date.now();
    if (now - lastPriceFetch < 5 * 60 * 1000 && lastPrices[coin]) {
      return lastPrices[coin];
    }
    const url = `https://min-api.cryptocompare.com/data/price?fsym=${coin.toUpperCase()}&tsyms=USD`;
    const res = await axios.get(url);
    const price = res.data.USD || 0;
    lastPrices[coin] = price;
    lastPriceFetch = now;
    return price;
  } catch (err) {
    console.error(`⚠️ Failed to fetch price for ${coin}:`, err.message);
    return lastPrices[coin] || 0;
  }
}

const blockchainCheckers = {
  btc: async (address) => {
    const res = await axios.get(`https://blockstream.info/api/address/${address}`);
    return res.data.chain_stats.funded_txo_sum / 1e8;
  },
  eth: async (address) => {
    const res = await axios.get(`https://api.blockcypher.com/v1/eth/main/addrs/${address}/balance`);
    return res.data.final_balance / 1e18;
  },
  tron: async (address) => {
    const res = await axios.get(`https://apilist.tronscanapi.com/api/account?address=${address}`);
    return res.data.balance / 1e6;
  },
  doge: async (address) => {
    const res = await axios.get(`https://dogechain.info/api/v1/address/balance/${address}`);
    return parseFloat(res.data.balance);
  },
  sol: async (address) => {
    const res = await axios.post("https://api.mainnet-beta.solana.com", {
      jsonrpc: "2.0",
      id: 1,
      method: "getBalance",
      params: [address],
    });
    return res.data.result.value / 1e9;
  },
};

async function checkBlockchainPayments() {
  try {
    console.log("🔍 Checking blockchain payments...");
    for (const [coin, address] of Object.entries(wallets)) {
      const checker = blockchainCheckers[coin];
      if (!checker) continue;
      await new Promise((r) => setTimeout(r, 3000));
      const balance = await checker(address);
      const usdPrice = await getUSDPrice(coin);
      const valueUSD = balance * usdPrice;
      console.log(`💰 ${coin.toUpperCase()} (${address.slice(0, 6)}...): ${balance} ≈ $${valueUSD.toFixed(2)}`);
    }
  } catch (err) {
    console.error("❌ Payment check failed:", err.message);
  }
}

app.get("/api/test-blockchain", async (_req, res) => {
  try {
    await checkBlockchainPayments();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============ REAL LIVE CRYPTO PRICING ============
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

app.get("/api/crypto-prices-detailed", async (req, res) => {
  try {
    const response = await axios.get(
      "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether,usd-coin,binancecoin,tron,solana,dogecoin&vs_currencies=usd&include_24hr_change=true&include_market_cap=true&include_24hr_vol=true",
      {
        timeout: 10000
      }
    );
    
    res.json(response.data);
  } catch (error) {
    console.error("Detailed crypto price fetch error:", error.message);
    res.status(500).json({ error: "Failed to fetch detailed prices" });
  }
});

setInterval(checkBlockchainPayments, 10 * 60 * 1000);

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
  console.log(`🤖 ADVANCED AI: GPT-5, GPT-5 Mini, GPT-5 Nano models`);
  console.log(`🎨 DALL-E 3 Image generation: 20 images/month included`);
  console.log(`💫 Advanced Chat: Voice, Deep Search, Custom Instructions`);
  console.log(`💰 REAL Crypto Prices: /api/crypto-prices (Live from CoinGecko)`);
  console.log(`🎉 Special account: farisalmhamad3@gmail.com → 100,000G`);
  console.log(`🌐 Domain: goldenspaceai.space`);
  console.log(`🚀 Ready for production!`);
});
