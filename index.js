// index.js — GoldenSpaceAI COMPLETE SYSTEM (Auth + Golden + Payments + Admin + AI + Refunds + Transfer + 2-min Sync)
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
import nodemailer from "nodemailer";
// ============ ENV & APP ============
dotenv.config();
const app = express();
app.set("trust proxy", 1);

// ============ MIDDLEWARE ============
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
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

// ============ PATHS ============
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Static files (serves all your *.html, images, etc.)
app.use(express.static(__dirname));

// ============ PASSPORT ============
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// ============ DB HELPERS (Persistent Storage on Render) ============
const GOLDEN_DB_PATH = "/data/golden_database.json";   // stored safely on persistent disk
const PAYMENT_DB_PATH = "/data/payment_database.json"; // stored safely on persistent disk

function loadGoldenDB() {
  try {
    if (fs.existsSync(GOLDEN_DB_PATH)) {
      const file = fs.readFileSync(GOLDEN_DB_PATH, "utf8");
      if (!file.trim()) return { users: {}, family_plans: {} };
      return JSON.parse(file);
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
function saveGoldenDB(db) {
  try {
    fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify(db, null, 2));
    return true;
  } catch (e) {
    console.error("DB save error:", e);
    return false;
  }
}
function loadPaymentDB() {
  try {
    if (fs.existsSync(PAYMENT_DB_PATH)) {
      const raw = fs.readFileSync(PAYMENT_DB_PATH, "utf8");
      return raw.trim() ? JSON.parse(raw) : { transactions: {}, user_packages: {} };
    }
  } catch (e) {
    console.error("Payment DB error:", e);
  }
  return { transactions: {}, user_packages: {} };
}
function savePaymentDB(d) {
  try {
    fs.writeFileSync(PAYMENT_DB_PATH, JSON.stringify(d, null, 2));
  } catch (e) {
    console.error("Payment DB save error:", e);
  }
}

// Helpers
function getUserIdentifier(req) {
  return req.user ? `${req.user.id}@${req.user.provider}` : null;
}
function getUserGoldenBalance(userId) {
  const db = loadGoldenDB();
  return db.users[userId]?.golden_balance || 0;
}
function ensureUserExists(user) {
  const db = loadGoldenDB();
  const id = `${user.id}@${user.provider}`;
  if (!db.users[id]) {
    db.users[id] = {
      email: user.email,
      name: user.name,
      golden_balance: 0,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      subscriptions: {},
      total_golden_earned: 0,
      total_golden_spent: 0,
      transactions: [],
    };
    saveGoldenDB(db);
  } else {
    db.users[id].last_login = new Date().toISOString();
    saveGoldenDB(db);
  }
}

// ============ GOLDEN / PAYMENTS CONFIG ============
const TRUST_WALLET_ADDRESSES = {
  BTC: "bc1qz5wtz2d329xsm7gcs9e3jwls9supg2fk2hkxtd",
  LTC: "ltc1qngssav372fl4sw0s8w66h4c8v5yftqw4qrkhdn",
};
const GOLDEN_PACKAGES = {
  20: { BTC: 0.00008333, LTC: 0.0625 },
  40: { BTC: 0.00016666, LTC: 0.125 },
  60: { BTC: 0.00025, LTC: 0.1875 },
  80: { BTC: 0.00033333, LTC: 0.25 },
  100: { BTC: 0.00041666, LTC: 0.3125 },
  200: { BTC: 0.00083333, LTC: 0.625 },
  400: { BTC: 0.00166666, LTC: 1.25 },
  600: { BTC: 0.0025, LTC: 1.875 },
  800: { BTC: 0.00333333, LTC: 2.5 },
  1000: { BTC: 0.00416666, LTC: 3.125 },
};
const FEATURE_PRICES = {
  search_info: 4,
  homework_helper: 20,
  chat_advancedai: 20,
  create_rocket: 4,
  create_satellite: 4,
  create_advanced_planet: 4,
  your_space: 4,
  learn_physics: 4,
  create_planet: 4,
  search_lessons: 10,
};

// ============ PAYMENT SYNC ============
async function checkBTC(address) {
  try {
    const res = await axios.get(`https://api.blockcypher.com/v1/btc/main/addrs/${address}/balance`);
    return res.data.final_balance / 1e8;
  } catch {
    return 0;
  }
}
async function checkLTC(address) {
  try {
    const res = await axios.get(`https://api.blockcypher.com/v1/ltc/main/addrs/${address}/balance`);
    return res.data.final_balance / 1e8;
  } catch {
    return 0;
  }
}
async function processPackagePayments() {
  const pay = loadPaymentDB();
  const gold = loadGoldenDB();
  let updated = false;

  for (const [userId, pkgs] of Object.entries(pay.user_packages || {})) {
    for (const [key, info] of Object.entries(pkgs)) {
      if (info.status !== "pending") continue;
      const bal = info.coin === "BTC" ? await checkBTC(info.address) : await checkLTC(info.address);
      if (bal >= info.requiredAmount) {
        if (gold.users[userId]) {
          const u = gold.users[userId];
          u.golden_balance = (u.golden_balance || 0) + info.packageSize;
          u.total_golden_earned = (u.total_golden_earned || 0) + info.packageSize;
          u.transactions = u.transactions || [];
          u.transactions.push({
            type: "purchase",
            amount: info.packageSize,
            coin: info.coin,
            address: info.address,
            timestamp: new Date().toISOString(),
          });
          info.status = "completed";
          info.completedAt = new Date().toISOString();
          updated = true;
        }
      }
    }
  }

  if (updated) {
    saveGoldenDB(gold);
    savePaymentDB(pay);
  }
  console.log("✅ Payment sync tick:", new Date().toLocaleTimeString());
}

// 2-Minute recurring sync for payments + feature expirations
setInterval(async () => {
  await processPackagePayments();

  const db = loadGoldenDB();
  let expiredCount = 0;
  for (const [, user] of Object.entries(db.users)) {
    if (!user.subscriptions) continue;
    for (const [feat, expiryIso] of Object.entries(user.subscriptions)) {
      if (new Date(expiryIso) <= new Date()) {
        delete user.subscriptions[feat];
        expiredCount++;
      }
    }
  }
  if (expiredCount > 0) saveGoldenDB(db);
  console.log(`✨ Feature expiry scan completed. Expired: ${expiredCount}`);
}, 120000);

// Keep session user hydrated with most recent Golden/subscriptions
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

// ============ AUTH ============
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
        proxy: true,
      },
      (_a, _b, profile, done) => {
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
  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login-signup.html" }),
    (_req, res) => res.redirect("https://goldenspaceai.space")
  );
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "/auth/github/callback",
        proxy: true,
      },
      (_a, _b, profile, done) => {
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
      }
    )
  );
  app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
  app.get(
    "/auth/github/callback",
    passport.authenticate("github", { failureRedirect: "/login-signup.html" }),
    (_req, res) => res.redirect("https://goldenspaceai.space")
  );
}

// Simple pages
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "login-signup.html")));
app.get("/login", (_req, res) => res.sendFile(path.join(__dirname, "login-signup.html")));
app.get("/:page.html", (req, res) => res.sendFile(path.join(__dirname, req.params.page + ".html")));

// Logout
app.post("/logout", (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).json({ error: "Logout failed" });
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ ok: true, message: "Logged out successfully" });
    });
  });
});

// ============ USER / ME ============
app.get("/api/me", (req, res) => {
  if (!req.user) {
    return res.json({ loggedIn: false });
  }

  const id = `${req.user.id}@${req.user.provider}`;
  const db = loadGoldenDB();
  const userData = db.users[id];

  if (!userData) {
    ensureUserExists(req.user); // auto-create missing
    return res.json({ loggedIn: true, user: req.user, balance: 0 });
  }

  // Refresh session with real balance + subscriptions
  req.session.golden_balance = userData.golden_balance || 0;
  req.session.subscriptions = userData.subscriptions || {};
  req.session.save();

  res.json({
    loggedIn: true,
    user: req.user,
    balance: userData.golden_balance || 0,
    subscriptions: userData.subscriptions || {},
  });
});


// ============ GOLDEN PUBLIC APIS ============
app.get("/api/golden-balance", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false, balance: 0 });
  const b = getUserGoldenBalance(getUserIdentifier(req));
  res.json({ loggedIn: true, balance: b, user: req.user });
});

app.get("/api/golden-packages", (_req, res) => {
  // For UI: $ price = G / 4
  const packages = {};
  Object.keys(GOLDEN_PACKAGES).forEach(sz => (packages[sz] = Number(sz) / 4));
  res.json(packages);
});

app.get("/api/package-address", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { coin, packageSize } = req.query;
  const size = parseInt(packageSize);
  if (!GOLDEN_PACKAGES[size]) return res.status(400).json({ error: "Invalid package size" });
  if (coin !== "BTC" && coin !== "LTC") return res.status(400).json({ error: "Only BTC and LTC are supported" });

  const userId = getUserIdentifier(req);
  const payDB = loadPaymentDB();
  payDB.user_packages[userId] = payDB.user_packages[userId] || {};
  const key = `${coin}_${size}`;

  if (!payDB.user_packages[userId][key]) {
    payDB.user_packages[userId][key] = {
      address: TRUST_WALLET_ADDRESSES[coin],
      packageSize: size,
      coin,
      requiredAmount: GOLDEN_PACKAGES[size][coin],
      status: "pending",
      createdAt: new Date().toISOString(),
    };
    savePaymentDB(payDB);
  }

  const pkg = payDB.user_packages[userId][key];
  res.json({
    packageSize: pkg.packageSize,
    coin: pkg.coin,
    address: pkg.address,
    requiredAmount: pkg.requiredAmount,
    usdPrice: pkg.packageSize / 4,
    status: pkg.status,
  });
});

// Feature status + unlock (used by your universal 20G lock)
app.get("/api/feature-status", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature } = req.query;
  if (!feature || !FEATURE_PRICES[feature]) {
    return res.status(400).json({ error: "Invalid feature" });
  }
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];
  if (!u?.subscriptions?.[feature]) {
    return res.json({ feature, unlocked: false, price: FEATURE_PRICES[feature] });
  }
  const expiry = new Date(u.subscriptions[feature]);
  if (expiry <= new Date()) {
    delete u.subscriptions[feature];
    saveGoldenDB(db);
    return res.json({ feature, unlocked: false, price: FEATURE_PRICES[feature] });
  }
  const remainingHours = Math.max(0, Math.floor((expiry - new Date()) / (1000 * 60 * 60)));
  res.json({ feature, unlocked: true, remainingHours, price: FEATURE_PRICES[feature] });
});

app.post("/api/unlock-feature", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature, cost } = req.body;
  if (!feature || FEATURE_PRICES[feature] !== cost) {
    return res.status(400).json({ error: "Invalid feature or cost" });
  }
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];
  if (!u) return res.status(404).json({ error: "User not found" });
  if ((u.golden_balance || 0) < cost) return res.status(400).json({ error: "Not enough Golden" });
  const exp = new Date();
  exp.setDate(exp.getDate() + 30);

  u.golden_balance -= cost;
  u.total_golden_spent = (u.total_golden_spent || 0) + cost;
  u.subscriptions = u.subscriptions || {};
  u.subscriptions[feature] = exp.toISOString();
  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "unlock",
    feature,
    amount: -cost,
    timestamp: new Date().toISOString(),
  });

  saveGoldenDB(db);
  res.json({ success: true, newBalance: u.golden_balance });
});

// ============ AI ENDPOINTS ============
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const upload = multer({ dest: "uploads/" });
// ==================== BASIC CHAT AI (Free Version) ====================
app.post("/chat-ai", async (req, res) => {
  try {
    const prompt = req.body.q || "Hello!";
    const model = req.body.model || "gpt-4o-mini"; // lighter, faster model for free chat

    const completion = await openai.chat.completions.create({
      model,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 800,
      temperature: 0.7,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });
  } catch (e) {
    console.error("Basic Chat AI error:", e);
    res.status(500).json({ error: e.message });
  }
});
// Advanced Chat (text, file, or image generation)
app.post("/chat-advanced-ai", upload.single("image"), async (req, res) => {
  try {
    const model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Answer helpfully.";
    const filePath = req.file?.path;

    // ============ 1️⃣ IMAGE GENERATION ==============
    if (model === "gpt-image-1") {
      try {
        const image = await openai.images.generate({
          model: "gpt-image-1",
          prompt,
          size: "1024x1024",
        });
        const base64Image = image.data?.[0]?.b64_json;
        if (!base64Image) throw new Error("No image data returned.");
        return res.json({
          reply: `data:image/png;base64,${base64Image}`,
          model,
        });
      } catch (imgErr) {
        console.error("Image generation error:", imgErr);
        return res.status(500).json({
          error: imgErr.message || "Image generation failed.",
        });
      }
    }

    // ============ 2️⃣ CHAT / VISION MODELS ==========
    let messages;
    if (filePath) {
      // Convert uploaded file to base64 (for vision models)
      const b64 = fs.readFileSync(filePath).toString("base64");
      const mime = req.file.mimetype || "image/png";
      messages = [
        {
          role: "user",
          content: [
            { type: "text", text: prompt },
            { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } },
          ],
        },
      ];
    } else {
      messages = [{ role: "user", content: prompt }];
    }

    const completion = await openai.chat.completions.create({
      model,
      messages,
      max_tokens: 1200,
      temperature: 0.7,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    if (filePath) fs.unlink(filePath, () => {}); // cleanup temp file
    res.json({ reply, model });

  } catch (e) {
    console.error("AI error:", e);
    res.status(500).json({ error: e.message || "Internal server error." });
  }
});

// ==================== AI LESSONS ENDPOINT ====================
app.post("/search-lessons", async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a professional teacher creating clear, educational lessons for students. Structure explanations into sections: Introduction, Explanation, Examples, and Practice." },
        { role: "user", content: query }
      ],
      max_tokens: 1200,
      temperature: 0.7,
    });

    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer: reply });
  } catch (e) {
    console.error("Lesson AI error:", e);
    res.status(500).json({ error: e.message });
  }
});
// Dedicated Homework Helper Vision endpoint (for your homework-helper.html)
app.post("/homework-helper", upload.single("image"), async (req, res) => {
  try {
    const model = req.body.model || "gpt-4o";
    const prompt =
      req.body.q ||
      "Solve this homework step-by-step. Show detailed reasoning and final answer.";
    const filePath = req.file?.path;

    if (!filePath) {
      return res.status(400).json({ error: "No image provided" });
    }

    const b64 = fs.readFileSync(filePath).toString("base64");
    const mime = req.file.mimetype || "image/png";

    const messages = [
      {
        role: "system",
        content:
          "You are a careful, step-by-step homework solver. Explain clearly and show working.",
      },
      {
        role: "user",
        content: [
          { type: "text", text: prompt },
          { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } },
        ],
      },
    ];

    const completion = await openai.chat.completions.create({
      model,
      messages,
      max_tokens: 1400,
      temperature: 0.4,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    fs.unlink(filePath, () => {});
    res.json({ reply, model });
  } catch (e) {
    console.error("Homework AI error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ============ ADMIN API ============
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || "golden-admin-secret-2024";

const requireAdminAuth = (req, res, next) => {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Admin authentication required" });
  }
  const token = auth.substring(7);
  if (token !== ADMIN_SECRET_KEY) {
    return res.status(403).json({ error: "Invalid admin token" });
  }
  next();
};

// Admin: all users
app.get("/api/admin/all-users", requireAdminAuth, (_req, res) => {
  const db = loadGoldenDB();
  const users = [];
  for (const [userId, u] of Object.entries(db.users || {})) {
    users.push({
      userId,
      name: u.name,
      email: u.email,
      golden_balance: u.golden_balance || 0,
      total_golden_earned: u.total_golden_earned || 0,
      total_golden_spent: u.total_golden_spent || 0,
      created_at: u.created_at,
      last_login: u.last_login,
      provider: userId.split("@")[1],
    });
  }
  users.sort((a, b) => b.golden_balance - a.golden_balance);
  const totalGolden = users.reduce((s, u) => s + (u.golden_balance || 0), 0);
  res.json({ success: true, users, totalUsers: users.length, totalGolden });
});

// Admin: search users
app.get("/api/admin/search-users", requireAdminAuth, (req, res) => {
  const q = (req.query.query || "").toLowerCase();
  const db = loadGoldenDB();
  const results = [];
  for (const [userId, u] of Object.entries(db.users || {})) {
    const hit =
      userId.toLowerCase().includes(q) ||
      (u.email && u.email.toLowerCase().includes(q)) ||
      (u.name && u.name.toLowerCase().includes(q));
    if (hit) {
      results.push({
        userId,
        name: u.name,
        email: u.email,
        golden_balance: u.golden_balance || 0,
        total_golden_earned: u.total_golden_earned || 0,
        total_golden_spent: u.total_golden_spent || 0,
        created_at: u.created_at,
        last_login: u.last_login,
        provider: userId.split("@")[1],
      });
    }
  }
  res.json({ success: true, users: results });
});

// Admin: add golden
app.post("/api/admin/add-golden", requireAdminAuth, (req, res) => {
  const { userId, amount, reason } = req.body;
  if (!userId || !amount) return res.status(400).json({ error: "User ID and amount required" });

  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  const prev = u.golden_balance || 0;
  u.golden_balance = prev + Number(amount);
  u.total_golden_earned = (u.total_golden_earned || 0) + Number(amount);
  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "add",
    amount: Number(amount),
    previous_balance: prev,
    new_balance: u.golden_balance,
    reason: reason || "Admin adjustment",
    timestamp: new Date().toISOString(),
  });
  saveGoldenDB(db);
  res.json({ success: true });
});

// Admin: subtract golden
app.post("/api/admin/subtract-golden", requireAdminAuth, (req, res) => {
  const { userId, amount, reason } = req.body;
  if (!userId || !amount) return res.status(400).json({ error: "User ID and amount required" });

  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  const prev = u.golden_balance || 0;
  const amt = Number(amount);
  if (prev < amt) return res.status(400).json({ error: "Insufficient balance" });

  u.golden_balance = prev - amt;
  u.total_golden_spent = (u.total_golden_spent || 0) + amt;
  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "subtract",
    amount: -amt,
    previous_balance: prev,
    new_balance: u.golden_balance,
    reason: reason || "Admin adjustment",
    timestamp: new Date().toISOString(),
  });
  saveGoldenDB(db);
  res.json({ success: true });
});

// Admin: set golden
app.post("/api/admin/set-golden", requireAdminAuth, (req, res) => {
  const { userId, balance, reason } = req.body;
  if (!userId || balance === undefined) return res.status(400).json({ error: "User ID and balance required" });

  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  const prev = u.golden_balance || 0;
  const newBal = Number(balance);
  u.golden_balance = newBal;
  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "set",
    amount: newBal - prev,
    previous_balance: prev,
    new_balance: newBal,
    reason: reason || "Admin set balance",
    timestamp: new Date().toISOString(),
  });
  saveGoldenDB(db);
  res.json({ success: true });
});

// Admin: user transactions
app.get("/api/admin/user-transactions/:userId", requireAdminAuth, (req, res) => {
  const { userId } = req.params;
  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });
  res.json({ success: true, transactions: u.transactions || [] });
});

// ============ REFUNDS (EMAIL via Namecheap PrivateEmail) ============
app.post("/api/refund-golden", async (req, res) => {
  try {
    const { amount, walletAddress, currency } = req.body;
    const sessUser = req.session?.passport?.user;
    const userIdFull = sessUser ? `${sessUser.id}@${sessUser.provider}` : null;
    const userEmail = sessUser?.email;
    const userName = sessUser?.displayName || sessUser?.name || "Unknown User";

    if (!userIdFull || !userEmail) return res.status(401).json({ error: "Not logged in" });
    if (!amount || amount <= 0) return res.status(400).json({ error: "Invalid amount" });

    const db = loadGoldenDB();
    const user = db.users[userIdFull];
    if (!user) return res.status(404).json({ error: "User not found" });

    if ((user.golden_balance || 0) < Number(amount)) {
      return res.status(400).json({ error: "Not enough Golden" });
    }

    const prev = user.golden_balance;
    user.golden_balance = prev - Number(amount);
    user.transactions = user.transactions || [];
    user.transactions.push({
      type: "refund",
      amount: -Number(amount),
      previous_balance: prev,
      new_balance: user.golden_balance,
      currency,
      walletAddress,
      timestamp: new Date().toISOString(),
    });
    saveGoldenDB(db);

    const transporter = nodemailer.createTransport({
      host: "mail.privateemail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.ADMIN_EMAIL || "support@goldenspaceai.space",
        pass: process.env.ADMIN_EMAIL_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: `"GoldenSpaceAI Refunds" <support@goldenspaceai.space>`,
      to: "support@goldenspaceai.space",
      subject: `🔔 Refund Request Received (RefundID:2233553)`,
      html: `
        <h2>💰 GoldenSpaceAI Refund Request</h2>
        <ul>
          <li><strong>RefundID:</strong> 2233553</li>
          <li><strong>User Name:</strong> ${userName}</li>
          <li><strong>User Email:</strong> ${userEmail}</li>
          <li><strong>User ID:</strong> ${userIdFull}</li>
          <li><strong>Refund Amount:</strong> ${amount}G</li>
          <li><strong>Currency:</strong> ${currency}</li>
          <li><strong>Wallet Address:</strong> ${walletAddress}</li>
          <li><strong>Date:</strong> ${new Date().toLocaleString()}</li>
        </ul>
        <p>Balance auto-adjusted: ${prev}G → ${user.golden_balance}G.</p>
        <p style="color:#999">Official Refund Email • RefundID:2233553</p>
      `,
    });

    res.json({
      success: true,
      message: "Refund request submitted successfully",
      newBalance: user.golden_balance,
    });
  } catch (e) {
    console.error("Refund error:", e);
    res.status(500).json({ error: "Server error: " + e.message });
  }
});

// ============ TRANSFERS (5% vault fee) ============
app.post("/api/transfer-golden", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });

  const { recipientEmail, amount } = req.body;
  const amt = Number(amount);
  if (!recipientEmail || !amt || amt <= 0) {
    return res.status(400).json({ error: "recipientEmail and positive amount required" });
    }

  const db = loadGoldenDB();
  const senderId = getUserIdentifier(req);
  const sender = db.users[senderId];
  if (!sender) return res.status(404).json({ error: "Sender not found" });

  const recipientId = Object.keys(db.users).find(
    id => db.users[id]?.email?.toLowerCase() === recipientEmail.toLowerCase()
  );
  if (!recipientId) return res.status(404).json({ error: "Recipient not found" });

  const fee = Math.ceil(amt * 0.05);
  const totalCost = amt + fee;
  if ((sender.golden_balance || 0) < totalCost) {
    return res.status(400).json({ error: "Insufficient balance for amount + fee" });
  }

  const vaultId = "goldenvault@system";
  if (!db.users[vaultId]) {
    db.users[vaultId] = {
      email: "vault@goldenspaceai.space",
      name: "GoldenVault",
      golden_balance: 0,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      subscriptions: {},
      transactions: [],
    };
  }

  // Apply balances
  sender.golden_balance -= totalCost;
  db.users[recipientId].golden_balance = (db.users[recipientId].golden_balance || 0) + amt;
  db.users[vaultId].golden_balance = (db.users[vaultId].golden_balance || 0) + fee;

  const now = new Date().toISOString();
  sender.transactions = sender.transactions || [];
  db.users[recipientId].transactions = db.users[recipientId].transactions || [];
  db.users[vaultId].transactions = db.users[vaultId].transactions || [];

  sender.transactions.push({
    type: "transfer-out",
    amount: -totalCost,
    fee,
    to: recipientEmail,
    timestamp: now,
  });
  db.users[recipientId].transactions.push({
    type: "transfer-in",
    amount: amt,
    from: sender.email,
    timestamp: now,
  });
  db.users[vaultId].transactions.push({
    type: "transfer-fee",
    amount: fee,
    from: sender.email,
    timestamp: now,
  });

  saveGoldenDB(db);
  res.json({
    success: true,
    message: `Transferred ${amt}G to ${recipientEmail} (fee: ${fee}G)`,
    newBalance: sender.golden_balance,
  });
});
// ===============================
// 📅 SUBSCRIPTION STATUS ROUTE
// ===============================
app.get("/api/subscriptions", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });

  const db = loadGoldenDB();
  const id = `${req.user.id}@${req.user.provider}`;
  const user = db.users[id];
  if (!user) return res.status(404).json({ error: "User not found" });

  const now = new Date();
  const subs = Object.entries(user.subscriptions || {}).map(([key, expiry]) => {
    const exp = new Date(expiry);
    const active = exp > now;
    const daysLeft = Math.max(0, Math.ceil((exp - now) / (1000 * 60 * 60 * 24)));
    return {
      feature: key,
      cost: FEATURE_PRICES[key] || 0,
      expiry: expiry,
      active,
      daysLeft
    };
  });

  res.json({ subscriptions: subs, balance: user.golden_balance || 0 });
});
// ===============================
// ❌ CANCEL SUBSCRIPTION
// ===============================
app.post("/api/cancel-subscription", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });

  const { feature } = req.body;
  if (!feature) return res.status(400).json({ error: "Feature required" });

  const db = loadGoldenDB();
  const id = `${req.user.id}@${req.user.provider}`;
  const user = db.users[id];
  if (!user || !user.subscriptions) return res.status(404).json({ error: "User or subscription not found" });

  delete user.subscriptions[feature];
  saveGoldenDB(db);
  res.json({ success: true });
});

// ===============================
// 🌐 PUBLIC BALANCE API (For GoldenChatAI)
// ===============================
app.get("/api/user-balance", (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: "Missing email" });

  const db = loadGoldenDB();
  // find user by email (case-insensitive)
  const user = Object.values(db.users || {}).find(
    u => u.email && u.email.toLowerCase() === email.toLowerCase()
  );

  if (!user) {
    return res.json({ balance: 0 });
  }

  res.json({ balance: user.golden_balance || 0 });
});
// ============ HEALTH ============
app.get("/health", (_req, res) => {
  const db = loadGoldenDB();
  res.json({
    status: "OK",
    users: Object.keys(db.users || {}).length,
    familyPlans: Object.keys(db.family_plans || {}).length,
    lastCheck: new Date().toISOString(),
  });
});

// ============ START ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI launched on port ${PORT}`);
  console.log(`✅ Payments auto-sync every 2 minutes`);
});
