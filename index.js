// index.js — GoldenSpaceAI COMPLETE SYSTEM
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
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
//===========connect to supabase============
async function ensureUserInDB(email, name) {
  const { data: existing } = await supabase.from('users').select('*').eq('email', email).single();
  if (!existing) {
    await supabase.from('users').insert([{ email, name, golden_balance: 0 }]);
  }
}
async function addGoldenToUser(email, amount) {
  await supabase.rpc('increment_balance', { user_email: email, amount_to_add: amount });
}
await supabase.from('subscriptions').insert([{
  user_id: userId,
  feature: 'AI access',
  expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
}]);
// ============ ENV & APP ============
dotenv.config();
const app = express();
app.set("trust proxy", 1);

// ============ ENVIRONMENT VALIDATION ============
function validateEnvironment() {
  const required = ['OPENAI_API_KEY', 'SESSION_SECRET'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing);
    process.exit(1);
  }
  
  console.log('✅ Environment variables validated');
}
validateEnvironment();
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
console.log("✅ Supabase connected");
// ============ MIDDLEWARE ============
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// ============ SUPABASE CHAT / PROJECT SYSTEM ============
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
      .order("timestamp", { ascending: false })
      .limit(10);
    if (error) throw error;
    res.json({ success: true, messages: data.reverse() });
  } catch (err) {
    console.error("Chat fetch error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/chat/message", async (req, res) => {
  try {
    const { chat_id, sender, content } = req.body;
    if (!chat_id || !content)
      return res.status(400).json({ error: "Missing chat_id or content" });

    const { error } = await supabase
      .from("messages")
      .insert([{ chat_id, sender, content }]);
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
      .eq("user_id", userId);
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

// ============ SESSION CONFIGURATION ============
const sessionConfig = {
  secret: process.env.SESSION_SECRET || "super-secret-key-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  }
};

app.use(session(sessionConfig));

// ============ PATHS ============
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ============ PASSPORT ============
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// ============ SECURE FILE UPLOAD ============
const upload = multer({
  dest: "uploads/",
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// ============ DB HELPERS ============
const GOLDEN_DB_PATH = "./data/golden_database.json";
const PAYMENT_DB_PATH = "./data/payment_database.json";

const dataDir = path.dirname(GOLDEN_DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
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
      return raw.trim() ? JSON.parse(raw) : { transactions: {}, user_packages: {}, nowpayments_orders: {} };
    }
  } catch (e) {
    console.error("Payment DB error:", e);
  }
  return { transactions: {}, user_packages: {}, nowpayments_orders: {} };
}

function savePaymentDB(data) {
  try {
    fs.writeFileSync(PAYMENT_DB_PATH, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error("Payment DB save error:", e);
  }
}

// ============ HELPER FUNCTIONS ============
function getUserIdentifier(req) {
  return req.user ? `${req.user.id}@${req.user.provider}` : null;
}

function getUserGoldenBalance(userId) {
  const db = loadGoldenDB();
  return db.users[userId]?.golden_balance || 0;
}

// ============ AUTO GOLDEN FOR SPECIFIC EMAIL ============
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
        type: "auto_bonus", amount: 100000, previous_balance: 0, new_balance: 100000,
        reason: "Automatic 100K Golden for admin", timestamp: new Date().toISOString(),
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
          type: "auto_fix", amount: 100000 - previousBalance, previous_balance: previousBalance,
          new_balance: 100000, reason: "Auto-corrected to 100K Golden", timestamp: new Date().toISOString(),
        });
        console.log(`🔄 Auto-corrected balance to 100,000G for ${user.email}`);
      }
    }
    db.users[id].last_login = new Date().toISOString();
    saveGoldenDB(db);
  }
}

// ============ ADMIN AUTH MIDDLEWARE ============
function requireAdminAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  
  const userId = getUserIdentifier(req);
  const adminUsers = ["118187920786158036693@google", process.env.ADMIN_USER_ID];
  const isAdmin = adminUsers.includes(userId) || req.user.email === "farisalmhamad3@gmail.com";
  
  if (!isAdmin) {
    console.log(`🚫 Admin access denied for: ${req.user.email}`);
    return res.status(403).json({ error: "Admin access required" });
  }
  
  console.log(`✅ Admin access granted to: ${req.user.email}`);
  next();
}

// ============ GOLDEN SYSTEM CONFIG ============
const GOLDEN_PACKAGES = {
  60: { priceUSD: 15 },
  100: { priceUSD: 20 },
  200: { priceUSD: 40 },
};

const FEATURE_PRICES = {
  search_info: 4, homework_helper: 20, chat_advancedai: 20,
  create_rocket: 4, create_satellite: 4, advanced_planet: 4,
  your_space: 4, learn_physics: 4, create_planet: 4, search_lessons: 10,
};

function requireFeature(feature) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    
    const db = loadGoldenDB();
    const userId = getUserIdentifier(req);
    const user = db.users[userId];
    if (!user) return res.status(404).json({ error: "User not found" });
    
    const subscription = user.subscriptions?.[feature];
    if (subscription && new Date(subscription) > new Date()) return next();
    
    const price = FEATURE_PRICES[feature];
    if (!price) return res.status(400).json({ error: "Invalid feature" });
    
    return res.status(403).json({ 
      error: "Feature locked", message: `This feature requires ${price} Golden`,
      requiredGolden: price, userBalance: user.golden_balance || 0
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
// ============ ADVANCED AI INTEGRATION (No extra billing logic) ============

// Subscribe user to Plus or Pro
app.post("/api/subscribe-advanced-ai", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { plan } = req.body;
  if (!["plus", "pro"].includes(plan)) return res.status(400).json({ error: "Invalid plan" });

  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];
  if (!user) return res.status(404).json({ error: "User not found" });

  // Only tag the subscription — Golden deduction handled elsewhere
  const now = new Date();
  const expiry = new Date(now);
  expiry.setMonth(now.getMonth() + 1);

  user.subscriptions = user.subscriptions || {};
  user.subscriptions.chat_advancedai = expiry.toISOString();
  user.subscriptions.chat_advancedai_plan = plan;

  saveGoldenDB(db);

  res.json({
    success: true,
    subscription: { plan, expires_at: expiry.toISOString() },
    newBalance: user.golden_balance || 0
  });
});

// Return current Advanced AI status
app.get("/api/advanced-ai-status", (req, res) => {
  if (!req.user) return res.json({ active: false, loggedIn: false });

  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];
  if (!user) return res.json({ active: false, loggedIn: true });

  const now = new Date();
  const expiry = user.subscriptions?.chat_advancedai;
  const plan = user.subscriptions?.chat_advancedai_plan;

  const active = expiry && new Date(expiry) > now;
  res.json({
    active,
    plan: active ? plan : null,
    expires_at: expiry || null,
    balance: user.golden_balance || 0
  });
});
// ============ AUTH ============
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  const siteUrl = "https://goldenspaceai.space";
  
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${siteUrl}/auth/google/callback`,
    proxy: true
  }, (_accessToken, _refreshToken, profile, done) => {
    const user = { 
      id: profile.id, 
      name: profile.displayName, 
      email: profile.emails?.[0]?.value || "", 
      photo: profile.photos?.[0]?.value || "", 
      provider: "google" 
    };
    ensureUserExists(user); 
    done(null, user);
  }));
  
  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  app.get("/auth/google/callback", passport.authenticate("google", { 
    failureRedirect: "/login-signup.html" 
  }), (_req, res) => res.redirect("/"));
}

if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  const siteUrl = "https://goldenspaceai.space";
  
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${siteUrl}/auth/github/callback`,
    proxy: true
  }, (_accessToken, _refreshToken, profile, done) => {
    const user = { 
      id: profile.id, 
      name: profile.displayName || profile.username, 
      email: profile.emails?.[0]?.value || `${profile.username}@github.user`, 
      photo: profile.photos?.[0]?.value || "", 
      username: profile.username, 
      provider: "github" 
    };
    ensureUserExists(user); 
    done(null, user);
  }));
  
  app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
  app.get("/auth/github/callback", passport.authenticate("github", { 
    failureRedirect: "/login-signup.html" 
  }), (_req, res) => res.redirect("/"));
}

// ============ BASIC ROUTES ============
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.get("/login", (_req, res) => res.sendFile(path.join(__dirname, "login-signup.html")));
app.get("/:page.html", (req, res) => {
  const page = req.params.page;
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

// ============ USER / ME ============
app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  const id = `${req.user.id}@${req.user.provider}`;
  const db = loadGoldenDB();
  const userData = db.users[id];
  if (!userData) { ensureUserExists(req.user); return res.json({ loggedIn: true, user: req.user, balance: 0 }); }
  res.json({ loggedIn: true, user: req.user, balance: userData.golden_balance || 0, subscriptions: userData.subscriptions || {} });
});

// ============ GOLDEN PUBLIC APIS ============
app.get("/api/golden-balance", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false, balance: 0 });
  const b = getUserGoldenBalance(getUserIdentifier(req));
  res.json({ loggedIn: true, balance: b, user: req.user });
});

app.get("/api/golden-packages", (_req, res) => res.json(GOLDEN_PACKAGES));

// ============ FEATURE MANAGEMENT ============
app.post("/api/unlock-feature", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature, cost } = req.body;
  if (!feature || FEATURE_PRICES[feature] !== cost) return res.status(400).json({ error: "Invalid feature or cost" });
  
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];
  if (!u) return res.status(404).json({ error: "User not found" });
  
  if (req.user.email !== "farisalmhamad3@gmail.com") {
    if ((u.golden_balance || 0) < cost) return res.status(400).json({ error: "Not enough Golden" });
    u.golden_balance -= cost;
    u.total_golden_spent = (u.total_golden_spent || 0) + cost;
  }
  
  const exp = new Date(); exp.setDate(exp.getDate() + 30);
  u.subscriptions = u.subscriptions || {};
  u.subscriptions[feature] = exp.toISOString();
  u.transactions = u.transactions || [];
  u.transactions.push({ type: "unlock", amount: req.user.email === "farisalmhamad3@gmail.com" ? 0 : -cost, feature, timestamp: new Date().toISOString() });

  saveGoldenDB(db);
  res.json({ success: true, newBalance: u.golden_balance, freeUnlock: req.user.email === "farisalmhamad3@gmail.com" });
});

app.get("/api/feature-status", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature } = req.query;
  if (!feature || !FEATURE_PRICES[feature]) return res.status(400).json({ error: "Invalid feature" });
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];
  if (!u?.subscriptions?.[feature]) return res.json({ feature, unlocked: false, price: FEATURE_PRICES[feature] });
  const expiry = new Date(u.subscriptions[feature]);
  if (expiry <= new Date()) { delete u.subscriptions[feature]; saveGoldenDB(db); return res.json({ feature, unlocked: false, price: FEATURE_PRICES[feature] }); }
  const remainingHours = Math.max(0, Math.floor((expiry - new Date()) / (1000 * 60 * 60)));
  res.json({ feature, unlocked: true, remainingHours, price: FEATURE_PRICES[feature] });
});

// ============ GOLDEN TRANSFER SYSTEM ============
app.post("/api/transfer-golden", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    const { recipientEmail, amount } = req.body;
    if (!recipientEmail || !amount || amount <= 0) return res.status(400).json({ error: "Valid recipient email and amount required" });

    const db = loadGoldenDB();
    const senderId = getUserIdentifier(req);
    const sender = db.users[senderId];
    if (!sender) return res.status(404).json({ error: "Sender account not found" });

    const fee = Math.ceil(amount * 0.05);
    const totalDeduction = amount + fee;
    if (sender.golden_balance < totalDeduction) return res.status(400).json({ error: `Insufficient balance. Need ${totalDeduction}G (${amount}G + ${fee}G fee), but only have ${sender.golden_balance}G` });

    let recipient = null, recipientId = null;
    for (const [userId, user] of Object.entries(db.users)) {
      if (user.email && user.email.toLowerCase() === recipientEmail.toLowerCase()) { recipient = user; recipientId = userId; break; }
    }
    if (!recipient) return res.status(404).json({ error: "Recipient not found" });
    if (recipientId === senderId) return res.status(400).json({ error: "Cannot transfer Golden to yourself" });

    const previousSenderBalance = sender.golden_balance;
    const previousRecipientBalance = recipient.golden_balance;
    sender.golden_balance -= totalDeduction;
    sender.total_golden_spent = (sender.total_golden_spent || 0) + totalDeduction;
    recipient.golden_balance += amount;
    recipient.total_golden_earned = (recipient.total_golden_earned || 0) + amount;

    sender.transactions = sender.transactions || [];
    sender.transactions.push({ type: "transfer_out", amount: -totalDeduction, previous_balance: previousSenderBalance, new_balance: sender.golden_balance, recipient: recipientEmail, fee, net_amount: amount, timestamp: new Date().toISOString() });

    recipient.transactions = recipient.transactions || [];
    recipient.transactions.push({ type: "transfer_in", amount, previous_balance: previousRecipientBalance, new_balance: recipient.golden_balance, sender: sender.email, timestamp: new Date().toISOString() });

    saveGoldenDB(db);
    console.log(`✅ Golden transfer: ${sender.email} → ${recipient.email} | Amount: ${amount}G | Fee: ${fee}G`);

    res.json({ success: true, message: `Successfully transferred ${amount}G to ${recipientEmail} (${fee}G fee applied)`, newBalance: sender.golden_balance, fee, totalDeduction });

  } catch (error) {
    console.error("Transfer Golden error:", error);
    res.status(500).json({ error: "Transfer failed due to server error", details: error.message });
  }
});
//=========================================================
// ============ SUBSCRIPTION MANAGEMENT ====================
app.get("/subscriptions.html", (req, res) =>
  res.sendFile(path.join(__dirname, "subscriptions.html"))
);

// ✅ unified route name so frontend /api/subscriptions works
app.get("/api/subscriptions", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });

  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];
  if (!user)
    return res.status(404).json({ error: "User not found" });

  const now = new Date();
  const subscriptions = Object.entries(user.subscriptions || {}).map(
    ([feature, expiry]) => {
      const exp = new Date(expiry);
      const active = exp > now;
      const daysLeft = Math.max(
        0,
        Math.ceil((exp - now) / (1000 * 60 * 60 * 24))
      );
      return {
        feature,
        cost: FEATURE_PRICES[feature] || 0,
        expiry,
        active,
        daysLeft,
        expired: !active
      };
    }
  );

  res.json({
    success: true,
    subscriptions,
    balance: user.golden_balance || 0
  });
});

// ✅ cancel subscription route unchanged but clarified
app.post("/api/cancel-subscription", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });

  const { feature } = req.body;
  if (!feature)
    return res.status(400).json({ error: "Feature required" });

  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];

  if (!user || !user.subscriptions)
    return res
      .status(404)
      .json({ error: "User or subscription not found" });

  delete user.subscriptions[feature];
  saveGoldenDB(db);

  res.json({
    success: true,
    message: `Subscription for ${feature} cancelled`
  });
});

// ============ ADMIN ROUTES =================
app.get("/admin-page-golden.html", (req, res) =>
  res.sendFile(path.join(__dirname, "admin-page-golden.html"))
);

// 🧾 Fetch all users with totals
app.get("/api/admin/all-users", requireAdminAuth, (_req, res) => {
  const db = loadGoldenDB();
  const users = Object.entries(db.users || {}).map(([userId, u]) => ({
    userId,
    name: u.name,
    email: u.email,
    golden_balance: u.golden_balance || 0,
    total_golden_earned: u.total_golden_earned || 0,
    total_golden_spent: u.total_golden_spent || 0,
    created_at: u.created_at,
    last_login: u.last_login,
    provider: userId.split("@")[1],
  }));

  users.sort((a, b) => b.golden_balance - a.golden_balance);
  const totalGolden = users.reduce((s, u) => s + (u.golden_balance || 0), 0);

  res.json({
    success: true,
    users,
    totalUsers: users.length,
    totalGolden,
  });
});

// 🔍 Search for specific user
app.get("/api/admin/search-users", requireAdminAuth, (req, res) => {
  const q = (req.query.query || "").toLowerCase();
  const db = loadGoldenDB();

  const results = Object.entries(db.users || {})
    .filter(([id, u]) =>
      id.toLowerCase().includes(q) ||
      (u.email && u.email.toLowerCase().includes(q)) ||
      (u.name && u.name.toLowerCase().includes(q))
    )
    .map(([userId, u]) => ({
      userId,
      name: u.name,
      email: u.email,
      golden_balance: u.golden_balance || 0,
      total_golden_earned: u.total_golden_earned || 0,
      total_golden_spent: u.total_golden_spent || 0,
      created_at: u.created_at,
      last_login: u.last_login,
      provider: userId.split("@")[1],
    }));

  res.json({ success: true, users: results });
});

// ➕ Add Golden
app.post("/api/admin/add-golden", requireAdminAuth, (req, res) => {
  const { userId, amount, reason } = req.body;
  const amt = Number(amount);
  if (!userId || isNaN(amt) || amt <= 0)
    return res.status(400).json({ error: "Valid user ID and positive amount required" });

  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  const prev = u.golden_balance || 0;
  u.golden_balance = prev + amt;
  u.total_golden_earned = (u.total_golden_earned || 0) + amt;

  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "admin_add",
    amount: amt,
    previous_balance: prev,
    new_balance: u.golden_balance,
    reason: reason || "Admin adjustment",
    timestamp: new Date().toISOString(),
  });

  saveGoldenDB(db);
  res.json({
    success: true,
    message: `Added ${amt}G to ${u.email}`,
    newBalance: u.golden_balance,
  });
});

// ➖ Subtract Golden
app.post("/api/admin/subtract-golden", requireAdminAuth, (req, res) => {
  const { userId, amount, reason } = req.body;
  const amt = Number(amount);
  if (!userId || isNaN(amt) || amt <= 0)
    return res.status(400).json({ error: "Valid user ID and positive amount required" });

  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  const prev = u.golden_balance || 0;
  if (prev < amt)
    return res.status(400).json({ error: "Insufficient balance" });

  u.golden_balance = prev - amt;
  u.total_golden_spent = (u.total_golden_spent || 0) + amt;

  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "admin_subtract",
    amount: -amt,
    previous_balance: prev,
    new_balance: u.golden_balance,
    reason: reason || "Admin adjustment",
    timestamp: new Date().toISOString(),
  });

  saveGoldenDB(db);
  res.json({
    success: true,
    message: `Subtracted ${amt}G from ${u.email}`,
    newBalance: u.golden_balance,
  });
});

// ⚖️ Set Golden balance directly
app.post("/api/admin/set-golden", requireAdminAuth, (req, res) => {
  const { userId, balance, reason } = req.body;
  const newBal = Number(balance);
  if (!userId || isNaN(newBal) || newBal < 0)
    return res.status(400).json({ error: "Valid user ID and non-negative balance required" });

  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  const prev = u.golden_balance || 0;
  u.golden_balance = newBal;

  u.transactions = u.transactions || [];
  u.transactions.push({
    type: "admin_set",
    amount: newBal - prev,
    previous_balance: prev,
    new_balance: newBal,
    reason: reason || "Admin set balance",
    timestamp: new Date().toISOString(),
  });

  saveGoldenDB(db);
  res.json({
    success: true,
    message: `Set balance to ${newBal}G for ${u.email}`,
    newBalance: u.golden_balance,
  });
});

// 📜 User transaction history
app.get("/api/admin/user-transactions/:userId", requireAdminAuth, (req, res) => {
  const { userId } = req.params;
  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u)
    return res.status(404).json({ error: "User not found" });

  res.json({ success: true, transactions: u.transactions || [] });
});


// ======================== AI ENDPOINTS =====================
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Free Chat AI
app.post("/chat-free-ai", async (req, res) => {
  try {
    const prompt = req.body.q || req.body.question || "Hello!";
    const model = req.body.model || "gpt-4o-mini";
    const messages = [{ role: "system", content: "You are GoldenSpaceAI's helpful chat assistant." }, { role: "user", content: prompt }];
    const completion = await openai.chat.completions.create({ model, messages, max_tokens: 1200, temperature: 0.7 });
    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });
  } catch (e) {
    console.error("Free AI error:", e);
    res.status(500).json({ error: e.message });
  }
});
// ========== ADVANCED CHAT AI (Supabase + Golden Integration) ==========
app.post("/chat-advanced-ai", requireFeature("chat_advancedai"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    const userId = req.user ? getUserIdentifier(req) : null;
    if (!userId) return res.status(401).json({ error: "Login required" });

    const db = loadGoldenDB();
    const user = db.users[userId];
    if (!user) return res.status(404).json({ error: "User not found" });

    const { model: requestedModel, q: prompt, project_id } = req.body;
    if (!prompt) return res.status(400).json({ error: "Missing prompt" });

    // 🔐 Step 1: Check subscription plan
    const plan = user.subscriptions?.chat_advancedai_plan || "free";
    const expiry = user.subscriptions?.chat_advancedai_expiry;
    const now = new Date();
    if (!expiry || new Date(expiry) < now) {
      return res.status(403).json({ error: "Subscription expired" });
    }

    let model = "gpt-4o-mini";
    let imageLimit = 0;
    if (plan === "plus") {
      model = requestedModel === "gpt-5-nano" ? "gpt-5-nano" : "gpt-4o-mini";
      imageLimit = 20;
    } else if (plan === "pro") {
      model = requestedModel === "gpt-5" ? "gpt-5" : requestedModel || "gpt-4o";
      imageLimit = Infinity;
    }

    // 🧮 Step 2: Handle image usage limit
    if (requestedModel === "gpt-image-1") {
      const { data: count, error: countErr } = await supabase
        .from("messages")
        .select("id", { count: "exact" })
        .eq("sender", "ai")
        .eq("chat_id", project_id)
        .like("content", "%Image generated:%");

      if (!countErr && count.length >= imageLimit && plan !== "pro") {
        return res.status(403).json({ error: "Image limit reached for this month." });
      }
    }

    // 🧠 Step 3: Load context (last 30 messages)
    const { data: history, error: histErr } = await supabase
      .from("messages")
      .select("sender, content")
      .eq("chat_id", project_id)
      .order("timestamp", { ascending: true })
      .limit(30);

    const contextMessages = !histErr && history?.length
      ? history.map(m => ({
          role: m.sender === "ai" ? "assistant" : "user",
          content: m.content
        }))
      : [];

    // 🧾 Step 4: Add user message (and optional image)
    let newMessage;
    if (filePath) {
      const b64 = fs.readFileSync(filePath).toString("base64");
      const mime = req.file.mimetype || "image/png";
      newMessage = {
        role: "user",
        content: [
          { type: "text", text: prompt },
          { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } }
        ]
      };
    } else {
      newMessage = { role: "user", content: prompt };
    }

    const conversation = [...contextMessages, newMessage];

    // 💾 Step 5: Save user's message
    await supabase.from("messages").insert([
      { chat_id: project_id, sender: userId, content: prompt }
    ]);

    // 🎨 Step 6: Handle image generation
    if (requestedModel === "gpt-image-1") {
      try {
        const img = await openai.images.generate({
          model: "dall-e-3",
          prompt,
          size: "1024x1024",
          n: 1
        });
        const imageUrl = img.data[0].url;

        await supabase.from("messages").insert([
          { chat_id: project_id, sender: "ai", content: `Image generated: ${imageUrl}` }
        ]);

        return res.json({
          reply: `![Generated Image](${imageUrl})`,
          imageUrl,
          model: "dall-e-3"
        });
      } catch (err) {
        console.error("DALL-E error:", err);
        return res.status(500).json({ error: "Image generation failed" });
      }
    }

    // 🤖 Step 7: Get AI reply
    const completion = await openai.chat.completions.create({
      model,
      messages: conversation,
      max_tokens: 2000,
      temperature: 0.7
    });
    const reply = completion.choices?.[0]?.message?.content || "No reply.";

    // 💾 Step 8: Save AI message
    await supabase.from("messages").insert([
      { chat_id: project_id, sender: "ai", content: reply }
    ]);

    // ⚙️ Step 9: Trim to last 30 messages
    const { data: allMsgs } = await supabase
      .from("messages")
      .select("id")
      .eq("chat_id", project_id)
      .order("timestamp", { ascending: false });

    if (allMsgs?.length > 30) {
      const extra = allMsgs.slice(30).map(m => m.id);
      await supabase.from("messages").delete().in("id", extra);
    }

    // 💰 Step 10: Deduct Golden monthly if not done
    const lastPaid = user.subscriptions?.chat_advancedai_lastPaid || null;
    if (!lastPaid || new Date(lastPaid).getMonth() !== now.getMonth()) {
      const cost = plan === "pro" ? 40 : 20;
      if ((user.golden_balance || 0) >= cost) {
        user.golden_balance -= cost;
        user.subscriptions.chat_advancedai_lastPaid = now.toISOString();
        saveGoldenDB(db);
      } else {
        return res.status(402).json({ error: "Insufficient Golden to renew subscription." });
      }
    }

    // ✅ Step 11: Send response
    res.json({ reply, model, plan });

  } catch (e) {
    console.error("Advanced AI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, () => {});
  }
});
// Search Info
app.post("/search-info", async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "system", content: "You are a helpful research assistant. Provide clear, concise, and informative answers. Structure your response with key points and summaries." }, { role: "user", content: query }],
      max_tokens: 1200, temperature: 0.7
    });
    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer: reply });
  } catch (e) {
    console.error("Search info error:", e);
    res.status(500).json({ error: e.message });
  }
});

// Learn Physics
app.post("/learn-physics", async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "system", content: "You are a physics tutor who explains concepts clearly and simply. Break down complex topics into understandable parts." }, { role: "user", content: question }],
      max_tokens: 1200, temperature: 0.7
    });
    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ success: true, answer: reply });
  } catch (err) {
    console.error("Physics AI error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Homework Helper
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
      { role: "user", content: [{ type: "text", text: prompt }, { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } }] },
    ];

    const completion = await openai.chat.completions.create({ model, messages, max_tokens: 1400, temperature: 0.4 });
    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });
  } catch (e) {
    console.error("Homework AI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, (err) => { if (err) console.error("File cleanup error:", err); });
  }
});

// Live Chat Processing
app.post("/live-chat-process", async (req, res) => {
  try {
    const { message, conversation, model = "gpt-5-nano" } = req.body;
    if (!message) return res.status(400).json({ error: "Message is required" });

    const messages = [
      { role: "system", content: "You are a friendly, conversational AI assistant. Keep responses natural and conversational since users will hear them spoken aloud. Respond in 1-2 sentences maximum for best audio experience." },
      ...conversation,
      { role: "user", content: message }
    ];

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini", messages, max_tokens: 150, temperature: 0.7,
    });

    const reply = completion.choices[0]?.message?.content || "I didn't get that. Could you repeat?";
    res.json({ success: true, reply, model, tokens_used: completion.usage?.total_tokens || 0 });

  } catch (error) {
    console.error("Live chat error:", error);
    res.status(500).json({ error: error.message });
  }
});
//=========price-check===============
app.get("/api/crypto-prices", async (req, res) => {
  try {
    const response = await axios.get("https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,tether,usd-coin,binancecoin,tron,solana,dogecoin&vs_currencies=usd");
    res.json(response.data);
  } catch (error) {
    console.error("Crypto price fetch error:", error.message);
    res.status(500).json({ error: "Failed to fetch prices" });
  }
});
//===================file naming==========
app.get("/success", (req, res) => {
  res.sendFile(path.join(__dirname, "success.html"));
});

app.get("/plans", (req, res) => {
  res.sendFile(path.join(__dirname, "plans.html"));
});

app.get("/FreeAI", (req, res) => {
  res.sendFile(path.join(__dirname, "chat-free-ai.html"));
});

app.get("/advancedAI", (req, res) => {
  res.sendFile(path.join(__dirname, "chat-advancedai.html"));
});

app.get("/homework-helper", (req, res) => {
  res.sendFile(path.join(__dirname, "homework-helper.html"));
});

app.get("/search-info", (req, res) => {
  res.sendFile(path.join(__dirname, "search-info.html"));
});

app.get("/create-your-universe", (req, res) => {
  res.sendFile(path.join(__dirname, "your-space.html"));
});

app.get("/search-educational-lessons", (req, res) => {
  res.sendFile(path.join(__dirname, "search-lessons.html"));
});

app.get("/create-your-rocket", (req, res) => {
  res.sendFile(path.join(__dirname, "create-rocket.html"));
});

app.get("/payment-cancel", (req, res) => {
  res.sendFile(path.join(__dirname, "plans.html"));
});

app.get("/create-satellite", (req, res) => {
  res.sendFile(path.join(__dirname, "create-satellite.html"));
});

app.get("/create-planet", (req, res) => {
  res.sendFile(path.join(__dirname, "create-planet.html"));
});

app.get("/create-advanced-planet", (req, res) => {
  res.sendFile(path.join(__dirname, "create-advanced-planet.html"));
});

app.get("/privacy-policy", (req, res) => {
  res.sendFile(path.join(__dirname, "privacy.html"));
});

app.get("/terms-of-service", (req, res) => {
  res.sendFile(path.join(__dirname, "terms.html"));
});

app.get("/refund-policy", (req, res) => {
  res.sendFile(path.join(__dirname, "refund.html"));
});

app.get("/contact-page", (req, res) => {
  res.sendFile(path.join(__dirname, "contact.html"));
});

app.get("/about-us-page", (req, res) => {
  res.sendFile(path.join(__dirname, "about-us.html"));
});
// ============ HEALTH ============
app.get("/health", (_req, res) => {
  const db = loadGoldenDB();
  res.json({ status: "OK", users: Object.keys(db.users || {}).length, lastCheck: new Date().toISOString() });
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ============ START ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 GoldenSpaceAI LAUNCHED on port ${PORT}`);
  console.log(`✅ All systems ready for launch!`);
  console.log(`💰 Golden packages: 60G/$15, 100G/$20, 200G/$40`);
  console.log(`🎨 DALL-E 3 Image generation: Ready`);
  console.log(`🎉 Special account: farisalmhamad3@gmail.com → 100,000G`);
  console.log(`🌐 Domain: goldenspaceai.space`);
  console.log(`🚀 Ready for production!`);
});
