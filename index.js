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

// ============ MIDDLEWARE ============
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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

// ============ NOWPAYMENTS INTEGRATION ============
const NOWPAYMENTS_API = "https://api.nowpayments.io/v1";
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY;

// Create Golden purchase
app.post("/api/nowpayments/create-golden", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    
    const { packageSize } = req.body;
    const packageInfo = GOLDEN_PACKAGES[packageSize];
    if (!packageInfo) return res.status(400).json({ error: "Invalid package size" });

    const siteUrl = "https://goldenspaceai.space";
    const amountUSD = packageInfo.priceUSD;
    const orderId = `golden-${req.user.id}-${packageSize}-${Date.now()}`;

    const payload = {
      price_amount: amountUSD,
      price_currency: "usd",
      pay_currency: "usdt",
      order_id: orderId,
      order_description: `GoldenSpaceAI ${packageSize} Golden Package`,
      ipn_callback_url: `${siteUrl}/api/nowpay/webhook`,
      success_url: `${siteUrl}/success.html`,
      cancel_url: `${siteUrl}/plans.html`
    };

    const response = await axios.post(`${NOWPAYMENTS_API}/payment`, payload, {
      headers: { "x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json" },
    });

    const payDB = loadPaymentDB();
    payDB.nowpayments_orders = payDB.nowpayments_orders || {};
    payDB.nowpayments_orders[orderId] = {
      user: getUserIdentifier(req),
      packageSize: parseInt(packageSize),
      amountUSD,
      status: "pending",
      paymentId: response.data.payment_id,
      invoiceUrl: response.data.invoice_url,
      payAddress: response.data.pay_address,
      createdAt: new Date().toISOString()
    };
    savePaymentDB(payDB);

    res.json({
      success: true,
      paymentId: response.data.payment_id,
      invoiceUrl: response.data.invoice_url,
      payAddress: response.data.pay_address,
      orderId, amountUSD, goldenAmount: packageSize
    });

  } catch (error) {
    console.error("NOWPayments error:", error.response?.data || error.message);
    res.status(500).json({ error: "Payment creation failed", details: error.response?.data || error.message });
  }
});

// WEBHOOK ENDPOINT - AUTOMATIC GOLDEN ADDITION
app.post("/api/nowpay/webhook", async (req, res) => {
  try {
    const event = req.body;
    console.log("💰 NOWPayments Webhook Received:", event);

    const orderId = event.order_id;
    const payDB = loadPaymentDB();
    const goldDB = loadGoldenDB();

    const order = payDB.nowpayments_orders[orderId];
    if (!order) {
      console.log("❌ Order not found:", orderId);
      return res.status(404).json({ error: "Order not found" });
    }

    if (event.payment_status === "finished" || event.payment_status === "confirmed") {
      order.status = "completed";
      order.confirmedAt = new Date().toISOString();
      order.transactionHash = event.payin_hash;

      const userId = order.user;
      const user = goldDB.users[userId];
      const goldenAmount = order.packageSize;
      
      if (user) {
        const previousBalance = user.golden_balance || 0;
        user.golden_balance = previousBalance + goldenAmount;
        user.total_golden_earned = (user.total_golden_earned || 0) + goldenAmount;
        
        user.transactions = user.transactions || [];
        user.transactions.push({
          type: "purchase", amount: goldenAmount, previous_balance: previousBalance,
          new_balance: user.golden_balance, package: `${goldenAmount} Golden`,
          usdAmount: order.amountUSD, paymentMethod: "NOWPayments", timestamp: new Date().toISOString()
        });

        console.log(`✅ Golden AUTO-ADDED: ${userId} +${goldenAmount}G`);
      }

      savePaymentDB(payDB);
      saveGoldenDB(goldDB);
    } else if (event.payment_status === "failed") {
      order.status = "failed";
      savePaymentDB(payDB);
    }

    res.json({ ok: true });

  } catch (error) {
    console.error("NOWPayments webhook error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Payment status check
app.get("/api/nowpayments/status/:orderId", async (req, res) => {
  try {
    const { orderId } = req.params;
    const payDB = loadPaymentDB();
    const order = payDB.nowpayments_orders[orderId];

    if (!order) return res.status(404).json({ error: "Order not found" });

    res.json({ orderId, status: order.status, packageSize: order.packageSize, amountUSD: order.amountUSD });

  } catch (error) {
    console.error("Status check error:", error);
    res.status(500).json({ error: error.message });
  }
});

// NOWPayments debug endpoint
app.get('/api/nowpayments/debug', async (req, res) => {
  try {
    if (!NOWPAYMENTS_API_KEY) return res.json({ error: 'NOWPAYMENTS_API_KEY not set' });

    const testResponse = await axios.get(`${NOWPAYMENTS_API}/status`, {
      headers: { "x-api-key": NOWPAYMENTS_API_KEY }
    });

    res.json({ apiKey: 'Set ✅', apiStatus: testResponse.data, apiUrl: NOWPAYMENTS_API, message: 'NOWPayments API working' });

  } catch (error) {
    res.json({ error: 'NOWPayments API test failed', details: error.response?.data || error.message, apiKey: NOWPAYMENTS_API_KEY ? 'Set' : 'Missing' });
  }
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

// ============ SUBSCRIPTION MANAGEMENT ============
app.get("/subscriptions.html", (req, res) => res.sendFile(path.join(__dirname, "subscriptions.html")));

app.get("/api/user-subscriptions", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];
  if (!user) return res.status(404).json({ error: "User not found" });

  const now = new Date();
  const subscriptions = Object.entries(user.subscriptions || {}).map(([feature, expiry]) => {
    const exp = new Date(expiry);
    const active = exp > now;
    const daysLeft = Math.max(0, Math.ceil((exp - now) / (1000 * 60 * 60 * 24)));
    return { feature, cost: FEATURE_PRICES[feature] || 0, expiry, active, daysLeft, expired: !active };
  });

  res.json({ success: true, subscriptions, balance: user.golden_balance || 0 });
});

app.post("/api/cancel-subscription", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature } = req.body;
  if (!feature) return res.status(400).json({ error: "Feature required" });
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const user = db.users[id];
  if (!user || !user.subscriptions) return res.status(404).json({ error: "User or subscription not found" });
  delete user.subscriptions[feature];
  saveGoldenDB(db);
  res.json({ success: true, message: `Subscription for ${feature} cancelled` });
});

// ============ ADMIN ROUTES ============
app.get("/admin-page-golden.html", (req, res) => res.sendFile(path.join(__dirname, "admin-page-golden.html")));

app.get("/api/admin/all-users", requireAdminAuth, (_req, res) => {
  const db = loadGoldenDB();
  const users = [];
  for (const [userId, u] of Object.entries(db.users || {})) {
    users.push({ userId, name: u.name, email: u.email, golden_balance: u.golden_balance || 0, total_golden_earned: u.total_golden_earned || 0, total_golden_spent: u.total_golden_spent || 0, created_at: u.created_at, last_login: u.last_login, provider: userId.split("@")[1] });
  }
  users.sort((a, b) => b.golden_balance - a.golden_balance);
  const totalGolden = users.reduce((s, u) => s + (u.golden_balance || 0), 0);
  res.json({ success: true, users, totalUsers: users.length, totalGolden });
});

app.get("/api/admin/search-users", requireAdminAuth, (req, res) => {
  const q = (req.query.query || "").toLowerCase();
  const db = loadGoldenDB();
  const results = [];
  for (const [userId, u] of Object.entries(db.users || {})) {
    const hit = userId.toLowerCase().includes(q) || (u.email && u.email.toLowerCase().includes(q)) || (u.name && u.name.toLowerCase().includes(q));
    if (hit) results.push({ userId, name: u.name, email: u.email, golden_balance: u.golden_balance || 0, total_golden_earned: u.total_golden_earned || 0, total_golden_spent: u.total_golden_spent || 0, created_at: u.created_at, last_login: u.last_login, provider: userId.split("@")[1] });
  }
  res.json({ success: true, users: results });
});

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
  u.transactions.push({ type: "admin_add", amount: Number(amount), previous_balance: prev, new_balance: u.golden_balance, reason: reason || "Admin adjustment", timestamp: new Date().toISOString() });
  saveGoldenDB(db);
  res.json({ success: true, message: `Added ${amount}G to ${u.email}`, newBalance: u.golden_balance });
});

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
  u.transactions.push({ type: "admin_subtract", amount: -amt, previous_balance: prev, new_balance: u.golden_balance, reason: reason || "Admin adjustment", timestamp: new Date().toISOString() });
  saveGoldenDB(db);
  res.json({ success: true, message: `Subtracted ${amount}G from ${u.email}`, newBalance: u.golden_balance });
});

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
  u.transactions.push({ type: "admin_set", amount: newBal - prev, previous_balance: prev, new_balance: newBal, reason: reason || "Admin set balance", timestamp: new Date().toISOString() });
  saveGoldenDB(db);
  res.json({ success: true, message: `Set balance to ${newBal}G for ${u.email}` });
});

app.get("/api/admin/user-transactions/:userId", requireAdminAuth, (req, res) => {
  const { userId } = req.params;
  const db = loadGoldenDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });
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

// Advanced Chat AI
app.post("/chat-advanced-ai", requireFeature("chat_advancedai"), upload.single("image"), async (req, res) => {
  let filePath = req.file?.path;
  try {
    let model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Answer helpfully.";
    if (model === "instant") model = "gpt-4o-mini";

    // DALL-E 3 Image Generation
    if (model === "gpt-image-1") {
      try {
        const image = await openai.images.generate({ 
          model: "dall-e-3", 
          prompt: prompt,
          size: "1024x1024",
          quality: "standard",
          n: 1
        });
        const imageUrl = image.data[0].url;
        return res.json({ 
          reply: `![Generated Image](${imageUrl})`, 
          imageUrl: imageUrl, 
          model: "dall-e-3" 
        });
      } catch (imgErr) {
        console.error("DALL-E 3 Image generation error:", imgErr);
        return res.status(500).json({ error: imgErr.message || "DALL-E 3 image generation failed." });
      }
    }

    let messages;
    if (filePath) {
      const b64 = fs.readFileSync(filePath).toString("base64");
      const mime = req.file.mimetype || "image/png";
      messages = [{ role: "user", content: [{ type: "text", text: prompt }, { type: "image_url", image_url: { url: `data:${mime};base64,${b64}` } }] }];
    } else {
      messages = [{ role: "user", content: prompt }];
    }

    const completion = await openai.chat.completions.create({ model, messages, max_tokens: 2000, temperature: 0.7 });
    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });

  } catch (e) {
    console.error("Advanced AI error:", e);
    res.status(500).json({ error: e.message });
  } finally {
    if (filePath && fs.existsSync(filePath)) fs.unlink(filePath, (err) => { if (err) console.error("File cleanup error:", err); });
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

// ============ NOWPAYMENTS DEBUG ENDPOINT ============
app.get('/api/nowpayments/test-payment', async (req, res) => {
  try {
    console.log("🧪 Testing NOWPayments payment creation...");
    
    if (!NOWPAYMENTS_API_KEY) {
      return res.json({ error: 'NOWPAYMENTS_API_KEY is missing from .env file' });
    }

    const siteUrl = "https://goldenspaceai.space";
    const testPayload = {
      price_amount: 15,
      price_currency: "usd",
      pay_currency: "usdt", 
      order_id: `test-${Date.now()}`,
      order_description: `Test Payment`,
      ipn_callback_url: `${siteUrl}/api/nowpay/webhook`,
      success_url: `${siteUrl}/success.html`,
      cancel_url: `${siteUrl}/plans.html`
    };

    console.log("📤 Test payload:", testPayload);
    
    let response;
    try {
      response = await axios.post(`${NOWPAYMENTS_API}/payment`, testPayload, {
        headers: { 
          "x-api-key": NOWPAYMENTS_API_KEY,
          "Content-Type": "application/json"
        },
        timeout: 30000
      });
      console.log("✅ NOWPayments test SUCCESS:", response.data);
      res.json({ 
        success: true, 
        message: 'NOWPayments API is working!',
        data: response.data 
      });
      
    } catch (apiError) {
      console.error("❌ NOWPayments test FAILED:", {
        status: apiError.response?.status,
        statusText: apiError.response?.statusText,
        data: apiError.response?.data,
        message: apiError.message
      });
      
      res.json({
        success: false,
        error: 'NOWPayments API request failed',
        status: apiError.response?.status,
        statusText: apiError.response?.statusText,
        data: apiError.response?.data,
        message: apiError.message
      });
    }

  } catch (error) {
    console.error("💥 Test endpoint error:", error);
    res.json({ error: 'Test failed', message: error.message });
  }
});
// Add these routes to your index.js
app.get("/success", (req, res) => {
  res.sendFile(path.join(__dirname, "success.html"));
});

app.get("/plans", (req, res) => {
  res.sendFile(path.join(__dirname, "plans.html"));
});
app.get("/FreeAI", (req, res) => {
  res.sendFile(path.join(__dirname, "chat-free-ai.html"));
});
app.get("/advancedAI", (req, ews =>{
  res.sendFile(path.json(__dirname, "chat-advancedai.html"));
});
app.get("/homework-helper", (req, ews =>{
  res.sendFile(path.json(__dirname, "homework-helper.html"));
});
app.get("search-info", (req, ews =>{
  res.sendFile(path.json(__dirname, "search-info.html"));
});
app.get("/create-your-universe", (req, ews =>{
  res.sendFile(path.json(__dirname, "your-space.html"));
});
app.get("/search-educational-lessons", (req, ews =>{
  res.sendFile(path.json(__dirname, "search-lessons.html"));
});
app.get("/create-your-rocket", (req, ews =>{
  res.sendFile(path.json(__dirname, "create-rocket.html"));
});
app.get("/payment-cancel", (req, res) => {
  res.sendFile(path.join(__dirname, "plans.html"));
});
app.get("/create-satellite", (req, ews =>{
  res.sendFile(path.json(__dirname, "create-satellite.html"));
});
app.get("/create-planet", (req, ews =>{
  res.sendFile(path.json(__dirname, "create-planet.html"));
});
app.get("/create-advanced-planet", (req, ews =>{
  res.sendFile(path.json(__dirname, "create-advanced-planet.html"));
});
app.get("/privacy-policy", (req, ews =>{
  res.sendFile(path.json(__dirname, "privacy.html"));
});
app.get("/terms-of-service", (req, ews =>{
  res.sendFile(path.json(__dirname, "terms.html"));
});
app.get("/refund-policy", (req, ews =>{
  res.sendFile(path.json(__dirname, "refund.html"));
});
app.get("/contact-page", (req, ews =>{
  res.sendFile(path.json(__dirname, "contact.html"));
});
app.get("/about-us-page", (req, ews =>{
  res.sendFile(path.json(__dirname, "about-us.html"));
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
