// index.js — GoldenSpaceAI COMPLETE SYSTEM - OPTIMIZED FOR RENDER
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

// Render-specific configuration
app.set("trust proxy", 1); // Trust Render's proxy

// ============ ENVIRONMENT VALIDATION ============
function validateEnvironment() {
  const required = ['OPENAI_API_KEY', 'SESSION_SECRET'];
  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing);
    console.error('Please check your Render environment variables');
    // Don't exit on Render, just warn
  }
  
  console.log('✅ Environment check complete');
  console.log('🔑 NOWPayments API Key:', process.env.NOWPAYMENTS_API_KEY ? 'Set' : 'Missing');
}
validateEnvironment();

// ============ MIDDLEWARE ============
app.use(cors({ 
  origin: true, 
  credentials: true 
}));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ============ SESSION CONFIGURATION FOR RENDER ============
const sessionConfig = {
  secret: process.env.SESSION_SECRET || "render-session-secret-change-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7,
  }
};

// On Render, we need to handle the fact that it uses reverse proxy
if (process.env.NODE_ENV === 'production') {
  sessionConfig.proxy = true; // Trust Render's proxy
  console.log('🔒 Production mode: Secure cookies enabled');
}

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

// Ensure data directory exists
const dataDir = path.dirname(GOLDEN_DB_PATH);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
  console.log('📁 Created data directory');
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

// Create Golden purchase - RENDER OPTIMIZED
app.post("/api/nowpayments/create-golden", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    
    const { packageSize } = req.body;
    const packageInfo = GOLDEN_PACKAGES[packageSize];
    if (!packageInfo) return res.status(400).json({ error: "Invalid package size" });

    // Get the actual Render URL for webhooks
    const renderUrl = process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
    const amountUSD = packageInfo.priceUSD;
    const orderId = `golden-${req.user.id}-${packageSize}-${Date.now()}`;
    
    const payload = {
      price_amount: amountUSD,
      price_currency: "usd",
      pay_currency: "usdt",
      order_id: orderId,
      order_description: `GoldenSpaceAI ${packageSize} Golden Package`,
      ipn_callback_url: `${renderUrl}/api/nowpay/webhook`,
      success_url: `${renderUrl}/success.html`,
      cancel_url: `${renderUrl}/plans.html`
    };

    console.log('💰 Creating NOWPayments order:', payload);

    const response = await axios.post(`${NOWPAYMENTS_API}/payment`, payload, {
      headers: { "x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json" },
      timeout: 30000
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
    res.status(500).json({ 
      error: "Payment creation failed", 
      details: error.response?.data || error.message 
    });
  }
});

// WEBHOOK ENDPOINT - RENDER OPTIMIZED
app.post("/api/nowpay/webhook", express.json(), async (req, res) => {
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
    if (!NOWPAYMENTS_API_KEY) {
      return res.json({ 
        error: 'NOWPAYMENTS_API_KEY not set in Render environment variables',
        setupInstructions: 'Add NOWPAYMENTS_API_KEY to your Render environment variables'
      });
    }

    const testResponse = await axios.get(`${NOWPAYMENTS_API}/status`, {
      headers: { "x-api-key": NOWPAYMENTS_API_KEY },
      timeout: 10000
    });

    res.json({ 
      apiKey: 'Set ✅', 
      apiStatus: testResponse.data, 
      apiUrl: NOWPAYMENTS_API, 
      message: 'NOWPayments API working',
      renderUrl: process.env.RENDER_EXTERNAL_URL
    });

  } catch (error) {
    res.json({ 
      error: 'NOWPayments API test failed', 
      details: error.response?.data || error.message, 
      apiKey: NOWPAYMENTS_API_KEY ? 'Set' : 'Missing' 
    });
  }
});

// ============ AUTH ============
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  const renderUrl = process.env.RENDER_EXTERNAL_URL || "https://goldenspaceai.space";
  
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${renderUrl}/auth/google/callback`,
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
  const renderUrl = process.env.RENDER_EXTERNAL_URL || "https://your-app-name.onrender.com";
  
  passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: `${renderUrl}/auth/github/callback`,
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
  if (!userData) { 
    ensureUserExists(req.user); 
    return res.json({ loggedIn: true, user: req.user, balance: 0 }); 
  }
  res.json({ 
    loggedIn: true, 
    user: req.user, 
    balance: userData.golden_balance || 0, 
    subscriptions: userData.subscriptions || {} 
  });
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
  
  const exp = new Date(); 
  exp.setDate(exp.getDate() + 30);
  u.subscriptions = u.subscriptions || {};
  u.subscriptions[feature] = exp.toISOString();
  u.transactions = u.transactions || [];
  u.transactions.push({ 
    type: "unlock", 
    amount: req.user.email === "farisalmhamad3@gmail.com" ? 0 : -cost, 
    feature, 
    timestamp: new Date().toISOString() 
  });

  saveGoldenDB(db);
  res.json({ 
    success: true, 
    newBalance: u.golden_balance, 
    freeUnlock: req.user.email === "farisalmhamad3@gmail.com" 
  });
});

// ... (rest of your AI endpoints remain the same - they should work fine on Render)

// ============ HEALTH CHECK FOR RENDER ============
app.get("/health", (_req, res) => {
  const db = loadGoldenDB();
  res.json({ 
    status: "OK", 
    users: Object.keys(db.users || {}).length, 
    lastCheck: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    renderUrl: process.env.RENDER_EXTERNAL_URL || 'not-set'
  });
});

// ============ ERROR HANDLING ============
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

app.use((req, res) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// ============ START SERVER ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 GoldenSpaceAI LAUNCHED on Render - Port ${PORT}`);
  console.log(`✅ All systems ready for production!`);
  console.log(`💰 Golden packages: 60G/$15, 100G/$20, 200G/$40`);
  console.log(`🔑 NOWPayments: ${NOWPAYMENTS_API_KEY ? 'Configured' : 'NOT SETUP'}`);
  console.log(`🌐 Render URL: ${process.env.RENDER_EXTERNAL_URL || 'Not set'}`);
  console.log(`🚀 Ready for production!`);
});
