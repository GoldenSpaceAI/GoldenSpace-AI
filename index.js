// index.js — GoldenSpaceAI COMPLETE SYSTEM (Auth + Golden + NOWPayments + AI)
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

// ============ DB HELPERS (Persistent Storage) ============
const GOLDEN_DB_PATH = "/data/golden_database.json";
const PAYMENT_DB_PATH = "/data/payment_database.json";

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
      return raw.trim() ? JSON.parse(raw) : { transactions: {}, user_packages: {}, nowpayments_orders: {} };
    }
  } catch (e) {
    console.error("Payment DB error:", e);
  }
  return { transactions: {}, user_packages: {}, nowpayments_orders: {} };
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

// ============ GOLDEN SYSTEM CONFIG ============
const GOLDEN_PACKAGES = {
  20: { priceUSD: 5 },    // 20 Golden for $5
  40: { priceUSD: 10 },   // 40 Golden for $10
  100: { priceUSD: 25 },  // 100 Golden for $25
  200: { priceUSD: 50 },  // 200 Golden for $50
  500: { priceUSD: 100 }, // 500 Golden for $100
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

// Feature access middleware
function requireFeature(feature) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Login required" });
    }
    
    const db = loadGoldenDB();
    const userId = getUserIdentifier(req);
    const user = db.users[userId];
    
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    
    // Check if feature is unlocked
    const subscription = user.subscriptions?.[feature];
    if (subscription && new Date(subscription) > new Date()) {
      return next(); // Feature is unlocked
    }
    
    // Check if user has enough Golden to unlock
    const price = FEATURE_PRICES[feature];
    if (!price) {
      return res.status(400).json({ error: "Invalid feature" });
    }
    
    return res.status(403).json({ 
      error: "Feature locked",
      message: `This feature requires ${price} Golden`,
      requiredGolden: price,
      userBalance: user.golden_balance || 0
    });
  };
}

// Keep session user hydrated with Golden balance
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

// Create payment for Golden package
app.post("/api/nowpayments/create-golden", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    
    const { packageSize } = req.body;
    const packageInfo = GOLDEN_PACKAGES[packageSize];
    
    if (!packageInfo) {
      return res.status(400).json({ error: "Invalid package size" });
    }

    const amountUSD = packageInfo.priceUSD;
    const orderId = `golden-${req.user.id}-${packageSize}-${Date.now()}`;
    const callbackUrl = "https://goldenspaceai.space/api/nowpayments/webhook";

    const payload = {
      price_amount: amountUSD,
      price_currency: "USD",
      pay_currency: "usdt", // Users pay with any crypto
      order_id: orderId,
      order_description: `GoldenSpaceAI ${packageSize} Golden Package`,
      ipn_callback_url: callbackUrl,
      success_url: "https://goldenspaceai.space/success.html",
      cancel_url: "https://goldenspaceai.space/plans.html"
    };

    console.log('Creating NOWPayments invoice:', payload);

    const response = await axios.post(`${NOWPAYMENTS_API}/invoice`, payload, {
      headers: { 
        "x-api-key": NOWPAYMENTS_API_KEY,
        "Content-Type": "application/json"
      },
    });

    // Store in payment database
    const payDB = loadPaymentDB();
    payDB.nowpayments_orders = payDB.nowpayments_orders || {};
    payDB.nowpayments_orders[orderId] = {
      user: getUserIdentifier(req),
      packageSize: parseInt(packageSize),
      amountUSD,
      status: "pending",
      paymentId: response.data.id,
      invoiceUrl: response.data.invoice_url,
      createdAt: new Date().toISOString()
    };
    savePaymentDB(payDB);

    res.json({
      success: true,
      paymentId: response.data.id,
      invoiceUrl: response.data.invoice_url,
      orderId,
      amountUSD,
      goldenAmount: packageSize
    });

  } catch (error) {
    console.error("NOWPayments Golden error:", error.response?.data || error.message);
    res.status(500).json({ 
      error: "Payment creation failed",
      details: error.response?.data || error.message 
    });
  }
});

// NOWPayments webhook for payment confirmation
app.post("/api/nowpayments/webhook", async (req, res) => {
  try {
    const secret = req.headers["x-nowpayments-sig"];
    // Note: Set NOWPAYMENTS_WEBHOOK_SECRET in your environment variables
    // if (secret !== process.env.NOWPAYMENTS_WEBHOOK_SECRET) {
    //   return res.status(403).json({ error: "Invalid signature" });
    // }

    const event = req.body;
    console.log("💰 NOWPayments Webhook Received:", event);

    const paymentId = event.payment_id;
    const orderId = event.order_id;

    // Load databases
    const payDB = loadPaymentDB();
    const goldDB = loadGoldenDB();

    const order = payDB.nowpayments_orders[orderId];
    if (!order) {
      console.log("Order not found:", orderId);
      return res.status(404).json({ error: "Order not found" });
    }

    // Handle payment confirmation
    if (event.payment_status === "finished" || event.payment_status === "confirmed") {
      // PAYMENT SUCCESSFUL - ADD GOLDEN TO USER
      order.status = "completed";
      order.confirmedAt = new Date().toISOString();
      order.transactionHash = event.payin_hash;

      const userId = order.user;
      const user = goldDB.users[userId];
      const goldenAmount = order.packageSize;
      
      if (user) {
        // Add Golden to user balance
        const previousBalance = user.golden_balance || 0;
        user.golden_balance = previousBalance + goldenAmount;
        user.total_golden_earned = (user.total_golden_earned || 0) + goldenAmount;
        
        // Add transaction record
        user.transactions = user.transactions || [];
        user.transactions.push({
          type: "purchase",
          amount: goldenAmount,
          previous_balance: previousBalance,
          new_balance: user.golden_balance,
          package: `${goldenAmount} Golden`,
          usdAmount: order.amountUSD,
          paymentMethod: "NOWPayments",
          timestamp: new Date().toISOString()
        });

        console.log(`✅ Golden added: ${userId} +${goldenAmount}G (Total: ${user.golden_balance}G)`);
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

// Check payment status
app.get("/api/nowpayments/status/:orderId", async (req, res) => {
  try {
    const { orderId } = req.params;
    const payDB = loadPaymentDB();
    const order = payDB.nowpayments_orders[orderId];

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    res.json({
      orderId,
      status: order.status,
      packageSize: order.packageSize,
      amountUSD: order.amountUSD
    });

  } catch (error) {
    console.error("Status check error:", error);
    res.status(500).json({ error: error.message });
  }
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
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
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
    ensureUserExists(req.user);
    return res.json({ loggedIn: true, user: req.user, balance: 0 });
  }

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
  res.json(GOLDEN_PACKAGES);
});

// Feature status + unlock
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

// ======================== AI ENDPOINTS =====================
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const upload = multer({ dest: "uploads/" });

// ========== FREE CHAT AI ==========
app.post("/chat-free-ai", async (req, res) => {
  try {
    const prompt = req.body.q || req.body.question || "Hello!";
    const model = req.body.model || "gpt-4o-mini";

    const messages = [
      { role: "system", content: "You are GoldenSpaceAI's helpful chat assistant." },
      { role: "user", content: prompt }
    ];

    const completion = await openai.chat.completions.create({
      model,
      messages,
      max_tokens: 1200,
      temperature: 0.7
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    res.json({ reply, model });
  } catch (e) {
    console.error("Free AI error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ========== ADVANCED CHAT AI ==========
app.post("/chat-advanced-ai", requireFeature("chat_advancedai"), upload.single("image"), async (req, res) => {
  try {
    let model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Answer helpfully.";
    const filePath = req.file?.path;

    // Handle instant mode
    if (model === "instant") {
      model = "gpt-4o-mini";
    }

    // Image generation
    if (model === "gpt-image-1") {
      try {
        const image = await openai.images.generate({
          model: "dall-e-3",
          prompt,
          size: "1024x1024",
        });
        const imageUrl = image.data?.[0]?.url;
        if (!imageUrl) throw new Error("No image data returned.");
        return res.json({
          reply: imageUrl,
          model: "dall-e-3",
        });
      } catch (imgErr) {
        console.error("Image generation error:", imgErr);
        return res.status(500).json({
          error: imgErr.message || "Image generation failed.",
        });
      }
    }

    // Chat / Vision models
    let messages;
    if (filePath) {
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
      max_tokens: 2000,
      temperature: 0.7,
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    if (filePath) fs.unlink(filePath, () => {}); // cleanup temp file
    res.json({ reply, model });

  } catch (e) {
    console.error("Advanced AI error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ============ OTHER AI ENDPOINTS ============
app.post("/search-lessons", requireFeature("search_lessons"), async (req, res) => {
  try {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a professional teacher creating clear, educational lessons." },
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

app.post("/homework-helper", requireFeature("homework_helper"), upload.single("image"), async (req, res) => {
  try {
    const model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Solve this homework step-by-step.";
    const filePath = req.file?.path;

    if (!filePath) {
      return res.status(400).json({ error: "No image provided" });
    }

    const b64 = fs.readFileSync(filePath).toString("base64");
    const mime = req.file.mimetype || "image/png";

    const messages = [
      {
        role: "system",
        content: "You are a careful, step-by-step homework solver.",
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

// ============ HEALTH ============
app.get("/health", (_req, res) => {
  const db = loadGoldenDB();
  res.json({
    status: "OK",
    users: Object.keys(db.users || {}).length,
    lastCheck: new Date().toISOString(),
  });
});

// ============ START ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI launched on port ${PORT}`);
  console.log(`✅ Golden system active with NOWPayments integration`);
  console.log(`💰 Golden packages: ${Object.keys(GOLDEN_PACKAGES).join(', ')}G`);
});
