// index.js — GoldenSpaceAI SIMPLIFIED SYSTEM (Auth + Plans + NOWPayments + AI)
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
const USER_DB_PATH = "/data/user_database.json";
const PAYMENT_DB_PATH = "/data/payment_database.json";

function loadUserDB() {
  try {
    if (fs.existsSync(USER_DB_PATH)) {
      const file = fs.readFileSync(USER_DB_PATH, "utf8");
      if (!file.trim()) return { users: {} };
      return JSON.parse(file);
    } else {
      const initial = { users: {} };
      fs.writeFileSync(USER_DB_PATH, JSON.stringify(initial, null, 2));
      return initial;
    }
  } catch (e) {
    console.error("DB load error:", e);
    return { users: {} };
  }
}

function saveUserDB(db) {
  try {
    fs.writeFileSync(USER_DB_PATH, JSON.stringify(db, null, 2));
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
      return raw.trim() ? JSON.parse(raw) : { transactions: {}, nowpayments_orders: {} };
    }
  } catch (e) {
    console.error("Payment DB error:", e);
  }
  return { transactions: {}, nowpayments_orders: {} };
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

function ensureUserExists(user) {
  const db = loadUserDB();
  const id = `${user.id}@${user.provider}`;
  if (!db.users[id]) {
    db.users[id] = {
      email: user.email,
      name: user.name,
      plan: "free", // Default to free plan
      plan_expiry: null,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
    };
    saveUserDB(db);
  } else {
    db.users[id].last_login = new Date().toISOString();
    saveUserDB(db);
  }
}

// ============ PLAN SYSTEM ============
const PLANS = {
  free: {
    name: "Free",
    features: ["chat-free-ai", "learn-info"]
  },
  plus: {
    name: "Plus",
    price: { monthly: 15, yearly: 150 },
    features: ["chat-free-ai", "learn-info", "physics-tools", "create-planet", "space-tools", "chat-advanced-ai"]
  },
  pro: {
    name: "Pro",
    price: { monthly: 25, yearly: 250 },
    features: ["all-plus-features", "image-creation", "file-upload", "deep-think", "web-search", "homework-solver", "lesson-search"]
  }
};

// Feature access check
function hasFeatureAccess(user, feature) {
  const userPlan = user.plan || 'free';
  return PLANS[userPlan].features.includes(feature);
}

// Middleware to check feature access
function requireFeature(feature) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "Login required" });
    }
    
    const db = loadUserDB();
    const userId = getUserIdentifier(req);
    const user = db.users[userId];
    
    if (!user || !hasFeatureAccess(user, feature)) {
      return res.status(403).json({ 
        error: "Upgrade required",
        message: `This feature requires ${feature.includes('advanced') ? 'Plus' : 'Pro'} plan`,
        requiredPlan: feature.includes('advanced') ? 'plus' : 'pro'
      });
    }
    
    next();
  };
}

// Keep session user hydrated with plan info
app.use((req, _res, next) => {
  if (req.user) {
    const db = loadUserDB();
    const uid = getUserIdentifier(req);
    if (uid && db.users[uid]) {
      req.user.plan = db.users[uid].plan || 'free';
      req.user.plan_expiry = db.users[uid].plan_expiry;
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
  const db = loadUserDB();
  const userData = db.users[id];

  if (!userData) {
    ensureUserExists(req.user);
    return res.json({ loggedIn: true, user: req.user, plan: "free" });
  }

  res.json({
    loggedIn: true,
    user: req.user,
    plan: userData.plan || "free",
    plan_expiry: userData.plan_expiry
  });
});

// ============ NOWPAYMENTS INTEGRATION ============
const NOWPAYMENTS_API = "https://api.nowpayments.io/v1";
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY;

// Create payment for plan subscription
app.post("/api/nowpayments/create-plan", async (req, res) => {
  try {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    
    const { plan, period } = req.body; // 'plus' or 'pro', 'monthly' or 'yearly'
    const amountUSD = PLANS[plan].price[period];
    
    if (!amountUSD || amountUSD <= 0) {
      return res.status(400).json({ error: "Invalid plan selection" });
    }

    const orderId = `goldenspace-${req.user.id}-${plan}-${period}-${Date.now()}`;
    const callbackUrl = "https://goldenspaceai.space/api/nowpayments/webhook";

    const payload = {
      price_amount: amountUSD,
      price_currency: "USD",
      pay_currency: "usdt", // Users can pay with any crypto, you receive USDT
      order_id: orderId,
      order_description: `GoldenSpaceAI ${PLANS[plan].name} Plan (${period})`,
      ipn_callback_url: callbackUrl,
      success_url: "https://goldenspaceai.space/success.html",
      cancel_url: "https://goldenspaceai.space/plans.html"
    };

    // Create NOWPayments invoice
    const response = await axios.post(`${NOWPAYMENTS_API}/invoice`, payload, {
      headers: { "x-api-key": NOWPAYMENTS_API_KEY },
    });

    // Store in payment database
    const payDB = loadPaymentDB();
    payDB.nowpayments_orders = payDB.nowpayments_orders || {};
    payDB.nowpayments_orders[orderId] = {
      user: getUserIdentifier(req),
      plan,
      period,
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
      plan: PLANS[plan].name,
      period
    });

  } catch (error) {
    console.error("NOWPayments plan error:", error.response?.data || error.message);
    res.status(500).json({ error: "Payment creation failed: " + error.message });
  }
});

// NOWPayments webhook for payment confirmation
app.post("/api/nowpayments/webhook", async (req, res) => {
  try {
    const secret = req.headers["x-nowpayments-sig"];
    // Verify webhook secret if you set one
    // if (secret !== process.env.NOWPAYMENTS_WEBHOOK_SECRET) {
    //   return res.status(403).json({ error: "Invalid signature" });
    // }

    const event = req.body;
    console.log("💰 NOWPayments Webhook:", event);

    const paymentId = event.payment_id;
    const orderId = event.order_id;

    // Load databases
    const payDB = loadPaymentDB();
    const userDB = loadUserDB();

    const order = payDB.nowpayments_orders[orderId];
    if (!order) {
      console.log("Order not found:", orderId);
      return res.status(404).json({ error: "Order not found" });
    }

    // Handle payment confirmation
    if (event.payment_status === "finished" || event.payment_status === "confirmed") {
      // PAYMENT SUCCESSFUL - ACTIVATE PLAN
      order.status = "completed";
      order.confirmedAt = new Date().toISOString();
      order.transactionHash = event.payin_hash;

      const userId = order.user;
      const user = userDB.users[userId];
      
      if (user) {
        // Update user's plan
        user.plan = order.plan;
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + (order.period === 'yearly' ? 365 : 30));
        user.plan_expiry = expiryDate.toISOString();
        
        console.log(`✅ Plan activated: ${userId} -> ${order.plan} (${order.period})`);
      }

      savePaymentDB(payDB);
      saveUserDB(userDB);
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
      plan: order.plan,
      period: order.period,
      amountUSD: order.amountUSD
    });

  } catch (error) {
    console.error("Status check error:", error);
    res.status(500).json({ error: error.message });
  }
});

// Get available plans
app.get("/api/plans", (req, res) => {
  res.json(PLANS);
});

// ======================== AI ENDPOINTS =====================
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const upload = multer({ dest: "uploads/" });

// ========== FREE CHAT AI (Available to all) ==========
app.post("/chat-free-ai", async (req, res) => {
  try {
    const prompt = req.body.q || req.body.question || "Hello!";
    const model = req.body.model || "gpt-4o-mini"; // default model

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

// ========== ADVANCED CHAT AI (Requires Plus/Pro plan) ==========
app.post("/chat-advanced-ai", requireFeature("chat-advanced-ai"), upload.single("image"), async (req, res) => {
  try {
    let model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Answer helpfully.";
    const filePath = req.file?.path;

    // Handle instant mode with GPT-5-nano
    if (model === "instant") {
      model = "gpt-5-nano";
    }

    // ============ IMAGE GENERATION ==============
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

    // ============ CHAT / VISION MODELS ==========
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

// ==================== AI LESSONS ENDPOINT ====================
app.post("/search-lessons", requireFeature("lesson-search"), async (req, res) => {
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

// ============ HOMEWORK HELPER (Requires Pro plan) ============
app.post("/homework-helper", requireFeature("homework-solver"), upload.single("image"), async (req, res) => {
  try {
    const model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Solve this homework step-by-step. Show detailed reasoning and final answer.";
    const filePath = req.file?.path;

    if (!filePath) {
      return res.status(400).json({ error: "No image provided" });
    }

    const b64 = fs.readFileSync(filePath).toString("base64");
    const mime = req.file.mimetype || "image/png";

    const messages = [
      {
        role: "system",
        content: "You are a careful, step-by-step homework solver. Explain clearly and show working.",
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

// ==================== PHYSICS AI ENDPOINTS ====================
app.post("/api/physics-explain", requireFeature("physics-tools"), async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a physics tutor who explains concepts clearly and simply." },
        { role: "user", content: question }
      ],
      max_tokens: 800,
      temperature: 0.7
    });

    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ reply });
  } catch (err) {
    console.error("Physics explain error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/physics-tutor", requireFeature("physics-tools"), async (req, res) => {
  try {
    const { question, topic, mode } = req.body;
    if (!question) return res.status(400).json({ error: "Missing question" });

    const systemPrompt = `You are a physics tutor. 
Mode: ${mode || "Socratic"}.
Topic: ${topic || "General Physics"}.
Respond with detailed, educational explanations. If "Steps" or "Practice" mode, show step-by-step reasoning.`;

    const completion = await openai.chat.completions.create({
      model: "gpt-4o",
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: question }
      ],
      max_tokens: 1200,
      temperature: 0.7
    });

    const reply = completion.choices[0]?.message?.content || "No reply.";
    res.json({ reply });
  } catch (err) {
    console.error("Physics tutor error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN API (Simplified) ============
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
  const db = loadUserDB();
  const users = [];
  for (const [userId, u] of Object.entries(db.users || {})) {
    users.push({
      userId,
      name: u.name,
      email: u.email,
      plan: u.plan || "free",
      plan_expiry: u.plan_expiry,
      created_at: u.created_at,
      last_login: u.last_login,
      provider: userId.split("@")[1],
    });
  }
  res.json({ success: true, users, totalUsers: users.length });
});

// Admin: update user plan
app.post("/api/admin/update-plan", requireAdminAuth, (req, res) => {
  const { userId, plan, period } = req.body;
  if (!userId || !plan) return res.status(400).json({ error: "User ID and plan required" });

  const db = loadUserDB();
  const u = db.users[userId];
  if (!u) return res.status(404).json({ error: "User not found" });

  u.plan = plan;
  if (period) {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + (period === 'yearly' ? 365 : 30));
    u.plan_expiry = expiryDate.toISOString();
  } else {
    u.plan_expiry = null;
  }

  saveUserDB(db);
  res.json({ success: true });
});
// In your index.js - this creates a tracked payment
app.post("/api/create-subscription", async (req, res) => {
  const { plan, period } = req.body; // 'plus' or 'pro', 'monthly' or 'yearly'
  const amountUSD = PLANS[plan].price[period];
  
  const orderId = `sub-${req.user.id}-${plan}-${Date.now()}`;
  
  const payload = {
    price_amount: amountUSD,
    price_currency: "USD",
    pay_currency: "usdt", // Users pay with any crypto
    order_id: orderId,
    order_description: `GoldenSpaceAI ${plan} Plan`,
    ipn_callback_url: "https://goldenspaceai.space/api/nowpay/webhook", // ← WEBHOOK URL
  };

  // Create payment with NOWPayments
  const response = await axios.post(`${NOWPAYMENTS_API}/invoice`, payload, {
    headers: { "x-api-key": NOWPAYMENTS_API_KEY },
  });

  // Store order in your database
  savePaymentToDB(orderId, req.user.id, plan, period, response.data.id);
  
  res.json({ 
    success: true, 
    paymentUrl: response.data.invoice_url // User goes here to pay
  });
});// ============ HEALTH ============
app.get("/health", (_req, res) => {
  const db = loadUserDB();
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
  console.log(`✅ Plan system ready with NOWPayments integration`);
});
