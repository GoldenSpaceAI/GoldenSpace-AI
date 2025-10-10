// index.js — GoldenSpaceAI (Unlocked version)
// All pages unlocked, all AI endpoints reply in professional, advanced way

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

dotenv.config();
const app = express();
app.set("trust proxy", 1);

// ---------- Middleware ----------
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
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ---------- Passport Setup ----------
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// ==================== GOLDEN DATABASE SYSTEM ====================

const GOLDEN_DB_PATH = path.join(__dirname, 'golden_database.json');

// Load Golden database
function loadGoldenDB() {
  try {
    if (fs.existsSync(GOLDEN_DB_PATH)) {
      return JSON.parse(fs.readFileSync(GOLDEN_DB_PATH, 'utf8'));
    }
  } catch (error) {
    console.error('Error loading Golden DB:', error);
  }
  return { users: {} };
}

// Save Golden database
function saveGoldenDB(data) {
  try {
    fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify(data, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving Golden DB:', error);
    return false;
  }
}

// Get user's unique ID (works for both Google & GitHub)
function getUserIdentifier(req) {
  if (!req.user) return null;
  return `${req.user.id}@${req.user.provider}`;
}

// Get user's Golden balance
function getUserGoldenBalance(userId) {
  const db = loadGoldenDB();
  return db.users[userId]?.golden_balance || 0;
}

// Update user's Golden balance
function updateUserGoldenBalance(userId, userData, newBalance) {
  const db = loadGoldenDB();
  
  if (!db.users[userId]) {
    // Create new user entry
    db.users[userId] = {
      email: userData.email,
      name: userData.name,
      golden_balance: newBalance,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString()
    };
  } else {
    // Update existing user
    db.users[userId].golden_balance = newBalance;
    db.users[userId].last_login = new Date().toISOString();
    db.users[userId].name = userData.name; // Update name if changed
  }
  
  return saveGoldenDB(db);
}

// Auto-create user on first login
function ensureUserExists(user) {
  const userId = `${user.id}@${user.provider}`;
  const currentBalance = getUserGoldenBalance(userId);
  if (currentBalance === 0 && !loadGoldenDB().users[userId]) {
    updateUserGoldenBalance(userId, user, 0); // Create with 0 balance
    console.log(`✅ Created new user: ${userId}`);
  }
}

// ---------- Google OAuth ----------
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
        proxy: true,
      },
      (_accessToken, _refreshToken, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          photo: profile.photos?.[0]?.value || "",
          provider: "google"
        };

        // Auto-create user in Golden database
        ensureUserExists(user);

        return done(null, user);
      }
    )
  );

  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login-signup.html" }),
    (req, res) => res.redirect("https://goldenspaceai.space")
  );
}

// ---------- GitHub OAuth ----------
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "/auth/github/callback",
        proxy: true,
      },
      (_accessToken, _refreshToken, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName || profile.username,
          email: profile.emails?.[0]?.value || `${profile.username}@github.user`,
          photo: profile.photos?.[0]?.value || "",
          username: profile.username,
          provider: "github"
        };

        // Auto-create user in Golden database
        ensureUserExists(user);

        return done(null, user);
      }
    )
  );

  app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
  
  app.get(
    "/auth/github/callback",
    passport.authenticate("github", { failureRedirect: "/login-signup.html" }),
    (req, res) => res.redirect("https://goldenspaceai.space")
  );
}

// ---------- Routes ----------

// Serve login page as first page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login-signup.html"));
});

// Serve login page directly
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login-signup.html"));
});

// ---------- API: User info ----------
app.get("/api/me", (req, res) => {
  if (req.user) {
    res.json({
      loggedIn: true,
      user: req.user,
      email: req.user.email,
      name: req.user.name,
      picture: req.user.photo,
      plan: "ultra", // always ultra (everything unlocked)
      provider: req.user.provider
    });
  } else {
    res.json({
      loggedIn: false,
      user: null,
      plan: "free"
    });
  }
});

// ---------- Logout ----------
app.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" });
    }
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ ok: true, message: "Logged out successfully" });
    });
  });
});

// ==================== GOLDEN BALANCE API ====================

// Get user's Golden balance
app.get("/api/golden-balance", (req, res) => {
  if (!req.user) return res.json({ balance: 0, loggedIn: false });
  
  const userId = getUserIdentifier(req);
  const balance = getUserGoldenBalance(userId);
  
  res.json({ 
    balance, 
    loggedIn: true,
    user: req.user 
  });
});

// Get available Golden packages
app.get("/api/golden-packages", (req, res) => {
  res.json({
    20: 5,    // 20 Golden = $5
    40: 10,   // 40 Golden = $10
    60: 15,   // 60 Golden = $15
    80: 20,   // 80 Golden = $20
    100: 25,  // 100 Golden = $25
    200: 50,  // 200 Golden = $50
    400: 100, // 400 Golden = $100
    600: 150, // 600 Golden = $150
    800: 200, // 800 Golden = $200
    1000: 250 // 1000 Golden = $250
  });
});

// Add Golden to user account
app.post("/api/add-golden", (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  
  const { goldenAmount } = req.body;
  const userId = getUserIdentifier(req);
  const currentBalance = getUserGoldenBalance(userId);
  const newBalance = currentBalance + goldenAmount;
  
  const success = updateUserGoldenBalance(userId, req.user, newBalance);
  
  if (success) {
    res.json({
      success: true,
      newBalance: newBalance,
      message: `Added ${goldenAmount} Golden coins`
    });
  } else {
    res.status(500).json({ error: 'Failed to update balance' });
  }
});

// ---------- OpenAI ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Image Handling ----------
const upload = multer({ dest: 'uploads/' });

// ---------- Unified AI route ----------
async function askAI(prompt, model, res, role = "General Assistant") {
  try {
    let completion;
    let imageURL;

    switch (model) {
      case "gemini_2_5_pro":
        // Call Gemini API (replace with actual Gemini 2.5 Pro API request)
        completion = await axios.post('YOUR_GEMINI_API_ENDPOINT', {
          prompt,
          model: 'gemini_2_5_pro',
        });
        imageURL = completion.data?.image_url || null;
        break;

      case "gemini_flash":
        // Call Gemini Flash API (replace with actual Gemini Flash API request)
        completion = await axios.post('YOUR_GEMINI_FLASH_API_ENDPOINT', {
          prompt,
          model: 'gemini_flash',
        });
        imageURL = completion.data?.image_url || null;
        break;

      case "gpt_4":
        // Use OpenAI's DALL-E for image generation
        completion = await openai.images.create({
          prompt: prompt,
          n: 1,
          size: "1024x1024",
        });
        imageURL = completion.data?.data[0]?.url || null;
        break;

      case "gpt_4o_mini":
        // GPT-4o-mini doesn't support image generation
        res.status(400).json({ error: "GPT-4o-mini does not support image generation." });
        return;

      default:
        res.status(400).json({ error: "Model not supported." });
        return;
    }

    if (imageURL) {
      res.json({ reply: "Image generated successfully", imageURL });
    } else {
      res.json({ reply: completion.choices[0]?.message?.content || "No reply." });
    }
  } catch (e) {
    console.error("AI error", e);
    res.status(500).json({ error: "AI error" });
  }
}

// ---------- AI Endpoints (all models with image generation and upload support) ----------
app.post("/chat-advanced-ai", upload.single("image"), async (req, res) => {
  const { q, model } = req.body;
  const image = req.file ? req.file.path : null;

  try {
    if (image) {
      console.log('Image uploaded:', image);
    }

    await askAI(q || "", model || "gpt-4", res, "Advanced Assistant");

  } catch (e) {
    console.error("Advanced AI error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});

app.post("/ask", async (req, res) => {
  await askAI(req.body?.question || "", "gpt-4o-mini", res, "Chat");
});

app.post("/chat-homework", async (req, res) => {
  await askAI(req.body?.q || "", "gpt-4o-mini", res, "Homework Solver");
});

app.post("/search-info", async (req, res) => {
  await askAI(req.body?.query || "", "gpt-4o-mini", res, "Knowledge Search");
});

app.post("/api/physics-explain", async (req, res) => {
  await askAI(req.body?.question || "", "gpt-4o-mini", res, "Physics Tutor");
});

app.post("/ai/create-planet", async (req, res) => {
  await askAI("Invent a realistic exoplanet: " + JSON.stringify(req.body?.specs || {}), "gpt-4o-mini", res, "Planet Builder");
});

app.post("/ai/create-rocket", async (req, res) => {
  await askAI("Design a conceptual rocket.", "gpt-4o-mini", res, "Rocket Engineer");
});

app.post("/ai/create-satellite", async (req, res) => {
  await askAI("Design a conceptual satellite.", "gpt-4o-mini", res, "Satellite Engineer");
});

app.post("/ai/create-universe", async (req, res) => {
  await askAI("Create a fictional shared universe. Theme: " + (req.body?.theme || "space opera"), "gpt-4o-mini", res, "Universe Creator");
});

// ==================== PAYMENT DETECTION SYSTEM ====================

let processedTransactions = new Set(); // track processed payments

// Check for new payments every 2 minutes
async function checkForNewPayments() {
  console.log("🔍 Checking for new payments...");
  
  try {
    // Check all coins in parallel
    const [btcData, ltcData, tronData] = await Promise.all([
      checkBitcoinPayments(),
      checkLitecoinPayments(), 
      checkTronPayments()
    ]);
    
    // Process detected payments
    await processDetectedPayments(btcData, ltcData, tronData);
    
  } catch (error) {
    console.error('Payment check error:', error);
  }
}

// Bitcoin payments (Blockstream.info)
async function checkBitcoinPayments() {
  try {
    const response = await fetch('https://blockstream.info/api/address/bc1qz5wtz2d329xsm7gcs9e3jwls9supg2fk2hkxtd');
    const data = await response.json();
    return { coin: 'BTC', data, source: 'blockstream' };
  } catch (error) {
    console.error('Bitcoin check failed:', error);
    return { coin: 'BTC', data: null, error: true };
  }
}

// Litecoin payments (BlockCypher)
async function checkLitecoinPayments() {
  try {
    const response = await fetch('https://api.blockcypher.com/v1/ltc/main/addrs/ltc1qngssav372fl4sw0s8w66h4c8v5yftqw4qrkhdn');
    const data = await response.json();
    return { coin: 'LTC', data, source: 'blockcypher' };
  } catch (error) {
    console.error('Litecoin check failed:', error);
    return { coin: 'LTC', data: null, error: true };
  }
}

// TRON payments (TRONSCAN)
async function checkTronPayments() {
  try {
    const response = await fetch('https://apilist.tronscan.org/api/account?address=TCN6eVtHFNtPAJNfebgGGm8c2h71NWYY9P');
    const data = await response.json();
    return { coin: 'TRON', data, source: 'tronscan' };
  } catch (error) {
    console.error('TRON check failed:', error);
    return { coin: 'TRON', data: null, error: true };
  }
}

// Process detected payments
async function processDetectedPayments(btcResult, ltcResult, tronResult) {
  // Process Bitcoin payments
  if (btcResult.data && btcResult.data.chain_stats.tx_count > 0) {
    console.log('💰 Bitcoin transactions found:', btcResult.data.chain_stats.tx_count);
    // We'll implement transaction details later
  }
  
  // Process Litecoin payments
  if (ltcResult.data && ltcResult.data.n_tx > 0) {
    console.log('💰 Litecoin transactions found:', ltcResult.data.n_tx);
    // Process LTC transactions
  }
  
  // Process TRON payments (USDT)
  if (tronResult.data && tronResult.data.trc20token_balances.length > 0) {
    console.log('💰 TRON USDT transactions found');
    // Process USDT transactions
  }
}

// Start checking every 2 minutes (120,000 milliseconds)
setInterval(checkForNewPayments, 120000);

// Also check immediately when server starts
setTimeout(checkForNewPayments, 5000);

// ---------- Health Check ----------
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "GoldenSpaceAI is running" });
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT} (ALL UNLOCKED + PERSISTENT GOLDEN SYSTEM)`));
