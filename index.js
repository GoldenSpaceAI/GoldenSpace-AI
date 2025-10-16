// index.js — GoldenSpaceAI COMPLETE SYSTEM WITH FAMILY AI PLANS + 2-MIN SYNC
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
const GOLDEN_DB_PATH = path.join(__dirname, "golden_database.json");
const PAYMENT_DB_PATH = path.join(__dirname, "payment_database.json");

function loadGoldenDB() {
  try {
    if (fs.existsSync(GOLDEN_DB_PATH)) {
      const file = fs.readFileSync(GOLDEN_DB_PATH, "utf8");
      return file.trim()
        ? JSON.parse(file)
        : { users: {}, family_plans: {} };
    } else {
      fs.writeFileSync(GOLDEN_DB_PATH, JSON.stringify({ users: {}, family_plans: {} }, null, 2));
      return { users: {}, family_plans: {} };
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
    };
    saveGoldenDB(db);
  }
}

// ==================== PAYMENT + 2-MIN CHECK SYSTEM ====================
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
  premium_monthly: 20,
};

function loadPaymentDB() {
  try {
    if (fs.existsSync(PAYMENT_DB_PATH)) return JSON.parse(fs.readFileSync(PAYMENT_DB_PATH, "utf8"));
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
async function checkBTC(address) {
  try {
    const res = await axios.get(`https://api.blockcypher.com/v1/btc/main/addrs/${address}/balance`);
    return res.data.final_balance / 1e8;
  } catch { return 0; }
}
async function checkLTC(address) {
  try {
    const res = await axios.get(`https://api.blockcypher.com/v1/ltc/main/addrs/${address}/balance`);
    return res.data.final_balance / 1e8;
  } catch { return 0; }
}
async function processPackagePayments() {
  const pay = loadPaymentDB();
  const gold = loadGoldenDB();
  for (const [userId, pkgs] of Object.entries(pay.user_packages || {})) {
    for (const [key, info] of Object.entries(pkgs)) {
      if (info.status !== "pending") continue;
      const bal = info.coin === "BTC" ? await checkBTC(info.address) : await checkLTC(info.address);
      if (bal >= info.requiredAmount) {
        if (gold.users[userId]) {
          gold.users[userId].golden_balance = (gold.users[userId].golden_balance || 0) + info.packageSize;
          gold.users[userId].total_golden_earned = (gold.users[userId].total_golden_earned || 0) + info.packageSize;
          info.status = "completed";
          info.completedAt = new Date().toISOString();
        }
      }
    }
  }
  saveGoldenDB(gold);
  savePaymentDB(pay);
  console.log("✅ Golden payment sync done:", new Date().toLocaleTimeString());
}

// ----------- 2-Minute Detection & Persistence -----------
setInterval(async () => {
  console.log("🔁 2-Minute GoldenSpaceAI sync running...");
  await processPackagePayments();
  const db = loadGoldenDB();
  let expired = 0;
  for (const [uid, user] of Object.entries(db.users)) {
    for (const [f, expiry] of Object.entries(user.subscriptions || {})) {
      if (new Date(expiry) < new Date()) {
        delete user.subscriptions[f];
        expired++;
      }
    }
  }
  if (expired > 0) saveGoldenDB(db);
  console.log(`✨ Sync completed. Expired features: ${expired}`);
}, 120000);

// keep user golden in memory during session
app.use((req, _res, next) => {
  if (req.user) {
    const db = loadGoldenDB();
    const uid = getUserIdentifier(req);
    if (db.users[uid]) {
      req.user.golden_balance = db.users[uid].golden_balance;
      req.user.subscriptions = db.users[uid].subscriptions || {};
    }
  }
  next();
});

// ==================== AUTH ====================
if (process.env.GOOGLE_CLIENT_ID) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
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
  app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login-signup.html" }),
    (_req, res) => res.redirect("https://goldenspaceai.space"));
}

// ==================== API ROUTES ====================
app.get("/api/golden-balance", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false, balance: 0 });
  const b = getUserGoldenBalance(getUserIdentifier(req));
  res.json({ loggedIn: true, balance: b, user: req.user });
});
app.post("/api/unlock-feature", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { feature, cost } = req.body;
  const db = loadGoldenDB();
  const id = getUserIdentifier(req);
  const u = db.users[id];
  if (!u) return res.status(404).json({ error: "User not found" });
  if (u.golden_balance < cost) return res.status(400).json({ error: "Not enough Golden" });
  const exp = new Date(); exp.setDate(exp.getDate() + 30);
  u.golden_balance -= cost;
  u.subscriptions[feature] = exp.toISOString();
  saveGoldenDB(db);
  res.json({ success: true, newBalance: u.golden_balance });
});

// ==================== AI ENDPOINT ====================
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const upload = multer({ dest: "uploads/" });
app.post("/chat-advanced-ai", upload.single("image"), async (req, res) => {
  try {
    const model = req.body.model || "gpt-4o";
    const prompt = req.body.q || "Describe this image.";
    const filePath = req.file?.path;
    const input = filePath
      ? [
          { role: "user", content: [
              { type: "input_text", text: prompt },
              { type: "input_image", image_url: `file://${filePath}` }
            ] }
        ]
      : [{ role: "user", content: prompt }];
    const completion = await openai.chat.completions.create({
      model,
      messages: input,
      max_tokens: 1200,
      temperature: 0.7,
    });
    const reply = completion.choices[0]?.message?.content || "No reply.";
    if (filePath) fs.unlink(filePath, () => {});
    res.json({ reply, model });
  } catch (e) {
    console.error("AI error:", e);
    res.status(500).json({ error: e.message });
  }
});

// ==================== HEALTH ====================
app.get("/health", (req, res) => {
  const db = loadGoldenDB();
  res.json({
    status: "OK",
    users: Object.keys(db.users || {}).length,
    familyPlans: Object.keys(db.family_plans || {}).length,
    lastCheck: new Date().toISOString(),
  });
});

// ==================== START ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 GoldenSpaceAI running with full AI + payment sync every 2min (port ${PORT})`)
);
