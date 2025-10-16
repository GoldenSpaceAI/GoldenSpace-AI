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
import nodemailer from "nodemailer";

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
  } else {
    db.users[id].last_login = new Date().toISOString();
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

// ===============================
// 🛡️ ADMIN GOLDEN MANAGEMENT API
// ===============================

// ✅ define ADMIN_SECRET_KEY (needed by requireAdminAuth)
const ADMIN_SECRET_KEY = process.env.ADMIN_SECRET_KEY || "golden-admin-secret-2024";

const requireAdminAuth = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Admin authentication required" });
  }
  const token = authHeader.substring(7);
  if (token !== ADMIN_SECRET_KEY) {
    return res.status(403).json({ error: "Invalid admin token" });
  }
  next();
};

// 📊 Get all users (include userId for admin page)
app.get("/api/admin/all-users", requireAdminAuth, (req, res) => {
  const goldenDB = loadGoldenDB();
  const users = [];
  for (const [userId, u] of Object.entries(goldenDB.users || {})) {
    users.push({
      userId,
      name: u.name,
      email: u.email,
      golden_balance: u.golden_balance || 0,
      total_golden_earned: u.total_golden_earned || 0,
      total_golden_spent: u.total_golden_spent || 0,
      created_at: u.created_at,
      last_login: u.last_login,
      provider: userId.split("@")[1]
    });
  }
  users.sort((a, b) => b.golden_balance - a.golden_balance);
  const totalGolden = users.reduce((s, u) => s + (u.golden_balance || 0), 0);
  res.json({
    success: true,
    users,
    totalUsers: users.length,
    totalGolden
  });
});

// 🔍 Search users (by id/email/name)
app.get("/api/admin/search-users", requireAdminAuth, (req, res) => {
  const q = (req.query.query || "").toLowerCase();
  const goldenDB = loadGoldenDB();
  const out = [];
  for (const [userId, u] of Object.entries(goldenDB.users || {})) {
    const hit =
      userId.toLowerCase().includes(q) ||
      (u.email && u.email.toLowerCase().includes(q)) ||
      (u.name && u.name.toLowerCase().includes(q));
    if (hit) {
      out.push({
        userId,
        name: u.name,
        email: u.email,
        golden_balance: u.golden_balance || 0,
        total_golden_earned: u.total_golden_earned || 0,
        total_golden_spent: u.total_golden_spent || 0,
        created_at: u.created_at,
        last_login: u.last_login,
        provider: userId.split("@")[1]
      });
    }
  }
  res.json({ success: true, users: out });
});

// ➕ Add Golden
app.post("/api/admin/add-golden", requireAdminAuth, (req, res) => {
  const { userId, amount, reason } = req.body;
  const goldenDB = loadGoldenDB();
  if (!goldenDB.users[userId]) return res.status(404).json({ error: "User not found" });

  const user = goldenDB.users[userId];
  const previous_balance = user.golden_balance || 0;
  user.golden_balance = previous_balance + Number(amount);
  if (!user.transactions) user.transactions = [];
  user.transactions.push({
    type: "add",
    amount: Number(amount),
    previous_balance,
    new_balance: user.golden_balance,
    reason,
    timestamp: new Date().toISOString()
  });
  saveGoldenDB(goldenDB);
  res.json({ success: true });
});

// ➖ Subtract Golden
app.post("/api/admin/subtract-golden", requireAdminAuth, (req, res) => {
  const { userId, amount, reason } = req.body;
  const goldenDB = loadGoldenDB();
  if (!goldenDB.users[userId]) return res.status(404).json({ error: "User not found" });

  const user = goldenDB.users[userId];
  const previous_balance = user.golden_balance || 0;
  user.golden_balance = Math.max(0, previous_balance - Number(amount));
  if (!user.transactions) user.transactions = [];
  user.transactions.push({
    type: "subtract",
    amount: -Number(amount),
    previous_balance,
    new_balance: user.golden_balance,
    reason,
    timestamp: new Date().toISOString()
  });
  saveGoldenDB(goldenDB);
  res.json({ success: true });
});

// ⚙️ Set Golden
app.post("/api/admin/set-golden", requireAdminAuth, (req, res) => {
  const { userId, balance, reason } = req.body;
  const goldenDB = loadGoldenDB();
  if (!goldenDB.users[userId]) return res.status(404).json({ error: "User not found" });

  const user = goldenDB.users[userId];
  const previous_balance = user.golden_balance || 0;
  user.golden_balance = Number(balance);
  if (!user.transactions) user.transactions = [];
  user.transactions.push({
    type: "set",
    amount: Number(balance) - previous_balance,
    previous_balance,
    new_balance: user.golden_balance,
    reason,
    timestamp: new Date().toISOString()
  });
  saveGoldenDB(goldenDB);
  res.json({ success: true });
});

// 🧾 User transactions (🟢 match admin page path param name)
app.get("/api/admin/user-transactions/:userId", requireAdminAuth, (req, res) => {
  const { userId } = req.params;
  const goldenDB = loadGoldenDB();
  const user = goldenDB.users[userId];
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({
    success: true,
    transactions: user.transactions || []
  });
});

// ===============================
// 💸 REFUND GOLDEN ENDPOINT (Namecheap Email)
// ===============================
app.post("/api/refund-golden", async (req, res) => {
  try {
    const { amount, walletAddress, currency } = req.body;

    const userId = req.session?.passport?.user?.id;
    const userEmail = req.session?.passport?.user?.email;
    const userName = req.session?.passport?.user?.displayName || "Unknown User";

    if (!userId || !userEmail)
      return res.status(401).json({ error: "Not logged in" });

    if (!amount || amount <= 0)
      return res.status(400).json({ error: "Invalid amount" });

    const goldenDB = loadGoldenDB();
    const user = goldenDB.users[userId];
    if (!user)
      return res.status(404).json({ error: "User not found" });

    if (user.golden_balance < amount)
      return res.status(400).json({ error: "Not enough Golden" });

    // Deduct the golden
    const prevBalance = user.golden_balance;
    user.golden_balance -= Number(amount);

    if (!user.transactions) user.transactions = [];
    user.transactions.push({
      type: "refund",
      amount: -Number(amount),
      previous_balance: prevBalance,
      new_balance: user.golden_balance,
      reason: "User requested refund",
      timestamp: new Date().toISOString()
    });

    saveGoldenDB(goldenDB);

    // Configure SMTP for Namecheap’s PrivateEmail
    const transporter = nodemailer.createTransport({
      host: "mail.privateemail.com",
      port: 465,
      secure: true,
      auth: {
        user: process.env.ADMIN_EMAIL || "support@goldenspaceai.space",
        pass: process.env.ADMIN_EMAIL_PASSWORD
      }
    });

    // Send email to support@goldenspaceai.space
    const mailOptions = {
      from: `"GoldenSpaceAI Refunds" <support@goldenspaceai.space>`,
      to: "support@goldenspaceai.space",
      subject: `🔔 Refund Request Received (RefundID:2233553)`,
      html: `
        <h2>💰 GoldenSpaceAI Refund Request</h2>
        <p>A new refund request has been submitted from <strong>${userName}</strong>:</p>
        <ul>
          <li><strong>RefundID:</strong> 2233553</li>
          <li><strong>User Name:</strong> ${userName}</li>
          <li><strong>User Email:</strong> ${userEmail}</li>
          <li><strong>User ID:</strong> ${userId}</li>
          <li><strong>Refund Amount:</strong> ${amount}G</li>
          <li><strong>Currency:</strong> ${currency}</li>
          <li><strong>Wallet Address:</strong> ${walletAddress}</li>
          <li><strong>Date:</strong> ${new Date().toLocaleString()}</li>
        </ul>
        <p>The user's balance was automatically adjusted from ${prevBalance}G → ${user.golden_balance}G.</p>
        <hr>
        <p style="color:#999">Official Refund Email from GoldenSpaceAI • RefundID:2233553</p>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Refund email sent for ${userEmail} (${amount}G)`);

    res.json({
      success: true,
      message: "Refund request submitted successfully",
      newBalance: user.golden_balance
    });

  } catch (error) {
    console.error("❌ Refund processing failed:", error);
    res.status(500).json({ error: "Server error: " + error.message });
  }
});

// ===============================
// 🤝 TRANSFER GOLDEN (5% fee to vault)
// ===============================
app.post("/api/transfer-golden", (req, res) => {
  if (!req.user) return res.status(401).json({ error: "Login required" });
  const { recipientEmail, amount } = req.body;
  if (!recipientEmail || !amount || amount <= 0) {
    return res.status(400).json({ error: "recipientEmail and positive amount required" });
  }

  const db = loadGoldenDB();
  const senderId = getUserIdentifier(req);
  const sender = db.users[senderId];
  if (!sender) return res.status(404).json({ error: "Sender not found" });

  const recipientId = Object.keys(db.users).find(id => db.users[id]?.email?.toLowerCase() === recipientEmail.toLowerCase());
  if (!recipientId) return res.status(404).json({ error: "Recipient not found" });

  const fee = Math.ceil(Number(amount) * 0.05);
  const totalCost = Number(amount) + fee;
  if ((sender.golden_balance || 0) < totalCost) {
    return res.status(400).json({ error: "Insufficient balance for amount + fee" });
  }

  // Vault
  const vaultId = "goldenvault@system";
  if (!db.users[vaultId]) {
    db.users[vaultId] = {
      email: "vault@goldenspaceai.space",
      name: "GoldenVault",
      golden_balance: 0,
      created_at: new Date().toISOString(),
      last_login: new Date().toISOString(),
      subscriptions: {}
    };
  }

  // Apply balances
  sender.golden_balance -= totalCost;
  db.users[recipientId].golden_balance = (db.users[recipientId].golden_balance || 0) + Number(amount);
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
    timestamp: now
  });
  db.users[recipientId].transactions.push({
    type: "transfer-in",
    amount: Number(amount),
    from: sender.email,
    timestamp: now
  });
  db.users[vaultId].transactions.push({
    type: "transfer-fee",
    amount: fee,
    from: sender.email,
    timestamp: now
  });

  saveGoldenDB(db);
  res.json({
    success: true,
    message: `Transferred ${amount}G to ${recipientEmail} (fee: ${fee}G)`,
    newBalance: sender.golden_balance
  });
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
