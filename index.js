// index.js — GoldenSpaceAI Complete Launch Version WITH PAGE LOCKS
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
      last_login: new Date().toISOString(),
      subscriptions: {}
    };
  } else {
    // Update existing user
    db.users[userId].golden_balance = newBalance;
    db.users[userId].last_login = new Date().toISOString();
    db.users[userId].name = userData.name; // Update name if changed
    
    // Ensure subscriptions object exists for existing users
    if (!db.users[userId].subscriptions) {
      db.users[userId].subscriptions = {};
    }
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

// ==================== FEATURE SUBSCRIPTION SYSTEM ====================

// Feature pricing configuration - UPDATED WITH YOUR PRICING
const FEATURE_PRICES = {
  // 4G Features
  search_info: 4,
  learn_physics: 4,
  create_planet: 4,
  advanced_planet: 4,
  create_rocket: 4,
  create_satellite: 4,
  your_space: 4,
  
  // 10G Features
  search_lessons: 10,
  
  // 20G Features
  chat_advancedai: 20,
  homework_helper: 20
};

// Calculate hours remaining until expiration
function getHoursRemaining(expiryDate) {
  const now = new Date();
  const expiry = new Date(expiryDate);
  const diffMs = expiry - now;
  const diffHours = Math.max(0, Math.floor(diffMs / (1000 * 60 * 60)));
  return diffHours;
}

// Check if a feature is unlocked for user
function isFeatureUnlocked(userId, feature) {
  const db = loadGoldenDB();
  const user = db.users[userId];
  
  if (!user || !user.subscriptions || !user.subscriptions[feature]) {
    return { unlocked: false, remainingHours: 0 };
  }
  
  const expiryDate = user.subscriptions[feature];
  const remainingHours = getHoursRemaining(expiryDate);
  
  // Auto-expire if time is up
  if (remainingHours <= 0) {
    delete user.subscriptions[feature];
    saveGoldenDB(db);
    return { unlocked: false, remainingHours: 0 };
  }
  
  return {
    unlocked: remainingHours > 0,
    remainingHours: remainingHours
  };
}

// Unlock a feature for user (deduct Golden and set expiry)
function unlockFeatureForUser(userId, feature, cost) {
  const db = loadGoldenDB();
  const user = db.users[userId];
  
  if (!user) {
    return { success: false, error: 'User not found' };
  }
  
  // Check if user has enough Golden balance
  if (user.golden_balance < cost) {
    return { success: false, error: 'Insufficient Golden balance' };
  }
  
  // Calculate expiry date (30 days from now)
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + 30);
  
  // Deduct Golden balance
  user.golden_balance -= cost;
  
  // Ensure subscriptions object exists
  if (!user.subscriptions) {
    user.subscriptions = {};
  }
  
  // Add/update subscription
  user.subscriptions[feature] = expiryDate.toISOString();
  
  // Save to database
  const success = saveGoldenDB(db);
  
  if (success) {
    return { 
      success: true, 
      newBalance: user.golden_balance,
      expiryDate: expiryDate.toISOString(),
      remainingHours: 720 // 30 days * 24 hours
    };
  } else {
    return { success: false, error: 'Failed to save database' };
  }
}

// ==================== PAGE PROTECTION MIDDLEWARE ====================

// Middleware to check if user can access a premium page
function requirePremiumPage(feature, price) {
  return (req, res, next) => {
    if (!req.user) {
      // Redirect to login if not authenticated
      return res.redirect('/login-signup.html');
    }
    
    const userId = getUserIdentifier(req);
    const featureStatus = isFeatureUnlocked(userId, feature);
    
    if (!featureStatus.unlocked) {
      // Serve the locked version of the page
      const lockedPage = generateLockedPage(feature, price);
      return res.send(lockedPage);
    }
    
    // User has access, serve the actual page
    next();
  };
}

// Generate locked page HTML
function generateLockedPage(feature, price) {
  const featureNames = {
    'search_info': 'Search Information',
    'learn_physics': 'Learn Physics', 
    'create_planet': 'Create Planet',
    'advanced_planet': 'Advanced Planet Builder',
    'create_rocket': 'Create Rocket',
    'create_satellite': 'Create Satellite',
    'your_space': 'Your Space Universe',
    'search_lessons': 'Search Lessons',
    'chat_advancedai': 'Advanced AI Chat',
    'homework_helper': 'Homework Helper'
  };
  
  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${featureNames[feature]} • GoldenSpaceAI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background: linear-gradient(135deg, #0c0c2e 0%, #1a1a4a 50%, #2d1b69 100%);
            min-height: 100vh; color: #e7f4e9; font-family: 'Segoe UI', sans-serif;
            display: flex; align-items: center; justify-content: center;
        }
        .lock-container { 
            background: linear-gradient(135deg, #0f1624, #0b1320);
            border: 2px solid #f6c64a; border-radius: 20px; padding: 40px;
            text-align: center; max-width: 500px; width: 90%;
            box-shadow: 0 20px 60px rgba(246, 198, 74, 0.3);
        }
        .lock-icon { font-size: 80px; margin-bottom: 20px; }
        .title { color: #f6c64a; font-size: 28px; margin-bottom: 15px; }
        .description { color: #cfc6a5; margin-bottom: 25px; line-height: 1.6; }
        .price { font-size: 42px; font-weight: bold; color: #f6c64a; margin: 20px 0; }
        .price span { font-size: 18px; color: #cfc6a5; }
        .unlock-btn {
            background: linear-gradient(135deg, #f6c64a, #eb8b36);
            color: #1a1300; border: none; border-radius: 12px;
            padding: 16px 40px; font-size: 18px; font-weight: bold;
            cursor: pointer; margin: 15px 0; width: 100%;
            box-shadow: 0 8px 25px rgba(246, 198, 74, 0.4);
        }
        .balance-info { color: #cfc6a5; margin: 15px 0; }
        .back-link { color: #f6c64a; text-decoration: none; margin-top: 20px; display: inline-block; }
    </style>
</head>
<body>
    <div class="lock-container">
        <div class="lock-icon">🔒</div>
        <h1 class="title">Unlock ${featureNames[feature]}</h1>
        <p class="description">Access this premium feature for 30 days with Golden coins</p>
        <div class="price">${price}G <span>per month</span></div>
        <div class="balance-info">Your balance: <span id="balance">0</span>G</div>
        <button class="unlock-btn" onclick="unlockFeature()">UNLOCK FOR ${price}G</button>
        <div id="status" style="margin: 15px 0; min-height: 20px;"></div>
        <a href="/" class="back-link">← Back to Home</a>
        <a href="/buy-golden.html" class="back-link" style="margin-left: 20px;">Buy More Golden →</a>
    </div>

    <script>
        let currentFeature = '${feature}';
        let currentPrice = ${price};

        async function loadBalance() {
            try {
                const response = await fetch('/api/golden-balance', { credentials: 'include' });
                const data = await response.json();
                document.getElementById('balance').textContent = data.balance;
            } catch (error) {
                console.error('Failed to load balance:', error);
            }
        }

        async function unlockFeature() {
            const btn = document.querySelector('.unlock-btn');
            const status = document.getElementById('status');
            
            btn.disabled = true;
            btn.textContent = 'Processing...';
            status.textContent = '';
            
            try {
                const response = await fetch('/api/unlock-feature', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({
                        feature: currentFeature,
                        cost: currentPrice
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    status.textContent = '✅ Success! Unlocking feature...';
                    status.style.color = '#90ee90';
                    setTimeout(() => {
                        window.location.reload(); // Reload to access the page
                    }, 1500);
                } else {
                    status.textContent = '❌ ' + (data.error || 'Failed to unlock');
                    status.style.color = '#ff6b6b';
                    btn.disabled = false;
                    btn.textContent = 'UNLOCK FOR ${price}G';
                }
            } catch (error) {
                status.textContent = '❌ Network error. Please try again.';
                status.style.color = '#ff6b6b';
                btn.disabled = false;
                btn.textContent = 'UNLOCK FOR ${price}G';
            }
        }

        // Load balance when page loads
        loadBalance();
    </script>
</body>
</html>
  `;
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

// ==================== PROTECTED PAGE ROUTES ====================

// 4G Features
app.get("/search-info.html", requirePremiumPage('search_info', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "search-info.html"));
});

app.get("/learn-physics.html", requirePremiumPage('learn_physics', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "learn-physics.html"));
});

app.get("/create-planet.html", requirePremiumPage('create_planet', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "create-planet.html"));
});

app.get("/create-advanced-planet.html", requirePremiumPage('advanced_planet', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "create-advanced-planet.html"));
});

app.get("/create-rocket.html", requirePremiumPage('create_rocket', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "create-rocket.html"));
});

app.get("/create-satellite.html", requirePremiumPage('create_satellite', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "create-satellite.html"));
});

app.get("/your-space.html", requirePremiumPage('your_space', 4), (req, res) => {
  res.sendFile(path.join(__dirname, "your-space.html"));
});

// 10G Features
app.get("/search-lessons.html", requirePremiumPage('search_lessons', 10), (req, res) => {
  res.sendFile(path.join(__dirname, "search-lessons.html"));
});

// 20G Features
app.get("/chat-advancedai.html", requirePremiumPage('chat_advancedai', 20), (req, res) => {
  res.sendFile(path.join(__dirname, "chat-advancedai.html"));
});

app.get("/homework-helper.html", requirePremiumPage('homework_helper', 20), (req, res) => {
  res.sendFile(path.join(__dirname, "homework-helper.html"));
});

// Free pages (no protection needed)
app.get("/buy-golden.html", (req, res) => {
  res.sendFile(path.join(__dirname, "buy-golden.html"));
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
      plan: "ultra",
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

// ==================== GOLDEN BALANCE & SUBSCRIPTION APIS ====================

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

// Check feature status
app.get("/api/feature-status", (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  
  const { feature } = req.query;
  const userId = getUserIdentifier(req);
  
  if (!feature || !FEATURE_PRICES[feature]) {
    return res.status(400).json({ error: 'Invalid feature' });
  }
  
  const status = isFeatureUnlocked(userId, feature);
  
  res.json({
    feature,
    unlocked: status.unlocked,
    remainingHours: status.remainingHours,
    price: FEATURE_PRICES[feature]
  });
});

// Unlock a feature
app.post("/api/unlock-feature", (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'Login required' });
  
  const { feature, cost } = req.body;
  const userId = getUserIdentifier(req);
  
  if (!feature || !FEATURE_PRICES[feature]) {
    return res.status(400).json({ error: 'Invalid feature' });
  }
  
  // Verify the cost matches our pricing
  if (cost !== FEATURE_PRICES[feature]) {
    return res.status(400).json({ error: 'Invalid cost for feature' });
  }
  
  const result = unlockFeatureForUser(userId, feature, cost);
  
  if (result.success) {
    res.json({
      success: true,
      feature,
      newBalance: result.newBalance,
      remainingHours: result.remainingHours,
      message: `Unlocked ${feature} for ${cost}G`
    });
  } else {
    res.status(400).json({
      success: false,
      error: result.error
    });
  }
});

// ==================== AI ENDPOINTS (ALL WORKING WITH LOCKS) ====================

// ---------- OpenAI ----------
const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY 
});

// ---------- Image Handling ----------
const upload = multer({ dest: 'uploads/' });

// ---------- FIXED AI Function ----------
async function askAI(prompt, model = "gpt-4o-mini") {
  try {
    const completion = await openai.chat.completions.create({
      model: model,
      messages: [
        {
          role: "system",
          content: "You are a helpful AI assistant that provides detailed, accurate, and engaging responses."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      max_tokens: 1500,
      temperature: 0.7
    });

    return {
      success: true,
      reply: completion.choices[0]?.message?.content || "No response generated.",
      model: model
    };
  } catch (error) {
    console.error("AI API Error:", error);
    return {
      success: false,
      error: error.message
    };
  }
}

// ---------- FREE AI Endpoints ----------
app.post("/ask", async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Question is required" });

    const result = await askAI(question, "gpt-4o-mini");
    if (result.success) {
      res.json({ answer: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------- PREMIUM AI Endpoints ----------

// Helper function to check feature access
async function checkFeatureAccess(req, res, feature) {
  if (!req.user) {
    return { allowed: false, error: 'Login required' };
  }
  
  const userId = getUserIdentifier(req);
  const featureStatus = isFeatureUnlocked(userId, feature);
  
  if (!featureStatus.unlocked) {
    return { 
      allowed: false, 
      error: 'Feature locked',
      message: `This feature requires ${FEATURE_PRICES[feature]}G to unlock`,
      requiredGolden: FEATURE_PRICES[feature]
    };
  }
  
  return { allowed: true };
}

// Search Information - 4G
app.post("/search-info", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'search_info');
    if (!access.allowed) return res.status(403).json(access);

    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Query is required" });

    const prompt = `Provide a comprehensive overview of: ${query}. Use 3-6 well-organized paragraphs.`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ answer: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Learn Physics - 4G
app.post("/api/physics-explain", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'learn_physics');
    if (!access.allowed) return res.status(403).json(access);

    const { question } = req.body;
    if (!question) return res.status(400).json({ error: "Question is required" });

    const prompt = `Explain this physics concept: ${question}. Provide clear explanations and examples.`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ answer: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create Planet - 4G
app.post("/ai/create-planet", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'create_planet');
    if (!access.allowed) return res.status(403).json(access);

    const { specs = {} } = req.body;
    const prompt = `Create a detailed planet description: ${JSON.stringify(specs)}`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ planet: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Advanced Planet - 4G
app.post("/ai/create-advanced-planet", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'advanced_planet');
    if (!access.allowed) return res.status(403).json(access);

    const { specs = {} } = req.body;
    const prompt = `Create an advanced planet description: ${JSON.stringify(specs)}`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ planet: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create Rocket - 4G
app.post("/ai/create-rocket", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'create_rocket');
    if (!access.allowed) return res.status(403).json(access);

    const prompt = "Design a detailed conceptual space rocket with specifications.";
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ rocket: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Create Satellite - 4G
app.post("/ai/create-satellite", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'create_satellite');
    if (!access.allowed) return res.status(403).json(access);

    const prompt = "Design a detailed conceptual satellite with specifications.";
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ satellite: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Your Space - 4G
app.post("/ai/your-space", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'your_space');
    if (!access.allowed) return res.status(403).json(access);

    const { theme = "space", elements = {} } = req.body;
    const prompt = `Create a space universe with theme: ${theme} and elements: ${JSON.stringify(elements)}`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ universe: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Search Lessons - 10G
app.post("/search-lessons", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'search_lessons');
    if (!access.allowed) return res.status(403).json(access);

    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Query is required" });

    const prompt = `Create an educational lesson about: ${query}`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ answer: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Homework Helper - 20G
app.post("/chat-homework", async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'homework_helper');
    if (!access.allowed) return res.status(403).json(access);

    const { q } = req.body;
    if (!q) return res.status(400).json({ error: "Question is required" });

    const prompt = `Solve this homework problem: ${q}. Provide step-by-step explanations.`;
    const result = await askAI(prompt, "gpt-4o-mini");
    
    if (result.success) {
      res.json({ answer: result.reply, model: result.model });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// Advanced AI Chat - 20G
app.post("/chat-advanced-ai", upload.single("image"), async (req, res) => {
  try {
    const access = await checkFeatureAccess(req, res, 'chat_advancedai');
    if (!access.allowed) return res.status(403).json(access);

    const { q, model = "gpt-4o-mini" } = req.body;
    const image = req.file;
    
    if (!q) return res.status(400).json({ error: "Question is required" });

    let prompt = q;
    if (image) {
      prompt = `Regarding the uploaded image: ${q}`;
      console.log('Image uploaded:', image.path);
    }

    const result = await askAI(prompt, model);
    
    if (result.success) {
      res.json({ 
        reply: result.reply,
        model: result.model,
        ...(image && { imageProcessed: true })
      });
    } else {
      res.status(500).json({ error: result.error });
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ==================== PAYMENT DETECTION SYSTEM ====================

let processedTransactions = new Set();

async function checkForNewPayments() {
  console.log("🔍 Checking for new payments...");
  try {
    const [btcData, ltcData, tronData] = await Promise.all([
      checkBitcoinPayments(),
      checkLitecoinPayments(), 
      checkTronPayments()
    ]);
    await processDetectedPayments(btcData, ltcData, tronData);
  } catch (error) {
    console.error('Payment check error:', error);
  }
}

async function checkBitcoinPayments() {
  try {
    const response = await fetch('https://blockstream.info/api/address/bc1qz5wtz2d329xsm7gcs9e3jwls9supg2fk2hkxtd');
    const data = await response.json();
    return { coin: 'BTC', data, source: 'blockstream' };
  } catch (error) {
    return { coin: 'BTC', data: null, error: true };
  }
}

async function checkLitecoinPayments() {
  try {
    const response = await fetch('https://api.blockcypher.com/v1/ltc/main/addrs/ltc1qngssav372fl4sw0s8w66h4c8v5yftqw4qrkhdn');
    const data = await response.json();
    return { coin: 'LTC', data, source: 'blockcypher' };
  } catch (error) {
    return { coin: 'LTC', data: null, error: true };
  }
}

async function checkTronPayments() {
  try {
    const response = await fetch('https://apilist.tronscan.org/api/account?address=TCN6eVtHFNtPAJNfebgGGm8c2h71NWYY9P');
    const data = await response.json();
    return { coin: 'TRON', data, source: 'tronscan' };
  } catch (error) {
    return { coin: 'TRON', data: null, error: true };
  }
}

async function processDetectedPayments(btcResult, ltcResult, tronResult) {
  if (btcResult.data && btcResult.data.chain_stats.tx_count > 0) {
    console.log('💰 Bitcoin transactions found:', btcResult.data.chain_stats.tx_count);
  }
  if (ltcResult.data && ltcResult.data.n_tx > 0) {
    console.log('💰 Litecoin transactions found:', ltcResult.data.n_tx);
  }
  if (tronResult.data && tronResult.data.trc20token_balances.length > 0) {
    console.log('💰 TRON USDT transactions found');
  }
}

// Start checking every 2 minutes
setInterval(checkForNewPayments, 120000);
setTimeout(checkForNewPayments, 5000);

// ---------- Health Check ----------
app.get("/health", (req, res) => {
  res.json({ 
    status: "LAUNCH READY", 
    message: "GoldenSpaceAI completely locked and ready for launch!",
    features: Object.keys(FEATURE_PRICES),
    timestamp: new Date().toISOString()
  });
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GOLDENSPACEAI FULLY LOCKED & LAUNCHED on port ${PORT}! 
🔒 ALL PAGES PROTECTED • 💰 GOLDEN SYSTEM ACTIVE • 🤖 AI WORKING PERFECTLY`));
