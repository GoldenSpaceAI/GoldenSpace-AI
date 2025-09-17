// index.js — GoldenSpaceAI (Login -> Plan Selection -> Strict Gating Flow)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

// --- 1. CORE APP SETUP ---
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || "a-very-strong-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
}));
app.use(passport.initialize());
app.use(passport.session());

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- 2. PLAN DEFINITIONS & PERMISSIONS ---
const PLAN_LIMITS = {
    moon: {
        ask: 20, search: 5,
        learnPhysics: false, createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false,
    },
    earth: {
        ask: 50, search: 20,
        learnPhysics: true, createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false,
    },
    sun: {
        ask: Infinity, search: Infinity,
        learnPhysics: true, createPlanet: true, createRocket: true, createSatellite: true, yourSpace: true,
    },
};

function getPlan(req) {
    return (req.user && req.user.plan) || null; // Return null if no plan is set
}

// --- 3. AUTHENTICATION (PASSPORT & GOOGLE OAUTH) ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
    proxy: true,
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value || "",
      photo: profile.photos?.[0]?.value || "",
      plan: null, // User has no plan upon first login
    };
    return done(null, user);
  }
));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- Auth Routes ---
app.get("/auth/google", passport.authenticate("google", { scope:["profile", "email"] }));

// After login, redirect to the plans page
app.get("/auth/google/callback",
    passport.authenticate("google", {
        successRedirect: "/plans.html", // <<< REDIRECTS TO PLANS PAGE
        failureRedirect: "/login.html",
    })
);

app.post("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(()=>res.redirect('/login.html'));
  });
});

// --- 4. PLAN SELECTION API ---
app.post('/api/select-plan', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'You must be logged in.' });
    }
    const { plan } = req.body;
    if (PLAN_LIMITS[plan]) {
        req.user.plan = plan; // Set plan on the user object
        res.json({ success: true, message: `Plan set to ${plan}` });
    } else {
        res.status(400).json({ error: 'Invalid plan selected.' });
    }
});

// --- 5. SECURITY MIDDLEWARE TO MANAGE USER FLOW & ENFORCE PLAN LIMITS ---
app.use((req, res, next) => {
    const publicPaths = ['/login.html', '/auth/google', '/auth/google/callback', '/health'];
    if (publicPaths.some(path => req.path.startsWith(path))) {
        return next();
    }

    if (!req.isAuthenticated()) {
        return res.redirect('/login.html');
    }

    if (!getPlan(req)) { // If user is logged in but has no plan
        if (req.path === '/plans.html' || req.path === '/api/select-plan') {
            return next(); // Allow access only to the plans page and its API
        }
        return res.redirect('/plans.html'); // Force all other requests to the plans page
    }

    next(); // User is logged in and has a plan, proceed
});

function checkPlanPermission(feature) {
    return (req, res, next) => {
        const plan = getPlan(req);
        if (plan && PLAN_LIMITS[plan] && PLAN_LIMITS[plan][feature]) {
            return next(); // User has permission, continue to the page
        }

        // User does NOT have permission, block them.
        res.status(403).send(`
            <html lang="en">
            <head>
                <title>Access Denied</title>
                <style>
                    body { font-family: sans-serif; background-color: #0a0e15; color: #E2E8F0; text-align: center; padding-top: 50px; }
                    h1 { color: #f6c64a; } a { color: #38BDF8; font-weight: bold; }
                </style>
            </head>
            <body>
                <h1>🚀 Feature Locked!</h1>
                <p>Your current plan does not grant access to this feature.</p>
                <p><a href="/plans.html">View Plans</a> or <a href="/">Go to Homepage</a></p>
            </body>
            </html>
        `);
    };
}

// --- 6. API & AI ROUTES ---
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.get("/api/me", (req, res) => {
  res.json({ loggedIn: !!req.user, user: req.user || null, plan: getPlan(req) });
});

app.post("/ask", async (req, res) => {
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
    const { question } = req.body;
    const result = await model.generateContent(question);
    res.json({ answer: result.response.text() });
});

// --- 7. FEATURE PAGE ROUTES WITH STRICT ENFORCEMENT ---
app.get("/learn-physics.html", checkPlanPermission('learnPhysics'), (req, res) => {
    res.sendFile(path.join(__dirname, "learn-physics.html"));
});
app.get("/create-planet.html", checkPlanPermission('createPlanet'), (req, res) => {
    res.sendFile(path.join(__dirname, "create-planet.html"));
});
app.get("/create-rocket.html", checkPlanPermission('createRocket'), (req, res) => {
    res.sendFile(path.join(__dirname, "create-rocket.html"));
});
app.get("/create-satellite.html", checkPlanPermission('createSatellite'), (req, res) => {
    res.sendFile(path.join(__dirname, "create-satellite.html"));
});
app.get("/your-space.html", checkPlanPermission('yourSpace'), (req, res) => {
    res.sendFile(path.join(__dirname, "your-space.html"));
});

// --- 8. STATIC FILE SERVER & SERVER START ---
// Serves index.html, login.html, plans.html, CSS, etc.
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI is running on port ${PORT}`));
