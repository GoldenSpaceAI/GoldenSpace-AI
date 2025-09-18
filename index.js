// index.js — GoldenSpaceAI (Updated with Strict Plan Flow and Gating)

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
import bodyParser from "body-parser";
import crypto from "crypto";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ---------- Sessions ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Plan definitions --- <<< UPDATE >>> ---
// This now includes all 5 plans with the exact permissions you specified.
const PLAN_LIMITS = {
  // Base Subscription Plans
  moon: {
    ask: 10, search: 5, learnPhysics: false,
    createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false,
    homeworkHelper: false, advancedChat: false, searchLessons: false,
  },
  earth: {
    ask: 30, search: 20, learnPhysics: true,
    createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false,
    homeworkHelper: false, advancedChat: false, searchLessons: false,
  },
  sun: {
    ask: Infinity, search: Infinity, learnPhysics: true,
    createPlanet: true, createRocket: false, createSatellite: false, yourSpace: false,
    homeworkHelper: false, advancedChat: false, searchLessons: false,
  },
  // Add-on Packs
  yourspace: { // This is the "Your Space Pack"
    ask: 0, search: 0, learnPhysics: false,
    createPlanet: true, createRocket: true, createSatellite: true, yourSpace: true,
    homeworkHelper: false, advancedChat: false, searchLessons: false,
  },
  chatai: { // This is the "ChatAI Pack"
    ask: 0, search: 0, learnPhysics: false,
    createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false,
    homeworkHelper: true, advancedChat: true, searchLessons: true,
  },
};

// --- <<< UPDATE >>> --- This now returns null if a user has not selected a plan.
function getPlan(req){ return (req.user && req.user.plan) || null; }
// ... (Your other usage tracking functions remain unchanged) ...
const usage = {};
const today = () => new Date().toISOString().slice(0,10);
function getUserKey(req, res){ /* Your original code */ }
function getUsage(req,res){ /* Your original code */ }
function enforceLimit(kind){ /* Your original code */ }


// ---------- Helper: compute base URL dynamically (Your Original Code) ----------
function getBaseUrl(req){ /* Your original code */ }

// ---------- Google OAuth --- <<< UPDATE >>> ---
// New users will have `plan: null` to force them to the plans page after login.
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback",
    proxy: true,
  },
  (accessToken, refreshToken, profile, done)=>{
    const user = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value || "",
      photo: profile.photos?.[0]?.value || "",
      plan: null, // <<< UPDATED: User has no plan when they first sign in.
    };
    return done(null, user);
  }
));
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((obj,done)=>done(null,obj));

app.get("/auth/google",(req,res,next)=>{  const callbackURL = `${getBaseUrl(req)}/auth/google/callback`; passport.authenticate("google",{ scope:["profile","email"], callbackURL })(req,res,next); });

// <<< UPDATE >>> After a user logs in, they are now redirected to the plans page.
app.get("/auth/google/callback",
    passport.authenticate("google", {
        successRedirect: "/plans.html",
        failureRedirect: "/login.html",
    })
);
app.post("/logout",(req,res,next)=>{ req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.json({ok:true})); }); });

// ---------- Public Login/Signup Page (Your Original Code) ----------
app.get("/login.html",(req,res)=>{ /* Your original code with res.send() is preserved here */ });

// --- <<< NEW >>> --- API Endpoint for the plans.html page to activate a plan.
app.post('/api/select-plan', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'You must be logged in.' });
    }
    const { plan } = req.body;
    if (PLAN_LIMITS[plan]) {
        req.user.plan = plan;
        return res.json({ success: true, message: `Plan activated: ${plan}` });
    }
    return res.status(400).json({ error: 'Invalid plan.' });
});

// ---------- PUBLIC / AUTH GATE --- <<< UPDATE >>> ---
// This middleware now enforces the entire "Login -> Plans -> Home" flow.
function authRequired(req,res,next){
  const publicPaths = ['/login.html', '/auth/google', '/health', '/plans.html', '/api/select-plan'];
  const isPublicFile = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i.test(req.path);
  
  if (isPublicFile || publicPaths.some(path => req.path.startsWith(path))) {
    return next();
  }
  if (!req.isAuthenticated()) {
    return res.redirect("/login.html");
  }
  if (!getPlan(req)) {
      return res.redirect('/plans.html');
  }
  next();
}
app.use(authRequired);


// ... (Your Paddle Webhook and alias redirects can remain here, unchanged) ...


// ---------- GATED PAGES --- <<< UPDATED >>> ---
// The strict blocking logic is now applied to all feature pages based on the new plan definitions.
function createGatedRoute(feature, filePath, upgradeMessage) {
    app.get(filePath, (req, res) => {
        const plan = getPlan(req);
        // We use the real getPlan() here which may be null. Default to a safe, no-permission object if so.
        const permissions = PLAN_LIMITS[plan] || {};
        if (permissions[feature]) {
            return res.sendFile(path.join(__dirname, filePath.substring(1))); // Use substring to remove leading slash
        }
        res.status(403).send(`
            <html><body style="font-family:sans-serif;text-align:center;margin-top:50px;color:#fff;background:#0b0f1a">
            <h2>🚀 Feature Locked!</h2><p>${upgradeMessage}</p>
            <p><a href="/plans.html" style="color:#f6c64a;font-weight:800">Change Your Plan</a></p></body></html>
        `);
    });
}

createGatedRoute('learnPhysics', '/learn-physics.html', 'This feature requires the Earth plan or higher.');
createGatedRoute('createPlanet', '/create-planet.html', 'This feature requires the Sun plan or the Your Space Pack.');
createGatedRoute('createRocket', '/create-rocket.html', 'This feature requires the Your Space Pack.');
createGatedRoute('createSatellite', '/create-satellite.html', 'This feature requires the Your Space Pack.');
createGatedRoute('yourSpace', '/your-space.html', 'This feature requires the Your Space Pack.');
createGatedRoute('homeworkHelper', '/homework-helper.html', 'This feature requires the ChatAI Pack.');
createGatedRoute('advancedChat', '/advanced-ai.html', 'This feature requires the ChatAI Pack.');
createGatedRoute('searchLessons', '/search-lessons.html', 'This feature requires the ChatAI Pack.');


// ... (All your other routes like /api/me, AI routes, etc., remain here, unchanged) ...
// NOTE: Your original gated pages logic has been replaced by the createGatedRoute function above.
app.get("/api/me", (req, res) => { 
    const plan = getPlan(req) || 'moon'; // Default to moon for display purposes if null
    const limits = PLAN_LIMITS[plan];
    const u = getUsage(req,res);
    const remaining = { /* ... your original code ... */ };
    res.json({ loggedIn:!!req.user, user:req.user||null, plan, limits, used:u, remaining });
 });
app.post("/ask", enforceLimit("ask"), async (req, res) => { /* Your original code */ });
app.post("/search-info", enforceLimit("search"), async (req, res) => { /* Your original code */ });
app.post("/ai/physics-explain", enforceLimit("physics"), async (req, res) => { /* Your original code */ });
app.post("/api/select-free",(req,res)=>{ /* Your original code */ });


// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));

