// index.js — Corrected Login -> Plan Selection -> Strict Gating Flow

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

// ---------- Plan definitions --- UPDATED ---
// This now includes all the feature flags for every plan.
const PLAN_LIMITS = {
  moon: {
    ask: 10, search: 5, physics: 0,
    learnPhysics: false, createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false
  },
  earth:{
    ask: 30, search: 20, physics: 5,
    learnPhysics: true, createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false
  },
  sun: {
    ask: Infinity, search: Infinity, physics: Infinity,
    learnPhysics: true, createPlanet: true, createRocket: true, createSatellite: true, yourSpace: true
  },
};

// --- UPDATED --- This function now returns null if a user has no plan.
function getPlan(req){ return (req.user && req.user.plan) || null; }
// ... (Your other usage tracking functions remain unchanged) ...
function getUsage(req,res){ /* ... your original code ... */ }
function enforceLimit(kind){ /* ... your original code ... */ }


// ---------- Helper: compute base URL dynamically ----------
function getBaseUrl(req){
  const proto = (req.headers["x-forwarded-proto"]||"").toString().split(",")[0] || req.protocol || "https";
  const host  = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
  return `${proto}://${host}`;
}

// ---------- Google OAuth --- UPDATED ---
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

app.get("/auth/google",(req,res,next)=>{
  const callbackURL = `${getBaseUrl(req)}/auth/google/callback`;
  passport.authenticate("google",{ scope:["profile","email"], callbackURL })(req,res,next);
});

// --- UPDATED GOOGLE CALLBACK: REDIRECTS TO PLANS PAGE ---
app.get("/auth/google/callback",
    passport.authenticate("google", {
        successRedirect: "/plans.html",
        failureRedirect: "/login.html",
    })
);

app.post("/logout",(req,res,next)=>{
  req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.json({ok:true})); });
});

// ---------- Public Login/Signup Page ----------
// This is your original code block, exactly as you provided it. It has not been changed.
app.get("/login.html",(req,res)=>{
  const appName="GoldenSpaceAI";
  const base=getBaseUrl(req);
  res.send(`<!doctype html>...`); // Your original login HTML is preserved.
});

// --- NEW --- API Endpoint to let users select and activate their plan.
app.post('/api/select-plan', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'You must be logged in to select a plan.' });
    }
    const { plan } = req.body;
    if (PLAN_LIMITS[plan]) {
        req.user.plan = plan; // This saves the selected plan to the user's session.
        return res.json({ success: true, message: `Plan activated: ${plan}` });
    }
    return res.status(400).json({ error: 'Invalid plan selected.' });
});

// --- UPDATED --- This security middleware now enforces the new login flow.
function authRequired(req,res,next){
  // Allow essential public and plan-selection pages to pass through
  const allowedPaths = ['/login.html', '/auth/google', '/plans.html', '/api/select-plan'];
  if (allowedPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

  // If the user is not logged in, force them to the login page.
  if (!req.isAuthenticated()) {
    return res.redirect("/login.html");
  }

  // If the user IS logged in but has NOT selected a plan yet, force them to the plans page.
  if (!getPlan(req)) {
      return res.redirect('/plans.html');
  }
  
  // If they are logged in and have a plan, they can proceed.
  next();
}
app.use(authRequired);

// ... (Your Paddle Webhook and other public routes can remain here) ...


// ---------- GATED PAGES --- UPDATED ---
// Your original gating logic is now applied to all feature pages to enforce plan limits.
app.get("/learn-physics.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan] || !PLAN_LIMITS[plan].learnPhysics){
    return res.status(403).send(`<html>...Upgrade Message...</html>`);
  }
  res.sendFile(path.join(__dirname,"learn-physics.html"));
});

app.get("/create-planet.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan] || !PLAN_LIMITS[plan].createPlanet){
    return res.status(403).send(`<html>...Upgrade Message...</html>`);
  }
  res.sendFile(path.join(__dirname,"create-planet.html"));
});

// Add all your other feature pages here with the same gating logic.
app.get("/create-rocket.html", (req, res) => {
    const plan = getPlan(req);
    if (!PLAN_LIMITS[plan] || !PLAN_LIMITS[plan].createRocket) {
        return res.status(403).send(`<html>...Upgrade Message...</html>`);
    }
    res.sendFile(path.join(__dirname, "create-rocket.html"));
});
// ... and so on for create-satellite.html, your-space.html, etc.


// ... (All your other routes like /api/me, AI routes, etc., remain here) ...


// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
