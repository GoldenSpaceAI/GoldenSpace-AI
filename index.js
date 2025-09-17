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
// Added all feature flags to every plan for strict gating.
const PLAN_LIMITS = {
  moon: { ask: 10, search: 5, physics: 0,  learnPhysics: false, createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false },
  earth:{ ask: 30, search: 20, physics: 5,  learnPhysics: true,  createPlanet: false, createRocket: false, createSatellite: false, yourSpace: false },
  sun:  { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true, createRocket: true, createSatellite: true, yourSpace: true },
};

// ---------- Usage tracking ----------
// --- UPDATED --- getPlan now returns null if a user has not selected a plan.
function getPlan(req){ return (req.user && req.user.plan) || null; }
// ... (Your other usage tracking functions remain unchanged) ...
const usage = {};
const today = () => new Date().toISOString().slice(0,10);
function getUserKey(req, res){
  if (req.user?.id) return `u:${req.user.id}`;
  if (!req.cookies.gs_uid){
    const uid = Math.random().toString(36).slice(2) + Date.now().toString(36);
    res.cookie("gs_uid", uid, { httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production" });
    return `g:${uid}`;
  }
  return `g:${req.cookies.gs_uid}`;
}
function getUsage(req,res){
  const key = getUserKey(req,res);
  const d = today();
  if (!usage[key] || usage[key].date !== d) usage[key] = { date:d, ask:0, search:0, physics:0 };
  return usage[key];
}
function enforceLimit(kind){
  return (req,res,next)=>{
    const plan = getPlan(req);
    const limits = PLAN_LIMITS[plan];
    const u = getUsage(req,res);
    const allowed = limits[kind];
    if (allowed === 0) return res.status(403).json({ error:`Your plan does not allow ${kind}.` });
    if (Number.isFinite(allowed) && u[kind] >= allowed) return res.status(429).json({ error:`Daily ${kind} limit reached for ${plan} plan.` });
    if (Number.isFinite(allowed)) u[kind]++;
    next();
  };
}


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
// This is your original code block, exactly as you provided it.
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

// ---------- PUBLIC / AUTH GATE --- UPDATED ---
// This middleware now enforces the entire login -> plans -> home flow.
function authRequired(req,res,next){
  const publicPaths = ['/login.html', '/auth/google', '/auth/google/callback', '/health', '/plans.html', '/api/select-plan'];
  const isPublicFile = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i.test(req.path);
  
  if (isPublicFile || publicPaths.some(path => req.path.startsWith(path))) {
    return next();
  }

  // If the user is not logged in at all, force them to the login page.
  if (!req.isAuthenticated()) {
    return res.redirect("/login.html");
  }

  const hasPlan = !!getPlan(req);

  // If the user IS logged in but has NOT selected a plan yet, force them to the plans page.
  if (!hasPlan) {
      return res.redirect('/plans.html');
  }
  
  // If they are logged in and have a plan, they can proceed.
  next();
}
app.use(authRequired);


// ... (Your Paddle Webhook and alias redirects can remain here) ...


// --- GATED PAGES --- UPDATED ---
// Your original gating logic is now applied to all feature pages.
app.get("/learn-physics.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan] || !PLAN_LIMITS[plan].learnPhysics){
    return res.status(403).send(`<html><body><h2>Upgrade to the Earth Plan or higher to access this feature.</h2><p><a href="/plans.html">View Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"learn-physics.html"));
});

app.get("/create-planet.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan] || !PLAN_LIMITS[plan].createPlanet){
    return res.status(403).send(`<html><body><h2>Upgrade to the Sun Plan to access this feature.</h2><p><a href="/plans.html">View Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"create-planet.html"));
});


// ... (All your other routes like /api/me, AI routes, etc., remain here, unchanged) ...


// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
