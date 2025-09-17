// index.js — GoldenSpaceAI (Login -> Plan Selection -> Main Page Flow with Strict Gating)

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

// ---------- Plan definitions with ALL feature flags----------
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

// ---------- Usage tracking ----------
function getPlan(req){ return (req.user && req.user.plan) || "moon"; } // Guests default to moon, but will be blocked
// ... (Your other usage tracking functions) ...

// ---------- Helper: compute base URL dynamically ----------
function getBaseUrl(req){
  const proto = (req.headers["x-forwarded-proto"]||"").toString().split(",")[0] || req.protocol || "https";
  const host  = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
  return `${proto}://${host}`;
}

// ---------- Google OAuth ----------
const DEFAULT_CALLBACK_PATH = "/auth/google/callback";
passport.use(new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: DEFAULT_CALLBACK_PATH,
    proxy: true,
  },
  (accessToken, refreshToken, profile, done)=>{
    const user = {
      id: profile.id,
      name: profile.displayName,
      email: profile.emails?.[0]?.value || "",
      photo: profile.photos?.[0]?.value || "",
      plan: null, // User has no plan on initial login
    };
    return done(null, user);
  }
));
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((obj,done)=>done(null,obj));

app.get("/auth/google",(req,res,next)=>{
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google",{ scope:["profile","email"], callbackURL })(req,res,next);
});

// --- UPDATED GOOGLE CALLBACK: REDIRECTS TO PLANS PAGE ---
app.get(DEFAULT_CALLBACK_PATH,
    passport.authenticate("google", {
        successRedirect: "/plans.html",
        failureRedirect: "/login.html",
    })
);

app.post("/logout",(req,res,next)=>{
  req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.json({ok:true})); });
});

// ---------- Public Login/Signup Page ----------
app.get("/login.html",(req,res)=>{
  const appName="GoldenSpaceAI";
  const base=getBaseUrl(req);
  res.send(`<!doctype html>...`); // Your original login HTML here for brevity
});

// --- NEW API ENDPOINT to select a plan ---
app.post('/api/select-plan', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'You must be logged in to select a plan.' });
    }
    const { plan } = req.body;
    if (PLAN_LIMITS[plan]) {
        req.user.plan = plan; // Set the plan on the user's session object
        return res.json({ success: true, message: `Plan activated: ${plan}` });
    }
    return res.status(400).json({ error: 'Invalid plan selected.' });
});

// ---------- PUBLIC / AUTH GATE ----------
// This still ensures a user must be logged in to access anything non-public
function authRequired(req,res,next){
  const publicPaths = ['/login.html', '/auth/google', '/auth/google/callback', '/health', '/plans.html', '/api/select-plan'];
  const isPublic = publicPaths.some(path => req.path.startsWith(path));
  if (isPublic) return next();

  if (req.isAuthenticated()) return next();
  
  return res.redirect("/login.html");
}
app.use(authRequired);


// --- NEW SECURITY MIDDLEWARE to gate pages by plan ---
function checkPlanPermission(feature) {
    return (req, res, next) => {
        const plan = getPlan(req); // Gets the user's activated plan
        if (PLAN_LIMITS[plan] && PLAN_LIMITS[plan][feature]) {
            return next(); // Permission granted, proceed to the page
        }
        // Permission denied, show upgrade message
        res.status(403).send(`
            <html>
            <body style="font-family:sans-serif;text-align:center;margin-top:50px;color:#fff;background:#0b0f1a">
                <h2>🚀 Feature Locked!</h2>
                <p>Your current plan does not grant access to this feature.</p>
                <p><a href="/plans.html" style="color:#f6c64a;font-weight:800">Upgrade Your Plan</a></p>
            </body>
            </html>
        `);
    };
}


// ---------- Gemini & AI Routes ----------
// Your AI routes remain here, they are protected by authRequired
// ... /ask, /search-info, etc. ...

// ---------- API /me Route ----------
app.get("/api/me",(req,res)=>{
  const plan = getPlan(req);
  res.json({ loggedIn:!!req.user, user:req.user||null, plan, limits: PLAN_LIMITS[plan] });
});

// ---------- GATED FEATURE PAGES ----------
// Each page now has the checkPlanPermission middleware applied
app.get("/learn-physics.html", checkPlanPermission('learnPhysics'), (req,res) => {
  res.sendFile(path.join(__dirname,"learn-physics.html"));
});
app.get("/create-planet.html", checkPlanPermission('createPlanet'), (req,res) => {
  res.sendFile(path.join(__dirname,"create-planet.html"));
});
// Add all your other feature pages here with the correct permission check:
app.get("/create-rocket.html", checkPlanPermission('createRocket'), (req,res) => {
  res.sendFile(path.join(__dirname,"create-rocket.html"));
});
app.get("/create-satellite.html", checkPlanPermission('createSatellite'), (req,res) => {
  res.sendFile(path.join(__dirname,"create-satellite.html"));
});
app.get("/your-space.html", checkPlanPermission('yourSpace'), (req,res) => {
  res.sendFile(path.join(__dirname,"your-space.html"));
});

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
