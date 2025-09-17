// index.js — GoldenSpaceAI (Guest Access Enabled for Testing)

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

// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon: { ask: 10, search: 5, physics: 0, learnPhysics: false, createPlanet: false },
  earth:{ ask: 30, search: 20, physics: 5, learnPhysics: true,  createPlanet: false },
  sun:  { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true },
};

// ---------- Usage tracking ----------
// This will now use a cookie for guests or the user ID for logged-in users.
function getUserKey(req, res){
  if (req.user?.id) return `u:${req.user.id}`;
  if (!req.cookies.gs_uid){
    const uid = Math.random().toString(36).slice(2) + Date.now().toString(36);
    res.cookie("gs_uid", uid, { httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production" });
    return `g:${uid}`;
  }
  return `g:${req.cookies.gs_uid}`;
}
function getPlan(req){ return (req.user && req.user.plan) || "moon"; } // Guests get the moon plan by default

// ---------- Google OAuth ----------
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
      plan: "moon", // Default plan on sign-up
    };
    return done(null, user);
  }
));
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((obj,done)=>done(null,obj));

app.get("/auth/google", passport.authenticate("google",{ scope:["profile","email"]}));
app.get("/auth/google/callback", passport.authenticate("google",{ failureRedirect:"/login.html" }), (req,res) => res.redirect("/"));
app.post("/logout",(req,res,next)=>{
  req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.json({ok:true})); });
});

// ---------- Your Original Login Page ----------
app.get("/login.html",(req,res)=>{
  const appName="GoldenSpaceAI";
  // ... your full res.send() HTML for the login page goes here ...
});

// --- SECURITY ROUTER REMOVED FOR GUEST ACCESS/TESTING ---

// ---------- Gemini & AI Routes ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
// ... your AI routes (/ask, /search-info, etc.) remain here ...

// ---------- API Routes ----------
app.get("/api/me",(req,res)=>{
  res.json({ 
      loggedIn:!!req.user, 
      user:req.user||null, 
      plan: getPlan(req), 
  });
});

app.post('/api/save-universe', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'You must be logged in to save.' });
    }
    // ... save logic ...
    res.json({ success: true });
});

// ---------- Static File Serving ----------
app.use(express.static(__dirname));

// ---------- Start Server ----------
const PORT = process.env.PORT || 1000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on port ${PORT}`));
