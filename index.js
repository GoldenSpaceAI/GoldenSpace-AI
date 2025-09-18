// index.js — GoldenSpaceAI (Login/Signup + Google OAuth + Plan Limits + Paddle Webhook)

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
  moon: { ask: 10, search: 5, physics: 0,  learnPhysics: false, createPlanet: false },
  earth:{ ask: 30, search: 20, physics: 5,  learnPhysics: true,  createPlanet: false },
  sun:  { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true },
};

// ---------- Usage tracking (memory, resets daily) ----------
const usage = {}; // { userKey: { date, ask, search, physics } }
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
function getPlan(req){ return (req.user && req.user.plan) || req.session?.plan || "moon"; }
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
      plan: "moon",
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
app.get(DEFAULT_CALLBACK_PATH,(req,res,next)=>{
  const callbackURL = `${getBaseUrl(req)}${DEFAULT_CALLBACK_PATH}`;
  passport.authenticate("google",{ failureRedirect:"/login.html", callbackURL })(req,res,()=>res.redirect("/"));
});
app.post("/logout",(req,res,next)=>{
  req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.json({ok:true})); });
});

// ---------- Public Login/Signup Page ----------
app.get("/login.html",(req,res)=>{
  const appName="GoldenSpaceAI";
  const base=getBaseUrl(req);
  res.send(`<!doctype html><html lang="en"><head> ... (unchanged) ... </html>`);
});

// ---------- PUBLIC / AUTH GATE ----------
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(req){
  const p = req.path;
  if (p === "/login.html") return true;
  if (p === "/terms.html") return true;
  if (p === "/privacy.html") return true;
  if (p === "/health") return true;
  if (p === "/webhooks/paddle") return true;
  if (p.startsWith("/auth/google")) return true;
  if (PUBLIC_FILE_EXT.test(p)) return true;
  if (p === "/favicon.ico") return true;
  return false;
}
function authRequired(req,res,next){
  if (isPublicPath(req)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error:"Sign in required" });
}

// ---------- Paddle Webhook (PUBLIC) ----------
const upgradesByEmail = {}; 
app.post("/webhooks/paddle",
  bodyParser.raw({ type: "*/*" }),
  (req,res)=>{ ... }
);

app.use(authRequired);

// ---------- Alias/redirects ----------
app.get("/terms.html", (_req,res)=>res.redirect("https://www.goldenspaceai.space/terms-of-service"));
app.get("/privacy.html", (_req,res)=>res.redirect("https://www.goldenspaceai.space/privacy"));

// ---------- Gemini ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });

// ---------- AI Routes ----------
app.post("/ask", enforceLimit("ask"), async (req,res)=>{ ... });
app.post("/search-info", enforceLimit("search"), async (req,res)=>{ ... });
app.post("/ai/physics-explain", enforceLimit("physics"), async (req,res)=>{ ... });

// ---------- Advanced Chat AI (with model selector) ----------
app.post("/chat-advanced-ai", async (req, res) => {
  try {
    const q = (req.body?.q || "").trim();
    const modelType = (req.body?.modelType || "flash").toLowerCase();
    if (!q) return res.json({ answer: "Ask me something." });

    const modelName = modelType === "pro" ? "gemini-1.5-pro" : "gemini-1.5-flash";
    const advModel = genAI.getGenerativeModel({ model: modelName });

    const result = await advModel.generateContent([{ text: q }]);
    const answer = result?.response?.text?.() || "No response.";
    res.json({ model: modelName, answer });
  } catch (e) {
    console.error("advanced-ai error", e);
    res.status(500).json({ answer: "Advanced AI error" });
  }
});

// ---------- Apply Paddle upgrades ----------
app.get("/api/me",(req,res)=>{ ... });

// ---------- Gated pages ----------
app.get("/learn-physics.html",(req,res)=>{ ... });
app.get("/create-planet.html",(req,res)=>{ ... });

// ---------- Select free plan ----------
app.post("/api/select-free",(req,res)=>{ ... });

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
