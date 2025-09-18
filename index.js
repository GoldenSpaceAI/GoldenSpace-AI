// index.js — GoldenSpaceAI (Gemini connected everywhere + safe checks)

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

// ---------- Plan Limits ----------
const PLAN_LIMITS = {
  moon:      { chatAI: 20, search: 5, physics: 0 },
  earth:     { chatAI: 30, search: 20, physics: 5 },
  sun:       { chatAI: Infinity, search: Infinity, physics: Infinity, createPlanet: true, createAdvancedPlanet: true },
  chatai:    { chatAI: Infinity, advancedChatAI: Infinity, homeworkSolver: Infinity, lessonSearcher: Infinity },
  yourspace: { createAdvancedPlanet: true, satellite: true, rocket: true },
};

// ---------- Usage Tracking ----------
const usage = {};
const today = () => new Date().toISOString().slice(0,10);

function getUserKey(req,res){
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
  if (!usage[key] || usage[key].date !== d) usage[key] = { date:d, chatAI:0, search:0, physics:0 };
  return usage[key];
}
function enforceLimit(kind){
  return (req,res,next)=>{
    const plan = getPlan(req);
    const limits = PLAN_LIMITS[plan] || {};
    const u = getUsage(req,res);
    const allowed = limits[kind];
    if (!allowed) return res.status(403).json({ error:`Your plan does not allow ${kind}.` });
    if (Number.isFinite(allowed) && u[kind] >= allowed) return res.status(429).json({ error:`Daily ${kind} limit reached for ${plan} plan.` });
    if (Number.isFinite(allowed)) u[kind]++;
    next();
  };
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

// ---------- Gemini ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// ---------- Chat AI (default: Flash) ----------
app.post("/chat-ai", enforceLimit("chatAI"), async (req,res)=>{
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ answer:"Ask me something." });

    const model = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });
    const result = await model.generateContent([{ text:q }]);
    const answer = result?.response?.text?.() || "No response.";
    res.json({ answer });
  } catch(e){
    console.error("Chat AI error", e);
    res.status(500).json({ answer:"Gemini API error" });
  }
});

// ---------- Advanced AI (Flash or Pro selector) ----------
app.post("/advanced-chat-ai", async (req,res)=>{
  const plan = getPlan(req);
  if (plan !== "chatai") return res.status(403).json({ error:"Only Chat AI Pack users can access Advanced AI." });

  const { q, modelType } = req.body;
  if (!q) return res.status(400).json({ error:"Missing prompt." });

  const chosenModel = modelType === "pro" ? "gemini-1.5-pro" : "gemini-1.5-flash";

  try {
    const model = genAI.getGenerativeModel({ model: chosenModel });
    const result = await model.generateContent([{ text:q }]);
    const answer = result?.response?.text?.() || "No response.";
    res.json({ model: chosenModel, answer });
  } catch(e){
    console.error("Advanced AI error", e);
    res.status(500).json({ error:"Gemini API error" });
  }
});

// ---------- Info Search ----------
app.post("/search-info", enforceLimit("search"), async (req,res)=>{
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ answer:"Type something to search." });

    const prompt = `Overview with 3 bullet points about: ${q}`;
    const model = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });
    const result = await model.generateContent([{ text:prompt }]);
    const answer = result?.response?.text?.() || "No info found.";
    res.json({ answer });
  } catch(e){
    console.error("Search error", e);
    res.status(500).json({ answer:"Gemini API error" });
  }
});

// ---------- Learn Physics ----------
app.post("/learn-physics", enforceLimit("physics"), async (req,res)=>{
  try {
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ reply:"Ask a physics question." });

    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly.\nQuestion: ${q}`;
    const model = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });
    const result = await model.generateContent([{ text:prompt }]);
    const reply = result?.response?.text?.() || "No reply.";
    res.json({ reply });
  } catch(e){
    console.error("Physics error", e);
    res.status(500).json({ reply:"Gemini API error" });
  }
});

// ---------- Page Routes ----------
app.get("/chat-advancedai.html",(req,res)=>{
  if (getPlan(req)!=="chatai") return res.status(403).send("Only Chat AI Pack can access Advanced AI.");
  res.sendFile(path.join(__dirname,"chat-advancedai.html"));
});
app.get("/create-planet.html",(req,res)=>{
  if (!PLAN_LIMITS[getPlan(req)]?.createPlanet) return res.status(403).send("Upgrade to Sun Pack to unlock Create Planet.");
  res.sendFile(path.join(__dirname,"create-planet.html"));
});
app.get("/create-advanced-planet.html",(req,res)=>{
  const plan = getPlan(req);
  if (!(PLAN_LIMITS[plan]?.createAdvancedPlanet || plan==="yourspace"))
    return res.status(403).send("Only Sun Pack or Your Space Pack can unlock Create Advanced Planet.");
  res.sendFile(path.join(__dirname,"create-advanced-planet.html"));
});

// ---------- Select Plan (testing) ----------
app.post("/api/select-plan/:plan",(req,res)=>{
  const plan = req.params.plan;
  if (!PLAN_LIMITS[plan]) return res.status(400).json({ error:"Invalid plan" });
  if (req.user) req.user.plan = plan;
  if (req.session) req.session.plan = plan;
  res.json({ ok:true, plan });
});

// ---------- Profile Info ----------
app.get("/api/me",(req,res)=>{
  const plan = getPlan(req);
  const limits = PLAN_LIMITS[plan];
  const u = getUsage(req,res);

  const remaining = {
    chatAI: limits.chatAI===Infinity?Infinity:Math.max(0, limits.chatAI-u.chatAI),
    search: limits.search===Infinity?Infinity:Math.max(0, limits.search-u.search),
    physics: limits.physics===Infinity?Infinity:Math.max(0, limits.physics-u.physics),
  };

  res.json({
    loggedIn: !!req.user,
    user: req.user || null,
    plan,
    used: u,
    remaining,
  });
});

// ---------- Static ----------
app.use(express.static(__dirname));
app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"index.html")));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
