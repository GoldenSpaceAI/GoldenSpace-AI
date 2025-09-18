// index.js — GoldenSpaceAI (Login/Signup + Google OAuth + Plan Limits + Free Test Plans)

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

// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon:  { chatAI: 10, advancedChatAI: 1, homeworkSolver: 1, lessonSearcher: 1, special: false },
  earth: { chatAI: 30, advancedChatAI: 20, homeworkSolver: 5, lessonSearcher: 20, special: false },
  sun:   { chatAI: Infinity, advancedChatAI: Infinity, homeworkSolver: Infinity, lessonSearcher: Infinity, special: false },
  spade: { chatAI: 0, advancedChatAI: 0, homeworkSolver: 0, lessonSearcher: 0, special: true },
};

// ---------- Usage tracking (memory, resets daily) ----------
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
  if (!usage[key] || usage[key].date !== d) usage[key] = { date:d, chatAI:0, advancedChatAI:0, homeworkSolver:0, lessonSearcher:0 };
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
const model = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });

// ---------- AI Routes ----------
app.post("/chat-ai", enforceLimit("chatAI"), async (req,res)=>{
  try{
    const q = req.body?.q || "";
    const result = await model.generateContent([{ text:`User: ${q}` }]);
    res.json({ answer: result.response.text() });
  }catch(e){ res.status(500).json({ answer:"ChatAI error" }); }
});
app.post("/advanced-chat-ai", enforceLimit("advancedChatAI"), async (req,res)=>{
  try{
    const q = req.body?.q || "";
    const prompt = `You are Advanced GoldenSpaceAI. Answer deeply.\n${q}`;
    const result = await model.generateContent([{ text:prompt }]);
    res.json({ answer: result.response.text() });
  }catch(e){ res.status(500).json({ answer:"Advanced AI error" }); }
});
app.post("/homework-solver", enforceLimit("homeworkSolver"), async (req,res)=>{
  try{
    const q = req.body?.q || "";
    const prompt = `Solve the following homework step by step:\n${q}`;
    const result = await model.generateContent([{ text:prompt }]);
    res.json({ solution: result.response.text() });
  }catch(e){ res.status(500).json({ solution:"Homework error" }); }
});
app.post("/lesson-searcher", enforceLimit("lessonSearcher"), async (req,res)=>{
  try{
    const q = req.body?.q || "";
    const prompt = `Summarize this lesson clearly with 3 key points:\n${q}`;
    const result = await model.generateContent([{ text:prompt }]);
    res.json({ summary: result.response.text() });
  }catch(e){ res.status(500).json({ summary:"Lesson search error" }); }
});

// ---------- Spade special routes ----------
app.get("/castle-your-universe",(req,res)=>{
  if (getPlan(req)!=="spade") return res.status(403).send("Upgrade to Spade to access Castle Your Universe.");
  res.send("<h1>🏰 Welcome to Castle Your Universe!</h1>");
});
app.get("/satellite",(req,res)=>{
  if (getPlan(req)!=="spade") return res.status(403).send("Upgrade to Spade to access Satellite.");
  res.send("<h1>🛰️ Satellite Control</h1>");
});
app.get("/rocket",(req,res)=>{
  if (getPlan(req)!=="spade") return res.status(403).send("Upgrade to Spade to access Rocket.");
  res.send("<h1>🚀 Rocket Launch</h1>");
});
app.get("/planets",(req,res)=>{
  if (getPlan(req)!=="spade") return res.status(403).send("Upgrade to Spade to access Planets.");
  res.send("<h1>🪐 Planetary Lab</h1>");
});

// ---------- Free Plan Select (no payment) ----------
app.post("/api/select-plan/:plan",(req,res)=>{
  const plan = req.params.plan;
  if (!PLAN_LIMITS[plan]) return res.status(400).json({ error:"Invalid plan" });
  if (req.user) req.user.plan = plan;
  if (req.session) req.session.plan = plan;
  res.json({ ok:true, plan });
});

// ---------- Static & Home ----------
// Serve static files like index.html
app.use(express.static(__dirname));

// Default route -> send index.html
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
