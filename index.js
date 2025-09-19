// index.js — GoldenSpaceAI (Gemini for ask/search, OpenAI for advanced chat)
// - Home is public first page; login.html unchanged
// - 20-message session memory for chat-advancedai.html & advanced-ai.html
// - Image upload to /chat-advanced-ai fixed (multer memory storage + proper OpenAI payload)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import multer from "multer";
import OpenAI from "openai";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();

const app = express();
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "25mb" }));
app.use(bodyParser.urlencoded({ extended: true }));
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
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  }),
);

app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- Plans & usage (unchanged limits) ----------
const PLAN_LIMITS = {
  moon: { ask: 10, search: 5, physics: 0,  learnPhysics: false, createPlanet: false },
  earth:{ ask: 30, search: 20, physics: 5,  learnPhysics: true,  createPlanet: false },
  sun:  { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true },
};
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

// ---------- Google OAuth (login.html left as-is) ----------
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
      plan: "moon",
    };
    return done(null, user);
  }
));
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((obj,done)=>done(null,obj));

app.get("/auth/google", passport.authenticate("google",{ scope:["profile","email"] }));
app.get("/auth/google/callback",
  passport.authenticate("google",{ failureRedirect:"/login.html" }),
  (_req,res)=>res.redirect("/")
);
app.post("/logout",(req,res,next)=>{
  req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.json({ok:true})); });
});

app.get("/login.html",(req,res)=> res.sendFile(path.join(__dirname,"login.html")));

// ---------- Public gate (home + legal pages public) ----------
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(p){
  if (p === "/") return true;
  if (p === "/login.html" || p === "/terms.html" || p === "/privacy.html" || p === "/refund.html") return true;
  if (p.startsWith("/auth/google")) return true;
  if (p === "/favicon.ico" || p === "/health") return true;
  if (PUBLIC_FILE_EXT.test(p)) return true;
  return false;
}
function authRequired(req,res,next){
  if (isPublicPath(req.path)) return next();
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) return res.redirect("/login.html");
  return res.status(401).json({ error:"Sign in required" });
}

// ---------- AI clients ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
// default cheap OpenAI chat model used below
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";

// ---------- Session memory (per page, last 20 messages) ----------
function ensureMem(req){
  if (!req.session.chatMem) {
    req.session.chatMem = { advA: [], advB: [] }; // A=chat-advancedai, B=advanced-ai
  }
  return req.session.chatMem;
}
function pushMem(req, key, role, content){
  const mem = ensureMem(req)[key];
  mem.push({ role, content });
  while (mem.length > 20) mem.shift();
}
function readMem(req, key){
  return ensureMem(req)[key];
}

// ---------- Gemini routes (unchanged features) ----------
app.post("/ask", enforceLimit("ask"), async (req,res)=>{
  try{
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer:"Ask me anything!" });
    const result = await geminiFlash.generateContent([{ text:`User: ${q}` }]);
    const answer = result.response.text() || "No response.";
    res.json({ answer });
  }catch(e){ console.error("ask error", e); res.status(500).json({ answer:"Gemini error" }); }
});

app.post("/search-info", enforceLimit("search"), async (req,res)=>{
  try{
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer:"Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  }catch(e){ console.error("search-info error", e); res.status(500).json({ answer:"Search error" }); }
});

// ---------- Advanced Chat A: /chat-advanced-ai (text + optional image) ----------
const uploadMemory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});
app.post("/chat-advanced-ai", uploadMemory.single("file"), async (req,res)=>{
  try{
    const q = (req.body?.q || "").trim();
    const hasImage = !!req.file;

    if (!q && !hasImage) return res.json({ answer:"Ask me something." });

    // store user input
    if (q) pushMem(req, "advA", "user", q);

    // build message with system + history + new user content
    const history = readMem(req, "advA");
    const contentParts = [];
    if (q) contentParts.push({ type: "text", text: q });
    if (hasImage){
      const mime = req.file.mimetype || "image/png";
      const b64 = req.file.buffer.toString("base64");
      const url = `data:${mime};base64,${b64}`;
      contentParts.push({ type: "image_url", image_url: { url } });
    }

    const messages = [
      {
        role: "system",
        content:
          "You are GoldenSpace Advanced AI. Use the prior conversation context to answer follow-up questions.",
      },
      ...history,
      { role: "user", content: contentParts },
    ];

    const completion = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      messages,
    });

    const answer = completion.choices?.[0]?.message?.content || "No response.";
    pushMem(req, "advA", "assistant", answer);
    res.json({ model: OPENAI_MODEL, answer });
  }catch(e){
    console.error("chat-advanced-ai error", e);
    res.status(500).json({ answer:"Advanced AI error" });
  }
});

// ---------- Advanced Chat B: /api/advanced-ai (text only by default) ----------
app.post("/api/advanced-ai", async (req,res)=>{
  try{
    const q = (req.body?.q || "").trim();
    if (!q) return res.json({ answer:"Ask me something." });

    pushMem(req, "advB", "user", q);

    const history = readMem(req, "advB");
    const messages = [
      {
        role: "system",
        content:
          "You are GoldenSpace Advanced AI (page B). Use the prior turns to maintain context.",
      },
      ...history,
      { role: "user", content: q },
    ];

    const completion = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      messages,
    });

    const answer = completion.choices?.[0]?.message?.content || "No response.";
    pushMem(req, "advB", "assistant", answer);
    res.json({ model: OPENAI_MODEL, answer });
  }catch(e){
    console.error("advanced-ai (B) error", e);
    res.status(500).json({ answer:"Advanced AI error" });
  }
});

// ---------- /api/me (minimal info; unchanged) ----------
app.get("/api/me",(req,res)=>{
  const plan = getPlan(req);
  const limits = PLAN_LIMITS[plan];
  const u = getUsage(req,res);
  const remaining = {
    ask: limits.ask===Infinity?Infinity:Math.max(0, limits.ask-u.ask),
    search: limits.search===Infinity?Infinity:Math.max(0, limits.search-u.search),
    physics: limits.physics===Infinity?Infinity:Math.max(0, limits.physics-u.physics),
  };
  const profile = req.user ? {
    email: req.user.email,
    name: req.user.name,
    picture: req.user.photo,
  } : null;
  res.json({ loggedIn:!!req.user, user:profile, plan, limits, used:u, remaining });
});

// ---------- Static & Health ----------
app.use(express.static(__dirname));     // serves index.html as the first page
app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI on ${PORT} (OpenAI=${OPENAI_MODEL})`));
