// index.js — GoldenSpaceAI (Google OAuth + Plan Limits)
// Keeps Gemini for search/physics; OpenAI for advanced chat & homework helper (with images)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import { GoogleGenerativeAI } from "@google/generative-ai"; // Gemini kept
import bodyParser from "body-parser";
import crypto from "crypto";
import multer from "multer";

// OpenAI (for Advanced Chat AI + Homework Helper with images)
import OpenAI from "openai";
import fs from "fs/promises";

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

// ---------- Usage tracking ----------
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

// ---------- Helper: compute base URL ----------
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
  res.send(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${appName} — Log in or Sign up</title><link rel="icon" href="/favicon.ico"/>
<style>
:root{--bg:#0b0f1a;--card:#12182a;--gold:#f0c419;--text:#e6ecff;--muted:#9fb0d1}
*{box-sizing:border-box}body{margin:0;font-family:ui-sans-serif,system-ui,Segoe UI,Inter,Arial;background:radial-gradient(1200px 800px at 80% -10%,#1a2340 0%,#0b0f1a 60%,#070a12 100%);color:var(--text)}
.wrap{min-height:100dvh;display:grid;place-items:center;padding:24px}
.card{width:100%;max-width:520px;background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,.01));border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
h1{margin:0 0 6px;font-size:28px}.sub{margin:0 0 18px;font-size:14px;color:var(--muted)}
.features{margin:12px 0 22px;padding:0;list-style:none;display:grid;gap:10px}
.badge{display:inline-flex;gap:8px;background:rgba(240,196,25,.1);border:1px solid rgba(240,196,25,.35);padding:6px 10px;border-radius:999px;color:var(--gold);font-weight:600;font-size:12px;margin-bottom:10px}
.btn{display:flex;align-items:center;gap:10px;justify-content:center;width:100%;padding:12px 16px;border-radius:12px;border:none;font-size:16px;font-weight:700;cursor:pointer;background:var(--gold);color:#1a1a1a;transition:transform .06s ease, box-shadow .2s ease}
.btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(240,196,25,.35)}
.google{background:#fff;color:#1f2937;border:1px solid rgba(0,0,0,.08)}
.or{display:flex;align-items:center;gap:12px;color:var(--muted);font-size:12px;margin:12px 0}
.or:before,.or:after{content:"";flex:1;height:1px;background:rgba(255,255,255,.12)}
.fine{margin-top:14px;color:var(--muted);font-size:12px}
.links{display:flex;gap:16px;margin-top:10px}a{color:var(--text)}
</style></head><body><div class="wrap"><div class="card">
<div class="badge">✨ Welcome, explorer</div>
<h1>Log in or Sign up</h1>
<p class="sub">Access ${appName}: ask AI about space, learn physics, and create your own planets.</p>
<ul class="features"><li>🚀 Ask Advanced AI (daily limits based on your plan)</li><li>📚 Learn Physics</li><li>🪐 Create custom planets (Sun Pack)</li></ul>
<div class="or">continue</div>
<button class="btn google" onclick="window.location='${base}/auth/google'">
<img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" width="18" height="18" style="display:inline-block"/> Continue with Google
</button>
<p class="fine">By continuing, you agree to our
<a href="https://www.goldenspaceai.space/terms-of-service" target="_blank" rel="noopener">Terms</a> and
<a href="https://www.goldenspaceai.space/privacy" target="_blank" rel="noopener">Privacy</a>.</p>
<div class="links"><a href="/">Back to home</a><a href="/plans.html">See plans</a></div>
</div></div></body></html>`);
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

// ---------- Gemini (kept for search / learn physics / lessons) ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const modelFlash = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });
const modelPro = genAI.getGenerativeModel({ model:"gemini-1.5-pro" });

// ---------- AI Routes (Gemini stays) ----------
app.post("/ask", enforceLimit("ask"), async (req,res)=>{
  try{
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer:"Ask me anything!" });
    const result = await modelFlash.generateContent([{ text:`User: ${q}` }]);
    const answer = result.response.text() || "No response.";
    res.json({ answer });
  }catch(e){ console.error("ask error", e); res.status(500).json({ answer:"Gemini error" }); }
});

app.post("/search-info", enforceLimit("search"), async (req,res)=>{
  try{
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer:"Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await modelFlash.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  }catch(e){ console.error("search-info error", e); res.status(500).json({ answer:"Search error" }); }
});

app.post("/ai/physics-explain", enforceLimit("physics"), async (req,res)=>{
  try{
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply:"Ask a physics question." });
    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly.\nQuestion: ${q}`;
    const result = await modelFlash.generateContent([{ text: prompt }]);
    const reply = result.response.text() || "No reply.";
    res.json({ reply });
  }catch(e){ console.error("physics error", e); res.status(500).json({ reply:"Physics error" }); }
});

// ---------- Advanced Chat AI (OpenAI) + Homework Helper (images) ----------
const upload = multer({ dest: "uploads/" });
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// cheapest GPT-4 family default; supports vision
const DEFAULT_OPENAI_MODEL = process.env.DEFAULT_OPENAI_MODEL || "gpt-4o-mini";
const ALLOWED_OPENAI_MODELS = new Set(["gpt-4o-mini", "gpt-4o", "gpt-4.1"]);

// helper: convert uploaded image file to data URL
async function fileToDataUrl(file) {
  const buf = await fs.readFile(file.path);
  const b64 = buf.toString("base64");
  const mime = file.mimetype || "image/jpeg";
  return `data:${mime};base64,${b64}`;
}

// Build a vision-capable user message content with text + images
async function buildUserContentParts(messageText, imageFiles) {
  const parts = [];
  if (messageText) {
    parts.push({ type: "text", text: messageText });
  }
  for (const f of imageFiles) {
    if (!f.mimetype?.startsWith("image/")) continue;
    const url = await fileToDataUrl(f);
    parts.push({
      type: "image_url",
      image_url: { url }
    });
  }
  return parts;
}

// Preferred route used by homework-helper.html
app.post("/api/chat", upload.array("files"), enforceLimit("ask"), async (req, res) => {
  const cleanup = async () => {
    // remove temp uploads
    await Promise.allSettled((req.files || []).map(f => fs.unlink(f.path)));
  };

  try {
    const userMessageText = (req.body?.message || "").trim();
    const requestedModel = (req.body?.model || DEFAULT_OPENAI_MODEL).trim();
    const model = ALLOWED_OPENAI_MODELS.has(requestedModel) ? requestedModel : DEFAULT_OPENAI_MODEL;

    const contentParts = await buildUserContentParts(userMessageText, req.files || []);

    if (contentParts.length === 0) {
      await cleanup();
      return res.status(400).json({ reply: "Please attach an image or write a message." });
    }

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are GoldenSpaceAI. Be clear, step-by-step, and helpful for homework. Show reasoning steps cleanly." },
        { role: "user", content: contentParts }
      ],
      temperature: 0.4,
      max_tokens: 900
    });

    const reply = completion.choices?.[0]?.message?.content || "No reply.";
    await cleanup();
    res.json({ reply, model });
  } catch (e) {
    console.error("api/chat error", e);
    await cleanup();
    res.status(500).json({ reply: "OpenAI error" });
  }
});

// Keep legacy route name too; supports text + single image
app.post("/chat-advanced-ai", upload.single("file"), enforceLimit("ask"), async (req,res)=>{
  const cleanup = async () => {
    if (req.file?.path) {
      await fs.unlink(req.file.path).catch(()=>{});
    }
  };

  try{
    const q = (req.body?.q || "").trim();
    const modelType = (req.body?.modelType || "").toLowerCase();
    const map = { pro: "gpt-4.1", flash: "gpt-4o-mini", gpt4: "gpt-4.1" };
    const requested = map[modelType] || DEFAULT_OPENAI_MODEL;
    const model = ALLOWED_OPENAI_MODELS.has(requested) ? requested : DEFAULT_OPENAI_MODEL;

    const parts = await buildUserContentParts(q, req.file ? [req.file] : []);
    if (parts.length === 0) {
      await cleanup();
      return res.json({ model, answer: "Ask me something or attach an image." });
    }

    const completion = await openai.chat.completions.create({
      model,
      messages: [
        { role: "system", content: "You are GoldenSpaceAI. Be concise and expert; if an image is provided, read it carefully." },
        { role: "user", content: parts }
      ],
      temperature: 0.6,
      max_tokens: 900
    });

    const answer = completion.choices?.[0]?.message?.content || "No response.";
    await cleanup();
    res.json({ model, answer });
  }catch(e){
    console.error("advanced-ai error", e);
    await cleanup();
    res.status(500).json({ answer:"Advanced AI error" });
  }
});

// ---------- Apply Paddle upgrades when user hits API ----------
const upgradesByEmail = {}; // ensure exists
app.get("/api/me",(req,res)=>{
  if (req.user?.email){
    const up = upgradesByEmail[req.user.email.toLowerCase()];
    if (up && (req.user.plan !== up || req.session?.plan !== up)){
      req.user.plan = up;
      if (req.session) req.session.plan = up;
    }
  }
  const plan = getPlan(req);
  const limits = PLAN_LIMITS[plan];
  const u = getUsage(req,res);
  const remaining = {
    ask: limits.ask===Infinity?Infinity:Math.max(0, limits.ask-u.ask),
    search: limits.search===Infinity?Infinity:Math.max(0, limits.search-u.search),
    physics: limits.physics===Infinity?Infinity:Math.max(0, limits.physics-u.physics),
  };
  res.json({ loggedIn:!!req.user, user:req.user||null, plan, limits, used:u, remaining });
});

// ---------- Gated pages ----------
app.get("/learn-physics.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].learnPhysics){
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
      <h2>🚀 Upgrade to the <span style="color:gold">Earth Pack</span> to unlock Learn Physics!</h2>
      <p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"learn-physics.html"));
});

app.get("/create-planet.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].createPlanet){
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
      <h2>🌍 Upgrade to the <span style="color:orange">Sun Pack</span> to unlock Create Planet!</h2>
      <p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"create-planet.html"));
});

// ---------- Select free plan ----------
app.post("/api/select-free",(req,res)=>{
  if (req.user) req.user.plan = "moon";
  if (req.session) req.session.plan = "moon";
  res.json({ ok:true, plan:"moon" });
});

// ---------- Static & Health ----------
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
