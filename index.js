// index.js — GoldenSpaceAI (Google OAuth + Plan Limits)
// Chat with AI & Search Info via Gemini; Advanced/Physics/Homework via OpenAI

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

// ---------- Helper: base URL ----------
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
      given_name: profile.name?.givenName,
      email: profile.emails?.[0]?.value || "",
      picture: profile.photos?.[0]?.value || "",
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

// ---------- PUBLIC / AUTH GATE ----------
// Home and legal pages are PUBLIC. Feature pages show "Please sign in" if unauthenticated.
const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
function isPublicPath(req){
  const p = req.path;
  if (p === "/") return true;                     // Home is public
  if (p === "/login.html") return true;
  if (p === "/terms.html") return true;
  if (p === "/privacy.html") return true;
  if (p === "/refund.html") return true;
  if (p === "/health") return true;
  if (p === "/webhooks/paddle") return true;
  if (p.startsWith("/auth/google")) return true;
  if (PUBLIC_FILE_EXT.test(p)) return true;
  if (p === "/favicon.ico") return true;
  return false;
}
function requireSignInOrMessage(filePath){
  return (req,res)=>{
    if (req.isAuthenticated && req.isAuthenticated()){
      return res.sendFile(path.join(__dirname, filePath));
    }
    // Not signed in: show friendly message (no redirect)
    return res.status(200).send(`<!doctype html><html><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/><title>Sign in required</title>
<style>body{margin:0;background:#0b1020;color:#e7f4e9;font-family:Inter,system-ui,sans-serif;display:grid;place-items:center;min-height:100dvh}
.card{max-width:560px;background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.02));border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:22px;text-align:center}
a.btn{display:inline-block;margin-top:12px;padding:10px 14px;border-radius:12px;background:linear-gradient(180deg,#f6c64a,#eb8b36);color:#1b1300;font-weight:900;text-decoration:none}
a.ghost{display:inline-block;margin-top:12px;padding:10px 14px;border:1px solid #24314c;border-radius:12px;color:#cfc6a5;text-decoration:none}
</style></head><body>
<div class="card">
  <h2>🔐 Please sign in to use this feature</h2>
  <p>You can browse the homepage and legal pages without signing in.</p>
  <p><a class="btn" href="/auth/google">Continue with Google</a></p>
  <p><a class="ghost" href="/">Back to Home</a></p>
</div></body></html>`);
  };
}

// Gate key feature pages (others remain public/static)
app.get("/chat-advancedai.html", requireSignInOrMessage("chat-advancedai.html"));
app.get("/homework-helper.html", requireSignInOrMessage("homework-helper.html"));
app.get("/search-info.html", requireSignInOrMessage("search-info.html"));
app.get("/learn-physics.html", (req,res)=>{
  if (!(req.isAuthenticated && req.isAuthenticated())) {
    return requireSignInOrMessage("learn-physics.html")(req,res);
  }
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].learnPhysics){
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
      <h2>🚀 Upgrade to the <span style="color:gold">Earth Pack</span> to unlock Learn Physics!</h2>
      <p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"learn-physics.html"));
});
app.get("/create-planet.html", (req,res)=>{
  if (!(req.isAuthenticated && req.isAuthenticated())) {
    return requireSignInOrMessage("create-planet.html")(req,res);
  }
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].createPlanet){
    return res.send(`<html><body style="font-family:sans-serif;text-align:center;margin-top:50px;">
      <h2>🌍 Upgrade to the <span style="color:orange">Sun Pack</span> to unlock Create Planet!</h2>
      <p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"create-planet.html"));
});

// ---------- AI Clients ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const DEFAULT_MODEL = process.env.OPENAI_MODEL || "gpt-5-nano";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------- AI Routes ----------

// Chat with AI → Gemini
app.post("/ask", enforceLimit("ask"), async (req,res)=>{
  try{
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer:"Ask me anything!" });
    const result = await geminiFlash.generateContent([{ text: q }]);
    const answer = result.response.text() || "No response.";
    res.json({ model: "gemini-1.5-flash", answer });
  }catch(e){ console.error("ask error", e); res.status(500).json({ answer:"Gemini error" }); }
});

// Search Info → Gemini
app.post("/search-info", enforceLimit("search"), async (req,res)=>{
  try{
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer:"Type something to search." });
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ model: "gemini-1.5-flash", answer });
  }catch(e){ console.error("search-info error", e); res.status(500).json({ answer:"Gemini error" }); }
});

// Physics Tutor → OpenAI
app.post("/ai/physics-explain", enforceLimit("physics"), async (req,res)=>{
  try{
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ reply:"Ask a physics question." });
    const prompt = `You are GoldenSpace Physics Tutor. Explain clearly for a student.\nQuestion: ${q}`;
    const r = await openai.responses.create({ model: DEFAULT_MODEL, input: prompt });
    const reply = r.output_text || "No reply.";
    res.json({ model: DEFAULT_MODEL, reply });
  }catch(e){ console.error("physics error", e); res.status(500).json({ reply:"Physics error" }); }
});

// Advanced AI (text + optional single image) → OpenAI
const upload = multer({ dest: "uploads/" });
app.post("/chat-advanced-ai", upload.single("file"), async (req,res)=>{
  try{
    const q = (req.body?.q || "").trim();
    if (!q && !req.file) return res.json({ answer:"Ask me something." });

    const parts = [];
    if (q) parts.push({ type: "input_text", text: q });
    if (req.file) {
      const fs = (await import("fs")).promises;
      const b64 = await fs.readFile(req.file.path).then(b=>b.toString("base64"));
      const mime = req.file.mimetype || "image/png";
      const dataUrl = `data:${mime};base64,${b64}`;
      parts.push({ type: "input_image", image_url: dataUrl });
      fs.unlink(req.file.path).catch(()=>{});
    }

    const r = await openai.responses.create({
      model: DEFAULT_MODEL,
      input: [{ role: "user", content: parts }],
    });
    const answer = r.output_text || "No response.";
    res.json({ model: DEFAULT_MODEL, answer });
  }catch(e){
    console.error("advanced-ai error", e);
    res.status(500).json({ answer:"Advanced AI error" });
  }
});

// Homework Solver (multi-image + text) → OpenAI
const multiUpload = multer({ dest: "uploads/" });
app.post("/api/chat", multiUpload.array("files"), async (req,res)=>{
  try{
    const message = (req.body?.message || "").trim();
    const files = req.files || [];
    if (!message && files.length === 0) return res.status(400).json({ error:"Add an image or a message." });

    const fs = (await import("fs")).promises;
    const contents = [];
    if (message) contents.push({ type: "input_text", text: message });
    for (const f of files){
      const mime = f.mimetype || "image/png";
      const b64 = await fs.readFile(f.path).then(b=>b.toString("base64"));
      const dataUrl = `data:${mime};base64,${b64}`;
      contents.push({ type: "input_image", image_url: dataUrl });
      fs.unlink(f.path).catch(()=>{});
    }

    const r = await openai.responses.create({
      model: DEFAULT_MODEL,
      input: [{ role: "user", content: contents }],
    });
    const reply = r.output_text || "No reply.";
    res.json({ model: DEFAULT_MODEL, reply });
  }catch(e){ console.error("api/chat error", e); res.status(500).json({ error:"OpenAI error" }); }
});

// ---------- /api/me (minimal profile + limits) ----------
const upgradesByEmail = {}; // plug in your Paddle sync later if needed
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
  const profile = req.user ? {
    email: req.user.email,
    name: req.user.name,
    given_name: req.user.given_name,
    picture: req.user.picture,
  } : null;
  res.json({ loggedIn:!!req.user, user:profile, plan, limits, used:u, remaining });
});

// ---------- Static & Health ----------
app.use(express.static(__dirname)); // serves index.html as public home
app.get("/", (req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on ${PORT} (OpenAI model: ${DEFAULT_MODEL})`));
