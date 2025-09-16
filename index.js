// index.js — GoldenSpaceAI (with Save Universe endpoint)

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
import bodyParser from "body-parser"; // Keep this for the Paddle webhook if you use it
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
    moon: { ask: 10, search: 5, physics: 0, learnPhysics: false, createPlanet: false, createSatellite: false, createRocket: false, yourSpace: false },
    earth:{ ask: 30, search: 20, physics: 5, learnPhysics: true,  createPlanet: false, createSatellite: false, createRocket: false, yourSpace: false },
    sun:  { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true, createSatellite: true, createRocket: true, yourSpace: true },
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
function getPlan(req){ return (req.user && req.user.plan) || req.session?.plan; }
function getUsage(req,res){
    const key = getUserKey(req,res);
    const d = today();
    if (!usage[key] || usage[key].date !== d) usage[key] = { date:d, ask:0, search:0, physics:0 };
    return usage[key];
}
function enforceLimit(kind){
    return (req,res,next)=>{
        const plan = getPlan(req);
        const limits = PLAN_LIMITS[plan] || {};
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
            plan: null, // New users have no plan by default.
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
    req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.redirect('/login.html')); });
});

// ---------- Public Login Page (Your Original Code Restored) ----------
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
<a href="/terms-of-service.html" target="_blank" rel="noopener">Terms</a> and
<a href="/privacy.html" target="_blank" rel="noopener">Privacy</a>.</p>
<div class="links"><a href="/">Back to home</a><a href="/plans.html">See plans</a></div>
</div></div></body></html>`);
});

// --- Middleware to handle routing logic ---
function appFlowRouter(req, res, next) {
    const publicPaths = ['/login.html', '/auth/google', '/auth/google/callback', '/health'];
    const isPublic = publicPaths.some(path => req.path.startsWith(path));

    if (isPublic) {
        return next();
    }

    if (!req.isAuthenticated()) {
        return res.redirect('/login.html');
    }

    const hasPlan = !!getPlan(req);

    if (!hasPlan) {
        if (req.path === '/select-plan' || req.path === '/api/set-plan') {
            return next();
        }
        return res.redirect('/select-plan');
    }

    if (hasPlan) {
        if (req.path === '/login.html' || req.path === '/select-plan') {
            return res.redirect('/');
        }
    }
    
    next();
}
app.use(appFlowRouter);

// --- Plan Selection Page ---
app.get("/select-plan", (req, res) => {
    res.send(`
        <!DOCTYPE html><html><head><title>Select Your Plan</title>
        <style>body { font-family: sans-serif; background-color: #0b0f1a; color: #e0e0e0; display: grid; place-items: center; min-height: 100vh; margin: 0; } .container { max-width: 800px; text-align: center; } .plan-card { background-color: #1a2035; padding: 2rem; border-radius: 12px; border: 1px solid #3c4260; margin: 1rem; cursor: pointer; transition: all 0.2s; } .plan-card:hover { border-color: #f6c64a; transform: translateY(-5px); } h1, h2 { color: #f6c64a; }</style>
        </head><body><div class="container"><h1>Welcome, ${req.user.name}!</h1><h2>Choose a plan to begin your journey.</h2>
        <div style="display: flex;"><div class="plan-card" onclick="selectPlan('moon')"><h3>Moon Plan (Free)</h3><p>Get started with basic access.</p></div><div class="plan-card" onclick="selectPlan('earth')"><h3>Earth Plan ($2/mo)</h3><p>Unlock more features.</p></div><div class="plan-card" onclick="selectPlan('sun')"><h3>Sun Plan ($3/mo)</h3><p>Unlimited access to everything.</p></div></div></div>
        <script>async function selectPlan(plan) { await fetch('/api/set-plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ plan }) }); window.location.href = '/'; }</script>
        </body></html>
    `);
});

// --- API Endpoint to set the user's plan ---
app.post('/api/set-plan', (req, res) => {
    const { plan } = req.body;
    if (PLAN_LIMITS[plan]) {
        req.user.plan = plan;
        if (req.session) req.session.plan = plan;
        return res.json({ success: true, message: `Plan set to ${plan}` });
    }
    res.status(400).json({ success: false, message: 'Invalid plan selected' });
});

// --- NEW --- API Endpoint to save the user's universe ---
app.post('/api/save-universe', (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        return res.status(401).json({ error: 'You must be logged in to save.' });
    }

    const universeData = req.body;
    const userId = req.user.id;

    console.log(`Received universe data from user ${userId}:`);
    console.log(JSON.stringify(universeData, null, 2));

    // In a real application, you would save `universeData` to your database,
    // associating it with the `userId`.
    // For now, we'll just log it and send a success message.
    
    res.json({ success: true, message: 'Universe data received by server.' });
});

// ---------- Gemini & AI Routes ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

app.post("/ask", enforceLimit("ask"), async (req,res)=>{
    try {
        const { question, model: modelName, instructions } = req.body;
        if (!question) return res.json({ answer: "Please ask a question." });

        if (!req.session.chatHistory) req.session.chatHistory = [];

        const allowedModels = ["gemini-1.5-flash-latest", "gemini-1.5-pro-latest"];
        const chosenModel = allowedModels.includes(modelName) ? modelName : "gemini-1.5-flash-latest";
        const model = genAI.getGenerativeModel({ model: chosenModel });

        const chat = model.startChat({ history: req.session.chatHistory });
        
        const prompt = `${instructions || ''}\n\n---\n\n${question}`;

        const result = await chat.sendMessage(prompt);
        const answer = result.response.text();
        
        req.session.chatHistory = await chat.getHistory();
        
        res.json({ answer });
    } catch (e) {
        console.error("ask error", e);
        res.status(500).json({ answer:"An error occurred with the AI model." });
    }
});

// Other AI routes
app.post("/search-info", enforceLimit("search"), async (req,res)=>{ /* your existing code */ });
app.post("/ai/physics-explain", enforceLimit("physics"), async (req,res)=>{ /* your existing code */ });

// --- API /me Route ---
app.get("/api/me",(req,res)=>{
    const plan = getPlan(req);
    res.json({
        loggedIn: !!req.user,
        user: req.user || null,
        plan: plan,
        limits: PLAN_LIMITS[plan] || {}
    });
});

// --- Feature Pages (now protected by the router) ---
app.get("/learn-physics.html",(req,res)=>{ res.sendFile(path.join(__dirname,"learn-physics.html")); });
app.get("/create-planet.html",(req,res)=>{ res.sendFile(path.join(__dirname,"create-planet.html")); });
app.get("/create-satellite.html", (req, res) => { res.sendFile(path.join(__dirname, "create-satellite.html")); });
app.get("/create-rocket.html", (req, res) => { res.sendFile(path.join(__dirname, "create-rocket.html")); });
app.get("/your-space.html", (req, res) => { res.sendFile(path.join(__dirname, "your-space.html")); });

// --- Static File Serving & Health Check ---
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on port ${PORT}`));
