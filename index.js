// index.js — GoldenSpaceAI (Login -> Plan Selection -> Main Page Flow)

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
    moon: { ask: 10, search: 5, physics: 0, learnPhysics: false, createPlanet: false, createSatellite: false, createRocket: false, yourSpace: false },
    earth:{ ask: 30, search: 20, physics: 5, learnPhysics: true, createPlanet: false, createSatellite: false, createRocket: false, yourSpace: false },
    sun: { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true, createSatellite: true, createRocket: true, yourSpace: true },
};

// ---------- Usage tracking (remains the same) ----------
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
    const host = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
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

// ---------- Public Login Page ----------
app.get("/login.html",(req,res)=>{
    // ... This can be a res.sendFile() or your existing res.send() for the login page
    res.sendFile(path.join(__dirname, "login.html"));
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
        <!DOCTYPE html>
        <html>
        <head>
            <title>Select Your Plan</title>
            <style>
                body { font-family: sans-serif; background-color: #0b0f1a; color: #e0e0e0; display: grid; place-items: center; min-height: 100vh; margin: 0; }
                .container { max-width: 800px; text-align: center; }
                .plan-card { background-color: #1a2035; padding: 2rem; border-radius: 12px; border: 1px solid #3c4260; margin: 1rem; cursor: pointer; transition: all 0.2s; }
                .plan-card:hover { border-color: #f6c64a; transform: translateY(-5px); }
                h1, h2 { color: #f6c64a; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Welcome, ${req.user.name}!</h1>
                <h2>Choose a plan to begin your journey.</h2>
                <div style="display: flex;">
                    <div class="plan-card" onclick="selectPlan('moon')">
                        <h3>Moon Plan (Free)</h3>
                        <p>Get started with basic access.</p>
                    </div>
                    <div class="plan-card" onclick="selectPlan('earth')">
                        <h3>Earth Plan ($2/mo)</h3>
                        <p>Unlock more features.</p>
                    </div>
                    <div class="plan-card" onclick="selectPlan('sun')">
                        <h3>Sun Plan ($3/mo)</h3>
                        <p>Unlimited access to everything.</p>
                    </div>
                </div>
            </div>
            <script>
                async function selectPlan(plan) {
                    await fetch('/api/set-plan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ plan })
                    });
                    window.location.href = '/'; // Redirect to main page after selection
                }
            </script>
        </body>
        </html>
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


// --- Gemini & AI Routes ---
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// --- THIS IS THE UPDATED /ask ENDPOINT ---
// It combines conversational memory with dynamic model selection and custom instructions.
app.post("/ask", enforceLimit("ask"), async (req,res) => {
    try {
        const { question, model: modelName, instructions } = req.body;
        if (!question) return res.json({ answer: "Please ask a question." });

        // Initialize chat history in session if it doesn't exist
        if (!req.session.chatHistory) req.session.chatHistory = [];

        // Validate and select the AI model
        const allowedModels = ["gemini-1.5-flash-latest", "gemini-1.5-pro-latest"];
        const chosenModel = allowedModels.includes(modelName) ? modelName : "gemini-1.5-flash-latest";
        const model = genAI.getGenerativeModel({ model: chosenModel });

        // Start a chat session using the stored history
        const chat = model.startChat({ history: req.session.chatHistory });
        
        // Create a dynamic prompt with user's custom instructions
        const prompt = `${instructions || ''}\n\n---\n\n${question}`;

        const result = await chat.sendMessage(prompt);
        const answer = result.response.text();
        
        // Update the history in the session for the next conversation turn
        req.session.chatHistory = await chat.getHistory();
        
        res.json({ answer });
    } catch (e) {
        console.error("ask error", e);
        res.status(500).json({ answer: "An error occurred with the AI model." });
    }
});

// Other AI routes remain unchanged for now
app.post("/search-info", enforceLimit("search"), async (req,res)=>{ /* your existing code */ });
app.post("/ai/physics-explain", enforceLimit("physics"), async (req,res)=>{ /* your existing code */ });

// --- API /me Route (Unchanged) ---
app.get("/api/me",(req,res)=>{ 
    const plan = getPlan(req);
    res.json({
        loggedIn: !!req.user,
        user: req.user || null,
        plan: plan,
        limits: PLAN_LIMITS[plan] || {}
    });
});

// --- Feature Pages (Unchanged, now protected by the router) ---
app.get("/learn-physics.html",(req,res)=>{ res.sendFile(path.join(__dirname,"learn-physics.html")); });
app.get("/create-planet.html",(req,res)=>{ res.sendFile(path.join(__dirname,"create-planet.html")); });
app.get("/create-satellite.html", (req, res) => { res.sendFile(path.join(__dirname, "create-satellite.html")); });
app.get("/create-rocket.html", (req, res) => { res.sendFile(path.join(__dirname, "create-rocket.html")); });
app.get("/your-space.html", (req, res) => { res.sendFile(path.join(__dirname, "your-space.html")); });


// --- Static File Serving & Health Check ---
app.use(express.static(__dirname));
app.get("/health",(_req,res)=>res.json({ ok:true }));


// --- Start Server ---
const PORT = process.env.PORT || 1000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on port ${PORT}`));
