// index.js — GoldenSpaceAI (Final Consolidated Version with All Features)

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
import { ImageAnnotatorClient } from '@google-cloud/vision'; // For Homework Solver
import bodyParser from "body-parser";
import crypto from "crypto";

dotenv.config();

// --- 1. CORE APP SETUP ---
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' })); // Increase limit for image uploads
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "a-very-strong-secret-key",
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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- 2. PLANS & USAGE LOGIC ---
const PLAN_LIMITS = {
  moon: { ask: 20, search: 5, physics: 0, learnPhysics: false, createPlanet: false, homework: 1 },
  earth:{ ask: 50, search: 20, physics: 5, learnPhysics: true,  createPlanet: false, homework: 5 },
  sun:  { ask: Infinity, search: Infinity, physics: Infinity, learnPhysics: true, createPlanet: true, homework: Infinity },
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
function getPlan(req){ return (req.user?.plan) || "moon"; } // Guests default to moon plan
function getUsage(req,res){
  const key = getUserKey(req,res);
  const d = today();
  if (!usage[key] || usage[key].date !== d) usage[key] = { date:d, ask:0, search:0, physics:0, homework: 0 };
  return usage[key];
}
function enforceLimit(kind){
  return (req,res,next)=>{
    const plan = getPlan(req);
    const limits = PLAN_LIMITS[plan] || {};
    const u = getUsage(req,res);
    const allowed = limits[kind];
    if (allowed === 0) return res.status(403).json({ error:`Your plan does not allow this feature.` });
    if (Number.isFinite(allowed) && u[kind] >= allowed) return res.status(429).json({ error:`Daily limit reached for this feature.` });
    if (Number.isFinite(allowed)) u[kind]++;
    next();
  };
}

// --- 3. AUTHENTICATION (PASSPORT & GOOGLE OAUTH) ---
passport.use(new GoogleStrategy({
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
      plan: "moon", // Default plan for new users who sign up
    };
    return done(null, user);
  }
));
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((obj,done)=>done(null,obj));

app.get("/auth/google", passport.authenticate("google",{ scope:["profile","email"]}));
app.get("/auth/google/callback", passport.authenticate("google",{ failureRedirect:"/" }), (req, res) => res.redirect("/"));
app.post("/logout",(req,res,next)=>{
  req.logout(err=>{
    if (err) return next(err);
    req.session.destroy(()=>res.json({ok:true}));
  });
});

// --- 4. API ROUTES ---

// User & Plan Management
app.get("/api/me",(req,res)=>{
  res.json({ loggedIn:!!req.user, user:req.user||null, plan: getPlan(req) });
});

app.post('/api/save-universe', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'You must be logged in to save your universe.' });
    }
    const universeData = req.body;
    const userId = req.user.id;
    console.log(`Saving universe for user ${userId}:`, JSON.stringify(universeData, null, 2));
    // In a real app, you would save this to your database.
    res.json({ success: true, message: 'Universe data received by server.' });
});

// --- 5. AI-POWERED ROUTES ---
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Advanced AI Chat Endpoint
app.post("/ask", enforceLimit("ask"), async (req,res)=>{
  try {
    const { question, model: modelName, instructions } = req.body;
    if (!question) return res.json({ answer: "Please ask a question." });

    if (!req.session.chatHistory) req.session.chatHistory = [];

    const allowedModels = ["gemini-1.5-flash-latest", "gemini-1.5-pro-latest"];
    const chosenModelName = allowedModels.includes(modelName) ? modelName : "gemini-1.5-flash-latest";
    const model = genAI.getGenerativeModel({ model: chosenModelName });

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

// Homework Solver Endpoint
app.post('/solve-homework', enforceLimit("homework"), async (req, res) => {
    try {
        const { image } = req.body;
        if (!image) return res.status(400).json({ error: 'No image data provided.' });

        const visionClient = new ImageAnnotatorClient();
        const [ocrResult] = await visionClient.textDetection({ image: { content: image } });
        const detectedText = ocrResult.fullTextAnnotation?.text;

        if (!detectedText) return res.status(400).json({ solution: "Could not detect any text in the image." });

        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash-latest" });
        const prompt = `You are an expert academic tutor. Provide a clear, step-by-step solution for the following problem:\n\n---\n${detectedText}\n---`;
        const result = await model.generateContent(prompt);
        const solution = result.response.text();

        res.json({ solution });
    } catch (error) {
        console.error('Error in homework solver:', error);
        res.status(500).json({ solution: 'An internal error occurred.' });
    }
});

// Other AI features
const basicModel = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });
app.post("/search-info", enforceLimit("search"), async (req,res)=>{
  try{
    const q = (req.body?.query || "").trim();
    const prompt = `You are GoldenSpace Knowledge. Overview + 3 bullet facts.\nTopic: ${q}`;
    const result = await basicModel.generateContent(prompt);
    res.json({ answer: result.response.text() || "No info found." });
  }catch(e){ res.status(500).json({ answer:"Search error" }); }
});

app.post("/ai/physics-explain", enforceLimit("physics"), async (req,res)=>{
    try{
        const q = (req.body?.question || "").trim();
        const prompt = `You are GoldenSpace Physics Tutor. Explain clearly.\nQuestion: ${q}`;
        const result = await basicModel.generateContent(prompt);
        res.json({ reply: result.response.text() || "No reply." });
    }catch(e){ res.status(500).json({ reply:"Physics error" }); }
});


// --- 6. SERVING HTML PAGES ---
// These are now accessible to guests because the strict router was removed.
app.get("/learn-physics.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].learnPhysics){
    return res.send(`<html><body><h2>Upgrade to the Earth Pack or higher to unlock Learn Physics!</h2><p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"learn-physics.html"));
});
app.get("/create-planet.html",(req,res)=>{
  const plan = getPlan(req);
  if (!PLAN_LIMITS[plan].createPlanet){
    return res.send(`<html><body><h2>Upgrade to the Sun Pack to unlock the Planet Creator!</h2><p><a href="/plans.html">See Plans</a></p></body></html>`);
  }
  res.sendFile(path.join(__dirname,"create-planet.html"));
});

// --- 7. STATIC FILE SERVER & SERVER START ---
// Serves index.html, login.html, all builder pages, CSS, client-side JS etc.
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI is running on port ${PORT}`));
