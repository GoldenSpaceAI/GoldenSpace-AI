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
function getPlan(req){ return (req.user?.plan) || "moon"; } // Guests default to moon plan

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
            plan: "moon", // Logged-in users start on moon plan
        };
        return done(null, user);
    }
));
passport.serializeUser((user,done)=>done(null,user));
passport.deserializeUser((obj,done)=>done(null,obj));

app.get("/auth/google", passport.authenticate("google", { scope:["profile", "email"] }));
app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect:"/" }), (req,res) => res.redirect("/"));
app.post("/logout",(req,res,next)=>{
    req.logout(err=>{ if (err) return next(err); req.session.destroy(()=>res.redirect('/')); });
});


// ---------- Gemini & AI Routes ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model:"gemini-1.5-flash" });

app.post("/ask", async (req,res)=>{
    try {
        const { question, model: modelName, instructions } = req.body;
        if (!question) return res.json({ answer: "Please ask a question." });

        if (!req.session.chatHistory) req.session.chatHistory = [];

        const allowedModels = ["gemini-1.5-flash-latest", "gemini-1.5-pro-latest"];
        const chosenModelName = allowedModels.includes(modelName) ? modelName : "gemini-1.5-flash-latest";
        const chosenModel = genAI.getGenerativeModel({ model: chosenModelName });

        const chat = chosenModel.startChat({ history: req.session.chatHistory });
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

// ---------- API Routes ----------
app.get("/api/me",(req,res)=>{
    res.json({
        loggedIn: !!req.user,
        user: req.user || null,
        plan: getPlan(req)
    });
});

app.post('/api/save-universe', (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        return res.status(401).json({ error: 'You must be logged in to save.' });
    }
    const universeData = req.body;
    console.log(`Received universe data from user ${req.user.id}:`, universeData);
    res.json({ success: true, message: 'Universe data received by server.' });
});

// ---------- Static File Serving ----------
// This will serve index.html, create-rocket.html, etc.
app.use(express.static(__dirname));

// ---------- Start Server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`🚀 GoldenSpaceAI running on port ${PORT}`));
