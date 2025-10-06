// index.js — GoldenSpaceAI (Unlocked version)
// All pages unlocked, all AI endpoints reply in professional, advanced way

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import OpenAI from "openai";
import axios from "axios";
import multer from "multer";

dotenv.config();
const app = express();
app.set("trust proxy", 1);

// ---------- Middleware ----------
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "super-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

// ---------- Google OAuth (if enabled) ----------
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
        proxy: true,
      },
      (_at, _rt, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          photo: profile.photos?.[0]?.value || "",
        };
        return done(null, user);
      }
    )
  );
  passport.serializeUser((u, d) => d(null, u));
  passport.deserializeUser((o, d) => d(null, o));
  app.use(passport.initialize());
  app.use(passport.session());

  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login.html" }),
    (req, res) => res.redirect("/")
  );
  app.post("/logout", (req, res) => {
    req.logout?.(() => {
      req.session.destroy(() => res.json({ ok: true }));
    });
  });
}

// ---------- API: User info ----------
app.get("/api/me", (req, res) => {
  res.json({
    loggedIn: !!req.user,
    email: req.user?.email || null,
    picture: req.user?.photo || null,
    plan: "ultra", // always ultra (everything unlocked)
  });
});

// ---------- OpenAI ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Image Handling (for uploaded images) ----------
const upload = multer({ dest: 'uploads/' }); // You can add more configurations for file handling

// ---------- Unified AI route ----------
async function askAI(prompt, model, res, role = "General Assistant") {
  try {
    let completion;

    // Determine which AI model to use
    switch (model) {
      case "gemini_2_5_pro":
        // Call Gemini API (replace with actual API request)
        completion = await axios.post('YOUR_GEMINI_API_ENDPOINT', {
          prompt,
          model: 'gemini_2_5_pro', // or actual Gemini API parameters
        });
        break;
      case "gemini_flash":
        // Call Gemini Flash API (replace with actual API request)
        completion = await axios.post('YOUR_GEMINI_FLASH_API_ENDPOINT', {
          prompt,
          model: 'gemini_flash', // actual API parameters
        });
        break;
      case "gpt_4":
        // Call GPT-4 API (OpenAI)
        completion = await openai.chat.completions.create({
          model: "gpt-4",
          messages: [
            {
              role: "system",
              content: `You are GoldenSpaceAI (${role}). Always reply in a professional, advanced, long, and detailed way with reasoning, examples, and structured explanations.`,
            },
            { role: "user", content: prompt },
          ],
          temperature: 0.5,
        });
        break;
      case "gpt_4o_mini":
        // Call GPT-4o-mini API (OpenAI)
        completion = await openai.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            {
              role: "system",
              content: `You are GoldenSpaceAI (${role}). Always reply in a professional, advanced, long, and detailed way with reasoning, examples, and structured explanations.`,
            },
            { role: "user", content: prompt },
          ],
          temperature: 0.5,
        });
        break;
      default:
        res.status(400).json({ error: "Model not supported." });
        return;
    }

    // Send the AI reply back to the frontend
    res.json({ reply: completion.choices[0]?.message?.content || "No reply." });
  } catch (e) {
    console.error("AI error", e);
    res.status(500).json({ error: "AI error" });
  }
}

// ---------- AI Endpoints (all models with image generation and upload support) ----------
app.post("/chat-advanced-ai", upload.single("image"), async (req, res) => {
  const { q, model } = req.body;
  const image = req.file ? req.file.path : null; // Image handling

  try {
    let aiResponse;

    // Handle Image Uploads (you can use the image for processing as needed)
    if (image) {
      console.log('Image uploaded:', image);
    }

    // Call the appropriate AI model
    await askAI(q || "", model || "gpt-4", res, "Advanced Assistant");

  } catch (e) {
    console.error("Advanced AI error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT} (ALL UNLOCKED)`));
