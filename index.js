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
    let imageURL;

    switch (model) {
      case "gemini_2_5_pro":
        // Call Gemini API (replace with actual Gemini 2.5 Pro API request)
        completion = await axios.post('YOUR_GEMINI_API_ENDPOINT', {
          prompt,
          model: 'gemini_2_5_pro', // Adjust Gemini API parameters
        });
        imageURL = completion.data?.image_url || null;
        break;

      case "gemini_flash":
        // Call Gemini Flash API (replace with actual Gemini Flash API request)
        completion = await axios.post('YOUR_GEMINI_FLASH_API_ENDPOINT', {
          prompt,
          model: 'gemini_flash', // Adjust Gemini Flash API parameters
        });
        imageURL = completion.data?.image_url || null;
        break;

      case "gpt_4":
        // Use OpenAI's DALL-E for image generation (GPT-4 with DALL-E)
        completion = await openai.images.create({
          prompt: prompt, // Text prompt to generate an image
          n: 1, // Number of images to generate
          size: "1024x1024", // Image size (can be 256x256, 512x512, 1024x1024)
        });
        imageURL = completion.data?.data[0]?.url || null;
        break;

      case "gpt_4o_mini":
        // GPT-4o-mini doesn't support image generation
        res.status(400).json({ error: "GPT-4o-mini does not support image generation." });
        return;

      default:
        res.status(400).json({ error: "Model not supported." });
        return;
    }

    if (imageURL) {
      res.json({ reply: "Image generated successfully", imageURL });
    } else {
      res.json({ reply: completion.choices[0]?.message?.content || "No reply." });
    }
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

app.post("/ask", async (req, res) => {
  await askAI(req.body?.question || "", res, "Chat");
});

app.post("/chat-homework", async (req, res) => {
  await askAI(req.body?.q || "", res, "Homework Solver");
});

app.post("/search-info", async (req, res) => {
  await askAI(req.body?.query || "", res, "Knowledge Search");
});

app.post("/api/physics-explain", async (req, res) => {
  await askAI(req.body?.question || "", res, "Physics Tutor");
});

app.post("/ai/create-planet", async (req, res) => {
  await askAI("Invent a realistic exoplanet: " + JSON.stringify(req.body?.specs || {}), res, "Planet Builder");
});

app.post("/ai/create-rocket", async (req, res) => {
  await askAI("Design a conceptual rocket.", res, "Rocket Engineer");
});

app.post("/ai/create-satellite", async (req, res) => {
  await askAI("Design a conceptual satellite.", res, "Satellite Engineer");
});

app.post("/ai/create-universe", async (req, res) => {
  await askAI("Create a fictional shared universe. Theme: " + (req.body?.theme || "space opera"), res, "Universe Creator");
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT} (ALL UNLOCKED)`));
