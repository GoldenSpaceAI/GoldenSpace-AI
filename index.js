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
import { Strategy as GitHubStrategy } from "passport-github2";
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

// ---------- Passport Setup ----------
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
app.use(passport.initialize());
app.use(passport.session());

// ---------- Google OAuth ----------
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback",
        proxy: true,
      },
      (_accessToken, _refreshToken, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName,
          email: profile.emails?.[0]?.value || "",
          photo: profile.photos?.[0]?.value || "",
          provider: "google"
        };
        return done(null, user);
      }
    )
  );

  app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
  
  app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login-signup.html" }),
    (req, res) => res.redirect("https://goldenspaceai.space")
  );
}

// ---------- GitHub OAuth ----------
if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
  passport.use(
    new GitHubStrategy(
      {
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: "/auth/github/callback",
        proxy: true,
      },
      (_accessToken, _refreshToken, profile, done) => {
        const user = {
          id: profile.id,
          name: profile.displayName || profile.username,
          email: profile.emails?.[0]?.value || `${profile.username}@github.user`,
          photo: profile.photos?.[0]?.value || "",
          username: profile.username,
          provider: "github"
        };
        return done(null, user);
      }
    )
  );

  app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));
  
  app.get(
    "/auth/github/callback",
    passport.authenticate("github", { failureRedirect: "/login-signup.html" }),
    (req, res) => res.redirect("https://goldenspaceai.space")
  );
}

// ---------- Routes ----------

// Serve login page as first page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "login-signup.html"));
});

// Serve login page directly
app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "login-signup.html"));
});

// ---------- API: User info ----------
app.get("/api/me", (req, res) => {
  if (req.user) {
    res.json({
      loggedIn: true,
      user: req.user,
      email: req.user.email,
      name: req.user.name,
      picture: req.user.photo,
      plan: "ultra", // always ultra (everything unlocked)
      provider: req.user.provider
    });
  } else {
    res.json({
      loggedIn: false,
      user: null,
      plan: "free"
    });
  }
});

// ---------- Logout ----------
app.post("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({ error: "Logout failed" });
    }
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.json({ ok: true, message: "Logged out successfully" });
    });
  });
});

// ---------- OpenAI ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Image Handling ----------
const upload = multer({ dest: 'uploads/' });

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
          model: 'gemini_2_5_pro',
        });
        imageURL = completion.data?.image_url || null;
        break;

      case "gemini_flash":
        // Call Gemini Flash API (replace with actual Gemini Flash API request)
        completion = await axios.post('YOUR_GEMINI_FLASH_API_ENDPOINT', {
          prompt,
          model: 'gemini_flash',
        });
        imageURL = completion.data?.image_url || null;
        break;

      case "gpt_4":
        // Use OpenAI's DALL-E for image generation
        completion = await openai.images.create({
          prompt: prompt,
          n: 1,
          size: "1024x1024",
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
  const image = req.file ? req.file.path : null;

  try {
    if (image) {
      console.log('Image uploaded:', image);
    }

    await askAI(q || "", model || "gpt-4", res, "Advanced Assistant");

  } catch (e) {
    console.error("Advanced AI error", e);
    res.status(500).json({ error: "Advanced AI error" });
  }
});

app.post("/ask", async (req, res) => {
  await askAI(req.body?.question || "", "gpt-4o-mini", res, "Chat");
});

app.post("/chat-homework", async (req, res) => {
  await askAI(req.body?.q || "", "gpt-4o-mini", res, "Homework Solver");
});

app.post("/search-info", async (req, res) => {
  await askAI(req.body?.query || "", "gpt-4o-mini", res, "Knowledge Search");
});

app.post("/api/physics-explain", async (req, res) => {
  await askAI(req.body?.question || "", "gpt-4o-mini", res, "Physics Tutor");
});

app.post("/ai/create-planet", async (req, res) => {
  await askAI("Invent a realistic exoplanet: " + JSON.stringify(req.body?.specs || {}), "gpt-4o-mini", res, "Planet Builder");
});

app.post("/ai/create-rocket", async (req, res) => {
  await askAI("Design a conceptual rocket.", "gpt-4o-mini", res, "Rocket Engineer");
});

app.post("/ai/create-satellite", async (req, res) => {
  await askAI("Design a conceptual satellite.", "gpt-4o-mini", res, "Satellite Engineer");
});

app.post("/ai/create-universe", async (req, res) => {
  await askAI("Create a fictional shared universe. Theme: " + (req.body?.theme || "space opera"), "gpt-4o-mini", res, "Universe Creator");
});

// ---------- Health Check ----------
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "GoldenSpaceAI is running" });
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT} (ALL UNLOCKED)`));
