// index.js
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import bodyParser from "body-parser";
import fetch from "node-fetch"; // make API calls
import session from "express-session";

const app = express();
const PORT = process.env.PORT || 10000;

// Fix __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== Middleware =====
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (css, js, images, html in root)
app.use(express.static(__dirname));

// Session (for login + plan info)
app.use(
  session({
    secret: process.env.SESSION_SECRET || "goldenspace-secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
);

// ===== Simple fake login for testing =====
app.get("/auth/google", (req, res) => {
  // Simulate Google login success
  req.session.user = {
    name: "Test User",
    email: "test@goldenspaceai.space",
    photo: "https://www.gravatar.com/avatar/?d=mp",
    plan: req.session.plan || "guest",
  };
  res.redirect("/");
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ===== Plan switching (for testing unlocks without Paddle) =====
app.get("/switch-plan/:plan", (req, res) => {
  if (!req.session.user) {
    req.session.user = { name: "Test User", email: "test@goldenspaceai.space" };
  }
  req.session.plan = req.params.plan; // "sun", "earth", "moon", "yourspace", "chatai"
  res.json({ ok: true, plan: req.session.plan });
});

// ===== API to return current user + plan =====
app.get("/api/me", (req, res) => {
  if (!req.session.user) {
    return res.json({ loggedIn: false });
  }
  res.json({
    loggedIn: true,
    user: req.session.user,
    plan: req.session.plan || "guest",
    usage: {
      ask: "∞",
      search: "∞",
      physics: "∞",
    },
  });
});

// ===== Gemini / Chat AI endpoint (dummy for now) =====
app.post("/api/ask", async (req, res) => {
  const { message } = req.body;

  // For now simulate AI reply
  res.json({
    reply: `🤖 [Simulated Gemini Reply]: You asked "${message}"`,
  });
});

// ===== Route serving HTML pages =====
const pages = [
  "index.html",
  "plans.html",
  "privacy.html",
  "terms.html",
  "refund.html",
  "contact.html",
  "advanced-ai.html",
  "search-info.html",
  "learn-physics.html",
  "create-planet.html",
  "your-space.html",
  "chatai.html",
];

pages.forEach((page) => {
  app.get("/" + page.replace(".html", ""), (req, res) => {
    res.sendFile(path.join(__dirname, page));
  });
});

// Catch-all (any other path → homepage)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ===== Start server =====
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on http://localhost:${PORT}`);
});
