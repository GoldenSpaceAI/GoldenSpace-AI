const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");

// Create app
const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Use __dirname directly (already available in CommonJS)
app.use(express.static(__dirname));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "goldenspace-secret",
    resave: false,
    saveUninitialized: true,
  })
);

// Fake login (testing only)
app.get("/auth/google", (req, res) => {
  req.session.user = { name: "Test User", email: "test@goldenspaceai.space" };
  res.redirect("/");
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Plans
app.get("/switch-plan/:plan", (req, res) => {
  req.session.plan = req.params.plan;
  res.json({ plan: req.session.plan });
});

app.get("/api/me", (req, res) => {
  res.json({
    loggedIn: !!req.session.user,
    user: req.session.user,
    plan: req.session.plan || "guest",
  });
});

// AI endpoint (mock)
app.post("/api/ask", (req, res) => {
  const { message } = req.body;
  res.json({ reply: `🤖 AI says: "${message}"` });
});

// Static pages
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

// Catch-all → homepage
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on port ${PORT}`);
});
