const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 10000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "goldenspace-secret",
    resave: false,
    saveUninitialized: true,
  })
);

// --- Login Required Middleware ---
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.send(`
      <html>
        <head><title>Login Required</title></head>
        <body style="font-family:sans-serif; text-align:center; margin-top:100px;">
          <h2>🚀 Welcome to GoldenSpaceAI</h2>
          <p>Please log in to continue.</p>
          <a href="/auth/google">
            <button style="padding:10px 20px; font-size:16px; cursor:pointer;">
              Continue with Google
            </button>
          </a>
        </body>
      </html>
    `);
  }
  next();
}

// --- Fake Google Login ---
app.get("/auth/google", (req, res) => {
  req.session.user = { name: "Test User", email: "test@goldenspaceai.space" };
  res.redirect("/");
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// --- Plans ---
app.get("/switch-plan/:plan", requireLogin, (req, res) => {
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

// --- Chat AI endpoint ---
app.post("/api/ask", requireLogin, (req, res) => {
  const { message } = req.body;
  res.json({ reply: `🤖 ChatAI says: "${message}"` });
});

// --- Learn Physics endpoint ---
app.post("/api/learn-physics", requireLogin, (req, res) => {
  const { topic } = req.body;
  const reply = topic
    ? `📘 Physics lesson on "${topic}": Energy, motion, and matter are all connected.`
    : "📘 Please provide a topic to learn physics about.";
  res.json({ reply });
});

// --- Search Information endpoint ---
app.post("/api/search-info", requireLogin, (req, res) => {
  const { query } = req.body;
  const reply = query
    ? `🔎 Search result for "${query}": This is sample information from GoldenSpaceAI.`
    : "🔎 Please provide a search query.";
  res.json({ reply });
});

// --- Search Lesson endpoint ---
app.post("/api/search-lesson", requireLogin, (req, res) => {
  const { subject } = req.body;
  const reply = subject
    ? `📚 Lesson on "${subject}": Here’s a helpful explanation from GoldenSpaceAI.`
    : "📚 Please provide a subject for the lesson.";
  res.json({ reply });
});

// --- Pages ---
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
  "chatai.html"
];

pages.forEach((page) => {
  app.get("/" + page.replace(".html", ""), requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, page));
  });
});

// --- Catch-all (login check first) ---
app.get("*", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on port ${PORT}`);
});
