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

// --- Login Gate ---
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.send(`
      <html>
        <head>
          <title>GoldenSpaceAI</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              background: linear-gradient(135deg, #000428, #004e92);
              color: white;
              margin: 0;
              padding: 0;
              height: 100vh;
              display: flex;
              justify-content: center;
              align-items: center;
            }
            .box {
              background: rgba(0, 0, 0, 0.8);
              padding: 40px;
              border-radius: 15px;
              max-width: 700px;
              text-align: center;
              box-shadow: 0 0 30px gold;
              animation: fadeIn 1s ease-in-out;
            }
            h1 {
              color: gold;
              font-size: 2.5em;
              margin-bottom: 20px;
            }
            p {
              font-size: 1.2em;
              line-height: 1.6;
              margin-bottom: 20px;
            }
            button {
              background: gold;
              border: none;
              padding: 15px 35px;
              font-size: 18px;
              border-radius: 8px;
              cursor: pointer;
              transition: 0.3s;
            }
            button:hover {
              background: #ffcc00;
              transform: scale(1.05);
            }
            @keyframes fadeIn {
              from { opacity: 0; transform: translateY(20px); }
              to { opacity: 1; transform: translateY(0); }
            }
          </style>
        </head>
        <body>
          <div class="box">
            <h1>🌌 Welcome to GoldenSpaceAI</h1>
            <p>
              Explore the universe of knowledge.<br>
              ✨ Learn physics<br>
              🤖 Chat with advanced AI<br>
              🪐 Create your own planet<br>
              🔎 Search and discover information
            </p>
            <p><b>GoldenSpaceAI is your gateway to the universe 🚀</b></p>
            <a href="/auth/google"><button>Continue with Google</button></a>
          </div>
        </body>
      </html>
    `);
  }
  next();
}

// --- Fake Google Login ---
app.get("/auth/google", (req, res) => {
  req.session.user = { name: "Explorer", email: "user@goldenspaceai.space" };
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

// --- Gemini API helper ---
async function askGemini(prompt) {
  try {
    const response = await fetch(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateText?key=" +
        process.env.GEMINI_API_KEY,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
        }),
      }
    );
    const data = await response.json();
    return (
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      "⚠️ No response from Gemini."
    );
  } catch (err) {
    console.error("Gemini API error:", err);
    return "⚠️ Error contacting Gemini API.";
  }
}

// --- AI Endpoints ---
app.post("/api/ask", requireLogin, async (req, res) => {
  const { message } = req.body;
  const reply = await askGemini(message);
  res.json({ reply });
});

app.post("/api/learn-physics", requireLogin, async (req, res) => {
  const { topic } = req.body;
  const reply = await askGemini(`Explain this physics topic in detail: ${topic}`);
  res.json({ reply });
});

app.post("/api/search-info", requireLogin, async (req, res) => {
  const { query } = req.body;
  const reply = await askGemini(`Find and explain: ${query}`);
  res.json({ reply });
});

app.post("/api/search-lesson", requireLogin, async (req, res) => {
  const { subject } = req.body;
  const reply = await askGemini(`Give me a full lesson on: ${subject}`);
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
  "chatai.html",
];

pages.forEach((page) => {
  app.get("/" + page.replace(".html", ""), requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, page));
  });
});

// --- Catch-all ---
app.get("*", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on port ${PORT}`);
});
