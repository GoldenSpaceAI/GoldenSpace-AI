const express = require("express");
const path = require("path");
const bodyParser = require("body-parser");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { Configuration, OpenAIApi } = require("openai");

require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;

// ✅ Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "goldenspace-secret",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// ✅ Passport Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
      });
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// ✅ OpenAI / Gemini Setup
const openai = new OpenAIApi(
  new Configuration({
    apiKey: process.env.GEMINI_API_KEY || process.env.OPENAI_API_KEY,
  })
);

// ✅ Auth Routes
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

app.get("/auth/logout", (req, res) => {
  req.logout(() => {
    req.session.destroy(() => res.redirect("/"));
  });
});

// ✅ Homepage (before login)
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/dashboard");
  }

  res.send(`
    <html>
      <head>
        <title>Welcome to GoldenSpaceAI</title>
        <style>
          body { font-family: Arial; text-align: center; padding: 50px; background: #0d0d0d; color: #ffd700; }
          .box { max-width: 600px; margin: auto; background: #1a1a1a; padding: 30px; border-radius: 12px; }
          a { display: inline-block; margin: 15px; padding: 12px 24px; background: #ffd700; color: #0d0d0d; text-decoration: none; border-radius: 8px; font-weight: bold; }
          a:hover { background: #e6c200; }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>🌌 Welcome to GoldenSpaceAI</h1>
          <p>GoldenSpaceAI is your gateway to the universe. Explore physics, AI-powered knowledge, and your own custom space journeys!</p>
          <a href="/auth/google">Continue with Google</a>
          <br/>
          <a href="/login">Login</a>
        </div>
      </body>
    </html>
  `);
});

// ✅ Dashboard after login
app.get("/dashboard", (req, res) => {
  if (!req.isAuthenticated()) return res.redirect("/");

  res.send(`
    <html>
      <head><title>Dashboard - GoldenSpaceAI</title></head>
      <body style="font-family:Arial; background:#0d0d0d; color:#ffd700; text-align:center; padding:40px;">
        <h1>Welcome, ${req.user.name} 🚀</h1>
        <p>You are logged in with ${req.user.email}</p>
        <p>Choose where to go:</p>
        <a href="/plans">Plans</a> |
        <a href="/advanced-ai">Advanced AI</a> |
        <a href="/search-info">Search Info</a> |
        <a href="/learn-physics">Learn Physics</a> |
        <a href="/create-planet">Create Planet</a> |
        <a href="/your-space">Your Space</a> |
        <a href="/chatai">Chat AI</a>
        <br/><br/>
        <a href="/auth/logout">Logout</a>
      </body>
    </html>
  `);
});

// ✅ AI endpoint
app.post("/api/ask", async (req, res) => {
  try {
    const { message } = req.body;
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini", // change to Gemini if you want
      messages: [{ role: "user", content: message }],
    });

    res.json({ reply: response.choices[0].message.content });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "AI request failed" });
  }
});

// ✅ Static pages
const pages = [
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
  app.get("/" + page.replace(".html", ""), (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/");
    res.sendFile(path.join(__dirname, page));
  });
});

// ✅ Start server
app.listen(PORT, () => {
  console.log(`🚀 GoldenSpaceAI running on port ${PORT}`);
});
