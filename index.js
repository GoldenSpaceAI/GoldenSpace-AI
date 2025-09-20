// index.js — GoldenSpaceAI (Auth + Plans + Limits + Gemini + OpenAI + Supabase)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import multer from "multer";

import { GoogleGenerativeAI } from "@google/generative-ai";
import OpenAI from "openai";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// ---------- App ----------
const app = express();
app.set("trust proxy", 1);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// ---------- Sessions ----------
app.use(
  session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: (process.env.COOKIE_SAMESITE || "lax"), // set env to 'none' on Render
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const getBaseUrl = (req) => {
  const proto = (req.headers["x-forwarded-proto"] || "").toString().split(",")[0] || req.protocol || "https";
  const host = (req.headers["x-forwarded-host"] || "").toString().split(",")[0] || req.get("host");
  return `${proto}://${host}`;
};

// ---------- Supabase ----------
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

// Tables expected:
//   users(id uuid pk, email text unique, plan text default 'moon', created_at timestamptz default now())
//   usage_daily(id uuid pk, user_id uuid, date date default CURRENT_DATE, ask_count int default 0, search_count int default 0)

async function getOrCreateUserByEmail(email) {
  if (!email) return null;
  const lower = email.toLowerCase();
  let { data: rows, error } = await supabase.from("users").select("*").eq("email", lower).limit(1);
  if (error) throw error;
  if (rows && rows.length) return rows[0];
  const { data, error: insErr } = await supabase.from("users").insert([{ email: lower, plan: "moon" }]).select().single();
  if (insErr) throw insErr;
  return data;
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

async function getUsageRow(user_id) {
  const d = today();
  let { data: rows, error } = await supabase
    .from("usage_daily")
    .select("*")
    .eq("user_id", user_id)
    .eq("date", d)
    .limit(1);
  if (error) throw error;
  if (rows && rows.length) return rows[0];
  const { data, error: insErr } = await supabase
    .from("usage_daily")
    .insert([{ user_id, date: d, ask_count: 0, search_count: 0 }])
    .select()
    .single();
  if (insErr) throw insErr;
  return insErr || data;
}

async function bumpUsage(user_id, kind) {
  const d = today();
  const col = kind === "ask" ? "ask_count" : "search_count";
  const { data, error } = await supabase.rpc("increment_usage", { p_user_id: user_id, p_date: d, p_col: col });
  if (error) {
    // fallback if the RPC is not created—do an update
    const row = await getUsageRow(user_id);
    const next = (row[col] || 0) + 1;
    await supabase.from("usage_daily").update({ [col]: next }).eq("id", row.id);
  }
}

async function getPlanAndRemaining(user_id, plan) {
  const limits = {
    ask: plan === "moon" ? 40 : Infinity,
    search: plan === "moon" ? 20 : Infinity,
  };
  const usage = await getUsageRow(user_id);
  const remaining = {
    ask: limits.ask === Infinity ? Infinity : Math.max(0, limits.ask - (usage.ask_count || 0)),
    search: limits.search === Infinity ? Infinity : Math.max(0, limits.search - (usage.search_count || 0)),
  };
  return { limits, remaining, usage };
}

// ---------- Google OAuth ----------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/auth/google/callback",
      proxy: true,
    },
    async (_accessToken, _refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value || "";
        const userRow = await getOrCreateUserByEmail(email);
        const user = {
          id: userRow.id,
          email: userRow.email,
          plan: userRow.plan || "moon",
          name: profile.displayName,
          given_name: profile.name?.givenName,
          picture: profile.photos?.[0]?.value || "",
        };
        return done(null, user);
      } catch (e) {
        return done(e);
      }
    }
  )
);
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// ---------- Always-public routes (keep BEFORE guard) ----------
app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/auth/google", (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}/auth/google/callback`;
  passport.authenticate("google", { scope: ["profile", "email"], callbackURL })(req, res, next);
});
app.get("/auth/google/callback", (req, res, next) => {
  const callbackURL = `${getBaseUrl(req)}/auth/google/callback`;
  passport.authenticate("google", { failureRedirect: "/login.html", callbackURL })(req, res, () =>
    res.redirect("/")
  );
});
app.post("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.json({ ok: true }));
  });
});

app.get("/api/me", async (req, res) => {
  try {
    if (!req.user?.email) return res.json({ loggedIn: false, user: null, plan: "moon" });
    // refresh plan from DB
    const row = await getOrCreateUserByEmail(req.user.email);
    req.user.plan = row.plan || "moon";
    const { limits, remaining, usage } = await getPlanAndRemaining(req.user.id, req.user.plan);
    return res.json({
      loggedIn: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        given_name: req.user.given_name,
        picture: req.user.picture,
        plan: req.user.plan,
      },
      limits,
      remaining,
      used: { ask: usage.ask_count || 0, search: usage.search_count || 0 },
    });
  } catch (e) {
    return res.json({ loggedIn: false, user: null, plan: "moon" });
  }
});

// ---------- Static (home & legal pages are public) ----------
app.use(express.static(__dirname)); // serve your index.html, chat-advancedai.html, etc.

// ---------- Auth guard for gated features ----------
app.use((req, res, next) => {
  const p = req.path;
  const PUBLIC_FILE_EXT = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|txt|woff2?)$/i;
  if (
    p === "/" ||
    p === "/login.html" ||
    p === "/privacy.html" ||
    p === "/terms.html" ||
    p === "/refund.html" ||
    p === "/favicon.ico" ||
    p.startsWith("/auth/google") ||
    p === "/health" ||
    p === "/api/me" ||
    PUBLIC_FILE_EXT.test(p)
  ) {
    return next();
  }
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  if (req.accepts("html")) {
    return res
      .status(401)
      .send(
        '<div style="font:16px/1.5 system-ui; padding:32px; text-align:center">🔒 Please <a href="/auth/google">sign in with Google</a> to access this feature.<br/><a href="/">Back to home</a></div>'
      );
  }
  return res.status(401).json({ error: "Sign in required" });
});

// ---------- Login page (same as your original, inline so it works even w/o file) ----------
app.get("/login.html", (req, res) => {
  const base = getBaseUrl(req);
  res.send(`<!doctype html><html lang="en"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>GoldenSpaceAI — Log in</title><link rel="icon" href="/favicon.ico"/>
<style>
:root{--bg:#0b0f1a;--card:#12182a;--gold:#f0c419;--text:#e6ecff;--muted:#9fb0d1}
*{box-sizing:border-box}body{margin:0;font-family:Inter,system-ui,Segoe UI,Arial;background:radial-gradient(1200px 800px at 80% -10%,#1a2340 0%,#0b0f1a 60%,#070a12 100%);color:var(--text)}
.wrap{min-height:100dvh;display:grid;place-items:center;padding:24px}
.card{width:100%;max-width:520px;background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,.01));border:1px solid rgba(255,255,255,.08);border-radius:20px;padding:28px 24px;box-shadow:0 20px 60px rgba(0,0,0,.35)}
h1{margin:0 0 6px;font-size:28px}.sub{margin:0 0 18px;font-size:14px;color:var(--muted)}
.btn{display:flex;align-items:center;gap:10px;justify-content:center;width:100%;padding:12px 16px;border-radius:12px;border:none;font-size:16px;font-weight:700;cursor:pointer;background:#fff;color:#1f2937;border:1px solid rgba(0,0,0,.08)}
.btn:hover{box-shadow:0 8px 24px rgba(255,255,255,.08)}
.links{display:flex;gap:16px;margin-top:12px}a{color:var(--text)}
</style></head><body><div class="wrap"><div class="card">
<h1>Log in</h1>
<p class="sub">Sign in to continue to GoldenSpaceAI.</p>
<button class="btn" onclick="window.location='${base}/auth/google'"><img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" width="18" height="18"/> Continue with Google</button>
<div class="links"><a href="/">Back to home</a><a href="/privacy.html">Privacy</a></div>
</div></div></body></html>`);
});

// ---------- Models ----------
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// ---------- Plan helper ----------
async function ensurePlanAndLimit(req, kind) {
  // kind: "ask" or "search"
  const user = req.user;
  if (!user?.id) return { allowed: false, error: "Sign in required." };
  const { limits, remaining } = await getPlanAndRemaining(user.id, user.plan || "moon");
  const left = remaining[kind];
  if (left === Infinity || left > 0) {
    await bumpUsage(user.id, kind);
    return { allowed: true };
  }
  return { allowed: false, error: `Daily ${kind} limit reached for your plan.` };
}

// ---------- Simple Chat (Gemini) ----------
app.post("/ask", async (req, res) => {
  try {
    const q = (req.body?.question || "").trim();
    if (!q) return res.json({ answer: "Ask me anything!" });

    const gate = await ensurePlanAndLimit(req, "ask");
    if (!gate.allowed) return res.status(429).json({ answer: gate.error });

    // Keep a small in-session memory for basic chat too (last 20 messages)
    req.session.basicHistory ||= [];
    req.session.basicHistory.push({ role: "user", text: q });
    if (req.session.basicHistory.length > 40) req.session.basicHistory.splice(0, req.session.basicHistory.length - 40);

    const prompt = [
      { text: "You are GoldenSpaceAI. Answer clearly and concisely." },
      ...req.session.basicHistory.map((m) => ({ text: (m.role === "user" ? "User: " : "Assistant: ") + m.text })),
    ];

    const result = await geminiFlash.generateContent(prompt);
    const answer = result.response.text() || "No response.";
    req.session.basicHistory.push({ role: "assistant", text: answer });
    res.json({ answer });
  } catch (e) {
    console.error("ask error", e);
    res.status(500).json({ answer: "Gemini error" });
  }
});

// ---------- Search Info (Gemini) ----------
app.post("/search-info", async (req, res) => {
  try {
    const q = (req.body?.query || "").trim();
    if (!q) return res.json({ answer: "Type something to search." });

    const gate = await ensurePlanAndLimit(req, "search");
    if (!gate.allowed) return res.status(429).json({ answer: gate.error });

    const prompt = `You are GoldenSpace Knowledge. Give a short overview then 3 bullet facts.\nTopic: ${q}`;
    const result = await geminiFlash.generateContent([{ text: prompt }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  } catch (e) {
    console.error("search-info error", e);
    res.status(500).json({ answer: "Search error" });
  }
});

// ---------- Advanced Assistant (OpenAI, files + 20-message memory) ----------
const upload = multer();
app.post("/api/chat", upload.array("files"), async (req, res) => {
  try {
    const userText = (req.body?.message || "").trim();
    const files = req.files || [];

    // Session memory for Advanced Assistant
    req.session.advHistory ||= [
      { role: "system", content: "You are GoldenSpaceAI, a crisp, expert assistant. Keep answers concise and helpful." },
    ];

    // Append user message (with file notes)
    const userParts = [];
    if (userText) userParts.push({ type: "text", text: userText });

    // Convert uploads to inline image content (base64) when images
    for (const f of files) {
      if (f.mimetype.startsWith("image/")) {
        userParts.push({
          type: "input_image",
          image: {
            data: f.buffer.toString("base64"),
            mime_type: f.mimetype,
          },
        });
      } else {
        // Non-image: attach a short notice so the model knows a file existed
        userParts.push({ type: "text", text: `Attached file: ${f.originalname} (${f.mimetype}, ${f.size} bytes)` });
      }
    }

    if (userParts.length === 0) {
      return res.json({ reply: "Please type a message or attach a file." });
    }

    req.session.advHistory.push({ role: "user", content: userParts });

    // Trim to last ~20 turns (system + 20)
    if (req.session.advHistory.length > 41) {
      // keep system at index 0
      const system = req.session.advHistory[0];
      const tail = req.session.advHistory.slice(-40);
      req.session.advHistory = [system, ...tail];
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: req.session.advHistory,
      temperature: 0.4,
    });

    const reply = completion?.choices?.[0]?.message?.content || "No reply.";
    req.session.advHistory.push({ role: "assistant", content: reply });

    res.json({ reply });
  } catch (e) {
    console.error("advanced chat error", e);
    res.status(500).json({ reply: "Advanced AI error" });
  }
});

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));

/* ---------------------------
Optional SQL helper for atomic increments (create once in Supabase SQL editor):

create or replace function increment_usage(p_user_id uuid, p_date date, p_col text)
returns void language plpgsql as $$
begin
  insert into usage_daily(user_id, date, ask_count, search_count)
  values (p_user_id, p_date, 0, 0)
  on conflict (user_id, date) do nothing;

  if p_col = 'ask_count' then
    update usage_daily set ask_count = ask_count + 1 where user_id = p_user_id and date = p_date;
  elsif p_col = 'search_count' then
    update usage_daily set search_count = search_count + 1 where user_id = p_user_id and date = p_date;
  end if;
end $$;

Also ensure a unique constraint on (user_id, date):
alter table usage_daily add constraint usage_daily_unique unique (user_id, date);
----------------------------*/
