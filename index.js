// index.js — GoldenSpaceAI (Supabase + Plans + Auth + Blocks)

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import multer from "multer";
import { createClient } from "@supabase/supabase-js";
import OpenAI from "openai";
import { GoogleGenerativeAI } from "@google/generative-ai";

dotenv.config();
const app = express();
app.set("trust proxy", 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// ---------- Supabase ----------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_ROLE
);

// ---------- Paths ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- AI Clients ----------
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const geminiFlash = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon: { ask: 40, search: 20, chatAdvanced: 0, homework: 0, space: false },
  earth: { ask: Infinity, search: Infinity, chatAdvanced: 0, homework: 0, space: false },
  chatpack: { ask: Infinity, search: Infinity, chatAdvanced: Infinity, homework: Infinity, space: false },
  yourspace: { ask: 40, search: 20, chatAdvanced: 0, homework: 0, space: true },
};

// ---------- Helpers ----------
function today() {
  return new Date().toISOString().slice(0, 10);
}

async function getUserPlan(userId) {
  const { data, error } = await supabase.from("users").select("plan").eq("id", userId).single();
  if (error || !data) return "moon";
  return data.plan || "moon";
}

async function checkAllowed(userId, kind) {
  const plan = await getUserPlan(userId);
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS["moon"];
  const allowed = limits[kind];

  if (allowed === 0) return { ok: false, reason: `Your plan does not allow ${kind}.` };
  if (allowed === Infinity) return { ok: true };

  // Count usage from DB
  const { data } = await supabase.from("use_daily").select("*").eq("user_id", userId).eq("date", today()).single();

  const current = data || { date: today(), ask: 0, search: 0 };
  if (current[kind] >= allowed) return { ok: false, reason: `Daily ${kind} limit reached.` };

  // Update count
  current[kind] = (current[kind] || 0) + 1;
  if (data) {
    await supabase.from("use_daily").update(current).eq("user_id", userId).eq("date", today());
  } else {
    await supabase.from("use_daily").insert({ user_id: userId, date: today(), ...current });
  }
  return { ok: true };
}

// ---------- Auth Routes ----------
app.get("/login.html", (_req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

app.get("/", async (req, res) => {
  // Always redirect root to login first
  res.redirect("/login.html");
});

// ---------- API: User info ----------
app.get("/api/me", async (req, res) => {
  const token = req.headers["authorization"]?.replace("Bearer ", "");
  if (!token) return res.json({ loggedIn: false });

  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.json({ loggedIn: false });

  const plan = await getUserPlan(user.id);
  res.json({ loggedIn: true, user, plan });
});

// ---------- AI Routes ----------
const upload = multer({ dest: "uploads/" });

app.post("/api/chat", upload.array("files"), async (req, res) => {
  const token = req.headers["authorization"]?.replace("Bearer ", "");
  const { data: { user } } = await supabase.auth.getUser(token);
  if (!user) return res.status(401).json({ error: "Sign in required" });

  const check = await checkAllowed(user.id, "ask");
  if (!check.ok) return res.status(403).json({ error: check.reason });

  const message = (req.body?.message || "").trim();
  if (!message && (!req.files || req.files.length === 0)) {
    return res.json({ reply: "Send me a question or upload a file." });
  }

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are GoldenSpaceAI, a crisp assistant." },
        { role: "user", content: message },
      ],
    });
    res.json({ model: "gpt-4o-mini", reply: completion.choices[0].message.content });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "OpenAI error" });
  }
});

app.post("/api/search-info", async (req, res) => {
  const token = req.headers["authorization"]?.replace("Bearer ", "");
  const { data: { user } } = await supabase.auth.getUser(token);
  if (!user) return res.status(401).json({ error: "Sign in required" });

  const check = await checkAllowed(user.id, "search");
  if (!check.ok) return res.status(403).json({ error: check.reason });

  const q = (req.body?.query || "").trim();
  if (!q) return res.json({ answer: "Type something to search." });

  try {
    const result = await geminiFlash.generateContent([{ text: `Overview + 3 bullet facts about: ${q}` }]);
    const answer = result.response.text() || "No info found.";
    res.json({ answer });
  } catch (e) {
    console.error(e);
    res.status(500).json({ answer: "Search error" });
  }
});

// Homework route (OpenAI vision)
app.post("/api/homework", upload.single("file"), async (req, res) => {
  const token = req.headers["authorization"]?.replace("Bearer ", "");
  const { data: { user } } = await supabase.auth.getUser(token);
  if (!user) return res.status(401).json({ error: "Sign in required" });

  const plan = await getUserPlan(user.id);
  if (PLAN_LIMITS[plan].homework === 0) {
    return res.status(403).json({ error: "Your plan does not allow homework solving." });
  }

  const text = req.body?.message || "";
  const file = req.file;

  try {
    if (!file) return res.status(400).json({ error: "No file uploaded" });

    const base64Image = Buffer.from(await fs.promises.readFile(file.path)).toString("base64");

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: "You are a homework solving assistant." },
        { role: "user", content: text },
        { role: "user", content: [{ type: "image_url", image_url: { url: `data:image/png;base64,${base64Image}` } }] },
      ],
    });

    res.json({ reply: completion.choices[0].message.content });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Homework error" });
  }
});

// ---------- Static ----------
app.use(express.static(__dirname));
app.get("/health", (_req, res) => res.json({ ok: true }));

// ---------- Start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 GoldenSpaceAI running on ${PORT}`));
