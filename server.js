// server.js
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 10000;

// Needed for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static files (your HTML, CSS, JS in "public")
app.use(express.static(path.join(__dirname, "public")));

// Example API route (for later, like Paddle or saving planets)
app.get("/api/ping", (req, res) => {
  res.json({ message: "Server is alive 🚀" });
});

// Fallback: send index.html
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
