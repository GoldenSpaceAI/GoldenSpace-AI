// index.js
document.addEventListener("DOMContentLoaded", () => {
  console.log("🚀 SpaceAI frontend loaded");

  // -------------------------------
  // Continue with Google button (kept as is)
  // -------------------------------
  const googleBtn = document.getElementById("google-login");
  if (googleBtn) {
    googleBtn.addEventListener("click", () => {
      window.location.href = "/auth/google"; // keeps your Google OAuth flow
    });
  }

  // -------------------------------
  // Space background (kept as is)
  // -------------------------------
  document.body.style.backgroundImage = "url('/images/space-bg.jpg')";
  document.body.style.backgroundSize = "cover";
  document.body.style.backgroundAttachment = "fixed";

  // -------------------------------
  // Unlock all plans for testing
  // -------------------------------
  function setPlan(plan) {
    localStorage.setItem("userPlan", plan);
    alert(`✅ Your plan has been set to: ${plan} (unlocked for testing)`);
    renderFeatures();
  }

  const planBtns = document.querySelectorAll(".plan-btn");
  planBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const plan = btn.dataset.plan; // e.g. "moon", "earth", "universe"
      setPlan(plan);
    });
  });

  // -------------------------------
  // Simple memory: store last 10 ChatAI Qs per user (by email)
  // -------------------------------
  function getUserEmail() {
    return localStorage.getItem("userEmail") || "guest@example.com";
  }

  function saveChatQuestion(question) {
    const email = getUserEmail();
    let memory = JSON.parse(localStorage.getItem("chatMemory")) || {};
    if (!memory[email]) memory[email] = [];
    memory[email].push(question);
    if (memory[email].length > 10) {
      memory[email].shift(); // keep only last 10
    }
    localStorage.setItem("chatMemory", JSON.stringify(memory));
  }

  function getChatMemory() {
    const email = getUserEmail();
    let memory = JSON.parse(localStorage.getItem("chatMemory")) || {};
    return memory[email] || [];
  }

  // Example hook: when user sends ChatAI question
  const chatForm = document.getElementById("chat-form");
  if (chatForm) {
    chatForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const input = document.getElementById("chat-input");
      const question = input.value.trim();
      if (question) {
        saveChatQuestion(question);
        console.log("💾 Saved question:", question);
        input.value = "";
      }
    });
  }

  // -------------------------------
  // Save "Create Your Planet" permanently per email
  // -------------------------------
  function savePlanet(data) {
    const email = getUserEmail();
    let planets = JSON.parse(localStorage.getItem("planets")) || {};
    if (!planets[email]) planets[email] = [];
    planets[email].push(data);
    localStorage.setItem("planets", JSON.stringify(planets));
  }

  const planetForm = document.getElementById("planet-form");
  if (planetForm) {
    planetForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const planetName = document.getElementById("planet-name").value.trim();
      if (planetName) {
        savePlanet({ name: planetName, created: new Date().toISOString() });
        alert(`🌍 Planet "${planetName}" saved forever for ${getUserEmail()}`);
      }
    });
  }

  // -------------------------------
  // Render features based on plan (for testing unlocked)
  // -------------------------------
  function renderFeatures() {
    const plan = localStorage.getItem("userPlan") || "universe"; // default unlocked
    console.log("✨ Rendering features for plan:", plan);

    // Example: unlock all sections
    document.querySelectorAll(".feature").forEach((el) => {
      el.style.display = "block";
    });
  }

  renderFeatures();
});
