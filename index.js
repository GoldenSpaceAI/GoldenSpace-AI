document.addEventListener("DOMContentLoaded", () => {
  const loginBtn = document.getElementById("google-login-btn");
  const featureButtons = document.querySelectorAll(".feature-btn");
  const modal = document.getElementById("universe-modal");
  const nextBtn = document.getElementById("next-btn");
  const backBtn = document.getElementById("back-btn");
  const stepTitle = document.getElementById("step-title");
  const stepDescription = document.getElementById("step-description");
  const closeModalBtn = document.getElementById("close-modal");

  let currentStep = 0;
  let loggedInUser = null;

  const steps = [
    { title: "Welcome to Universe Pack", description: "Explore the whole universe with AI." },
    { title: "Galaxies", description: "Generate amazing galaxies." },
    { title: "Planets", description: "Build planets and customize them." },
    { title: "Rockets", description: "Design rockets to explore space." },
    { title: "Publish", description: "Save and publish your creations 🚀" }
  ];

  // ✅ Handle Google login
  loginBtn.addEventListener("click", async () => {
    try {
      // Redirect to backend Google login
      window.location.href = "/auth/google";
    } catch (err) {
      console.error("Login error:", err);
    }
  });

  // ✅ Check login status on load
  async function checkLoginStatus() {
    try {
      const res = await fetch("/auth/status");
      const data = await res.json();

      if (data.loggedIn) {
        loggedInUser = data.user;
        loginBtn.textContent = `Welcome, ${loggedInUser.displayName}`;
        unlockAllFeatures();
      } else {
        loginBtn.textContent = "Continue with Google";
      }
    } catch (err) {
      console.error("Status check failed:", err);
    }
  }

  // ✅ Unlock all features
  function unlockAllFeatures() {
    featureButtons.forEach(btn => {
      btn.classList.remove("locked");
      btn.disabled = false;
    });
  }

  // ✅ Feature button click
  featureButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      if (!loggedInUser) {
        alert("Please log in with Google to unlock this feature.");
        return;
      }
      if (btn.id === "universe-pack-btn") {
        openModal();
      } else if (btn.id === "create-planet-btn") {
        savePlanet();
      } else {
        alert(`${btn.textContent} feature unlocked! 🚀`);
      }
    });
  });

  // ✅ Open Universe Pack modal
  function openModal() {
    currentStep = 0;
    updateStep();
    modal.style.display = "flex";
  }

  // ✅ Close modal
  closeModalBtn.addEventListener("click", () => {
    modal.style.display = "none";
  });

  // ✅ Modal navigation
  nextBtn.addEventListener("click", () => {
    if (currentStep < steps.length - 1) {
      currentStep++;
      updateStep();
    }
  });

  backBtn.addEventListener("click", () => {
    if (currentStep > 0) {
      currentStep--;
      updateStep();
    }
  });

  function updateStep() {
    stepTitle.textContent = steps[currentStep].title;
    stepDescription.textContent = steps[currentStep].description;
  }

  // ✅ Save Planet (backend memory)
  async function savePlanet() {
    const planetName = prompt("Enter a name for your planet:");
    if (!planetName) return;

    try {
      const res = await fetch("/api/savePlanet", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user: loggedInUser.email, planetName })
      });

      if (res.ok) {
        alert(`Planet "${planetName}" saved to your account 🌍`);
      } else {
        alert("Error saving planet.");
      }
    } catch (err) {
      console.error("Save planet error:", err);
      alert("Failed to save planet.");
    }
  }

  // Run login check on page load
  checkLoginStatus();
});
