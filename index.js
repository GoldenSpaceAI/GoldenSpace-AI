<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <title>Create Your Advanced Planet • GoldenSpaceAI</title>
  <style>
    body {
      margin: 0;
      font-family: Inter, system-ui, sans-serif;
      background: url("https://images.unsplash.com/photo-1580428180163-9c89365a2d50?q=80&w=1920&auto=format&fit=crop") center/cover fixed;
      color: #f9f9f9;
      padding: 0;
    }
    header {
      padding: 16px;
      background: rgba(10, 14, 21, 0.8);
      border-bottom: 1px solid rgba(255,255,255,.1);
      color: #f6c64a;
      font-size: 20px;
      font-weight: 800;
      text-align: center;
    }
    main {
      max-width: 900px;
      margin: 20px auto;
      background: rgba(15, 22, 36, 0.9);
      padding: 20px;
      border-radius: 16px;
      box-shadow: 0 12px 40px rgba(0,0,0,0.5);
    }
    h2 {
      margin-top: 28px;
      color: #f6c64a;
      font-size: 20px;
    }
    label {
      display: block;
      margin: 10px 0 4px;
      font-weight: 600;
    }
    input, select {
      width: 100%;
      padding: 8px;
      border-radius: 8px;
      border: none;
      background: #0f1624;
      color: #fff;
      font-size: 14px;
    }
    input[type=range] {
      padding: 0;
    }
    .section {
      margin-bottom: 20px;
      border-bottom: 1px solid rgba(255,255,255,.08);
      padding-bottom: 20px;
    }
    #preview {
      background: #111a2d;
      border: 1px solid rgba(255,255,255,.1);
      border-radius: 12px;
      padding: 16px;
      margin-top: 20px;
      font-size: 14px;
      color: #d0d7e4;
    }
    .btn {
      display: inline-block;
      margin-top: 20px;
      padding: 12px 20px;
      border-radius: 12px;
      font-weight: 800;
      background: linear-gradient(180deg, #f6c64a, #eb8b36);
      border: none;
      color: #1a1200;
      cursor: pointer;
      box-shadow: 0 8px 20px rgba(246,198,74,.3);
    }
    .btn:hover {
      transform: translateY(-1px);
    }
    #message {
      margin-top: 20px;
      font-size: 14px;
      color: #ffecb3;
    }
  </style>
</head>
<body>
  <header>🌌 GoldenSpaceAI — Create Your Advanced Planet</header>
  <main>
    <h1>Create Your Advanced Planet</h1>
    <p>Customize everything: climate, oceans, life, and unique features. When done, build your planet!</p>

    <!-- Planet Basics -->
    <div class="section">
      <h2>Planet Basics</h2>
      <label>Planet Name</label>
      <input type="text" id="planetName" placeholder="Enter planet name"/>
      
      <label>Size</label>
      <select id="planetSize">
        <option>Small</option>
        <option>Earth-like</option>
        <option>Giant</option>
      </select>

      <label>Gravity Level</label>
      <select id="gravity">
        <option>Low</option>
        <option>Medium</option>
        <option>High</option>
      </select>
    </div>

    <!-- Environment -->
    <div class="section">
      <h2>Environment & Climate</h2>
      <label>Temperature (°C)</label>
      <input type="range" id="temp" min="-200" max="500" value="25"/>
      <span id="tempVal">25°C</span>

      <label>Atmosphere</label>
      <select id="atmosphere">
        <option>Oxygen-rich</option>
        <option>Carbon-heavy</option>
        <option>Methane</option>
        <option>Custom</option>
      </select>

      <label>Weather</label>
      <select id="weather">
        <option>Calm</option>
        <option>Stormy</option>
        <option>Windy</option>
        <option>Snowy</option>
        <option>Mixed</option>
      </select>
    </div>

    <!-- Oceans -->
    <div class="section">
      <h2>Oceans & Land</h2>
      <label>Water Coverage (%)</label>
      <input type="range" id="water" min="0" max="100" value="70"/>
      <span id="waterVal">70%</span>

      <label>Ocean Color</label>
      <select id="oceanColor">
        <option>Blue</option>
        <option>Green</option>
        <option>Red</option>
        <option>Black</option>
      </select>

      <label>Continents</label>
      <input type="number" id="continents" value="5"/>
    </div>

    <!-- Life -->
    <div class="section">
      <h2>Life & Ecosystem</h2>
      <label>Type of Life</label>
      <select id="life">
        <option>None</option>
        <option>Microbial</option>
        <option>Plants</option>
        <option>Animals</option>
        <option>Intelligent Civilization</option>
      </select>

      <label>Diversity</label>
      <input type="range" id="diversity" min="0" max="10" value="5"/>
      <span id="divVal">5</span>

      <label>Civilization Level</label>
      <select id="civLevel">
        <option>Stone Age</option>
        <option>Industrial</option>
        <option>Futuristic</option>
      </select>
    </div>

    <!-- Special -->
    <div class="section">
      <h2>Special Features</h2>
      <label>Rings</label>
      <select id="rings">
        <option>No</option>
        <option>Yes</option>
      </select>

      <label>Number of Moons</label>
      <input type="number" id="moons" value="1"/>

      <label>Magnetic Field</label>
      <select id="magField">
        <option>Weak</option>
        <option>Strong</option>
        <option>None</option>
      </select>

      <label>Core Type</label>
      <select id="core">
        <option>Iron</option>
        <option>Ice</option>
        <option>Exotic</option>
      </select>
    </div>

    <button class="btn" id="buildBtn">🚀 Build Advanced Planet</button>
    <div id="message"></div>

    <div id="preview"></div>
  </main>

  <script>
    const temp = document.getElementById("temp");
    const tempVal = document.getElementById("tempVal");
    temp.oninput = () => tempVal.textContent = temp.value + "°C";

    const water = document.getElementById("water");
    const waterVal = document.getElementById("waterVal");
    water.oninput = () => waterVal.textContent = water.value + "%";

    const diversity = document.getElementById("diversity");
    const divVal = document.getElementById("divVal");
    diversity.oninput = () => divVal.textContent = diversity.value;

    document.getElementById("buildBtn").onclick = async () => {
      const planet = {
        name: document.getElementById("planetName").value,
        size: document.getElementById("planetSize").value,
        gravity: document.getElementById("gravity").value,
        temp: temp.value,
        atmosphere: document.getElementById("atmosphere").value,
        weather: document.getElementById("weather").value,
        water: water.value,
        oceanColor: document.getElementById("oceanColor").value,
        continents: document.getElementById("continents").value,
        life: document.getElementById("life").value,
        diversity: diversity.value,
        civLevel: document.getElementById("civLevel").value,
        rings: document.getElementById("rings").value,
        moons: document.getElementById("moons").value,
        magField: document.getElementById("magField").value,
        core: document.getElementById("core").value,
      };

      const res = await fetch("/api/me", { credentials: "include" });
      const data = await res.json();

      if (data.plan === "sun" || data.plan === "universe") {
        document.getElementById("message").textContent = "✅ Planet created! Saved to your account.";
        document.getElementById("preview").textContent = JSON.stringify(planet, null, 2);
      } else {
        document.getElementById("message").textContent = "⚠️ Please upgrade to Sun Pack or Your Space Pack to build advanced planets.";
      }
    };
  </script>
</body>
</html>
