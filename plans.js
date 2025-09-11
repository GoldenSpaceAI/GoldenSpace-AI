// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  moon: {
    ask: 10,
    search: 5,
    physics: 0,
    learnPhysics: false,
    createPlanet: false,
  },
  earth: {
    ask: 30,
    search: 20,
    physics: 5,
    learnPhysics: true,
    createPlanet: false,
  },
  sun: {
    ask: Infinity,
    search: Infinity,
    physics: Infinity,
    learnPhysics: true,
    createPlanet: true,
  },

  // NEW: Your Space (Universe) — focused on building; no physics learning
  yourspace: {
    ask: 50,
    search: 20,
    physics: 0,
    learnPhysics: false,
    createPlanet: true,   // can create planets & place them in Your Space
  },

  // NEW: Chat AI — study-focused features; no planet builder/physics learning
  chatai: {
    ask: Infinity,
    search: Infinity,
    physics: 0,
    learnPhysics: false,
    createPlanet: false,
  },
};
