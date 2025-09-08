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
};
