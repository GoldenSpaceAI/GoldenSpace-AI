// ---------- Plan definitions ----------
const PLAN_LIMITS = {
  free: {
    ask: 20,            // small allowance for chatting
    search: 0,          // no search
    physics: 0,         // no physics solver
    learnPhysics: false,
    createPlanet: false,
    advanced: false,
    rocket: false,
    satellite: false,
    universe: false,
    exams: false,
  },

  starter: {
    ask: 100,           // bigger allowance
    search: 20,         // can use search-info
    physics: 0,
    learnPhysics: false,
    createPlanet: false,
    advanced: false,
    rocket: false,
    satellite: false,
    universe: false,
    exams: false,
  },

  plus: {
    ask: Infinity,      // unlimited chat
    search: Infinity,   // unlimited search
    physics: 10,        // small physics limit
    learnPhysics: true,
    createPlanet: true, // can create planets
    advanced: false,
    rocket: false,
    satellite: false,
    universe: false,
    exams: false,
  },

  pro: {
    ask: Infinity,
    search: Infinity,
    physics: Infinity,
    learnPhysics: true,
    createPlanet: true,
    advanced: true,     // unlock advanced chat
    rocket: true,
    satellite: true,
    universe: true,
    exams: true,        // unlock exam prep & grading
  },

  ultra: {
    ask: Infinity,
    search: Infinity,
    physics: Infinity,
    learnPhysics: true,
    createPlanet: true,
    advanced: true,
    rocket: true,
    satellite: true,
    universe: true,
    exams: true,
  },
};

export default PLAN_LIMITS;
