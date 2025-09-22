/* GoldenY — Local memory chat (static site version) */

// ======= DOM =======
const chatLog = document.getElementById('chatLog');
const userInput = document.getElementById('userInput');
const sendBtn = document.getElementById('sendBtn');
const resetBtn = document.getElementById('resetBtn');

// ======= Local Storage =======
const LS = {
  messagesKey: 'goldeny_messages_v1',
  factsKey: 'goldeny_facts_v1',
  load(k) { try { return JSON.parse(localStorage.getItem(k)) || []; } catch { return []; } },
  save(k, v) { localStorage.setItem(k, JSON.stringify(v)); },
  clear() { localStorage.clear(); }
};

let MESSAGES = LS.load(LS.messagesKey);
let FACTS = LS.load(LS.factsKey);

// ======= Knowledge Base =======
const knowledgeBase = [];

function addQA({ keywords = [], answer = '' }) {
  knowledgeBase.push({ type: 'keywords', keywords: keywords.map(k => k.toLowerCase()), answer });
}
function addQAExact({ question = '', answer = '' }) {
  knowledgeBase.push({ type: 'exact', question: question.trim().toLowerCase(), answer });
}

// Example Q&A
addQAExact({ question: 'what is goldeny?', answer: 'GoldenY is your friendly study assistant built by Faris.' });
addQA({ keywords: ['math','homework'], answer: 'For math homework, write what is known, what is asked, then solve step by step.' });
addQA({ keywords: ['name','who'], answer: "I'm GoldenY — happy to help with schoolwork, coding, and quick facts!" });

// ======= Render =======
function renderMessages() {
  chatLog.innerHTML = '';
  for (const m of MESSAGES) {
    const row = document.createElement('div');
    row.className = 'row ' + (m.role === 'user' ? 'user' : 'bot');
    row.innerHTML = `<div class="bubble"><strong>${m.role === 'user' ? 'You' : 'GoldenY'}</strong><br>${escapeHTML(m.content)}</div>`;
    chatLog.appendChild(row);
  }
  chatLog.scrollTop = chatLog.scrollHeight;
}

function pushMessage(role, content) {
  MESSAGES.push({ role, content, ts: Date.now() });
  LS.save(LS.messagesKey, MESSAGES);
  renderMessages();
}

// ======= Learning =======
function learnFrom(text) {
  const addFact = (k,v) => { FACTS.push({k,v,ts:Date.now()}); LS.save(LS.factsKey, FACTS); };
  let m;
  if ((m = text.match(/my name is\\s+([a-zA-Z ]{2,40})/i))) addFact('name', m[1].trim());
  if ((m = text.match(/remember that\\s+(.{3,120})/i))) addFact('note', m[1].trim());
  if ((m = text.match(/i like\\s+(.{2,60})/i))) addFact('likes', m[1].trim());
}

// ======= Answer Logic =======
function bestSeededAnswer(userText) {
  const t = userText.trim().toLowerCase();
  for (const item of knowledgeBase) {
    if (item.type === 'exact' && t === item.question) return item.answer;
  }
  let best = { ans:null, score:0 };
  for (const item of knowledgeBase) {
    if (item.type!=='keywords') continue;
    const score = item.keywords.reduce((a,kw)=>a+(t.includes(kw)?1:0),0);
    if (score>best.score) best={ans:item.answer,score};
  }
  return best.ans;
}

function fallbackAnswer() {
  const name = FACTS.find(f=>f.k==='name');
  return (name?`Hi ${name.v}! `:'') + "I don't know that yet. You can teach me by typing 'remember that ...'.";
}

// ======= Events =======
async function handleUserMessage() {
  const text = (userInput.value||'').trim();
  if(!text) return;
  pushMessage('user', text);
  learnFrom(text);
  let reply = bestSeededAnswer(text) || fallbackAnswer();
  pushMessage('bot', reply);
  userInput.value='';
}

sendBtn.addEventListener('click', handleUserMessage);
userInput.addEventListener('keydown', e => { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();handleUserMessage();} });
resetBtn.addEventListener('click', ()=>{ if(confirm('Clear chat?')){MESSAGES=[];FACTS=[];LS.clear();renderMessages();} });

// ======= Utils =======
function escapeHTML(s){return s.replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}

// ======= Boot =======
renderMessages();
if(!MESSAGES.length) pushMessage('bot',"Hey! I'm GoldenY. Tell me your name (e.g., 'my name is Faris') or ask me something.");
