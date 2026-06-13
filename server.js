import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import fs from 'fs';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taloosh-secret-2025';
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY || '';

// ── DATABASE ──
fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
const db = new Database(path.join(__dirname, 'data', 'taloosh.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    last_login INTEGER
  );
  CREATE TABLE IF NOT EXISTS profiles (
    user_id TEXT PRIMARY KEY,
    contract TEXT, seniority INTEGER, degree TEXT,
    subject TEXT, institution TEXT, hours INTEGER,
    gender TEXT, kids INTEGER, homeroom INTEGER DEFAULT 0, role TEXT,
    updated_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    title TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS analysis_reports (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    conversation_id TEXT,
    report_json TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  );
`);

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(__dirname));

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'לא מחובר' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'פג תוקף החיבור' }); }
}

// ── AUTH ──
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'אימייל וסיסמה נדרשים' });
  if (password.length < 6) return res.status(400).json({ error: 'סיסמה חייבת להיות לפחות 6 תווים' });
  try {
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email))
      return res.status(409).json({ error: 'האימייל כבר רשום' });
    const id = uuidv4();
    db.prepare('INSERT INTO users (id,email,password_hash,name) VALUES (?,?,?,?)')
      .run(id, email, await bcrypt.hash(password, 10), name || '');
    const token = jwt.sign({ id, email, name: name||'' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id, email, name: name||'' } });
  } catch(e) { res.status(500).json({ error: 'שגיאה בהרשמה' }); }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'אימייל וסיסמה נדרשים' });
  try {
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!user || !await bcrypt.compare(password, user.password_hash))
      return res.status(401).json({ error: 'אימייל או סיסמה שגויים' });
    db.prepare('UPDATE users SET last_login=unixepoch() WHERE id=?').run(user.id);
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch(e) { res.status(500).json({ error: 'שגיאה בהתחברות' }); }
});

app.get('/api/auth/me', auth, (req, res) => {
  const user = db.prepare('SELECT id,email,name FROM users WHERE id=?').get(req.user.id);
  res.json(user);
});

// ── PROFILE ──
app.get('/api/profile', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM profiles WHERE user_id=?').get(req.user.id) || {});
});

app.post('/api/profile', auth, (req, res) => {
  const { contract,seniority,degree,subject,institution,hours,gender,kids,homeroom,role } = req.body;
  const ex = db.prepare('SELECT user_id FROM profiles WHERE user_id=?').get(req.user.id);
  if (ex) {
    db.prepare('UPDATE profiles SET contract=?,seniority=?,degree=?,subject=?,institution=?,hours=?,gender=?,kids=?,homeroom=?,role=?,updated_at=unixepoch() WHERE user_id=?')
      .run(contract,seniority,degree,subject,institution,hours,gender,kids,homeroom?1:0,role,req.user.id);
  } else {
    db.prepare('INSERT INTO profiles (user_id,contract,seniority,degree,subject,institution,hours,gender,kids,homeroom,role) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(req.user.id,contract,seniority,degree,subject,institution,hours,gender,kids,homeroom?1:0,role);
  }
  res.json({ ok: true });
});

// ── CONVERSATIONS ──
app.get('/api/conversations', auth, (req, res) => {
  const convs = db.prepare('SELECT c.*,(SELECT content FROM messages WHERE conversation_id=c.id ORDER BY created_at DESC LIMIT 1) as last_message FROM conversations c WHERE c.user_id=? ORDER BY c.updated_at DESC LIMIT 50').all(req.user.id);
  res.json(convs);
});

app.post('/api/conversations', auth, (req, res) => {
  const id = uuidv4();
  db.prepare('INSERT INTO conversations (id,user_id,title) VALUES (?,?,?)').run(id, req.user.id, req.body.title||'שיחה חדשה');
  res.json({ id, title: req.body.title||'שיחה חדשה' });
});

app.get('/api/conversations/:id/messages', auth, (req, res) => {
  const conv = db.prepare('SELECT * FROM conversations WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!conv) return res.status(404).json({ error: 'לא נמצא' });
  const msgs = db.prepare('SELECT * FROM messages WHERE conversation_id=? ORDER BY created_at ASC').all(req.params.id);
  res.json(msgs.map(m => ({ ...m, content: JSON.parse(m.content) })));
});

app.delete('/api/conversations/:id', auth, (req, res) => {
  const conv = db.prepare('SELECT * FROM conversations WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!conv) return res.status(404).json({ error: 'לא נמצא' });
  db.prepare('DELETE FROM messages WHERE conversation_id=?').run(req.params.id);
  db.prepare('DELETE FROM conversations WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ── AI CHAT ──
app.post('/api/chat', auth, async (req, res) => {
  if (!ANTHROPIC_KEY) return res.status(500).json({ error: 'API Key לא מוגדר בשרת' });
  const { messages, system, conversation_id, save } = req.body;
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'x-api-key':ANTHROPIC_KEY, 'anthropic-version':'2023-06-01' },
      body: JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:2000, system:system||getSystem(), messages:(messages||[]).slice(-16) })
    });
    const data = await r.json();
    if (data.error) return res.status(400).json({ error: data.error.message });

    if (save && conversation_id && messages?.length) {
      const conv = db.prepare('SELECT id FROM conversations WHERE id=? AND user_id=?').get(conversation_id, req.user.id);
      if (conv) {
        const last = messages[messages.length-1];
        db.prepare('INSERT INTO messages (id,conversation_id,role,content) VALUES (?,?,?,?)').run(uuidv4(),conversation_id,last.role,JSON.stringify(last.content));
        db.prepare('INSERT INTO messages (id,conversation_id,role,content) VALUES (?,?,?,?)').run(uuidv4(),conversation_id,'assistant',JSON.stringify(data.content?.[0]?.text||''));
        db.prepare('UPDATE conversations SET updated_at=unixepoch() WHERE id=?').run(conversation_id);
        if (last.role==='user' && typeof last.content==='string') {
          const title = last.content.substring(0,40);
          db.prepare("UPDATE conversations SET title=? WHERE id=? AND title='שיחה חדשה'").run(title, conversation_id);
        }
      }
    }
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── ANALYZE ──
app.post('/api/analyze', auth, async (req, res) => {
  if (!ANTHROPIC_KEY) return res.status(500).json({ error: 'API Key לא מוגדר' });
  const { messages, conversation_id } = req.body;
  const profile = db.prepare('SELECT * FROM profiles WHERE user_id=?').get(req.user.id);
  const profStr = profile ? `פרופיל: חוזה ${profile.contract||'?'}, ותק ${profile.seniority||'?'} שנים` : '';
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
      body:JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:4000,
        system:`אתה מנתח תלושי שכר מומחה לעובדי הוראה בישראל. ${profStr}
נתח את התלוש: זהה חוזה/ותק/שכר, בדוק כל רכיב עם ✅/⚠️/❌, חשב פוטנציאל גבייה, תן צעדים לתיקון. ענה בעברית.`,
        messages:(messages||[]).slice(-4) })
    });
    const data = await r.json();
    if (data.error) return res.status(400).json({ error: data.error.message });
    if (conversation_id) {
      const conv = db.prepare('SELECT id FROM conversations WHERE id=? AND user_id=?').get(conversation_id, req.user.id);
      if (conv && messages?.length) {
        const last = messages[messages.length-1];
        db.prepare('INSERT INTO messages (id,conversation_id,role,content) VALUES (?,?,?,?)').run(uuidv4(),conversation_id,last.role,JSON.stringify(last.content));
        db.prepare('INSERT INTO messages (id,conversation_id,role,content) VALUES (?,?,?,?)').run(uuidv4(),conversation_id,'assistant',JSON.stringify(data.content?.[0]?.text||''));
        db.prepare('UPDATE conversations SET updated_at=unixepoch() WHERE id=?').run(conversation_id);
      }
    }
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── LETTER ──
app.post('/api/letter', auth, async (req, res) => {
  if (!ANTHROPIC_KEY) return res.status(500).json({ error: 'API Key לא מוגדר' });
  const { letterType, issues, teacherProfile } = req.body;
  const profile = db.prepare('SELECT * FROM profiles WHERE user_id=?').get(req.user.id);
  const user = db.prepare('SELECT name FROM users WHERE id=?').get(req.user.id);
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{'Content-Type':'application/json','x-api-key':ANTHROPIC_KEY,'anthropic-version':'2023-06-01'},
      body:JSON.stringify({ model:'claude-sonnet-4-6', max_tokens:1500,
        system:'כתוב מכתב עברי מקצועי לעובד הוראה עם הפניות לסעיפי חוק.',
        messages:[{role:'user',content:`סוג: ${letterType}\nשם: ${user?.name||''}\nפרופיל: ${JSON.stringify(profile||teacherProfile||{})}\nבעיות: ${JSON.stringify(issues||[])}`}] })
    });
    const data = await r.json();
    res.json({ letter: data.content?.[0]?.text||'' });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

function getSystem(){
  return `אתה "תלוש חכם" — סוכן AI מומחה לשכר וזכויות עובדי הוראה בישראל. אתה יועץ פעיל ויוזם.
אופק חדש: 0-2→₪7,800 | 3-5→₪8,400 | 6-8→₪9,100 | 9-11→₪9,700 | 12-14→₪10,400 | 15-17→₪11,200 | 18-20→₪12,100 | 21-25→₪13,200 | 26-30→₪14,500 | 31+→₪16,200
עוז לתמורה: 0-2→₪8,200 | 3-5→₪8,900 | 6-8→₪9,600 | 9-11→₪10,300 | 12-14→₪11,100 | 15-17→₪12,000 | 18-20→₪13,100 | 21-25→₪14,400 | 26-30→₪15,800 | 31+→₪17,500
תוספות תואר אופק: ראשון+₪800 שני+₪1,600 דוקטורט+₪2,800
תוספות תואר עוז: ראשון+₪900 שני+₪1,800 דוקטורט+₪3,200
כיתת אם: אופק ₪820 | עוז ₪900 | פנסיה 20.83% | קרן השתלמות 10% | שעת מילוי מקום: אופק ₪72.5 | עוז ₪85
כלל: ענה בעברית עם ₪ מדויקים. אל תשאל שוב על מידע שנמסר. לאחר ניתוח הצע מכתב.`;
}

app.get('*', (req, res) => res.sendFile(path.join(__dirname, "index.html")));

app.listen(PORT, () => console.log(`✅ תלוש חכם רץ על פורט ${PORT} | API Key: ${ANTHROPIC_KEY?'✓':'✗ חסר!'}`));
