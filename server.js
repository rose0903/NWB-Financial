const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(process.env.DB_PATH || path.join(__dirname, "nwb.sqlite"));

db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wallets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  currency TEXT NOT NULL,
  balance REAL NOT NULL DEFAULT 0,
  UNIQUE(user_id, currency),
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  currency TEXT NOT NULL,
  amount REAL NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'completed',
  reference TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const currencies = ["USD","GBP","EUR","NGN","ZAR","CAD","AUD"];
const ratesToUSD = { USD:1, GBP:1.28, EUR:1.09, NGN:0.00067, ZAR:0.055, CAD:0.73, AUD:0.66 };

function seed() {
  const existing = db.prepare("SELECT id FROM users WHERE email=?").get("admin@nwb.local");
  if (!existing) {
    const hash = bcrypt.hashSync("Admin123!", 10);
    const info = db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)")
      .run("NWB Administrator","admin@nwb.local",hash,"admin");
    currencies.forEach(c => db.prepare("INSERT INTO wallets(user_id,currency,balance) VALUES(?,?,?)")
      .run(info.lastInsertRowid,c,0));
  }
}
seed();

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 86400000 }
}));

function auth(req,res,next) {
  if (!req.session.userId) return res.status(401).json({error:"Please sign in."});
  next();
}
function admin(req,res,next) {
  if (!req.session.userId) return res.status(401).json({error:"Please sign in."});
  const u = db.prepare("SELECT role FROM users WHERE id=?").get(req.session.userId);
  if (!u || u.role !== "admin") return res.status(403).json({error:"Administrator access required."});
  next();
}
function ref() {
  return "NWB-" + Date.now().toString(36).toUpperCase() + "-" + Math.random().toString(36).slice(2,8).toUpperCase();
}

app.post("/api/register", async (req,res) => {
  const {name,email,password} = req.body;
  if (!name || !email || !password || password.length < 8)
    return res.status(400).json({error:"Name, email and an 8-character password are required."});
  try {
    const hash = await bcrypt.hash(password,10);
    const info = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name.trim(),email.trim().toLowerCase(),hash);
    const id = info.lastInsertRowid;
    const insertWallet = db.prepare("INSERT INTO wallets(user_id,currency,balance) VALUES(?,?,0)");
    currencies.forEach(c => insertWallet.run(id,c));
    req.session.userId = id;
    res.json({ok:true});
  } catch(e) {
    res.status(400).json({error:"That email is already registered."});
  }
});

app.post("/api/login", async (req,res) => {
  const {email,password} = req.body;
  const u = db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
  if (!u || !(await bcrypt.compare(password||"",u.password_hash)))
    return res.status(401).json({error:"Invalid email or password."});
  req.session.userId = u.id;
  res.json({ok:true, role:u.role});
});

app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/me", auth, (req,res) => {
  const u = db.prepare("SELECT id,name,email,role,created_at FROM users WHERE id=?").get(req.session.userId);
  const wallets = db.prepare("SELECT currency,balance FROM wallets WHERE user_id=? ORDER BY currency").all(u.id);
  const transactions = db.prepare("SELECT type,currency,amount,description,status,reference,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 50").all(u.id);
  res.json({user:u,wallets,transactions});
});

app.post("/api/transfer", auth, (req,res) => {
  const {currency,amount,description} = req.body;
  const n = Number(amount);
  if (!currencies.includes(currency) || !Number.isFinite(n) || n <= 0)
    return res.status(400).json({error:"Enter a valid currency and amount."});
  const wallet = db.prepare("SELECT balance FROM wallets WHERE user_id=? AND currency=?").get(req.session.userId,currency);
  if (!wallet || wallet.balance < n) return res.status(400).json({error:"Insufficient available balance."});
  const reference = ref();
  const tx = db.transaction(() => {
    db.prepare("UPDATE wallets SET balance=balance-? WHERE user_id=? AND currency=?").run(n,req.session.userId,currency);
    db.prepare("INSERT INTO transactions(user_id,type,currency,amount,description,status,reference) VALUES(?,?,?,?,?,?,?)")
      .run(req.session.userId,"transfer",currency,-n,description||"Internal transfer","completed",reference);
  });
  tx();
  res.json({ok:true,reference});
});

app.post("/api/withdraw", auth, (req,res) => {
  const {currency,amount,description} = req.body;
  const n = Number(amount);
  if (!currencies.includes(currency) || !Number.isFinite(n) || n <= 0)
    return res.status(400).json({error:"Enter a valid currency and amount."});
  const wallet = db.prepare("SELECT balance FROM wallets WHERE user_id=? AND currency=?").get(req.session.userId,currency);
  if (!wallet || wallet.balance < n) return res.status(400).json({error:"Insufficient available balance."});
  const reference = ref();
  const tx = db.transaction(() => {
    db.prepare("UPDATE wallets SET balance=balance-? WHERE user_id=? AND currency=?").run(n,req.session.userId,currency);
    db.prepare("INSERT INTO transactions(user_id,type,currency,amount,description,status,reference) VALUES(?,?,?,?,?,?,?)")
      .run(req.session.userId,"withdrawal",currency,-n,description||"Withdrawal request","pending",reference);
  });
  tx();
  res.json({ok:true,reference});
});

app.post("/api/exchange", auth, (req,res) => {
  const {from,to,amount} = req.body;
  const n = Number(amount);
  if (!currencies.includes(from)||!currencies.includes(to)||from===to||!Number.isFinite(n)||n<=0)
    return res.status(400).json({error:"Choose two different currencies and a valid amount."});
  const source = db.prepare("SELECT balance FROM wallets WHERE user_id=? AND currency=?").get(req.session.userId,from);
  if (!source || source.balance < n) return res.status(400).json({error:"Insufficient available balance."});
  const converted = n * ratesToUSD[from] / ratesToUSD[to];
  const tx = db.transaction(() => {
    db.prepare("UPDATE wallets SET balance=balance-? WHERE user_id=? AND currency=?").run(n,req.session.userId,from);
    db.prepare("UPDATE wallets SET balance=balance+? WHERE user_id=? AND currency=?").run(converted,req.session.userId,to);
    db.prepare("INSERT INTO transactions(user_id,type,currency,amount,description,status,reference) VALUES(?,?,?,?,?,?,?)")
      .run(req.session.userId,"exchange",from,-n,`Exchange ${from} to ${to}`,"completed",ref());
    db.prepare("INSERT INTO transactions(user_id,type,currency,amount,description,status,reference) VALUES(?,?,?,?,?,?,?)")
      .run(req.session.userId,"exchange",to,converted,`Received from ${from} exchange`,"completed",ref());
  });
  tx();
  res.json({ok:true,received:converted});
});

app.get("/api/admin/users", admin, (req,res) => {
  const users = db.prepare(`
    SELECT u.id,u.name,u.email,u.role,u.created_at,
    COALESCE(SUM(CASE WHEN w.currency='USD' THEN w.balance ELSE 0 END),0) usd_balance
    FROM users u LEFT JOIN wallets w ON u.id=w.user_id
    GROUP BY u.id ORDER BY u.id DESC
  `).all();
  res.json(users);
});

app.post("/api/admin/credit", admin, (req,res) => {
  const {userId,currency,amount,description} = req.body;
  const n = Number(amount);
  if (!currencies.includes(currency)||!Number.isFinite(n)||n<=0) return res.status(400).json({error:"Invalid credit."});
  const user = db.prepare("SELECT id FROM users WHERE id=?").get(userId);
  if (!user) return res.status(404).json({error:"Customer not found."});
  const reference = ref();
  const tx = db.transaction(() => {
    db.prepare("UPDATE wallets SET balance=balance+? WHERE user_id=? AND currency=?").run(n,userId,currency);
    db.prepare("INSERT INTO transactions(user_id,type,currency,amount,description,status,reference) VALUES(?,?,?,?,?,?,?)")
      .run(userId,"credit",currency,n,description||"Account credit","completed",reference);
  });
  tx();
  res.json({ok:true,reference});
});

app.get("/api/admin/transactions", admin, (req,res) => {
  res.json(db.prepare(`
    SELECT t.*,u.name,u.email FROM transactions t JOIN users u ON u.id=t.user_id
    ORDER BY t.id DESC LIMIT 100
  `).all());
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`NWB Financial running on port ${PORT}`));
