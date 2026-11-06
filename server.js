const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AD_DIRECT_URL = process.env.AD_DIRECT_URL || "https://example.com";

if (!DATABASE_URL || !SESSION_SECRET || !ADMIN_PASSWORD) {
  console.error("Missing DATABASE_URL, SESSION_SECRET or ADMIN_PASSWORD environment variable.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
});

app.set("trust proxy", 1);
const FRONTEND_ORIGIN = "https://dhrutivirani907-blip.github.io";
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin === FRONTEND_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: "30kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });

function tokenFor(payload) {
  return jwt.sign(payload, SESSION_SECRET, { expiresIn: "30d" });
}
function setSession(res, payload) {
  res.cookie("zoi_session", tokenFor(payload), {
    httpOnly: true, secure: process.env.NODE_ENV === "production",
    sameSite: "none", maxAge: 30 * 24 * 60 * 60 * 1000
  });
}
function requireUser(req, res, next) {
  try {
    const t = req.cookies.zoi_session;
    if (!t) return res.status(401).json({ error: "Please log in." });
    const data = jwt.verify(t, SESSION_SECRET);
    if (data.role !== "user") return res.status(403).json({ error: "User access required." });
    req.user = data;
    next();
  } catch { return res.status(401).json({ error: "Session expired. Please log in again." }); }
}
function requireAdmin(req, res, next) {
  try {
    const t = req.cookies.zoi_session;
    if (!t) return res.status(401).json({ error: "Admin login required." });
    const data = jwt.verify(t, SESSION_SECRET);
    if (data.role !== "admin") return res.status(403).json({ error: "Admin access required." });
    next();
  } catch { return res.status(401).json({ error: "Admin login required." }); }
}
const emailOk = v => typeof v === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254;
const reelOk = v => {
  try {
    const u = new URL(v);
    return ["instagram.com", "www.instagram.com"].includes(u.hostname) && u.pathname.includes("/reel/");
  } catch { return false; }
};

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, credits BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS ad_sessions (
      id UUID PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), claimed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS requests (
      id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      amount BIGINT NOT NULL CHECK (amount IN (1000,5000,10000,20000,50000,100000)),
      reel_url TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','completed','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  console.log("ZON OF INSTA database ready");
}

app.get("/api/config", (req, res) => res.json({ adUrl: AD_DIRECT_URL }));
app.post("/api/signup", authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (typeof name !== "string" || name.trim().length < 2 || name.trim().length > 60 ||
        !emailOk(email) || typeof password !== "string" || password.length < 8 || password.length > 72) {
      return res.status(400).json({ error: "Enter a valid name, email and password (8–72 characters)." });
    }
    const hash = await bcrypt.hash(password, 12);
    const r = await pool.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email,credits",
      [name.trim(), email.toLowerCase().trim(), hash]
    );
    setSession(res, { id: r.rows[0].id, role: "user" });
    res.json({ user: r.rows[0] });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "An account with this email already exists. Please log in." });
    console.error(e); res.status(500).json({ error: "Signup failed." });
  }
});
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!emailOk(email) || typeof password !== "string") return res.status(400).json({ error: "Enter email and password." });
    const r = await pool.query("SELECT id,name,email,password_hash,credits FROM users WHERE email=$1", [email.toLowerCase().trim()]);
    if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash))) return res.status(401).json({ error: "Incorrect email or password." });
    const u = r.rows[0]; setSession(res, { id: u.id, role: "user" });
    delete u.password_hash; res.json({ user: u });
  } catch (e) { console.error(e); res.status(500).json({ error: "Login failed." }); }
});
app.post("/api/logout", (req, res) => { res.clearCookie("zoi_session", { httpOnly: true, secure: true, sameSite: "none" }); res.json({ ok: true }); });
app.get("/api/me", requireUser, async (req, res) => {
  const r = await pool.query("SELECT id,name,email,credits FROM users WHERE id=$1", [req.user.id]);
  if (!r.rowCount) return res.status(401).json({ error: "Account not found." });
  res.json({ user: r.rows[0] });
});

/* The ad timer is validated by the server; clients cannot claim before 8 seconds. */
app.post("/api/ads/start", requireUser, async (req, res) => {
  const { randomUUID } = require("crypto");
  const id = randomUUID();
  await pool.query("INSERT INTO ad_sessions(id,user_id) VALUES($1,$2)", [id, req.user.id]);
  res.json({ adSessionId: id, adUrl: AD_DIRECT_URL });
});
app.post("/api/ads/claim", requireUser, async (req, res) => {
  const id = req.body && req.body.adSessionId;
  if (typeof id !== "string") return res.status(400).json({ error: "Invalid ad session." });
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const r = await c.query(
      "SELECT id FROM ad_sessions WHERE id=$1 AND user_id=$2 AND claimed_at IS NULL AND started_at <= NOW() - INTERVAL '8 seconds' FOR UPDATE",
      [id, req.user.id]
    );
    if (!r.rowCount) { await c.query("ROLLBACK"); return res.status(400).json({ error: "Please complete at least 8 seconds first, or this ad was already claimed." }); }
    await c.query("UPDATE ad_sessions SET claimed_at=NOW() WHERE id=$1", [id]);
    const u = await c.query("UPDATE users SET credits=credits+20 WHERE id=$1 RETURNING credits", [req.user.id]);
    await c.query("COMMIT");
    res.json({ added: 20, credits: u.rows[0].credits });
  } catch (e) { await c.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Could not claim reward." }); }
  finally { c.release(); }
});

app.post("/api/requests", requireUser, async (req, res) => {
  const amount = Number(req.body && req.body.amount);
  const reelUrl = req.body && req.body.reelUrl;
  const allowed = [1000,5000,10000,20000,50000,100000];
  if (!allowed.includes(amount) || !reelOk(reelUrl)) return res.status(400).json({ error: "Choose a valid amount and enter an Instagram Reel URL." });
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const u = await c.query("UPDATE users SET credits=credits-$1 WHERE id=$2 AND credits >= $1 RETURNING credits", [amount, req.user.id]);
    if (!u.rowCount) { await c.query("ROLLBACK"); return res.status(400).json({ error: "Not enough credits." }); }
    const r = await c.query(
      "INSERT INTO requests(user_id,amount,reel_url) VALUES($1,$2,$3) RETURNING id,status,amount,reel_url,created_at",
      [req.user.id, amount, reelUrl]
    );
    await c.query("COMMIT");
    res.json({ request: r.rows[0], credits: u.rows[0].credits });
  } catch (e) { await c.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Could not submit request." }); }
  finally { c.release(); }
});
app.get("/api/requests", requireUser, async (req, res) => {
  const r = await pool.query("SELECT id,amount,reel_url,status,admin_note,created_at,updated_at FROM requests WHERE user_id=$1 ORDER BY created_at DESC", [req.user.id]);
  res.json({ requests: r.rows });
});

app.post("/api/admin/login", authLimiter, (req, res) => {
  if (!req.body || req.body.password !== ADMIN_PASSWORD) return res.status(401).json({ error: "Incorrect admin password." });
  setSession(res, { role: "admin" }); res.json({ ok: true });
});
app.get("/api/admin/summary", requireAdmin, async (req, res) => {
  const [u, r, p] = await Promise.all([
    pool.query("SELECT COUNT(*)::int AS count FROM users"),
    pool.query("SELECT COUNT(*)::int AS count FROM requests"),
    pool.query("SELECT COUNT(*)::int AS count FROM requests WHERE status='pending'")
  ]);
  res.json({ users: u.rows[0].count, requests: r.rows[0].count, pending: p.rows[0].count });
});
app.get("/api/admin/requests", requireAdmin, async (req, res) => {
  const r = await pool.query(`SELECT r.id,r.user_id,u.name,u.email,r.amount,r.reel_url,r.status,r.admin_note,r.created_at
    FROM requests r JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC LIMIT 500`);
  res.json({ requests: r.rows });
});
app.put("/api/admin/requests/:id", requireAdmin, async (req, res) => {
  const id = Number(req.params.id), status = req.body && req.body.status;
  const note = typeof (req.body && req.body.note) === "string" ? req.body.note.slice(0,500) : "";
  if (!Number.isSafeInteger(id) || id < 1 || !["completed","rejected"].includes(status)) return res.status(400).json({ error: "Invalid update." });
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    const r = await c.query("SELECT id,user_id,amount,status FROM requests WHERE id=$1 FOR UPDATE", [id]);
    if (!r.rowCount) { await c.query("ROLLBACK"); return res.status(404).json({ error: "Request not found." }); }
    if (r.rows[0].status !== "pending") { await c.query("ROLLBACK"); return res.status(409).json({ error: "This request has already been processed." }); }
    if (status === "rejected") await c.query("UPDATE users SET credits=credits+$1 WHERE id=$2", [r.rows[0].amount, r.rows[0].user_id]);
    await c.query("UPDATE requests SET status=$1,admin_note=$2,updated_at=NOW() WHERE id=$3", [status,note,id]);
    await c.query("COMMIT"); res.json({ ok: true, refunded: status === "rejected" ? r.rows[0].amount : 0 });
  } catch (e) { await c.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Could not update request." }); }
  finally { c.release(); }
});

app.get("/admin", (req, res) => {
    res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("/{*splat}", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

init().then(() => app.listen(PORT, () => console.log(`ZON OF INSTA running on ${PORT}`)))
  .catch(e => { console.error("Database initialization failed:", e); process.exit(1); });
