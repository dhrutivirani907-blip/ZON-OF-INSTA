'use strict';

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

if (!DATABASE_URL) {
  console.error('DATABASE_URL is missing. Configure it in Render Environment.');
}
if (!ADMIN_PASSWORD) {
  console.warn('ADMIN_PASSWORD is missing. Admin login is disabled.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : undefined
});

app.use(cors());
app.use(express.json({ limit: '30kb' }));
app.use(express.static(path.join(__dirname)));

const adminTokens = new Map();
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const MIN_WITHDRAW = 2500000;
const AD_REWARD = 250000;
const MIN_AD_SECONDS = 8;

const q = (sql, params = []) => pool.query(sql, params);

// -------------------- Database --------------------
async function initDb() {
  await q(`
    CREATE TABLE IF NOT EXISTS bd_users (
      user_id TEXT PRIMARY KEY,
      balance BIGINT NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS bd_ad_sessions (
      session_id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      claimed_at TIMESTAMPTZ,
      claimed BOOLEAN NOT NULL DEFAULT FALSE
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS bd_withdrawals (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      binance_id TEXT NOT NULL,
      amount BIGINT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'complete', 'reject')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

// -------------------- Helpers --------------------
function validUserId(value) {
  return typeof value === 'string' &&
    value.length >= 4 && value.length <= 100 &&
    /^[a-zA-Z0-9_-]+$/.test(value);
}

function adminOnly(req, res, next) {
  const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const createdAt = adminTokens.get(token);

  if (!token || !createdAt || Date.now() - createdAt > TOKEN_TTL_MS) {
    if (token) adminTokens.delete(token);
    return res.status(401).json({ error: 'Admin login required. Please login again.' });
  }

  next();
}

// -------------------- Health check --------------------
app.get('/api/health', async (req, res) => {
  try {
    await q('SELECT 1');
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false });
  }
});

// -------------------- Balance --------------------
app.get('/api/user/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!validUserId(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const result = await q(`
      INSERT INTO bd_users (user_id)
      VALUES ($1)
      ON CONFLICT (user_id) DO UPDATE SET updated_at = NOW()
      RETURNING balance
    `, [userId]);

    res.json({ balance: Number(result.rows[0].balance) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load account' });
  }
});

// -------------------- Start ad timer --------------------
app.post('/api/ad/start', async (req, res) => {
  try {
    const { userId } = req.body;
    if (!validUserId(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    await q('INSERT INTO bd_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);

    const sessionId = crypto.randomUUID();
    await q(
      'INSERT INTO bd_ad_sessions (session_id, user_id) VALUES ($1, $2)',
      [sessionId, userId]
    );

    res.json({ sessionId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not start ad session' });
  }
});

// -------------------- Claim ad reward --------------------
app.post('/api/ad/claim', async (req, res) => {
  const { userId, sessionId } = req.body;

  if (!validUserId(userId) || typeof sessionId !== 'string') {
    return res.status(400).json({ error: 'Invalid ad session' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const sessionResult = await client.query(`
      SELECT * FROM bd_ad_sessions
      WHERE session_id = $1 AND user_id = $2
      FOR UPDATE
    `, [sessionId, userId]);

    if (!sessionResult.rowCount) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Ad session not found' });
    }

    const session = sessionResult.rows[0];
    if (session.claimed) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This ad session has already been claimed' });
    }

    const elapsedSeconds = (Date.now() - new Date(session.started_at).getTime()) / 1000;
    if (elapsedSeconds < MIN_AD_SECONDS) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Please watch for at least 8 seconds' });
    }

    await client.query(`
      UPDATE bd_ad_sessions
      SET claimed = TRUE, claimed_at = NOW()
      WHERE session_id = $1
    `, [sessionId]);

    const balanceResult = await client.query(`
      UPDATE bd_users
      SET balance = balance + $2, updated_at = NOW()
      WHERE user_id = $1
      RETURNING balance
    `, [userId, AD_REWARD]);

    await client.query('COMMIT');
    res.json({ reward: AD_REWARD, balance: Number(balanceResult.rows[0].balance) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Could not claim reward' });
  } finally {
    client.release();
  }
});

// -------------------- Submit withdrawal --------------------
app.post('/api/withdraw', async (req, res) => {
  const { userId, binanceId, amount } = req.body;
  const id = String(binanceId || '').trim();
  const n = Number(amount);

  if (!validUserId(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  if (!id || id.length > 100) {
    return res.status(400).json({ error: 'Please enter a valid Binance ID' });
  }
  if (!Number.isSafeInteger(n) || n < MIN_WITHDRAW) {
    return res.status(400).json({ error: 'Minimum withdrawal is 2,500,000 BabyDoge' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      'SELECT balance FROM bd_users WHERE user_id = $1 FOR UPDATE',
      [userId]
    );

    if (!userResult.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Account not found' });
    }
    if (Number(userResult.rows[0].balance) < n) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Insufficient BabyDoge balance' });
    }

    const balanceResult = await client.query(`
      UPDATE bd_users
      SET balance = balance - $2, updated_at = NOW()
      WHERE user_id = $1
      RETURNING balance
    `, [userId, n]);

    const withdrawalResult = await client.query(`
      INSERT INTO bd_withdrawals (user_id, binance_id, amount)
      VALUES ($1, $2, $3)
      RETURNING id, status, created_at
    `, [userId, id, n]);

    await client.query('COMMIT');
    res.json({
      balance: Number(balanceResult.rows[0].balance),
      request: withdrawalResult.rows[0]
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Withdrawal request failed' });
  } finally {
    client.release();
  }
});

// -------------------- User withdrawal history --------------------
app.get('/api/withdrawals/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;
    if (!validUserId(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const result = await q(`
      SELECT id, binance_id, amount, status, created_at
      FROM bd_withdrawals
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [userId]);

    res.json({ requests: result.rows.map(row => ({ ...row, amount: Number(row.amount) })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load withdrawals' });
  }
});

// -------------------- Admin login --------------------
app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({ error: 'Admin password is not configured on server' });
  }

  const password = req.body.password;
  const correct = typeof password === 'string' &&
    password.length === ADMIN_PASSWORD.length &&
    crypto.timingSafeEqual(Buffer.from(password), Buffer.from(ADMIN_PASSWORD));

  if (!correct) {
    return res.status(401).json({ error: 'Incorrect password' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.set(token, Date.now());
  res.json({ token });
});

// -------------------- Admin withdrawal list --------------------
app.get('/api/admin/withdrawals', adminOnly, async (req, res) => {
  try {
    const result = await q(`
      SELECT id, user_id, binance_id, amount, status, created_at
      FROM bd_withdrawals
      ORDER BY created_at DESC
    `);

    res.json({ requests: result.rows.map(row => ({ ...row, amount: Number(row.amount) })) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load admin requests' });
  }
});

// -------------------- Admin status change --------------------
app.patch('/api/admin/withdrawals/:id', adminOnly, async (req, res) => {
  const status = req.body.status;
  if (!['pending', 'complete', 'reject'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const requestResult = await client.query(
      'SELECT * FROM bd_withdrawals WHERE id = $1 FOR UPDATE',
      [req.params.id]
    );

    if (!requestResult.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Request not found' });
    }

    const old = requestResult.rows[0];
    if (old.status !== 'pending' && old.status !== status) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Finalized requests cannot be changed again' });
    }

    // Refund the user's reserved coins exactly once when rejecting a pending request.
    if (old.status === 'pending' && status === 'reject') {
      await client.query(`
        UPDATE bd_users
        SET balance = balance + $2, updated_at = NOW()
        WHERE user_id = $1
      `, [old.user_id, old.amount]);
    }

    const updateResult = await client.query(`
      UPDATE bd_withdrawals
      SET status = $1, updated_at = NOW()
      WHERE id = $2
      RETURNING id, status
    `, [status, req.params.id]);

    await client.query('COMMIT');
    res.json({ request: updateResult.rows[0] });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Status update failed' });
  } finally {
    client.release();
  }
});

// -------------------- App page --------------------
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

initDb()
  .then(() => {
    app.listen(PORT, () => console.log(`BabyDoge Rewards server running on port ${PORT}`));
  })
  .catch(err => {
    console.error('Database initialization failed:', err);
    process.exit(1);
  });
