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
      binance_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q('ALTER TABLE bd_users ADD COLUMN IF NOT EXISTS binance_id TEXT');

  await q(`
    CREATE TABLE IF NOT EXISTS bd_user_bans (
      user_id TEXT PRIMARY KEY REFERENCES bd_users(user_id),
      reason TEXT NOT NULL,
      banned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

  await q(`
    CREATE TABLE IF NOT EXISTS bd_tasks (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL DEFAULT 'TIN APP',
      link TEXT NOT NULL,
      amount BIGINT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS bd_task_sessions (
      session_id TEXT PRIMARY KEY,
      task_id BIGINT NOT NULL REFERENCES bd_tasks(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      claimed_at TIMESTAMPTZ
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS bd_task_claims (
      id BIGSERIAL PRIMARY KEY,
      task_id BIGINT NOT NULL REFERENCES bd_tasks(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL,
      amount BIGINT NOT NULL,
      claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(task_id, user_id)
    )
  `);

  await q(`
    CREATE TABLE IF NOT EXISTS bd_referrals (
      id BIGSERIAL PRIMARY KEY,
      referrer_id TEXT NOT NULL REFERENCES bd_users(user_id),
      referred_id TEXT NOT NULL UNIQUE REFERENCES bd_users(user_id),
      reward BIGINT NOT NULL DEFAULT 10000000,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CHECK (referrer_id <> referred_id)
    )
  `);

  const defaultTask = await q(
    'SELECT id FROM bd_tasks WHERE active = TRUE ORDER BY id ASC LIMIT 1'
  );

  if (!defaultTask.rowCount) {
    await q(
      `INSERT INTO bd_tasks (name, link, amount)
       VALUES ('TIN APP', 'https://t.me/', 3000000)`
    );
  }
}

// -------------------- Helpers --------------------
function validUserId(value) {
  return typeof value === 'string' &&
    value.length >= 4 &&
    value.length <= 100 &&
    /^[a-zA-Z0-9_-]+$/.test(value);
}

function adminOnly(req, res, next) {
  const token = String(req.headers.authorization || '')
    .replace(/^Bearer\s+/i, '');

  const createdAt = adminTokens.get(token);

  if (!token || !createdAt || Date.now() - createdAt > TOKEN_TTL_MS) {
    if (token) adminTokens.delete(token);

    return res.status(401).json({
      error: 'Admin login required. Please login again.'
    });
  }

  next();
}

// Block banned accounts from user actions, while allowing status check, Binance save, and admin routes.
app.use('/api', async (req, res, next) => {
  try {
    if (req.path === '/admin/login' || req.path.startsWith('/admin/') || req.path === '/binance/save' || (req.method === 'GET' && /^\/user\/[^/]+$/.test(req.path))) return next();
    const pathUserMatch = req.path.match(/^\/(?:withdrawals|referrals)\/([^/]+)$/);
    const userId = req.body?.userId || pathUserMatch?.[1] || req.params.userId;
    if (!userId || !validUserId(userId)) return next();
    const ban = await q('SELECT reason FROM bd_user_bans WHERE user_id = $1', [userId]);
    if (ban.rowCount) return res.status(403).json({ error: 'Your account is banned: ' + ban.rows[0].reason, banned: true, reason: ban.rows[0].reason });
    next();
  } catch (err) { console.error(err); res.status(500).json({ error: 'Account status check failed' }); }
});

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
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    const result = await q(`
      INSERT INTO bd_users (user_id)
      VALUES ($1)
      ON CONFLICT (user_id)
      DO UPDATE SET updated_at = NOW()
      RETURNING balance
    `, [userId]);

    const userData = await q('SELECT binance_id FROM bd_users WHERE user_id = $1', [userId]);
    const banData = await q('SELECT reason, banned_at FROM bd_user_bans WHERE user_id = $1', [userId]);
    res.json({
      balance: Number(result.rows[0].balance),
      binanceId: userData.rows[0]?.binance_id || null,
      banned: !!banData.rowCount,
      banReason: banData.rows[0]?.reason || null
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not load account'
    });
  }
});

// Save user's Binance ID (first-time setup)
app.post('/api/binance/save', async (req, res) => {
  try {
    const { userId, binanceId } = req.body;
    if (!validUserId(userId) || typeof binanceId !== 'string' || !binanceId.trim() || binanceId.trim().length > 100) return res.status(400).json({ error: 'Please enter a valid Binance ID' });
    await q('INSERT INTO bd_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
    const current = await q('SELECT binance_id FROM bd_users WHERE user_id = $1', [userId]);
    if (current.rows[0].binance_id) return res.status(409).json({ error: 'Binance ID is already saved and cannot be changed here.' });
    await q('UPDATE bd_users SET binance_id = $2, updated_at = NOW() WHERE user_id = $1', [userId, binanceId.trim()]);
    res.json({ success: true, binanceId: binanceId.trim() });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not save Binance ID' }); }
});

// -------------------- Start ad timer --------------------
app.post('/api/ad/start', async (req, res) => {
  try {
    const { userId } = req.body;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    await q(
      'INSERT INTO bd_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING',
      [userId]
    );

    const sessionId = crypto.randomUUID();

    await q(
      `INSERT INTO bd_ad_sessions
       (session_id, user_id)
       VALUES ($1, $2)`,
      [sessionId, userId]
    );

    res.json({
      sessionId
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not start ad session'
    });
  }
});

// -------------------- Claim ad reward --------------------
app.post('/api/ad/claim', async (req, res) => {
  const {
    userId,
    sessionId,
    hiddenSeconds
  } = req.body;

  if (!validUserId(userId) || typeof sessionId !== 'string') {
    return res.status(400).json({
      error: 'Invalid ad session'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const sessionResult = await client.query(`
      SELECT *
      FROM bd_ad_sessions
      WHERE session_id = $1
      AND user_id = $2
      FOR UPDATE
    `, [sessionId, userId]);

    if (!sessionResult.rowCount) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Ad session not found'
      });
    }

    const session = sessionResult.rows[0];

    if (session.claimed) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'This ad session has already been claimed'
      });
    }

    const elapsedSeconds =
      (Date.now() - new Date(session.started_at).getTime()) / 1000;

    const awaySeconds = Number(hiddenSeconds);

    if (
      !Number.isFinite(awaySeconds) ||
      awaySeconds < MIN_AD_SECONDS ||
      elapsedSeconds < MIN_AD_SECONDS
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Please watch for at least 8 seconds'
      });
    }

    await client.query(`
      UPDATE bd_ad_sessions
      SET claimed = TRUE,
          claimed_at = NOW()
      WHERE session_id = $1
    `, [sessionId]);

    const balanceResult = await client.query(`
      UPDATE bd_users
      SET balance = balance + $2,
          updated_at = NOW()
      WHERE user_id = $1
      RETURNING balance
    `, [userId, AD_REWARD]);

    await client.query('COMMIT');

    res.json({
      reward: AD_REWARD,
      balance: Number(balanceResult.rows[0].balance)
    });

  } catch (err) {
    await client.query('ROLLBACK');

    console.error(err);

    res.status(500).json({
      error: 'Could not claim reward'
    });

  } finally {
    client.release();
  }
});

// -------------------- Submit withdrawal --------------------
app.post('/api/withdraw', async (req, res) => {
  const {
    userId,
    binanceId,
    amount
  } = req.body;

  const id = String(binanceId || '').trim();
  const n = Number(amount);

  if (!validUserId(userId)) {
    return res.status(400).json({
      error: 'Invalid user ID'
    });
  }

  if (!id || id.length > 100) {
    return res.status(400).json({
      error: 'Please enter a valid Binance ID'
    });
  }

  if (!Number.isSafeInteger(n) || n < MIN_WITHDRAW) {
    return res.status(400).json({
      error: 'Minimum withdrawal is 2,500,000 BabyDoge'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const userResult = await client.query(
      `SELECT balance
       FROM bd_users
       WHERE user_id = $1
       FOR UPDATE`,
      [userId]
    );

    if (!userResult.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Account not found'
      });
    }

    if (Number(userResult.rows[0].balance) < n) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Insufficient BabyDoge balance'
      });
    }

    const balanceResult = await client.query(`
      UPDATE bd_users
      SET balance = balance - $2,
          updated_at = NOW()
      WHERE user_id = $1
      RETURNING balance
    `, [userId, n]);

    const withdrawalResult = await client.query(`
      INSERT INTO bd_withdrawals
      (user_id, binance_id, amount)
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

    res.status(500).json({
      error: 'Withdrawal request failed'
    });

  } finally {
    client.release();
  }
});

// -------------------- User withdrawal history --------------------
app.get('/api/withdrawals/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    const result = await q(`
      SELECT id,
             binance_id,
             amount,
             status,
             created_at
      FROM bd_withdrawals
      WHERE user_id = $1
      ORDER BY created_at DESC
    `, [userId]);

    res.json({
      requests: result.rows.map(row => ({
        ...row,
        amount: Number(row.amount)
      }))
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not load withdrawals'
    });
  }
});

// -------------------- Referral system --------------------
const REFERRAL_REWARD = 10000000;

app.get('/api/referrals/:userId', async (req, res) => {
  const userId = req.params.userId;
  if (!validUserId(userId)) return res.status(400).json({ error: 'Invalid user ID' });
  try {
    const result = await q('SELECT COUNT(*)::int AS count FROM bd_referrals WHERE referrer_id = $1', [userId]);
    res.json({ count: result.rows[0].count });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not load referral stats' });
  }
});

app.post('/api/referrals/claim', async (req, res) => {
  const { userId, referrerId } = req.body || {};
  if (!validUserId(userId) || !validUserId(referrerId)) {
    return res.status(400).json({ error: 'Invalid referral information' });
  }
  if (userId === referrerId) return res.status(400).json({ error: 'Self-referral is not allowed' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('INSERT INTO bd_users(user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
    await client.query('INSERT INTO bd_users(user_id) VALUES ($1) ON CONFLICT DO NOTHING', [referrerId]);
    const inserted = await client.query(`
      INSERT INTO bd_referrals(referrer_id, referred_id, reward)
      VALUES ($1, $2, $3)
      ON CONFLICT (referred_id) DO NOTHING
      RETURNING id
    `, [referrerId, userId, REFERRAL_REWARD]);
    if (!inserted.rowCount) {
      await client.query('COMMIT');
      return res.json({ reward: 0, alreadyProcessed: true });
    }
    const refBalance = await client.query(`
      UPDATE bd_users SET balance = balance + $2, updated_at = NOW()
      WHERE user_id = $1 RETURNING balance
    `, [referrerId, REFERRAL_REWARD]);
    await client.query('COMMIT');
    res.json({ reward: REFERRAL_REWARD, balance: Number(refBalance.rows[0].balance) });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Referral reward could not be processed' });
  } finally {
    client.release();
  }
});

// -------------------- Tasks --------------------
app.get('/api/tasks', async (req, res) => {
  try {
    const userId = String(req.query.userId || '');

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    const result = await q(`
      SELECT
        t.id,
        t.name,
        t.link,
        t.amount,

        EXISTS (
          SELECT 1
          FROM bd_task_claims c
          WHERE c.task_id = t.id
          AND c.user_id = $1
        ) AS claimed

      FROM bd_tasks t

      WHERE t.active = TRUE

      ORDER BY t.id ASC
    `, [userId]);

    res.json({
      tasks: result.rows.map(r => ({
        ...r,
        amount: Number(r.amount)
      }))
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not load tasks'
    });
  }
});

// -------------------- Start task --------------------
app.post('/api/tasks/:id/start', async (req, res) => {
  try {
    const userId = req.body.userId;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    const task = await q(
      `SELECT id,
              name,
              link,
              amount
       FROM bd_tasks
       WHERE id = $1
       AND active = TRUE`,
      [req.params.id]
    );

    if (!task.rowCount) {
      return res.status(404).json({
        error: 'Task not found'
      });
    }

    const already = await q(
      `SELECT 1
       FROM bd_task_claims
       WHERE task_id = $1
       AND user_id = $2`,
      [req.params.id, userId]
    );

    if (already.rowCount) {
      return res.status(400).json({
        error: 'This task is already claimed'
      });
    }

    const sessionId = crypto.randomUUID();

    await q(
      `INSERT INTO bd_task_sessions
       (session_id, task_id, user_id)
       VALUES ($1, $2, $3)`,
      [sessionId, req.params.id, userId]
    );

    res.json({
      sessionId,
      link: task.rows[0].link,
      amount: Number(task.rows[0].amount)
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not start task'
    });
  }
});

// -------------------- Claim task reward --------------------
app.post('/api/tasks/:id/claim', async (req, res) => {
  const {
    userId,
    sessionId
  } = req.body;

  if (!validUserId(userId) || typeof sessionId !== 'string') {
    return res.status(400).json({
      error: 'Invalid task session'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const session = await client.query(`
      SELECT
        s.*,
        t.amount,
        t.active

      FROM bd_task_sessions s

      JOIN bd_tasks t
      ON t.id = s.task_id

      WHERE s.session_id = $1
      AND s.task_id = $2
      AND s.user_id = $3

      FOR UPDATE
    `, [
      sessionId,
      req.params.id,
      userId
    ]);

    if (
      !session.rowCount ||
      !session.rows[0].active
    ) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'Task session is invalid or task is no longer active'
      });
    }

    const s = session.rows[0];

    if (s.claimed_at) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'This task session has already been claimed'
      });
    }

    const existing = await client.query(
      `SELECT 1
       FROM bd_task_claims
       WHERE task_id = $1
       AND user_id = $2
       FOR UPDATE`,
      [req.params.id, userId]
    );

    if (existing.rowCount) {
      await client.query('ROLLBACK');

      return res.status(400).json({
        error: 'This task is already claimed'
      });
    }

    const reward = Number(s.amount);

    const balance = await client.query(`
      UPDATE bd_users

      SET balance = balance + $2,
          updated_at = NOW()

      WHERE user_id = $1

      RETURNING balance
    `, [userId, reward]);

    await client.query(`
      INSERT INTO bd_task_claims
      (task_id, user_id, amount)

      VALUES ($1, $2, $3)
    `, [
      req.params.id,
      userId,
      reward
    ]);

    await client.query(`
      UPDATE bd_task_sessions

      SET claimed_at = NOW()

      WHERE session_id = $1
    `, [sessionId]);

    await client.query('COMMIT');

    res.json({
      reward,
      balance: Number(balance.rows[0].balance)
    });

  } catch (err) {
    await client.query('ROLLBACK');

    console.error(err);

    res.status(500).json({
      error: 'Could not claim task reward'
    });

  } finally {
    client.release();
  }
});

// -------------------- Admin Task Management --------------------
app.get('/api/admin/tasks', adminOnly, async (req, res) => {
  try {
    const result = await q(`
      SELECT
        id,
        name,
        link,
        amount,
        active,
        created_at

      FROM bd_tasks

      ORDER BY id DESC
    `);

    res.json({
      tasks: result.rows.map(r => ({
        ...r,
        amount: Number(r.amount)
      }))
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Failed to load tasks'
    });
  }
});

// -------------------- Add Task --------------------
app.post('/api/admin/tasks', adminOnly, async (req, res) => {
  try {
    const link = String(req.body.link || '').trim();
    const amount = Number(req.body.amount);

    const name = String(req.body.name || '').trim();

    if (!name || name.length > 100) {
      return res.status(400).json({
        error: 'Please enter a task name (maximum 100 characters)'
      });
    }

    if (
      !/^https?:\/\//i.test(link) ||
      link.length > 500
    ) {
      return res.status(400).json({
        error: 'Please enter a valid task link'
      });
    }

    if (
      !Number.isSafeInteger(amount) ||
      amount <= 0
    ) {
      return res.status(400).json({
        error: 'Please enter a valid reward amount'
      });
    }

    const result = await q(`
      INSERT INTO bd_tasks
      (name, link, amount)

      VALUES ($1, $2, $3)

      RETURNING
        id,
        name,
        link,
        amount,
        active,
        created_at
    `, [
      name,
      link,
      amount
    ]);

    const row = result.rows[0];

    res.json({
      task: {
        ...row,
        amount: Number(row.amount)
      }
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not add task'
    });
  }
});

// -------------------- Delete Task --------------------
app.delete('/api/admin/tasks/:id', adminOnly, async (req, res) => {
  try {
    const result = await q(
      `DELETE FROM bd_tasks
       WHERE id = $1
       RETURNING id`,
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'Task not found'
      });
    }

    res.json({
      ok: true
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Could not delete task'
    });
  }
});

// -------------------- Admin login --------------------
app.post('/api/admin/login', (req, res) => {
  if (!ADMIN_PASSWORD) {
    return res.status(503).json({
      error: 'Admin password is not configured on server'
    });
  }

  const password = req.body.password;

  const correct =
    typeof password === 'string' &&
    password.length === ADMIN_PASSWORD.length &&
    crypto.timingSafeEqual(
      Buffer.from(password),
      Buffer.from(ADMIN_PASSWORD)
    );

  if (!correct) {
    return res.status(401).json({
      error: 'Incorrect password'
    });
  }

  const token = crypto.randomBytes(32).toString('hex');

  adminTokens.set(token, Date.now());

  res.json({
    token
  });
});

// Admin Panel 3: ban account by Binance ID
app.post('/api/admin/ban-binance', adminOnly, async (req, res) => {
  try {
    const binanceId = String(req.body.binanceId || '').trim();
    const reason = String(req.body.reason || '').trim();
    if (!binanceId || binanceId.length > 100) return res.status(400).json({ error: 'Enter a valid Binance ID' });
    if (!reason || reason.length > 1000) return res.status(400).json({ error: 'Enter a ban reason (up to 1000 characters)' });
    const found = await q('SELECT user_id FROM bd_users WHERE LOWER(binance_id) = LOWER($1)', [binanceId]);
    if (!found.rowCount) return res.status(404).json({ error: 'No account found for this Binance ID' });
    const targetUserId = found.rows[0].user_id;
    await q(`INSERT INTO bd_user_bans(user_id, reason) VALUES ($1, $2)
      ON CONFLICT(user_id) DO UPDATE SET reason = EXCLUDED.reason, banned_at = NOW()`, [targetUserId, reason]);
    res.json({ success: true, userId: targetUserId, binanceId, reason });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not ban account' }); }
});

// Admin Panel 3: unban account by Binance ID
app.post('/api/admin/unban-binance', adminOnly, async (req, res) => {
  try {
    const binanceId = String(req.body.binanceId || '').trim();
    if (!binanceId || binanceId.length > 100) return res.status(400).json({ error: 'Enter a valid Binance ID' });
    const found = await q('SELECT user_id FROM bd_users WHERE LOWER(binance_id) = LOWER($1)', [binanceId]);
    if (!found.rowCount) return res.status(404).json({ error: 'No account found for this Binance ID' });
    const targetUserId = found.rows[0].user_id;
    const result = await q('DELETE FROM bd_user_bans WHERE user_id = $1 RETURNING user_id', [targetUserId]);
    if (!result.rowCount) return res.status(404).json({ error: 'This account is not banned' });
    res.json({ success: true, userId: targetUserId, binanceId });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not unban account' }); }
});

// Admin Panel 4: reset balance, withdrawals, and referral records by Binance ID
app.post('/api/admin/reset-binance', adminOnly, async (req, res) => {
  const binanceId = String(req.body.binanceId || '').trim();
  if (!binanceId || binanceId.length > 100) return res.status(400).json({ error: 'Enter a valid Binance ID' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query('SELECT user_id, binance_id FROM bd_users WHERE LOWER(binance_id) = LOWER($1) FOR UPDATE', [binanceId]);
    if (!found.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'No account found for this Binance ID' }); }
    const targetUserId = found.rows[0].user_id;
    await client.query('UPDATE bd_users SET balance = 0, updated_at = NOW() WHERE user_id = $1', [targetUserId]);
    const withdrawals = await client.query('DELETE FROM bd_withdrawals WHERE user_id = $1 RETURNING id', [targetUserId]);
    const referrals = await client.query('DELETE FROM bd_referrals WHERE referrer_id = $1 OR referred_id = $1 RETURNING id', [targetUserId]);
    await client.query('COMMIT');
    res.json({ success: true, userId: targetUserId, binanceId: found.rows[0].binance_id, deletedWithdrawals: withdrawals.rowCount, deletedReferrals: referrals.rowCount });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Could not reset account data' });
  } finally { client.release(); }
});

// -------------------- Admin withdrawal list --------------------
app.get('/api/admin/withdrawals', adminOnly, async (req, res) => {
  try {
    const result = await q(`
      SELECT
        id,
        user_id,
        binance_id,
        amount,
        status,
        created_at

      FROM bd_withdrawals

      ORDER BY created_at DESC
    `);

    res.json({
      requests: result.rows.map(row => ({
        ...row,
        amount: Number(row.amount)
      }))
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: 'Failed to load admin requests'
    });
  }
});

// -------------------- Admin status change --------------------
app.patch('/api/admin/withdrawals/:id', adminOnly, async (req, res) => {
  const status = req.body.status;

  if (
    ![
      'pending',
      'complete',
      'reject'
    ].includes(status)
  ) {
    return res.status(400).json({
      error: 'Invalid status'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const requestResult = await client.query(
      `SELECT *
       FROM bd_withdrawals
       WHERE id = $1
       FOR UPDATE`,
      [req.params.id]
    );

    if (!requestResult.rowCount) {
      await client.query('ROLLBACK');

      return res.status(404).json({
        error: 'Request not found'
      });
    }

    const old = requestResult.rows[0];

    if (
      old.status !== 'pending' &&
      old.status !== status
    ) {
      await client.query('ROLLBACK');

      return res.status(409).json({
        error: 'Finalized requests cannot be changed again'
      });
    }

    if (
      old.status === 'pending' &&
      status === 'reject'
    ) {
      await client.query(`
        UPDATE bd_users

        SET balance = balance + $2,
            updated_at = NOW()

        WHERE user_id = $1
      `, [
        old.user_id,
        old.amount
      ]);
    }

    const updateResult = await client.query(`
      UPDATE bd_withdrawals

      SET status = $1,
          updated_at = NOW()

      WHERE id = $2

      RETURNING id, status
    `, [
      status,
      req.params.id
    ]);

    await client.query('COMMIT');

    res.json({
      request: updateResult.rows[0]
    });

  } catch (err) {
    await client.query('ROLLBACK');

    console.error(err);

    res.status(500).json({
      error: 'Status update failed'
    });

  } finally {
    client.release();
  }
});

// -------------------- App page --------------------
app.get('*', (req, res) => {
  res.sendFile(
    path.join(__dirname, 'index.html')
  );
});

// -------------------- Start Server --------------------
initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `BabyDoge Rewards server running on port ${PORT}`
      );
    });
  })
  .catch(err => {
    console.error(
      'Database initialization failed:',
      err
    );

    process.exit(1);
  });
