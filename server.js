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
const AD_REWARD = 0;
const MIN_AD_SECONDS = 8;
const ADS_PER_MINER = 10;
const MINER_RATE = 1500;
const MINER_DURATION_SECONDS = 30 * 60;

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
  await q('ALTER TABLE bd_users ADD COLUMN IF NOT EXISTS valid_ads_count BIGINT NOT NULL DEFAULT 0');
  await q('ALTER TABLE bd_users ADD COLUMN IF NOT EXISTS total_miners_activated BIGINT NOT NULL DEFAULT 0');
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
    CREATE TABLE IF NOT EXISTS bd_miners (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      rate BIGINT NOT NULL DEFAULT 1500,
      active BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);
  await q('ALTER TABLE bd_miners ADD COLUMN IF NOT EXISTS credited_seconds BIGINT NOT NULL DEFAULT 0');
  await q('CREATE INDEX IF NOT EXISTS bd_miners_user_active_idx ON bd_miners(user_id, active, expires_at)');
  await q(`UPDATE bd_users u SET total_miners_activated = GREATEST(u.total_miners_activated, COALESCE((SELECT COUNT(*) FROM bd_miners m WHERE m.user_id = u.user_id), 0))`);

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

// -------------------- Miner helpers --------------------
async function settleMiners(client, userId) {
  const now = Date.now();
  const rows = await client.query(`
    SELECT id, started_at, expires_at, rate, credited_seconds
    FROM bd_miners
    WHERE user_id = $1 AND active = TRUE
    FOR UPDATE
  `, [userId]);

  let earned = 0;
  for (const miner of rows.rows) {
    const startMs = new Date(miner.started_at).getTime();
    const expiryMs = new Date(miner.expires_at).getTime();
    const endMs = Math.min(now, expiryMs);
    const seconds = Math.max(0, Math.floor((endMs - startMs) / 1000));
    const creditedSeconds = Number(miner.credited_seconds || 0);
    // credited_seconds is added below if the column exists; fallback is handled by migration.
    const deltaSeconds = Math.max(0, seconds - creditedSeconds);
    if (deltaSeconds > 0) {
      earned += deltaSeconds * Number(miner.rate || MINER_RATE);
      await client.query(
        'UPDATE bd_miners SET started_at = started_at, active = CASE WHEN $2 >= expires_at THEN FALSE ELSE active END, rate = rate, expires_at = expires_at, credited_seconds = $3 WHERE id = $1',
        [miner.id, new Date(now), seconds]
      );
    } else if (now >= expiryMs) {
      await client.query('UPDATE bd_miners SET active = FALSE WHERE id = $1', [miner.id]);
    }
  }

  if (earned > 0) {
    await client.query(
      'UPDATE bd_users SET balance = balance + $2, updated_at = NOW() WHERE user_id = $1',
      [userId, earned]
    );
  }

  await client.query('UPDATE bd_miners SET active = FALSE WHERE user_id = $1 AND expires_at <= NOW()', [userId]);
  return earned;
}

async function activateCompletedMiners(client, userId) {
  const result = await client.query(
    'SELECT valid_ads_count FROM bd_users WHERE user_id = $1 FOR UPDATE',
    [userId]
  );
  if (!result.rowCount) return 0;

  let count = Number(result.rows[0].valid_ads_count || 0);
  if (count < ADS_PER_MINER) return 0;

  const minersToAdd = Math.floor(count / ADS_PER_MINER);
  const remainder = count % ADS_PER_MINER;

  for (let i = 0; i < minersToAdd; i++) {
    await client.query(`
      INSERT INTO bd_miners (user_id, started_at, expires_at, rate, active, credited_seconds)
      VALUES ($1, NOW(), NOW() + ($2 * INTERVAL '1 second'), $3, TRUE, 0)
    `, [userId, MINER_DURATION_SECONDS, MINER_RATE]);
  }

  await client.query(`
    UPDATE bd_users
    SET valid_ads_count = $2,
        total_miners_activated = total_miners_activated + $3,
        updated_at = NOW()
    WHERE user_id = $1
  `, [userId, remainder, minersToAdd]);

  return minersToAdd;
}

async function getMinerState(client, userId) {
  await activateCompletedMiners(client, userId);
  await settleMiners(client, userId);
  const active = await client.query(`
    SELECT id, expires_at, rate
    FROM bd_miners
    WHERE user_id = $1 AND active = TRUE AND expires_at > NOW()
    ORDER BY expires_at ASC
  `, [userId]);
  const activeMiners = active.rowCount;
  return {
    activeMiners,
    hashRate: activeMiners * MINER_RATE,
    minerRate: MINER_RATE,
    durationSeconds: MINER_DURATION_SECONDS,
    adsPerMiner: ADS_PER_MINER,
    miners: active.rows.map(r => ({
      id: r.id,
      expiresAt: new Date(r.expires_at).toISOString(),
      rate: Number(r.rate || MINER_RATE)
    }))
  };
}

// -------------------- Balance --------------------
app.get('/api/user/:userId', async (req, res) => {
  try {
    const userId = req.params.userId;

    if (!validUserId(userId)) {
      return res.status(400).json({
        error: 'Invalid user ID'
      });
    }

    await q('INSERT INTO bd_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const minerState = await getMinerState(client, userId);
      const result = await client.query('SELECT balance FROM bd_users WHERE user_id = $1 FOR UPDATE', [userId]);
      const userData = await client.query('SELECT binance_id, valid_ads_count FROM bd_users WHERE user_id = $1', [userId]);
      const banData = await client.query('SELECT reason, banned_at FROM bd_user_bans WHERE user_id = $1', [userId]);
      await client.query('COMMIT');
      res.json({
        balance: Number(result.rows[0].balance),
        binanceId: userData.rows[0]?.binance_id || null,
        validAdsCount: Number(userData.rows[0]?.valid_ads_count || 0),
        banned: !!banData.rowCount,
        banReason: banData.rows[0]?.reason || null,
        miner: minerState
      });
    } finally {
      client.release();
    }
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
// Sync legacy client-side ad count without ever lowering the server count.
app.post('/api/ads/count/sync', async (req, res) => {
  try {
    const { userId, localCount } = req.body;
    const count = Number(localCount);
    if (!validUserId(userId) || !Number.isSafeInteger(count) || count < 0) {
      return res.status(400).json({ error: 'Invalid ad count sync' });
    }
    await q('INSERT INTO bd_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
    const result = await q(`
      UPDATE bd_users
      SET valid_ads_count = GREATEST(valid_ads_count, $2), updated_at = NOW()
      WHERE user_id = $1
      RETURNING valid_ads_count
    `, [userId, count]);
    res.json({ validAdsCount: Number(result.rows[0].valid_ads_count) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Could not sync ad count' });
  }
});

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

    // Count this valid ad. When the count reaches 10, activate one miner
    // and keep any extra ads as progress toward the next miner. This also
    // repairs old accounts whose count accidentally went above 10.
    const countResult = await client.query(`
      UPDATE bd_users
      SET balance = balance + $2,
          valid_ads_count = valid_ads_count + 1,
          updated_at = NOW()
      WHERE user_id = $1
      RETURNING balance, valid_ads_count
    `, [userId, AD_REWARD]);

    const balanceValue = Number(countResult.rows[0].balance);
    const minersActivated = await activateCompletedMiners(client, userId);
    const countAfterActivation = await client.query(
      'SELECT valid_ads_count FROM bd_users WHERE user_id = $1',
      [userId]
    );
    const validAdsCount = Number(countAfterActivation.rows[0].valid_ads_count || 0);
    const minerState = await getMinerState(client, userId);

    await client.query('COMMIT');

    res.json({
      reward: AD_REWARD,
      balance: balanceValue,
      validAdsCount,
      minerActivated: minersActivated > 0,
      minersActivated,
      miner: minerState
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

// -------------------- Miner API --------------------
app.get('/api/miner/state/:userId', async (req, res) => {
  const userId = req.params.userId;
  if (!validUserId(userId)) return res.status(400).json({ error: 'Invalid user ID' });
  await q('INSERT INTO bd_users (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const miner = await getMinerState(client, userId);
    const balance = await client.query('SELECT balance FROM bd_users WHERE user_id = $1', [userId]);
    const ads = await client.query('SELECT valid_ads_count FROM bd_users WHERE user_id = $1', [userId]);
    await client.query('COMMIT');
    res.json({
      balance: Number(balance.rows[0].balance),
      validAdsCount: Number(ads.rows[0].valid_ads_count || 0),
      miner
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Could not load miner state' });
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

// Admin Panel 4: all accounts with account totals (admin-only)
app.get('/api/admin/users', adminOnly, async (req, res) => {
  try {
    const result = await q(`
      SELECT u.user_id, u.binance_id, u.balance, u.valid_ads_count,
        u.total_miners_activated, u.created_at,
        COALESCE(m.miner_count, 0)::BIGINT AS miner_count,
        COALESCE(r.referral_count, 0)::BIGINT AS referral_count,
        COALESCE(w.completed_total, 0)::BIGINT AS completed_total,
        COALESCE(w.request_count, 0)::BIGINT AS request_count,
        COALESCE(w.requested_total, 0)::BIGINT AS requested_total
      FROM bd_users u
      LEFT JOIN (
        SELECT user_id, COUNT(*) AS miner_count
        FROM bd_miners
        WHERE active = TRUE AND expires_at > NOW()
        GROUP BY user_id
      ) m ON m.user_id = u.user_id
      LEFT JOIN (SELECT referrer_id, COUNT(*) AS referral_count FROM bd_referrals GROUP BY referrer_id) r ON r.referrer_id = u.user_id
      LEFT JOIN (SELECT user_id, SUM(amount) FILTER (WHERE status = 'complete') AS completed_total,
        COUNT(*) AS request_count, SUM(amount) AS requested_total FROM bd_withdrawals GROUP BY user_id) w ON w.user_id = u.user_id
      ORDER BY u.created_at DESC, u.user_id DESC
    `);
    res.json({ users: result.rows.map(row => ({
      userId: row.user_id, binanceId: row.binance_id,
      balance: Number(row.balance || 0), validAdsCount: Number(row.valid_ads_count || 0),
      createdAt: row.created_at, referrals: Number(row.referral_count || 0),
      totalWithdrawn: Number(row.completed_total || 0),
      withdrawalRequests: Number(row.request_count || 0), totalRequested: Number(row.requested_total || 0),
      totalMinersActivated: Number(row.total_miners_activated || 0),
      activeMiners: Number(row.miner_count || 0)
    })) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load user accounts' }); }
});

// Admin Panel 4: reset one account by user ID
app.post('/api/admin/users/:userId/reset', adminOnly, async (req, res) => {
  const targetUserId = req.params.userId;
  if (!validUserId(targetUserId)) return res.status(400).json({ error: 'Invalid user ID' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const found = await client.query('SELECT user_id, binance_id FROM bd_users WHERE user_id = $1 FOR UPDATE', [targetUserId]);
    if (!found.rowCount) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Account not found' }); }
    await client.query('UPDATE bd_users SET balance = 0, valid_ads_count = 0, updated_at = NOW() WHERE user_id = $1', [targetUserId]);
    await client.query('DELETE FROM bd_miners WHERE user_id = $1', [targetUserId]);
    const withdrawals = await client.query('DELETE FROM bd_withdrawals WHERE user_id = $1 RETURNING id', [targetUserId]);
    const referrals = await client.query('DELETE FROM bd_referrals WHERE referrer_id = $1 OR referred_id = $1 RETURNING id', [targetUserId]);
    await client.query('COMMIT');
    res.json({ success: true, userId: targetUserId, binanceId: found.rows[0].binance_id,
      deletedWithdrawals: withdrawals.rowCount, deletedReferrals: referrals.rowCount });
  } catch (err) { await client.query('ROLLBACK'); console.error(err); res.status(500).json({ error: 'Could not reset account' }); }
  finally { client.release(); }
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
    await client.query('UPDATE bd_users SET balance = 0, valid_ads_count = 0, updated_at = NOW() WHERE user_id = $1', [targetUserId]);
    await client.query('DELETE FROM bd_miners WHERE user_id = $1', [targetUserId]);
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
