require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.DASHBOARD_API_PORT || 4000;
const ROOT = path.resolve(__dirname, '..');
const RESULTS_DIR = path.join(ROOT, 'results');
const useMockData = process.env.DASHBOARD_USE_MOCK === 'true';

// Configure CORS for dashboard UI
const allowedOrigins = [
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:3000',
  'http://localhost:4000',
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('dashboard origin is not allowed'))
    }
  },
  credentials: true,
}));

app.use(express.json());

// Set up PostgreSQL read-only pool
const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER_RO || 'dashboard_ro',
  password: process.env.PGPASSWORD_RO || 'dashboard-password',
  database: process.env.PGDATABASE || 'acscp',
  max: 10,
  idleTimeoutMillis: 30000,
});

pool.on('error', (err) => {
  console.error('[dashboard-db] pool error:', err.message);
});

// Helper: load benchmark data
function getBenchmarkData() {
  const realFile = path.join(RESULTS_DIR, 'benchmark.json');
  const mockFile = path.join(RESULTS_DIR, 'mock_benchmark.json');

  if (fs.existsSync(realFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(realFile, 'utf8'));
      return { source: 'real', data };
    } catch (_) {}
  }
  if (useMockData && fs.existsSync(mockFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(mockFile, 'utf8'));
      return { source: 'mock', data };
    } catch (_) {}
  }
  return { source: 'none', data: null };
}

// Helper: load stats data
function getStatsData() {
  const statsFile = path.join(RESULTS_DIR, 'stats.json');
  if (fs.existsSync(statsFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(statsFile, 'utf8'));
      if (!useMockData && data.mock === true) return null;
      return data;
    } catch (_) {}
  }
  return null;
}

// â”€â”€ ENDPOINTS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'ac-scp-dashboard-api', port: PORT, timestamp: new Date().toISOString() });
});

// GET /dash/benchmark: Returns benchmark data
app.get('/dash/benchmark', (req, res) => {
  const result = getBenchmarkData();
  if (!result.data) {
    return res.status(503).json({
      error: 'No real benchmark.json is available. Run run_benchmark_matrix.py without --dry-run.',
      mock_enabled: useMockData,
    });
  }
  res.json(result.data);
});

// GET /dash/stats: Returns statistical analysis results
app.get('/dash/stats', (req, res) => {
  const stats = getStatsData();
  if (!stats) {
    return res.status(404).json({ error: 'No stats.json available. Run python analyze_results.py' });
  }
  res.json(stats);
});

// GET /dash/live/risk: Current risk scores
app.get('/dash/live/risk', async (req, res) => {
  try {
    const userScores = await pool.query(`
      SELECT user_id, risk, features, scored_at
      FROM user_risk_scores
      ORDER BY risk DESC
      LIMIT 50
    `);
    const workloadScores = await pool.query(`
      SELECT workload_id, risk, features, scored_at
      FROM workload_risk_scores
      ORDER BY risk DESC
      LIMIT 50
    `);
    res.json({
      users: userScores.rows,
      workloads: workloadScores.rows,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    // Return graceful mock/empty if database is disconnected
    res.json({ users: [], workloads: [], db_status: 'unavailable', error: err.message });
  }
});

// GET /dash/live/decisions: Recent decisions
app.get('/dash/live/decisions', async (req, res) => {
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10)));
  try {
    const decisions = await pool.query(`
      SELECT id, user_id, role, action, resource, region, sensitivity_label,
             decision, decision_reason, enforced_template, risk_u_at_decision,
             risk_w_at_decision, decision_latency_ms, timestamp
      FROM telemetry_logs
      ORDER BY timestamp DESC
      LIMIT $1
    `, [limit]);
    res.json({ items: decisions.rows, timestamp: new Date().toISOString(), db_status: 'connected' });
  } catch (err) {
    res.json({ items: [], timestamp: new Date().toISOString(), db_status: 'unavailable', error: err.message });
  }
});

// GET /dash/live/quarantines: Active quarantines
app.get('/dash/live/quarantines', async (req, res) => {
  try {
    const quarantines = await pool.query(`
      SELECT p.entity_id AS user_id, p.template_id, p.applied_at, p.scored_at,
             u.risk
      FROM policy_state p
      LEFT JOIN user_risk_scores u ON u.user_id = p.entity_id
      WHERE p.scope = 'identity' AND p.template_id = 'KEYCLOAK_QUARANTINED'
      ORDER BY p.applied_at DESC
    `);
    res.json({ items: quarantines.rows, timestamp: new Date().toISOString(), db_status: 'connected' });
  } catch (err) {
    res.json({ items: [], timestamp: new Date().toISOString(), db_status: 'unavailable', error: err.message });
  }
});

// GET /dash/live/stream: SSE real-time stream (every 2s)
app.get('/dash/live/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  const sendEvent = async () => {
    try {
      let activeUsers = [];
      let recentDecisions = [];
      let activeQuarantines = [];
      let payloadError = null;

      try {
        const uRes = await pool.query('SELECT user_id, risk, scored_at FROM user_risk_scores ORDER BY risk DESC LIMIT 10');
        activeUsers = uRes.rows;
        const dRes = await pool.query('SELECT id, user_id, action, resource, decision, decision_reason, timestamp FROM telemetry_logs ORDER BY timestamp DESC LIMIT 10');
        recentDecisions = dRes.rows;
        const qRes = await pool.query("SELECT entity_id AS user_id, applied_at FROM policy_state WHERE template_id = 'KEYCLOAK_QUARANTINED'");
        activeQuarantines = qRes.rows;
      } catch (error) {
        payloadError = error.message;
      }

      const payload = {
        timestamp: new Date().toISOString(),
        users: activeUsers,
        decisions: recentDecisions,
        quarantines: activeQuarantines,
        db_status: payloadError ? 'unavailable' : 'connected',
        ...(payloadError ? { error: payloadError } : {}),
      };

      res.write(`data: ${JSON.stringify(payload)}\n\n`);
    } catch (_) {}
  };

  const timer = setInterval(sendEvent, 2000);
  sendEvent(); // Immediate initial push

  req.on('close', () => {
    clearInterval(timer);
  });
});

const server = app.listen(PORT, () => {
  console.log(`[dashboard-api] AC-SCP Research Dashboard API listening on port ${PORT}`);
});

module.exports = { app, server };
