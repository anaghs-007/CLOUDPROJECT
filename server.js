require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const { pool, insertTelemetry, updateTelemetryDecision } = require('./db');
const { enforceStaticSCP } = require('./staticPolicyEngine');
const { adaptivePolicyEngine, loadThetaBest, loadTemplates } = require('./adaptivePolicyEngine');

const app = express();
app.use(express.json());
app.set('trust proxy', true);

// Decode (NOT verify) a JWT payload. Keycloak verification comes in Phase 4.
function extractUserId(req) {
  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Bearer ')) {
    try {
      const payload = auth.slice(7).split('.')[1];
      const json = JSON.parse(Buffer.from(payload, 'base64url').toString());
      return json.sub || json.preferred_username || 'anonymous';
    } catch (_) { /* fall through to header */ }
  }
  return req.headers['x-user-id'] || 'anonymous';
}

function classify(pathUrl) {
  if (pathUrl.startsWith('/api/admin')) return 'restricted';
  if (pathUrl.startsWith('/api/workload')) return 'internal';
  return 'public';
}

// Visual Web Dashboard Routes (bypasses telemetry to keep research data pure)
app.get(['/', '/dashboard'], (req, res) => {
  const file = path.join(__dirname, 'dashboard.html');
  if (fs.existsSync(file)) {
    return res.sendFile(file);
  }
  return res.send('AC-SCP Sense Layer Active');
});

app.get('/api/dashboard/data', async (req, res) => {
  let logs = [];
  try {
    const result = await pool.query(
      `SELECT id, user_id, role, action, resource, region, sensitivity_label, decision, decision_reason, enforced_template, timestamp
       FROM telemetry_logs
       ORDER BY timestamp DESC
       LIMIT 25`
    );
    logs = result.rows;
  } catch (_) {
    // If database connection is not yet configured, return empty logs gracefully
  }
  return res.json({
    policyMode: process.env.POLICY_MODE || 'adaptive',
    theta: loadThetaBest(),
    templates: loadTemplates(),
    logs,
  });
});

function telemetryInterceptor(req, res, next) {
  // Ignore dashboard and favicon from security telemetry
  if (req.path === '/' || req.path === '/dashboard' || req.path === '/api/dashboard/data' || req.path === '/favicon.ico') {
    return next();
  }

  req.userId = extractUserId(req);
  const entry = {
    user_id: req.userId,
    action: req.method,
    resource: req.originalUrl,
    ip_address: req.ip,
    sensitivity_label: classify(req.originalUrl),
    role: req.headers['x-role'] || null,
    decision: 'ALLOWED',
    sim_label: req.headers['x-sim-label'] || null,
    episode_id: req.headers['x-episode-id'] || null,
    session_id: req.headers['x-session-id'] || null,
    tenant_id: req.headers['x-tenant-id'] || null,
    account_id: req.headers['x-account-id'] || null,
    workload_id: req.headers['x-workload-id'] || null,
    region: req.headers['x-region'] || null,
  };
  req.telemetryEntry = entry;
  req.updateTelemetryDecision = updateTelemetryDecision;
  req.telemetryIdPromise = insertTelemetry(entry).catch((err) => {
    console.error('[db] telemetry insert failed:', err.message);
    return null;
  });
  req.sensitivityLabel = classify(req.originalUrl);
  next();
}

app.use(telemetryInterceptor);
app.use(enforceStaticSCP);
app.use(adaptivePolicyEngine);

app.get('/api/public/status', (req, res) =>
  res.json({ status: 'ok', label: 'public' }));
app.post('/api/workload/compute', (req, res) =>
  res.json({ job: 'queued', label: 'internal' }));
app.delete('/api/admin/storage', (req, res) =>
  res.json({ deleted: true, label: 'restricted' }));
app.get('/api/admin/storage', (req, res) =>
  res.json({ status: 'active', label: 'restricted' }));
app.post('/api/iam/assume-role', (req, res) => {
  req.privilegeEscalation = true;
  res.json({ ok: true, privilege_escalation: true });
});

app.use((req, res) => res.status(404).json({ error: 'not found' }));

const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () =>
  console.log(`AC-SCP Sense layer listening on ${PORT}`));

process.on('unhandledRejection', (e) => console.error('[unhandled]', e));
process.on('SIGTERM', () => server.close(() => pool.end()));
process.on('SIGINT', () => server.close(() => pool.end()));

module.exports = { app, server, extractUserId, classify, telemetryInterceptor };
