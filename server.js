require('dotenv').config();
const express = require('express');
const { pool, insertTelemetry, updateTelemetryDecision } = require('./db');
const { enforceStaticSCP } = require('./staticPolicyEngine');
const { adaptivePolicyEngine } = require('./adaptivePolicyEngine');

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

function classify(path) {
  if (path.startsWith('/api/admin')) return 'restricted';
  if (path.startsWith('/api/workload')) return 'internal';
  return 'public';
}

function telemetryInterceptor(req, res, next) {
  req.userId = extractUserId(req);
  const entry = {
    user_id: req.userId,
    action: req.method,
    resource: req.originalUrl,
    ip_address: req.ip,
    sensitivity_label: classify(req.originalUrl),
    role: null,
    decision: 'ALLOWED',
    sim_label: req.headers['x-sim-label'] || null,
    episode_id: req.headers['x-episode-id'] || null,
    session_id: req.headers['x-session-id'] || null,
    tenant_id: req.headers['x-tenant-id'] || null,
    account_id: req.headers['x-account-id'] || null,
    workload_id: req.headers['x-workload-id'] || null,
    region: req.headers['x-region'] || null,
    user_id: req.userId,
  };
  req.telemetryEntry = entry;
  req.updateTelemetryDecision = updateTelemetryDecision;
  req.telemetryIdPromise = insertTelemetry(entry).catch((err) => {
    console.error('[telemetry] insert failed:', err.message);
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
