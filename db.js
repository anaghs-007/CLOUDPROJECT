require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: Number(process.env.PGPORT || 5432),
  user: process.env.PGUSER || 'postgres',
  password: process.env.PGPASSWORD || 'postgres',
  database: process.env.PGDATABASE || 'acscp',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

// Idle-client errors must never crash the process.
pool.on('error', (err) => {
  console.error('[db] idle client error:', err.message);
});

async function insertTelemetry(entry) {
  const sql = `INSERT INTO telemetry_logs
    (user_id, action, resource, ip_address, sensitivity_label, role,
     sim_label, episode_id, session_id, decision, decision_latency_ms)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    RETURNING id`;
  const result = await pool.query(sql, [
    entry.user_id,
    entry.action,
    entry.resource,
    entry.ip_address,
    entry.sensitivity_label,
    entry.role || null,
    entry.sim_label || null,
    entry.episode_id || null,
    entry.session_id || null,
    entry.decision || 'ALLOWED',
    entry.decision_latency_ms || null,
  ]);
  return result.rows[0].id;
}

async function updateTelemetryDecision(id, decision, decisionLatencyMs, role) {
  return pool.query(
    `UPDATE telemetry_logs
     SET decision = $2, decision_latency_ms = $3, role = COALESCE($4, role)
     WHERE id = $1`,
    [id, decision, decisionLatencyMs, role || null],
  );
}

async function insertBaselineViolation(violation) {
  return pool.query(
    `INSERT INTO baseline_violations
      (user_id, resource, ip_address, rule_violated, session_id)
     VALUES ($1, $2, $3, $4, $5)`,
    [
      violation.user_id,
      violation.resource,
      violation.ip_address,
      violation.rule_violated,
      violation.session_id,
    ],
  );
}

module.exports = {
  pool,
  insertTelemetry,
  updateTelemetryDecision,
  insertBaselineViolation,
};
