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
     sim_label, episode_id, session_id, decision, decision_latency_ms,
     tenant_id, account_id, workload_id, region, effective_ts,
     risk_u_at_decision, risk_w_at_decision, enforced_template,
     decision_reason, privilege_escalation)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
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
    entry.tenant_id || null,
    entry.account_id || null,
    entry.workload_id || null,
    entry.region || null,
    entry.effective_ts || null,
    entry.risk_u_at_decision ?? null,
    entry.risk_w_at_decision ?? null,
    entry.enforced_template || null,
    entry.decision_reason || null,
    entry.privilege_escalation ?? false,
  ]);
  return result.rows[0].id;
}

async function updateTelemetryDecision(id, decision, decisionLatencyMs, role, metadata = {}) {
  return pool.query(
    `UPDATE telemetry_logs
     SET decision = $2,
         decision_latency_ms = $3,
         role = COALESCE($4, role),
         tenant_id = COALESCE($5, tenant_id),
         account_id = COALESCE($6, account_id),
         workload_id = COALESCE($7, workload_id),
         region = COALESCE($8, region),
         effective_ts = COALESCE($9, effective_ts),
         risk_u_at_decision = COALESCE($10, risk_u_at_decision),
         risk_w_at_decision = COALESCE($11, risk_w_at_decision),
         enforced_template = COALESCE($12, enforced_template),
         decision_reason = COALESCE($13, decision_reason),
         privilege_escalation = COALESCE($14, privilege_escalation)
     WHERE id = $1`,
    [
      id,
      decision,
      decisionLatencyMs,
      role || null,
      metadata.tenant_id || null,
      metadata.account_id || null,
      metadata.workload_id || null,
      metadata.region || null,
      metadata.effective_ts || null,
      metadata.risk_u_at_decision ?? null,
      metadata.risk_w_at_decision ?? null,
      metadata.enforced_template || null,
      metadata.decision_reason || null,
      metadata.privilege_escalation ?? null,
    ],
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

async function insertShadowDecision(entry) {
  return pool.query(
    `INSERT INTO shadow_decisions
      (session_id, user_id, resource, action, rule, template_id, would_block)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      entry.session_id,
      entry.user_id,
      entry.resource,
      entry.action,
      entry.rule,
      entry.template_id,
      entry.would_block,
    ],
  );
}

module.exports = {
  pool,
  insertTelemetry,
  updateTelemetryDecision,
  insertBaselineViolation,
  insertShadowDecision,
};
