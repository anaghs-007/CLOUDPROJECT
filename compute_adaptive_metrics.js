require('dotenv').config();
const { pool } = require('./db');

async function computeAdaptiveMetrics(sessionId) {
  const session = sessionId || process.env.SESSION_ID;
  if (!session) throw new Error('Provide a session id or SESSION_ID');
  const client = await pool.connect();
  try {
    const stats = await client.query(`
      SELECT COUNT(*)::int AS total_requests,
             COUNT(*) FILTER (WHERE sim_label = 'threat' AND decision = 'ALLOWED')::int AS violations_missed,
             COUNT(*) FILTER (WHERE sim_label = 'normal' AND decision = 'BLOCKED')::int AS false_denies,
             COUNT(*) FILTER (WHERE sim_label = 'threat' AND decision = 'BLOCKED')::int AS violations_blocked,
             COALESCE(AVG(exposure_seconds), 0) AS avg_exposure_seconds,
             COALESCE(AVG(update_latency_ms), 0) AS avg_update_latency_ms,
             COALESCE(COUNT(DISTINCT id), 0) AS policy_changes
      FROM (
        SELECT t.*, ae.exposure_seconds, pu.update_latency_ms
        FROM telemetry_logs t
        LEFT JOIN attack_episodes ae ON ae.episode_id = t.episode_id
        LEFT JOIN policy_updates pu ON pu.scope = 'user' AND pu.entity_id = t.user_id
        WHERE t.session_id = $1
      ) q
    `, [session]);
    const row = stats.rows[0];
    const result = await client.query(`
      INSERT INTO adaptive_metrics
      (session_id, policy_type, total_requests, violations_missed, violations_blocked,
       false_denies, avg_exposure_seconds, avg_update_latency_ms, policy_changes)
      VALUES ($1, 'ADAPTIVE_SCP', $2, $3, $4, $5, $6, $7, $8)
      RETURNING *
    `, [session, row.total_requests, row.violations_missed, row.violations_blocked, row.false_denies, row.avg_exposure_seconds, row.avg_update_latency_ms, row.policy_changes]);
    console.table(result.rows);
    return result.rows[0];
  } finally {
    client.release();
  }
}

if (require.main === module) {
  computeAdaptiveMetrics(process.argv[2]).catch((error) => {
    console.error('[adaptive-metrics] failed:', error.message);
    process.exitCode = 1;
  }).finally(() => pool.end());
}

module.exports = { computeAdaptiveMetrics };
