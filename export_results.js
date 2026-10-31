require('dotenv').config();
const fs = require('fs');
const { pool } = require('./db');

async function exportResults() {
  const client = await pool.connect();
  try {
    const modeRows = await client.query(`
      SELECT session_id, policy_type, total_requests, violations_missed, violations_blocked,
             false_denies, avg_exposure_seconds, avg_update_latency_ms, policy_changes
      FROM adaptive_metrics
      ORDER BY created_at DESC
      LIMIT 50
    `);
    const episodes = await client.query(`
      SELECT episode_id, exposure_seconds, contained, session_id
      FROM attack_episodes
      ORDER BY first_malicious_ts DESC
      LIMIT 25
    `);
    const riskHistory = await client.query(`
      SELECT session_id, entity_type, entity_id, risk, scored_at
      FROM risk_score_history
      ORDER BY scored_at DESC
      LIMIT 100
    `);
    const updateLatency = await client.query(`
      SELECT update_latency_ms
      FROM policy_updates
      ORDER BY ts DESC
      LIMIT 100
    `);
    const identityMetrics = await client.query(`
      SELECT session_id,
             COUNT(*) FILTER (WHERE action = 'QUARANTINE')::int AS quarantine_events,
             AVG(enforcement_call_ms) FILTER (WHERE action = 'QUARANTINE') AS enforcement_call_mean_ms,
             STDDEV_POP(enforcement_call_ms) FILTER (WHERE action = 'QUARANTINE') AS enforcement_call_std_ms,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY enforcement_call_ms)
               FILTER (WHERE action = 'QUARANTINE') AS enforcement_call_p95_ms,
             AVG(time_to_effective_ms) AS time_to_effective_mean_ms,
             STDDEV_POP(time_to_effective_ms) AS time_to_effective_std_ms,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY time_to_effective_ms)
               FILTER (WHERE time_to_effective_ms IS NOT NULL) AS time_to_effective_p95_ms
      FROM identity_enforcement_events
      GROUP BY session_id ORDER BY MAX(enforced_at) DESC LIMIT 50
    `);
    const tokenOverhead = await client.query(`
      SELECT session_id, AVG(identity_validation_ms) AS mean_identity_validation_ms,
             STDDEV_POP(identity_validation_ms) AS std_identity_validation_ms,
             percentile_cont(0.95) WITHIN GROUP (ORDER BY identity_validation_ms) AS p95_identity_validation_ms
      FROM telemetry_logs WHERE identity_validation_ms IS NOT NULL GROUP BY session_id
    `);

    const benchmark = {
      generated_at: new Date().toISOString(),
      violations_per_mode: modeRows.rows,
      exposure_per_episode: episodes.rows,
      risk_score_history: riskHistory.rows,
      update_latency_samples: updateLatency.rows.map((row) => Number(row.update_latency_ms || 0)),
      identity_enforcement: identityMetrics.rows,
      token_validation_overhead: tokenOverhead.rows,
      ablation: [
        { mode: 'static', violations: 0, false_denies: 0 },
        { mode: 'static_context', violations: 0, false_denies: 0 },
        { mode: 'static_ml', violations: 0, false_denies: 0 },
        { mode: 'adaptive', violations: 0, false_denies: 0 },
        { mode: 'identity', violations: 0, false_denies: 0 },
        { mode: 'adaptive_identity', violations: 0, false_denies: 0 },
      ],
      scalability: [
        { tenants: 10, avg_update_latency_ms: 0, violations: 0 },
        { tenants: 25, avg_update_latency_ms: 0, violations: 0 },
        { tenants: 50, avg_update_latency_ms: 0, violations: 0 },
        { tenants: 100, avg_update_latency_ms: 0, violations: 0 },
        { tenants: 200, avg_update_latency_ms: 0, violations: 0 },
      ],
    };

    fs.writeFileSync('benchmark.json', JSON.stringify(benchmark, null, 2));
    console.log('benchmark.json written');
    return benchmark;
  } finally {
    client.release();
    await pool.end();
  }
}

if (require.main === module) {
  exportResults().catch((error) => {
    console.error('[export-results] failed:', error.message);
    process.exitCode = 1;
  });
}

module.exports = { exportResults };
