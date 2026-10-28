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

    const benchmark = {
      generated_at: new Date().toISOString(),
      violations_per_mode: modeRows.rows,
      exposure_per_episode: episodes.rows,
      risk_score_history: riskHistory.rows,
      update_latency_samples: updateLatency.rows.map((row) => Number(row.update_latency_ms || 0)),
      ablation: [
        { mode: 'static', violations: 0, false_denies: 0 },
        { mode: 'static_context', violations: 0, false_denies: 0 },
        { mode: 'static_ml', violations: 0, false_denies: 0 },
        { mode: 'adaptive', violations: 0, false_denies: 0 },
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
