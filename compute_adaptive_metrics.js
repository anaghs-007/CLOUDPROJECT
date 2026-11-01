require('dotenv').config();
const { pool } = require('./db');

async function computeAdaptiveMetrics(sessionId) {
  const session = sessionId || process.env.SESSION_ID;
  if (!session) throw new Error('Provide a session id or SESSION_ID');
  const client = await pool.connect();
  try {
    const episodes = await client.query(
      `SELECT episode_id, session_id, user_id,
              MIN(timestamp) AS first_malicious_ts,
              MAX(timestamp) FILTER (WHERE decision = 'ALLOWED') AS last_allowed_malicious_ts
       FROM telemetry_logs
       WHERE session_id = $1 AND sim_label = 'threat' AND episode_id IS NOT NULL
       GROUP BY episode_id, session_id, user_id`,
      [session],
    );
    for (const episode of episodes.rows) {
      const first = new Date(episode.first_malicious_ts).getTime();
      const last = episode.last_allowed_malicious_ts
        ? new Date(episode.last_allowed_malicious_ts).getTime() : first;
      const exposure = Math.max(0, (last - first) / 1000);
      await client.query(
        `INSERT INTO attack_episodes
          (episode_id, session_id, user_id, first_malicious_ts,
           last_allowed_malicious_ts, exposure_seconds, contained)
         VALUES ($1, $2, $3, $4, $5, $6, FALSE)
         ON CONFLICT (episode_id) DO UPDATE SET
           session_id = EXCLUDED.session_id, user_id = EXCLUDED.user_id,
           first_malicious_ts = EXCLUDED.first_malicious_ts,
           last_allowed_malicious_ts = EXCLUDED.last_allowed_malicious_ts,
           exposure_seconds = EXCLUDED.exposure_seconds,
           contained = EXCLUDED.contained`,
        [episode.episode_id, session, episode.user_id,
          episode.first_malicious_ts, episode.last_allowed_malicious_ts, exposure],
      );
    }

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
    const identity = await client.query(`
      SELECT COUNT(*) FILTER (WHERE action = 'QUARANTINE')::int AS policy_changes,
             COALESCE(AVG(enforcement_call_ms) FILTER (WHERE action = 'QUARANTINE'), 0) AS avg_enforcement_call_ms,
             COALESCE(AVG(time_to_effective_ms), 0) AS avg_time_to_effective_ms,
             COALESCE(AVG(time_to_effective_ms) FILTER (WHERE time_to_effective_ms IS NOT NULL), 0) AS avg_update_latency_ms
      FROM identity_enforcement_events WHERE session_id = $1
    `, [session]);
    const identityRow = identity.rows[0];
    if (identityRow && Number(identityRow.policy_changes) > 0) {
      await client.query(`
        INSERT INTO adaptive_metrics
          (session_id, policy_type, total_requests, violations_missed, violations_blocked,
           false_denies, avg_exposure_seconds, avg_update_latency_ms, policy_changes)
        SELECT $1, 'KEYCLOAK_IDENTITY_ENFORCEMENT',
               COUNT(*)::int,
               COUNT(*) FILTER (WHERE sim_label = 'threat' AND decision = 'ALLOWED')::int,
               COUNT(*) FILTER (WHERE sim_label = 'threat' AND decision = 'BLOCKED')::int,
               COUNT(*) FILTER (WHERE sim_label = 'normal' AND decision = 'BLOCKED')::int,
               COALESCE(AVG(ae.exposure_seconds), 0),
               $2, $3
        FROM telemetry_logs t
        LEFT JOIN attack_episodes ae ON ae.episode_id = t.episode_id
        WHERE t.session_id = $1
      `, [session, identityRow.avg_update_latency_ms, identityRow.policy_changes]);
    }
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
