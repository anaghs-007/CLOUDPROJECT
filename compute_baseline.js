require('dotenv').config();
const { pool } = require('./db');

async function computeBaseline(sessionId) {
  const session = sessionId || process.env.SESSION_ID;
  if (!session) throw new Error('Provide a session id or SESSION_ID');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
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

    const metrics = await client.query(
      `SELECT COUNT(*)::int AS total_requests,
              COUNT(*) FILTER (WHERE sim_label = 'threat' AND decision = 'BLOCKED')::int AS violations_detected,
              COUNT(*) FILTER (WHERE sim_label = 'threat' AND decision = 'ALLOWED')::int AS violations_missed,
              COUNT(*) FILTER (WHERE sim_label = 'normal' AND decision = 'BLOCKED')::int AS false_positives,
              COALESCE(AVG(decision_latency_ms), 0) AS avg_latency_ms
       FROM telemetry_logs WHERE session_id = $1`,
      [session],
    );
    const exposure = await client.query(
      `SELECT COALESCE(AVG(exposure_seconds), 0) AS avg_exposure_seconds
       FROM attack_episodes WHERE session_id = $1`,
      [session],
    );
    const row = metrics.rows[0];
    const saved = await client.query(
      `INSERT INTO baseline_metrics
        (session_id, total_requests, violations_detected, violations_missed,
         false_positives, avg_latency_ms, avg_exposure_seconds)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [session, row.total_requests, row.violations_detected, row.violations_missed,
        row.false_positives, row.avg_latency_ms, exposure.rows[0].avg_exposure_seconds],
    );
    await client.query('COMMIT');
    console.table(saved.rows);
    return saved.rows[0];
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

if (require.main === module) {
  computeBaseline(process.argv[2])
    .catch((error) => { console.error('[baseline] failed:', error.message); process.exitCode = 1; })
    .finally(() => pool.end());
}

module.exports = { computeBaseline };
