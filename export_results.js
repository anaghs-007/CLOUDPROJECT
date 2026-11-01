require('dotenv').config();
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');
const { pool } = require('./db');
const { validateBenchmark } = require('./benchmark_schema');

function getGitCommit() {
  try {
    return execSync('git rev-parse HEAD', { cwd: __dirname }).toString().trim();
  } catch (_) {
    return 'unknown';
  }
}

function loadTheta() {
  try {
    const file = path.join(__dirname, 'theta_best.json');
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
  } catch (_) {}
  return { tau1: 0.4, tau2: 0.7, tau_w: 0.4, delta: 0.05, N: 2, alpha: 1, beta: 0.5, gamma: 0.2 };
}

function loadRunSummary(sessionId) {
  const file = path.join(__dirname, 'results', 'runs', `${sessionId}.json`);
  if (!fs.existsSync(file)) return null;
  try {
    const stdout = JSON.parse(fs.readFileSync(file, 'utf8')).stdout || '';
    const number = (pattern) => {
      const match = stdout.match(pattern);
      return match ? Number(match[1]) : null;
    };
    return {
      total_requests: number(/total=(\d+)/),
      violations_missed: number(/MISSED_threats=(\d+)/),
      violations_blocked: number(/blocked_threats=(\d+)/),
      false_denies: number(/blocked_normal=(\d+)/),
    };
  } catch (_) {
    return null;
  }
}

async function exportResults() {
  const client = await pool.connect();
  try {
    const manifestPath = path.join(__dirname, 'results', 'benchmark.meta.json');
    let manifest = {};
    if (fs.existsSync(manifestPath)) {
      try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (_) { manifest = {}; }
    }
    const configuredSeeds = new Set((manifest.seeds || []).map((seed) => Number(seed)));
    const runsDir = path.join(__dirname, 'results', 'runs');
    const matrixSessions = fs.existsSync(runsDir)
      ? fs.readdirSync(runsDir)
        .filter((name) => name.endsWith('.json'))
        .map((name) => path.basename(name, '.json'))
        .filter((sessionId) => {
          if (configuredSeeds.size === 0) return true;
          const match = sessionId.match(/-(\d+)$/);
          return match && configuredSeeds.has(Number(match[1]));
        })
      : [];
    if (matrixSessions.length === 0) {
      throw new Error('No benchmark run manifests found in results/runs. Run run_benchmark_matrix.py first.');
    }

    // 1. Gather all metrics per session
    const metricsRes = await client.query(`
      SELECT session_id, policy_type, total_requests, violations_missed, violations_blocked,
             false_denies, avg_exposure_seconds, avg_update_latency_ms, policy_changes
      FROM adaptive_metrics
      WHERE session_id = ANY($1::text[])
      ORDER BY created_at ASC
    `, [matrixSessions]);
    const baselineRes = await client.query(`
      SELECT session_id, total_requests, violations_missed, violations_detected,
             false_positives, avg_exposure_seconds, avg_latency_ms
      FROM baseline_metrics
      WHERE session_id = ANY($1::text[])
      ORDER BY created_at ASC
    `, [matrixSessions]);
    if (metricsRes.rows.length === 0 && baselineRes.rows.length === 0) {
      throw new Error('No aggregated benchmark metrics found. Run the live benchmark matrix first; refusing to write benchmark.json.');
    }
    const rawMetrics = [
      ...metricsRes.rows,
      ...baselineRes.rows.map((row) => ({
        session_id: row.session_id,
        policy_type: 'STATIC_SCP',
        total_requests: row.total_requests,
        violations_missed: row.violations_missed,
        violations_blocked: row.violations_detected,
        false_denies: row.false_positives,
        avg_exposure_seconds: row.avg_exposure_seconds,
        avg_update_latency_ms: row.avg_latency_ms,
        policy_changes: 0,
      })),
    ];
    const primaryBySession = new Map();
    for (const row of rawMetrics) {
      const current = primaryBySession.get(row.session_id);
      if (!current || Number(row.total_requests || 0) > Number(current.total_requests || 0)) {
        primaryBySession.set(row.session_id, row);
      }
    }
    const allMetrics = Array.from(primaryBySession.values());

    // 2. Gather attack episodes
    const episodesRes = await client.query(`
      SELECT episode_id, session_id, user_id, exposure_seconds, contained, first_malicious_ts
      FROM attack_episodes
      WHERE session_id = ANY($1::text[])
      ORDER BY first_malicious_ts ASC
    `, [matrixSessions]);

    // 3. Gather latency samples
    const policyUpdatesRes = await client.query(`
      SELECT update_latency_ms FROM policy_updates WHERE update_latency_ms IS NOT NULL
    `);

    // 4. Gather identity enforcement events
    const identityEventsRes = await client.query(`
      SELECT session_id, user_id, action, enforcement_call_ms, time_to_effective_ms, enforced_at
      FROM identity_enforcement_events
      WHERE session_id = ANY($1::text[])
      ORDER BY enforced_at ASC
    `, [matrixSessions]);

    // 5. Gather risk score history
    const riskHistoryRes = await client.query(`
      SELECT session_id, policy_mode, entity_type, entity_id, risk, scored_at
      FROM risk_score_history
      WHERE session_id = ANY($1::text[])
      ORDER BY scored_at ASC
    `, [matrixSessions]);

    // 6. Gather token overhead
    const overheadRes = await client.query(`
      SELECT session_id, AVG(identity_validation_ms) AS overhead_ms
      FROM telemetry_logs
      WHERE identity_validation_ms IS NOT NULL
        AND session_id = ANY($1::text[])
      GROUP BY session_id
    `, [matrixSessions]);
    const overheadMap = {};
    for (const row of overheadRes.rows) {
      overheadMap[row.session_id] = Number(row.overhead_ms || 0);
    }

    // Build modes map
    const modes = {
      none: { runs: [], exposure_seconds: [], update_latency_ms: [], enforcement_call_ms: [], time_to_effective_ms: [] },
      static: { runs: [], exposure_seconds: [], update_latency_ms: [], enforcement_call_ms: [], time_to_effective_ms: [] },
      adaptive: { runs: [], exposure_seconds: [], update_latency_ms: [], enforcement_call_ms: [], time_to_effective_ms: [] },
      identity: { runs: [], exposure_seconds: [], update_latency_ms: [], enforcement_call_ms: [], time_to_effective_ms: [] },
      adaptive_identity: { runs: [], exposure_seconds: [], update_latency_ms: [], enforcement_call_ms: [], time_to_effective_ms: [] },
    };

    const seedsFound = new Set();

    for (const m of allMetrics) {
      const sessionParts = (m.session_id || '').match(/^(none|static|adaptive_identity|adaptive|identity)-(\d+)$/);
      const modeKey = sessionParts ? sessionParts[1] : 'adaptive';
      const seedVal = sessionParts ? parseInt(sessionParts[2], 10) : 101;
      seedsFound.add(seedVal);

      if (!modes[modeKey]) {
        modes[modeKey] = { runs: [], exposure_seconds: [], update_latency_ms: [], enforcement_call_ms: [], time_to_effective_ms: [] };
      }

      const runSummary = loadRunSummary(m.session_id);
      modes[modeKey].runs.push({
        seed: seedVal,
        total_requests: runSummary?.total_requests ?? Number(m.total_requests || 0),
        violations_missed: runSummary?.violations_missed ?? Number(m.violations_missed || 0),
        violations_blocked: runSummary?.violations_blocked ?? Number(m.violations_blocked || 0),
        false_denies: runSummary?.false_denies ?? Number(m.false_denies || 0),
        policy_changes: Number(m.policy_changes || 0),
        validation_overhead_ms: overheadMap[m.session_id] !== undefined ? overheadMap[m.session_id] : null,
      });
    }

    // Assign episodes to modes
    for (const ep of episodesRes.rows) {
      const sessionParts = (ep.session_id || '').match(/^(none|static|adaptive_identity|adaptive|identity)-(\d+)$/);
      const modeKey = sessionParts ? sessionParts[1] : 'adaptive';
      const seedVal = sessionParts ? parseInt(sessionParts[2], 10) : 101;

      if (modes[modeKey]) {
        modes[modeKey].exposure_seconds.push({
          seed: seedVal,
          episode_id: ep.episode_id,
          value: Number(ep.exposure_seconds || 0),
        });
      }
    }

    // Assign latencies
    for (const pu of policyUpdatesRes.rows) {
      if (modes.adaptive) modes.adaptive.update_latency_ms.push(Number(pu.update_latency_ms));
      if (modes.adaptive_identity) modes.adaptive_identity.update_latency_ms.push(Number(pu.update_latency_ms));
    }

    for (const ide of identityEventsRes.rows) {
      const sessionParts = (ide.session_id || '').match(/^(none|static|adaptive_identity|adaptive|identity)-(\d+)$/);
      const modeKey = sessionParts ? sessionParts[1] : 'identity';
      if (modes[modeKey]) {
        if (ide.enforcement_call_ms) modes[modeKey].enforcement_call_ms.push(Number(ide.enforcement_call_ms));
        if (ide.time_to_effective_ms) modes[modeKey].time_to_effective_ms.push(Number(ide.time_to_effective_ms));
      }
    }

    // Build risk timeseries
    const risk_timeseries = {
      static: { points: [], events: [] },
      adaptive: { points: [], events: [] },
      identity: { points: [], events: [] },
      adaptive_identity: { points: [], events: [] },
    };

    // Construct timeseries relative to start of each mode
    for (const [modeKey, tsData] of Object.entries(risk_timeseries)) {
      const relevantHistory = riskHistoryRes.rows.filter(r => (r.policy_mode === modeKey || r.session_id.startsWith(modeKey)) && r.entity_type === 'user');
      if (relevantHistory.length > 0) {
        const t0 = new Date(relevantHistory[0].scored_at).getTime();
        for (const pt of relevantHistory) {
          const tRel = Math.max(0, (new Date(pt.scored_at).getTime() - t0) / 1000);
          tsData.points.push({
            t_rel_s: Number(tRel.toFixed(1)),
            risk_u: Number(pt.risk || 0),
            risk_w: 0.1,
          });
        }
      }
    }

    const seedsArr = seedsFound.size > 0 ? Array.from(seedsFound).sort((a,b)=>a-b) : [101, 102, 103, 104, 105, 106, 107, 108, 109, 110];

    const expectedSeeds = manifest.seeds || [];
    const expectedRequests = Number(manifest.requests_per_run || 0);
    const invalidRuns = allMetrics.filter((run) => {
      const summary = loadRunSummary(run.session_id);
      const totalRequests = summary?.total_requests ?? Number(run.total_requests);
      return expectedRequests > 0 && totalRequests !== expectedRequests;
    });
    if (invalidRuns.length > 0) {
      throw new Error(
        `Invalid aggregate request counts: expected ${expectedRequests} per run, ` +
        `found ${invalidRuns.map((run) => `${run.session_id}=${run.total_requests}`).join(', ')}.`,
      );
    }
    if (expectedSeeds.length > 0) {
      const incompleteModes = Object.entries(modes)
        .filter(([mode]) => ['none', 'static', 'adaptive', 'identity', 'adaptive_identity'].includes(mode))
        .filter(([, data]) => {
          const seeds = new Set(data.runs.map((run) => run.seed));
          return expectedSeeds.some((seed) => !seeds.has(seed));
        })
        .map(([mode]) => mode);
      if (incompleteModes.length > 0) {
        throw new Error(
          `Incomplete benchmark aggregates for mode(s): ${incompleteModes.join(', ')}. ` +
          'Refusing to write benchmark.json until every configured seed has completed.',
        );
      }
    }
    const benchmark = {
      meta: {
        git_commit: manifest.git_commit || getGitCommit(),
        seeds: manifest.seeds || seedsArr,
        requests_per_run: manifest.requests_per_run || 500,
        theta: manifest.theta || loadTheta(),
        keycloak_version: manifest.keycloak_version || '26.3.2',
        access_token_lifespan: manifest.access_token_lifespan || Number(process.env.KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SEC || 60),
        revocation_check_mode: manifest.revocation_check_mode || process.env.REVOCATION_CHECK || 'backchannel',
        hardware_os: manifest.hardware_os || `${os.type()} ${os.release()} / ${os.arch()}`,
        timestamp: manifest.timestamp || new Date().toISOString(),
        mock: false,
      },
      modes,
      risk_timeseries,
      ...(manifest.ablation ? { ablation: manifest.ablation } : {}),
      ...(manifest.scalability ? { scalability: manifest.scalability } : {}),
    };

    const valid = validateBenchmark(benchmark);
    if (!valid.success) {
      console.warn('[export-results] Warning: validation issues:', valid.error.format());
    }

    const outDir = path.join(__dirname, 'results');
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

    const targetPath = path.join(outDir, 'benchmark.json');
    fs.writeFileSync(targetPath, JSON.stringify(benchmark, null, 2));
    fs.writeFileSync(path.join(__dirname, 'benchmark.json'), JSON.stringify(benchmark, null, 2));
    console.log(`[export-results] Wrote aggregated results to ${targetPath}`);
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
