const fs = require('fs');
const path = require('path');
const { validateBenchmark } = require('./benchmark_schema');

function makeGaussian(mean, std, minVal = 0, maxVal = Infinity) {
  let u = 0, v = 0;
  while (u === 0) u = Math.random();
  while (v === 0) v = Math.random();
  const num = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
  const res = mean + num * std;
  return Math.max(minVal, Math.min(maxVal, res));
}

function generateMockBenchmark() {
  const seeds = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120];
  const requestsPerRun = 500;

  const mockMeta = {
    git_commit: '50a8d9a00d0cbdc89891b46d5413f7bb635507cb',
    seeds,
    requests_per_run: requestsPerRun,
    theta: { tau1: 0.4, tau2: 0.7, tau_w: 0.4, delta: 0.05, N: 2, alpha: 1, beta: 0.5, gamma: 0.2 },
    keycloak_version: '26.3.2',
    access_token_lifespan: 60,
    revocation_check_mode: 'backchannel',
    hardware_os: 'Windows 11 / x86_64 / Intel Core i7',
    timestamp: new Date().toISOString(),
    mock: true,
  };

  const modeProfiles = {
    none: {
      missedMean: 100, missedStd: 1.2,
      blockedMean: 0, blockedStd: 0,
      falseDenyMean: 0, falseDenyStd: 0,
      changesMean: 0, changesStd: 0,
      overheadMean: 0.2, overheadStd: 0.05,
      exposureMean: 1250, exposureStd: 80,
      updateLatencyMean: 0, updateLatencyStd: 0,
      enforcementCallMean: 0, enforcementCallStd: 0,
      timeToEffectiveMean: 0, timeToEffectiveStd: 0,
    },
    static: {
      missedMean: 74, missedStd: 4.5,
      blockedMean: 26, blockedStd: 4.5,
      falseDenyMean: 10, falseDenyStd: 2.1,
      changesMean: 0, changesStd: 0,
      overheadMean: 0.45, overheadStd: 0.08,
      exposureMean: 1140, exposureStd: 65, // ~19 min
      updateLatencyMean: 0, updateLatencyStd: 0,
      enforcementCallMean: 0, enforcementCallStd: 0,
      timeToEffectiveMean: 0, timeToEffectiveStd: 0,
    },
    adaptive: {
      missedMean: 31, missedStd: 3.2,
      blockedMean: 69, blockedStd: 3.2,
      falseDenyMean: 3, falseDenyStd: 1.1,
      changesMean: 18, changesStd: 2.4,
      overheadMean: 1.8, overheadStd: 0.3,
      exposureMean: 390, exposureStd: 35, // ~6.5 min
      updateLatencyMean: 247.4, updateLatencyStd: 58.6,
      enforcementCallMean: 0, enforcementCallStd: 0,
      timeToEffectiveMean: 247.4, timeToEffectiveStd: 58.6,
    },
    identity: {
      missedMean: 51, missedStd: 4.1,
      blockedMean: 49, blockedStd: 4.1,
      falseDenyMean: 2, falseDenyStd: 0.9,
      changesMean: 12, changesStd: 1.8,
      overheadMean: 2.4, overheadStd: 0.4,
      exposureMean: 510, exposureStd: 45,
      updateLatencyMean: 0, updateLatencyStd: 0,
      enforcementCallMean: 138.5, enforcementCallStd: 24.2,
      timeToEffectiveMean: 420.0, timeToEffectiveStd: 48.0,
    },
    adaptive_identity: {
      missedMean: 18, missedStd: 2.6,
      blockedMean: 82, blockedStd: 2.6,
      falseDenyMean: 3, falseDenyStd: 1.2,
      changesMean: 24, changesStd: 3.1,
      overheadMean: 3.2, overheadStd: 0.5,
      exposureMean: 180, exposureStd: 25, // ~3 min
      updateLatencyMean: 242.0, updateLatencyStd: 52.0,
      enforcementCallMean: 135.0, enforcementCallStd: 22.0,
      timeToEffectiveMean: 310.0, timeToEffectiveStd: 42.0,
    },
  };

  const modes = {};

  for (const [mode, prof] of Object.entries(modeProfiles)) {
    const runs = [];
    const exposure_seconds = [];
    const update_latency_ms = [];
    const enforcement_call_ms = [];
    const time_to_effective_ms = [];

    for (const seed of seeds) {
      const missed = Math.round(makeGaussian(prof.missedMean, prof.missedStd, 0, requestsPerRun));
      const blocked = Math.round(makeGaussian(prof.blockedMean, prof.blockedStd, 0, requestsPerRun));
      const falseDenies = Math.round(makeGaussian(prof.falseDenyMean, prof.falseDenyStd, 0, requestsPerRun));
      const changes = Math.round(makeGaussian(prof.changesMean, prof.changesStd, 0, 100));
      const overhead = Number(makeGaussian(prof.overheadMean, prof.overheadStd, 0.05).toFixed(3));

      runs.push({
        seed,
        total_requests: requestsPerRun,
        violations_missed: missed,
        violations_blocked: blocked,
        false_denies: falseDenies,
        policy_changes: changes,
        validation_overhead_ms: overhead,
      });

      // 2 episodes per run
      for (let epIdx = 1; epIdx <= 2; epIdx++) {
        exposure_seconds.push({
          seed,
          episode_id: `ep-${mode}-${seed}-${epIdx}`,
          value: Number(makeGaussian(prof.exposureMean, prof.exposureStd, 10).toFixed(1)),
        });
      }

      // Latency samples per run
      if (prof.updateLatencyMean > 0) {
        for (let k = 0; k < 5; k++) {
          update_latency_ms.push(Number(makeGaussian(prof.updateLatencyMean, prof.updateLatencyStd, 80).toFixed(2)));
        }
      }
      if (prof.enforcementCallMean > 0) {
        for (let k = 0; k < 5; k++) {
          enforcement_call_ms.push(Number(makeGaussian(prof.enforcementCallMean, prof.enforcementCallStd, 40).toFixed(2)));
        }
      }
      if (prof.timeToEffectiveMean > 0) {
        for (let k = 0; k < 5; k++) {
          time_to_effective_ms.push(Number(makeGaussian(prof.timeToEffectiveMean, prof.timeToEffectiveStd, 100).toFixed(2)));
        }
      }
    }

    modes[mode] = {
      runs,
      exposure_seconds,
      update_latency_ms,
      enforcement_call_ms,
      time_to_effective_ms,
    };
  }

  // Generate Risk Evolution Timeseries
  const risk_timeseries = {
    static: {
      points: [
        { t_rel_s: 0, risk_u: 0.10, risk_w: 0.10 },
        { t_rel_s: 15, risk_u: 0.18, risk_w: 0.12 },
        { t_rel_s: 30, risk_u: 0.28, risk_w: 0.15 },
        { t_rel_s: 45, risk_u: 0.42, risk_w: 0.22 },
        { t_rel_s: 60, risk_u: 0.58, risk_w: 0.35 },
        { t_rel_s: 75, risk_u: 0.72, risk_w: 0.45 },
        { t_rel_s: 90, risk_u: 0.85, risk_w: 0.52 },
        { t_rel_s: 105, risk_u: 0.92, risk_w: 0.58 },
        { t_rel_s: 120, risk_u: 0.95, risk_w: 0.60 },
      ],
      events: [],
    },
    adaptive: {
      points: [
        { t_rel_s: 0, risk_u: 0.10, risk_w: 0.10 },
        { t_rel_s: 10, risk_u: 0.15, risk_w: 0.12 },
        { t_rel_s: 20, risk_u: 0.32, risk_w: 0.18 },
        { t_rel_s: 30, risk_u: 0.55, risk_w: 0.28 },
        { t_rel_s: 40, risk_u: 0.78, risk_w: 0.42 },
        { t_rel_s: 50, risk_u: 0.84, risk_w: 0.40 },
        { t_rel_s: 65, risk_u: 0.62, risk_w: 0.32 },
        { t_rel_s: 85, risk_u: 0.38, risk_w: 0.22 },
        { t_rel_s: 100, risk_u: 0.21, risk_w: 0.15 },
        { t_rel_s: 120, risk_u: 0.12, risk_w: 0.10 },
      ],
      events: [
        { t_rel_s: 34.2, type: 'ENFORCED' },
        { t_rel_s: 92.5, type: 'RESTORED' },
      ],
    },
    identity: {
      points: [
        { t_rel_s: 0, risk_u: 0.10, risk_w: 0.10 },
        { t_rel_s: 10, risk_u: 0.18, risk_w: 0.12 },
        { t_rel_s: 25, risk_u: 0.45, risk_w: 0.20 },
        { t_rel_s: 35, risk_u: 0.74, risk_w: 0.35 },
        { t_rel_s: 45, risk_u: 0.86, risk_w: 0.42 },
        { t_rel_s: 60, risk_u: 0.72, risk_w: 0.38 },
        { t_rel_s: 80, risk_u: 0.48, risk_w: 0.25 },
        { t_rel_s: 100, risk_u: 0.25, risk_w: 0.14 },
        { t_rel_s: 120, risk_u: 0.12, risk_w: 0.10 },
      ],
      events: [
        { t_rel_s: 37.8, type: 'ENFORCED' },
        { t_rel_s: 38.3, type: 'FIRST_REJECTED' },
        { t_rel_s: 96.0, type: 'RESTORED' },
      ],
    },
    adaptive_identity: {
      points: [
        { t_rel_s: 0, risk_u: 0.10, risk_w: 0.10 },
        { t_rel_s: 10, risk_u: 0.20, risk_w: 0.15 },
        { t_rel_s: 20, risk_u: 0.44, risk_w: 0.25 },
        { t_rel_s: 30, risk_u: 0.76, risk_w: 0.40 },
        { t_rel_s: 40, risk_u: 0.88, risk_w: 0.48 },
        { t_rel_s: 55, risk_u: 0.65, risk_w: 0.35 },
        { t_rel_s: 70, risk_u: 0.42, risk_w: 0.22 },
        { t_rel_s: 90, risk_u: 0.22, risk_w: 0.14 },
        { t_rel_s: 110, risk_u: 0.11, risk_w: 0.10 },
      ],
      events: [
        { t_rel_s: 31.0, type: 'ENFORCED' },
        { t_rel_s: 31.4, type: 'FIRST_REJECTED' },
        { t_rel_s: 88.0, type: 'RESTORED' },
      ],
    },
  };

  // Table 5 Ablation study from research paper
  const ablation = [
    { mode: 'Static SCP', violations: 120, false_denies: 10, reduction_pct: 0.0 },
    { mode: 'SCP + Context-Aware Engine', violations: 78, false_denies: 6, reduction_pct: 35.0 },
    { mode: 'SCP + ML Risk Assessment', violations: 65, false_denies: 4, reduction_pct: 45.8 },
    { mode: 'Full Adaptive AC-SCP Framework', violations: 45, false_denies: 3, reduction_pct: 62.5 },
  ];

  // Table 6 Scalability from research paper
  const scalability = [
    { tenants: 10, users: 500, avg_update_latency_ms: 182, violations: 12 },
    { tenants: 25, users: 1250, avg_update_latency_ms: 205, violations: 21 },
    { tenants: 50, users: 2500, avg_update_latency_ms: 247, violations: 45 },
    { tenants: 100, users: 5000, avg_update_latency_ms: 289, violations: 83 },
    { tenants: 200, users: 10000, avg_update_latency_ms: 332, violations: 155 },
  ];

  const benchmark = {
    meta: mockMeta,
    modes,
    risk_timeseries,
    ablation,
    scalability,
  };

  const validation = validateBenchmark(benchmark);
  if (!validation.success) {
    console.error('Mock data failed Zod schema validation:', validation.error.format());
    process.exit(1);
  }

  const outPath = path.join(__dirname, 'results', 'mock_benchmark.json');
  fs.writeFileSync(outPath, JSON.stringify(benchmark, null, 2));
  console.log('✓ Successfully wrote and validated results/mock_benchmark.json');
  return benchmark;
}

if (require.main === module) {
  generateMockBenchmark();
}

module.exports = { generateMockBenchmark };

