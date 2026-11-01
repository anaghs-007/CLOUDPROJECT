const { z } = require('zod');

const MetaSchema = z.object({
  git_commit: z.string(),
  seeds: z.array(z.number()),
  requests_per_run: z.number().int().positive(),
  theta: z.record(z.any()),
  keycloak_version: z.string(),
  access_token_lifespan: z.number().positive(),
  revocation_check_mode: z.string(),
  hardware_os: z.string(),
  timestamp: z.string(),
  mock: z.boolean(),
});

const RunMetricSchema = z.object({
  seed: z.number(),
  total_requests: z.number().int().nonnegative(),
  violations_missed: z.number().int().nonnegative(),
  violations_blocked: z.number().int().nonnegative(),
  false_denies: z.number().int().nonnegative(),
  policy_changes: z.number().int().nonnegative(),
  validation_overhead_ms: z.number().nullable().optional(),
});

const ExposureItemSchema = z.object({
  seed: z.number(),
  episode_id: z.string(),
  value: z.number().nonnegative(),
});

const ModeDataSchema = z.object({
  runs: z.array(RunMetricSchema),
  exposure_seconds: z.array(ExposureItemSchema),
  update_latency_ms: z.array(z.number().nonnegative()),
  enforcement_call_ms: z.array(z.number().nonnegative()),
  time_to_effective_ms: z.array(z.number().nonnegative()),
});

const RiskPointSchema = z.object({
  t_rel_s: z.number(),
  risk_u: z.number(),
  risk_w: z.number(),
});

const RiskEventSchema = z.object({
  t_rel_s: z.number(),
  type: z.enum(['ENFORCED', 'FIRST_REJECTED', 'RESTORED']),
});

const RiskTimeseriesModeSchema = z.object({
  points: z.array(RiskPointSchema),
  events: z.array(RiskEventSchema),
});

const AblationItemSchema = z.object({
  mode: z.string(),
  violations: z.number().nonnegative(),
  false_denies: z.number().nonnegative().optional(),
  reduction_pct: z.number(),
});

const ScalabilityItemSchema = z.object({
  tenants: z.number().int().positive(),
  users: z.number().int().positive(),
  avg_update_latency_ms: z.number().nonnegative(),
  violations: z.number().nonnegative(),
});

const BenchmarkSchema = z.object({
  meta: MetaSchema,
  modes: z.record(ModeDataSchema),
  risk_timeseries: z.record(RiskTimeseriesModeSchema),
  ablation: z.array(AblationItemSchema).optional(),
  scalability: z.array(ScalabilityItemSchema).optional(),
});

function validateBenchmark(data) {
  return BenchmarkSchema.safeParse(data);
}

module.exports = {
  BenchmarkSchema,
  MetaSchema,
  ModeDataSchema,
  RunMetricSchema,
  validateBenchmark,
};

