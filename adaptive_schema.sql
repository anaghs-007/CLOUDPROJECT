-- Phase 3+: Adaptive multi-tenant context and policy-state schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE telemetry_logs
  ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS account_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS workload_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS region VARCHAR(64),
  ADD COLUMN IF NOT EXISTS effective_ts TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS risk_u_at_decision DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS risk_w_at_decision DOUBLE PRECISION,
  ADD COLUMN IF NOT EXISTS enforced_template VARCHAR(32),
  ADD COLUMN IF NOT EXISTS decision_reason VARCHAR(128),
  ADD COLUMN IF NOT EXISTS privilege_escalation BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS workloads (
  workload_id VARCHAR(64) PRIMARY KEY,
  tenant_id VARCHAR(64) NOT NULL,
  account_id VARCHAR(64) NOT NULL,
  region VARCHAR(64) NOT NULL,
  sensitivity_label VARCHAR(32) NOT NULL CHECK (sensitivity_label IN ('public', 'internal', 'regulated')),
  encrypted BOOLEAN NOT NULL DEFAULT FALSE,
  public_exposed BOOLEAN NOT NULL DEFAULT FALSE,
  compliance_tag VARCHAR(128),
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ip_region_map (
  cidr VARCHAR(64) PRIMARY KEY,
  region VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS user_risk_scores (
  user_id VARCHAR(255) PRIMARY KEY,
  risk DOUBLE PRECISION NOT NULL DEFAULT 0.1,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workload_risk_scores (
  workload_id VARCHAR(64) PRIMARY KEY REFERENCES workloads(workload_id),
  risk DOUBLE PRECISION NOT NULL DEFAULT 0.1,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_score_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id VARCHAR(50) NOT NULL,
  policy_mode VARCHAR(32) NOT NULL DEFAULT 'static',
  entity_type VARCHAR(32) NOT NULL,
  entity_id VARCHAR(255) NOT NULL,
  risk DOUBLE PRECISION NOT NULL,
  scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_state (
  scope VARCHAR(32) NOT NULL,
  entity_id VARCHAR(255) NOT NULL,
  template_id VARCHAR(32) NOT NULL,
  theta JSONB NOT NULL DEFAULT '{}'::jsonb,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (scope, entity_id)
);

CREATE TABLE IF NOT EXISTS policy_updates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  scope VARCHAR(32) NOT NULL,
  entity_id VARCHAR(255) NOT NULL,
  from_template VARCHAR(32),
  to_template VARCHAR(32),
  risk DOUBLE PRECISION,
  update_latency_ms DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS adaptive_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id VARCHAR(50) NOT NULL,
  policy_type VARCHAR(32) NOT NULL,
  total_requests INTEGER NOT NULL,
  violations_missed INTEGER NOT NULL,
  violations_blocked INTEGER NOT NULL,
  false_denies INTEGER NOT NULL,
  avg_exposure_seconds DOUBLE PRECISION NOT NULL,
  avg_update_latency_ms DOUBLE PRECISION NOT NULL,
  policy_changes INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS shadow_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id VARCHAR(50) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  resource TEXT NOT NULL,
  action VARCHAR(16) NOT NULL,
  rule VARCHAR(128),
  template_id VARCHAR(32),
  would_block BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO ip_region_map (cidr, region) VALUES
  ('10.0.0.0/8', 'us-east'),
  ('192.168.0.0/16', 'us-west'),
  ('172.16.0.0/12', 'eu-central')
ON CONFLICT (cidr) DO NOTHING;

INSERT INTO workloads (workload_id, tenant_id, account_id, region, sensitivity_label, encrypted, public_exposed, compliance_tag, status) VALUES
  ('tenant-a-w1', 'tenant-a', 'acct-1', 'us-east', 'internal', true, false, 'pci', 'active'),
  ('tenant-a-w2', 'tenant-a', 'acct-1', 'us-west', 'regulated', true, false, 'sox', 'active'),
  ('tenant-b-w1', 'tenant-b', 'acct-2', 'eu-central', 'public', true, true, 'none', 'active'),
  ('tenant-b-w2', 'tenant-b', 'acct-2', 'us-east', 'internal', false, false, 'hipaa', 'active'),
  ('tenant-c-w1', 'tenant-c', 'acct-3', 'us-west', 'regulated', true, false, 'gdpr', 'active'),
  ('tenant-c-w2', 'tenant-c', 'acct-3', 'eu-central', 'internal', true, false, 'none', 'active'),
  ('tenant-d-w1', 'tenant-d', 'acct-4', 'us-east', 'public', true, true, 'none', 'active'),
  ('tenant-d-w2', 'tenant-d', 'acct-4', 'us-east', 'internal', true, false, 'none', 'active'),
  ('tenant-e-w1', 'tenant-e', 'acct-5', 'us-west', 'regulated', false, true, 'pci', 'active'),
  ('tenant-e-w2', 'tenant-e', 'acct-5', 'eu-central', 'internal', true, false, 'none', 'active')
ON CONFLICT (workload_id) DO NOTHING;
