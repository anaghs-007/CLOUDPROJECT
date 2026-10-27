-- Phase 2: static control-group schema. Safe to run after schema.sql.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE telemetry_logs
  ADD COLUMN IF NOT EXISTS role VARCHAR(32),
  ADD COLUMN IF NOT EXISTS decision VARCHAR(10) NOT NULL DEFAULT 'ALLOWED',
  ADD COLUMN IF NOT EXISTS sim_label VARCHAR(10),
  ADD COLUMN IF NOT EXISTS episode_id VARCHAR(50),
  ADD COLUMN IF NOT EXISTS session_id VARCHAR(50),
  ADD COLUMN IF NOT EXISTS decision_latency_ms DOUBLE PRECISION;

ALTER TABLE telemetry_logs
  DROP CONSTRAINT IF EXISTS telemetry_logs_decision_check;
ALTER TABLE telemetry_logs
  ADD CONSTRAINT telemetry_logs_decision_check
  CHECK (decision IN ('ALLOWED', 'BLOCKED'));

CREATE TABLE IF NOT EXISTS baseline_violations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id VARCHAR(255) NOT NULL,
  resource TEXT NOT NULL,
  ip_address VARCHAR(64),
  rule_violated VARCHAR(32) NOT NULL
    CHECK (rule_violated IN ('IP_RANGE', 'RESTRICTED_HOURS', 'ROLE_BOUNDARY')),
  session_id VARCHAR(50),
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS baseline_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id VARCHAR(50) NOT NULL,
  policy_type VARCHAR(32) NOT NULL DEFAULT 'STATIC_SCP',
  total_requests INTEGER NOT NULL,
  violations_detected INTEGER NOT NULL,
  violations_missed INTEGER NOT NULL,
  false_positives INTEGER NOT NULL,
  avg_latency_ms DOUBLE PRECISION NOT NULL,
  avg_exposure_seconds DOUBLE PRECISION NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attack_episodes (
  episode_id VARCHAR(50) PRIMARY KEY,
  session_id VARCHAR(50) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  policy_type VARCHAR(32) NOT NULL DEFAULT 'STATIC_SCP',
  first_malicious_ts TIMESTAMPTZ NOT NULL,
  last_allowed_malicious_ts TIMESTAMPTZ,
  exposure_seconds DOUBLE PRECISION NOT NULL DEFAULT 0,
  contained BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_telemetry_session
  ON telemetry_logs (session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_telemetry_episode
  ON telemetry_logs (episode_id, timestamp);
