-- Phase 4: identity-layer enforcement and Keycloak latency telemetry.
ALTER TABLE adaptive_metrics ALTER COLUMN policy_type TYPE VARCHAR(50);
ALTER TABLE telemetry_logs
  ADD COLUMN IF NOT EXISTS identity_validation_ms DOUBLE PRECISION;

CREATE TABLE IF NOT EXISTS identity_enforcement_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id VARCHAR(50),
  user_id VARCHAR(255) NOT NULL,
  risk DOUBLE PRECISION NOT NULL,
  scored_at TIMESTAMPTZ NOT NULL,
  lookup_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
  role_removal_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
  logout_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
  enforcement_call_ms DOUBLE PRECISION NOT NULL DEFAULT 0,
  enforced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  first_rejected_at TIMESTAMPTZ,
  time_to_effective_ms DOUBLE PRECISION,
  action VARCHAR(10) NOT NULL CHECK (action IN ('QUARANTINE', 'RESTORE'))
);

CREATE INDEX IF NOT EXISTS idx_identity_events_user_time
  ON identity_enforcement_events (user_id, enforced_at DESC);
CREATE INDEX IF NOT EXISTS idx_identity_events_session
  ON identity_enforcement_events (session_id, enforced_at DESC);
