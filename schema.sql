-- Phase 1: telemetry schema (Sense layer)
-- Adaptive Context-Aware Service Control Policies (AC-SCP)
-- Context Tuple: C(t) = (u, a, r, w, g, l, rho_u(t), rho_w(t))

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS telemetry_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(255) NOT NULL,       -- principal u
    action VARCHAR(16) NOT NULL,         -- HTTP method, a
    resource TEXT NOT NULL,              -- API endpoint, r
    ip_address VARCHAR(64),              -- source for geolocation g
    sensitivity_label VARCHAR(32) NOT NULL, -- workload label l
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_telemetry_user_time
    ON telemetry_logs (user_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_telemetry_time
    ON telemetry_logs (timestamp DESC);
