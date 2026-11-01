-- Run once as a PostgreSQL administrator. Keep the password in the local
-- environment, never in this repository.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'dashboard_ro') THEN
    CREATE ROLE dashboard_ro LOGIN PASSWORD 'dashboard-password';
  END IF;
END
$$;
ALTER ROLE dashboard_ro PASSWORD 'dashboard-password';
GRANT CONNECT ON DATABASE acscp TO dashboard_ro;
GRANT USAGE ON SCHEMA public TO dashboard_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dashboard_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO dashboard_ro;
