# AC-SCP Complete Execution Guide

This guide is the end-to-end procedure for running AC-SCP locally on Windows.
Run commands from `D:\CLOUDPROJECT` unless stated otherwise.

## 1. What AC-SCP does

AC-SCP collects API telemetry, scores user and workload risk, applies static
or adaptive policies, optionally quarantines identities through Keycloak, and
measures how quickly enforcement becomes effective.

The Phase 5 dashboard displays only completed benchmark output. It must not be
used for conclusions until `results\benchmark.json` contains complete runs and
`results\stats.json` has been generated from it.

## 2. Required software

Install and verify:

```powershell
node --version
python --version
psql --version
docker --version
docker compose version
```

Use Node.js 18 or newer. PostgreSQL, Docker Desktop, and Python 3.13 are
supported by the current project setup.

## 3. Install dependencies

```powershell
cd D:\CLOUDPROJECT
npm install
npm --prefix dashboard-ui install
python -m pip install -r requirements.txt
```

## 4. Configure environment variables

Create the local environment file:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set real local values in `.env`:

```ini
PGHOST=localhost
PGPORT=55432
PGUSER=postgres
PGPASSWORD=your-postgres-password
PGDATABASE=acscp

PORT=3000
POLICY_MODE=adaptive

KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=your-keycloak-admin-password
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=ac-scp-realm
KEYCLOAK_SERVICE_CLIENT_SECRET=your-service-client-secret
REVOCATION_CHECK=backchannel

# Only true when running the benchmark matrix.
BENCHMARK_MODE_HEADER=false

# Keep false for real dashboard results.
DASHBOARD_USE_MOCK=false
```

Never commit `.env`, passwords, client secrets, or access tokens.

## 5. Initialize PostgreSQL

Create the database. If it already exists, continue:

```powershell
psql -U postgres -c "CREATE DATABASE acscp;"
```

Apply all schemas:

```powershell
psql -U postgres -d acscp -f schema.sql
psql -U postgres -d acscp -f baseline_schema.sql
psql -U postgres -d acscp -f adaptive_schema.sql
psql -U postgres -d acscp -f identity_enforcement.sql
```

Create the read-only dashboard role:

```powershell
psql -U postgres -d acscp -f dashboard_schema.sql
```

Set the dashboard role password in PostgreSQL and use the same value when
starting the dashboard API:

```powershell
$env:PGUSER_RO="dashboard_ro"
$env:PGPASSWORD_RO="your-dashboard-readonly-password"
```

## 6. Start PostgreSQL and Keycloak

```powershell
cd D:\CLOUDPROJECT
docker compose down
docker compose up -d
```

This starts both PostgreSQL (`localhost:55432`) and Keycloak
(`localhost:8080`). The PostgreSQL init scripts create the `acscp` database,
all tables, and the `dashboard_ro` read-only role with password
`dashboard-password` on a fresh Docker volume. If the volume already exists,
apply changed SQL manually or recreate only the named `postgres-data` volume.

Wait for the imported realm, not `/health/ready`:

```powershell
do {
  Start-Sleep -Seconds 2
  try {
    $ready = (Invoke-WebRequest `
      http://localhost:8080/realms/ac-scp-realm/.well-known/openid-configuration `
      -UseBasicParsing).StatusCode -eq 200
  } catch {
    $ready = $false
  }
} until ($ready)

Write-Host "Keycloak realm is ready"
```

The realm is `ac-scp-realm`. The imported users include `alice`, `bob`, `carol`,
and `sim-user-0` through `sim-user-4`.

## 7. Run the application tests

```powershell
cd D:\CLOUDPROJECT
npm test
npm test --prefix dashboard-api
npm test --prefix dashboard-ui
```

Do not continue if these fail. Fix the reported error first.

## 8. Start the main API

Open Terminal 1:

```powershell
cd D:\CLOUDPROJECT
$env:BENCHMARK_MODE_HEADER="true"
$env:POLICY_MODE="none"
$env:REVOCATION_CHECK="backchannel"
npm start
```

Keep this terminal open for the entire benchmark.

Verify the API:

```powershell
Invoke-WebRequest `
  http://localhost:3000/api/public/status `
  -UseBasicParsing
```

Expected status: `200`.

`BENCHMARK_MODE_HEADER=true` is required because the matrix contains several
policy modes while one Node process serves the requests. The simulator sends
the current mode using `X-Policy-Mode`.

## 9. Optional identity smoke test

Get Carol's token:

```powershell
$TOKEN = (Invoke-RestMethod `
  -Uri "http://localhost:8080/realms/ac-scp-realm/protocol/openid-connect/token" `
  -Method POST `
  -ContentType "application/x-www-form-urlencoded" `
  -Body @{
    grant_type="password"
    client_id="acscp-api"
    username="carol"
    password="carol-password"
  }).access_token
```

Call the protected route:

```powershell
Invoke-WebRequest `
  http://localhost:3000/api/admin/storage `
  -Headers @{ Authorization="Bearer $TOKEN" } `
  -UseBasicParsing
```

Quarantine Carol:

```powershell
python keycloak_enforcer.py `
  --user carol `
  --risk 1.0 `
  --action quarantine `
  --session-id smoke-carol
```

Replay the old token. It should be rejected:

```powershell
Invoke-WebRequest `
  http://localhost:3000/api/admin/storage `
  -Headers @{ Authorization="Bearer $TOKEN" } `
  -SkipHttpErrorCheck `
  -UseBasicParsing
```

Expected status: `401`.

## 10. Run a single simulator check

Use this before the full matrix:

```powershell
cd D:\CLOUDPROJECT
python simulate_traffic.py `
  --requests 50 `
  --seed 101 `
  --scenario insider_threat `
  --session-id smoke-101 `
  --base-url http://localhost:3000
```

The output should report `total=50`. If it reports connection failures, stop
and restart the main API before proceeding.

## 11. Run the real benchmark matrix

Open Terminal 2:

```powershell
cd D:\CLOUDPROJECT

python run_benchmark_matrix.py `
  --modes none static adaptive identity adaptive_identity `
  --seeds 101 102 103 104 105 106 107 108 109 110 `
  --requests 500
```

Do not add `--dry-run`. That option creates synthetic mock data.

The runner:

1. Checks the API and Keycloak realm.
2. Resets request-level state for each run.
3. Preserves completed aggregate rows.
4. Clears revocation state.
5. Restores Keycloak simulation identities.
6. Runs 50 mode/seed combinations.
7. Flushes asynchronous telemetry writes.
8. Aggregates each run.
9. Rejects incomplete request counts or missing seeds.
10. Writes `results\benchmark.json` only after a complete matrix.
11. Writes `results\stats.json` after successful analysis.

If the command fails, do not run the dashboard. Read the first error in the
benchmark terminal and fix that service or configuration issue.

## 12. Validate the real benchmark

Run these commands only after the matrix exits successfully:

```powershell
Test-Path results\benchmark.json
Test-Path results\stats.json
```

Both must return `True`.

Check that every mode has 10 runs:

```powershell
python -c "import json; d=json.load(open('results/benchmark.json')); print({m: len(v['runs']) for m,v in d['modes'].items()})"
```

Expected:

```text
{'none': 10, 'static': 10, 'adaptive': 10, 'identity': 10, 'adaptive_identity': 10}
```

Check that every run contains exactly 500 requests:

```powershell
python -c "import json; d=json.load(open('results/benchmark.json')); print(sorted(set(r['total_requests'] for m in d['modes'].values() for r in m['runs'])))"
```

Expected:

```text
[500]
```

Check that the data is real:

```powershell
Select-String results\benchmark.json -Pattern '"mock": false'
Select-String results\stats.json -Pattern '"mock": false'
```

If any check fails, delete the invalid generated files and rerun the matrix:

```powershell
Remove-Item results\benchmark.json, results\stats.json -Force -ErrorAction SilentlyContinue
```

## 13. Start the dashboard API

Open Terminal 3:

```powershell
cd D:\CLOUDPROJECT
$env:PGUSER_RO="dashboard_ro"
$env:PGPASSWORD_RO="your-dashboard-readonly-password"
$env:DASHBOARD_USE_MOCK="false"
npm run dashboard-api
```

Verify the API:

```powershell
Invoke-RestMethod http://localhost:4000/health
Invoke-RestMethod http://localhost:4000/dash/benchmark |
  Select-Object -ExpandProperty meta
```

The benchmark metadata must show:

```text
mock : False
```

## 14. Start the React dashboard

Open Terminal 4:

```powershell
cd D:\CLOUDPROJECT
npm run dashboard-ui
```

Open:

```text
http://localhost:5173
```

The banner `MOCK DATA - NOT RESULTS` must not appear for real benchmark data.

## 15. What to record

For each experiment, save:

### Environment

```powershell
git rev-parse HEAD
node --version
python --version
psql --version
docker --version
docker images quay.io/keycloak/keycloak
```

Record:

- Git commit
- Operating system and CPU
- Node and Python versions
- PostgreSQL version
- Keycloak version
- Docker version
- Timestamp

### Configuration

Record:

- Policy modes
- Seeds
- Requests per run
- Scenario
- `REVOCATION_CHECK`
- Token lifespan
- `tau1`, `tau2`, `tau_w`
- `delta`
- Hysteresis `N`

Never record secrets or tokens.

### Per-run metrics

Record from `results\benchmark.json`:

- `total_requests`
- `violations_missed`
- `violations_blocked`
- `false_denies`
- `policy_changes`
- `validation_overhead_ms`
- Exposure samples
- Update latency samples
- Enforcement latency samples
- Time-to-effective samples

### Identity timing

For each quarantine event, record:

- `scored_at` (`t0`)
- `enforced_at` (`t1`)
- `lookup_ms`
- `role_removal_ms`
- `logout_ms`
- `enforcement_call_ms`
- `first_rejected_at` (`t2`)
- `time_to_effective_ms` (`t2 - t0`)

### Screenshots

Capture:

1. Normal request allowed.
2. Risk crossing `tau2`.
3. Keycloak quarantine.
4. Old token rejected.
5. Fresh login denied privileged access.
6. Dashboard overview without the mock banner.
7. Violations chart.
8. Exposure chart.
9. Latency chart.
10. Risk evolution markers.
11. Live monitor.

## 16. Interpretation requirements

Compare modes using measured values only:

- Missed threats
- Blocked threats
- False denies
- Exposure duration
- API policy update latency
- Keycloak enforcement latency
- Time to effective rejection
- Token validation overhead
- Policy churn
- Confidence intervals
- Sample size and seeds

Do not claim that identity enforcement is faster or better before comparing its
measured results against the same seeded traffic under the other modes.

## 17. Troubleshooting

### `benchmark.json` does not exist

The matrix did not complete. Keep the API running, read the first benchmark
error, fix it, and rerun the matrix. The dashboard cannot show real results
without this file.

### `stats.json` does not exist

Run:

```powershell
python analyze_results.py
```

It will reject incomplete benchmark data instead of creating misleading stats.

### Counts are below 500

Do not use the output. Delete generated exports and rerun:

```powershell
Remove-Item results\benchmark.json, results\stats.json -Force -ErrorAction SilentlyContinue
```

The runner now flushes pending telemetry before aggregation.

### `WinError 10048`

Stop duplicate Node processes and start one API only:

```powershell
Get-NetTCPConnection -LocalPort 3000 -State Listen
Stop-Process -Id <PID> -Force
```

Then restart the API and rerun the matrix.

### Keycloak `404 /health/ready`

Use realm discovery instead:

```text
http://localhost:8080/realms/ac-scp-realm/.well-known/openid-configuration
```

### `401 invalid identity token`

Check Keycloak, issuer, realm, token expiry, and `KEYCLOAK_ISSUER`.

### `403 admin_access role required`

Obtain a new token after restoring or changing roles. Existing tokens do not
automatically gain newly assigned roles.

### Dashboard shows mock data

Set:

```powershell
$env:DASHBOARD_USE_MOCK="false"
```

Ensure `results\benchmark.json` exists and contains:

```json
"mock": false
```

Then restart the dashboard API and refresh the browser.
