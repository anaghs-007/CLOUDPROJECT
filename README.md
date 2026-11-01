# AC-SCP: Phase 1 — The "Sense" Layer (Telemetry Collection Engine)

Implementation of **Phase 1: Telemetry Collection Engine** for the **Adaptive Context-Aware Service Control Policies (AC-SCP)** framework.

Traditional cloud guardrails are static and fail to adapt to live threats. This engine forms the foundation of the dynamic "Sense-Analyze-Act" loop by logging every API request non-blockingly into PostgreSQL, capturing the exact context tuple:

$$C(t) = (u, a, r, w, g, l, \rho_u(t), \rho_w(t))$$

Where:
- $u$ = Principal (`user_id` extracted from JWT `sub` / `preferred_username` or `x-user-id` header)
- $a$ = Action (HTTP method: `GET`, `POST`, `DELETE`, etc.)
- $r$ = Resource (API endpoint path, e.g. `/api/workload/compute`)
- $w$ = Workload context
- $g$ = Geolocation source (`ip_address`)
- $l$ = Workload sensitivity label (`public`, `internal`, `restricted`)
- $\rho_u(t), \rho_w(t)$ = Temporal risk context derived downstream by the ML risk engine

---

## Deliverables

- **`schema.sql`**: PostgreSQL database DDL creating the `telemetry_logs` table with UUID primary key, timestamp indexes, and UUID extension.
- **`db.js`**: Robust PostgreSQL connection pool (`pg` module) with graceful idle client error handling and `insertTelemetry(entry)` function.
- **`server.js`**: Express backend with `telemetryInterceptor` middleware providing non-blocking asynchronous telemetry logging, JWT extraction, dynamic sensitivity labeling, dummy workload routes, and graceful shutdown handling.
- **`test.js`**: Unit test suite verifying JWT extraction, sensitivity classification, and non-blocking interceptor execution.

---

## Prerequisites & Setup

1. **Node.js**: Ensure Node.js (v18+) is installed.
2. **PostgreSQL**: Ensure PostgreSQL is running.

### 1. Database Initialization

The supported local setup starts PostgreSQL and Keycloak together. PostgreSQL
is not started by the application process.

```powershell
docker compose up -d
docker compose ps
```

The first PostgreSQL start applies `schema.sql`, `baseline_schema.sql`,
`adaptive_schema.sql`, `identity_enforcement.sql`, and `dashboard_schema.sql`.
The dashboard API uses `dashboard_ro` / `dashboard-password` by default; set
`PGPASSWORD_RO` to a different value if you manage PostgreSQL outside Docker.

For a Docker-managed database, the init scripts above already do this. If
you are managing PostgreSQL yourself, run:

```bash
psql -h localhost -p 55432 -U postgres -c "CREATE DATABASE acscp;"
psql -h localhost -p 55432 -U postgres -d acscp -f schema.sql
psql -h localhost -p 55432 -U postgres -d acscp -f baseline_schema.sql
psql -h localhost -p 55432 -U postgres -d acscp -f adaptive_schema.sql
```

### 2. Environment Configuration

Copy `.env.example` to `.env` and set your credentials:

```ini
PGHOST=localhost
PGPORT=55432
PGUSER=postgres
PGPASSWORD=postgres
PGDATABASE=acscp
PORT=3000
POLICY_MODE=adaptive
```

`POLICY_MODE=adaptive` is the default used by the dashboard and enables the
adaptive templates. The static control-group modes (`static`, `static_context`,
and `static_ml`) intentionally reject requests from IP addresses outside the
configured private CIDRs, which includes local loopback (`127.0.0.1`).

For benchmark runs, the API must be started with
`BENCHMARK_MODE_HEADER=true`. This allows each simulator request to select its
declared matrix mode through `X-Policy-Mode`; changing `POLICY_MODE` in the
Python runner alone cannot change an already-running Node process.

### 3. Run the Server

```bash
# Production start
npm start

# Development with hot-reload
npm run dev
```

### 4. Run Unit Tests

```bash
npm test
```

`npm test` includes the Python feature tests. To train the persisted
behavioural models used by the scorer, install `requirements.txt` and run:

```powershell
python risk\train_model.py
python risk\risk_engine.py
```

---

## Cloud Workload API Endpoints

| Method | Endpoint | Sensitivity Label | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/public/status` | `public` | Public health/status probe |
| `POST` | `/api/workload/compute` | `internal` | Internal compute execution |
| `DELETE` | `/api/admin/storage` | `restricted` | Admin-level privileged operation |

---

## Sample Requests

### 1. Public Endpoint
```bash
curl http://localhost:3000/api/public/status
```

### 2. Internal Compute (with `x-user-id` header)
```bash
curl -X POST http://localhost:3000/api/workload/compute \
  -H "Content-Type: application/json" \
  -H "x-user-id: dev_user_42" \
  -d '{"task": "batch-processing"}'
```

### 3. Restricted Endpoint (with Bearer JWT)
```bash
curl -X DELETE http://localhost:3000/api/admin/storage \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbl9hbGljZSJ9.signature"
```
## Phase 2 - Static Control Group

Phase 2 adds a deliberately rigid `STATIC_SCP` policy. It allows only the
private CIDRs in `ALLOWED_CIDRS`, blocks `/api/admin/*` from 22:00 through
06:00, and prevents the `developer` role from using admin paths. It has no
rate, volume, or behavioral rules: exfiltration bursts, low-and-slow activity,
and valid credentials from an allowed IP are intentionally missed. An
unknown external IP is caught by `IP_RANGE`, including for the workload route.

Initialize the Phase 2 tables after the Phase 1 schema:

```bash
psql -U postgres -d acscp -f schema.sql
psql -U postgres -d acscp -f baseline_schema.sql
```

Set these options in `.env` for simulated runs:

```ini
POLICY_MODE=static
SIM_MODE=true
```

`POLICY_MODE=none` bypasses static checks while retaining telemetry. The
`X-Simulated-Time` header is honored only when `SIM_MODE=true`; otherwise the
policy uses the server clock. Roles are read from a decoded JWT `role` claim
or the `X-Role` header used by the simulator.

Run the deterministic concurrent traffic replay:

```bash
python -m pip install -r requirements.txt
python simulate_traffic.py --requests 500 --seed 42 --threat-ratio 0.2
```

The command prints the generated session ID. Aggregate that run:

```bash
node compute_baseline.js <session-id>
```

The aggregation stores one row in `baseline_metrics` and one row per tagged
episode in `attack_episodes`. Static policy never contains a missed attack,
so missed episodes have `contained = false`. Decision latency is measured
inside the policy middleware with `process.hrtime.bigint()`, independently
of network and database write latency.

Verification query for the final baseline numbers:

```sql
SELECT session_id, policy_type, total_requests, violations_detected,
       violations_missed, false_positives, ROUND(avg_latency_ms::numeric, 3)
         AS avg_latency_ms, ROUND(avg_exposure_seconds::numeric, 3)
         AS avg_exposure_seconds, created_at
FROM baseline_metrics
ORDER BY created_at DESC
LIMIT 1;

SELECT episode_id, exposure_seconds, contained
FROM attack_episodes
ORDER BY first_malicious_ts;
```

## Phase 3A+ paper-method extension

### Objective J(theta)

The objective used in the optimizer is:

```text
J(theta) = alpha * V + beta * O - gamma * A
```

- `V`: malicious requests that were allowed
- `O`: legitimate requests incorrectly blocked
- `A`: availability (share of legitimate requests served)

Run the optimizer on validation seed 11 and save the best parameters:

```bash
python theta_optimizer.py
```

This writes `theta_best.json`, which is loaded automatically by the adaptive engine.
The defaults are `alpha=1`, `beta=0.5`, and `gamma=0.2`.

### Staged rollout / shadow mode

`POLICY_MODE=adaptive_shadow` evaluates the adaptive rules without enforcing them,
writing to the `shadow_decisions` table. A pilot tenant gate can be enabled with:

```ini
POLICY_MODE=adaptive_shadow
PILOT_TENANT=tenant-a
```

Pre-deployment validation runs with:

```bash
node validate_templates.js
```

This rejects template sets with duplicates, unreachable allowlists, or conflicting
thresholds such as `tau1 >= tau2`.

### Scenario-based simulator validation

Use the simulator with named scenarios:

```bash
python simulate_traffic.py --scenario insider_threat --requests 200 --seed 42
python simulate_traffic.py --scenario misconfiguration --requests 200 --seed 42
python simulate_traffic.py --scenario workload_migration --requests 200 --seed 42
python simulate_traffic.py --scenario compliance_change --requests 200 --seed 42
```

These scenarios exercise insider threats, misconfigurations, workload migration,
and compliance label changes while preserving the same seeded request stream.

### Ablation modes

The ablation matrix is driven by `POLICY_MODE`:

- `static`: hardcoded static controls only
- `static_context`: region/time/label predicates without ML risk
- `static_ml`: risk thresholds without context predicates
- `adaptive`: full paper method

Run a held-out seed using the same request generator and compare mode outputs.

### Scalability evaluation

Synthetic scales are emulated at 10/25/50/100/200 tenants. The generated benchmark
object can be exported with:

```bash
node export_results.js
```

This writes `benchmark.json` with per-mode violations, exposure samples, risk-score
history, update-latency samples, ablation rows, and scalability rows for Phase 5.

### Verification

```sql
SELECT session_id, policy_type, total_requests, violations_missed,
       violations_blocked, false_denies, avg_exposure_seconds,
       avg_update_latency_ms, policy_changes
FROM adaptive_metrics
ORDER BY created_at DESC
LIMIT 10;

SELECT * FROM shadow_decisions ORDER BY created_at DESC LIMIT 20;
```

## Phase 4 — Keycloak identity-layer enforcement

Phase 4 adds an opt-in identity enforcement path; it does not replace the
Phase 3 API policy. `identity` enables Keycloak verification, revocation, and
the risk-engine quarantine action while leaving the Phase 3 risk-cache
middleware off. `adaptive_identity` enables both layers. The supported modes
are therefore `none`, `static`, `adaptive`, `identity`, and
`adaptive_identity` (plus the existing shadow/ablation modes).

### Start Keycloak

Copy the Phase 4 values from `.env.example` into `.env`, set real local
bootstrap/service credentials, then initialize PostgreSQL and Keycloak:

```bash
psql -U postgres -c "CREATE DATABASE acscp;"
psql -U postgres -d acscp -f schema.sql
psql -U postgres -d acscp -f baseline_schema.sql
psql -U postgres -d acscp -f adaptive_schema.sql
psql -U postgres -d acscp -f identity_enforcement.sql
docker compose up -d keycloak
```

The pinned image imports [keycloak/realm-ac-scp.json](keycloak/realm-ac-scp.json)
with realm `ac-scp-realm`, 60-second access tokens, `alice`, `bob`, `carol`,
and five `sim-user-*` accounts. The API client has direct access grants enabled
for the simulator only. The service-account client is intended only for the
Python risk engine and must be assigned `manage-users`, `view-users`, and
`query-users` under the `realm-management` client roles. Do not expose
Keycloak's development server in production. `start-dev` data lives in the
container; removing the container removes the imported development data.

If Docker is unavailable, run Keycloak 26.x with the same realm JSON import:

```bash
bin/kc.bat start-dev --import-realm
```

### Manual PowerShell smoke test

Copy the Phase 4 block from `.env.example` into `.env` first. The Python
commands now load that file automatically; Node and Compose do so natively.
Run these commands from the repository root in separate terminals:

```powershell
docker compose down
docker compose up -d
do {
  Start-Sleep -Seconds 2
  $ready = try {
    (Invoke-WebRequest `
      http://localhost:8080/realms/ac-scp-realm/.well-known/openid-configuration `
      -UseBasicParsing).StatusCode -eq 200
  } catch { $false }
} until ($ready)

psql -U postgres -c "CREATE DATABASE acscp;" 2>$null
psql -U postgres -d acscp -f schema.sql
psql -U postgres -d acscp -f baseline_schema.sql
psql -U postgres -d acscp -f adaptive_schema.sql
psql -U postgres -d acscp -f identity_enforcement.sql
```

In terminal 1:

```powershell
$env:POLICY_MODE="identity"
$env:REVOCATION_CHECK="backchannel"
npm start
```

In terminal 2:

```powershell
$TOKEN = (Invoke-RestMethod `
  -Uri "http://localhost:8080/realms/ac-scp-realm/protocol/openid-connect/token" `
  -Method POST -ContentType "application/x-www-form-urlencoded" `
  -Body @{ grant_type="password"; client_id="acscp-api"; username="carol"; password="carol-password" }).access_token
Invoke-WebRequest http://localhost:3000/api/admin/storage `
  -Headers @{ Authorization="Bearer $TOKEN" }
```

The response must be `200`. To perform the quarantine action without waiting
for the scorer to accumulate telemetry, use the supported CLI:

```powershell
python keycloak_enforcer.py --user carol --risk 1.0 --action quarantine --session-id smoke-carol
Invoke-WebRequest http://localhost:3000/api/admin/storage `
  -Headers @{ Authorization="Bearer $TOKEN" } -SkipHttpErrorCheck
```

The replay must be `401`. Log in again; the new token must not contain
`admin_access`, and the admin route must be `403`. Restore only after
`N` consecutive scores below `tau2 - delta`; the CLI intentionally does not
bypass that hysteresis.

### Run the identity path

```bash
python -m pip install -r requirements.txt
$env:POLICY_MODE="identity"
npm start

# In another terminal, with the same repository .env:
$env:POLICY_MODE="identity"
python risk\risk_engine.py
python simulate_traffic.py --identity --scenario insider_threat --requests 200 --seed 42
node compute_adaptive_metrics.js <session-id>
node export_results.js
```

Use `POLICY_MODE=adaptive_identity` to compare identity enforcement with the
Phase 3 adaptive API layer. The simulator obtains real direct-grant tokens,
refreshes them when needed, keeps sending the original token after quarantine,
and then attempts a fresh login. `privileged_access_regained` should remain
zero until the hysteresis restore condition is met.

For comparison runs, keep the same seed, request count, scenario, and session
shape while changing only `POLICY_MODE`. `REVOCATION_CHECK=backchannel` is the
default; `introspection` verifies tokens against Keycloak on each request for a
comparison run, and `none` disables the revocation check (signature and expiry
verification still apply). `benchmark.json` contains identity
`enforcement_call_ms` and `time_to_effective_ms` mean/std/p95 values,
per-request token-validation overhead, exposure, and the existing Phase 3
metrics. `t0` is `risk_score_history.scored_at`; `t1` is
`identity_enforcement_events.enforced_at`; `t2` is the first rejected request
recorded in `first_rejected_at`.

The Overview, Violations, Exposure, Risk evolution, Latency, and Operations
tabs read the last completed matrix from `results/benchmark.json` and
`results/stats.json`; they refresh every five seconds. A standalone
`simulate_traffic.py` run updates live PostgreSQL telemetry only and does not
change those aggregate files. Run the full `run_benchmark_matrix.py` command
to regenerate the cards, then leave the dashboard open or refresh it.

Troubleshooting:

- `401 invalid identity token`: verify `KEYCLOAK_ISSUER`, port 8080, and the
  realm import; delete and recreate only the Keycloak container if a previous
  import left stale realm data.
- `403 admin_access role required`: the user has no `admin_access` realm role,
  or a previously issued token predates role restoration; log in again.
- Service-account `403`: assign only `manage-users`, `view-users`, and
  `query-users` in the `realm-management` client roles and verify the service
  client secret in `.env`.
- Missing identity rows: run `identity_enforcement.sql` after the Phase 3
  schemas and confirm the Python process is using the same `.env` and
  PostgreSQL database as the API.

## Phase 5 — Empirical evidence and dashboard

The Phase 5 pipeline never substitutes paper values for measured output.
`results/mock_benchmark.json` is explicitly synthetic and the UI displays a
persistent `MOCK DATA - NOT RESULTS` banner whenever `meta.mock` is true.
Mock data is opt-in. By default the dashboard API requires
`results/benchmark.json` and reports a clear error if real benchmark output is
missing. Set `DASHBOARD_USE_MOCK=true` only for UI development.

Install the analysis dependencies and generate reproducible mock data for UI
development:

```powershell
python -m pip install -r requirements.txt
python run_benchmark_matrix.py --dry-run
```

Run the held-out matrix against a running API, PostgreSQL, and Keycloak stack:

```powershell
$env:BENCHMARK_MODE_HEADER="true"
$env:POLICY_MODE="adaptive"
npm start
```

In another terminal:

```powershell
python run_benchmark_matrix.py `
  --modes none static adaptive identity adaptive_identity `
  --seeds 101 102 103 104 105 106 107 108 109 110 `
  --requests 500
```

Every run resets request-level database/policy state while retaining completed
aggregate rows, clears the local revocation cache, restores Keycloak simulation
identities, writes `results/runs/<mode>-<seed>.json`, and records
`results/benchmark.meta.json`. The runner excludes training and
validation seeds `11` and `42`. Aggregation writes `results/benchmark.json`;
analysis writes `results/stats.json`.

Create the read-only dashboard database role once:

```powershell
psql -U postgres -d acscp -f dashboard_schema.sql
$env:PGUSER_RO="dashboard_ro"
$env:PGPASSWORD_RO="replace-dashboard-ro-password"
```

Start the separate read-only API and React UI:

```powershell
npm run dashboard-api
npm --prefix dashboard-ui install
npm run dashboard-ui
```

Open `http://localhost:5173`. The dashboard API is on port 4000 and exposes
`/dash/benchmark`, `/dash/stats`, `/dash/live/risk`,
`/dash/live/decisions`, `/dash/live/quarantines`, and the two-second
`/dash/live/stream` SSE endpoint. It does not use the telemetry or policy
middleware. CORS is limited to the local dashboard origins.

Each figure caption reports mode, units, sample size, and seeds. Exported
benchmark data contains measured values only; ablation and scalability tabs are
hidden unless supplied in the manifest. Paper reference values should be added
only as a separately labelled, toggleable comparison layer.

Limitations: runs use a local simulated environment, local network and
database latency, direct-grant tokens for testing only, and a small synthetic
tenant population. These measurements do not establish production latency or
generalization.
