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

Create the database and run the schema script:

```bash
psql -U postgres -c "CREATE DATABASE acscp;"
psql -U postgres -d acscp -f schema.sql
psql -U postgres -d acscp -f baseline_schema.sql
psql -U postgres -d acscp -f adaptive_schema.sql
```

### 2. Environment Configuration

Copy `.env.example` to `.env` and set your credentials:

```ini
PGHOST=localhost
PGPORT=5432
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
