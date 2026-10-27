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
```

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
