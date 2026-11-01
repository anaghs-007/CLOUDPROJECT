#!/usr/bin/env python3
"""AC-SCP Phase 5: Reproducible Benchmark Matrix Runner.

Executes test matrix across all experimental modes and seeds:
- Modes: none, static, adaptive, identity, adaptive_identity (and ablation modes)
- Seeds: configurable held-out seeds (excludes training seeds 11 and 42)
- State Reset: TRUNCATES telemetry/policy/risk tables, restores Keycloak roles,
  clears memory revocations via /internal/clear-revocations.
- Records per-run JSONs to results/runs/{session_id}.json
- Triggers export_results.js to aggregate into results/benchmark.json
"""

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
RESULTS_DIR = ROOT / "results"
RUNS_DIR = RESULTS_DIR / "runs"

DEFAULT_SEEDS = [101, 102, 103, 104, 105, 106, 107, 108, 109, 110]
ALL_MODES = ["none", "static", "adaptive", "identity", "adaptive_identity", "static_context", "static_ml"]
CORE_MODES = ["none", "static", "adaptive", "identity", "adaptive_identity"]


def get_git_commit():
    """Retrieve current git commit hash."""
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(ROOT), stderr=subprocess.DEVNULL)
        return out.decode("utf-8").strip()
    except Exception:
        return "unknown"


def get_hardware_info():
    """Retrieve OS and hardware summary string."""
    return f"{platform.system()} {platform.release()} / {platform.machine()} / {platform.processor() or 'CPU'}"


def load_theta():
    """Load theta parameters from theta_best.json."""
    theta_file = ROOT / "theta_best.json"
    if theta_file.exists():
        try:
            with open(theta_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"tau1": 0.4, "tau2": 0.7, "tau_w": 0.4, "delta": 0.05, "N": 2, "alpha": 1, "beta": 0.5, "gamma": 0.2}


def get_db_connection():
    """Connect to PostgreSQL database."""
    return psycopg2.connect(
        host=os.getenv("PGHOST", "localhost"),
        port=int(os.getenv("PGPORT", "5432")),
        user=os.getenv("PGUSER", "postgres"),
        password=os.getenv("PGPASSWORD", "postgres"),
        dbname=os.getenv("PGDATABASE", "acscp"),
    )


def reset_database(session_id):
    """Reset per-run state while retaining completed benchmark aggregates."""
    tables_to_truncate = [
        "telemetry_logs",
        "baseline_violations",
        "shadow_decisions",
        "user_risk_scores",
        "workload_risk_scores",
        "policy_state",
        "policy_updates",
    ]
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            for table in ("identity_enforcement_events", "attack_episodes",
                          "adaptive_metrics", "baseline_metrics", "risk_score_history"):
                cur.execute(f"DELETE FROM {table} WHERE session_id = %s;", (session_id,))
            for table in tables_to_truncate:
                cur.execute(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE;")
        conn.commit()
        conn.close()
        print("  [db] Reset current run state; retained completed benchmark aggregates.")
    except Exception as e:
        print(f"  [db-warn] Database reset skipped or failed: {e}")


def reset_revocation_cache(base_url="http://localhost:3000"):
    """Call /internal/clear-revocations to clear the server token revocation set."""
    try:
        resp = requests.post(f"{base_url}/internal/clear-revocations", timeout=2)
        if resp.status_code == 200:
            print("  [server] In-memory revocation cache cleared.")
    except Exception as e:
        print(f"  [server-warn] Revocation reset endpoint unreachable: {e}")


def flush_telemetry(base_url, timeout=30):
    """Wait until asynchronous telemetry inserts and decision updates finish."""
    try:
        response = requests.post(f"{base_url}/internal/flush-telemetry", timeout=timeout)
        response.raise_for_status()
    except Exception as exc:
        raise RuntimeError(f"Telemetry flush failed at {base_url}: {exc}") from exc


def reset_keycloak_quarantines():
    """Restore privileged roles and clear active sessions in Keycloak."""
    try:
        from keycloak_enforcer import KeycloakEnforcer
        enforcer = KeycloakEnforcer()
        # Restore carol and simulation users
        test_users = ["carol", "sim-user-0", "sim-user-1", "sim-user-2", "sim-user-3", "sim-user-4"]
        for user in test_users:
            try:
                enforcer.reset_identity(user)
            except Exception:
                pass
        print("  [keycloak] Keycloak test identities restored.")
    except Exception as e:
        print(f"  [keycloak-warn] Keycloak identity reset skipped: {e}")


def check_prerequisites(modes, base_url):
    """Fail before a matrix run if its required services are unavailable."""
    try:
        response = requests.get(f"{base_url}/api/public/status", timeout=3)
        response.raise_for_status()
    except Exception as exc:
        raise RuntimeError(
            f"API is not reachable at {base_url}. Start npm start before running the matrix: {exc}"
        ) from exc

    if any(mode in ("identity", "adaptive_identity") for mode in modes):
        keycloak_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
        realm = os.getenv("KEYCLOAK_REALM", "ac-scp-realm")
        try:
            response = requests.get(
                f"{keycloak_url}/realms/{realm}/.well-known/openid-configuration",
                timeout=3,
            )
            response.raise_for_status()
        except Exception as exc:
            raise RuntimeError(
                f"Keycloak realm discovery is unavailable at {keycloak_url}/realms/{realm}. "
                "Start docker compose and wait for the realm import before "
                f"running identity modes: {exc}"
            ) from exc


def run_single_benchmark(mode, seed, requests_count, base_url):
    """Execute one simulation run for a given mode and seed."""
    session_id = f"{mode}-{seed}"
    print(f"\n>> Running session: {session_id} (Mode: {mode}, Seed: {seed}, Requests: {requests_count})")

    # Step A: Reset State
    reset_database(session_id)
    reset_revocation_cache(base_url)
    if mode in ("identity", "adaptive_identity"):
        reset_keycloak_quarantines()

    # Step B: Set server policy mode via environment or headers
    sim_cmd = [
        sys.executable,
        str(ROOT / "simulate_traffic.py"),
        "--requests", str(requests_count),
        "--seed", str(seed),
        "--session-id", session_id,
        "--base-url", base_url,
    ]
    if mode in ("identity", "adaptive_identity"):
        sim_cmd.append("--identity")

    # Pass POLICY_MODE in subprocess environment
    env = os.environ.copy()
    env["POLICY_MODE"] = mode
    env["BENCHMARK_MODE_HEADER"] = "true"
    env["SESSION_ID"] = session_id

    # Execute simulation
    start_time = time.perf_counter()
    res = subprocess.run(
        sim_cmd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    sim_duration = time.perf_counter() - start_time
    print(f"  Simulation completed in {sim_duration:.2f}s (Exit code: {res.returncode})")
    if res.returncode != 0:
        raise RuntimeError(f"Simulation failed for {session_id}:\n{res.stderr[-2000:]}")

    # Step C: Aggregate metrics into database
    flush_telemetry(base_url)
    if mode == "static":
        aggregate = subprocess.run(
            ["node", str(ROOT / "compute_baseline.js"), session_id],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    else:
        aggregate = subprocess.run(
            ["node", str(ROOT / "compute_adaptive_metrics.js"), session_id],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    if aggregate.returncode != 0:
        raise RuntimeError(f"Metric aggregation failed for {session_id}:\n{aggregate.stderr[-2000:]}")

    # Step D: Save run JSON
    run_output = {
        "session_id": session_id,
        "mode": mode,
        "seed": seed,
        "requests": requests_count,
        "duration_seconds": sim_duration,
        "stdout": res.stdout,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    run_file = RUNS_DIR / f"{session_id}.json"
    with open(run_file, "w", encoding="utf-8") as f:
        json.dump(run_output, f, indent=2)

    return run_output


def main():
    parser = argparse.ArgumentParser(description="AC-SCP Phase 5 Benchmark Matrix Runner")
    parser.add_argument("--modes", nargs="+", default=CORE_MODES, choices=ALL_MODES)
    parser.add_argument("--seeds", nargs="+", type=int, default=DEFAULT_SEEDS)
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--base-url", default="http://localhost:3000")
    parser.add_argument("--dry-run", action="store_true", help="Generate mock benchmark instead of live execution")
    args = parser.parse_args()

    # Guard against using training seeds in held-out benchmark
    forbidden_seeds = {11, 42}
    valid_seeds = [s for s in args.seeds if s not in forbidden_seeds]
    if len(valid_seeds) < len(args.seeds):
        print(f"Notice: Excluded training/validation seeds {forbidden_seeds} from test matrix.")

    if args.dry_run:
        print("Dry run requested: generating results/mock_benchmark.json and stats.json...")
        subprocess.run(["node", str(ROOT / "generate_mock_data.js")], check=True)
        subprocess.run([
            sys.executable,
            str(ROOT / "analyze_results.py"),
            "--input",
            str(RESULTS_DIR / "mock_benchmark.json"),
            "--allow-mock",
        ], check=True)
        print("[OK] Dry run complete: mock data and stats ready.")
        return

    manifest = {
        "git_commit": get_git_commit(),
        "seeds": valid_seeds,
        "requests_per_run": args.requests,
        "theta": load_theta(),
        "keycloak_version": "26.3.2",
        "access_token_lifespan": int(os.getenv("KEYCLOAK_ACCESS_TOKEN_LIFESPAN_SEC", "60")),
        "revocation_check_mode": os.getenv("REVOCATION_CHECK", "backchannel"),
        "hardware_os": get_hardware_info(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mock": False,
    }

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_DIR / "benchmark.meta.json", "w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=2)

    print("=== AC-SCP Benchmark Matrix Runner ===")
    print(f"Modes: {args.modes}")
    print(f"Seeds ({len(valid_seeds)}): {valid_seeds}")
    print(f"Requests per run: {args.requests}")
    print(f"Git commit: {manifest['git_commit']}")
    print(f"Hardware: {manifest['hardware_os']}\n")

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    check_prerequisites(args.modes, args.base_url)

    completed_runs = 0
    for mode in args.modes:
        for seed in valid_seeds:
            try:
                run_single_benchmark(mode, seed, args.requests, args.base_url)
                completed_runs += 1
            except Exception as exc:
                raise RuntimeError(f"Benchmark matrix stopped at {mode}-{seed}: {exc}") from exc

    if completed_runs == 0:
        raise RuntimeError("No benchmark runs completed; benchmark.json was not generated.")

    # Aggregate all runs using export_results.js
    print("\n[export] Aggregating benchmark matrix into results/benchmark.json...")
    try:
        subprocess.run(["node", str(ROOT / "export_results.js")], check=True)
        print("[export] Running statistical analysis...")
        subprocess.run([sys.executable, str(ROOT / "analyze_results.py")], check=True)
        print("[OK] Benchmark matrix and statistical analysis complete.")
    except Exception as exc:
        print(f"Export or analysis failed: {exc}")


if __name__ == "__main__":
    main()
