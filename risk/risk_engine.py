#!/usr/bin/env python3
import json
import os
import sys
import time
from datetime import datetime, timezone

import psycopg2
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def get_connection():
    return psycopg2.connect(
        host=os.getenv('PGHOST', 'localhost'),
        port=os.getenv('PGPORT', '5432'),
        user=os.getenv('PGUSER', 'postgres'),
        password=os.getenv('PGPASSWORD', 'postgres'),
        dbname=os.getenv('PGDATABASE', 'acscp'),
    )


def default_risk():
    return 0.1


def score_active_users_and_workloads():
    """Score user and workload risk using only observable behavioural signals.

    IMPORTANT – label hygiene:
    ``sim_label`` and ``episode_id`` are evaluation-only metadata written by the
    traffic simulator. They are stored in ``telemetry_logs`` so that metrics
    scripts can compute ground-truth violations after a run finishes, but they
    must NEVER appear as inputs to the risk scoring formula. Using them at score
    time would tell the engine who is an attacker (label leakage), making every
    identity-layer measurement invalid.

    Observable behavioural signals used here (all derived from real telemetry):
      - privilege_escalation flag (bool on the telemetry row)
      - sensitivity_label of accessed resources (public / internal / restricted)
      - action (HTTP verb) – DELETE is weighted as more suspicious
      - request volume in the trailing 15-minute window

    These are the same features computed by risk/features.py for the ML scorer.
    """
    mode = os.getenv('POLICY_MODE', 'static')
    enforcer = score_active_users_and_workloads.enforcer
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            # ── USER RISK ─────────────────────────────────────────────────────
            # Inputs: total requests, privilege escalations, sensitive-resource
            # accesses, and DELETE actions – all observable without ground-truth.
            # sim_label / episode_id are deliberately excluded.
            cur.execute("""
                SELECT
                    user_id,
                    COUNT(*)                                                        AS total_requests,
                    COUNT(*) FILTER (WHERE privilege_escalation = TRUE)             AS escalation_count,
                    COUNT(*) FILTER (WHERE sensitivity_label IN ('restricted','regulated'))
                                                                                    AS sensitive_count,
                    COUNT(*) FILTER (WHERE action = 'DELETE')                       AS delete_count
                FROM telemetry_logs
                WHERE timestamp > NOW() - INTERVAL '15 minutes'
                GROUP BY user_id
            """)
            users = cur.fetchall()

            for user_id, total, escalations, sensitive, deletes in users:
                total = max(1, total)
                # Additive risk model (each factor is bounded, sum is capped).
                risk = (
                    default_risk()
                    + min(0.4, float(escalations) * 0.2)
                    + min(0.3, float(sensitive)   / total * 0.3)
                    + min(0.15, float(deletes)    / total * 0.15)
                )
                risk = min(0.95, round(risk, 4))
                features = {
                    'source': 'telemetry_behavioural',
                    'total_requests': total,
                    'escalation_count': int(escalations),
                    'sensitive_count': int(sensitive),
                    'delete_count': int(deletes),
                }
                scored_at = datetime.now(timezone.utc)
                cur.execute(
                    """INSERT INTO user_risk_scores (user_id, risk, features, scored_at)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (user_id) DO UPDATE SET risk = EXCLUDED.risk,
                       features = EXCLUDED.features, scored_at = EXCLUDED.scored_at""",
                    (user_id, risk, json.dumps(features), scored_at),
                )
                cur.execute(
                    """INSERT INTO risk_score_history
                       (session_id, policy_mode, entity_type, entity_id, risk, scored_at)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    ('system', mode, 'user', user_id, risk, scored_at),
                )
                if enforcer:
                    try:
                        if risk >= enforcer.tau2:
                            enforcer.enforce_identity_quarantine(user_id, risk, scored_at)
                        else:
                            enforcer.restore_identity(user_id, risk, scored_at)
                    except (LookupError, psycopg2.Error, requests.RequestException) as error:
                        print(f'[identity] enforcement failed for {user_id}: {error}', flush=True)

            # ── WORKLOAD RISK ─────────────────────────────────────────────────
            cur.execute("SELECT workload_id FROM workloads")
            workloads = [row[0] for row in cur.fetchall()]
            for workload_id in workloads:
                risk = default_risk()
                scored_at = datetime.now(timezone.utc)
                cur.execute(
                    """INSERT INTO workload_risk_scores (workload_id, risk, features, scored_at)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (workload_id) DO UPDATE SET risk = EXCLUDED.risk,
                       features = EXCLUDED.features, scored_at = EXCLUDED.scored_at""",
                    (workload_id, risk, json.dumps({'source': 'baseline'}), scored_at),
                )
                cur.execute(
                    """INSERT INTO risk_score_history
                       (session_id, policy_mode, entity_type, entity_id, risk, scored_at)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    ('system', mode, 'workload', workload_id, risk, scored_at),
                )
        conn.commit()
    finally:
        conn.close()


score_active_users_and_workloads.enforcer = None


def main():
    if os.getenv('POLICY_MODE', 'static') in ('identity', 'adaptive_identity'):
        from keycloak_enforcer import KeycloakEnforcer
        score_active_users_and_workloads.enforcer = KeycloakEnforcer()
    while True:
        score_active_users_and_workloads()
        time.sleep(int(os.getenv('SCORE_INTERVAL_SEC', '2')))


if __name__ == '__main__':
    main()
