#!/usr/bin/env python3
import json
import os
import pickle
import sys
import time
from datetime import datetime, timezone

import psycopg2
import requests
from dotenv import load_dotenv
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from risk.features import compute_user_features, compute_workload_features

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))


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


USER_FEATURE_ORDER = (
    'api_diversity', 'outside_baseline_api_share', 'hour_deviation',
    'region_deviation', 'privilege_escalation_count', 'sensitive_access_ratio',
    'peak_requests_per_min',
)
WORKLOAD_FEATURE_ORDER = (
    'storage_access_rate', 'inter_region_share', 'config_change_count',
    'misconfig_flags', 'sensitivity_weight', 'incident_count',
)
_model_cache = {}


def _trained_risk(model_name, features, feature_order):
    if model_name not in _model_cache:
        model_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            f'{model_name}_model.pkl',
        )
        try:
            with open(model_path, 'rb') as handle:
                _model_cache[model_name] = pickle.load(handle)
        except FileNotFoundError:
            _model_cache[model_name] = False
    model = _model_cache[model_name]
    if model:
        return round(float(model.predict_proba([[
            features[name] for name in feature_order
        ]])[0][1]), 4)
    return None


def score_user_features(features):
    trained = _trained_risk('user', features, USER_FEATURE_ORDER)
    if trained is not None:
        return min(0.95, trained)
    return min(
        0.95,
        round(
            0.05
            + min(0.25, features['privilege_escalation_count'] * 0.2)
            + features['sensitive_access_ratio'] * 0.3
            + features['outside_baseline_api_share'] * 0.2
            + features['region_deviation'] * 0.1
            + min(0.1, features['peak_requests_per_min'] / 20),
            4,
        ),
    )


def score_workload_features(features):
    trained = _trained_risk('workload', features, WORKLOAD_FEATURE_ORDER)
    if trained is not None:
        return min(0.95, trained)
    return min(
        0.95,
        round(
            0.05
            + features['storage_access_rate'] * 0.2
            + features['inter_region_share'] * 0.15
            + min(0.25, features['config_change_count'] * 0.2)
            + min(0.25, features['misconfig_flags'] * 0.15)
            + features['sensitivity_weight'] * 0.2
            + min(0.1, features['incident_count'] * 0.1),
            4,
        ),
    )


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
                SELECT user_id, action, resource, region, sensitivity_label,
                       privilege_escalation, effective_ts
                FROM telemetry_logs
                WHERE timestamp > NOW() - INTERVAL '15 minutes'
            """)
            user_rows = {}
            for row in cur.fetchall():
                user_rows.setdefault(row[0], []).append({
                    'user_id': row[0], 'action': row[1], 'resource': row[2],
                    'region': row[3], 'sensitivity_label': row[4],
                    'privilege_escalation': row[5], 'effective_ts': row[6],
                })

            for user_id, rows in user_rows.items():
                features = compute_user_features(rows)
                risk = score_user_features(features)
                features = {
                    'source': 'telemetry_behavioural',
                    **features,
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
            cur.execute("SELECT workload_id, encrypted, public_exposed, sensitivity_label FROM workloads")
            workloads = cur.fetchall()
            for workload_id, encrypted, public_exposed, sensitivity_label in workloads:
                cur.execute("""
                    SELECT action, resource, region, sensitivity_label,
                           privilege_escalation, decision, sim_label, effective_ts
                    FROM telemetry_logs
                    WHERE workload_id = %s AND timestamp > NOW() - INTERVAL '15 minutes'
                """, (workload_id,))
                rows = [
                    {
                        'action': row[0], 'resource': row[1], 'region': row[2],
                        'privilege_escalation': row[4], 'decision': row[5],
                        'sim_label': row[6], 'effective_ts': row[7],
                        'encrypted': encrypted, 'public_exposed': public_exposed,
                        'sensitivity_label': row[3] or sensitivity_label,
                    }
                    for row in cur.fetchall()
                ]
                features = compute_workload_features(rows)
                risk = score_workload_features(features)
                scored_at = datetime.now(timezone.utc)
                cur.execute(
                    """INSERT INTO workload_risk_scores (workload_id, risk, features, scored_at)
                       VALUES (%s, %s, %s, %s)
                       ON CONFLICT (workload_id) DO UPDATE SET risk = EXCLUDED.risk,
                       features = EXCLUDED.features, scored_at = EXCLUDED.scored_at""",
                    (workload_id, risk, json.dumps({
                        'source': 'telemetry_behavioural', **features
                    }), scored_at),
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
