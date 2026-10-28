#!/usr/bin/env python3
import json
import os
import time
from collections import defaultdict
from datetime import datetime

import psycopg2

ROOT = os.path.dirname(os.path.dirname(__file__))


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
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM telemetry_logs WHERE timestamp > NOW() - INTERVAL '15 minutes' GROUP BY user_id")
            users = [row[0] for row in cur.fetchall()]
            cur.execute("SELECT workload_id FROM workloads")
            workloads = [row[0] for row in cur.fetchall()]
            for user_id in users:
                risk = default_risk()
                cur.execute("INSERT INTO user_risk_scores (user_id, risk, features, scored_at) VALUES (%s, %s, %s, NOW()) ON CONFLICT (user_id) DO UPDATE SET risk = EXCLUDED.risk, features = EXCLUDED.features, scored_at = NOW()", (user_id, risk, json.dumps({'source': 'baseline'})))
                cur.execute("INSERT INTO risk_score_history (session_id, policy_mode, entity_type, entity_id, risk, scored_at) VALUES (%s, %s, %s, %s, %s, NOW())", ('system', os.getenv('POLICY_MODE', 'static'), 'user', user_id, risk))
            for workload_id in workloads:
                risk = default_risk()
                cur.execute("INSERT INTO workload_risk_scores (workload_id, risk, features, scored_at) VALUES (%s, %s, %s, NOW()) ON CONFLICT (workload_id) DO UPDATE SET risk = EXCLUDED.risk, features = EXCLUDED.features, scored_at = NOW()", (workload_id, risk, json.dumps({'source': 'baseline'})))
                cur.execute("INSERT INTO risk_score_history (session_id, policy_mode, entity_type, entity_id, risk, scored_at) VALUES (%s, %s, %s, %s, %s, NOW())", ('system', os.getenv('POLICY_MODE', 'static'), 'workload', workload_id, risk))
        conn.commit()
    finally:
        conn.close()


def main():
    while True:
        score_active_users_and_workloads()
        time.sleep(int(os.getenv('SCORE_INTERVAL_SEC', '2')))


if __name__ == '__main__':
    main()
