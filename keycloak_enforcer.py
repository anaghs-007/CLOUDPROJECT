#!/usr/bin/env python3
"""Keycloak identity enforcement for Phase 4.

The class deliberately uses the Keycloak REST API directly so the measured
latencies include the same calls used by the production path.
"""
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

import requests
import psycopg2


class KeycloakEnforcer:
    def __init__(self, session_id=None):
        self.base_url = os.getenv("KEYCLOAK_URL", "http://localhost:8080").rstrip("/")
        self.realm = os.getenv("KEYCLOAK_REALM", "ac-scp-realm")
        self.api_base = f"{self.base_url}/admin/realms/{self.realm}"
        self.token_url = f"{self.base_url}/realms/{self.realm}/protocol/openid-connect/token"
        self.session_id = session_id or os.getenv("SESSION_ID", "system")
        self.http = requests.Session()
        self._service_token = None
        self._service_token_expires_at = 0.0
        self.user_ids = {}
        self.role_ids = {}
        self.restore_samples = defaultdict(list)
        theta_path = os.getenv(
            "THETA_FILE",
            os.path.join(os.path.dirname(__file__), "theta_best.json"),
        )
        try:
            with open(theta_path, encoding="utf-8") as theta_file:
                theta = json.load(theta_file)
        except (OSError, ValueError):
            theta = {}
        self.tau2 = float(theta.get("tau2", 0.8))
        self.delta = float(theta.get("delta", 0.1))
        self.consecutive_scores = int(theta.get("N", 3))
        self.privileged_roles = [
            role.strip()
            for role in os.getenv("KEYCLOAK_PRIVILEGED_ROLES", "admin_access").split(",")
            if role.strip()
        ]
        self._warm_caches()

    def _service_access_token(self):
        now = time.time()
        if self._service_token and now < self._service_token_expires_at - 10:
            return self._service_token
        response = self.http.post(
            self.token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": os.environ["KEYCLOAK_SERVICE_CLIENT_ID"],
                "client_secret": os.environ["KEYCLOAK_SERVICE_CLIENT_SECRET"],
            },
            timeout=float(os.getenv("KEYCLOAK_TIMEOUT_SEC", "5")),
        )
        response.raise_for_status()
        payload = response.json()
        self._service_token = payload["access_token"]
        self._service_token_expires_at = now + int(payload.get("expires_in", 60))
        return self._service_token

    def _request(self, method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._service_access_token()}"
        response = self.http.request(
            method,
            f"{self.api_base}{path}",
            headers=headers,
            timeout=float(os.getenv("KEYCLOAK_TIMEOUT_SEC", "5")),
            **kwargs,
        )
        response.raise_for_status()
        return response

    def _warm_caches(self):
        users = self._request("GET", "/users", params={"max": 1000}).json()
        self.user_ids = {
            user["id"]: user["id"] for user in users if user.get("id")
        }
        self.user_ids.update({
            user["username"]: user["id"] for user in users
            if user.get("username") and user.get("id")
        })
        roles = self._request("GET", "/roles").json()
        self.role_ids = {
            role["name"]: role["id"] for role in roles
            if role.get("name") and role.get("id")
        }

    def _resolve_user_id(self, user_id):
        if user_id in self.user_ids:
            return self.user_ids[user_id]
        users = self._request("GET", "/users", params={"username": user_id, "exact": "true"}).json()
        if not users:
            raise LookupError(f"Keycloak user not found: {user_id}")
        resolved = users[0]["id"]
        self.user_ids[user_id] = resolved
        return resolved

    def _db(self):
        return psycopg2.connect(
            host=os.getenv("PGHOST", "localhost"),
            port=os.getenv("PGPORT", "5432"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres"),
            dbname=os.getenv("PGDATABASE", "acscp"),
        )

    def _insert_event(self, user_id, risk, scored_at, timings, action):
        with self._db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO identity_enforcement_events
                       (session_id, user_id, risk, scored_at, lookup_ms,
                        role_removal_ms, logout_ms, enforcement_call_ms,
                        enforced_at, action)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)""",
                    (
                        self.session_id, user_id, risk, scored_at,
                        timings.get("lookup_ms", 0),
                        timings.get("role_removal_ms", 0),
                        timings.get("logout_ms", 0),
                        timings.get("enforcement_call_ms", 0),
                        action,
                    ),
                )

    def _is_quarantined(self, user_id):
        with self._db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT template_id FROM policy_state WHERE scope = 'identity' AND entity_id = %s",
                    (user_id,),
                )
                row = cur.fetchone()
        return bool(row and row[0] == "KEYCLOAK_QUARANTINED")

    def enforce_identity_quarantine(self, user_id, risk, scored_at):
        if self._is_quarantined(user_id):
            return False
        started = time.perf_counter()
        keycloak_user_id = self._resolve_user_id(user_id)
        lookup_ms = (time.perf_counter() - started) * 1000

        removal_started = time.perf_counter()
        for role_name in self.privileged_roles:
            role_id = self.role_ids.get(role_name)
            if role_id:
                self._request(
                    "DELETE",
                    f"/users/{keycloak_user_id}/role-mappings/realm",
                    json=[{"id": role_id, "name": role_name}],
                )
        role_removal_ms = (time.perf_counter() - removal_started) * 1000

        logout_started = time.perf_counter()
        self._request("POST", f"/users/{keycloak_user_id}/logout")
        logout_ms = (time.perf_counter() - logout_started) * 1000
        timings = {
            "lookup_ms": lookup_ms,
            "role_removal_ms": role_removal_ms,
            "logout_ms": logout_ms,
            "enforcement_call_ms": (time.perf_counter() - started) * 1000,
        }
        with self._db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO policy_state (scope, entity_id, template_id, theta, scored_at)
                       VALUES ('identity', %s, 'KEYCLOAK_QUARANTINED', %s, %s)
                       ON CONFLICT (scope, entity_id) DO UPDATE SET
                         template_id = EXCLUDED.template_id, theta = EXCLUDED.theta,
                         scored_at = EXCLUDED.scored_at, applied_at = NOW()""",
                    (user_id, json.dumps({"tau2": self.tau2, "delta": self.delta, "N": self.consecutive_scores}), scored_at),
                )
        self._insert_event(user_id, risk, scored_at, timings, "QUARANTINE")
        return True

    def restore_identity(self, user_id, risk, scored_at):
        threshold = self.tau2 - self.delta
        if risk >= threshold:
            self.restore_samples[user_id].clear()
            return False
        samples = self.restore_samples[user_id]
        samples.append(float(risk))
        del samples[:-self.consecutive_scores]
        if len(samples) < self.consecutive_scores or not self._is_quarantined(user_id):
            return False
        keycloak_user_id = self._resolve_user_id(user_id)
        started = time.perf_counter()
        roles = [
            {"id": self.role_ids[name], "name": name}
            for name in self.privileged_roles if name in self.role_ids
        ]
        if roles:
            self._request("POST", f"/users/{keycloak_user_id}/role-mappings/realm", json=roles)
        self._request("POST", f"/users/{keycloak_user_id}/logout")
        elapsed = (time.perf_counter() - started) * 1000
        with self._db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE policy_state SET template_id = 'IDENTITY_RESTORED',
                       scored_at = %s, applied_at = NOW() WHERE scope = 'identity' AND entity_id = %s""",
                    (scored_at, user_id),
                )
        self._insert_event(
            user_id, risk, scored_at,
            {"lookup_ms": 0, "role_removal_ms": 0, "logout_ms": elapsed, "enforcement_call_ms": elapsed},
            "RESTORE",
        )
        samples.clear()
        return True


def enforce_identity_quarantine(user_id, risk, scored_at, session_id=None):
    """Convenience entry point used by risk_engine.py."""
    return KeycloakEnforcer(session_id=session_id).enforce_identity_quarantine(user_id, risk, scored_at)


if __name__ == "__main__":
    raise SystemExit("Import KeycloakEnforcer from the risk engine; do not run this module directly.")
