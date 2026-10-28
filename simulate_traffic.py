#!/usr/bin/env python3
"""Deterministic traffic simulator for baseline and adaptive policy benchmarking."""
import argparse
import concurrent.futures
import random
import time
import uuid
from collections import defaultdict

import requests

SCENARIOS = [
    "default",
    "insider_threat",
    "misconfiguration",
    "workload_migration",
    "compliance_change",
]


def build_headers(session_id, rng, scenario, threat, index):
    tenant_id = f"tenant-{(index % 5) + 1}"
    account_id = f"acct-{(index % 3) + 1}"
    workload_id = f"tenant-{(index % 5) + 1}-w{(index % 2) + 1}"
    allowed_region = "us-east"
    if scenario == "misconfiguration":
        workload_id = "tenant-a-w2"
        allowed_region = "us-west"
    if scenario == "workload_migration":
        workload_id = "tenant-b-w1"
        allowed_region = "eu-central"
    headers = {
        "X-Session-Id": session_id,
        "X-Sim-Label": "threat" if threat else "normal",
        "X-User-Id": f"sim-user-{index}",
        "X-Role": "admin" if threat else rng.choice(["developer", "analyst"]),
        "X-Tenant-Id": tenant_id,
        "X-Account-Id": account_id,
        "X-Workload-Id": workload_id,
        "X-Region": allowed_region,
        "X-Forwarded-For": rng.choice(["10.1.0.10", "192.168.10.25", "203.0.113.10"]),
    }
    return headers


def build_request(index, rng, session_id, scenario='default', threat=False):
    headers = build_headers(session_id, rng, scenario, threat, index)
    episode = None
    if threat:
        headers['X-Sim-Label'] = 'threat'
        if scenario == 'insider_threat':
            headers['X-Role'] = 'admin'
            headers['X-Region'] = 'eu-central'
            headers['X-Forwarded-For'] = '10.1.0.10'
            headers['X-Simulated-Time'] = '2026-10-27T02:00:00Z'
            headers['X-Episode-Id'] = f'{session_id}-insider'
            method, path = ('GET', '/api/admin/storage')
            episode = headers['X-Episode-Id']
        elif scenario == 'misconfiguration':
            headers['X-Role'] = 'admin'
            headers['X-Region'] = 'eu-central'
            headers['X-Workload-Id'] = 'tenant-a-w2'
            headers['X-Forwarded-For'] = '10.1.0.11'
            headers['X-Simulated-Time'] = '2026-10-27T16:00:00Z'
            headers['X-Episode-Id'] = f'{session_id}-misconfig'
            method, path = ('DELETE', '/api/admin/storage')
            episode = headers['X-Episode-Id']
        elif scenario == 'workload_migration':
            headers['X-Role'] = 'admin'
            headers['X-Region'] = 'us-west'
            headers['X-Workload-Id'] = 'tenant-b-w1'
            headers['X-Simulated-Time'] = '2026-10-27T12:30:00Z'
            headers['X-Episode-Id'] = f'{session_id}-migration'
            method, path = ('POST', '/api/workload/compute')
            episode = headers['X-Episode-Id']
        elif scenario == 'compliance_change':
            headers['X-Role'] = 'admin'
            headers['X-Region'] = 'us-east'
            headers['X-Forwarded-For'] = '10.1.0.12'
            headers['X-Simulated-Time'] = '2026-10-27T13:00:00Z'
            headers['X-Episode-Id'] = f'{session_id}-compliance'
            method, path = ('DELETE', '/api/admin/storage')
            episode = headers['X-Episode-Id']
        else:
            headers['X-Simulated-Time'] = '2026-10-27T14:00:00Z'
            method, path = ('GET', '/api/admin/storage')
            episode = f'{session_id}-threat'
            headers['X-Episode-Id'] = episode
    else:
        headers['X-Simulated-Time'] = '2026-10-27T14:00:00Z'
        method, path = ('GET', '/api/public/status') if rng.random() < 0.5 else ('POST', '/api/workload/compute')

    headers['X-Simulated-Time'] = headers.get('X-Simulated-Time', '2026-10-27T14:00:00Z')
    headers['X-Forwarded-For'] = headers.get('X-Forwarded-For', '10.1.0.10')
    headers['X-Region'] = headers.get('X-Region', 'us-east')
    headers['X-Workload-Id'] = headers.get('X-Workload-Id', 'tenant-a-w1')
    return index, threat, episode, method, path, headers


def send(base_url, request_data):
    index, threat, episode, method, path, headers = request_data
    started = time.perf_counter()
    try:
        resp = requests.request(method, f'{base_url}{path}', headers=headers, timeout=10)
        elapsed = (time.perf_counter() - started) * 1000
        return index, threat, episode, resp.status_code, elapsed
    except requests.RequestException as exc:
        elapsed = (time.perf_counter() - started) * 1000
        return index, threat, episode, 599, elapsed, str(exc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--requests', type=int, default=500)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--threat-ratio', type=float, default=0.2)
    parser.add_argument('--session-id', default=None)
    parser.add_argument('--scenario', default='default', choices=SCENARIOS)
    parser.add_argument('--base-url', default='http://localhost:3000')
    args = parser.parse_args()
    if not 0 <= args.threat_ratio <= 1:
        parser.error('--threat-ratio must be between 0 and 1')

    session_id = args.session_id or f'sim-{uuid.uuid4().hex[:12]}'
    rng = random.Random(args.seed)
    requests_to_send = []
    threat_count = max(1, int(args.requests * args.threat_ratio))
    for idx in range(args.requests):
        threat = idx < threat_count and args.scenario != 'default'
        if args.scenario == 'default':
            threat = rng.random() < args.threat_ratio
        requests_to_send.append(build_request(idx, rng, session_id, args.scenario, threat))

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, args.requests))) as executor:
        results = list(executor.map(lambda item: send(args.base_url, item), requests_to_send))

    episodes = defaultdict(list)
    for result in results:
        if result[2]:
            episodes[result[2]].append(result)
    threats = [result for result in results if result[1]]
    normal = [result for result in results if not result[1]]
    blocked = lambda result: 400 <= result[3] < 500 and result[3] != 404
    blocked_threats = sum(blocked(r) for r in threats)
    missed = sum(1 for r in threats if r[3] < 400 or r[3] == 404)
    avg_latency = sum(float(r[4]) for r in results) / max(1, len(results))
    exposures = []
    for episode_results in episodes.values():
        allowed = [float(r[4]) for r in episode_results if not blocked(r)]
        exposures.append(max(allowed) - min(allowed) if allowed else 0.0)
    print(f'session_id={session_id}')
    print(f'scenario={args.scenario}')
    print(f'total={len(results)} blocked={sum(blocked(r) for r in results)}')
    print(f'allowed_normal={sum((r[3] < 400 or r[3] == 404) for r in normal)} blocked_normal={sum(blocked(r) for r in normal)}')
    print(f'blocked_threats={blocked_threats} MISSED_threats={missed}')
    print(f'avg_latency_ms={avg_latency:.3f}')
    print(f'avg_exposure_per_episode={sum(exposures) / max(1, len(exposures)) / 1000:.3f}s')


if __name__ == '__main__':
    main()
