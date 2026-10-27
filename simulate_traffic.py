#!/usr/bin/env python3
"""Replayable Phase 2 traffic generator for the static policy control group."""
import argparse
import concurrent.futures
import random
import time
import uuid
from collections import defaultdict

import requests


def build_request(index, threat, rng, session_id, scenario=None):
    headers = {
        "X-Session-Id": session_id,
        "X-Sim-Label": "threat" if threat else "normal",
        "X-User-Id": f"sim-user-{index}",
        "X-Role": rng.choice(["developer", "analyst"]) if not threat else "admin",
    }
    if not threat:
        method, path = ("GET", "/api/public/status") if rng.random() < 0.5 else (
            "POST", "/api/workload/compute")
        ip = rng.choice(["10.1.0.10", "192.168.10.25"])
        simulated_time = "2026-10-27T14:00:00Z"
        episode = None
    else:
        scenario = scenario or rng.choice(["off-hours", "exfiltration", "external-ip", "low-slow"])
        episode = f"{session_id}-{scenario}"
        if scenario == "off-hours":
            method, path, ip, simulated_time = "DELETE", "/api/admin/storage", "10.1.0.10", "2026-10-27T02:00:00Z"
        elif scenario == "external-ip":
            method, path, ip, simulated_time = "POST", "/api/workload/compute", "203.0.113.10", "2026-10-27T14:00:00Z"
        elif scenario == "exfiltration":
            method, path = rng.choice(
                [("DELETE", "/api/admin/storage"), ("GET", "/api/admin/storage")])
            ip, simulated_time = "10.1.0.10", "2026-10-27T14:00:00Z"
        else:
            method, path, ip, simulated_time = "POST", "/api/workload/compute", "10.1.0.10", "2026-10-27T14:00:00Z"
        headers["X-Episode-Id"] = episode
    headers["X-Forwarded-For"] = ip
    headers["X-Simulated-Time"] = simulated_time
    return index, threat, episode, method, path, headers


def send(base_url, request_data):
    index, threat, episode, method, path, headers = request_data
    started = time.perf_counter()
    try:
        response = requests.request(method, base_url + path, headers=headers, timeout=10)
        return index, threat, episode, response.status_code, (time.perf_counter() - started) * 1000
    except requests.RequestException as error:
        return index, threat, episode, 599, (time.perf_counter() - started) * 1000, str(error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threat-ratio", type=float, default=0.2)
    parser.add_argument("--session-id", default=None)
    parser.add_argument("--base-url", default="http://localhost:3000")
    args = parser.parse_args()
    if not 0 <= args.threat_ratio <= 1:
        parser.error("--threat-ratio must be between 0 and 1")

    session_id = args.session_id or f"sim-{uuid.uuid4().hex[:12]}"
    rng = random.Random(args.seed)
    threat_indexes = [index for index in range(args.requests)
                      if rng.random() < args.threat_ratio]
    rng.shuffle(threat_indexes)
    scenarios = {}
    burst_size = min(40, len(threat_indexes))
    for index in threat_indexes[:burst_size]:
        scenarios[index] = "exfiltration"
    remaining = threat_indexes[burst_size:]
    for offset, index in enumerate(remaining):
        scenarios[index] = ["low-slow", "off-hours", "external-ip"][offset % 3]
    requests_to_send = [
        build_request(index, index in scenarios, rng, session_id, scenarios.get(index))
        for index in range(args.requests)
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, args.requests))) as executor:
        results = list(executor.map(lambda item: send(args.base_url, item), requests_to_send))

    episodes = defaultdict(list)
    for result in results:
        if result[2]:
            episodes[result[2]].append(result)
    threats = [result for result in results if result[1]]
    normal = [result for result in results if not result[1]]
    blocked = lambda result: 400 <= result[3] < 500 and result[3] != 404
    blocked_threats = sum(blocked(result) for result in threats)
    missed_threats = sum(result[3] < 400 or result[3] == 404 for result in threats)
    exposure = []
    for episode_results in episodes.values():
        allowed = [result[4] for result in episode_results if not blocked(result)]
        if allowed:
            exposure.append(max(allowed) - min(allowed))
        else:
            exposure.append(0.0)
    print(f"session_id={session_id}")
    print(f"total={len(results)} blocked={sum(blocked(r) for r in results)}")
    print(f"allowed_normal={sum(r[3] < 400 or r[3] == 404 for r in normal)} "
          f"blocked_normal={sum(blocked(r) for r in normal)}")
    print(f"blocked_threats={blocked_threats} MISSED_threats={missed_threats}")
    print(f"avg_latency_ms={sum(r[4] for r in results) / max(1, len(results)):.3f}")
    print(f"avg_exposure_per_episode={sum(exposure) / max(1, len(exposure)) / 1000:.3f}s")


if __name__ == "__main__":
    main()
