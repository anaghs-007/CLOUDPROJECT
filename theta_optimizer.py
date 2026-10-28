#!/usr/bin/env python3
import itertools
import json
import os
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def synthetic_validation_seed(seed=11, n=200):
    rng = random.Random(seed)
    rows = []
    for _ in range(n):
        risk_u = round(rng.random(), 3)
        risk_w = round(rng.random(), 3)
        malicious = rng.random() < 0.35
        legit = rng.random() < 0.65
        rows.append({
            'risk_u': risk_u,
            'risk_w': risk_w,
            'malicious': malicious,
            'legit': legit,
            'served': (not malicious) and legit,
            'blocked': (not legit) or (malicious and risk_u > 0.6),
        })
    return rows


def objective(rows, theta):
    alpha = float(theta.get('alpha', 1.0))
    beta = float(theta.get('beta', 0.5))
    gamma = float(theta.get('gamma', 0.2))
    violations = sum(1 for r in rows if r['malicious'] and r['served'])
    overhead = sum(1 for r in rows if (not r['malicious']) and r['blocked'])
    served = sum(1 for r in rows if (not r['malicious']) and r['served'])
    total_legit = sum(1 for r in rows if not r['malicious'])
    availability = (served / max(1, total_legit)) if total_legit else 1.0
    return (alpha * violations) + (beta * overhead) - (gamma * availability)


def evaluate_candidate(theta):
    rows = synthetic_validation_seed(seed=11)
    return objective(rows, theta)


def choose_best():
    candidates = []
    for tau1 in [0.4, 0.5, 0.6]:
        for tau2 in [0.7, 0.8, 0.9]:
            for tau_w in [0.4, 0.6, 0.8]:
                for delta in [0.05, 0.1, 0.2]:
                    for n in [2, 3, 5]:
                        theta = {'tau1': tau1, 'tau2': tau2, 'tau_w': tau_w, 'delta': delta, 'N': n, 'alpha': 1, 'beta': 0.5, 'gamma': 0.2}
                        candidates.append((theta, evaluate_candidate(theta)))
    best_theta, _ = min(candidates, key=lambda item: item[1])
    return best_theta


def main():
    best = choose_best()
    out = ROOT / 'theta_best.json'
    out.write_text(json.dumps(best, indent=2), encoding='utf-8')
    print(json.dumps(best, indent=2))
    print(f'Wrote {out}')


if __name__ == '__main__':
    main()
