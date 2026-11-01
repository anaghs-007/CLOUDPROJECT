#!/usr/bin/env python3
"""Statistical analysis engine for AC-SCP Phase 5 empirical evaluation.

Computes descriptive statistics (mean, std, median, p95, bootstrap 95% CI),
pairwise non-parametric hypothesis testing (Mann-Whitney U), effect sizes
(Cliff's delta), and percentage reduction confidence intervals.
Produces results/stats.json consumed by the research dashboard.
"""

import argparse
import json
import os
import sys
from pathlib import Path

import numpy as np
import scipy.stats as stats

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"


def bootstrap_ci(values, stat_func=np.mean, n_boot=2000, alpha=0.05, seed=42):
    """Compute non-parametric bootstrap confidence interval."""
    arr = np.asarray(values, dtype=float)
    if len(arr) == 0:
        return [0.0, 0.0]
    if len(arr) == 1:
        return [float(arr[0]), float(arr[0])]

    rng = np.random.default_rng(seed)
    boot_indices = rng.choice(len(arr), size=(n_boot, len(arr)), replace=True)
    boot_stats = np.array([stat_func(arr[idx]) for idx in boot_indices])
    low = float(np.percentile(boot_stats, 100 * (alpha / 2.0)))
    high = float(np.percentile(boot_stats, 100 * (1.0 - alpha / 2.0)))
    return [round(low, 3), round(high, 3)]


def bootstrap_reduction_ci(base_values, target_values, n_boot=2000, alpha=0.05, seed=42):
    """Compute bootstrap CI for percentage reduction: (base - target) / base * 100."""
    base_arr = np.asarray(base_values, dtype=float)
    target_arr = np.asarray(target_values, dtype=float)
    if len(base_arr) == 0 or len(target_arr) == 0 or np.mean(base_arr) == 0:
        return 0.0, [0.0, 0.0]

    obs_reduction = float((np.mean(base_arr) - np.mean(target_arr)) / np.mean(base_arr) * 100.0)

    rng = np.random.default_rng(seed)
    boot_reductions = []
    for _ in range(n_boot):
        b_sample = rng.choice(base_arr, size=len(base_arr), replace=True)
        t_sample = rng.choice(target_arr, size=len(target_arr), replace=True)
        b_mean = np.mean(b_sample)
        if b_mean > 0:
            red = (b_mean - np.mean(t_sample)) / b_mean * 100.0
            boot_reductions.append(red)

    if not boot_reductions:
        return round(obs_reduction, 2), [0.0, 0.0]

    low = float(np.percentile(boot_reductions, 100 * (alpha / 2.0)))
    high = float(np.percentile(boot_reductions, 100 * (1.0 - alpha / 2.0)))
    return round(obs_reduction, 2), [round(low, 2), round(high, 2)]


def cliffs_delta(x, y):
    """Compute Cliff's delta non-parametric effect size.
    
    delta = (#(x > y) - #(x < y)) / (n_x * n_y)
    Returns: (delta_value, interpretation_string)
    """
    x = np.asarray(x, dtype=float)
    y = np.asarray(y, dtype=float)
    if len(x) == 0 or len(y) == 0:
        return 0.0, "negligible"

    n_x, n_y = len(x), len(y)
    greater = 0
    less = 0
    for val_x in x:
        greater += np.sum(val_x > y)
        less += np.sum(val_x < y)

    delta = float((greater - less) / (n_x * n_y))
    abs_d = abs(delta)
    if abs_d < 0.147:
        interp = "negligible"
    elif abs_d < 0.33:
        interp = "small"
    elif abs_d < 0.474:
        interp = "medium"
    else:
        interp = "large"
    return round(delta, 3), interp


def summarize_array(arr):
    """Compute descriptive statistics and bootstrap CI for an array."""
    values = [float(v) for v in arr if v is not None]
    n = len(values)
    if n == 0:
        return {
            "n": 0, "mean": 0.0, "std": 0.0, "median": 0.0,
            "p95": 0.0, "ci_95": [0.0, 0.0], "low_sample_size": True
        }

    val_mean = float(np.mean(values))
    val_std = float(np.std(values, ddof=1)) if n > 1 else 0.0
    val_med = float(np.median(values))
    val_p95 = float(np.percentile(values, 95))
    ci = bootstrap_ci(values, stat_func=np.mean)

    return {
        "n": n,
        "mean": round(val_mean, 3),
        "std": round(val_std, 3),
        "median": round(val_med, 3),
        "p95": round(val_p95, 3),
        "ci_95": ci,
        "low_sample_size": bool(n < 20),
    }


def analyze(benchmark_data):
    """Perform full statistical analysis on benchmark data."""
    meta = benchmark_data.get("meta", {})
    modes_data = benchmark_data.get("modes", {})

    mode_stats = {}
    for mode, data in modes_data.items():
        runs = data.get("runs", [])
        exposures = [item.get("value", 0) for item in data.get("exposure_seconds", [])]
        update_latencies = data.get("update_latency_ms", [])
        enforcement_calls = data.get("enforcement_call_ms", [])
        time_to_effective = data.get("time_to_effective_ms", [])

        violations_missed = [r.get("violations_missed", 0) for r in runs]
        violations_blocked = [r.get("violations_blocked", 0) for r in runs]
        false_denies = [r.get("false_denies", 0) for r in runs]
        policy_changes = [r.get("policy_changes", 0) for r in runs]
        validation_overheads = [r.get("validation_overhead_ms") for r in runs if r.get("validation_overhead_ms") is not None]

        mode_stats[mode] = {
            "runs_count": len(runs),
            "violations_missed": summarize_array(violations_missed),
            "violations_blocked": summarize_array(violations_blocked),
            "false_denies": summarize_array(false_denies),
            "policy_changes": summarize_array(policy_changes),
            "validation_overhead_ms": summarize_array(validation_overheads),
            "exposure_seconds": summarize_array(exposures),
            "update_latency_ms": summarize_array(update_latencies),
            "enforcement_call_ms": summarize_array(enforcement_calls),
            "time_to_effective_ms": summarize_array(time_to_effective),
        }

    # Pairwise hypothesis tests vs static baseline and adaptive vs identity
    pairwise = {}
    comparisons = [
        ("adaptive", "static"),
        ("identity", "static"),
        ("adaptive_identity", "static"),
        ("adaptive", "identity"),
        ("adaptive_identity", "adaptive"),
    ]

    for target_mode, base_mode in comparisons:
        pair_key = f"{target_mode}_vs_{base_mode}"
        if target_mode in modes_data and base_mode in modes_data:
            target_runs = modes_data[target_mode].get("runs", [])
            base_runs = modes_data[base_mode].get("runs", [])

            target_missed = [r.get("violations_missed", 0) for r in target_runs]
            base_missed = [r.get("violations_missed", 0) for r in base_runs]

            # Mann-Whitney U test on violations missed
            if len(target_missed) > 0 and len(base_missed) > 0:
                try:
                    u_res = stats.mannwhitneyu(target_missed, base_missed, alternative="two-sided")
                    p_val = float(u_res.pvalue)
                    u_stat = float(u_res.statistic)
                except Exception:
                    p_val = 1.0
                    u_stat = 0.0

                c_delta, c_interp = cliffs_delta(target_missed, base_missed)
                red_pct, red_ci = bootstrap_reduction_ci(base_missed, target_missed)

                # Significance stars
                if p_val < 0.001:
                    stars = "***"
                elif p_val < 0.01:
                    stars = "**"
                elif p_val < 0.05:
                    stars = "*"
                else:
                    stars = "ns"

                pairwise[pair_key] = {
                    "target_mode": target_mode,
                    "base_mode": base_mode,
                    "metric": "violations_missed",
                    "mann_whitney_u": round(u_stat, 2),
                    "p_value": p_val,
                    "significance": stars,
                    "cliffs_delta": c_delta,
                    "effect_size": c_interp,
                    "reduction_pct": red_pct,
                    "reduction_pct_ci_95": red_ci,
                }

    output = {
        "generated_at": meta.get("timestamp"),
        "meta": meta,
        "mode_statistics": mode_stats,
        "pairwise_comparisons": pairwise,
    }
    return output


def main():
    parser = argparse.ArgumentParser(description="Analyze AC-SCP benchmark empirical data.")
    parser.add_argument("--input", default=None, help="Input benchmark JSON file")
    parser.add_argument("--output", default=str(RESULTS_DIR / "stats.json"), help="Output stats JSON file")
    parser.add_argument("--allow-mock", action="store_true", help="Allow analysis of explicitly selected mock input")
    args = parser.parse_args()

    # Determine input file
    input_file = args.input
    if not input_file:
        real_bench = RESULTS_DIR / "benchmark.json"
        mock_bench = RESULTS_DIR / "mock_benchmark.json"
        if real_bench.exists():
            input_file = str(real_bench)
        elif mock_bench.exists():
            input_file = str(mock_bench)
        else:
            print("Error: neither results/benchmark.json nor results/mock_benchmark.json found.", file=sys.stderr)
            sys.exit(1)

    print(f"Reading benchmark data from: {input_file}")
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if data.get("meta", {}).get("mock") is True and not args.allow_mock:
        print("Error: refusing to analyze mock benchmark data as real results.", file=sys.stderr)
        sys.exit(1)
    expected_seeds = data.get("meta", {}).get("seeds", [])
    expected_requests = data.get("meta", {}).get("requests_per_run")
    required_modes = ["none", "static", "adaptive", "identity", "adaptive_identity"]
    invalid = []
    for mode in required_modes:
        runs = data.get("modes", {}).get(mode, {}).get("runs", [])
        if {run.get("seed") for run in runs} != set(expected_seeds):
            invalid.append(f"{mode}: expected seeds {expected_seeds}")
        if expected_requests and any(run.get("total_requests") != expected_requests for run in runs):
            invalid.append(f"{mode}: expected {expected_requests} requests per run")
    if invalid:
        print("Error: refusing to analyze incomplete benchmark data:\n- " + "\n- ".join(invalid), file=sys.stderr)
        sys.exit(1)

    stats_output = analyze(data)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(stats_output, f, indent=2)

    print(f"[OK] Analysis complete. Wrote: {out_path}")


if __name__ == "__main__":
    main()
