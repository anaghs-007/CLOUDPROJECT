#!/usr/bin/env python3
"""Unit tests for analyze_results.py using a controlled tiny fixture."""

import unittest
from analyze_results import (
    bootstrap_ci,
    bootstrap_reduction_ci,
    cliffs_delta,
    summarize_array,
    analyze,
)


class TestAnalyzeResults(unittest.TestCase):
    def test_bootstrap_ci(self):
        vals = [10.0, 10.0, 10.0, 10.0]
        ci = bootstrap_ci(vals)
        self.assertEqual(ci, [10.0, 10.0])

        vals2 = [1.0, 2.0, 3.0, 4.0, 5.0]
        ci2 = bootstrap_ci(vals2)
        self.assertTrue(ci2[0] < ci2[1])
        self.assertTrue(1.0 <= ci2[0] <= 5.0)

    def test_cliffs_delta(self):
        # Target completely smaller than base
        target = [1, 2, 3]
        base = [10, 11, 12]
        delta, interp = cliffs_delta(target, base)
        self.assertEqual(delta, -1.0)
        self.assertEqual(interp, "large")

        # Equal distributions
        eq_a = [5, 6, 7]
        eq_b = [5, 6, 7]
        delta_eq, interp_eq = cliffs_delta(eq_a, eq_b)
        self.assertEqual(delta_eq, 0.0)
        self.assertEqual(interp_eq, "negligible")

    def test_reduction_ci(self):
        base = [100.0, 100.0]
        target = [50.0, 50.0]
        red, ci = bootstrap_reduction_ci(base, target)
        self.assertEqual(red, 50.0)
        self.assertEqual(ci, [50.0, 50.0])

    def test_summarize_array_low_sample_flag(self):
        # n < 20 must have low_sample_size: True
        small = [5.0] * 10
        stats_small = summarize_array(small)
        self.assertTrue(stats_small["low_sample_size"])
        self.assertEqual(stats_small["n"], 10)

        # n >= 20 must have low_sample_size: False
        large = [5.0] * 20
        stats_large = summarize_array(large)
        self.assertFalse(stats_large["low_sample_size"])
        self.assertEqual(stats_large["n"], 20)

    def test_analyze_tiny_fixture(self):
        fixture = {
            "meta": {
                "git_commit": "abc1234",
                "seeds": [1, 2],
                "requests_per_run": 50,
                "timestamp": "2026-11-01T00:00:00Z",
                "mock": True,
            },
            "modes": {
                "static": {
                    "runs": [
                        {"seed": 1, "violations_missed": 20, "violations_blocked": 5, "false_denies": 2},
                        {"seed": 2, "violations_missed": 22, "violations_blocked": 4, "false_denies": 1},
                    ],
                    "exposure_seconds": [{"seed": 1, "episode_id": "ep1", "value": 100}],
                    "update_latency_ms": [0],
                    "enforcement_call_ms": [0],
                    "time_to_effective_ms": [0],
                },
                "adaptive": {
                    "runs": [
                        {"seed": 1, "violations_missed": 8, "violations_blocked": 17, "false_denies": 0},
                        {"seed": 2, "violations_missed": 6, "violations_blocked": 19, "false_denies": 1},
                    ],
                    "exposure_seconds": [{"seed": 1, "episode_id": "ep2", "value": 30}],
                    "update_latency_ms": [245.0],
                    "enforcement_call_ms": [0],
                    "time_to_effective_ms": [245.0],
                },
            },
        }
        res = analyze(fixture)
        self.assertIn("mode_statistics", res)
        self.assertIn("adaptive", res["mode_statistics"])
        self.assertIn("static", res["mode_statistics"])
        self.assertIn("adaptive_vs_static", res["pairwise_comparisons"])
        pair = res["pairwise_comparisons"]["adaptive_vs_static"]
        self.assertTrue(pair["reduction_pct"] > 50.0)


if __name__ == "__main__":
    unittest.main()

