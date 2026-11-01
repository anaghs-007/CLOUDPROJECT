import unittest
from datetime import datetime, timedelta

from risk.features import compute_user_features, compute_workload_features
from risk.risk_engine import score_user_features, score_workload_features


class RiskFeatureTests(unittest.TestCase):
    def test_user_features_reflect_telemetry_values(self):
        now = datetime.utcnow().isoformat()
        rows = [
            {'action': 'GET', 'resource': '/api/public/status', 'region': 'us-east',
             'sensitivity_label': 'public', 'privilege_escalation': False,
             'effective_ts': now},
            {'action': 'DELETE', 'resource': '/api/admin/storage', 'region': 'eu-central',
             'sensitivity_label': 'restricted', 'privilege_escalation': True,
             'effective_ts': now},
        ]
        features = compute_user_features(rows)
        self.assertEqual(features['api_diversity'], 1.0)
        self.assertEqual(features['outside_baseline_api_share'], 1.0)
        self.assertEqual(features['privilege_escalation_count'], 1)
        self.assertEqual(features['sensitive_access_ratio'], 0.5)
        self.assertGreater(score_user_features(features), 0.05)

    def test_workload_features_average_sensitivity_and_misconfiguration(self):
        now = datetime.utcnow().isoformat()
        rows = [
            {'action': 'GET', 'resource': '/api/public/status', 'region': 'us-east',
             'sensitivity_label': 'public', 'privilege_escalation': False,
             'decision': 'ALLOWED', 'sim_label': 'normal', 'encrypted': True,
             'public_exposed': False, 'effective_ts': now},
            {'action': 'DELETE', 'resource': '/api/admin/storage', 'region': 'eu-central',
             'sensitivity_label': 'regulated', 'privilege_escalation': True,
             'decision': 'BLOCKED', 'sim_label': 'threat', 'encrypted': False,
             'public_exposed': True, 'effective_ts': now},
        ]
        features = compute_workload_features(rows)
        self.assertEqual(features['sensitivity_weight'], 0.6)
        self.assertEqual(features['misconfig_flags'], 1)
        self.assertEqual(features['incident_count'], 1)
        self.assertGreater(score_workload_features(features), 0.05)


if __name__ == '__main__':
    unittest.main()
