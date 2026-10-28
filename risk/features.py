#!/usr/bin/env python3
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta


def parse_ts(value):
    if value is None:
        return datetime.utcnow()
    return datetime.fromisoformat(str(value).replace('Z', '+00:00')).astimezone().replace(tzinfo=None)


def compute_user_features(rows, window_minutes=15):
    if not rows:
        return {"api_diversity": 0.0, "outside_baseline_api_share": 0.0, "hour_deviation": 0.0,
                "region_deviation": 0.0, "privilege_escalation_count": 0, "sensitive_access_ratio": 0.0,
                "peak_requests_per_min": 0.0}
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    recent = [r for r in rows if parse_ts(r.get('effective_ts')) >= cutoff]
    if not recent:
        recent = rows
    api_counts = Counter(r.get('action') for r in recent)
    total = max(1, len(recent))
    baseline = defaultdict(float)
    for r in recent:
        baseline[r.get('resource', '')] += 1
    outside_baseline = sum(1 for r in recent if r.get('resource') not in baseline) / total
    hours = [parse_ts(r.get('effective_ts')).hour for r in recent]
    hour_deviation = (sum(abs(h - 14) for h in hours) / total) / 24.0
    regions = [r.get('region') for r in recent if r.get('region')]
    region_deviation = 1.0 if len(set(regions)) > 1 else 0.0
    privilege_escalation = sum(1 for r in recent if r.get('privilege_escalation'))
    sensitive = sum(1 for r in recent if r.get('sensitivity_label') in {'restricted', 'regulated'})
    peak_requests = Counter(parse_ts(r.get('effective_ts')).strftime('%Y-%m-%d %H:%M') for r in recent)
    return {
        'api_diversity': len(api_counts) / max(1.0, len(api_counts)),
        'outside_baseline_api_share': float(outside_baseline),
        'hour_deviation': float(hour_deviation),
        'region_deviation': float(region_deviation),
        'privilege_escalation_count': int(privilege_escalation),
        'sensitive_access_ratio': float(sensitive / total),
        'peak_requests_per_min': float(max(peak_requests.values(), default=0.0)),
    }


def compute_workload_features(rows, window_minutes=15):
    if not rows:
        return {'storage_access_rate': 0.0, 'inter_region_share': 0.0, 'config_change_count': 0,
                'misconfig_flags': 0, 'sensitivity_weight': 0.0, 'incident_count': 0}
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    recent = [r for r in rows if parse_ts(r.get('effective_ts')) >= cutoff]
    if not recent:
        recent = rows
    total = max(1, len(recent))
    storage = sum(1 for r in recent if r.get('action') == 'DELETE' or '/storage' in (r.get('resource') or ''))
    inter_region = sum(1 for r in recent if r.get('region') and r.get('resource') and 'region' in r.get('resource', '').lower())
    config_changes = sum(1 for r in recent if r.get('privilege_escalation'))
    misconfig = sum(1 for r in recent if not r.get('encrypted') or r.get('public_exposed'))
    sensitivity = {'public': 0.2, 'internal': 0.5, 'regulated': 1.0}.get(r.get('sensitivity_label'), 0.0) if recent else 0.0
    incidents = sum(1 for r in recent if r.get('decision') == 'BLOCKED' and r.get('sim_label') == 'threat')
    return {
        'storage_access_rate': float(storage / total),
        'inter_region_share': float(inter_region / total),
        'config_change_count': int(config_changes),
        'misconfig_flags': int(misconfig),
        'sensitivity_weight': float(sensitivity),
        'incident_count': int(incidents),
    }


def serialize_features(features):
    return json.dumps(features, sort_keys=True)
