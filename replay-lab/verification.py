"""Post-replay audit of frozen outcomes. This is the only attack-label reader."""
import csv
from bisect import bisect_left
from collections import Counter
from datetime import datetime, timezone
from telemetry import CAPABILITIES

EXPECTED = {
    'network_scans': {'recon'}, 'service_scans': {'recon'},
    'dirb': {'web'}, 'wpscan': {'web'}, 'webshell': {'execution'},
    'cracking': {'cracking'}, 'reverse_shell': {'callback'},
    'privilege_escalation': {'privilege'}, 'service_stop': {'service'}, 'dnsteal': {'dns'},
}
REQUIRED = {
    'network_scans': ('connection',), 'service_scans': ('connection', 'auth', 'web'),
    'dirb': ('web',), 'wpscan': ('web',), 'webshell': ('web', 'process'),
    'cracking': ('process', 'auth', 'web'), 'reverse_shell': ('process', 'connection', 'web'),
    'privilege_escalation': ('auth', 'process'), 'service_stop': ('service',), 'dnsteal': ('dns',),
}


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def verify(root, scenario, outcomes):
    scenarios = [scenario] if isinstance(scenario, str) else scenario
    with (root / 'labels.csv').open(newline='') as handle:
        windows = [r for r in csv.DictReader(handle) if r['scenario'] in scenarios]
    grouped = {name: [] for name in scenarios}
    for outcome in outcomes:
        grouped[outcome[4]].append(outcome)
    for records in grouped.values():
        records.sort(key=lambda x: x[0])
    stamps = {name: [x[0] for x in records] for name, records in grouped.items()}
    results = []
    for row in windows:
        start, end = float(row['start']), float(row['end'])
        name, phase = row['scenario'], row['attack']
        records = grouped[name][bisect_left(stamps[name], start):bisect_left(stamps[name], end)]
        counts = Counter(x[1] for x in records)
        operational = Counter(x[1] for x in records if not x[3])
        expected = EXPECTED.get(phase, set())
        supported = sum(operational[f] for f in expected)
        training_related = sum(x[3] and x[1] in expected for x in records)
        coverage, training_coverage = Counter(), Counter()
        for x in records:
            bits = x[5] if len(x) > 5 else 0
            for field, bit in CAPABILITIES.items():
                if bits & bit:
                    (training_coverage if x[3] else coverage)[field] += 1
        required = REQUIRED.get(phase, ())
        if supported:
            status, interpretation = 'specific_signal', 'Technique-specific signal observed; attribution unverified'
            diagnosis = 'A related operational rule fired. Window overlap does not establish malicious membership or attack success.'
        elif training_related:
            status, interpretation = 'training_only', 'Related evidence exists only in training mode'
            diagnosis = 'Operational exclusion: a rule recognized the record, but training evidence cannot establish operational detection.'
        elif not records or not any(coverage[field] for field in required):
            status, interpretation = 'insufficient_telemetry', 'Insufficient relevant telemetry in exported records'
            diagnosis = 'No operational excerpts with the required field types were observed. Obtain original telemetry before tuning detection.'
        else:
            status, interpretation = 'unsupported_behavior', 'Relevant excerpts available; no technique-specific signal'
            diagnosis = 'Review fields and behavior against the rules. Available excerpts do not establish complete collection or a detector false negative.'
        references = []
        for x in records:
            if x[1] in expected and len(x) > 7 and len(references) < 8:
                references.append({'id': x[7], 'rule': x[6], 'time': iso(x[0]), 'training': bool(x[3])})
        results.append({
            'scenario': name, 'phase': phase, 'start': iso(start), 'end': iso(end), 'records': len(records),
            'training': sum(bool(x[3]) for x in records), 'categories': dict(counts),
            'relevant': supported, 'expected': sorted(expected), 'training_related': training_related,
            'generic_anomalies': operational['anomaly'], 'evidence_status': status,
            'interpretation': interpretation, 'diagnosis': diagnosis, 'references': references,
            'telemetry': {'operational': dict(coverage), 'training': dict(training_coverage),
                          'needed_any': list(required), 'collection_complete': False},
        })
    summary = Counter(row['evidence_status'] for row in results)
    phases = {}
    for row in results:
        phase = phases.setdefault(row['phase'], {'windows': 0, 'specific_signal': 0, 'statuses': Counter()})
        phase['windows'] += 1
        phase['specific_signal'] += row['evidence_status'] == 'specific_signal'
        phase['statuses'][row['evidence_status']] += 1
    for phase in phases.values():
        phase['statuses'] = dict(phase['statuses'])
    total = len(results)
    detected = summary['specific_signal']
    possible_misses = summary['unsupported_behavior'] + summary['training_only']
    score = {
        'percent': round(100 * detected / total, 1) if total else None,
        'detected': detected, 'total': total, 'possible_misses': possible_misses,
        'insufficient_telemetry': summary['insufficient_telemetry'],
        'definition': 'Percentage of labeled attack windows with an operational technique-specific signal. All labeled windows are included; this is detection coverage, not record-level accuracy.',
    }
    return {'scenarios': scenarios, 'rows': results, 'outcomes': len(outcomes), 'summary': dict(summary), 'phases': phases,
            'score': score,
            'note': 'Labels describe time windows, not individual malicious records. Specific signals, generic anomalies, training-only evidence and missing telemetry are reported separately. This is not precision, recall or proof of success. Intervals are [start, end).',
            'isolation': 'Read only after replay completion. Frozen classifications and groups are unchanged.'}
