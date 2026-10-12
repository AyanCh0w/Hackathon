"""Paired full-export replay; labels are opened only after each replay has completed."""
import builtins
import argparse
import io
import json
import sqlite3
import sys
import time
from collections import Counter
from contextlib import closing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
from baseline import classify as baseline_classify
from engine import OnlineEngine
from investigation import review
from telemetry import SCENARIOS
from detection import RULES_VERSION


def configure(alert_only):
    if alert_only:
        server.INPUTS = Path(__file__).parent / 'no-native-inputs'
        server.CACHE = server.CACHE / 'alerts-only'


def prepare_one(name):
    server.CATALOG[name] = {'status': 'loading'}
    server.prepare_worker(name)
    result = server.CATALOG[name]
    if result['status'] != 'ready':
        raise RuntimeError(result)
    return result


def evaluate_one(name):
    meta = prepare_one(name)
    engine, baseline = OnlineEngine(), []
    started = time.monotonic()
    real_builtin, real_io = builtins.open, io.open
    def guard(original):
        def wrapped(path, *args, **kwargs):
            if str(path).endswith('labels.csv'):
                raise AssertionError('Labels read during inference')
            return original(path, *args, **kwargs)
        return wrapped
    with patch('builtins.open', guard(real_builtin)), patch('io.open', guard(real_io)):
        with closing(sqlite3.connect(meta['cache'])) as db:
            for row in db.execute('SELECT payload FROM events ORDER BY ts,source_order,line'):
                event = json.loads(row[0])
                old_family = baseline_classify(event)[0]
                baseline.append((event['timestamp'], old_family, '', event['training'], name, event['capabilities'], '', event['id']))
                engine.ingest(event)
        assert engine.processed == meta['total']
        before = engine.snapshot(False)
        reviews = [review(engine.public_group(g)) for g in engine.groups.values() if g['family'] in ('dns', 'cracking', 'callback', 'execution')]
        assert engine.snapshot(False) == before
    from verification import verify
    current = verify(server.ROOT, name, tuple(engine.timeline))
    old = verify(server.ROOT, name, tuple(baseline))
    assert engine.snapshot(False) == before
    # Compare both using the corrected verifier, isolating classifier changes from scoring changes.
    old_rows = {(r['scenario'], r['phase']): r for r in old['rows']}
    for r in current['rows']:
        previous = old_rows[(name, r['phase'])]
        r['baseline_specific'] = previous['relevant']
        r['baseline_status'] = previous['evidence_status']
    return {'scenario': name, 'records': engine.processed, 'sources': meta['sources'], 'skipped': meta['errors'], 'seconds': round(time.monotonic()-started, 2),
            'categories': dict(engine.categories), 'groups': len(engine.groups),
            'review_counts': dict(Counter(r['decision'] for r in reviews)), 'rows': current['rows'],
            'baseline_summary': old['summary'], 'summary': current['summary'],
            'checks': {'labels_during_inference': 'denied', 'record_conservation': 'passed', 'review_mutation': 'none', 'verification_mutation': 'none'}}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--alert-only',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    started = time.monotonic()
    results=[]
    with ProcessPoolExecutor(max_workers=3,initializer=configure,initargs=(args.alert_only,)) as pool:
        for result in pool.map(evaluate_one, SCENARIOS):
            results.append(result)
            print(json.dumps({'scenario':result['scenario'],'records':result['records'],'summary':result['summary']}),flush=True)
    rows = [r for result in results for r in result['rows']]
    phases = {}
    for r in rows:
        p = phases.setdefault(r['phase'], {'windows': 0, 'baseline_specific_windows': 0, 'current_specific_windows': 0, 'statuses': Counter()})
        p['windows'] += 1
        p['baseline_specific_windows'] += r['baseline_specific'] > 0
        p['current_specific_windows'] += r['relevant'] > 0
        p['statuses'][r['evidence_status']] += 1
    for p in phases.values():p['statuses'] = dict(p['statuses'])
    report = {'rules_version': RULES_VERSION, 'input_mode': 'alerts only' if args.alert_only else 'alerts and optional native telemetry', 'records': sum(r['records'] for r in results), 'windows': len(rows),
              'seconds': round(time.monotonic()-started,2), 'phases': phases, 'scenarios': results,
              'limitations': ['Window coverage is not precision/recall or attack success.',
                             'Both classifiers use corrected technique-specific verification; original cracking success was generic overlap.',
                             'All eight scenarios were previously inspected; this is regression evaluation, not untouched validation.',
                             'Behavioral thresholds are uncalibrated. Sources are reported per scenario; selected raw logs do not establish complete collection. Event-level ground truth is not loaded by this evaluation.']}
    output = args.output or Path(__file__).parent / ('alert-only-improvement-results.json' if args.alert_only else 'improvement-results.json')
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='scenarios'},indent=2),flush=True)


if __name__ == '__main__':main()
