"""Paired chronological triage benchmark. Never infer benign labels from attack gaps."""
import argparse
import csv
import json
import sqlite3
import statistics
import hashlib
import heapq
from bisect import bisect_left
from pathlib import Path
from engine import OnlineEngine
from verification import verify
from detection import RULES_VERSION


def compare(events, windows, benign_reviews=(), severity_threshold=10, correlation_seconds=900):
    engine = OnlineEngine()
    methods = {name: {'times': {}, 'selected_ids': set(), 'items': set(), 'selected_records': 0}
               for name in ('raw_severity', 'time_correlation', 'pipeline')}
    sessions = {}
    input_digest = hashlib.sha256()
    ranked = []
    operational = 0
    promoted = []
    engine.priority_observer = lambda group, event: promoted.append(group['id'])
    total = 0
    last = float('-inf')
    for e in events:
        if e['timestamp'] < last:
            raise ValueError('Benchmark inputs must be chronologically ordered')
        last = e['timestamp']
        total += 1
        input_digest.update(json.dumps([e['id'], e['timestamp'], e.get('evidence_hash'), e['training']], separators=(',', ':')).encode())
        promoted.clear()
        result = engine.ingest(e)
        if e['training']:
            continue
        operational += 1
        rank = (e['level'], e['timestamp'], e['id'])
        if len(ranked) < 100:
            heapq.heappush(ranked, rank)
        elif rank > ranked[0]:
            heapq.heapreplace(ranked, rank)
        gid = result['group']
        group = engine.groups[gid]
        selections = {}
        if e['level'] >= severity_threshold:
            selections['raw_severity'] = e['id']
            key = (e['scenario'], e['host'] if e['host'] != 'unresolved host' else e['sensor'] + ':' + e['location'])
            session = sessions.get(key)
            if session is None or e['timestamp'] - session[0] > correlation_seconds:
                session = (e['timestamp'], e['id'])
            sessions[key] = (e['timestamp'], session[1])
            selections['time_correlation'] = (key, session[1])
        if promoted or group['priority'] in ('high', 'investigate'):
            selections['pipeline'] = gid
        for name, item in selections.items():
            method = methods[name]
            method['times'].setdefault(e['scenario'], []).append(e['timestamp'])
            method['selected_ids'].add(e['id'])
            method['items'].add(item)
            method['selected_records'] += 1
    # Final pipeline consolidation determines review units; decision times above
    # remain prefix-only, so later promotion cannot backdate latency.
    methods['pipeline']['items'] = {item['id'] for item in engine.review_queue()}
    windows = windows() if callable(windows) else windows
    output = {}
    for name, method in methods.items():
        coverage, latency, misses = 0, [], []
        for w in windows:
            times = method['times'].get(w['scenario'], [])
            start, end = float(w['start']), float(w['end'])
            index = bisect_left(times, start)
            if index < len(times) and times[index] < end:
                coverage += 1
                latency.append(times[index] - start)
            else:
                misses.append({'scenario': w['scenario'], 'attack': w['attack'], 'start': start, 'end': end})
        reviews = [r for r in benign_reviews if r.get('status') == 'Confirmed false positive' and
                   r.get('notes', '').strip() and r.get('evidenceIds')]
        flagged = sum(bool(set(r['evidenceIds']) & method['selected_ids']) for r in reviews)
        count = len(method['items'])
        output[name] = {'attack_window_review_coverage': {'covered': coverage, 'total': len(windows)},
                        'review_items': count, 'selected_records': method['selected_records'],
                        'alert_reduction_fraction': 1 - count / operational if operational else None,
                        'detection_latency_seconds': {'median': statistics.median(latency) if latency else None,
                                                     'per_covered_window': latency},
                        'missed_windows': misses,
                        'analyst_review_burden': {'units': count, 'measured_minutes': None},
                        'reviewed_benign': {'cases': len(reviews), 'selected_cases': flagged,
                                           'case_selection_rate': flagged / len(reviews) if reviews else None}}
    return {'methods': output, 'records': total, 'operational_records': operational,
            'input_evidence_digest': input_digest.hexdigest(),
            'raw_severity_ranking_preview': [{'level': level, 'timestamp': timestamp, 'alert_id': rid} for level, timestamp, rid in sorted(ranked, reverse=True)], 'rules_version': RULES_VERSION,
            'parameters': {'severity_threshold': severity_threshold, 'correlation_seconds': correlation_seconds},
            'methodology': 'Identical chronological inputs, training excluded. Raw baseline ranks by severity and selects severity >= threshold; time baseline groups by scenario/host with inactivity timeout. Pipeline decisions use online priority. Coverage is any selected review signal in [start,end), not proof of technique detection. Latency is from window start to first selected signal; misses excluded from latency and reported separately. Review units are a workload proxy, not measured human time. Benign rates use only explicitly reviewed cases and sampled reference intersection; no population false-positive rate is claimed. Suppressions disabled for reproducibility.'}, engine


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scenarios', nargs='+', required=True)
    parser.add_argument('--cache-dir', type=Path, default=Path(__file__).parent / '.cache')
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--reviews', type=Path)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'tests' / 'triage-benchmark.json')
    parser.add_argument('--severity-threshold', type=int, default=10)
    args = parser.parse_args()
    if args.labels.name != 'labels.csv':
        parser.error('Use the canonical labels.csv for technique verification')
    import heapq
    from contextlib import ExitStack
    reviews = json.loads(args.reviews.read_text()) if args.reviews else []
    from contextlib import closing
    from telemetry import VERSION
    def load_windows():
        with args.labels.open(newline='') as handle:
            return [w for w in csv.DictReader(handle) if w['scenario'] in args.scenarios]
    with ExitStack() as stack:
        streams = []
        for scenario in args.scenarios:
            cache = args.cache_dir / (scenario + f'-v{VERSION}.sqlite3')
            db = stack.enter_context(closing(sqlite3.connect(f'file:{cache}?mode=ro', uri=True)))
            streams.append((json.loads(r[0]) for r in db.execute('SELECT payload FROM events ORDER BY ts,source_order,line')))
        events = heapq.merge(*streams, key=lambda e: e['timestamp'])
        result, engine = compare(events, load_windows, reviews, args.severity_threshold)
    result['pipeline_technique_coverage'] = verify(args.labels.parent, args.scenarios, tuple(engine.timeline))
    args.output.write_text(json.dumps(result, indent=2))
    print(args.output)

if __name__ == '__main__':
    main()
