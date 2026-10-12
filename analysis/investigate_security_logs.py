"""Streaming, descriptive investigation of local AIT-ADS alerts; no malicious-event classifier.

Run from any directory with Python 3. Results use UTC event times and half-open
label intervals. An alert inside a phase interval is not necessarily malicious.
"""
from pathlib import Path
from collections import Counter, defaultdict
import csv
import datetime as dt
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis' / 'security-log-evidence.json'
labels = list(csv.DictReader((ROOT / 'labels.csv').open()))
for label in labels:
    label.update(start=float(label['start']), end=float(label['end']))
by_scenario = defaultdict(list)
for label in labels:
    by_scenario[label['scenario']].append(label)

def utc(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()

query_re = re.compile(r'query\[([^\]]+)\]\s+(\S+)\s+from\s+(\S+)')
result = {'definitions': {
    'phase_membership': 'start <= event_time < end; temporal co-occurrence only, not event-level truth',
    'time': 'Wazuh @timestamp; AMiner minimum LogData.Timestamps; UTC',
    'summary_buckets': 'source, 60-second UTC bucket, sensor, category, src, dst, resource; descriptive compression only',
    'dns_coverage': 'Explicit query[type] name from client patterns in alert raw logs only; not all DNS traffic',
    'raw_duplicate': 'Same sensor, event time and complete nonempty raw log string within a file; detector IDs ignored; empty raw logs excluded'
}, 'files': [], 'windows': []}
windows = {}
for label in labels:
    key = (label['scenario'], label['attack'])
    windows[key] = dict(label, start_utc=utc(label['start']), end_utc=utc(label['end']),
                        duration_seconds=label['end']-label['start'], sources={})

for path in sorted((ROOT / 'ait_ads').glob('*.json')):
    scenario, source = path.stem.rsplit('_', 1)
    totals, categories, resources, field_counts, data_fields = [Counter() for _ in range(5)]
    buckets, raw_seen, event_ids = set(), set(), set()
    sensors, peers = set(), set()
    counts = defaultdict(Counter)
    phase_cats = defaultdict(Counter)
    samples = defaultdict(dict)
    dns = defaultdict(Counter)
    dns_names = defaultdict(set)
    dns_clients = defaultdict(set)
    low = high = None
    first_online = last_training = None
    for line_number, line in enumerate(path.open(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            totals['bad_json'] += 1
            continue
        totals['rows'] += 1
        field_counts.update(record.keys())
        if source == 'wazuh':
            stamp = record.get('@timestamp')
            ts = dt.datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp() if stamp else None
            rule = record.get('rule', {})
            cat = rule.get('description', '(missing)')
            sensor = record.get('agent', {}).get('ip', '')
            data = record.get('data', {})
            data_fields.update(data.keys())
            src = data.get('srcip', data.get('src_ip', ''))
            dst = data.get('dstip', data.get('dest_ip', ''))
            resource = record.get('location', '')
            raw = record.get('full_log', '')
            training = False
            eid = record.get('id')
            if eid is not None:
                totals['duplicate_event_ids'] += eid in event_ids
                event_ids.add(eid)
            totals['has_srcip'] += bool(src)
            totals['has_dstip'] += bool(dst)
            totals['has_flow_id'] += 'flow_id' in data
            totals['level_ge_10'] += int(rule.get('level', 0)) >= 10
        else:
            log = record.get('LogData', {})
            timestamps = log.get('Timestamps', [])
            ts = min(timestamps) if timestamps else None
            component = record.get('AnalysisComponent', {})
            cat = component.get('AnalysisComponentType', '(missing)')
            sensor = record.get('AMiner', {}).get('ID', '')
            src = dst = ''
            resource = '|'.join(log.get('LogResources', []))
            raw = '\n'.join(log.get('RawLogData', []))
            training = component.get('TrainingMode') is True
            totals['training'] += training
            totals['multiple_timestamps'] += len(timestamps) > 1
        categories[cat] += 1
        resources[resource] += 1
        if sensor:
            sensors.add(sensor)
        for peer in (src, dst):
            if peer:
                peers.add(str(peer))
        if ts is None:
            totals['missing_time'] += 1
            continue
        low = ts if low is None else min(low, ts)
        high = ts if high is None else max(high, ts)
        if training:
            last_training = ts if last_training is None else max(last_training, ts)
        else:
            first_online = ts if first_online is None else min(first_online, ts)
        phase = next((x['attack'] for x in by_scenario[scenario] if x['start'] <= ts < x['end']), 'outside_windows')
        counts[phase]['rows'] += 1
        counts[phase]['training'] += training
        phase_cats[phase][cat] += 1
        if source == 'wazuh':
            counts[phase]['level_ge_10'] += int(rule.get('level', 0)) >= 10
        totals['missing_raw_evidence'] += not bool(raw)
        if raw:
            digest = hashlib.blake2b(json.dumps([sensor, ts, raw]).encode(), digest_size=16).digest()
            totals['duplicate_raw_evidence'] += digest in raw_seen
            raw_seen.add(digest)
        buckets.add((int(ts // 60), str(sensor), cat, str(src), str(dst), resource))
        if cat not in samples[phase] and len(samples[phase]) < 12:
            samples[phase][cat] = {'file': path.name, 'line': line_number, 'event_time': utc(ts),
                                   'category': cat, 'resource': resource, 'sensor': sensor,
                                   'raw_excerpt': raw[:1400], 'training': training}
        match = query_re.search(raw)
        if match:
            qtype, name, client = match.groups()
            dns[phase]['query_alert_rows'] += 1
            dns[phase]['qtype_' + qtype] += 1
            dns[phase]['longest_name'] = max(dns[phase]['longest_name'], len(name))
            dns_names[phase].add(name)
            dns_clients[phase].add(client)
    info = {'file': path.name, 'bytes': path.stat().st_size, 'scenario': scenario, 'source': source,
            'totals': dict(totals), 'start_utc': utc(low), 'end_utc': utc(high),
            'first_nontraining_utc': utc(first_online) if first_online else None,
            'last_training_utc': utc(last_training) if last_training else None,
            'sensor_count': len(sensors), 'sensors': sorted(sensors),
            'peer_values': len(peers), 'top_categories': categories.most_common(20),
            'resources': dict(resources), 'top_level_fields': dict(field_counts),
            'data_fields': dict(data_fields), 'unique_raw_evidence': len(raw_seen),
            'sixty_second_summary_buckets': len(buckets),
            'outside_windows': dict(counts['outside_windows']),
            'outside_top_categories': phase_cats['outside_windows'].most_common(8),
            'dns': {phase: dict(counter, unique_names=len(dns_names[phase]), unique_clients=len(dns_clients[phase]))
                    for phase, counter in dns.items()}}
    result['files'].append(info)
    for label in by_scenario[scenario]:
        phase = label['attack']
        windows[(scenario, phase)]['sources'][source] = {
            **dict(counts[phase]), 'top_categories': phase_cats[phase].most_common(10),
            'examples': list(samples[phase].values())}
    print(path.name, totals['rows'], 'buckets', len(buckets), flush=True)
result['windows'] = list(windows.values())
result['generated_at_utc'] = dt.datetime.now(dt.timezone.utc).isoformat()
OUT.write_text(json.dumps(result, indent=2))
print('Saved', OUT)
