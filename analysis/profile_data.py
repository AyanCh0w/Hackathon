"""Reproduce the streaming profile of the original local dataset."""
from pathlib import Path
import json
import csv
import collections
import datetime

ROOT = Path(__file__).resolve().parents[1]
rows = list(csv.DictReader((ROOT / 'labels.csv').open()))
for row in rows:
    row['start'] = float(row['start'])
    row['end'] = float(row['end'])
labels = collections.defaultdict(list)
for row in rows:
    labels[row['scenario']].append(row)
summary = {'labels': {
    'rows': len(rows),
    'attacks': dict(collections.Counter(r['attack'] for r in rows)),
    'scenarios': dict(collections.Counter(r['scenario'] for r in rows)),
    'invalid_windows': sum(r['end'] <= r['start'] for r in rows),
    'missing_cells': sum(v == '' for r in rows for v in r.values()),
    'duplicate_rows': len(rows) - len({tuple(r.items()) for r in rows}),
    'min_start': min(r['start'] for r in rows),
    'max_end': max(r['end'] for r in rows),
}, 'files': []}
for file in sorted((ROOT / 'ait_ads').glob('*.json')):
    scenario, source = file.stem.rsplit('_', 1)
    info = {'file': file.name, 'scenario': scenario, 'source': source,
            'bytes': file.stat().st_size, 'rows': 0, 'bad_json': 0,
            'missing_time': 0, 'min_time': None, 'max_time': None,
            'inside_attack_windows': 0}
    cats, daily, levels, fields, training = (collections.Counter() for _ in range(5))
    ids = set()
    dupids = multiple = loglines = 0
    with file.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                info['bad_json'] += 1
                continue
            info['rows'] += 1
            fields.update(record.keys())
            if source == 'wazuh':
                timestamp = record.get('@timestamp')
                ts = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00')).timestamp() if timestamp else None
                rule = record.get('rule', {})
                cats[rule.get('description', '(missing)')] += 1
                levels[str(rule.get('level'))] += 1
                event_id = record.get('id')
                dupids += event_id in ids if event_id is not None else 0
                if event_id is not None:
                    ids.add(event_id)
            else:
                log_data = record.get('LogData', {})
                times = log_data.get('Timestamps', [])
                ts = min(times) if times else None
                multiple += len(times) > 1
                loglines += log_data.get('LogLinesCount', 0)
                component = record.get('AnalysisComponent', {})
                cats[component.get('AnalysisComponentType', '(missing)')] += 1
                training[str(component.get('TrainingMode'))] += 1
            if ts is None:
                info['missing_time'] += 1
                continue
            info['min_time'] = ts if info['min_time'] is None else min(info['min_time'], ts)
            info['max_time'] = ts if info['max_time'] is None else max(info['max_time'], ts)
            daily[datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%d')] += 1
            if any(r['start'] <= ts < r['end'] for r in labels[scenario]):
                info['inside_attack_windows'] += 1
    info.update(top_categories=cats.most_common(8), daily=dict(sorted(daily.items())), fields=dict(fields))
    if source == 'wazuh':
        info.update(levels=dict(levels), duplicate_ids=dupids)
    else:
        info.update(training=dict(training), records_multiple_timestamps=multiple, referenced_log_lines=loglines)
    summary['files'].append(info)
    print(file.name, info['rows'], info['bad_json'], flush=True)
    (ROOT / 'analysis/data-profile.json').write_text(json.dumps(summary, indent=2))
