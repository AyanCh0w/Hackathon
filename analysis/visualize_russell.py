"""Aggregate Russell Mitchell source records for inline charts, without raw logs."""
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter
import csv
import json

ROOT = Path(__file__).resolve().parents[1]
OUT = Path('/Users/ayanchowdhary/.codex/visualizations/2026/10/12/01a130e0-b822-7d22-92d8-1c5d2c1674e8')
windows = [dict(attack=r['attack'].replace('_', ' '), start=float(r['start']), end=float(r['end']))
           for r in csv.DictReader((ROOT / 'labels.csv').open()) if r['scenario'] == 'russellmitchell']
assert len(windows) == 10
assert all(w['start'] < w['end'] for w in windows)
assert all(a['end'] <= b['start'] for a, b in zip(windows, windows[1:]))
hourly, attacks, daily, totals, bounds = {}, {}, {}, {}, {}
for source in ['Wazuh', 'AMiner']:
    times = []
    hourly[source], attacks[source], daily[source] = Counter(), Counter(), Counter()
    with (ROOT / 'ait_ads' / f'russellmitchell_{source.lower()}.json').open() as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            if source == 'Wazuh':
                timestamp = datetime.fromisoformat(row['@timestamp'].replace('Z', '+00:00')).timestamp()
            else:
                timestamps = row['LogData']['Timestamps']
                assert len(timestamps) == 1
                timestamp = timestamps[0]
            times.append(timestamp)
            hourly[source][int(timestamp // 3600) * 3600] += 1
            daily[source][datetime.fromtimestamp(timestamp, timezone.utc).strftime('%Y-%m-%d')] += 1
            for window in windows:
                if window['start'] <= timestamp < window['end']:
                    attacks[source][window['attack']] += 1
    totals[source] = len(times)
    bounds[source] = [min(times), max(times)]
    assert sum(hourly[source].values()) == totals[source]
    assert sum(attacks[source].values()) <= totals[source]

first = int(min(b[0] for b in bounds.values()) // 3600) * 3600
last = int(max(b[1] for b in bounds.values()) // 3600) * 3600
hour_rows = [{'hour': datetime.fromtimestamp(t, timezone.utc).strftime('%m-%d %H:%M'),
              'source': source, 'events': hourly[source][t]}
             for t in range(first, last + 1, 3600) for source in totals]
attack_rows = [{'attack': w['attack'], 'source': source, 'events': attacks[source][w['attack']],
                'duration_seconds': w['end'] - w['start'],
                'start_utc': datetime.fromtimestamp(w['start'], timezone.utc).isoformat(),
                'end_utc': datetime.fromtimestamp(w['end'], timezone.utc).isoformat()}
               for w in windows for source in totals]
captured = datetime.now(timezone.utc).isoformat()
common = {
    'label': 'Russell Mitchell event records',
    'files': [{'label': f'russellmitchell_{s.lower()}.json'} for s in totals],
    'filters': ['Scenario: russellmitchell'],
    'caveats': ['Each JSON record counts as one event; Wazuh and AMiner produce different kinds of records.',
                'AMiner counts include training-mode records.'],
    'evidenceFlow': [{'kind': 'validation', 'title': 'Aggregation checks',
                     'detail': f'Parsed {totals["Wazuh"]:,} Wazuh and {totals["AMiner"]:,} AMiner records with valid timestamps. Hourly counts reconcile to source totals. Every AMiner record has exactly one event timestamp.'}],
}
for name, title, rows, chart in [
    ('russell-hourly', 'Russell Mitchell · hourly events', hour_rows,
     {'type': 'line', 'x': 'hour', 'y': 'events', 'series': 'source', 'xLabel': 'January 2022 · hour start (UTC)', 'yLabel': 'Events per hour', 'startAtZero': True}),
    ('russell-attacks', 'Events within labeled attack windows', attack_rows,
     {'type': 'horizontalBar', 'x': 'attack', 'y': 'events', 'series': 'source', 'xLabel': 'Event records', 'yLabel': 'Attack window', 'startAtZero': True}),
]:
    source = json.loads(json.dumps(common))
    if name == 'russell-hourly':
        source['metricDefinitions'] = [{'name': 'Hourly events', 'definition': 'Hourly events count all source records by UTC hour, using @timestamp for Wazuh and LogData.Timestamps for AMiner.'}]
        source['caveats'].append('The last hour is partial; source records end before 24:00 UTC on January 24.')
        cols = ['hour', 'source', 'events']
        period = 'January 21–24, 2022 (UTC)'
    else:
        source['files'].append({'label': 'labels.csv'})
        source['metricDefinitions'] = [{'name': 'Attack-window events', 'definition': 'Attack-window events count source records whose event timestamp lies in a Russell Mitchell labeled interval, including its start and excluding its end.'}]
        source['caveats'] += ['Timing overlap with an attack window does not establish a true positive or detection accuracy.', 'Attack windows have different durations, so these counts are not event rates.']
        cols = ['attack', 'source', 'events', 'duration_seconds', 'start_utc', 'end_utc']
        period = 'January 24, 2022 (UTC)'
    payload = {'schemaVersion': 1, 'id': name, 'title': title, 'chart': chart, 'rows': rows,
               'columns': cols, 'source': source, 'generatedAt': captured,
               'height': 360 if name == 'russell-hourly' else 440}
    (OUT / f'{name}.json').write_text(json.dumps(payload))
    receipt = {'schemaVersion': 1, 'items': [{'id': name, 'title': title, 'queries': [{
        'id': f'{name}-aggregation', 'source': source, 'rows': rows, 'columns': cols,
        'reportingPeriod': period, 'capturedAt': captured,
        'preview': {'kind': 'aggregate', 'note': 'Complete aggregated chart rows; raw log messages are excluded.'}
    }]}]}
    (OUT / f'{name}-sources.json').write_text(json.dumps(receipt))

print(json.dumps({'total_events': totals, 'daily': daily, 'inside_attack_windows': {s: sum(c.values()) for s,c in attacks.items()},
                  'per_attack': attacks, 'hour_rows': len(hour_rows), 'attack_rows': len(attack_rows)}, indent=2))
