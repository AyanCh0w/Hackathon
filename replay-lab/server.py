#!/usr/bin/env python3
"""Loopback replay service for selected alerts and optional native telemetry."""
from __future__ import annotations

import argparse
import copy
import heapq
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from engine import OnlineEngine, FAMILIES
from telemetry import normalize, normalize_external, SCENARIOS, VERSION
from detection import RULES, RULES_VERSION
from investigation import review, public_record
from telemetry import CAPABILITIES
from ai_analysis import analyze, AnalysisError, load_env

ROOT = Path(__file__).resolve().parent
# Support the original workspace layout when its data has not been moved yet.
if not (ROOT / 'ait_ads').is_dir() and (ROOT.parent / 'ait_ads').is_dir():
    ROOT = ROOT.parent
STATIC = Path(__file__).resolve().parent / 'static'
CACHE = Path(__file__).resolve().parent / '.cache'
INPUTS = Path(__file__).resolve().parent / 'telemetry-inputs'
CATALOG, RUNS = {}, {}
CATALOG_LOCK = threading.RLock()


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace('+00:00', 'Z')


def selected_scenarios(body):
    names = body.get('scenarios', [body.get('scenario', '')])
    if not isinstance(names, list) or not names or len(names) > len(SCENARIOS) or any(name not in SCENARIOS for name in names) or len(set(names)) != len(names):
        raise ValueError('Select one or more distinct datasets from the eight available scenarios')
    return [name for name in SCENARIOS if name in names]


def source_files(scenario):
    sources = [('wazuh', ROOT / 'ait_ads' / (scenario + '_wazuh.json')),
               ('aminer', ROOT / 'ait_ads' / (scenario + '_aminer.json'))]
    external = INPUTS / (scenario + '.jsonl')
    if external.is_file():
        sources.append(('telemetry', external))
    return sources


def fingerprint(scenario):
    return [VERSION] + [(str(path), path.stat().st_size, path.stat().st_mtime_ns)
                       for _, path in source_files(scenario)]


def prepare_worker(scenario):
    cache = CACHE / (scenario + f'-v{VERSION}.sqlite3')
    temporary = CACHE / (scenario + f'.{uuid.uuid4().hex}.building.sqlite3')
    db = None
    try:
        CACHE.mkdir(exist_ok=True)
        signature = json.dumps(fingerprint(scenario))
        legacy = CACHE / (scenario + '.sqlite3')
        if not cache.exists() and legacy.exists():
            try:
                with closing(sqlite3.connect(legacy)) as cached:
                    metadata = dict(cached.execute('SELECT key,value FROM metadata'))
                    fields = {row[1] for row in cached.execute('PRAGMA table_info(events)')}
                if metadata.get('fingerprint') == signature and 'record_id' in fields:
                    # The linked inode remains stable if an older server replaces its cache.
                    try:
                        os.link(legacy, cache)
                    except FileExistsError:
                        pass
            except sqlite3.Error:
                pass
        if cache.exists():
            with closing(sqlite3.connect(cache)) as cached:
                metadata = dict(cached.execute('SELECT key,value FROM metadata'))
            if metadata.get('fingerprint') == signature:
                with CATALOG_LOCK:
                    CATALOG[scenario] = {**json.loads(metadata['summary']), 'status': 'ready', 'cache': str(cache)}
                return
        temporary.unlink(missing_ok=True)
        db = sqlite3.connect(temporary)
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('PRAGMA synchronous=OFF')
        db.execute('CREATE TABLE events(ts REAL, source_order INTEGER, line INTEGER, payload TEXT, record_id TEXT, host TEXT, actor TEXT, capabilities INTEGER)')
        db.execute('CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT)')
        count, errors, by_source, bounds = 0, 0, {}, [float('inf'), float('-inf')]
        for order, (source, path) in enumerate(source_files(scenario)):
            filename = path.name
            source_count = 0
            buffer = []
            with path.open() as handle:
                for number, raw in enumerate(handle, 1):
                    if not raw.strip():
                        continue
                    try:
                        obj = json.loads(raw)
                        event = normalize_external(obj, scenario, filename, number) if source == 'telemetry' else normalize(obj, filename, number)
                    except (ValueError, TypeError, KeyError, IndexError):
                        errors += 1
                        continue
                    buffer.append((event['timestamp'], order, number, json.dumps(event, separators=(',', ':')), event['id'], event['host'], event['src'], event['capabilities']))
                    source_count += 1
                    count += 1
                    bounds[0] = min(bounds[0], event['timestamp'])
                    bounds[1] = max(bounds[1], event['timestamp'])
                    if len(buffer) >= 2000:
                        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)', buffer)
                        buffer.clear()
                        with CATALOG_LOCK:
                            CATALOG[scenario].update({'loaded': count, 'errors': errors, 'file': filename})
            if buffer:
                db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?)', buffer)
            by_source[source] = source_count
        db.execute('CREATE INDEX chronology ON events(ts,source_order,line)')
        db.execute('CREATE UNIQUE INDEX record_lookup ON events(record_id)')
        db.execute('CREATE INDEX host_time ON events(host,ts)')
        summary = {'scenario': scenario, 'total': count, 'errors': errors, 'sources': by_source,
                   'start': iso(bounds[0]), 'end': iso(bounds[1]), 'start_ts': bounds[0], 'end_ts': bounds[1],
                   'loaded': count, 'status': 'ready'}
        db.executemany('INSERT INTO metadata VALUES(?,?)', [('fingerprint', signature), ('summary', json.dumps(summary))])
        db.commit()
        db.close()
        db = None
        os.replace(temporary, cache)
        with CATALOG_LOCK:
            CATALOG[scenario] = {**summary, 'cache': str(cache)}
    except Exception as exc:
        with CATALOG_LOCK:
            CATALOG[scenario] = {'scenario': scenario, 'status': 'error', 'error': str(exc)}
    finally:
        if db:
            db.close()


def prepare(scenario):
    if scenario not in SCENARIOS:
        raise ValueError('Unknown scenario')
    with CATALOG_LOCK:
        if CATALOG.get(scenario, {}).get('status') not in ('loading', 'ready'):
            CATALOG[scenario] = {'scenario': scenario, 'status': 'loading', 'loaded': 0}
            threading.Thread(target=prepare_worker, args=(scenario,), daemon=True).start()
        return {k: v for k, v in CATALOG[scenario].items() if k != 'cache'}


class Run:
    def __init__(self, scenarios, duration, pacing):
        self.id = uuid.uuid4().hex[:12]
        self.scenarios = [scenarios] if isinstance(scenarios, str) else list(scenarios)
        self.scenario, self.duration, self.pacing = ', '.join(self.scenarios), duration, pacing
        self.dataset_meta = [dict(CATALOG[s]) for s in self.scenarios]
        self.meta = {'total': sum(m['total'] for m in self.dataset_meta),
                     'start_ts': min(m['start_ts'] for m in self.dataset_meta),
                     'end_ts': max(m['end_ts'] for m in self.dataset_meta)}
        self.meta.update({'start': iso(self.meta['start_ts']), 'end': iso(self.meta['end_ts'])})
        self.engine = OnlineEngine()
        self.lock = threading.RLock()
        self.status = 'running'
        self.elapsed = 0.0
        self.active_seconds = 0.0
        self.virtual = self.meta['start_ts']
        self.error = None
        self.verification = None
        self.revision = 0
        self.steps = 0
        self.analysis_gate = threading.Lock()
        self.analyses = {}
        self.dataset_counts = {name: 0 for name in self.scenarios}
        self.worker = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        self.worker.start()

    def loop(self):
        try:
            from contextlib import ExitStack
            with ExitStack() as stack:
                heap = []
                cursors = []
                for index, meta in enumerate(self.dataset_meta):
                    db = stack.enter_context(closing(sqlite3.connect(meta['cache'])))
                    cursor = db.execute('SELECT ts,source_order,line,payload FROM events ORDER BY ts,source_order,line')
                    cursors.append(cursor)
                    row = cursor.fetchone()
                    if row:
                        heapq.heappush(heap, (row[0], index, row[1], row[2], row[3]))
                def advance():
                    if not heap:
                        return None
                    row = heapq.heappop(heap)
                    next_row = cursors[row[1]].fetchone()
                    if next_row:
                        heapq.heappush(heap, (next_row[0], row[1], next_row[1], next_row[2], next_row[3]))
                    return row
                pending = advance()
                last = time.monotonic()
                while pending and self.status != 'cancelled':
                    now = time.monotonic()
                    delta, last = now - last, now
                    with self.lock:
                        if self.status == 'running':
                            self.active_seconds += delta
                            self.elapsed = min(self.duration, self.elapsed + delta)
                        stepped = self.steps > 0
                        if stepped:
                            self.steps -= 1
                        if self.status == 'paused' and not stepped:
                            budget = 0
                        elif stepped:
                            budget = 1
                        elif self.elapsed >= self.duration:
                            # Finish the actual cursor even if cached catalog totals
                            # changed after preparation. Completion requires EOF.
                            budget = 2400
                        elif self.pacing == 'events':
                            target = int(self.meta['total'] * self.elapsed / self.duration)
                            budget = min(2400, max(0, target - self.engine.processed))
                        else:
                            budget = 2400
                        if budget:
                            for _ in range(budget):
                                if not pending:
                                    break
                                parse_start = time.perf_counter()
                                event = json.loads(pending[4])
                                if self.pacing == 'time' and not stepped:
                                    target_time = self.meta['start_ts'] + (self.meta['end_ts'] - self.meta['start_ts']) * self.elapsed / self.duration
                                    if event['timestamp'] > target_time:
                                        break
                                self.engine.stages['normalize']['ms'] += (time.perf_counter() - parse_start) * 1000
                                self.engine.stages['normalize']['count'] += 1
                                self.engine.stages['normalize']['last'] = event['time']
                                event['_replay_elapsed'] = self.elapsed
                                self.engine.ingest(event)
                                self.dataset_counts[event['scenario']] += 1
                                self.virtual = event['timestamp']
                                pending = advance()
                            self.revision += 1
                        if not pending:
                            self.meta['total'] = self.engine.processed
                            for meta in self.dataset_meta:
                                meta['total'] = self.dataset_counts[meta['scenario']]
                            self.status = 'complete'
                            self.elapsed = self.duration
                            self.revision += 1
                            break
                    time.sleep(.001 if budget else .008)
        except Exception as exc:
            with self.lock:
                self.error, self.status = str(exc), 'error'
                self.revision += 1

    def snapshot(self):
        with self.lock:
            snapshot = self.engine.snapshot()
            return {**snapshot, 'id': self.id, 'scenario': self.scenario, 'status': self.status,
                    'scenarios': self.scenarios, 'dataset_counts': self.dataset_counts.copy(),
                    'dataset_totals': {m['scenario']: m['total'] for m in self.dataset_meta},
                    'elapsed': round(self.elapsed, 3), 'duration': self.duration, 'pacing': self.pacing,
                    'actual_elapsed': round(self.active_seconds, 3),
                    'virtual': iso(self.virtual), 'total': self.meta['total'], 'start': self.meta['start'],
                    'end': self.meta['end'], 'revision': self.revision, 'error': self.error,
                    'verification': self.verification}

    def action(self, action):
        with self.lock:
            if action == 'pause' and self.status == 'running':
                self.status = 'paused'
            elif action == 'resume' and self.status == 'paused':
                self.status = 'running'
            elif action == 'step' and self.status == 'paused':
                self.steps += 1
            elif action == 'cancel' and self.status in ('running', 'paused'):
                self.status = 'cancelled'
            else:
                raise ValueError('Action not available in this state')
            self.revision += 1

    def evidence(self, record_id):
        """Only IDs already ingested are addressable, including ties at the cutoff."""
        with self.lock:
            if not any(row[7] == record_id for row in self.engine.timeline):
                raise ValueError('Record not observed in this replay')
            name = record_id.split(':', 1)[0]
            meta = next((m for m in self.dataset_meta if m['scenario'] == name), None)
        if meta is None:
            raise ValueError('Record not in selected datasets')
        with closing(sqlite3.connect(meta['cache'])) as db:
            row = db.execute('SELECT payload FROM events WHERE record_id=?', (record_id,)).fetchone()
        if row is None:
            raise ValueError('Observed record unavailable in cache')
        return public_record(json.loads(row[0]))

    def members(self, gid, cursor=0, limit=50):
        if cursor < 0 or not 1 <= limit <= 50:
            raise ValueError('Invalid member cursor or page size')
        with self.lock:
            group = self.engine.groups.get(gid)
            if group is None:
                raise ValueError('Group not found')
            references, next_cursor = [], None
            for index in range(cursor, len(self.engine.timeline)):
                row = self.engine.timeline[index]
                if row[2] != gid:
                    continue
                references.append({'id': row[7], 'time': iso(row[0]), 'rule': row[6], 'training': bool(row[3])})
                if len(references) == limit:
                    next_cursor = index + 1
                    break
            return {'group': gid, 'members': references, 'next_cursor': next_cursor, 'total': group['count']}

    def investigate(self, gid, frozen=None):
        with self.lock:
            group = self.engine.groups.get(gid)
            if group is None:
                raise ValueError('Group not found')
            group = self.engine.public_group(group)
            cutoff = self.virtual
            prefix = len(self.engine.timeline)
            meta = next(m for m in self.dataset_meta if m['scenario'] == group['scenario'])
            if frozen is not None:
                group, cutoff, prefix = frozen
        def retrieve(field):
            if group['host'] == 'unresolved host':
                raise ValueError('Host unresolved; cross-host retrieval cannot be justified')
            start, end = group['last_ts'] - 300, min(cutoff, group['last_ts'] + 300)
            query = {'scenario': group['scenario'], 'host': group['host'], 'start': iso(start), 'end': iso(end), 'capability': field, 'limit': 50}
            with closing(sqlite3.connect(meta['cache'])) as db:
                rows = db.execute('SELECT record_id,payload FROM events WHERE host=? AND ts>=? AND ts<=? AND capabilities & ? != 0 ORDER BY ts,source_order,line LIMIT 51',
                                  (group['host'], start, end, CAPABILITIES[field])).fetchall()
            candidates = {row[0] for row in rows}
            with self.lock:
                allowed = {row[7] for row in self.engine.timeline[:prefix] if row[7] in candidates}
            records = [json.loads(payload) for record_id, payload in rows[:50] if record_id in allowed]
            return {'records': records, 'truncated': len(rows) > 50, 'query': query}
        return review(group, retrieve)

    def analysis_context(self, gid):
        """Freeze public node details and traces without reading future records or labels."""
        with self.lock:
            if gid not in self.engine.groups:
                raise ValueError('Group not found')
            group = copy.deepcopy(self.engine.public_group(self.engine.groups[gid]))
            cutoff, prefix = self.virtual, len(self.engine.timeline)
            members = [row for row in self.engine.timeline if row[2] == gid]
            edges = copy.deepcopy([e for e in self.engine.edges.values() if gid in (e['from'], e['to'])])
            neighbor_ids = {e['from'] if e['to'] == gid else e['to'] for e in edges}
            neighbors = [copy.deepcopy(self.engine.public_group(self.engine.groups[n])) for n in sorted(neighbor_ids)]
            histories = [self.engine.history, self.engine.signal_history, *self.engine.dataset_history.values(), *self.engine.dataset_signal_history.values()]
            decisions = {e['id']: copy.deepcopy(e) for history in histories for e in history if e.get('group') == gid}
            meta = next(m for m in self.dataset_meta if m['scenario'] == group['scenario'])
        # Include representatives plus a chronological sample spanning the whole episode.
        ids = {e['id'] for e in group['evidence']}
        if members:
            ids.update(members[round(i * (len(members) - 1) / 119)][7] for i in range(120))
        with closing(sqlite3.connect(meta['cache'])) as db:
            records = [public_record(json.loads(row[0])) for row in db.execute(
                'SELECT payload FROM events WHERE record_id IN (' + ','.join('?' for _ in ids) + ') ORDER BY ts,source_order,line', tuple(ids))]
        investigation = self.investigate(gid, (group, cutoff, prefix))
        context = {'snapshot': {'run': self.id, 'group': gid, 'processed': prefix, 'cutoff': iso(cutoff)},
                   'node': group, 'member_records': records, 'connections': edges, 'connected_nodes': neighbors,
                   'decision_trace': sorted(decisions.values(), key=lambda e: e['id'])[-100:],
                   'investigation_trace': investigation}
        # Bound cost without silently claiming complete raw-trace coverage.
        total_neighbors = len(neighbors)
        context['connected_nodes'] = neighbors[:20]
        for node in context['connected_nodes']:
            node['evidence'] = node['evidence'][:4]
        while len(json.dumps(context).encode()) > 180000 and context['member_records']:
            context['member_records'] = context['member_records'][::2] if len(context['member_records']) > 1 else []
        if len(json.dumps(context).encode()) > 240000:
            raise AnalysisError('This node has too much connected context for one analysis. Inspect its evidence directly.', 413)
        evidence = list(group['evidence']) + context['member_records']
        for node in context['connected_nodes']:
            evidence.extend(node['evidence'])
        for entry in investigation['ledger']:
            evidence.extend(entry.get('records', []))
        context['evidence_ids'] = sorted({e['id'] for e in evidence})
        context['coverage'] = {'total_members': len(members), 'included_members': len(context['member_records']),
                               'member_traces_sampled': len(context['member_records']) < len(members),
                               'connected_nodes_total': total_neighbors, 'connected_nodes_included': len(context['connected_nodes']),
                               'decision_entries_included': len(context['decision_trace']), 'decision_trace_retained_only': True,
                               'retrieval_queries': investigation['queries'], 'redacted': True}
        return context

    def ai_analysis(self, gid):
        if not self.analysis_gate.acquire(blocking=False):
            raise AnalysisError('An analysis is already running for this replay. Wait for it to finish, then retry.', 409)
        try:
            context = self.analysis_context(gid)
            key = (gid, context['snapshot']['processed'], os.environ.get('OPENAI_MODEL', 'gpt-6-astra'))
            if key not in self.analyses:
                result = analyze(context)
                if len(self.analyses) >= 24:
                    self.analyses.pop(next(iter(self.analyses)))
                self.analyses[key] = result
            return self.analyses[key]
        finally:
            self.analysis_gate.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        if '/api/stream' not in args[0]:
            print(fmt % args, flush=True)

    def send_json(self, value, status=200):
        body = json.dumps(value, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def run_for(self, query):
        key = query.get('id', [''])[0]
        if key not in RUNS:
            raise ValueError('Run not found')
        return RUNS[key]

    def do_GET(self):
        url = urlsplit(self.path)
        query = parse_qs(url.query)
        try:
            if url.path == '/api/catalog':
                with CATALOG_LOCK:
                    catalog = {k: {a: b for a, b in v.items() if a != 'cache'} for k, v in CATALOG.items()}
                return self.send_json({'scenarios': SCENARIOS, 'catalog': catalog, 'families': FAMILIES})
            if url.path == '/api/run':
                return self.send_json(self.run_for(query).snapshot())
            if url.path == '/api/rules':
                return self.send_json({'version': RULES_VERSION, 'rules': RULES, 'calibration': 'Experimental starting thresholds; no measured false-positive operating point.'})
            if url.path == '/api/evidence':
                return self.send_json({'record': self.run_for(query).evidence(query.get('record', [''])[0])})
            if url.path == '/api/group-members':
                return self.send_json(self.run_for(query).members(query.get('group', [''])[0], int(query.get('cursor', ['0'])[0])))
            if url.path == '/api/investigate':
                return self.send_json(self.run_for(query).investigate(query.get('group', [''])[0]))
            if url.path == '/api/group':
                run = self.run_for(query)
                with run.lock:
                    group = run.engine.groups.get(query.get('group', [''])[0])
                    if group is None:
                        raise ValueError('Group not found')
                    return self.send_json({'group': run.engine.public_group(group)})
            if url.path == '/api/stream':
                run = self.run_for(query)
                self.send_response(200)
                self.send_header('Content-Type', 'text/event-stream')
                self.send_header('Cache-Control', 'no-cache')
                self.send_header('Connection', 'close')
                self.end_headers()
                last = -1
                while True:
                    snapshot = run.snapshot()
                    if snapshot['revision'] != last:
                        self.wfile.write(('event: snapshot\ndata: ' + json.dumps(snapshot, separators=(',', ':')) + '\n\n').encode())
                        self.wfile.flush()
                        last = snapshot['revision']
                    if snapshot['status'] in ('complete', 'cancelled', 'error'):
                        break
                    time.sleep(.2)
                self.close_connection = True
                return
            name = '/index.html' if url.path == '/' else url.path
            from urllib.parse import unquote
            target = (STATIC / unquote(name).lstrip('/')).resolve()
            if not target.is_relative_to(STATIC) or not target.is_file():
                return self.send_json({'error': 'Not found'}, 404)
            body = target.read_bytes()
            types = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml'}
            self.send_response(200)
            self.send_header('Content-Type', types.get(target.suffix, 'application/octet-stream'))
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except ValueError as exc:
            self.send_json({'error': str(exc)}, 400)

    def do_POST(self):
        # This service only accepts same-origin or non-browser local requests.
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host', ''):
            return self.send_json({'error': 'Same-origin requests required'}, 403)
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length < 10000:
                raise ValueError('Invalid request size')
            body = json.loads(self.rfile.read(length))
            path = urlsplit(self.path).path
            if path == '/api/analyze-node':
                run = self.run_for({'id': [body.get('id', '')]})
                gid = body.get('group')
                if not isinstance(gid, str):
                    raise ValueError('Select a node to analyze')
                return self.send_json(run.ai_analysis(gid))
            if path == '/api/prepare':
                if 'scenarios' in body:
                    names = selected_scenarios(body)
                    return self.send_json({'datasets': [prepare(name) for name in names]})
                return self.send_json(prepare(body.get('scenario', '')))
            if path == '/api/start':
                scenarios = selected_scenarios(body)
                if any(CATALOG.get(s, {}).get('status') != 'ready' for s in scenarios):
                    return self.send_json({'error': 'Prepare scenario first'}, 409)
                duration = float(body.get('duration', 60))
                pacing = body.get('pacing', 'events')
                if not 1 <= duration <= 600 or pacing not in ('events', 'time'):
                    raise ValueError('Duration must be 1–600 seconds; pacing events or time')
                for old in RUNS.values():
                    if old.status in ('running', 'paused'):
                        old.action('cancel')
                run = Run(scenarios, duration, pacing)
                RUNS[run.id] = run
                # Keep completed sessions bounded, preserving the current run.
                for key in list(RUNS)[:-4]:
                    RUNS.pop(key, None)
                run.start()
                return self.send_json({'id': run.id, 'status': 'running'})
            if path in ('/api/action', '/api/verify'):
                run = self.run_for({'id': [body.get('id', '')]})
                if path == '/api/action':
                    run.action(body.get('action'))
                    return self.send_json(run.snapshot())
                with run.lock:
                    if run.status != 'complete':
                        return self.send_json({'error': 'Labels are sealed until replay completes'}, 409)
                    if run.verification is None:
                        from verification import verify
                        frozen = tuple(run.engine.timeline)
                        run.verification = verify(ROOT, run.scenarios, frozen)
                    return self.send_json(run.verification)
            return self.send_json({'error': 'Not found'}, 404)
        except AnalysisError as exc:
            self.send_json({'error': str(exc)}, exc.status)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_json({'error': str(exc)}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    load_env()
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8788)
    args = parser.parse_args()
    prepare('russellmitchell')
    service = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'Replay Lab: http://127.0.0.1:{args.port}', flush=True)
    service.serve_forever()


if __name__ == '__main__':
    main()
