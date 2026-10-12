import copy
from contextlib import closing
import io
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ai_analysis
import server
from telemetry import normalize


def report(ref):
    return {'narrative_evidence_ids': [ref], 'answers': [{'question': 'Why escalated?', 'answer': 'Observed transition', 'status': 'supported', 'evidence_ids': [ref]}], 'summary': '<script>untrusted text</script>', 'assessment': 'investigate', 'confidence': 'low',
            'confidence_reason': 'Missing corroboration',
            'findings': [{'observation': 'Privilege transition', 'meaning': 'Check authorization', 'evidence_ids': [ref]}],
            'possible_explanations': ['Approved maintenance'],
            'next_steps': [{'priority': 'now', 'action': 'Check auth logs', 'why': 'Establish initiating identity',
                            'expected_result': 'Approved change or unauthorized identity', 'evidence_ids': [ref]}],
            'missing_evidence': ['Process ancestry'], 'escalation_criteria': 'Escalate if unauthorized.'}


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        cache = str(Path(self.temp.name) / 'events.sqlite3')
        self.events = [normalize({'@timestamp': f'2022-01-24T04:{i // 60:02}:{i % 60:02}Z',
                                 'full_log': 'Jan 24 04:00:00 intranet-server su: Successful su for jhall by www-data password=hidden-secret',
                                 'predecoder': {'hostname': 'intranet-server'}, 'rule': {'description': 'alert', 'level': 3}},
                                'russellmitchell_wazuh.json', i + 1) for i in range(160)]
        with closing(sqlite3.connect(cache)) as db:
            db.execute('CREATE TABLE events(ts REAL,source_order INTEGER,line INTEGER,payload TEXT,record_id TEXT,host TEXT,capabilities INTEGER)')
            db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?)',
                           [(e['timestamp'], 0, e['line'], json.dumps(e), e['id'], e['host'], e['capabilities']) for e in self.events])
            db.commit()
        meta = {'scenario': 'russellmitchell', 'cache': cache, 'total': 160, 'start_ts': self.events[0]['timestamp'], 'end_ts': self.events[-1]['timestamp']}
        with patch.dict(server.CATALOG, {'russellmitchell': meta}):
            self.run = server.Run('russellmitchell', 1, 'events')
        for event in self.events[:150]:
            self.run.engine.ingest(event)
        self.run.virtual = self.events[149]['timestamp']
        self.gid = next(iter(self.run.engine.groups))

    def tearDown(self):
        self.temp.cleanup()

    def test_frozen_context_sampling_redaction_and_no_future(self):
        before = copy.deepcopy(self.run.engine.timeline)
        context = self.run.analysis_context(self.gid)
        serialized = json.dumps(context)
        self.assertNotIn('hidden-secret', serialized)
        self.assertNotIn('_command', serialized)
        for event in self.events[150:]:
            self.assertNotIn(event['id'], serialized)
        self.assertEqual(context['coverage']['total_members'], 150)
        self.assertTrue(context['coverage']['member_traces_sampled'])
        self.assertIn(self.events[0]['id'], context['evidence_ids'])
        self.assertIn(self.events[149]['id'], context['evidence_ids'])
        self.assertEqual(self.run.engine.timeline, before)
        self.run.engine.ingest(self.events[150])
        self.assertEqual(context['node']['count'], 150)
        self.assertEqual(context['snapshot']['processed'], 150)

    def test_context_excludes_other_neighbors_and_broad_retrieval(self):
        base = copy.deepcopy(self.run.engine.groups[self.gid])
        for node_id, priority in [('direct', 'investigate'), ('context', 'context'),
                                  ('high', 'high'), ('indirect', 'investigate')]:
            node = copy.deepcopy(base)
            node.update(id=node_id, priority=priority)
            node['evidence'] = [dict(base['evidence'][0], id=node_id + '-evidence')]
            self.run.engine.groups[node_id] = node
        self.run.engine.edges = {
            'direct': {'from': self.gid, 'to': 'direct'},
            'context': {'from': 'context', 'to': self.gid},
            'high': {'from': self.gid, 'to': 'high'},
            'indirect': {'from': 'direct', 'to': 'indirect'},
        }
        with patch.object(self.run, 'investigate', side_effect=AssertionError('Unscoped retrieval')):
            context = self.run.analysis_context(self.gid)
        self.assertEqual([node['id'] for node in context['connected_nodes']], ['direct'])
        self.assertEqual(context['connections'], [{'from': self.gid, 'to': 'direct'}])
        self.assertIn('direct-evidence', context['evidence_ids'])
        for excluded in ('context', 'high', 'indirect'):
            self.assertNotIn(excluded + '-evidence', context['evidence_ids'])
        self.assertEqual(context['coverage']['retrieval_queries'], 0)

    def test_oversized_evidence_is_bounded_without_rejecting_analysis(self):
        group = self.run.engine.groups[self.gid]
        group['evidence'][0]['raw'] = 'large trace ' * 100000
        with closing(sqlite3.connect(self.run.dataset_meta[0]['cache'])) as db:
            for event in self.events[:150]:
                event['raw'] = 'large trace ' * 2000
                db.execute('UPDATE events SET payload=? WHERE record_id=?',
                           (json.dumps(event), event['id']))
            db.commit()
        context = self.run.analysis_context(self.gid)
        self.assertLess(len(json.dumps(context).encode()), 180000)
        self.assertGreater(context['coverage']['truncated_fields'], 0)
        self.assertIn(group['evidence'][0]['id'], context['evidence_ids'])
        self.assertTrue(context['coverage']['member_traces_sampled'])

    def test_demo_suppression_does_not_change_review_queue(self):
        from incident_workflow import Suppressions
        import time
        store = Suppressions(Path(self.temp.name) / 'suppression.json')
        group = next(iter(self.run.engine.groups.values()))
        group['actor'] = '192.0.2.1'
        store.approve(group, 'Reviewer', 'Reviewed maintenance', time.time()+60)
        before = copy.deepcopy(self.run.engine.snapshot()['review_queue'])
        with patch.object(server, 'SUPPRESSIONS', store):
            snapshot = self.run.snapshot()
            self.assertTrue(snapshot['suppression_demo_only'])
            self.assertEqual(snapshot['review_queue'], before)
            self.assertNotIn('suppression', snapshot['groups'][0])

    def test_provider_request_and_bound_citations(self):
        context = self.run.analysis_context(self.gid)
        answer = report(context['evidence_ids'][0])
        def response(request, timeout):
            payload = json.loads(request.data)
            self.assertFalse(payload['store'])
            self.assertTrue(payload['text']['format']['strict'])
            self.assertEqual(request.full_url, 'https://api.openai.com/v1/responses')
            self.assertNotIn('test-key', payload['input'])
            return io.BytesIO(json.dumps({'status': 'completed', 'model': 'test-model', 'output': [
                {'type': 'message', 'content': [{'type': 'output_text', 'text': json.dumps(answer)}]}]}).encode())
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}), patch.object(ai_analysis, 'urlopen', side_effect=response):
            self.assertEqual(ai_analysis.analyze(context)['analysis'], answer)
            answer['findings'][0]['evidence_ids'] = []
            with self.assertRaisesRegex(ai_analysis.AnalysisError, 'unsupported evidence'):
                ai_analysis.analyze(context)
            answer['findings'][0]['evidence_ids'] = ['invented']
            with self.assertRaisesRegex(ai_analysis.AnalysisError, 'unsupported evidence'):
                ai_analysis.analyze(context)

    def test_configuration_provider_failures_and_cache(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}):
            with self.assertRaisesRegex(ai_analysis.AnalysisError, 'not configured'):
                self.run.ai_analysis(self.gid)
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'test-key'}):
            for error, message in [(HTTPError('https://api.openai.com', 401, 'bad', {}, None), 'rejected'),
                                   (HTTPError('https://api.openai.com', 429, 'limit', {}, None), 'quota'),
                                   (URLError('timeout'), 'timed out')]:
                with patch.object(ai_analysis, 'urlopen', side_effect=error):
                    with self.assertRaisesRegex(ai_analysis.AnalysisError, message):
                        self.run.ai_analysis(self.gid)
        with patch.object(server, 'analyze', return_value={'analysis': 'test'}) as call:
            self.run.ai_analysis(self.gid)
            self.run.ai_analysis(self.gid)
            self.assertEqual(call.call_count, 1)
            self.run.engine.ingest(self.events[150])
            self.run.ai_analysis(self.gid)
            self.assertEqual(call.call_count, 2)
        self.run.analysis_gate.acquire()
        try:
            with self.assertRaisesRegex(ai_analysis.AnalysisError, 'already running'):
                self.run.ai_analysis(self.gid)
        finally:
            self.run.analysis_gate.release()

    def test_http_endpoint_missing_key_and_origin(self):
        service = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        url = f'http://127.0.0.1:{service.server_port}/api/analyze-node'
        try:
            with patch.dict(server.RUNS, {self.run.id: self.run}), patch.dict(os.environ, {'OPENAI_API_KEY': ''}):
                data = json.dumps({'id': self.run.id, 'group': self.gid}).encode()
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(url, data=data, headers={'Content-Type': 'application/json'}))
                self.assertEqual(caught.exception.code, 503)
                self.assertIn('OPENAI_API_KEY', caught.exception.read().decode())
                caught.exception.close()
                with self.assertRaises(HTTPError) as caught:
                    urlopen(Request(url, data=data, headers={'Origin': 'http://other.example'}))
                self.assertEqual(caught.exception.code, 403)
                caught.exception.close()
                for endpoint in ('/api/suppress', '/api/unsuppress'):
                    with self.assertRaises(HTTPError) as caught:
                        urlopen(Request(f'http://127.0.0.1:{service.server_port}{endpoint}', data=data,
                                        headers={'Content-Type': 'application/json'}))
                    self.assertEqual(caught.exception.code, 403)
                    self.assertIn('For demo only', caught.exception.read().decode())
                    caught.exception.close()
                with patch.object(server, 'analyze', return_value={'analysis': report(self.events[0]['id'])}):
                    with urlopen(Request(url, data=data, headers={'Content-Type': 'application/json'})) as response:
                        self.assertEqual(json.load(response)['analysis']['assessment'], 'investigate')
        finally:
            service.shutdown()
            service.server_close()
