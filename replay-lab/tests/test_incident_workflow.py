import copy
import tempfile
import time
import unittest
from pathlib import Path
from test_pipeline import wazuh
from telemetry import normalize
from engine import OnlineEngine
from incident_workflow import Suppressions, incident
from benchmark import compare


def event(line, second=0, host='intranet-server', src='192.0.2.1', dst='192.0.2.2', raw='nmap port scan'):
    e = normalize(wazuh(raw, f'2022-01-24T03:00:{second:02}Z', predecoder={'hostname': host}), 'test_wazuh.json', line)
    e.update(src=src, dst=dst, evidence_key=f'event-{line}')
    return e


class WorkflowTests(unittest.TestCase):
    def test_destination_source_chain_and_evidence(self):
        engine = OnlineEngine()
        engine.ingest(event(1))
        engine.ingest(event(2, 1, host='second-host', src='192.0.2.2', dst='192.0.2.3'))
        chain = incident(engine, 'g1')
        self.assertEqual(len(chain['timeline']), 2)
        self.assertEqual(chain['edges'][0]['relationship'], 'inferred')
        self.assertEqual(len(chain['edges'][0]['evidence_ids']), 2)
        self.assertTrue(chain['edges'][0]['confirmed_evidence'])
        e = event(3, 2, host='third-host'); e['scenario'] = 'other'
        engine.ingest(e)
        self.assertEqual(len(engine.edges), 1)

    def test_operational_edge_after_training_samples_fill(self):
        engine = OnlineEngine()
        for i in range(7):
            e = event(i+1, i); e['training'] = True; engine.ingest(e)
        engine.ingest(event(8, 7))
        e = event(9, 8, raw='Jan 24 03:00:08 intranet-server su: Successful su for root by www-data')
        engine.ingest(e)
        edge = next(iter(engine.edges.values()))
        self.assertEqual(edge['evidence_ids'][0], engine.groups['g1']['latest_operational_alert'])
        self.assertTrue(any(not e['training'] for e in engine.groups['g1']['evidence']))

    def test_suppression_reopens_for_lateral_evidence_and_persists(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Suppressions(Path(tmp) / 'rules.json')
            engine = OnlineEngine(); engine.ingest(event(1))
            g = engine.groups['g1']
            with self.assertRaises(ValueError):
                store.approve(g, '', 'benign', time.time()+60)
            rule = store.approve(g, 'Analyst', 'Approved scan evidence', time.time()+60)
            self.assertTrue(store.status(g, engine.groups.values())['suppressed'])
            engine.ingest(event(2, 1, host='second-host', src='192.0.2.2', dst='192.0.2.3'))
            self.assertTrue(store.status(g, engine.groups.values())['reopened'])
            restored = Suppressions(store.path)
            self.assertFalse(restored.rules[0]['active'])
            self.assertEqual(restored.rules[0]['audit'][-1]['action'], 'reopened')
            restored.revoke(rule['id'], 'Analyst')
            self.assertEqual(restored.rules[0]['audit'][-1]['action'], 'unsuppressed')

    def test_expiry_new_technique_and_no_detector_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = Suppressions(Path(tmp)/'rules.json')
            engine = OnlineEngine(); engine.ingest(event(1))
            g = engine.groups['g1']; before = copy.deepcopy(engine.timeline)
            rule = store.approve(g, 'Analyst', 'Reviewed benign case', time.time()+60)
            rule['expires'] = time.time()-1
            self.assertFalse(store.status(g, engine.groups.values())['suppressed'])
            rule['expires'] = time.time()+60
            g['rules']['novel-rule'] = 1
            self.assertTrue(store.status(g, engine.groups.values())['reopened'])
            self.assertEqual(engine.timeline, before)

    def test_benchmark_labels_after_replay_and_reviewed_benign_only(self):
        events = [event(1), event(2, 1), event(3, 2)]
        for e in events: e['level'] = 12
        consumed = []
        def stream():
            for e in events:
                consumed.append(e['id']); yield e
        def windows():
            self.assertEqual(len(consumed), 3)
            return [{'scenario': 'test', 'attack': 'network_scans', 'start': events[0]['timestamp'], 'end': events[-1]['timestamp']+1},
                    {'scenario': 'test', 'attack': 'dnsteal', 'start': events[-1]['timestamp']+2, 'end': events[-1]['timestamp']+3}]
        reviews = [{'status':'Confirmed false positive', 'notes':'Approved scanner', 'evidenceIds':[events[0]['id']]},
                   {'status':'Suspected', 'notes':'?', 'evidenceIds':[events[1]['id']]}]
        result, _ = compare(stream(), windows, reviews)
        raw = result['methods']['raw_severity']; correlated = result['methods']['time_correlation']
        self.assertEqual(raw['review_items'], 3)
        self.assertEqual(correlated['review_items'], 1)
        self.assertEqual(raw['attack_window_review_coverage']['covered'], 1)
        self.assertEqual(len(raw['missed_windows']), 1)
        self.assertEqual(raw['reviewed_benign']['cases'], 1)
        self.assertEqual(raw['detection_latency_seconds']['median'], 0)
