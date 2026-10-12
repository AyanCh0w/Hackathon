import json
import sqlite3
import unittest
from pathlib import Path
from test_improvements import external
from engine import OnlineEngine
from telemetry import training_flag
from evaluate_security import fixtures, replay
from incident_workflow import incident


class SecurityTests(unittest.TestCase):
    def test_training_flags(self):
        for value in (False, 'false', '0', None): self.assertFalse(training_flag(value))
        for value in (True, 'true', '1'): self.assertTrue(training_flag(value))

    def test_wardbeck_operational_duplicate(self):
        engine = OnlineEngine()
        raw = 'type=SERVICE_STOP msg=audit(1642716748.499:500): unit=officia res=success'
        engine.ingest(external(training=True, raw=raw))
        engine.ingest(external(line=2, raw=raw))
        group = next(iter(engine.groups.values()))
        self.assertEqual(group['operational_unique'], 1)
        self.assertEqual(group['confidence'], 'medium')
        self.assertNotIn('Training mode', group['reason'])
        self.assertTrue(any(not e['training'] for e in group['evidence']))

    def test_dns_volume_duplicates_answers_and_encoding(self):
        engine = OnlineEngine()
        for i in range(100):
            engine.ingest(external(line=i+1, stamp=1642996800+i/10, src_ip='192.0.2.5', dns={'rrname':'www.example.org','rrtype':'A'}))
        self.assertEqual(engine.timeline[-1][6], 'dns.volume')
        duplicates = OnlineEngine()
        e = external(src_ip='192.0.2.5', dns={'rrname':'www.example.org','rrtype':'A'})
        for i in range(120): duplicates.ingest(e)
        self.assertEqual(duplicates.categories['dns'], 0)
        answer = external(dns={'type':'answer','rrname':'a'*60+'.example.org'})
        self.assertEqual(answer['dns_queries'], [])
        encoded = external(dns={'query':'0123456789abcdef0123456789abcdef.example.org'})
        self.assertEqual(OnlineEngine().ingest(encoded)['family'], 'dns')

    def test_scan_metrics(self):
        engine = OnlineEngine()
        for i in range(20):
            row = engine.ingest(external(line=i+1, stamp=1642996800+i, src_ip='192.0.2.5', dest_ip='192.0.2.8', dest_port=1000+i, proto='TCP', conn_state='S0', flow_id=str(i)))
        self.assertEqual(row['family'], 'recon')
        self.assertEqual(row['behavior_metrics']['connection_failures'], 20)
        self.assertEqual(row['behavior_metrics']['unique_destination_ports'], 20)

    def test_grouping_preserves_three_stages(self):
        benign, attacks = fixtures()
        _, b = replay(benign)
        engine, a = replay(attacks)
        view = incident(engine, 'g1')
        self.assertEqual(b['false_alerts'], 0)
        self.assertEqual(a['true_alerts'], 3000)
        self.assertEqual({r['technique'] for r in view['timeline']}, {'recon','execution','callback'})
        self.assertEqual(sum(g['count'] for g in view['groups']), 3000)
        self.assertTrue(all(r['evidence_ids'] for r in view['timeline']))
