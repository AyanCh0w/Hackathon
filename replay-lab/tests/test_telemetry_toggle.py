"""Native telemetry selection must affect preparation, replay and evidence access."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class TelemetryToggleTests(unittest.TestCase):
    def test_alerts_only_cache_and_replay_exclude_native_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'ait_ads').mkdir()
            inputs = root / 'inputs'
            inputs.mkdir()
            alert = {'@timestamp': '2022-01-24T03:00:00Z', 'full_log': 'routine',
                     'rule': {'level': 3, 'description': 'alert'}}
            (root / 'ait_ads/russellmitchell_wazuh.json').write_text(json.dumps(alert) + '\n')
            (root / 'ait_ads/russellmitchell_aminer.json').write_text('')
            native = {'timestamp': '2022-01-24T04:00:00Z', 'host': 'intranet', 'raw': 'native-only'}
            (inputs / 'russellmitchell.jsonl').write_text(json.dumps(native) + '\n')
            with patch.object(server, 'ROOT', root), patch.object(server, 'INPUTS', inputs), \
                    patch.object(server, 'CACHE', root / 'cache'), patch.object(server, 'CATALOG', {}):
                with patch.object(server, 'normalize_external', side_effect=AssertionError('Native input read')):
                    server.prepare_worker('russellmitchell', False)
                alerts = server.CATALOG['russellmitchell:alerts']
                self.assertEqual(alerts['status'], 'ready')
                self.assertEqual(alerts['total'], 1)
                self.assertNotIn('telemetry', alerts['sources'])
                server.prepare_worker('russellmitchell', True)
                full = server.CATALOG['russellmitchell']
                self.assertEqual(full['total'], 2)
                self.assertNotEqual(alerts['cache'], full['cache'])
                run = server.Run(['russellmitchell'], 1, 'events', False)
                run.elapsed = 1
                run.loop()
                self.assertEqual(run.status, 'complete')
                self.assertEqual(run.engine.processed, 1)
                self.assertFalse(run.snapshot()['include_telemetry'])
                self.assertEqual(run.meta['end_ts'], alerts['end_ts'])

    def test_reuses_existing_alerts_only_cache_without_reading_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / 'cache'
            old = cache / 'alerts-only'
            old.mkdir(parents=True)
            legacy = old / f'russellmitchell-v{server.VERSION}.sqlite3'
            import sqlite3
            with sqlite3.connect(legacy) as db:
                db.execute('CREATE TABLE events(record_id TEXT)')
                db.execute('CREATE TABLE metadata(key TEXT, value TEXT)')
                db.executemany('INSERT INTO metadata VALUES (?, ?)', [
                    ('fingerprint', 'validated-signature'),
                    ('summary', json.dumps({'scenario': 'russellmitchell', 'total': 45544}))])
            with patch.object(server, 'CACHE', cache), patch.object(server, 'CATALOG', {}), \
                    patch.object(server, 'fingerprint', return_value='signature'), \
                    patch.object(server, 'source_files', side_effect=AssertionError('Inputs reread')):
                # Match the exact serialized fingerprint used by preparation.
                with sqlite3.connect(legacy) as db:
                    db.execute("UPDATE metadata SET value=? WHERE key='fingerprint'", (json.dumps('signature'),))
                server.prepare_worker('russellmitchell', False)
                meta = server.CATALOG['russellmitchell:alerts']
                self.assertEqual(meta['status'], 'ready')
                self.assertEqual(meta['total'], 45544)
                self.assertFalse(meta['include_telemetry'])

    def test_option_requires_boolean(self):
        self.assertTrue(server.telemetry_option({}))
        self.assertFalse(server.telemetry_option({'include_telemetry': False}))
        with self.assertRaises(ValueError):
            server.telemetry_option({'include_telemetry': 'false'})


if __name__ == '__main__':
    unittest.main()
