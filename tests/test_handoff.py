import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

import extract
import handoff
from support import workspace


class HandoffTests(unittest.TestCase):
    def fixture(self):
        record = {'reference_schema': 'drs-extraction-reference-v1', 'success': True,
                  'resources_returned': True, 'template_sha256': extract.TEMPLATE,
                  'raw_bytes': extract.RAW_SIZE, 'raw_sha256': 'a' * 64, 'remote_phase': 'complete',
                  'systemd': {'Result': 'success', 'ExecMainStatus': '0', 'ActiveState': 'inactive', 'MainPID': '0'},
                  'job': {'id': 'b' * 48, 'sha256': 'c' * 64, 'bytes': 1200000000,
                          'created': 100, 'expires': 7300, 'state': 'ready'}}
        logs = {'run.log': 'image.zip: OK\n', 'python.log': 'Done testing\n',
                'bsd-version.log': 'bsdtar 3.7.4', 'seven-version.log': '7-Zip 26.06'}
        for name in ('bsd', 'seven'):
            logs[name + '.sha'] = 'a' * 64 + '  -\n'
            logs[name + '.bytes'] = str(extract.RAW_SIZE) + ' bytes copied\n'
        return record, logs

    def test_only_same_complete_clean_fresh_reference_is_accepted(self):
        record, logs = self.fixture()
        self.assertEqual(handoff.reference(record, logs, 200), record['job'])
        for field, value in (('reference_schema', 'other'), ('success', False), ('resources_returned', False),
                             ('template_sha256', 'd' * 64), ('raw_bytes', 4), ('remote_phase', 'running')):
            bad = copy.deepcopy(record); bad[field] = value
            with self.assertRaises(ValueError):
                handoff.reference(bad, logs, 200)
        for field, value in (('expires', 300), ('created', 201), ('state', 'queued'), ('id', '../escape'), ('bytes', 2**32)):
            bad = copy.deepcopy(record); bad['job'][field] = value
            with self.assertRaises(ValueError):
                handoff.reference(bad, logs, 200)

    def test_each_decoder_hash_length_identity_and_zip_crc_must_be_proven(self):
        record, logs = self.fixture()
        for name, value in [('bsd.sha', 'd' * 64 + ' -'), ('seven.bytes', '3 bytes copied'),
                            ('bsd-version.log', 'unknown'), ('seven-version.log', 'unknown'),
                            ('run.log', ''), ('python.log', 'corrupt')]:
            bad = {**logs, name: value}
            with self.assertRaises(ValueError):
                handoff.reference(record, bad, 200)
        with self.assertRaises(ValueError):
            handoff.reference(record, {**logs, 'bsd.bytes': logs['bsd.bytes'] * 2}, 200)

    def test_small_staging_bundle_binds_manifest_scripts_url_and_launcher(self):
        record, logs = self.fixture()
        with workspace() as root:
            for name in ('explorer.ps1', 'receive.ps1'):
                (root / name).write_text('# synthetic own script\n')
            receipt = root / 'run.json'; receipt.write_text(json.dumps(record))
            for name, raw in logs.items():
                (root / name).write_text(raw)
            with patch.object(handoff, 'ROOT', root), patch('extract.request', return_value=record['job']):
                result = handoff.prepare(receipt, now=200)
            folder = Path(result['folder'])
            raw = (folder / 'manifest.json').read_bytes(); manifest = json.loads(raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), result['manifest_sha256'])
            self.assertEqual(manifest['archive']['url'], extract.ORIGIN + '/download/' + record['job']['id'])
            self.assertEqual(manifest['image']['sha256'], record['raw_sha256'])
            self.assertIn(result['manifest_sha256'], (folder / 'start.cmd').read_text())
            self.assertIn('DRS_REPORT_PATH', (folder / 'start.cmd').read_text())
            self.assertFalse(result['nativeWindowsTested'])
            with zipfile.ZipFile(folder / 'payload.zip') as archive:
                self.assertEqual(set(archive.namelist()), {'manifest.json', 'start.cmd', 'explorer.ps1', 'receive.ps1'})
                self.assertIsNone(archive.testzip())
                for name, sha in result['files'].items():
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), sha)
            self.assertLess((folder / 'payload.zip').stat().st_size, 65536)

    def test_live_authority_drift_refused_before_any_payload_is_created(self):
        record, logs = self.fixture()
        with workspace() as root:
            receipt = root / 'run.json'; receipt.write_text(json.dumps(record))
            for name, raw in logs.items():
                (root / name).write_text(raw)
            with patch.object(handoff, 'ROOT', root), patch('extract.request', return_value={**record['job'], 'sha256': 'f' * 64}):
                with self.assertRaises(ValueError):
                    handoff.prepare(receipt, now=200)
            self.assertFalse((root / 'build').exists())

    def test_failed_reference_pipeline_stops_only_the_exact_submitted_unit(self):
        with workspace() as root:
            folder = root / 'artifacts' / ('extract-' + 'a' * 10); folder.mkdir(parents=True)
            record = {'unit': 'debrescuestick-extract-' + 'a' * 10 + '.service',
                      'remote_root': '/tmp/debrescuestick-extract-' + 'a' * 10}
            (folder / 'run.json').write_text(json.dumps(record))
            failed = {'systemd': {'ActiveState': 'failed'}, 'success': False}
            with patch.object(handoff, 'ROOT', root), patch('extract.start', return_value={'key': 'a' * 10}), \
                    patch('extract.status', return_value=failed), patch('extract.finish') as finish, \
                    patch('extract.remote') as remote, patch('handoff.prepare') as prepare:
                with self.assertRaises(RuntimeError):
                    handoff.new()
                remote.assert_called_once_with('systemctl stop ' + record['unit'])
                finish.assert_called_once_with('a' * 10)
                prepare.assert_not_called()

    def test_successful_reference_is_cleaned_before_vm_staging(self):
        with workspace() as root:
            folder = root / 'artifacts' / ('extract-' + 'a' * 10); folder.mkdir(parents=True)
            (folder / 'run.json').write_text('{"resources_returned":true}')
            events = []
            with patch.object(handoff, 'ROOT', root), patch('extract.start', return_value={'key': 'a' * 10}), \
                    patch('extract.status', return_value={'systemd': {'ActiveState': 'inactive'}, 'success': True}), \
                    patch('extract.finish', side_effect=lambda token: events.append('clean')), \
                    patch('handoff.prepare', side_effect=lambda path: events.append('stage')):
                handoff.new()
            self.assertEqual(events, ['clean', 'stage'])
