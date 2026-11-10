from pathlib import Path
import base64
import json
import hashlib
import types
import unittest
from unittest.mock import patch
import host
from support import workspace


class HostTests(unittest.TestCase):
    def test_preparation_keeps_logs_open_and_restores_existing_service_policy(self):
        with workspace() as folder:
            policy=folder/'policy';policy.write_bytes(b'original policy')
            def apt(argv,**kwargs):
                if '--simulate' in argv:return types.SimpleNamespace(stdout='Inst guestfish (1 Debian [amd64])\n',stderr='')
                kwargs['stdout'].write('bounded apt fixture\n')
                return types.SimpleNamespace(returncode=0)
            sha=hashlib.sha256(Path(host.__file__).read_bytes()).hexdigest()
            with patch.object(host,'SETUP',folder),patch.object(host,'POLICY',policy),\
                 patch.object(host.socket,'gethostname',return_value=host.HOSTNAME),patch.object(host.os,'geteuid',return_value=0),\
                 patch.object(host,'resources'),patch.object(host.subprocess,'run',side_effect=apt):
                self.assertEqual(host.install('debrescuestick-tools-012345abcd',sha),0)
            self.assertEqual(policy.read_bytes(),b'original policy')

    def test_durable_service_policy_restore_and_concurrent_edit_preservation(self):
        with workspace() as folder:
            unit='debrescuestick-tools-012345abcd';policy=folder/'policy';policy.write_bytes(b'original')
            info=policy.stat();data={'existed':True,'data':base64.b64encode(b'original').decode(),
              'mode':info.st_mode & 0o777,'uid':info.st_uid,'gid':info.st_gid,'atime_ns':info.st_atime_ns,'mtime_ns':info.st_mtime_ns}
            (folder/(unit+'-policy.json')).write_text(json.dumps(data));policy.write_bytes(host.DENY)
            with patch.object(host,'SETUP',folder),patch.object(host,'POLICY',policy):
                self.assertTrue(host.restore_policy(unit)['restored']);self.assertEqual(policy.read_bytes(),b'original')
                policy.write_bytes(b'newer edit');self.assertTrue(host.restore_policy(unit)['restored'])
                self.assertEqual(policy.read_bytes(),b'newer edit')
                (folder/(unit+'-policy-restored.json')).unlink()
                self.assertFalse(host.restore_policy(unit)['restored']);self.assertEqual(policy.read_bytes(),b'newer edit')

    def test_exact_actual_generated_unit_name_and_foreign_refusal(self):
        self.assertEqual(host.own_unit('debrescuestick-tools-012345abcd'),'debrescuestick-tools-012345abcd')
        for name in ('','apache2','debrescuestick-tools-../escape','debrescuestick-tools-012345abcg'):
            with self.assertRaises(ValueError):host.own_unit(name)

    def test_only_new_packages_no_existing_upgrade_or_removal(self):
        self.assertEqual(host.changes('Inst qemu (1:7.2 Debian [amd64])\nInst ovmf (2022 Debian [all])'),{'qemu':'1:7.2','ovmf':'2022'})
        for raw in ('Remv apache2 [2.4]','Inst apache2 [2.4] (2.5 Debian [amd64])','Inst bad syntax'):
            with self.assertRaises(RuntimeError):host.changes(raw)

    def test_wrong_host_refused_before_file_or_package_operations(self):
        with patch.object(host.socket,'gethostname',return_value='aicoder2'),patch.object(Path,'open') as opening,\
             patch.object(host.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):host.install('bad','bad')
        opening.assert_not_called();run.assert_not_called()


if __name__=='__main__':unittest.main()
