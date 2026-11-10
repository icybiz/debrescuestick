import json
import os
import unittest
from unittest.mock import patch

import qa_clean
from support import workspace


class ReturnTests(unittest.TestCase):
    def fixture(self, root):
        root.chmod(0o700)
        (root / 'result.json').write_text(json.dumps({'template_job': 'a' * 10, 'success': True, 'finished': 1}))
        (root / 'bios').mkdir()
        (root / 'bios/result.json').write_text('{"qemu_exit":0}')
        job = root / 'jobs' / ('b' * 48)
        job.mkdir(parents=True)
        (job / '.owner').write_text(json.dumps({'job': job.name, 'schema': 'drs-job-v1'}))
        (job / 'image.img').write_bytes(b'synthetic tiny disk')
        (root / 'key-a').write_text('synthetic ephemeral secret')
        return job

    def test_only_owned_temporary_data_selected_and_proofs_retained(self):
        with workspace() as root:
            job = self.fixture(root)
            self.assertEqual(set(qa_clean.targets(root, os.getuid())), {job / 'image.img', root / 'key-a'})
            for path in qa_clean.targets(root, os.getuid()):
                path.unlink()
            self.assertTrue((root / 'result.json').exists())
            self.assertTrue((job / '.owner').exists())
            self.assertEqual(qa_clean.targets(root, os.getuid()), [])

    def test_live_guest_foreign_marker_and_link_are_refused(self):
        with workspace() as root:
            job = self.fixture(root)
            (root / 'bios/result.json').write_text('{"qemu_exit":null}')
            with self.assertRaises(ValueError):
                qa_clean.targets(root, os.getuid())
            (root / 'bios/result.json').write_text('{"qemu_exit":0}')
            (job / '.owner').write_text('{}')
            with self.assertRaises(ValueError):
                qa_clean.targets(root, os.getuid())
            (job / '.owner').write_text(json.dumps({'job': job.name, 'schema': 'drs-job-v1'}))
            (root / 'key-a').unlink()
            (root / 'key-a').symlink_to(job / 'image.img')
            with self.assertRaises(ValueError):
                qa_clean.targets(root, os.getuid())
            self.assertEqual((job / 'image.img').read_bytes(), b'synthetic tiny disk')

    def test_local_host_refused_before_cleanup_or_unit_operation(self):
        with patch('base.socket.gethostname', return_value='aicoder2'), patch('qa_clean.targets') as targets, \
                patch('qa_clean.subprocess.check_output') as systemctl:
            with self.assertRaises(RuntimeError):
                qa_clean.run('a' * 10, 'b' * 10)
            targets.assert_not_called()
            systemctl.assert_not_called()
