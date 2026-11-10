import subprocess
import unittest
from unittest.mock import patch

import image


class ImageTests(unittest.TestCase):
    def test_cold_file_sizes_allow_cli_newlines_but_refuse_real_data(self):
        text='DRS_KEYS\n0\nDRS_MACHINE\n0\nDRS_PACKAGES\nDRS_SSH\nPasswordAuthentication no\n\nDRS_NETWORK\nDHCP=yes\n\nDRS_HOSTKEYS\n\nDRS_MARKER\nfalse\nDRS_END\n'
        image.cold_proof(text)
        for wrong in (text.replace('DRS_KEYS\n0','DRS_KEYS\n3'),text.replace('DRS_MACHINE\n0','DRS_MACHINE\n32'),
                      text.replace('DRS_HOSTKEYS\n\n','DRS_HOSTKEYS\n/etc/ssh/ssh_host_ed25519_key\n'),
                      text.replace('DRS_MARKER\nfalse','DRS_MARKER\ntrue')):
            with self.assertRaises(RuntimeError):image.cold_proof(wrong)

    def test_local_host_refused_before_image_access(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('base.digest') as digest:
            with self.assertRaisesRegex(RuntimeError,'assigned prox'):image.run('a'*10,'build','x')
        digest.assert_not_called()

    def test_guest_script_refuses_host_execution(self):
        result=subprocess.run(['sh',str(image.ROOT/'image/setup.sh')],capture_output=True,text=True)
        self.assertEqual(64,result.returncode)
        self.assertIn('isolated guestfs target',result.stderr)

    def test_source_bundle_is_complete(self):
        files,manifest,sha=image.bundle()
        self.assertEqual(set(files),set(manifest));self.assertEqual(64,len(sha))
        names=files['image/packages.txt'].decode().splitlines()
        self.assertIn('gddrescue',names);self.assertIn('linux-image-amd64',names)
        self.assertTrue(all(name and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789+-.' for c in name) for name in names))
