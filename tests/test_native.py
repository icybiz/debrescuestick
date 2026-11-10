from pathlib import Path
import unittest
from unittest.mock import patch
import native


class NativeTests(unittest.TestCase):
    def test_exact_own_probe_and_local_rejection_before_disk_or_guest(self):
        self.assertEqual(native.own('debrescuestick-probe-012345abcd'),'debrescuestick-probe-012345abcd')
        for name in ('','apache2','debrescuestick-probe-../escape'):
            with self.assertRaises(ValueError):native.own(name)
        with patch.object(native.socket,'gethostname',return_value='aicoder2'),patch.object(Path,'mkdir') as mkdir,\
             patch.object(native.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):native.run('debrescuestick-probe-012345abcd','unused')
        mkdir.assert_not_called();run.assert_not_called()


if __name__=='__main__':unittest.main()
