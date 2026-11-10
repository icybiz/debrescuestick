import unittest
from unittest.mock import patch
import retire


class RetirementTests(unittest.TestCase):
    def test_reject_foreign_identifiers(self):
        for name in ('','../escape','/','a'*48+'/next','.'*48):
            with self.assertRaises(ValueError):retire.job_id(name)
        self.assertEqual('a'*48,retire.job_id('a'*48))

    def test_no_local_disk_or_key_retirement(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('base.digest') as digest:
            with self.assertRaises(RuntimeError):retire.run('a'*10,'b'*10,'c'*10,'d'*10,'x','y')
        digest.assert_not_called()
