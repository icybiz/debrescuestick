import unittest
from unittest.mock import patch
import qualify


class QualificationTests(unittest.TestCase):
    def test_qa_uses_separate_unit_and_rejects_unknown_tokens(self):
        self.assertEqual(qualify.qa_unit('a'*10),'debrescuestick-qa-worker-'+'a'*10)
        self.assertNotEqual(qualify.qa_unit('a'*10),'debrescuestick-worker')
        for bad in ('','../x','a'*9,'A'*10):
            with self.assertRaises(ValueError):qualify.qa_unit(bad)

    def test_local_native_refusal_precedes_file_access(self):
        with patch('worker.socket.gethostname',return_value='aicoder2'),patch('qualify.os.link') as link:
            with self.assertRaises(RuntimeError):qualify.run('a'*10,'b'*10,'x')
        link.assert_not_called()

    def test_port_comes_only_from_owned_monitor(self):
        self.assertEqual(43210,qualify.forward_port('VLAN 0 (net0):\n  TCP[HOST_FORWARD] 13 127.0.0.1 43210 10.0.2.15 22 0 0\n'))
        for value in ('','TCP[HOST_FORWARD] 13 0.0.0.0 22 10.0.2.15 22 0 0',
                      'TCP[HOST_FORWARD] 13 127.0.0.1 0 10.0.2.15 22 0 0',
                      'TCP[HOST_FORWARD] 13 127.0.0.1 22 10.0.2.15 80 0 0'):
            with self.assertRaises(ValueError):qualify.forward_port(value)
