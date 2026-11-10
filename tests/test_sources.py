import unittest
from unittest.mock import patch
import sources


class SourceTests(unittest.TestCase):
    def test_actual_source_versions_and_complete_dsc(self):
        rows=sources.inventory('example:amd64\t2\texample\t1:2-3\nexample-doc\t2\texample\t1:2-3\n')
        self.assertEqual(rows,[('example','1:2-3')])
        text='Source: example\nVersion: 1:2-3\nChecksums-Sha256:\n '+'a'*64+' 42 example_2.orig.tar.xz\n-----BEGIN PGP SIGNATURE-----\n'
        self.assertEqual(sources.dsc_files(text,*rows[0]),[{'name':'example_2.orig.tar.xz','sha256':'a'*64,'bytes':42}])
        for bad in (text.replace('1:2-3','2-3'),text.replace('example_2.orig.tar.xz','../escape'),text.replace(' 42 ',' 0 ')):
            with self.assertRaises(ValueError):sources.dsc_files(bad,*rows[0])

    def test_no_local_source_archive_work(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('base.digest') as digest:
            with self.assertRaises(RuntimeError):sources.run('a'*10,'b'*10,'x')
        digest.assert_not_called()
