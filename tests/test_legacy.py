import unittest
from unittest.mock import patch
import legacy


class LegacyTests(unittest.TestCase):
    def test_homepage_keeps_other_products_exact(self):
        old='SafeFileManager 1.3.0 <a href="oss/index.html">image</a><a href="oss/index.html">Open source section with SystemRescueImage</a> RAC'
        new=legacy.home(old)
        self.assertIn('SafeFileManager 1.3.0',new);self.assertTrue(new.endswith(' RAC'))
        self.assertEqual(new.count(legacy.URL),2)
        for wrong in (old.replace('oss/index.html','elsewhere'),old+old):
            with self.assertRaises(ValueError):legacy.home(wrong)

    def test_no_local_archive_or_page_mutation(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('legacy.bundle') as bundle:
            with self.assertRaises(RuntimeError):legacy.run('a'*10,'b'*10,'c'*10,'x',{},'y')
        bundle.assert_not_called()
