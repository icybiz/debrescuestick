import unittest
from unittest.mock import patch
import inventory


class InventoryTests(unittest.TestCase):
    def test_signed_and_static_binaries_retain_embedded_source_versions(self):
        text='Package: signed-kernel\nVersion: 6.12-1\nSource: linux-signed (6.12+1)\nBuilt-Using: linux (= 6.12-1)\n\nPackage: static-tool\nVersion: 2\nStatic-Built-Using: library-a (= 1:3-4),\n library-b (= 5)\n'
        self.assertEqual(inventory.source_set(text),{('linux-signed','6.12+1'),('linux','6.12-1'),('static-tool','2'),('library-a','1:3-4'),('library-b','5')})
        with self.assertRaises(ValueError):inventory.source_set(text.replace('(= 6.12-1)','(>= 6.12-1)'))

    def test_local_image_read_is_refused(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('inventory.subprocess.run') as process:
            with self.assertRaises(RuntimeError):inventory.collect('a'*10,'unused.img','unused.txt')
        process.assert_not_called()
