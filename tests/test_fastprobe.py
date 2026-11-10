import unittest
from unittest.mock import patch
from pathlib import Path
import fastprobe
import fast
from support import workspace


class FastProbeTests(unittest.TestCase):
    def test_reference_compresses_the_same_patched_bytes(self):
        with workspace() as root:
            source=root/'synthetic';source.write_bytes(b'a'*50+b'old'*10+b'z'*70)
            meta=fast.pack(source,50,30,root/'packed')
            self.assertEqual(fastprobe.complete(source,b'new'*10,meta)['crc32'],__import__('zlib').crc32(b'a'*50+b'new'*10+b'z'*70))

    def test_no_local_benchmark(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch.object(Path,'mkdir') as mkdir:
            with self.assertRaises(RuntimeError):fastprobe.run('a'*10,'b'*10,'c'*10)
        mkdir.assert_not_called()
