import unittest
from unittest.mock import patch
from pathlib import Path
import fastbuild


class FastBuildTests(unittest.TestCase):
    def test_no_local_image_access(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch.object(Path,'mkdir') as mkdir:
            with self.assertRaises(RuntimeError):fastbuild.run('a'*10,'b'*10)
        mkdir.assert_not_called()
