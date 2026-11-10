import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import base


class BaseTests(unittest.TestCase):
    def test_only_pinned_generic_debian_not_reduced_cloud_or_unrelated_input(self):
        source=json.loads((base.ROOT/'debian.lock.json').read_text());self.assertEqual(base.pin(source),source)
        for field,value in [('vendor','genericcloud'),('arch','arm64'),('type','unofficial')]:
            bad=copy.deepcopy(source);bad['info'][field]=value
            with self.assertRaises(ValueError):base.pin(bad)
        bad=copy.deepcopy(source);bad['url']='https://example.org/image'
        with self.assertRaises(ValueError):base.pin(bad)

    def test_local_refusal_before_any_disk_or_network(self):
        with patch.object(base.socket,'gethostname',return_value='aicoder2'),patch.object(Path,'mkdir') as mkdir,\
             patch.object(base.urllib.request,'urlopen') as network:
            with self.assertRaises(RuntimeError):base.run('012345abcd','unused','unused')
        mkdir.assert_not_called();network.assert_not_called()


if __name__=='__main__':unittest.main()
