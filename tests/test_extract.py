import unittest
import json
from pathlib import Path
from unittest.mock import patch
import extract
from support import workspace


class ExtractionTests(unittest.TestCase):
    def start_with_status(self, root, status):
        def request(path, data=None):
            if data is None:return status
            return {'id':'b'*48,'sha256':'c'*64,'bytes':1200000000,'state':'ready',
                    'fingerprint':extract.public_key(data['public_key'])[1]}
        with patch.object(extract,'ROOT',root),patch('extract.request',side_effect=request),\
             patch('extract.remote',return_value='own unit started'),\
             patch('extract.subprocess.check_output',return_value='fixture-commit'):
            return extract.start()

    def test_reference_receipt_persists_exact_template_and_private_key_is_discarded(self):
        with workspace() as root:
            result=self.start_with_status(root,{'available':True,'sources_url':'/debrescuestick/sources/'+extract.TEMPLATE+'/'})
            record=json.loads((Path(result['artifacts'])/'run.json').read_text())
            self.assertEqual(record['template_sha256'],extract.TEMPLATE)
            self.assertEqual(record['reference_schema'],'drs-extraction-reference-v1')
            self.assertEqual(list((root/'.private').iterdir()),[])

    def test_similar_but_different_template_url_cannot_mint_a_reference(self):
        with workspace() as root:
            with self.assertRaises(RuntimeError):
                self.start_with_status(root,{'available':True,'sources_url':'/debrescuestick/sources/'+extract.TEMPLATE+'-other/'})
    def test_runtime_ledger_cannot_redirect_remote_cleanup(self):
        key='a'*10
        record={'unit':'debrescuestick-extract-'+key+'.service','remote_root':'/tmp/debrescuestick-extract-'+key}
        self.assertEqual(extract.runtime(record,key),record['remote_root'])
        for bad in ('','/','/tmp','/home/user',record['remote_root']+'/../foreign'):
            with self.assertRaises(ValueError):extract.runtime({**record,'remote_root':bad},key)
        with self.assertRaises(ValueError):extract.runtime({**record,'unit':'foreign.service'},key)

    def test_fixed_browser_host_ram_only_and_strict_download_binding(self):
        record={'key':'a'*10,'job':{'id':'b'*48,'sha256':'c'*64,'bytes':1221038091}}
        text=extract.script(record)
        self.assertIn('test "$(hostname -s)" = browser',text)
        self.assertIn('--target /tmp',text)
        self.assertIn('cmp bsd.sha seven.sha',text)
        self.assertNotIn('root@prox',text);self.assertNotIn('aiserver',text)
        for bad in ('','../escape','a'*9,'A'*10):
            with self.assertRaises(ValueError):extract.script({**record,'key':bad})
        with self.assertRaises(ValueError):extract.script({**record,'job':{**record['job'],'id':'../escape'}})
        with self.assertRaises(ValueError):extract.script({**record,'job':{**record['job'],'bytes':2*1024**3}})
