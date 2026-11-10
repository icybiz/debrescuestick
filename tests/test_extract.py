import unittest
import extract


class ExtractionTests(unittest.TestCase):
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
