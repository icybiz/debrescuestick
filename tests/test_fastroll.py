import unittest
from unittest.mock import patch
from pathlib import Path
import fastroll
from support import workspace


class UpgradeTests(unittest.TestCase):
    def test_failed_second_rename_restores_the_serving_base(self):
        with workspace() as root:
            current=root/'base';future=root/'next';backup=root/'backup'
            current.mkdir();future.mkdir();(current/'id').write_text('old');(future/'id').write_text('new')
            rename=fastroll.os.rename
            def failing(source,target):
                if source==future:raise OSError('controlled second-rename failure')
                rename(source,target)
            with patch('fastroll.os.rename',side_effect=failing):
                with self.assertRaises(OSError):fastroll.move_base(current,future,backup)
            self.assertEqual((current/'id').read_text(),'old');self.assertEqual((future/'id').read_text(),'new')
            self.assertFalse(backup.exists())
            fastroll.move_base(current,future,backup)
            self.assertEqual((current/'id').read_text(),'new');self.assertEqual((backup/'id').read_text(),'old')

    def test_no_local_deployment(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch.object(Path,'mkdir') as mkdir:
            with self.assertRaises(RuntimeError):fastroll.run('a'*10,'b'*10,'c'*10,'d'*10)
        mkdir.assert_not_called()

    def test_native_identity_and_real_comparisons_required(self):
        sha='a'*64
        qa={'success':True,'qualified':True,'key_isolation':True,'ssh_positive_negative':True,'sha256':sha,
            'results':[{'firmware':f,'success':True,'clean_shutdown':True,'personalization_seconds':.05} for f in ('bios','uefi')]}
        perf={'success':True,'sha256':sha,'full':[{},{}],'reuse':[{},{}]}
        fastroll.validate({'sha256':sha},qa,perf,'same','same')
        for bad in ({**qa,'sha256':'b'*64},{**qa,'results':qa['results'][:1]},
                    {**qa,'results':[{**r,'personalization_seconds':6} for r in qa['results']]}):
            with self.assertRaises(ValueError):fastroll.validate({'sha256':sha},bad,perf,'same','same')
        with self.assertRaises(ValueError):fastroll.validate({'sha256':sha},qa,{**perf,'full':[{}]},'same','same')
        with self.assertRaises(ValueError):fastroll.validate({'sha256':sha},qa,perf,'old','new')
