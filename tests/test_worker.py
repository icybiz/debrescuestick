import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

from keys import public_key
from store import Store,Missing
from support import workspace
from test_keys import sample
import worker


class WorkerTests(unittest.TestCase):
    def test_local_refusal_precedes_files_or_subprocesses(self):
        with patch.object(worker.socket,'gethostname',return_value='aicoder2'),\
             patch.object(Path,'open') as opening,patch.object(worker.subprocess,'run') as process:
            with self.assertRaises(RuntimeError):worker.personalize('/not/a/real/path',{})
        opening.assert_not_called();process.assert_not_called()

    def test_job_path_refusal_and_foreign_files_are_preserved(self):
        with workspace() as root:
            for value in ('','../escape','/', '0'*48+'/x'):
                with self.assertRaises(ValueError):worker.folder(root,value)
            job='a'*48;path=worker.folder(root,job);path.mkdir(parents=True)
            (path/'.owner').write_text(json.dumps({'job':job,'schema':'drs-job-v1'}))
            (path/'foreign.txt').write_text('preserve')
            with self.assertRaises(ValueError):worker.cleanup(root,job)
            self.assertEqual((path/'foreign.txt').read_text(),'preserve')

    def test_personalized_artifact_forward_progress_then_expiry(self):
        with workspace() as root:
            state=root/'state';state.mkdir();now=[1000];store=Store(state/'db',clock=lambda:now[0],ttl=10)
            try:
                a=store.create(*public_key(sample()),'a');b=store.create(*public_key(sample(1)),'b')
                def fake(state,job):
                    out=worker.folder(state,job['id']);out.mkdir(parents=True)
                    (out/'.owner').write_text(json.dumps({'job':job['id'],'schema':'drs-job-v1'}))
                    (out/'image.img').write_bytes(('tiny synthetic test payload\n'+job['key']).encode())
                    return out
                self.assertTrue(worker.process(store,state,store.claim(),prepare=fake))
                first=store.get(a['id']);out=worker.folder(state,a['id'])
                self.assertEqual(first['state'],'ready');self.assertFalse((out/'image.img').exists())
                self.assertEqual(hashlib.sha256((out/'image.zip').read_bytes()).hexdigest(),first['sha256'])
                with zipfile.ZipFile(out/'image.zip') as archive:
                    data=archive.read('DebRescueStick-amd64.img').decode()
                    self.assertIn(public_key(sample())[0],data);self.assertNotIn(public_key(sample(1))[0],data)
                self.assertEqual(store.claim()['id'],b['id']);store.fail(b['id'])
                now[0]=1011;worker.reap(store,state)
                self.assertFalse(out.exists())
                with self.assertRaises(Missing):store.get(a['id'])
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
            finally:store.close()


if __name__=='__main__':unittest.main()
