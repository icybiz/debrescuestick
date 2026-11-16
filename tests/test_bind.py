"""Bounded real HTTP/child lifecycle using tiny synthetic metadata, never images."""
from contextlib import contextmanager
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import qualify
import replay
import base
from support import workspace
from test_keys import sample

POPEN = subprocess.Popen


class BindingTests(unittest.TestCase):
    def qualification_fixture(self, root):
        factory=root/'factory';source=factory/('image-'+'b'*10)
        (source/'fast').mkdir(parents=True)
        (source/'base.img').write_bytes(b'synthetic base')
        (source/'fast/prefix.zip').write_bytes(b'synthetic prefix')
        sha=base.digest(source/'base.img')
        (source/'template.json').write_text(json.dumps({'sha256':sha,'fast':{}}))
        qa=root/'qa';native=qa/('c'*10);native.mkdir(parents=True)
        (native/'result.json').write_text(json.dumps({'success':True,'qualified':True,
            'key_isolation':True,'ssh_positive_negative':True,'architecture':'amd64','sha256':sha}))
        manifest={n:base.digest(qualify.ROOT/n) for n in qualify.FILES}
        bundle=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
        return factory,qa,bundle

    def service_run(self, root, mutate=False):
        factory,qa,bundle=self.qualification_fixture(root)
        original_digest=base.digest
        closed=threading.Event();verified=[];before=[]
        def digest(path,*args):
            if path.name=='base.img':
                if closed.is_set():raise RuntimeError('Image read deferred to shutdown')
                verified.append(True)
            return original_digest(path,*args)
        def serve(path):
            before.append(bool(verified));closed.set()
            if mutate:
                with (path/'base/fast/prefix.zip').open('ab') as f:f.write(b'changed')
            return {'stopped':True}
        def path(value):return qa if value=='/var/lib/debrescuestick/qa' else Path(value)
        with patch('worker.require_host'),patch.object(base,'REMOTE',factory),patch('qualify.Path',side_effect=path),patch('base.digest',side_effect=digest),patch('replay.serve',side_effect=serve),redirect_stdout(io.StringIO()):
            result=qualify.run('a'*10,'b'*10,bundle,serve=True,qualification='c'*10)
        return result,before,json.loads((qa/('a'*10)/'result.json').read_text())

    def test_service_verifies_image_before_admission_and_never_reads_it_during_shutdown(self):
        with workspace() as root:
            result,before,record=self.service_run(root)
            self.assertEqual(result,0,record.get('error'))
            self.assertEqual(before,[True])
            self.assertTrue(record['success'])

    def test_source_mutation_is_still_rejected_when_full_read_is_removed_from_shutdown(self):
        with workspace() as root:
            result,before,record=self.service_run(root,mutate=True)
            self.assertEqual(result,1)
            self.assertEqual(before,[True])
            self.assertIn('changed',record['error'].lower())

    def test_other_input_references_do_not_look_like_content_mutation(self):
        with workspace() as root:
            (root/'fast').mkdir();(root/'base.img').write_bytes(b'fixture base')
            prefix=root/'fast/prefix.zip';prefix.write_bytes(b'fixture prefix')
            original=qualify.input_stamp(root)
            alias=root/'another-reference';alias.hardlink_to(prefix)
            self.assertEqual(qualify.input_stamp(root),original)
            alias.unlink()
            self.assertEqual(qualify.input_stamp(root),original)

    @contextmanager
    def runtime(self, state):
        base = state/'base';base.mkdir()
        (base/'qualified.json').write_text(json.dumps({'qualified':True,'key_isolation':True,
            'ssh_positive_negative':True,'architecture':'amd64','sha256':'a'*64}))
        (base/'template.json').write_text(json.dumps({'sha256':'a'*64}))
        children = []
        # A tiny owned heartbeat process replaces image work in unit fixtures.
        code = "from pathlib import Path;import sys,json,time,os;p=Path(sys.argv[1])/'heartbeat.json'\nwhile True:\n p.write_text(json.dumps({'time':time.time(),'pid':os.getpid()}));time.sleep(.05)\n"
        def child(*args, **kwargs):
            process = POPEN([sys.executable,'-c',code,str(state)], **kwargs)
            children.append(process)
            return process
        with patch('worker.require_host'),patch('replay.subprocess.Popen',side_effect=child):
            try:yield children
            finally:
                for process in children:
                    if process.poll() is None:
                        process.terminate();process.wait(5)

    def test_real_http_acceptance_recovery_and_complete_child_shutdown(self):
        with workspace() as root,self.runtime(root) as children:
            with replay.session(root,ready_timeout=5) as info:
                url = info['endpoint']
                with urllib.request.urlopen(url+'/api/status',timeout=5) as response:
                    self.assertTrue(json.load(response)['available'])
                data=json.dumps({'public_key':sample(),'request_key':'a'*64}).encode()
                def start():
                    request=urllib.request.Request(url+'/api/jobs',data=data,headers={'Content-Type':'application/json'})
                    with urllib.request.urlopen(request,timeout=5) as response:
                        self.assertEqual(response.status,202)
                        return json.load(response)
                first=start();self.assertEqual(start(),first)
                with urllib.request.urlopen(url+'/api/requests/'+'a'*64,timeout=5) as response:
                    self.assertEqual(json.load(response),first)
                self.assertIsNone(children[0].poll())
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(info['stopped'])
            self.assertFalse((root/'heartbeat.json').exists())
            with self.assertRaises(urllib.error.URLError):urllib.request.urlopen(url+'/api/status',timeout=1)

    def test_expired_session_returns_listener_and_worker(self):
        with workspace() as root,self.runtime(root) as children:
            result=replay.serve(root,lifetime=.05)
            self.assertTrue(result['stopped'])
            self.assertIsNotNone(children[0].poll())
            self.assertEqual(json.loads((root/'progress.json').read_text())['phase'],'service-ready')

    def test_worker_start_failure_cannot_advertise_available_endpoint(self):
        with workspace() as root,self.runtime(root):
            with patch('replay.subprocess.Popen',side_effect=lambda *a,**k:POPEN([sys.executable,'-c','raise SystemExit(7)'],**k)):
                with self.assertRaisesRegex(RuntimeError,'stopped before readiness'):
                    with replay.session(root,ready_timeout=5):self.fail('Failed worker was admitted')
            self.assertFalse((root/'progress.json').exists())

    def test_foreign_fresh_heartbeat_does_not_admit_silent_new_worker(self):
        with workspace() as root,self.runtime(root):
            import time
            (root/'heartbeat.json').write_text(json.dumps({'time':time.time(),'pid':-1}))
            with patch('replay.subprocess.Popen',side_effect=lambda *a,**k:POPEN([sys.executable,'-c','import time;time.sleep(30)'],**k)):
                with self.assertRaisesRegex(RuntimeError,'readiness timed out'):
                    with replay.session(root,ready_timeout=.1):self.fail('Foreign heartbeat was trusted')

    def test_host_guard_and_binding_identity_precede_native_work(self):
        with patch('worker.require_host',side_effect=RuntimeError('wrong host')),patch('replay.subprocess.Popen') as child:
            with self.assertRaisesRegex(RuntimeError,'wrong host'):
                with replay.session(Path('/unread-owned-state')):self.fail()
            child.assert_not_called()
        good={'success':True,'qualified':True,'key_isolation':True,'ssh_positive_negative':True,
              'architecture':'amd64','sha256':'a'*64}
        self.assertEqual(replay.binding_proof({'sha256':'a'*64},good),good)
        for change in ({'sha256':'b'*64},{'success':False},{'architecture':'arm64'},{'qualified':False}):
            with self.assertRaises(ValueError):replay.binding_proof({'sha256':'a'*64},dict(good,**change))

    def test_unbounded_lifetime_or_missing_qualification_cannot_start(self):
        for value in (0,-1,2701,float('inf'),float('nan')):
            with self.assertRaises(ValueError):replay.serve(Path('/unread-owned-state'),lifetime=value)
        with patch('base.remote') as remote:
            for kwargs in ({'serve':True},{'serve':True,'qualification':'x'},
                           {'queue':True,'serve':True,'qualification':'c'*10},
                           {'qualification':'c'*10}):
                with self.assertRaises(ValueError):qualify.submit('a'*10,'b'*10,**kwargs)
            remote.assert_not_called()

    def test_stop_refuses_other_generation_or_nonservice_unit_before_remote_access(self):
        with workspace() as root,patch.object(qualify,'ROOT',root),patch('base.remote') as remote:
            folder=root/'artifacts';folder.mkdir()
            for receipt in ({'key':'a'*10,'unit':qualify.qa_unit('a'*10),'serve':False},
                            {'key':'b'*10,'unit':qualify.qa_unit('a'*10),'serve':True},
                            {'key':'a'*10,'unit':'debrescuestick-worker','serve':True}):
                (folder/('qa-job-'+'a'*10+'.json')).write_text(json.dumps(receipt))
                with self.assertRaises(ValueError):qualify.stop_session('a'*10)
            remote.assert_not_called()

    def test_stop_transport_can_wait_for_its_full_remote_stop_budget(self):
        with workspace() as root,patch.object(qualify,'ROOT',root):
            folder=root/'artifacts';folder.mkdir()
            receipt={'key':'a'*10,'unit':qualify.qa_unit('a'*10),'serve':True,
                     'bundle_sha256':'d'*64,'template_job':'b'*10,'qualification':'c'*10}
            (folder/('qa-job-'+'a'*10+'.json')).write_text(json.dumps(receipt))
            def reply(argv,**kw):
                if kw['timeout']<75:raise subprocess.TimeoutExpired(argv,kw['timeout'])
                return subprocess.CompletedProcess(argv,0,json.dumps({'stopped':True}), '')
            with patch('base.subprocess.run',side_effect=reply):
                self.assertTrue(qualify.stop_session('a'*10)['stopped'])
