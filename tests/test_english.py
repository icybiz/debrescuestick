import ast
import io
import json
from pathlib import Path
import time
import unittest
import urllib.error
import urllib.request

import server
import english
from keys import public_key
from support import workspace
from test_keys import sample
from test_server import serving
from unittest.mock import patch


class EnglishTests(unittest.TestCase):
    def test_final_acceptance_waits_for_the_actual_listener_after_restart(self):
        not_ready=urllib.error.HTTPError('http://localhost',503,'starting',{},io.BytesIO(b''))
        with patch('english.read',side_effect=[not_ready,json.dumps({'available':True}).encode()]),patch('english.time.sleep'):
            self.assertTrue(english.web_ready(1234)['status']['available'])

    def test_unavailable_service_cannot_pass_readiness(self):
        with patch('english.read',return_value=b'{"available":false}'):
            with self.assertRaises(RuntimeError):english.web_ready(1234,timeout=0)

    def test_final_staging_refuses_the_development_host_before_any_write(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch.object(Path,'mkdir') as mkdir:
            with self.assertRaises(RuntimeError):english.run('a'*10,'b'*10,'c'*64,'final')
        mkdir.assert_not_called()

    def test_archive_translation_preserves_file_permissions_and_rejects_links(self):
        with workspace() as root:
            page=root/'archive.html';page.write_text('old');page.chmod(0o640);info=page.stat()
            english.atomic_page(page,b'English',info,'a'*10)
            self.assertEqual(page.read_bytes(),b'English');self.assertEqual(page.stat().st_mode&0o777,0o640)
            link=root/'alias';link.symlink_to(page)
            with self.assertRaises(ValueError):english.atomic_page(link,b'changed',info,'b'*10)
            self.assertEqual(page.read_bytes(),b'English')

    def test_qualified_parser_and_queue_errors_have_web_translations(self):
        messages=set()
        for name in ('keys.py','store.py'):
            for node in ast.walk(ast.parse((server.ROOT/name).read_text())):
                if (isinstance(node,ast.Raise) and isinstance(node.exc,ast.Call) and
                    isinstance(node.exc.func,ast.Name) and node.exc.func.id in ('InvalidKey','Busy','Missing')):
                    messages.add(ast.literal_eval(node.exc.args[0]))
        self.assertTrue(messages)
        self.assertEqual(messages-set(server.ERROR_TEXT),set())
        self.assertTrue(all(server.ERROR_TEXT[m]!=m and server.ERROR_TEXT[m].isascii() for m in messages))

    def test_http_errors_are_english_and_the_queue_keeps_its_original_data(self):
        with workspace() as state,serving(state) as (app,url):
            def call(path,data=None):
                request=urllib.request.Request(url+path,data=json.dumps(data).encode() if data is not None else None,
                                               headers={'Content-Type':'application/json'})
                try:response=urllib.request.urlopen(request)
                except urllib.error.HTTPError as error:response=error
                with response:return response.status,json.load(response)
            status,value=call('/api/jobs',{'public_key':'-----BEGIN PRIVATE KEY-----\nsecret'})
            self.assertEqual(status,400);self.assertEqual(value['error'],'Paste one public key line, never a private key.')
            base=state/'base';base.mkdir();sha='a'*64
            (base/'template.json').write_text(json.dumps({'sha256':sha}))
            (base/'qualified.json').write_text(json.dumps({'sha256':sha,'architecture':'amd64',
                'qualified':True,'key_isolation':True,'ssh_positive_negative':True}))
            (state/'heartbeat.json').write_text(json.dumps({'time':time.time()}))
            status,first=call('/api/jobs',{'public_key':sample()});self.assertEqual(status,202)
            status,error=call('/api/jobs',{'public_key':sample()})
            self.assertEqual(status,429);self.assertEqual(error['error'],'Please wait briefly before submitting another request.')
            with app.store() as store:
                store.create(*public_key(sample(1)),'second');store.create(*public_key(sample(2)),'third')
                store.db.execute('DELETE FROM limits')
            status,error=call('/api/jobs',{'public_key':sample(3)})
            self.assertEqual(status,429);self.assertEqual(error['error'],'The queue is full. Please try again later.')
            with app.store() as store:
                store.db.execute('UPDATE jobs SET expires=0 WHERE id=?',(first['id'],))
                active=store.claim();store.fail(active['id'])
                self.assertEqual(store.get(active['id'])['error'],'Das Image konnte nicht erstellt werden. Bitte später erneut versuchen.')
            status,error=call('/api/jobs/'+first['id'])
            self.assertEqual(status,404);self.assertEqual(error['error'],'The download has expired.')
            status,failed=call('/api/jobs/'+active['id'])
            self.assertEqual(status,200);self.assertEqual(failed['state'],'failed')
            self.assertEqual(failed['error'],'The image could not be prepared. Please try again later.')
