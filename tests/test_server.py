from contextlib import contextmanager
import hashlib
import json
import socket
import threading
import time
import unittest
import urllib.request
import urllib.error

from server import Handler,App,HTTPServer,byte_range
from support import workspace
from test_keys import sample


@contextmanager
def serving(folder):
    app=App(folder)
    with app.store():pass
    server=HTTPServer(('127.0.0.1',0),Handler);server.app=app
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield app,'http://127.0.0.1:'+str(server.server_address[1])
    finally:server.shutdown();server.server_close();thread.join(5)


class HTTPTests(unittest.TestCase):
    def test_composite_download_crosses_parts_and_expires(self):
        with workspace() as folder,serving(folder) as (app,url):
            from keys import public_key
            from store import Store
            data=b'fixed system prefix' + b'personal partition and ZIP end'
            prefix=data[:19];tail=data[19:];sha=hashlib.sha256(data).hexdigest();base='b'*64
            with app.store() as store:
                job=store.create(*public_key(sample()),'fixture');store.claim();store.progress(job['id']);store.finish(job['id'],len(data),sha)
            path=folder/'jobs'/job['id'];path.mkdir(parents=True)
            (path/'image.tail').write_bytes(tail)
            (path/'archive.json').write_text(json.dumps({'base_sha256':base,'bytes':len(data),'sha256':sha,'prefix_bytes':len(prefix)}))
            shared=folder/'archives'/base;shared.mkdir(parents=True);(shared/'prefix.zip').write_bytes(prefix)
            link=url+'/debrescuestick/download/'+job['id']
            for span,expected in [(None,data),('bytes=17-22',data[17:23]),('bytes=19-',tail),('bytes=-4',data[-4:])]:
                request=urllib.request.Request(link,headers={'Range':span} if span else {})
                with urllib.request.urlopen(request) as r:
                    self.assertEqual(r.read(),expected);self.assertEqual(r.headers['ETag'],'"'+sha+'"')
            with urllib.request.urlopen(urllib.request.Request(link,method='HEAD')) as r:self.assertEqual(r.read(),b'');self.assertEqual(int(r.headers['Content-Length']),len(data))
            with app.store() as store:store.db.execute('UPDATE jobs SET expires=0 WHERE id=?',(job['id'],))
            with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(link)
            self.assertEqual(caught.exception.code,404)

    def test_slow_connections_are_bounded_and_service_recovers(self):
        with workspace() as folder,serving(folder) as (app,url):
            address=('127.0.0.1',int(url.rsplit(':',1)[1]));clients=[]
            try:
                for unused in range(8):
                    client=socket.create_connection(address,timeout=2)
                    client.sendall(b'GET / HTTP/1.0\r\n');clients.append(client)
                time.sleep(.1)
                with socket.create_connection(address,timeout=2) as rejected:
                    self.assertIn(b'503 Busy',rejected.recv(1024))
            finally:
                for client in clients:client.close()
            end=time.monotonic()+2
            while True:
                try:
                    with urllib.request.urlopen(url+'/api/status',timeout=2) as reply:
                        self.assertEqual(json.load(reply),{'available':False});break
                except urllib.error.HTTPError:
                    if time.monotonic()>end:raise
                    time.sleep(.05)

    def test_bounded_download_can_resume_without_changing_bytes(self):
        with workspace() as folder,serving(folder) as (app,url):
            data=b'tiny synthetic download fixture'
            with app.store() as store:
                from keys import public_key
                job=store.create(*public_key(sample()),'fixture');store.claim();store.progress(job['id'])
                store.finish(job['id'],len(data),hashlib.sha256(data).hexdigest())
            path=folder/'jobs'/job['id'];path.mkdir(parents=True);(path/'image.zip').write_bytes(data)
            link=url+'/debrescuestick/download/'+job['id']
            request=urllib.request.Request(link,headers={'Range':'bytes=5-11'})
            with urllib.request.urlopen(request) as r:
                self.assertEqual(r.status,206);self.assertEqual(r.read(),data[5:12])
                self.assertEqual(r.headers['Content-Range'],'bytes 5-11/'+str(len(data)))
            with urllib.request.urlopen(urllib.request.Request(link,method='HEAD')) as r:
                self.assertEqual(int(r.headers['Content-Length']),len(data));self.assertEqual(r.read(),b'')
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(urllib.request.Request(link,headers={'Range':'bytes=999-'}))
            self.assertEqual(caught.exception.code,416)
            for bad in ('bytes=-0','bytes=4-2','bytes=1-2,4-5','items=1-2','bytes=--1'):
                with self.assertRaises(ValueError):byte_range(bad,len(data))

    def test_subdirectory_canonical_url_preserves_relative_assets(self):
        with workspace() as folder,serving(folder) as (app,url):
            with urllib.request.urlopen(url+'/debrescuestick') as reply:
                self.assertEqual(reply.geturl(),url+'/debrescuestick/')
                self.assertIn(b'id="request"',reply.read())
            for name in ('style.css','app.js'):
                with urllib.request.urlopen(url+'/debrescuestick/'+name) as reply:self.assertEqual(reply.status,200)

    def test_qualified_live_worker_accepts_key_and_exposes_only_fingerprint(self):
        with workspace() as folder,serving(folder) as (app,url):
            base=folder/'base';base.mkdir()
            proof={'qualified':True,'key_isolation':True,'ssh_positive_negative':True,'architecture':'amd64','sha256':'a'*64}
            (base/'qualified.json').write_text(json.dumps(proof))
            (base/'template.json').write_text(json.dumps({'sha256':'a'*64}))
            self.assertFalse(app.available())
            heartbeat=folder/'heartbeat.json';heartbeat.write_text(json.dumps({'time':time.time()}))
            self.assertTrue(app.available())
            with urllib.request.urlopen(url+'/debrescuestick/api/status') as r:
                self.assertEqual(json.load(r)['sources_url'],'/debrescuestick/sources/'+'a'*64+'/')
            request=urllib.request.Request(url+'/debrescuestick/api/jobs',data=json.dumps({'public_key':sample()}).encode(),headers={'Content-Type':'application/json'})
            with urllib.request.urlopen(request) as r:
                self.assertEqual(r.status,202);job=json.load(r);self.assertNotIn('key',job)
            with urllib.request.urlopen(url+'/debrescuestick/api/jobs/'+job['id']) as r:self.assertEqual(json.load(r)['fingerprint'],job['fingerprint'])
            heartbeat.write_text(json.dumps({'time':time.time()-60}));self.assertFalse(app.available())
            (base/'template.json').write_text(json.dumps({'sha256':'b'*64}))
            self.assertIsNone(app.proof())

    def test_page_status_and_unqualified_image_refusal(self):
        with workspace() as folder,serving(folder) as (app,url):
            with urllib.request.urlopen(url+'/debrescuestick/') as r:
                body=r.read();self.assertIn(b'DebRescueStick',body)
            with urllib.request.urlopen(url+'/debrescuestick/api/status') as r:self.assertEqual(json.load(r),{'available':False})
            request=urllib.request.Request(url+'/debrescuestick/api/jobs',data=json.dumps({'public_key':sample()}).encode(),headers={'Content-Type':'application/json'})
            with self.assertRaises(urllib.error.HTTPError) as caught:urllib.request.urlopen(request)
            self.assertEqual(caught.exception.code,503)
            with app.store() as store:self.assertIsNone(store.claim())


if __name__=='__main__':unittest.main()
