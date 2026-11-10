#!/usr/bin/env python3
"""Small independent HTTP frontend for the bounded rescue-image queue."""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import stat
import threading
import time
from urllib.parse import urlsplit

from keys import public_key,InvalidKey
from store import Store,Busy,Missing
import fast

ROOT=Path(__file__).resolve().parent
PREFIX='/debrescuestick'

# Presentation only: keep the natively qualified key parser, queue and worker byte-identical.
ERROR_TEXT = {'Bitte einen öffentlichen SSH-Schlüssel angeben.': 'Please provide a public SSH key.',
 'Bitte nur eine öffentliche Schlüsselzeile einfügen, keinen privaten Schlüssel.': 'Paste one public key '
                                                                                   'line, never a private '
                                                                                   'key.',
 'Das ist kein öffentlicher OpenSSH-Schlüssel.': 'This is not an OpenSSH public key.',
 'Unterstützt werden Ed25519, RSA ab2048Bit, ECDSA und OpenSSH-Sicherheitsschlüssel.': 'Supported key '
                                                                                       'types are Ed25519, '
                                                                                       'RSA with at least '
                                                                                       '2048 bits, ECDSA, '
                                                                                       'and OpenSSH '
                                                                                       'security keys.',
 'Ungültige Base64-Schlüsseldaten.': 'Invalid Base64 key data.',
 'Der Schlüssel ist zu groß.': 'The key is too large.',
 'Unvollständiger Schlüssel.': 'Incomplete public key.',
 'Unvollständige Schlüsseldaten.': 'Incomplete key data.',
 'Schlüsseltyp und Schlüsseldaten passen nicht zusammen.': 'The key type does not match the key data.',
 'Ed25519 benötigt32Bytes Schlüsseldaten.': 'Ed25519 requires 32 bytes of key data.',
 'Ungültiger RSA-Schlüssel.': 'Invalid RSA key.',
 'RSA benötigt einen gültigen Schlüssel mit mindestens2048Bit.': 'RSA requires a valid key with at least '
                                                                 '2048 bits.',
 'ECDSA-Kurve und Schlüsseltyp passen nicht zusammen.': 'The ECDSA curve does not match the key type.',
 'Ungültiger ECDSA-Punkt.': 'Invalid ECDSA point.',
 'Ungültige Sicherheitsschlüssel-Anwendung.': 'Invalid security key application.',
 'Unerwartete zusätzliche Schlüsseldaten.': 'Unexpected extra key data.',
 'Bitte vor einer weiteren Anfrage kurz warten.': 'Please wait briefly before submitting another request.',
 'Die Warteschlange ist gerade voll. Bitte später erneut versuchen.': 'The queue is full. Please try again '
                                                                      'later.',
 'Auftrag nicht gefunden.': 'Request not found.',
 'Auftrag nicht gefunden oder bereits gelöscht.': 'The request was not found or has already been removed.',
 'Der Download ist abgelaufen.': 'The download has expired.',
 'Das Image konnte nicht erstellt werden. Bitte später erneut versuchen.': 'The image could not be '
                                                                           'prepared. Please try again '
                                                                           'later.'}


class HTTPServer(ThreadingHTTPServer):
    """Bound both slow requests and concurrent image downloads."""
    daemon_threads=True
    request_queue_size=8

    def __init__(self,*args,**kwargs):
        self.slots=threading.BoundedSemaphore(8)
        super().__init__(*args,**kwargs)

    def get_request(self):
        request,address=super().get_request();request.settimeout(15)
        return request,address

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            try:request.sendall(b'HTTP/1.0 503 Busy\r\nContent-Length: 0\r\nRetry-After: 10\r\n\r\n')
            finally:self.shutdown_request(request)
            return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise

    def process_request_thread(self,*args):
        try:super().process_request_thread(*args)
        finally:self.slots.release()


def byte_range(value,size):
    if value is None:return 0,size-1,False
    unit,sep,span=value.partition('=')
    if unit!='bytes' or not sep or ',' in span:raise ValueError('Single byte range required')
    first,sep,last=span.partition('-')
    if not sep or not first and not last:raise ValueError('Bounded byte range required')
    if any(c not in '0123456789' for c in first+last):raise ValueError('Decimal range required')
    if first:start=int(first);end=min(int(last),size-1) if last else size-1
    else:start=max(0,size-int(last));end=size-1
    if not 0<=start<=end<size:raise ValueError('Unsatisfiable byte range')
    return start,end,True


def archive(state,record):
    folder=state/'jobs'/record['id']
    if (folder/'image.zip').is_file():return fast.Reader([folder/'image.zip'])
    path=folder/'archive.json'
    if path.is_symlink() or path.stat().st_size>4096:raise Missing('Invalid download.')
    meta=json.loads(path.read_text());sha=meta['base_sha256']
    if len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha):raise Missing('Invalid base image.')
    if meta['bytes']!=record['bytes'] or meta['sha256']!=record['sha256']:raise Missing('Invalid download.')
    reader=fast.Reader([state/'archives'/sha/'prefix.zip',folder/'image.tail'])
    if reader.parts[0][1]!=meta['prefix_bytes']:
        reader.close();raise Missing('Invalid download base.')
    return reader


class App:
    def __init__(self,state,origin='https://eorls.com'):
        self.state=Path(state);self.origin=origin

    @contextmanager
    def store(self):
        store=Store(self.state/'jobs.sqlite3')
        try:yield store
        finally:store.close()

    def available(self):
        heartbeat=self.state/'heartbeat.json'
        if self.proof() is None or not heartbeat.is_file():return False
        try:
            age=time.time()-json.loads(heartbeat.read_text())['time']
        except (ValueError,KeyError,OSError):return False
        if not -5<=age<=30:return False
        return True

    def proof(self):
        try:
            record=json.loads((self.state/'base/qualified.json').read_text())
            template=json.loads((self.state/'base/template.json').read_text())
        except (ValueError,OSError):return None
        sha=record.get('sha256')
        if (not all(record.get(k) is True for k in ('qualified','key_isolation','ssh_positive_negative')) or
            record.get('architecture')!='amd64' or not isinstance(sha,str) or
            len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha) or sha!=template.get('sha256')):
            return None
        return record


class Handler(BaseHTTPRequestHandler):
    server_version='DebRescueStick'

    @property
    def app(self):return self.server.app

    def log_message(self,format,*args):
        # Download tokens and submitted key material do not belong in access logs.
        return

    def send_headers(self,status,kind,length):
        self.send_response(status)
        self.send_header('Content-Type',kind);self.send_header('Content-Length',str(length))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy',"default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

    def json(self,status,value):
        if isinstance(value,dict) and isinstance(value.get('error'),str):
            value={**value,'error':ERROR_TEXT.get(value['error'],value['error'])}
        raw=json.dumps(value,ensure_ascii=False).encode()
        self.send_headers(status,'application/json; charset=utf-8',len(raw));self.end_headers()
        self.wfile.write(raw)

    def route(self):
        value=urlsplit(self.path).path
        if value==PREFIX:return '/'
        return value[len(PREFIX):] if value.startswith(PREFIX+'/') else value

    def do_GET(self):
        if urlsplit(self.path).path==PREFIX:
            self.send_headers(301,'text/plain; charset=utf-8',0)
            self.send_header('Location',PREFIX+'/');self.end_headers();return
        path=self.route()
        try:
            if path in ('/','/app.js','/ui.js','/style.css'):
                name={'/':'index.html','/app.js':'app.js','/ui.js':'ui.js','/style.css':'style.css'}[path]
                data=(ROOT/'static'/name).read_bytes()
                kind='text/html; charset=utf-8' if path=='/' else 'text/css; charset=utf-8' if path=='/style.css' else 'text/javascript; charset=utf-8'
                self.send_headers(200,kind,len(data));self.end_headers();self.wfile.write(data);return
            if path=='/api/status':
                value={'available':self.app.available()};proof=self.app.proof()
                if proof:value['sources_url']=PREFIX+'/sources/'+proof['sha256']+'/'
                self.json(200,value);return
            if path.startswith('/api/jobs/'):
                token=path.removeprefix('/api/jobs/')
                with self.app.store() as store:record=store.get(token)
                self.json(200,record);return
            if path.startswith('/download/'):
                token=path.removeprefix('/download/')
                with self.app.store() as store:record=store.get(token)
                if record['state']!='ready':raise Missing('The image is not ready yet.')
                with archive(self.app.state,record) as stream:
                    size=stream.size
                    if size!=record['bytes']:
                        raise Missing('The download is unavailable.')
                    try:start,end,partial=byte_range(self.headers.get('Range'),size)
                    except ValueError:
                        self.send_headers(416,'application/zip',0);self.send_header('Content-Range','bytes */'+str(size));self.end_headers();return
                    self.send_headers(206 if partial else 200,'application/zip',end-start+1)
                    self.send_header('Accept-Ranges','bytes')
                    self.send_header('ETag','"'+record['sha256']+'"')
                    if partial:self.send_header('Content-Range','bytes '+str(start)+'-'+str(end)+'/'+str(size))
                    self.send_header('Content-Disposition','attachment; filename="DebRescueStick-amd64.img.zip"')
                    self.end_headers()
                    if self.command=='HEAD':return
                    stream.seek(start);remaining=end-start+1;deadline=time.monotonic()+300
                    while remaining:
                        if time.monotonic()>deadline or time.time()>=record['expires']:break
                        block=stream.read(min(1024*1024,remaining))
                        if not block:break
                        self.wfile.write(block);remaining-=len(block)
                return
            self.json(404,{'error':'Page not found.'})
        except Missing as error:self.json(404,{'error':str(error)})
        except (BrokenPipeError,ConnectionResetError,TimeoutError):return
        except (FileNotFoundError,OSError):self.json(404,{'error':'File unavailable.'})

    def do_HEAD(self):
        if self.route().startswith('/download/'):self.do_GET()
        else:self.send_headers(405,'text/plain',0);self.end_headers()

    def do_POST(self):
        if self.route()!='/api/jobs':self.json(404,{'error':'Page not found.'});return
        if self.headers.get('Origin') not in (None,self.app.origin):
            self.json(403,{'error':'The request does not belong to this website.'});return
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':
            self.json(415,{'error':'Expected JSON.'});return
        try:
            length=int(self.headers.get('Content-Length','0'))
            if not 0<length<=20000:raise ValueError('Invalid request size.')
            data=json.loads(self.rfile.read(length))
            key,fingerprint=public_key(data['public_key'])
            if not self.app.available():
                self.json(503,{'error':'Image preparation is currently unavailable. Please try again later.'});return
            # Apache must remove any incoming copy and set this from REMOTE_ADDR.
            address=self.headers.get('X-DRS-Client',self.client_address[0])
            client=hashlib.sha256(str(ipaddress.ip_address(address)).encode()).hexdigest()
            with self.app.store() as store:record=store.create(key,fingerprint,client)
            self.json(202,record)
        except (ValueError,KeyError,TypeError) as error:
            self.json(429 if isinstance(error,Busy) else 400,{'error':str(error) if isinstance(error,(InvalidKey,Busy)) else 'Invalid request.'})


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--port',type=int,default=0);parser.add_argument('--origin',default='https://eorls.com');args=parser.parse_args()
    app=App(args.state,args.origin)
    args.state.mkdir(mode=0o700,parents=True,exist_ok=True)
    with app.store():pass
    server=HTTPServer(('127.0.0.1',args.port),Handler);server.app=app
    print(json.dumps({'listen':server.server_address,'state':str(args.state)}),flush=True)
    server.serve_forever()


if __name__=='__main__':main()
