#!/usr/bin/env python3
"""Check the draft using only our isolated browser.local session and SSH tunnels."""
import json
import argparse
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
import urllib.request

import base
from server import HTTPServer,Handler,App

ROOT=Path(__file__).resolve().parent


class DraftHandler(Handler):
    """Local-only preview of the independently deployed archive page."""
    def do_GET(self):
        name={'/archive/':'move.html','/archive/move.css':'move.css'}.get(self.route())
        if name:
            data=(ROOT/'static'/name).read_bytes()
            kind='text/html; charset=utf-8' if name.endswith('.html') else 'text/css; charset=utf-8'
            self.send_headers(200,kind,len(data));self.end_headers();self.wfile.write(data)
        else:super().do_GET()


def stop_tunnel(child,expected):
    if child and child.poll() is None:
        try:actual=(Path('/proc')/str(child.pid)/'cmdline').read_bytes()
        except FileNotFoundError:
            if child.poll() is not None:return
            raise RuntimeError('Owned tunnel identity unavailable; stop refused')
        if child.poll() is not None:return
        if actual!=expected:raise RuntimeError('Owned tunnel PID changed; stop refused')
        child.terminate()
        try:child.wait(10)
        except subprocess.TimeoutExpired:
            if (Path('/proc')/str(child.pid)/'cmdline').read_bytes()!=expected:raise RuntimeError('Owned tunnel PID changed')
            child.kill();child.wait(5)


def run(live=False,job=None,request=False):
    os.nice(10)
    if request and (not live or job):raise ValueError('Request a new ordinary image only for live acceptance')
    if job and (len(job)!=48 or any(c not in '0123456789abcdef' for c in job)):raise ValueError('Exact own canary token required')
    profile=ROOT/'artifacts'/('preview-'+secrets.token_hex(5));profile.mkdir(mode=0o700)
    if request:
        identity=profile/'ephemeral-key'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','English-page-acceptance','-f',str(identity)],check=True)
        public=Path(str(identity)+'.pub')
        try:payload=json.dumps({'public_key':public.read_text()}).encode()
        finally:identity.unlink(missing_ok=True);public.unlink(missing_ok=True)
        req=urllib.request.Request('https://eorls.com/debrescuestick/api/jobs',data=payload,
                                  headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=15) as response:job=json.load(response)['id']
        if len(job)!=48 or any(c not in '0123456789abcdef' for c in job):raise ValueError('Exact own acceptance token required')
    state=profile/'state';state.mkdir(mode=0o700)
    app=App(state)
    with app.store():pass
    server=HTTPServer(('127.0.0.1',0),DraftHandler);server.app=app
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    with socket.socket() as reservation:reservation.bind(('127.0.0.1',0));cdp=reservation.getsockname()[1]
    command=['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','-oExitOnForwardFailure=yes',
             '-oControlMaster=no','-oControlPath=none','-N','-L','127.0.0.1:'+str(cdp)+':127.0.0.1:41446']
    if not live:command+=['-R','127.0.0.1:0:127.0.0.1:'+str(server.server_address[1])]
    command.append('root@browser.local')
    record={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
            'source_sha256':{name:base.digest(ROOT/name) for name in ('server.py','worker.py','fast.py','keys.py','store.py','static/index.html','static/app.js','static/ui.js','static/style.css','static/move.html','static/move.css','preview.py','preview.mjs')},
            'local_http':server.server_address[1],'local_cdp':cdp,'session':'debrescuestick',
            'remote_profile':'/var/lib/browser-sessions/debrescuestick/profile',
            'remote_unit':'browser-session@debrescuestick.service','cpu_quota':'50%','memory_max_mib':768,
            'parallel_browser_runs':[],'started':time.time(),'success':False,'live':live,'job':job,'requested':request}
    child=None;expected=None
    try:
        with (profile/'tunnel.log').open('wb') as log:
            child=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            expected=(Path('/proc')/str(child.pid)/'cmdline').read_bytes();record['tunnel_pid']=child.pid
            end=time.monotonic()+10;remote=None
            while not live and time.monotonic()<end:
                if child.poll() is not None:raise RuntimeError('Owned tunnel failed; see tunnel.log')
                for line in (profile/'tunnel.log').read_text().splitlines():
                    fields=line.split()
                    if fields[:2]==['Allocated','port']:remote=int(fields[2])
                if remote:break
                time.sleep(.1)
            if not live and not remote:raise RuntimeError('No OS-assigned remote preview port')
            record['remote_http']=remote;base.write(profile/'run.json',record)
            url='https://eorls.com/debrescuestick/' if live else 'http://127.0.0.1:'+str(remote)+'/debrescuestick/'
            record['url']=url
            with (profile/'browser.log').open('wb') as output:
                node=Path(os.environ.get('DRS_NODE','node'))
                result=subprocess.run([str(node) if node.is_file() else 'node',str(ROOT/'preview.mjs'),str(cdp),
                    url,str(profile),'live' if live else 'preview',job or ''],
                    stdout=output,stderr=subprocess.STDOUT,timeout=90)
            if result.returncode:raise RuntimeError('Browser check failed; see browser.log')
            record.update(success=True,browser=json.loads((profile/'browser.json').read_text()))
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    finally:
        server.shutdown();server.server_close();thread.join(5)
        try:stop_tunnel(child,expected)
        except Exception as error:
            record.update(success=False,cleanup_error=type(error).__name__+': '+str(error))
            raise
        finally:
            record['finished']=time.time();base.write(profile/'run.json',record)
    print(json.dumps({'success':record['success'],'error':record.get('error'),'artifacts':str(profile)}))
    return 0 if record['success'] else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--live',action='store_true')
    group=p.add_mutually_exclusive_group();group.add_argument('--job');group.add_argument('--request',action='store_true')
    a=p.parse_args();raise SystemExit(run(a.live,a.job,a.request))
