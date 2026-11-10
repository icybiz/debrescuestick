#!/usr/bin/env python3
"""Generate and verify one real private-service image, then prove its expiry."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import zipfile

import base

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/canary')


def get(url,data=None):
    request=urllib.request.Request(url,data=json.dumps(data).encode() if data is not None else None,
                                  headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=10) as reply:return json.load(reply)


def wait_removed(state,identifier,timeout=20,interval=1):
    end=time.monotonic()+timeout
    while True:
        db=sqlite3.connect(state/'jobs.sqlite3')
        try:row=db.execute('SELECT id FROM jobs WHERE id=?',(identifier,)).fetchone()
        finally:db.close()
        if row is None and not (state/'jobs'/identifier).exists():return
        if time.monotonic()>=end:raise RuntimeError('Expired cleanup not complete: artifacts or row retained')
        time.sleep(interval)


def run(token,stage_key,sha,base_sha,expire_key=None):
    unit=base.admitted(token)
    if base.digest(Path(__file__))!=sha or base.digest(ROOT/'base.py')!=base_sha:raise RuntimeError('Frozen canary source required')
    base.key(stage_key)
    stage=json.loads((Path('/var/lib/debrescuestick/rollout')/('run-'+stage_key)/'result.json').read_text())
    if stage.get('success') is not True or stage.get('phase') not in ('private-services-staged','upgraded'):
        raise RuntimeError('Qualified owned deployment required')
    port=stage['port']
    if not isinstance(port,int) or not 0<port<65536:raise ValueError('Own staged port required')
    url='http://127.0.0.1:'+str(port)+'/debrescuestick'
    output=REMOTE/('run-'+base.key(token));output.mkdir(mode=0o700)
    record={'unit':unit,'started':time.time(),'stage_job':stage_key,'success':False,'mode':'expiry' if expire_key else 'image'}
    try:
        state=Path('/var/lib/debrescuestick/state')
        if expire_key:
            base.key(expire_key)
            previous=REMOTE/('run-'+expire_key)
            old=json.loads((previous/'result.json').read_text())
            if old.get('success') is not True or old.get('mode')!='image' or old['stage_job']!=stage_key:
                raise RuntimeError('Verified actual canary image required')
            job=old['job'];identifier=job['id']
            if len(identifier)!=48 or any(c not in '0123456789abcdef' for c in identifier):raise ValueError('Own canary token required')
            with sqlite3.connect(state/'jobs.sqlite3') as db:
                changed=db.execute("UPDATE jobs SET expires=? WHERE id=? AND sha256=? AND state='ready'",
                                   (int(time.time())-1,identifier,job['sha256'])).rowcount
                existing=db.execute('SELECT id FROM jobs WHERE id=?',(identifier,)).fetchone()
            db.close()
            if changed!=1:
                if existing is not None or (state/'jobs'/identifier).exists():
                    raise RuntimeError('Exact own ready or already-cleaned canary required for expiry probe')
                record['already_removed']=True
            try:get(url+'/api/jobs/'+identifier)
            except urllib.error.HTTPError as error:
                if error.code!=404:raise
            else:raise RuntimeError('Expired job remains available')
            try:
                with urllib.request.urlopen(url+'/download/'+identifier,timeout=10):pass
            except urllib.error.HTTPError as error:
                if error.code!=404:raise
            else:raise RuntimeError('Expired download remains available')
            wait_removed(state,identifier)
            for name in ('key','key.pub'):
                path=previous/name
                if path.is_symlink():raise ValueError('Linked test key preserved')
                path.unlink(missing_ok=True)
            record.update(success=True,expired_job=identifier,api_rejected=True,download_rejected=True,
                          artifacts_removed=True,row_removed=True,previous_canary=expire_key)
        else:
            end=time.monotonic()+30
            while not get(url+'/api/status')['available']:
                if time.monotonic()>end:raise RuntimeError('Private qualified worker not available')
                time.sleep(1)
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','DebRescueStick-ephemeral-canary','-f',str(output/'key')],check=True)
            public=(output/'key.pub').read_text()
            expected=subprocess.check_output(['ssh-keygen','-l','-E','sha256','-f',str(output/'key.pub')],text=True).split()[1]
            requested=time.monotonic()
            job=get(url+'/api/jobs',{'public_key':public})
            if job['fingerprint']!=expected:raise RuntimeError('Actual API key fingerprint mismatch')
            identifier=job['id']
            if len(identifier)!=48 or any(c not in '0123456789abcdef' for c in identifier):raise ValueError('Own generated token required')
            base.write(output/'request.json',job)
            end=time.monotonic()+1800;last=None
            while True:
                job=get(url+'/api/jobs/'+identifier)
                if job['state']!=last:
                    last=job['state'];base.write(output/'progress.json',{'phase':last,'job':identifier})
                if last=='ready':break
                if last=='failed':raise RuntimeError('Real unprivileged worker failed to generate image')
                if time.monotonic()>end:raise RuntimeError('Actual image creation timed out')
                time.sleep(1)
            record.update(ready_seconds=time.monotonic()-requested,ready_poll_seconds=1)
            checksum=hashlib.sha256();size=0
            archive=output/'http-readback.zip'
            with urllib.request.urlopen(url+'/download/'+identifier,timeout=30) as reply,archive.open('xb') as sink:
                while block:=reply.read(1024*1024):checksum.update(block);size+=len(block);sink.write(block)
            if checksum.hexdigest()!=job['sha256'] or size!=job['bytes']:raise RuntimeError('Full HTTP download SHA256/length mismatch')
            if stage.get('published'):
                public_url='https://eorls.com/debrescuestick/download/'+identifier
                checksum=hashlib.sha256();public_size=0
                with urllib.request.urlopen(public_url,timeout=30) as reply:
                    while block:=reply.read(1024**2):checksum.update(block);public_size+=len(block)
                if checksum.hexdigest()!=job['sha256'] or public_size!=size:raise RuntimeError('Full HTTPS download mismatch')
                record['https_sha256']=True
                metadata=state/'jobs'/identifier/'archive.json'
                if metadata.exists():
                    meta=json.loads(metadata.read_text());boundary=meta['prefix_bytes']
                    with (state/'archives'/meta['base_sha256']/'prefix.zip').open('rb') as source:
                        source.seek(boundary-8);expected_bytes=source.read(8)
                    expected_bytes+=(state/'jobs'/identifier/'image.tail').read_bytes()[:9]
                    request=urllib.request.Request(public_url,headers={'Range':'bytes='+str(boundary-8)+'-'+str(boundary+8)})
                    with urllib.request.urlopen(request,timeout=30) as reply:
                        if reply.status!=206 or reply.read()!=expected_bytes:raise RuntimeError('Real HTTPS composite boundary range differs')
                    record['https_boundary_range']=True
            raw_sha=hashlib.sha256();amount=0
            with zipfile.ZipFile(archive) as package:
                if package.namelist()!=['DebRescueStick-amd64.img']:raise RuntimeError('Exact single-image ZIP payload required')
                with package.open('DebRescueStick-amd64.img') as stream:
                    while block:=stream.read(1024*1024):raw_sha.update(block);amount+=len(block)
            template=json.loads((state/'base/template.json').read_text())
            if amount!=template['bytes']:raise RuntimeError('Extracted image byte length mismatch')
            archive.unlink()
            if (state/'jobs'/identifier/'image.img').exists():raise RuntimeError('Temporary raw image retained after packaging')
            record.update(success=True,job=job,http_sha256=True,http_bytes=size,zip_crc=True,
                          raw_bytes=amount,raw_sha256=raw_sha.hexdigest(),temporary_raw_removed=True)
    except Exception as error:
        record['error']=type(error).__name__+': '+str(error)
        log=subprocess.run(['journalctl','-u','debrescuestick-worker.service','-n','25','--no-pager'],capture_output=True,text=True)
        (output/'worker-journal.log').write_text(log.stdout+log.stderr)
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','error','mode','http_bytes','raw_bytes')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,stage_key,expire_key=None):
    for value in (token,stage_key):base.key(value)
    if expire_key:base.key(expire_key)
    raw=Path(__file__).read_bytes();helper=(ROOT/'base.py').read_bytes()
    sha=hashlib.sha256(raw).hexdigest();base_sha=hashlib.sha256(helper).hexdigest();unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import socket,json,base64,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/canary');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/('run-'+KEY)).exists(),'Existing canary preserved'
code=p/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data,digest in [('canary.py',SOURCE,SHA),('base.py',BASE,BASE_SHA)]:
 f=code/name;raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==digest
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=32','--property=RuntimeMaxSec=2400','--property=TimeoutStopSec=45',
 '/usr/bin/python3',str(code/'canary.py'),'run','--key',KEY,'--stage',STAGE,'--sha',SHA,'--base-sha',BASE_SHA]
if EXPIRE:argv+=['--expire',EXPIRE]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'key':KEY,'unit':UNIT,'stage_job':STAGE,'source_sha256':SHA,'base_sha256':BASE_SHA,'expire':EXPIRE}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'STAGE':stage_key,'EXPIRE':expire_key,'UNIT':unit,'SHA':sha,'BASE_SHA':base_sha,
            'SOURCE':base64.b64encode(raw).decode(),'BASE':base64.b64encode(helper).decode()}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('canary-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/canary')/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
for name in ('result','progress'):
 if (p/(name+'.json')).exists():value[name]=json.loads((p/(name+'.json')).read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code);base.write(ROOT/'artifacts'/('canary-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    for name in ('key','stage','sha','base-sha','expire'):p.add_argument('--'+name)
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.stage,a.sha,a.base_sha,a.expire))
    print(json.dumps(submit(a.key or secrets.token_hex(5),a.stage,a.expire) if a.action=='submit' else status(a.key)))
