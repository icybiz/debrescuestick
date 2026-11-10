#!/usr/bin/env python3
"""Narrow Apache cutover with native/canary gates, rollback and HTTPS readback."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

import base

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/publish')
FILES=('publish.py','base.py','deploy/apache.conf')
ENABLED=Path('/etc/apache2/sites-enabled/017-eorls.com-le-ssl.conf')
ORIGIN='https://eorls.com'
PREFIX='/debrescuestick'


def bundle():
    files={name:(ROOT/name).read_bytes() for name in FILES}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}
    return files,manifest,hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()


def patch_vhost(old):
    include='    Include /etc/debrescuestick/apache.conf\n'
    anchor='    ProxyPass / https://127.0.0.1:7796/\n'
    logging='    CustomLog ${APACHE_LOG_DIR}/eorls.com.ssl.access.log combined\n'
    if old.count(anchor)!=1 or old.count(logging)!=1 or include in old:
        raise ValueError('Exact untouched EORLS proxy/log anchors required')
    new=old.replace(anchor,include+anchor,1).replace(logging,logging.rstrip('\n')+' env=!drs_private\n',1)
    restored=new.replace(include,'',1).replace(' combined env=!drs_private\n',' combined\n',1)
    if restored!=old:raise ValueError('Unrelated vhost bytes changed')
    return new


def atomic(path,raw,mode=0o644,uid=0,gid=0):
    if path.is_symlink():raise ValueError('Atomic target must be the resolved actual file')
    temporary=path.with_name(path.name+'.drs-'+secrets.token_hex(5))
    with temporary.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    temporary.chmod(mode);os.chown(temporary,uid,gid);os.replace(temporary,path)


def read(url,limit=2*1024**2):
    with urllib.request.urlopen(url,timeout=30) as reply:
        raw=reply.read(limit+1)
        if len(raw)>limit:raise ValueError('Bounded web metadata required')
        return raw,{'status':reply.status,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'url':reply.url}


def run(token,stage_key,web_key,canary_key,vhost_sha,sha):
    unit=base.admitted(token)
    if bundle()[2]!=sha:raise RuntimeError('Frozen publisher bundle required')
    for value in (stage_key,web_key,canary_key):base.key(value)
    output=REMOTE/('run-'+base.key(token));output.mkdir(mode=0o700)
    record={'unit':unit,'started':time.time(),'success':False,'stage_job':stage_key,'web_job':web_key,'canary_job':canary_key}
    changed=None;before=None;target=None;info=None;include_written=False;reloaded=False
    try:
        stage=json.loads((Path('/var/lib/debrescuestick/rollout')/('run-'+stage_key)/'result.json').read_text())
        web=json.loads((Path('/var/lib/debrescuestick/rollout')/('run-'+web_key)/'result.json').read_text())
        canary=json.loads((Path('/var/lib/debrescuestick/canary')/('run-'+canary_key)/'result.json').read_text())
        if stage.get('success') is not True or web.get('success') is not True or web.get('previous_stage')!=stage_key:
            raise ValueError('Qualified refreshed private stage required')
        if (canary.get('success') is not True or canary.get('mode')!='image' or canary.get('stage_job')!=stage_key or
            not all(canary.get(name) is True for name in ('http_sha256','zip_crc','temporary_raw_removed'))):
            raise ValueError('Real generated image and full HTTP/ZIP canary required')
        if str(Path('/opt/debrescuestick/current').resolve())!=web['release']:raise ValueError('Different current deployment preserved')
        if canary['raw_bytes']!=8*1024**3 or stage['port']!=web['port']:raise ValueError('Exact current image/port binding required')
        target=ENABLED.resolve(strict=True)
        if target!=Path('/etc/apache2/sites-available/eorls.com-le-ssl.conf'):
            raise ValueError('Unexpected existing Apache configuration target preserved')
        before=target.read_bytes();info=target.stat()
        if hashlib.sha256(before).hexdigest()!=vhost_sha:raise ValueError('Existing vhost changed; compare before cutover')
        changed=patch_vhost(before.decode()).encode()
        record['root_before']=read(ORIGIN+'/')[1]
        backup=Path('/var/backups/debrescuestick')/('site-'+token);backup.mkdir(mode=0o700,parents=True)
        shutil.copy2(target,backup/'vhost.conf')
        base.write(backup/'metadata.json',{'target':str(target),'before_sha256':vhost_sha,
            'after_sha256':hashlib.sha256(changed).hexdigest(),'mode':info.st_mode & 0o7777,'uid':info.st_uid,'gid':info.st_gid})
        include=Path('/etc/debrescuestick/apache.conf')
        if include.exists():raise ValueError('Existing rescue Apache include preserved')
        config=(ROOT/'deploy/apache.conf').read_text().replace('DRS_PORT',str(stage['port'])).encode()
        atomic(include,config);include_written=True
        atomic(target,changed,info.st_mode & 0o7777,info.st_uid,info.st_gid)
        checked=subprocess.run(['apache2ctl','configtest'],capture_output=True,text=True)
        (output/'configtest.log').write_text(checked.stdout+checked.stderr)
        if checked.returncode:raise RuntimeError('Apache configtest failed before reload')
        subprocess.run(['systemctl','reload','apache2'],check=True);reloaded=True
        record['root_after']=read(ORIGIN+'/')[1]
        if record['root_after']['status']!=record['root_before']['status']:raise RuntimeError('Existing root response changed status')
        pages={}
        for name in ('','app.js','style.css','api/status'):
            raw,row=read(ORIGIN+PREFIX+'/'+name);pages[name or 'index']=row
            if name=='api/status':
                status=json.loads(raw)
                if status.get('available') is not True:raise RuntimeError('Published qualified service unavailable')
                expected=PREFIX+'/sources/'+stage['template_sha256']+'/'
                if status.get('sources_url')!=expected:raise RuntimeError('Published source binding mismatch')
            elif not name and b'DebRescueStick' not in raw:raise RuntimeError('Independent page was not served')
        record['pages']=pages
        source_url=ORIGIN+PREFIX+'/sources/'+stage['template_sha256']+'/'
        raw,row=read(source_url+'index.json',2*1024**2);catalog=json.loads(raw)
        if catalog.get('template_sha256')!=stage['template_sha256'] or catalog.get('includes_built_using') is not True:
            raise RuntimeError('Corresponding-source metadata mismatch')
        if len(catalog['sources'])!=stage['source_count'] or len(catalog['files'])!=stage['source_files']:
            raise RuntimeError('Corresponding-source coverage mismatch')
        def head(item):
            name,value=item
            path=Path(name)
            if path.is_absolute() or '..' in path.parts:raise ValueError('Foreign public source path refused')
            request=urllib.request.Request(source_url+urllib.parse.quote(name,safe='/'),method='HEAD')
            with urllib.request.urlopen(request,timeout=30) as reply:
                size=int(reply.headers['Content-Length'])
                if reply.status!=200 or size!=value['bytes']:raise RuntimeError('Public source length mismatch: '+name)
            return name
        with ThreadPoolExecutor(max_workers=4) as pool:verified=list(pool.map(head,catalog['files'].items()))
        record['sources']={'index':row,'versions':len(catalog['sources']),'verified_files':len(verified)}
        job=canary['job'];identifier=job['id']
        if len(identifier)!=48 or any(c not in '0123456789abcdef' for c in identifier):raise ValueError('Exact canary download token required')
        checksum=hashlib.sha256();amount=0
        base.write(output/'progress.json',{'phase':'full-https-image'})
        with urllib.request.urlopen(ORIGIN+PREFIX+'/download/'+identifier,timeout=30) as reply:
            while block:=reply.read(1024*1024):checksum.update(block);amount+=len(block)
        if amount!=job['bytes'] or checksum.hexdigest()!=job['sha256']:raise RuntimeError('Full public HTTPS image SHA256/length mismatch')
        record['image']={'bytes':amount,'sha256':checksum.hexdigest(),'full_https':True}
        access=Path('/var/log/apache2/eorls.com.ssl.access.log')
        with access.open('rb') as stream:
            stream.seek(max(0,access.stat().st_size-128*1024))
            if identifier.encode() in stream.read():raise RuntimeError('Personal token entered Apache access log')
        subprocess.run(['systemctl','enable','debrescuestick-web.service','debrescuestick-worker.service'],check=True)
        record.update(success=True,url=ORIGIN+PREFIX+'/',backup=str(backup),vhost=str(target),
                      vhost_sha256=hashlib.sha256(changed).hexdigest(),tokens_not_logged=True)
    except Exception as error:
        record['error']=type(error).__name__+': '+str(error)
        if changed is not None and target is not None and before is not None and target.read_bytes()==changed:
            atomic(target,before,info.st_mode & 0o7777,info.st_uid,info.st_gid)
            if include_written:
                own=Path('/etc/debrescuestick/apache.conf')
                if own.exists():own.unlink()
            checked=subprocess.run(['apache2ctl','configtest'],capture_output=True,text=True)
            (output/'rollback-configtest.log').write_text(checked.stdout+checked.stderr)
            if checked.returncode==0 and reloaded:
                subprocess.run(['systemctl','reload','apache2'],check=True);record['rolled_back']=True
        elif reloaded:record['rollback_refused']='Concurrent configuration change; preserve and inspect'
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','error','url','rolled_back','rollback_refused')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,stage_key,web_key,canary_key,vhost_sha):
    for value in (token,stage_key,web_key,canary_key):base.key(value)
    if len(vhost_sha)!=64 or any(c not in '0123456789abcdef' for c in vhost_sha):raise ValueError('Observed exact Apache SHA256 required')
    files,manifest,sha=bundle();unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import socket,json,base64,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/publish');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/('run-'+KEY)).exists(),'Existing publication preserved'
code=p/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data in FILES.items():
 f=code/name;f.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==MANIFEST[name]
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=64','--property=RuntimeMaxSec=1800','--property=TimeoutStopSec=45',
 '/usr/bin/python3',str(code/'publish.py'),'run','--key',KEY,'--stage',STAGE,'--web',WEB,'--canary',CANARY,'--vhost-sha',VHOST_SHA,'--sha',SHA]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'key':KEY,'unit':UNIT,'stage_job':STAGE,'web_job':WEB,'canary_job':CANARY,'bundle_sha256':SHA,'files':MANIFEST,'vhost_before_sha256':VHOST_SHA}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'STAGE':stage_key,'WEB':web_key,'CANARY':canary_key,
            'VHOST_SHA':vhost_sha,'UNIT':unit,'SHA':sha,
            'FILES':{name:base64.b64encode(raw).decode() for name,raw in files.items()},'MANIFEST':manifest}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('publish-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/publish')/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
for name in ('result','progress'):
 if (p/(name+'.json')).exists():value[name]=json.loads((p/(name+'.json')).read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code);base.write(ROOT/'artifacts'/('publish-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    for name in ('key','stage','web','canary','vhost-sha','sha'):p.add_argument('--'+name)
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.stage,a.web,a.canary,a.vhost_sha,a.sha))
    print(json.dumps(submit(a.key or secrets.token_hex(5),a.stage,a.web,a.canary,a.vhost_sha) if a.action=='submit' else status(a.key)))
