#!/usr/bin/env python3
"""Fetch pinned Debian hardware-capable base inputs only on bounded prox jobs."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/factory')
HOSTNAME=os.environ.get('DRS_BUILD_HOST','')


def key(value):
    if len(value)!=10 or any(c not in '0123456789abcdef' for c in value):raise ValueError('Exact own factory key required')
    return value


def pin(value):
    info=value['info'];version=info['version'];date,sep,count=version.partition('-')
    if len(date)!=8 or not sep or not count or any(c not in '0123456789' for c in date+count):raise ValueError('Pinned Debian build required')
    url='https://cloud.debian.org/images/cloud/trixie/'+version+'/debian-13-generic-amd64-'+version+'.qcow2'
    if (info['arch'],info['release'],info['vendor'],info['type'])!=('amd64','trixie','generic','official') or value['url']!=url:
        raise ValueError('Official hardware-capable Debian13 generic AMD64 input required')
    sha=value['sha512']
    if len(sha)!=128 or any(c not in '0123456789abcdef' for c in sha) or not 0<value['bytes']<=1024**3:
        raise ValueError('Bounded vendor bytes and SHA512 required')
    return value


def admitted(token):
    unit='debrescuestick-base-'+key(token)
    if socket.gethostname()!=HOSTNAME or os.geteuid()!=0:raise RuntimeError('Image input work requires assigned prox host')
    if '0::/system.slice/'+unit+'.service' not in Path('/proc/self/cgroup').read_text().splitlines():
        raise RuntimeError('Own bounded image-input unit required')
    group=Path('/sys/fs/cgroup/system.slice')/(unit+'.service')
    quota,period=(group/'cpu.max').read_text().split();memory=(group/'memory.max').read_text().strip()
    if quota=='max' or int(quota)/int(period)>1 or memory=='max' or int(memory)>2*1024**3:
        raise RuntimeError('Image-input job exceeds1CPU/2GiB')
    return unit


def digest(path,algorithm='sha256'):
    with path.open('rb') as stream:return hashlib.file_digest(stream,algorithm).hexdigest()


def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_name(path.name+'.new');temporary.write_text(json.dumps(value,indent=2)+'\n');os.replace(temporary,path)


def brief(value):
    """Full proofs remain in artifacts; routine terminal output stays bounded."""
    result={k:value[k] for k in ('unit','key','systemd','progress') if k in value}
    row=value.get('result',{})
    if row:
        result['result']={k:row[k] for k in ('success','error','qualified','sha256','completed','directory','template') if k in row}
        if 'files' in row:result['result']['file_count']=len(row['files'])
    if row.get('success') is False and 'tail' in value:result['tail']=value['tail']
    for firmware in ('bios','uefi'):
        if firmware in value:result[firmware]=value[firmware]
    return result


def run(token,sha,pin_sha):
    unit=admitted(token)
    if digest(Path(__file__))!=sha:raise RuntimeError('Frozen factory source required')
    input_file=REMOTE/'inputs'/('pin-'+pin_sha+'.json')
    if digest(input_file)!=pin_sha:raise RuntimeError('Pinned input metadata changed')
    source=pin(json.loads(input_file.read_text()));output=REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'unit':unit,'source_sha256':sha,'input_sha256':pin_sha,'started':time.time(),'success':False}
    try:
        available=os.statvfs(REMOTE).f_bavail*os.statvfs(REMOTE).f_frsize
        if available<50*1024**3+2*source['bytes']:raise RuntimeError('50GiB host reserve plus source space required')
        cache=REMOTE/'inputs';target=cache/(source['sha512']+'.qcow2')
        with (cache/'fetch.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if target.exists():
                if target.is_symlink() or target.stat().st_size!=source['bytes'] or digest(target,'sha512')!=source['sha512']:
                    raise RuntimeError('Different existing cloud input preserved')
            else:
                part=target.with_suffix('.qcow2.part')
                if part.exists():raise RuntimeError('Previous partial cloud input preserved; inspect before retry')
                amount=0;checksum=hashlib.sha512()
                request=urllib.request.Request(source['url'],headers={'User-Agent':'DebRescueStick-build'})
                with urllib.request.urlopen(request,timeout=90) as reply,part.open('xb') as stream:
                    if not reply.url.startswith('https://'):raise RuntimeError('HTTPS image source required')
                    while block:=reply.read(1024*1024):
                        amount+=len(block)
                        if amount>source['bytes']:raise RuntimeError('Vendor image length exceeded')
                        checksum.update(block);stream.write(block)
                        if amount%(32*1024*1024)==0:write(output/'progress.json',{'phase':'download','bytes':amount,'total':source['bytes']})
                    stream.flush();os.fsync(stream.fileno())
                if amount!=source['bytes'] or checksum.hexdigest()!=source['sha512']:raise RuntimeError('Vendor image SHA512/length mismatch')
                os.replace(part,target);target.chmod(0o600)
        record.update(success=True,source=source,image=str(target),sha512_verified=True)
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','unit','error','image')}),flush=True)
    return 0 if record['success'] else 1


def remote(code):
    compile(code,'<factory-submit>','exec')
    reply=subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes',os.environ.get('DRS_BUILD_SSH','root@prox'),'python3 -'],input=code,
                         capture_output=True,text=True,timeout=30)
    if reply.returncode:raise RuntimeError(reply.stderr[-2500:])
    return json.loads(reply.stdout)


def submit(token):
    key(token);source=Path(__file__).read_bytes();raw=(ROOT/'debian.lock.json').read_bytes();pin(json.loads(raw))
    sha=hashlib.sha256(source).hexdigest();input_sha=hashlib.sha256(raw).hexdigest();unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import os,json,base64,socket,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path(REMOTE);p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
(p/'inputs').mkdir(mode=0o700,exist_ok=True)
for name,data,sha in [('code-'+SOURCE_SHA+'.py',SOURCE,SOURCE_SHA),('inputs/pin-'+PIN_SHA+'.json',PIN,PIN_SHA)]:
 f=p/name;raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==sha
assert not (p/('run-'+KEY)).exists(),'Existing factory run preserved'
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=128','--property=RuntimeMaxSec=1200','--property=TimeoutStopSec=30',
 '/usr/bin/python3',str(p/('code-'+SOURCE_SHA+'.py')),'run','--key',KEY,'--sha',SOURCE_SHA,'--pin-sha',PIN_SHA]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'unit':UNIT,'key':KEY,'source_sha256':SOURCE_SHA,'pin_sha256':PIN_SHA}))
'''
    values={'HOSTNAME':HOSTNAME,'REMOTE':str(REMOTE),'SOURCE_SHA':sha,'PIN_SHA':input_sha,'KEY':token,'UNIT':unit,
            'SOURCE':base64.b64encode(source).decode(),'PIN':base64.b64encode(raw).decode()}
    prefix='\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'
    result=remote(prefix+code);write(ROOT/'artifacts'/('base-job-'+token+'.json'),result);return result


def status(token):
    key(token);row=json.loads((ROOT/'artifacts'/('base-job-'+token+'.json')).read_text())
    code=r'''from pathlib import Path
import subprocess,json
p=Path(REMOTE)/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show',UNIT+'.service','--property=ActiveState,SubState,ExecMainStatus,Result'],text=True)
value={'unit':UNIT,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
for name in ('result','progress'):
 if (p/(name+'.json')).exists():value[name]=json.loads((p/(name+'.json')).read_text())
print(json.dumps(value))
'''
    result=remote('REMOTE='+repr(str(REMOTE))+'\nKEY='+repr(token)+'\nUNIT='+repr(row['unit'])+'\n'+code)
    write(ROOT/'artifacts'/('base-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    p.add_argument('--key');p.add_argument('--sha');p.add_argument('--pin-sha');a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.sha,a.pin_sha))
    print(json.dumps(submit(a.key or secrets.token_hex(5)) if a.action=='submit' else status(a.key)))
