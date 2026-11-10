#!/usr/bin/env python3
"""Run an isolated libguestfs smoke probe only in a dedicated bounded prox unit."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/native')
HOSTNAME=os.environ.get('DRS_BUILD_HOST','')


def own(unit):
    tail=unit.removeprefix('debrescuestick-probe-')
    if unit!='debrescuestick-probe-'+tail or len(tail)!=10 or any(c not in '0123456789abcdef' for c in tail):
        raise ValueError('Exact own probe unit required')
    return unit


def admitted(unit):
    own(unit)
    if socket.gethostname()!=HOSTNAME or os.geteuid()!=0:raise RuntimeError('Probe requires the assigned prox host')
    expected='0::/system.slice/'+unit+'.service'
    if expected not in Path('/proc/self/cgroup').read_text().splitlines():raise RuntimeError('Own bounded probe unit required')
    group=Path('/sys/fs/cgroup/system.slice')/(unit+'.service')
    quota,period=(group/'cpu.max').read_text().split();memory=(group/'memory.max').read_text().strip()
    if quota=='max' or int(quota)/int(period)>1 or memory=='max' or int(memory)>2*1024**3:
        raise RuntimeError('Probe exceeds1CPU/2GiB')
    return group


def run(unit,sha):
    group=admitted(unit)
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=sha:raise RuntimeError('Frozen native probe source required')
    folder=REMOTE/unit;folder.mkdir(mode=0o700)
    temporary=folder/'tmp';temporary.mkdir(mode=0o700)
    cache=Path('/var/cache/debrescuestick/guestfs');cache.mkdir(mode=0o700,parents=True,exist_ok=True)
    env={**os.environ,'LIBGUESTFS_BACKEND':'direct','LIBGUESTFS_MEMSIZE':'512',
         'LIBGUESTFS_CACHEDIR':str(cache),'LIBGUESTFS_TMPDIR':str(temporary)}
    record={'unit':unit,'source_sha256':sha,'started':time.time(),'success':False}
    with (folder/'probe.log').open('wb') as log:
        child=subprocess.run(['/usr/bin/libguestfs-test-tool','--timeout','240'],stdout=log,stderr=subprocess.STDOUT,env=env)
    record['exit_code']=child.returncode
    remaining=[]
    for pid in (group/'cgroup.procs').read_text().split():
        try:
            name=(Path('/proc')/pid/'comm').read_text().strip()
            if name.startswith('qemu'):remaining.append({'pid':pid,'name':name})
        except FileNotFoundError:pass
    record.update(finished=time.time(),own_qemu_remaining=remaining,success=child.returncode==0 and not remaining)
    (folder/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record),flush=True);return 0 if record['success'] else 1


def submit():
    raw=Path(__file__).read_bytes();sha=hashlib.sha256(raw).hexdigest();unit='debrescuestick-probe-'+sha[:10]
    code=r'''from pathlib import Path
import base64,json,os,socket,hashlib,subprocess
assert socket.gethostname()==HOSTNAME
p=Path(REMOTE);p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
f=p/('code-'+SHA+'.py');raw=base64.b64decode(PAYLOAD)
if f.exists():assert f.read_bytes()==raw
else:f.write_bytes(raw);f.chmod(0o600)
assert hashlib.sha256(f.read_bytes()).hexdigest()==SHA
assert not (p/UNIT).exists(),'Previous native probe preserved'
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=128','--property=RuntimeMaxSec=360','--property=TimeoutStopSec=30',
 '--property=IPAddressDeny=any','/usr/bin/python3',str(f),'run','--unit',UNIT,'--sha',SHA]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'unit':UNIT,'source_sha256':SHA,'root':str(p)}))
'''
    prefix='HOSTNAME='+repr(HOSTNAME)+'\nREMOTE='+repr(str(REMOTE))+'\nSHA='+repr(sha)+'\nUNIT='+repr(unit)+'\nPAYLOAD='+repr(base64.b64encode(raw).decode())+'\n'
    value=remote(prefix+code);(ROOT/'artifacts/native-job.json').write_text(json.dumps(value,indent=2)+'\n');return value


def remote(code):
    compile(code,'<native-probe>','exec')
    reply=subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes',os.environ.get('DRS_BUILD_SSH','root@prox'),'python3 -'],
                         input=code,text=True,capture_output=True,timeout=30)
    if reply.returncode:raise RuntimeError(reply.stderr[-2500:])
    return json.loads(reply.stdout)


def status():
    row=json.loads((ROOT/'artifacts/native-job.json').read_text());unit=own(row['unit'])
    code=r'''from pathlib import Path
import subprocess,json
p=Path(REMOTE)/UNIT
raw=subprocess.check_output(['systemctl','show',UNIT+'.service','--property=ActiveState,SubState,ExecMainStatus,Result,MemoryPeak,CPUUsageNSec'],text=True)
value={'unit':UNIT,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
if (p/'result.json').exists():value['result']=json.loads((p/'result.json').read_text())
if (p/'probe.log').exists():
 with (p/'probe.log').open('rb') as stream:stream.seek(max(0,(p/'probe.log').stat().st_size-2500));value['log_tail']=stream.read().decode(errors='replace')
print(json.dumps(value))
'''
    value=remote('REMOTE='+repr(str(REMOTE))+'\nUNIT='+repr(unit)+'\n'+code)
    (ROOT/'artifacts/native-status.json').write_text(json.dumps(value,indent=2)+'\n')
    return {k:v for k,v in value.items() if k!='log_tail'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'));p.add_argument('--unit');p.add_argument('--sha');a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.unit,a.sha))
    print(json.dumps(submit() if a.action=='submit' else status()))
