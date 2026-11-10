#!/usr/bin/env python3
"""Prepare only missing rescue-image tools in a bounded own prox unit."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parent
SETUP=Path('/var/lib/debrescuestick/setup')
PACKAGES=('libguestfs-tools','qemu-system-x86','ovmf')
HOSTNAME=os.environ.get('DRS_BUILD_HOST','')
POLICY=Path('/usr/sbin/policy-rc.d')
DENY=b'#!/bin/sh\nexit 101\n'


def own_unit(unit):
    suffix=unit.removeprefix('debrescuestick-tools-')
    if unit!='debrescuestick-tools-'+suffix or len(suffix)!=10 or any(c not in '0123456789abcdef' for c in suffix):
        raise ValueError('Exact own tools unit required')
    return unit


def changes(text):
    result={}
    for line in text.splitlines():
        if line.startswith('Remv '):raise RuntimeError('Existing package removal refused')
        if not line.startswith('Inst '):continue
        before,sep,after=line.partition('(')
        if not sep or '[' in before:raise RuntimeError('Existing package upgrade refused')
        name=before.split()[1];version=after.split()[0]
        if name in result:raise RuntimeError('Duplicate planned package')
        result[name]=version
    return result


def resources(unit):
    expected='0::/system.slice/'+unit+'.service'
    if expected not in Path('/proc/self/cgroup').read_text().splitlines():raise RuntimeError('Own bounded preparation unit required')
    group=Path('/sys/fs/cgroup/system.slice')/(unit+'.service')
    quota,period=(group/'cpu.max').read_text().split();memory=(group/'memory.max').read_text().strip()
    if quota=='max' or int(quota)/int(period)>1 or memory=='max' or int(memory)>768*1024**2:
        raise RuntimeError('Preparation exceeds1CPU/768MiB')


def restore_policy(unit):
    own_unit(unit);receipt=SETUP/(unit+'-policy-restored.json')
    if receipt.exists():return json.loads(receipt.read_text())
    snapshot=SETUP/(unit+'-policy.json')
    if not snapshot.exists():return {'restored':True,'changed':False}
    previous=json.loads(snapshot.read_text())
    if POLICY.is_symlink() or not POLICY.exists() or POLICY.read_bytes()!=DENY:
        return {'restored':False,'error':'Concurrent service-policy change preserved'}
    if previous['existed']:
        POLICY.write_bytes(base64.b64decode(previous['data']));POLICY.chmod(previous['mode'])
        os.chown(POLICY,previous['uid'],previous['gid'])
        os.utime(POLICY,ns=(previous['atime_ns'],previous['mtime_ns']))
    else:POLICY.unlink()
    result={'restored':True,'changed':True};receipt.write_text(json.dumps(result)+'\n');return result


def install(unit,sha):
    if socket.gethostname()!=HOSTNAME or os.geteuid()!=0:raise RuntimeError('Only the assigned prox host may prepare these tools')
    resources(unit)
    if hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=sha:raise RuntimeError('Frozen preparation source required')
    log=SETUP/(unit+'.log');record={'success':False,'source_sha256':sha,'unit':unit,'started':time.time()}
    environment={**os.environ,'DEBIAN_FRONTEND':'noninteractive','NEEDRESTART_MODE':'l','LC_ALL':'C'}
    policy=POLICY;changed=False
    try:
        with log.open('x') as output:
            subprocess.run(['apt-get','-o','APT::Update::Error-Mode=any','update'],stdout=output,stderr=subprocess.STDOUT,
                           env=environment,check=True,timeout=300)
            command=['apt-get','--simulate','--no-upgrade','--no-install-recommends','install',*PACKAGES]
            reply=subprocess.run(command,capture_output=True,text=True,env=environment,check=True,timeout=90)
            output.write(reply.stdout+reply.stderr);output.flush();planned=changes(reply.stdout)
            if not planned:raise RuntimeError('Expected missing tools; do not repeat preparation')
            record['packages']=planned
            if policy.is_symlink():raise RuntimeError('Linked service policy preserved')
            previous={'existed':policy.exists()}
            if policy.exists():
                info=policy.stat();previous.update(data=base64.b64encode(policy.read_bytes()).decode(),mode=info.st_mode & 0o777,
                    uid=info.st_uid,gid=info.st_gid,atime_ns=info.st_atime_ns,mtime_ns=info.st_mtime_ns)
            snapshot=SETUP/(unit+'-policy.json')
            with snapshot.open('x') as snapshot_output:
                snapshot_output.write(json.dumps(previous)+'\n');snapshot_output.flush();os.fsync(snapshot_output.fileno())
            policy.write_bytes(DENY);policy.chmod(0o755);changed=True
            selectors=[name+'='+version for name,version in planned.items()]
            subprocess.run(['apt-get','-y','--no-upgrade','--no-install-recommends',
                            '-o','APT::Get::AllowUnauthenticated=false','install',*selectors],
                           stdout=output,stderr=subprocess.STDOUT,env=environment,check=True,timeout=600)
            record['success']=True
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    finally:
        if changed:
            restored=restore_policy(unit)
            if not restored['restored']:record['success']=False;record['error']=restored['error']
        record['finished']=time.time();(SETUP/(unit+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'success':record['success'],'unit':unit,'error':record.get('error')}),flush=True)
    return 0 if record['success'] else 1


def prepare():
    raw=Path(__file__).read_bytes();sha=hashlib.sha256(raw).hexdigest();unit='debrescuestick-tools-'+sha[:10]
    code=r'''import pathlib,base64,hashlib,os,json,socket,subprocess
assert socket.gethostname()==HOSTNAME
p=pathlib.Path(SETUP);p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
target=p/('host-'+SHA+'.py');data=base64.b64decode(PAYLOAD)
if target.exists():assert target.read_bytes()==data
else:target.write_bytes(data);target.chmod(0o600)
assert hashlib.sha256(target.read_bytes()).hexdigest()==SHA
assert not (p/(UNIT+'.json')).exists(),'Preparation record already exists; inspect instead of repeating'
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=768M',
 '--property=MemorySwapMax=0','--property=TasksMax=128','--property=Nice=10',
 '--property=ExecStopPost=/usr/bin/python3 '+str(target)+' restore-policy --unit '+UNIT,
 '--property=RuntimeMaxSec=1000','--property=TimeoutStopSec=30','/usr/bin/python3',str(target),'install','--unit',UNIT,'--sha',SHA]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'unit':UNIT,'source_sha256':SHA,'setup':str(p)}))
'''
    # Prefix constants instead of substituting inside encoded code/data.
    code='HOSTNAME='+repr(HOSTNAME)+'\nSETUP='+repr(str(SETUP))+'\nSHA='+repr(sha)+'\nUNIT='+repr(unit)+'\nPAYLOAD='+repr(base64.b64encode(raw).decode())+'\n'+code
    reply=subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes',os.environ.get('DRS_BUILD_SSH','root@prox'),'python3 -'],
                         input=code,text=True,capture_output=True,timeout=30)
    if reply.returncode:raise RuntimeError(reply.stderr[-2500:])
    value=json.loads(reply.stdout);path=ROOT/'artifacts';path.mkdir(exist_ok=True)
    (path/'tools-job.json').write_text(json.dumps(value,indent=2)+'\n');return value


def status():
    row=json.loads((ROOT/'artifacts/tools-job.json').read_text());unit=own_unit(row['unit'])
    code='''from pathlib import Path
import json,subprocess
p=Path(SETUP);unit=UNIT
raw=subprocess.check_output(['systemctl','show',unit+'.service','--property=ActiveState,SubState,ExecMainStatus,Result'],text=True)
v={'unit':unit,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
if (p/(unit+'.json')).exists():v['result']=json.loads((p/(unit+'.json')).read_text())
print(json.dumps(v))
'''.replace('SETUP',repr(str(SETUP))).replace('UNIT',repr(unit))
    reply=subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes',os.environ.get('DRS_BUILD_SSH','root@prox'),'python3 -'],input=code,
                         text=True,capture_output=True,check=True,timeout=30)
    value=json.loads(reply.stdout);(ROOT/'artifacts/tools-status.json').write_text(json.dumps(value,indent=2)+'\n')
    return {**value,'result':({k:value['result'].get(k) for k in ('success','error','started','finished')} if 'result' in value else None)}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('prepare','status','install','restore-policy'))
    parser.add_argument('--unit');parser.add_argument('--sha');args=parser.parse_args()
    if args.action=='install':raise SystemExit(install(args.unit,args.sha))
    if args.action=='restore-policy':
        if socket.gethostname()!=HOSTNAME or os.geteuid()!=0:raise RuntimeError('Own root cleanup on prox required')
        print(json.dumps(restore_policy(args.unit)));raise SystemExit(0)
    print(json.dumps(prepare() if args.action=='prepare' else status()))
