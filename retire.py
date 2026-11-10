#!/usr/bin/env python3
"""Release only completed, identified rescue QA disks and ephemeral test keys."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time

import base

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/retire')
QA=Path('/var/lib/debrescuestick/qa')
FACTORY=Path('/var/lib/debrescuestick/factory')


def job_id(value):
    if not isinstance(value,str) or len(value)!=48 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Exact own QA job identifier required')
    return value


def guest_running(record):
    pid=record['pid'];path=Path('/proc')/str(pid)
    try:
        started=(path/'stat').read_text().rpartition(')')[2].split()[19]
        command=(path/'cmdline').read_bytes().decode(errors='replace')
    except FileNotFoundError:return False
    return [started,command]==record['identity']


def run(token,qa_key,legacy_key,failed,sha,base_sha):
    unit=base.admitted(token)
    if base.digest(Path(__file__))!=sha or base.digest(ROOT/'base.py')!=base_sha:raise RuntimeError('Frozen retirement source required')
    for value in (qa_key,legacy_key,failed):base.key(value)
    output=REMOTE/('run-'+base.key(token));output.mkdir(mode=0o700)
    record={'unit':unit,'started':time.time(),'success':False,'qa_job':qa_key,'legacy_job':legacy_key,'removed':[]}
    try:
        proof=json.loads((QA/qa_key/'result.json').read_text())
        legacy=json.loads((Path('/var/lib/debrescuestick/legacy')/('run-'+legacy_key)/'result.json').read_text())
        if proof.get('success') is not True or proof.get('qualified') is not True or legacy.get('success') is not True:
            raise ValueError('Completed QA and completed publication/migration required')
        profile=QA/qa_key
        if profile.resolve()!=profile or profile.stat().st_uid!=0:raise ValueError('Canonical own QA profile required')
        for mode in ('bios','uefi'):
            result=json.loads((profile/mode/'result.json').read_text())
            if result.get('success') is not True or result.get('clean_shutdown') is not True or result.get('qemu_exit')!=0:
                raise ValueError('Successful clean guest shutdown required')
            if guest_running(json.loads((profile/mode/'pid.json').read_text())):
                raise RuntimeError('Own recorded guest is still running; no deletion or signal')
        pending=[]
        for path in (profile/'jobs').iterdir():
            identifier=job_id(path.name)
            if path.resolve()!=path or path.stat().st_uid!=0:raise ValueError('Foreign QA job directory preserved')
            owner=path/'.owner'
            if owner.is_symlink() or json.loads(owner.read_text())!={'job':identifier,'schema':'drs-job-v1'}:
                raise ValueError('QA ownership marker mismatch')
            image=path/'image.img'
            if image.exists():
                if image.is_symlink() or not image.is_file() or image.stat().st_uid!=0 or image.stat().st_size!=8*1024**3:
                    raise ValueError('Unexpected QA image preserved')
                pending.append(image)
        for name in ('key-a','key-a.pub','key-b','key-b.pub'):
            path=profile/name
            if path.exists():
                if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_size>16384:
                    raise ValueError('Unexpected QA key preserved')
                pending.append(path)
        variables=profile/'uefi/OVMF_VARS.fd'
        if variables.exists():
            if variables.is_symlink() or variables.stat().st_uid!=0 or not 0<variables.stat().st_size<=4*1024**2:
                raise ValueError('Unexpected own firmware runtime preserved')
            pending.append(variables)
        # The failed early configuration is reconstructible; never remove a
        # hardlink to the current successful production template.
        failed_root=FACTORY/('image-'+failed)
        prior=json.loads((failed_root/'result.json').read_text())
        raw=failed_root/'base.img';production=Path('/var/lib/debrescuestick/state/base/base.img')
        if failed==proof['template_job'] or prior.get('success') is not False or prior.get('unit')!='debrescuestick-base-'+failed:
            raise ValueError('Exact own failed builder required')
        status=subprocess.check_output(['systemctl','show','debrescuestick-base-'+failed+'.service','--property=ActiveState','--value'],text=True).strip()
        if status not in ('inactive','failed'):raise ValueError('Failed builder must be stopped')
        if raw.exists():
            if raw.resolve()!=raw or raw.is_symlink() or raw.stat().st_uid!=0 or os.path.samefile(raw,production):
                raise ValueError('Production or foreign raw image preserved')
            pending.append(raw)
        for path in pending:
            info=path.stat()
            record['removed'].append({'path':str(path),'bytes':info.st_size,'blocks':info.st_blocks,'links_before':info.st_nlink})
            path.unlink()
        if any(Path(row['path']).exists() for row in record['removed']):raise RuntimeError('Own runtime retirement incomplete')
        current=json.loads((production.parent/'template.json').read_text())
        if current['sha256']!=proof['sha256'] or not production.is_file():raise RuntimeError('Production template binding changed')
        record.update(success=True,production_template_preserved=True,guest_processes_absent=True,
                      metadata_logs_preserved=True,original_sources_untouched=True)
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps({'success':record['success'],'error':record.get('error'),'removed_files':len(record['removed'])}),flush=True)
    return 0 if record['success'] else 1


def submit(token,qa_key,legacy_key,failed):
    for value in (token,qa_key,legacy_key,failed):base.key(value)
    raw=Path(__file__).read_bytes();helper=(ROOT/'base.py').read_bytes()
    sha=hashlib.sha256(raw).hexdigest();base_sha=hashlib.sha256(helper).hexdigest();unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import socket,json,base64,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/retire');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/('run-'+KEY)).exists(),'Existing retirement preserved'
code=p/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data,digest in [('retire.py',SOURCE,SHA),('base.py',BASE,BASE_SHA)]:
 f=code/name;raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==digest
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=32','--property=RuntimeMaxSec=300','--property=TimeoutStopSec=30',
 '/usr/bin/python3',str(code/'retire.py'),'run','--key',KEY,'--qa',QA,'--legacy',LEGACY,'--failed',FAILED,'--sha',SHA,'--base-sha',BASE_SHA]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'key':KEY,'unit':UNIT,'qa_job':QA,'legacy_job':LEGACY,'failed_job':FAILED,'source_sha256':SHA,'base_sha256':BASE_SHA}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'QA':qa_key,'LEGACY':legacy_key,'FAILED':failed,'UNIT':unit,'SHA':sha,'BASE_SHA':base_sha,
            'SOURCE':base64.b64encode(raw).decode(),'BASE':base64.b64encode(helper).decode()}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('retire-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/retire')/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
if (p/'result.json').exists():value['result']=json.loads((p/'result.json').read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code);base.write(ROOT/'artifacts'/('retire-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    for name in ('key','qa','legacy','failed','sha','base-sha'):p.add_argument('--'+name)
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.qa,a.legacy,a.failed,a.sha,a.base_sha))
    print(json.dumps(submit(a.key or secrets.token_hex(5),a.qa,a.legacy,a.failed) if a.action=='submit' else status(a.key)))
