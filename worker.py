#!/usr/bin/env python3
"""Serialize isolated libguestfs personalization and expire only owned artifacts."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import time
import zipfile

from keys import public_key
from store import Store
import fast

FILES={'.owner','public.key','image.img','image.zip.part','image.zip','guestfs.log',
       'keys.fat','image.tail','image.tail.part','archive.json'}
TEMPLATES={}


def load_template(path,proof):
    if path not in TEMPLATES:
        candidate=fast.Template(path/'fast')
        if candidate.meta!=proof['fast']:raise ValueError('Cold archive manifest changed')
        TEMPLATES[path]=candidate
    return TEMPLATES[path]


def require_host():
    # This guard runs before reading/copying a disk image or launching an appliance.
    if socket.gethostname().partition('.')[0] in ('aicoder2','aicoder','localhost'):
        raise RuntimeError('Image/VM work is forbidden on this shared development host')
    marker=Path('/etc/debrescuestick/worker.json');info=marker.stat()
    if marker.resolve()!=marker or info.st_uid!=0 or info.st_mode & 0o022:
        raise RuntimeError('Protected worker host marker required')
    record=json.loads(marker.read_text())
    if record.get('hostname')!=socket.gethostname():raise RuntimeError('Wrong worker host')
    actual=Path('/proc/self/cgroup').read_text().splitlines()
    units=[line.removeprefix('0::/system.slice/') for line in actual if line.startswith('0::/system.slice/')]
    if len(units)!=1:raise RuntimeError('Dedicated worker cgroup required')
    unit=units[0]
    qa=unit.removeprefix('debrescuestick-qa-worker-').removesuffix('.service')
    if unit!='debrescuestick-worker.service' and (unit!='debrescuestick-qa-worker-'+qa+'.service' or len(qa)!=10 or any(c not in '0123456789abcdef' for c in qa)):
        raise RuntimeError('Unknown worker cgroup')
    group=Path('/sys/fs/cgroup/system.slice')/unit
    if not group.is_dir():raise RuntimeError('Dedicated bounded worker service required')
    limit=(group/'memory.max').read_text().strip()
    quota,period=(group/'cpu.max').read_text().split()
    if limit=='max' or int(limit)>2*1024**3 or quota=='max' or int(quota)/int(period)>1:
        raise RuntimeError('Worker exceeds1CPU/2GiB')
    if '0::/system.slice/'+unit not in actual:
        raise RuntimeError('Process is not in the admitted worker cgroup')


def token(value):
    if not isinstance(value,str) or len(value)!=48 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Exact own job token required')
    return value


def folder(state,job):
    state=Path(state)
    if state.resolve()!=state or state.is_symlink():raise ValueError('Canonical own state directory required')
    path=state/'jobs'/token(job)
    if path.resolve()!=path or not path.is_relative_to(state):raise ValueError('Foreign job path refused')
    return path


def cleanup(state,job):
    path=folder(state,job)
    if not path.exists():return
    owner=path/'.owner'
    if owner.is_symlink() or json.loads(owner.read_text())!={'job':job,'schema':'drs-job-v1'}:
        raise ValueError('Foreign job artifacts preserved')
    children=list(path.iterdir())
    if any(p.name not in FILES or p.is_symlink() or not p.is_file() for p in children):
        raise ValueError('Unexpected job artifact preserved')
    for p in children:p.unlink()
    path.rmdir()


def personalize(state,job):
    require_host()
    base=Path(state)/'base'
    # A native qualification run must use exactly the production personalization
    # path before it can approve publication. Queue admission checks qualified.json;
    # this lower-level operation requires a verified, keyless, cold template.
    proof=json.loads((base/'template.json').read_text())
    if proof.get('keyless') is not True or proof.get('cold_identity') is not True:
        raise ValueError('Verified keyless cold template required')
    if proof.get('arch')!='amd64':raise ValueError('Only AMD64 templates are supported')
    if 'fast' in proof:
        key,fingerprint=public_key(job['key'])
        if fingerprint!=job['fingerprint']:raise ValueError('Requested key identity changed')
        output=folder(state,job['id']);output.parent.mkdir(mode=0o700,exist_ok=True);output.mkdir(mode=0o700)
        (output/'.owner').write_text(json.dumps({'job':job['id'],'schema':'drs-job-v1'}))
        tail,size,sha=load_template(base,proof).personalize(key,output)
        (output/'image.tail').write_bytes(tail)
        (output/'archive.json').write_text(json.dumps({'base_sha256':proof['sha256'],'bytes':size,
                                                    'sha256':sha,'prefix_bytes':size-len(tail)}))
        return output
    image=base/'base.img'
    if image.is_symlink():raise ValueError('Linked base image refused')
    info=image.stat()
    if info.st_size<=0 or info.st_size>8*1024**3:raise ValueError('Base exceeds the8GiB image limit')
    space=os.statvfs(state)
    if space.f_bavail*space.f_frsize<50*1024**3+2*info.st_size:
        raise RuntimeError('Insufficient disk space while preserving50GiB host reserve')
    with image.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
    if sha!=proof['sha256']:raise ValueError('Cold base image changed')
    key,fingerprint=public_key(job['key'])
    if fingerprint!=job['fingerprint']:raise ValueError('Requested key identity changed')
    output=folder(state,job['id']);output.parent.mkdir(mode=0o700,exist_ok=True);output.mkdir(mode=0o700)
    (output/'.owner').write_text(json.dumps({'job':job['id'],'schema':'drs-job-v1'}))
    (output/'public.key').write_text(key);(output/'public.key').chmod(0o600)
    command=['cp','--reflink=auto','--sparse=always','--',str(image),str(output/'image.img')]
    subprocess.run(command,check=True,timeout=300)
    reset='rm -f /etc/ssh/ssh_host_*; truncate -s 0 /etc/machine-id'
    command=['virt-customize','--format','raw','-a',str(output/'image.img'),'--no-network','--no-logfile',
             '--mkdir','/root/.ssh','--upload',str(output/'public.key')+':/root/.ssh/authorized_keys',
             '--chmod','0700:/root/.ssh','--chmod','0600:/root/.ssh/authorized_keys','--run-command',reset]
    env={**os.environ,'LIBGUESTFS_BACKEND':'direct','LIBGUESTFS_MEMSIZE':'512',
         'LIBGUESTFS_BACKEND_SETTINGS':'force_kvm'}
    env.setdefault('LIBGUESTFS_CACHEDIR','/var/cache/debrescuestick/guestfs')
    with (output/'guestfs.log').open('wb') as log:
        subprocess.run(command,check=True,timeout=600,stdout=log,stderr=subprocess.STDOUT,env=env)
    # Read the key back from the modified filesystem; no operator/default keys remain.
    command=['guestfish','--ro','--format=raw','-a',str(output/'image.img'),'-i','download','/root/.ssh/authorized_keys','-']
    readback=subprocess.check_output(command,env=env,timeout=120).decode()
    if readback!=key:raise ValueError('Personalized filesystem does not contain exactly the requested key')
    (output/'public.key').unlink()
    return output


def process(store,state,job,prepare=personalize):
    try:
        output=prepare(state,job);store.progress(job['id'])
        if (output/'image.tail').exists():
            meta=json.loads((output/'archive.json').read_text())
            store.finish(job['id'],meta['bytes'],meta['sha256'])
            return True
        with zipfile.ZipFile(output/'image.zip.part','x',compression=zipfile.ZIP_DEFLATED,compresslevel=3,allowZip64=True) as archive:
            archive.write(output/'image.img','DebRescueStick-amd64.img')
        with (output/'image.zip.part').open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        size=(output/'image.zip.part').stat().st_size
        os.replace(output/'image.zip.part',output/'image.zip')
        store.finish(job['id'],size,sha)
        (output/'image.img').unlink()
    except Exception:
        store.fail(job['id'])
        cleanup(state,job['id'])
        return False
    return True


def reap(store,state):
    for job in store.expired():cleanup(state,job);store.forget(job)
    store.purge()
    store.db.execute('DELETE FROM limits WHERE until<=?',(int(store.clock()),))


def heartbeat(state,stop):
    while not stop.is_set():
        temporary=state/'heartbeat.new'
        temporary.write_text(json.dumps({'time':time.time(),'pid':os.getpid()})+'\n')
        os.replace(temporary,state/'heartbeat.json')
        stop.wait(2)


def run(state):
    require_host();state=Path(state)
    proof=json.loads((state/'base/qualified.json').read_text())
    template=json.loads((state/'base/template.json').read_text())
    if not all(proof.get(k) is True for k in ('qualified','key_isolation','ssh_positive_negative')) or proof.get('sha256')!=template.get('sha256'):
        raise ValueError('Native qualification of this exact template required')
    descriptor=os.open(state/'worker.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(descriptor,'w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        store=Store(state/'jobs.sqlite3')
        stop=threading.Event();pulse=threading.Thread(target=heartbeat,args=(state,stop),daemon=True)
        try:
            # Only after exclusive worker ownership; systemd KillMode=control-group
            # must have retired every old appliance before restarting this unit.
            stale=store.db.execute("SELECT id FROM jobs WHERE state IN ('personalizing','compressing')").fetchall()
            for row in stale:store.fail(row['id']);cleanup(state,row['id'])
            if 'fast' in template:load_template(state/'base',template)
            pulse.start()
            while True:
                reap(store,state);job=store.claim()
                if job:process(store,state,job)
                else:time.sleep(2)
        finally:
            stop.set()
            if pulse.is_alive():pulse.join(5)
            store.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--state',type=Path,required=True)
    run(parser.parse_args().state)
