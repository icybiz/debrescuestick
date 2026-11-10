#!/usr/bin/env python3
"""Client-side ZIP acceptance on browser.local; never launch a Prox test job.

Only standard tool commands are sent over SSH, not project source files.
The temporary compressed ZIP lives in a bounded tmpfs; decoded IMG is streamed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import time
import urllib.request

from keys import public_key

ROOT=Path(__file__).resolve().parent
ORIGIN='https://eorls.com/debrescuestick'
RAW_SIZE=8598323200
TEMPLATE='fd4ff0918e30b11ffe4b992929c9c62f520b1b6919d9b79891f88c4ccd045a9a'
SEVEN_URL='https://github.com/ip7z/7zip/releases/download/26.06/7z2606-linux-x64.tar.xz'
SEVEN_SHA='2b539cf067b2ad48e1baa5093dbaa8818b73542d1222a0ffde9dc5f2922ea62e'
BSD_URL='https://deb.debian.org/debian/pool/main/liba/libarchive/libarchive-tools_3.7.4-4%2Bdeb13u1_amd64.deb'
BSD_SHA='2b5a2e176e77aa2939d9144d3422f5e291f713ec62281a6c9699cd49fdd80e3e'


def key(value):
    if not isinstance(value,str) or len(value)!=10 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Exact own extraction ID required')
    return value


def runtime(record,token):
    key(token)
    folder='/tmp/debrescuestick-extract-'+token
    if record.get('remote_root')!=folder or record.get('unit')!='debrescuestick-extract-'+token+'.service':
        raise ValueError('Owned fixed runtime and unit required')
    return folder


def remote(command):
    return subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes',
        '-oConnectTimeout=10','root@browser.local',command],capture_output=True,text=True,timeout=45,check=True).stdout


def write(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n')


def request(path,data=None):
    r=urllib.request.Request(ORIGIN+path,data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type':'application/json','User-Agent':'DebRescueStick-extraction-acceptance'})
    with urllib.request.urlopen(r,timeout=15) as response:return json.load(response)


def script(record):
    token=key(record['key']);folder='/tmp/debrescuestick-extract-'+token
    job=record['job']
    if len(job['id'])!=48 or any(c not in '0123456789abcdef' for c in job['id']):raise ValueError('Owned download token required')
    if len(job['sha256'])!=64 or any(c not in '0123456789abcdef' for c in job['sha256']):raise ValueError('Known ZIP SHA required')
    if not 0<job['bytes']<1400*1024**2:raise ValueError('ZIP exceeds the bounded RAM plan')
    # No scripts/repository files are installed remotely. This is an ordinary
    # shell invocation of curl/tar/dpkg-deb/7-Zip/bsdtar/dd/sha256sum.
    lines=['set -euo pipefail','umask 077','export LC_ALL=C',
        'test "$(hostname -s)" = browser','test "$(findmnt -n -o FSTYPE --target /tmp)" = tmpfs',
        "awk '/^MemAvailable:/ {exit ($2 < 4194304)}' /proc/meminfo",
        'mkdir -m 0700 '+shlex.quote(folder),
        'printf "%s\\n" '+shlex.quote(token)+' > '+shlex.quote(folder+'/.owner'),
        'cd '+shlex.quote(folder),'exec >run.log 2>&1',
        'printf "tools\\n" > phase',
        'curl -fLsS --connect-timeout 10 --max-time 90 '+shlex.quote(SEVEN_URL)+' -o seven.tar.xz',
        'printf "%s  seven.tar.xz\\n" '+shlex.quote(SEVEN_SHA)+' | sha256sum -c -',
        'tar -xOJf seven.tar.xz 7zz > seven',
        'curl -fLsS --connect-timeout 10 --max-time 90 '+shlex.quote(BSD_URL)+' -o archive.deb',
        'printf "%s  archive.deb\\n" '+shlex.quote(BSD_SHA)+' | sha256sum -c -',
        'dpkg-deb --fsys-tarfile archive.deb | tar -xOf - ./usr/bin/bsdtar > bsdtar',
        'chmod 0700 seven bsdtar','./seven i > seven-version.log','./bsdtar --version > bsd-version.log',
        'printf "download\\n" > phase',
        'curl -fLsS --connect-timeout 10 --max-time 240 '+shlex.quote(ORIGIN+'/download/'+job['id'])+' -o image.zip',
        'test "$(stat -c %s image.zip)" = '+str(job['bytes']),
        'printf "%s  image.zip\\n" '+shlex.quote(job['sha256'])+' | sha256sum -c -',
        'printf "python-crc\\n" > phase','python3 -m zipfile -t image.zip > python.log',
        './bsdtar -tf image.zip > entries.log',
        'test "$(cat entries.log)" = DebRescueStick-amd64.img',
        'printf "libarchive\\n" > phase',
        './bsdtar -xOf image.zip -- DebRescueStick-amd64.img 2>bsd.log | dd bs=1048576 2>bsd.bytes | sha256sum > bsd.sha',
        'printf "7zip\\n" > phase',
        './seven x -so -bd -bb0 image.zip DebRescueStick-amd64.img 2>seven.log | dd bs=1048576 2>seven.bytes | sha256sum > seven.sha',
        'cmp bsd.sha seven.sha',
        "awk '$2==\"bytes\" {if ($1 != "+str(RAW_SIZE)+") exit 1; found=1} END {if (!found) exit 1}' bsd.bytes",
        "awk '$2==\"bytes\" {if ($1 != "+str(RAW_SIZE)+") exit 1; found=1} END {if (!found) exit 1}' seven.bytes",
        'printf "complete\\n" > phase','touch success']
    return '\n'.join(lines)


def start():
    token=secrets.token_hex(5);folder=ROOT/'artifacts'/('extract-'+token);folder.mkdir(mode=0o700,parents=True)
    private=ROOT/'.private';private.mkdir(mode=0o700,exist_ok=True)
    keyfile=private/('extract-key-'+token)
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','DebRescueStick-extraction','-f',str(keyfile)],check=True)
    pub=Path(str(keyfile)+'.pub')
    try:public,fingerprint=public_key(pub.read_text())
    finally:keyfile.unlink(missing_ok=True);pub.unlink(missing_ok=True)
    record={'key':token,'unit':'debrescuestick-extract-'+token+'.service',
        'host':'browser.local','cpu_max':1,'memory_max':2*1024**3,'swap_max':0,
        'raw_file_written':False,'started':time.time(),'phase':'request','success':False,
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        'operator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    write(folder/'run.json',record)
    status=request('/api/status')
    if not status.get('available') or TEMPLATE not in status.get('sources_url',''):
        raise RuntimeError('Exact qualified live template required')
    job=request('/api/jobs',{'public_key':public})
    if job['fingerprint']!=fingerprint:raise RuntimeError('Requested public key identity differs')
    record['job']=job;write(folder/'run.json',record)
    end=time.monotonic()+45
    while job['state']!='ready':
        if job['state']=='failed' or time.monotonic()>end:raise RuntimeError('Live download did not become ready')
        time.sleep(1);job=request('/api/jobs/'+job['id'])
    record['job']=job
    path='/tmp/debrescuestick-extract-'+token;record['remote_root']=path
    command=script(record)
    cleanup='if [ ! -L '+shlex.quote(path)+' ] && [ "$(cat '+shlex.quote(path+'/.owner')+' 2>/dev/null)" = '+shlex.quote(token)+' ]; then rm -f -- '+shlex.quote(path+'/image.zip')+'; fi'
    argv=['systemd-run','--unit='+record['unit'],'--description=DebRescueStick owned ZIP extraction '+token,
        '--property=CPUQuota=100%','--property=MemoryMax=2G','--property=MemorySwapMax=0',
        '--property=Nice=10','--property=IOWeight=10','--property=TasksMax=32',
        '--property=RuntimeMaxSec=900','--property=TimeoutStopSec=30','--property=KillMode=control-group',
        '--property=ExecStopPost='+shlex.join(['/bin/bash','-c',cleanup]),
        '/bin/bash','-c',command]
    write(folder/'run.json',record)
    record['submit_output']=remote(shlex.join(argv));record['phase']='running';write(folder/'run.json',record)
    return {'key':token,'unit':record['unit'],'artifacts':str(folder)}


def status(token):
    token=key(token);folder=ROOT/'artifacts'/('extract-'+token)
    record=json.loads((folder/'run.json').read_text());path=runtime(record,token)
    output=remote(shlex.join(['systemctl','show',record['unit'],
        '--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,MemoryPeak,CPUUsageNSec']))
    state=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
    record['systemd']=state
    if state['ActiveState'] in ('active','activating'):
        record['remote_phase']=remote('cat '+shlex.quote(path+'/phase')+' 2>/dev/null || true').strip()
    else:
        for name in ('phase','run.log','seven-version.log','bsd-version.log','python.log','entries.log','bsd.sha','bsd.bytes','bsd.log','seven.sha','seven.bytes','seven.log'):
            raw=remote('if test -f '+shlex.quote(path+'/'+name)+'; then head -c 32768 '+shlex.quote(path+'/'+name)+'; fi')
            (folder/name).write_text(raw)
        record['remote_phase']=(folder/'phase').read_text().strip()
        record['success']=state['Result']=='success' and state['ExecMainStatus']=='0' and record['remote_phase']=='complete'
        if record['success']:
            hashes=[(folder/(p+'.sha')).read_text().split()[0] for p in ('bsd','seven')]
            if len(set(hashes))!=1 or any(len(s)!=64 for s in hashes):raise RuntimeError('Independent decoded image SHA differs')
            record['raw_sha256']=hashes[0];record['raw_bytes']=RAW_SIZE
        record['finished']=time.time()
    write(folder/'run.json',record)
    return {k:record.get(k) for k in ('key','success','systemd','remote_phase','raw_bytes','raw_sha256')}


def finish(token):
    token=key(token);folder=ROOT/'artifacts'/('extract-'+token)
    record=json.loads((folder/'run.json').read_text());state=record['systemd']
    if state['ActiveState'] in ('active','activating') or state['MainPID']!='0':raise RuntimeError('Own unit must finish before cleanup')
    path=runtime(record,token)
    names=['image.zip','.owner','phase','success','run.log','seven.tar.xz','seven','archive.deb','bsdtar','seven-version.log',
           'bsd-version.log','python.log','entries.log','bsd.sha','bsd.bytes','bsd.log','seven.sha','seven.bytes','seven.log']
    command='set -e\ntest ! -L '+shlex.quote(path)+'\ntest "$(cat '+shlex.quote(path+'/.owner')+')" = '+shlex.quote(token)
    command+='\nrm -f -- '+shlex.join([path+'/'+n for n in names])+'\nrmdir '+shlex.quote(path)
    remote(command);record['resources_returned']=True;write(folder/'run.json',record)
    return {'key':token,'success':record['success'],'resources_returned':True}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('start','status','finish'));p.add_argument('--key');a=p.parse_args()
    print(json.dumps(start() if a.action=='start' else status(a.key) if a.action=='status' else finish(a.key)))
