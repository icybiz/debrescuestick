#!/usr/bin/env python3
"""Inspect/build a cold rescue template in an isolated bounded Prox job."""
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
FILES=('image.py','base.py','debian.lock.json','image/setup.sh','image/packages.txt','image/info.sh','image/mdns.conf')
SIZE=8*1024**3


def bundle():
    result={name:(ROOT/name).read_bytes() for name in FILES}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in result.items()}
    sha=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
    return result,manifest,sha


def command(argv,log,env,stdin=None,capture=True):
    log.write(('COMMAND '+json.dumps(argv)+'\n').encode());log.flush()
    result=subprocess.run(argv,input=stdin,stdout=subprocess.PIPE if capture else log,stderr=log,env=env)
    if result.stdout:log.write(result.stdout)
    log.flush()
    if result.returncode:raise RuntimeError('Image command failed: '+argv[0]+' ('+str(result.returncode)+')')
    return result.stdout or b''


def inspect(source,log,env):
    script='''run
echo DRS_FILESYSTEMS
list-filesystems
echo DRS_ROOTS
inspect-os
mount-ro /dev/sda1 /
echo DRS_OS
cat /etc/os-release
echo DRS_FSTAB
cat /etc/fstab
echo DRS_NETWORKD
is-file /usr/lib/systemd/systemd-networkd
echo DRS_GRUB
ls /boot
echo DRS_END
'''
    raw=command(['guestfish','--ro','--format=qcow2','-a',str(source)],log,env,script.encode())
    text=raw.decode()
    if '\n/dev/sda1\n' not in text or 'VERSION_ID="13"' not in text or '\nDRS_END\n' not in text:
        raise RuntimeError('Unexpected Debian root layout: inspect full image.log')
    return text


def cold_proof(text):
    names=('KEYS','MACHINE','PACKAGES','SSH','NETWORK','HOSTKEYS','MARKER','END')
    values={name:text.split('DRS_'+name+'\n',1)[1].split('DRS_'+names[index+1]+'\n',1)[0].strip()
            for index,name in enumerate(names[:-1])}
    if values['KEYS']!='0' or values['MACHINE']!='0' or values['HOSTKEYS'] or values['MARKER']!='false':
        raise RuntimeError('Template must have no authorized key, machine id, host private key or build marker')
    if 'PasswordAuthentication no' not in values['SSH'] or 'DHCP=yes' not in values['NETWORK']:
        raise RuntimeError('Rescue network/SSH configuration missing')


def cold_readback(raw,output,log,env,pin,sha,expected_size=SIZE):
    script='''echo DRS_KEYS
filesize /root/.ssh/authorized_keys
echo DRS_MACHINE
filesize /etc/machine-id
echo DRS_PACKAGES
download /usr/local/share/debrescuestick/installed-packages.txt OUTPUT_PACKAGES
echo DRS_SSH
cat /etc/ssh/sshd_config.d/00-debrescuestick.conf
echo DRS_NETWORK
cat /etc/systemd/network/05-debrescuestick.network
echo DRS_HOSTKEYS
glob-expand /etc/ssh/ssh_host_*_key
echo DRS_MARKER
is-file /etc/debrescuestick-build-marker
echo DRS_END
echo DRS_HOSTNAME
cat /etc/hostname
echo DRS_AVAHI_ENABLED
is-symlink /etc/systemd/system/multi-user.target.wants/avahi-daemon.service
echo DRS_FEATURES_END
download /usr/local/sbin/debrstick-info OUTPUT_INFO
download /etc/avahi/avahi-daemon.conf OUTPUT_MDNS
'''
    script=script.replace('OUTPUT_INFO',str(output/'boot-info.sh')).replace('OUTPUT_MDNS',str(output/'mdns.conf'))
    script=script.replace('OUTPUT_PACKAGES',str(output/'installed-packages.txt'))
    readback=command(['guestfish','--ro','--format=raw','-a',str(raw),'-i'],log,env,script.encode()).decode()
    cold_proof(readback)
    hostname=readback.split('DRS_HOSTNAME\n',1)[1].split('DRS_AVAHI_ENABLED\n',1)[0].strip()
    enabled=readback.split('DRS_AVAHI_ENABLED\n',1)[1].split('DRS_FEATURES_END\n',1)[0].strip()
    if hostname!='debrstick' or enabled!='true':raise RuntimeError('mDNS hostname/service not configured')
    for actual,source in (('boot-info.sh','info.sh'),('mdns.conf','mdns.conf')):
        if (output/actual).read_bytes()!=(ROOT/'image'/source).read_bytes():raise RuntimeError('Boot/mDNS helper readback differs')
    packages=(output/'installed-packages.txt').read_text()
    installed={line.split('\t')[0].partition(':')[0] for line in packages.splitlines()}
    missing=set((ROOT/'image/packages.txt').read_text().splitlines())-installed
    if missing:raise RuntimeError('Missing rescue packages: '+','.join(sorted(missing)))
    if raw.stat().st_size!=expected_size:raise RuntimeError('Exact output image size required')
    proof={'raw':str(raw),'bytes':expected_size,'sha256':base.digest(raw),'arch':'amd64',
        'keyless':True,'cold_identity':True,'qualified':False,'vendor_sha512':pin['sha512'],
        'bundle_sha256':sha,'packages_sha256':hashlib.sha256(packages.encode()).hexdigest(),
        'mdns':{'hostname':'debrstick','fqdn':'debrstick.local','console_sha256':base.digest(output/'boot-info.sh')}}
    base.write(output/'template.json',proof)
    return proof


def run(token,mode,sha,template=None):
    unit=base.admitted(token)
    _,_,actual=bundle()
    if actual!=sha:raise RuntimeError('Frozen image bundle changed')
    output=base.REMOTE/('image-'+base.key(token));output.mkdir(mode=0o700)
    record={'unit':unit,'mode':mode,'bundle_sha256':sha,'started':time.time(),'success':False}
    env=os.environ.copy();env.update(LIBGUESTFS_BACKEND='direct',LIBGUESTFS_MEMSIZE='768',
        LIBGUESTFS_CACHEDIR='/var/cache/debrescuestick/guestfs',LIBGUESTFS_TMPDIR=str(output/'tmp'))
    (output/'tmp').mkdir(mode=0o700)
    try:
        if mode not in ('inspect','build','resume','seal'):raise ValueError('Known image mode required')
        pin=base.pin(json.loads((ROOT/'debian.lock.json').read_text()))
        source=base.REMOTE/'inputs'/(pin['sha512']+'.qcow2')
        if source.is_symlink() or source.stat().st_size!=pin['bytes'] or base.digest(source,'sha512')!=pin['sha512']:
            raise RuntimeError('Verified vendor image required')
        stat=os.statvfs(output)
        if stat.f_bavail*stat.f_frsize<50*1024**3+2*SIZE:raise RuntimeError('50GiB reserve plus two raw images required')
        with (output/'image.log').open('xb',buffering=0) as log:
            base.write(output/'progress.json',{'phase':'inspect'})
            info=json.loads(command(['qemu-img','info','--output=json',str(source)],log,env))
            if info['format']!='qcow2' or info.get('backing-filename') or not 0<info['virtual-size']<=SIZE:
                raise RuntimeError('Standalone bounded vendor QCOW2 required')
            record['vendor_info']=info
            if mode in ('inspect','build'):record['inspection']=inspect(source,log,env)
            if mode in ('build','resume','seal'):
                raw=output/'base.img'
            if mode in ('resume','seal'):
                previous=base.REMOTE/('image-'+base.key(template))
                prior=json.loads((previous/'result.json').read_text())
                expected='RuntimeError: Image command failed: virt-customize (1)' if mode=='resume' else 'RuntimeError: Template must have no authorized key, machine id, host private key or build marker'
                if prior.get('mode') not in ('build','resume') or prior.get('success') is not False or prior.get('error')!=expected:
                    raise RuntimeError('Exact completed own failure required for recovery')
                state=subprocess.check_output(['systemctl','show','debrescuestick-base-'+template+'.service','--property=ActiveState','--value'],text=True).strip()
                if state not in ('inactive','failed'):raise RuntimeError('Previous image unit must be stopped')
                old=previous/'base.img'
                if old.is_symlink() or old.stat().st_size!=SIZE:raise RuntimeError('Exact owned raw image required')
                if mode=='resume':command(['cp','--reflink=auto','--sparse=always','--',str(old),str(raw)],log,env,capture=False)
                else:os.link(old,raw)
                record['previous_build']=template;record['build_bundle_sha256']=prior['bundle_sha256']
            if mode=='build':
                with raw.open('xb') as stream:stream.truncate(SIZE)
                base.write(output/'progress.json',{'phase':'resize'})
                command(['virt-resize','--format','qcow2','--output-format','raw','--expand','/dev/sda1',
                         str(source),str(raw)],log,env,capture=False)
            if mode in ('build','resume'):
                marker=output/'marker';marker.write_text('guestfs-image-v1\n')
                base.write(output/'progress.json',{'phase':'configure'})
                command(['virt-customize','--format','raw','-a',str(raw),'--no-logfile','--hostname','debrstick',
                    '--mkdir','/usr/local/share/debrescuestick',
                    '--upload',str(marker)+':/etc/debrescuestick-build-marker',
                    '--upload',str(ROOT/'image/packages.txt')+':/usr/local/share/debrescuestick/packages.txt',
                    '--upload',str(ROOT/'image/info.sh')+':/usr/local/share/debrescuestick/info.sh',
                    '--upload',str(ROOT/'image/mdns.conf')+':/usr/local/share/debrescuestick/mdns.conf',
                    '--run',str(ROOT/'image/setup.sh')],log,env,capture=False)
            if mode in ('build','resume','seal'):
                base.write(output/'progress.json',{'phase':'cold-readback'})
                record['template']=cold_readback(raw,output,log,env,pin,sha)
        record['success']=True
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','unit','error','template')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,mode,template=None):
    base.key(token)
    if mode not in ('inspect','build','resume','seal'):raise ValueError('Known image mode required')
    if mode in ('resume','seal'):base.key(template)
    files,manifest,sha=bundle();unit='debrescuestick-base-'+token
    payload={name:base64.b64encode(raw).decode() for name,raw in files.items()}
    code=r'''from pathlib import Path
import os,json,base64,socket,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path(REMOTE);assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
code=p/'code'/SHA;code.mkdir(mode=0o700,parents=True,exist_ok=True)
for name,data in FILES.items():
 f=code/name;f.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==MANIFEST[name]
assert not (p/('image-'+KEY)).exists(),'Existing image run preserved'
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=128','--property=RuntimeMaxSec=2400','--property=TimeoutStopSec=45',
 '/usr/bin/python3',str(code/'image.py'),'run','--key',KEY,'--mode',MODE,'--sha',SHA]
if TEMPLATE:argv+=['--template',TEMPLATE]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'unit':UNIT,'key':KEY,'mode':MODE,'bundle_sha256':SHA,'files':MANIFEST}))
'''
    values={'HOSTNAME':base.HOSTNAME,'REMOTE':str(base.REMOTE),'SHA':sha,'KEY':token,'UNIT':unit,
            'MODE':mode,'FILES':payload,'MANIFEST':manifest,'TEMPLATE':template}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('image-job-'+token+'.json'),result);return result


def status(token):
    base.key(token);row=json.loads((ROOT/'artifacts'/('image-job-'+token+'.json')).read_text())
    code=r'''from pathlib import Path
import subprocess,json
p=Path(REMOTE)/('image-'+KEY)
raw=subprocess.check_output(['systemctl','show',UNIT+'.service','--property=ActiveState,SubState,ExecMainStatus,Result'],text=True)
value={'unit':UNIT,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
for name in ('result','progress'):
 if (p/(name+'.json')).exists():value[name]=json.loads((p/(name+'.json')).read_text())
if (p/'image.log').exists():
 with (p/'image.log').open('rb') as f:
  f.seek(max(0,(p/'image.log').stat().st_size-5000));value['tail']=f.read().decode(errors='replace')
print(json.dumps(value))
'''
    result=base.remote('REMOTE='+repr(str(base.REMOTE))+'\nKEY='+repr(token)+'\nUNIT='+repr(row['unit'])+'\n'+code)
    base.write(ROOT/'artifacts'/('image-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    p.add_argument('--key');p.add_argument('--mode',choices=('inspect','build','resume','seal'),default='inspect');p.add_argument('--sha');p.add_argument('--template');p.add_argument('--verbose',action='store_true');a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.mode,a.sha,a.template))
    result=submit(a.key or secrets.token_hex(5),a.mode,a.template) if a.action=='submit' else status(a.key)
    print(json.dumps(result if a.action=='submit' or a.verbose else base.brief(result)))
