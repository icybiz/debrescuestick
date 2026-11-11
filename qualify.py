#!/usr/bin/env python3
"""Native USB BIOS/UEFI and SSH isolation qualification, only on bounded Prox."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
import zipfile

import base
from keys import public_key
import worker
import fast
import mdns
import replay

ROOT=Path(__file__).resolve().parent
FILES=('qualify.py','base.py','worker.py','store.py','keys.py','fast.py','mdns.py','server.py','replay.py','COPYING','NOTICE')


def qa_unit(token):return 'debrescuestick-qa-worker-'+base.key(token)


def materialize(output,prefix,size):
    with fast.Reader([prefix,output/'image.tail']) as source,zipfile.ZipFile(source) as archive:
        names=archive.namelist()
        if names!=[fast.NAME.decode()] or archive.getinfo(names[0]).file_size!=size:
            raise ValueError('Exact single complete image entry required')
        count=0
        with archive.open(names[0]) as data,(output/'image.img').open('xb') as target:
            while block:=data.read(1024**2):
                if block.strip(b'\0'):target.write(block)
                else:target.seek(len(block),os.SEEK_CUR)
                count+=len(block)
            if count!=size:raise ValueError('Truncated personalized image')
            target.truncate(size)


def forward_port(text):
    rows=[]
    for line in text.splitlines():
        fields=line.split()
        if fields and fields[0]=='TCP[HOST_FORWARD]':
            if len(fields)!=8 or fields[2]!='127.0.0.1' or fields[5]!='22':
                raise ValueError('Unexpected owned SSH forward')
            port=int(fields[3])
            if not 0<port<65536:raise ValueError('Bound SSH forward required')
            rows.append(port)
    if len(rows)!=1:raise ValueError('One owned SSH forward required')
    return rows[0]


class Monitor:
    def __init__(self,path):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(5)
        self.sock.connect(str(path));self.stream=self.sock.makefile('rwb',buffering=0)
        greeting=json.loads(self.stream.readline())
        if 'QMP' not in greeting:raise RuntimeError('Owned QEMU monitor required')
        self.call('qmp_capabilities')

    def call(self,name,args=None):
        request={'execute':name}
        if args is not None:request['arguments']=args
        self.stream.write(json.dumps(request).encode()+b'\n')
        while True:
            line=self.stream.readline()
            if not line:raise RuntimeError('Owned monitor closed')
            reply=json.loads(line)
            if 'error' in reply:raise RuntimeError(str(reply['error']))
            if 'return' in reply:return reply['return']

    def close(self):self.stream.close();self.sock.close()


def identity(pid):
    path=Path('/proc')/str(pid)
    return (path/'stat').read_text().rpartition(')')[2].split()[19],(path/'cmdline').read_bytes()


def stop(child,expected,monitor):
    if child.poll() is not None:return
    try:monitor.call('system_powerdown')
    except (OSError,RuntimeError):pass
    try:child.wait(40);return
    except subprocess.TimeoutExpired:pass
    if identity(child.pid)!=expected:raise RuntimeError('Owned guest PID changed; signal refused')
    child.terminate()
    try:child.wait(20)
    except subprocess.TimeoutExpired:
        if identity(child.pid)!=expected:raise RuntimeError('Owned guest PID changed; kill refused')
        child.kill();child.wait(10)


def ssh(port,key,known,command,method='publickey',timeout=12):
    argv=['ssh','-F','/dev/null','-oBatchMode=yes','-oIdentitiesOnly=yes','-oIdentityAgent=none',
          '-oConnectTimeout=3','-oConnectionAttempts=1','-oStrictHostKeyChecking=accept-new',
          '-oUserKnownHostsFile='+str(known),'-oGlobalKnownHostsFile=/dev/null',
          '-oPreferredAuthentications='+method,'-i',str(key),'-p',str(port),'root@127.0.0.1',command]
    return subprocess.run(argv,capture_output=True,text=True,timeout=timeout)


PROBE=r'''set -eu
test "$(id -u)" = 0
systemctl is-active --quiet ssh systemd-networkd
test "$(wc -l </root/.ssh/authorized_keys)" = 1
test "$(wc -c </etc/machine-id)" = 33
test ! -e /etc/debrescuestick-build-marker
test -f /etc/cloud/cloud-init.disabled
sshd -T | awk '$1=="passwordauthentication" || $1=="kbdinteractiveauthentication" || $1=="permitrootlogin"'
echo DRS_MACHINE
cat /etc/machine-id
echo DRS_IP
ip -4 -o address show scope global
echo DRS_HOSTKEY
ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_ed25519_key.pub
echo DRS_USERKEY
ssh-keygen -l -E sha256 -f /root/.ssh/authorized_keys
echo DRS_TOOLS
for tool in ddrescue testdisk smartctl gparted cryptsetup rsync; do command -v "$tool"; done
echo DRS_FIRMWARE
if test -d /sys/firmware/efi; then echo uefi; else echo bios; fi
echo DRS_ROOT
findmnt -n -o SOURCE /
echo DRS_BASE_END
'''


def boot(profile,image,key,wrong,firmware):
    run=profile/firmware;run.mkdir(mode=0o700);qmp=run/'qmp.sock';serial=run/'serial.log'
    argv=['qemu-system-x86_64','-enable-kvm','-m','1024','-smp','1','-display','none',
          '-serial','file:'+str(serial),'-monitor','none','-qmp','unix:'+str(qmp)+',server=on,wait=off',
          '-no-reboot','-snapshot','-device','qemu-xhci',
          '-drive','file='+str(image)+',format=raw,if=none,id=stick',
          '-device','usb-storage,drive=stick,bootindex=1',
          '-nic','user,model=e1000,hostfwd=tcp:127.0.0.1:0-:22']
    if firmware in ('uefi','secure'):
        seed='/usr/share/OVMF/OVMF_VARS_4M'+('.ms' if firmware=='secure' else '')+'.fd'
        code='/usr/share/OVMF/OVMF_CODE_4M'+('.secboot' if firmware=='secure' else '')+'.fd'
        vars=run/'OVMF_VARS.fd';shutil.copyfile(seed,vars)
        argv+=['-drive','if=pflash,format=raw,readonly=on,file='+code,
               '-drive','if=pflash,format=raw,file='+str(vars)]
        if firmware=='secure':argv+=['-machine','q35,smm=on','-global','driver=cfi.pflash01,property=secure,value=on']
    with (run/'qemu.log').open('xb') as log:
        child=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT)
        expected=identity(child.pid);monitor=None
        base.write(run/'pid.json',{'pid':child.pid,'identity':[expected[0],expected[1].decode(errors='replace')]})
        record={'firmware':'bios' if firmware=='bios' else 'uefi','profile':firmware,'usb_emulation':True,'started':time.time(),'success':False}
        try:
            end=time.monotonic()+20
            while not qmp.exists():
                if child.poll() is not None or time.monotonic()>end:raise RuntimeError('Guest monitor did not start')
                time.sleep(.2)
            monitor=Monitor(qmp)
            network=monitor.call('human-monitor-command',{'command-line':'info usernet'})
            (run/'usernet.txt').write_text(network);port=forward_port(network);record['port']=port
            end=time.monotonic()+240;attempt=0
            while time.monotonic()<end:
                if child.poll() is not None:raise RuntimeError('Guest stopped before SSH')
                result=ssh(port,key,run/'known_hosts','true');attempt+=1
                (run/'ssh-last.txt').write_text(result.stdout+'\nSTDERR\n'+result.stderr)
                if result.returncode==0:break
                time.sleep(3)
            else:raise RuntimeError('SSH probe timed out; inspect serial.log and ssh-last.txt')
            probe=PROBE+mdns.probe_script()+r'''
printf 'DRS_OWN_LICENSE\n'
sha256sum /usr/local/share/debrescuestick/COPYING /usr/local/share/debrescuestick/NOTICE
'''
            if firmware=='secure':
                probe+=r'''
printf 'DRS_SECURE_BOOT\n'
printf 'SECURE_BOOT='; od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-* | awk '{print $NF}'
printf 'SETUP_MODE='; od -An -tu1 /sys/firmware/efi/efivars/SetupMode-* | awk '{print $NF}'
cat /sys/kernel/security/lockdown
'''
            result=ssh(port,key,run/'known_hosts',probe+'\necho DRS_END\n',timeout=90)
            (run/'ssh-last.txt').write_text(result.stdout+'\nSTDERR\n'+result.stderr)
            expected_firmware='bios' if firmware=='bios' else 'uefi'
            if result.returncode or '\n'+expected_firmware+'\n' not in result.stdout or 'DRS_END' not in result.stdout:
                raise RuntimeError('Native firmware/network probe did not complete')
            peer=json.loads(result.stdout.split('DRS_MDNS_PEER\n',1)[1].split('DRS_CONSOLE\n',1)[0].strip())
            if not peer.get('success') or not peer.get('independent_network_stack') or not peer.get('ssh_banner') or peer.get('hostname')!=mdns.HOST_NAME:
                raise RuntimeError('Independent mDNS/SSH peer proof missing')
            console=result.stdout.split('DRS_CONSOLE\n',1)[1].split('DRS_NETWORK_END\n',1)[0]
            if 'ssh root@'+mdns.HOST_NAME not in console or 'SSH access: ready' not in console:
                raise RuntimeError('Connection dashboard is incomplete')
            if firmware=='secure' and ('SECURE_BOOT=1' not in result.stdout or 'SETUP_MODE=0' not in result.stdout or not any(word in result.stdout for word in ('[integrity]','[confidentiality]'))):
                raise RuntimeError('Secure Boot/lockdown is not enabled')
            for name in ('COPYING','NOTICE'):
                expected=base.digest(ROOT/name)+'  /usr/local/share/debrescuestick/'+name
                if expected not in result.stdout:raise RuntimeError('Own license readback differs: '+name)
            record.update(mdns=peer,console=True,secure_boot=firmware=='secure',own_license=True)
            monitor.call('screendump',{'filename':str(run/'screen.png'),'format':'png'})
            keyline=public_key(Path(str(key)+'.pub').read_text())[1]
            if keyline not in result.stdout or 'passwordauthentication no' not in result.stdout or 'kbdinteractiveauthentication no' not in result.stdout:
                raise RuntimeError('Native SSH identity/configuration mismatch')
            (run/'ssh-positive.txt').write_text(result.stdout)
            negative=ssh(port,wrong,run/'known_hosts','true')
            (run/'ssh-wrong-key.txt').write_text(negative.stdout+negative.stderr)
            if negative.returncode==0 or 'Permission denied' not in negative.stderr:raise RuntimeError('Foreign key rejection not proved')
            password=ssh(port,wrong,run/'known_hosts','true',method='password,keyboard-interactive')
            (run/'ssh-password.txt').write_text(password.stdout+password.stderr)
            if password.returncode==0 or 'Permission denied' not in password.stderr:raise RuntimeError('Password rejection not proved')
            machine=result.stdout.split('DRS_MACHINE\n',1)[1].splitlines()[0]
            hostkey=result.stdout.split('DRS_HOSTKEY\n',1)[1].splitlines()[0].split()[1]
            record.update(machine_id=machine,host_key=hostkey,owner_key=keyline,wrong_key_rejected=True,
                          password_rejected=True,ssh_positive=True,attempts=attempt)
            shutdown=ssh(port,key,run/'known_hosts','systemctl poweroff')
            child.wait(45)
            if child.returncode!=0:raise RuntimeError('Clean guest shutdown failed')
            record.update(success=True,clean_shutdown=True)
        except Exception as error:record['error']=type(error).__name__+': '+str(error)
        finally:
            if child.poll() is None:
                if monitor:stop(child,expected,monitor)
                else:
                    if identity(child.pid)!=expected:raise RuntimeError('Owned guest PID changed')
                    child.terminate();child.wait(20)
            if monitor:monitor.close()
        record.update(finished=time.time(),qemu_exit=child.returncode)
        base.write(run/'result.json',record)
        if not record['success']:raise RuntimeError(record['error'])
        return record


def run(token,template,bundle_sha,queue=False):
    worker.require_host();base.key(token);base.key(template)
    manifest={name:base.digest(ROOT/name) for name in FILES}
    if hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()!=bundle_sha:
        raise RuntimeError('Frozen qualification bundle changed')
    path=Path('/var/lib/debrescuestick/qa')/token;path.mkdir(mode=0o700)
    record={'started':time.time(),'template_job':template,'bundle_sha256':bundle_sha,'success':False}
    try:
        source=base.REMOTE/('image-'+template)
        proof=json.loads((source/'template.json').read_text())
        target=path/'base';target.mkdir(mode=0o700)
        os.link(source/'base.img',target/'base.img')
        base.write(target/'template.json',proof)
        if 'fast' in proof:
            shutil.copytree(source/'fast',target/'fast',copy_function=os.link)
            started=time.perf_counter();worker.load_template(target,proof)
            record['prefix_warmup_seconds']=time.perf_counter()-started
        results=[]
        for name in ('a','b'):
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','DebRescueStick-ephemeral-QA',
                            '-f',str(path/('key-'+name))],check=True)
        if queue:
            base.write(path/'progress.json',{'phase':'queue-replay'})
            queue_result=replay.qualify(path)
            if base.digest(target/'base.img')!=proof['sha256']:raise RuntimeError('Cold template was modified')
            record.update(success=True,queue_replay=queue_result,sha256=proof['sha256'])
        else:
            for index,firmware in enumerate(('bios','uefi','secure')):
                owner=path/('key-'+('a' if index%2==0 else 'b'));wrong=path/('key-'+('b' if index%2==0 else 'a'))
                key,fingerprint=public_key(Path(str(owner)+'.pub').read_text())
                job={'id':secrets.token_hex(24),'key':key,'fingerprint':fingerprint}
                base.write(path/'progress.json',{'phase':'personalize','firmware':firmware})
                started=time.perf_counter();output=worker.personalize(path,job)
                elapsed=time.perf_counter()-started
                if 'fast' in proof:materialize(output,target/'fast/prefix.zip',proof['bytes'])
                base.write(path/'progress.json',{'phase':'boot-ssh','firmware':firmware})
                result=boot(path,output/'image.img',owner,wrong,firmware)
                result['personalization_seconds']=elapsed
                if 'fast' in proof:result['archive']=json.loads((output/'archive.json').read_text())
                results.append(result)
            if len({row['machine_id'] for row in results})!=len(results) or len({row['host_key'] for row in results})!=len(results):
                raise RuntimeError('Personal images share host identity')
            if base.digest(target/'base.img')!=proof['sha256']:raise RuntimeError('Cold template was modified by qualification')
            record.update(success=True,results=results,key_isolation=True,ssh_positive_negative=True,
                          architecture='amd64',sha256=proof['sha256'],qualified=True,secure_boot=True,mdns=True,console=True,own_license=True,hostname=mdns.HOST_NAME)
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    finally:
        if queue:
            for name in ('key-a','key-a.pub','key-b','key-b.pub'):
                (path/name).unlink(missing_ok=True)
    record['finished']=time.time();base.write(path/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','error','sha256','qualified')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,template,queue=False):
    base.key(token);base.key(template)
    files={name:(ROOT/name).read_bytes() for name in FILES}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}
    sha=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
    code=r'''from pathlib import Path
import os,json,base64,socket,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/qa');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/KEY).exists(),'Existing QA profile preserved'
assert Path('/var/lib/debrescuestick/factory', 'image-'+TEMPLATE,'template.json').is_file(),'Built template required'
state=subprocess.check_output(['systemctl','show',UNIT+'.service','--property=LoadState,ActiveState'],text=True)
assert 'LoadState=not-found' in state,'Existing worker unit preserved'
marker=Path('/etc/debrescuestick/worker.json');marker.parent.mkdir(mode=0o755,exist_ok=True)
expected={'hostname':HOSTNAME}
if marker.exists():assert not marker.is_symlink() and json.loads(marker.read_text())==expected
else:marker.write_text(json.dumps(expected)+'\n');marker.chmod(0o644)
code=p/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data in FILES.items():
 f=code/name;raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==MANIFEST[name]
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=128','--property=RuntimeMaxSec=1800','--property=TimeoutStopSec=45',
 '/usr/bin/python3',str(code/'qualify.py'),'run','--key',KEY,'--template',TEMPLATE,'--sha',SHA]
if QUEUE:argv.append('--queue')
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'unit':UNIT,'key':KEY,'template_job':TEMPLATE,'bundle_sha256':SHA,'files':MANIFEST,'queue':QUEUE}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'TEMPLATE':template,'UNIT':qa_unit(token),'SHA':sha,
            'FILES':{name:base64.b64encode(raw).decode() for name,raw in files.items()},'MANIFEST':manifest,'QUEUE':queue}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('qa-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/qa')/KEY
raw=subprocess.check_output(['systemctl','show',UNIT+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'unit':UNIT,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
for name in ('result','progress'):
 if (p/(name+'.json')).exists():value[name]=json.loads((p/(name+'.json')).read_text())
for firmware in ('bios','uefi'):
 f=p/firmware/'result.json'
 if f.exists():value[firmware]=json.loads(f.read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\nUNIT='+repr(qa_unit(token))+'\n'+code)
    base.write(ROOT/'artifacts'/('qa-status-'+token+'.json'),result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    p.add_argument('--key');p.add_argument('--template');p.add_argument('--sha');p.add_argument('--queue',action='store_true');p.add_argument('--verbose',action='store_true');a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.template,a.sha,a.queue))
    result=submit(a.key or secrets.token_hex(5),a.template,a.queue) if a.action=='submit' else status(a.key)
    print(json.dumps(result if a.action=='submit' or a.verbose else base.brief(result)))
