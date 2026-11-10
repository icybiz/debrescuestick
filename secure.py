#!/usr/bin/env python3
"""Secure Boot acceptance of the public image, confined to browser.local RAM."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import subprocess
import time

import extract
from keys import public_key

ROOT=Path(__file__).resolve().parent
TOOLS={
 'ovmf':('pool/main/e/edk2/ovmf_2025.02-8+deb13u1_all.deb','78e0d54df11fc77406cb7a0bc9a39e5bca6d1cbe06556b91d9a73491c52decdf'),
 'archive':('pool/main/liba/libarchive/libarchive-tools_3.7.4-4+deb13u1_amd64.deb',extract.BSD_SHA),
 'mtools':('pool/main/m/mtools/mtools_4.0.48-1_amd64.deb','e7069109ce49f5a450caeca681e454f24dc412f9fdb289cde54e115162203760'),
 'sbsign':('pool/main/s/sbsigntool/sbsigntool_0.9.4-3.2+deb13u1_amd64.deb','b5390c50b1970a98bd5dab6a4a8bba124e41708792da9ea62bb75c0522dd714f'),
}
STAGES=('signed','unsigned-off','unsigned-on')


def strip_lines():
    # shim can be signed by several Microsoft CAs; sbattach removes one at a time.
    return ['cp original.efi unsigned.efi',
      'for attempt in 1 2 3 4 5 6 7 8; do',
      '  tools/usr/bin/sbverify --list unsigned.efi > unsigned-signatures.log 2>&1',
      '  if grep -Fq "No signature table present" unsigned-signatures.log; then break; fi',
      '  tools/usr/bin/sbattach --remove unsigned.efi',
      'done',
      'tools/usr/bin/sbverify --list unsigned.efi > unsigned-signatures.log 2>&1',
      'grep -F "No signature table present" unsigned-signatures.log']


def paths(record):
    token=extract.key(record['key']);folder='/tmp/debrescuestick-secure-'+token
    unit='debrescuestick-secure-'+token+'.service'
    if record.get('remote_root')!=folder or record.get('unit')!=unit:raise ValueError('Exact owned runtime and unit required')
    return folder,unit


def load(token):
    folder=ROOT/'artifacts'/('secure-'+extract.key(token))
    return folder,json.loads((folder/'run.json').read_text())


def write(folder,record):extract.write(folder/'run.json',record)


def script(record):
    folder,unit=paths(record);job=record['job'];token=record['key']
    if len(job['id'])!=48 or any(c not in '0123456789abcdef' for c in job['id']):raise ValueError('Exact public download ID required')
    if len(job['sha256'])!=64 or any(c not in '0123456789abcdef' for c in job['sha256']):raise ValueError('Known ZIP SHA required')
    if not 0<job['bytes']<1400*1024**2:raise ValueError('Unexpected ZIP size')
    q=shlex.quote
    lines=['set -euo pipefail','umask 077','export LC_ALL=C',
      'test "$(hostname -s)" = browser',
      'test "$(cat /proc/self/cgroup)" = '+q('0::/system.slice/'+unit),
      'test "$(findmnt -n -o FSTYPE --target /tmp)" = tmpfs',
      "awk '/^MemAvailable:/ {exit ($2 < 4718592)}' /proc/meminfo",
      'mkdir -m 0700 '+q(folder),'cd '+q(folder),
      'printf "%s\\n" '+q(token)+' > .owner','exec >run.log 2>&1',
      'export TMPDIR='+q(folder),'printf "tools\\n" > phase','mkdir tools']
    for name,(path,sha) in TOOLS.items():
        lines += ['curl -fLsS --connect-timeout 10 --max-time 90 '+q('https://deb.debian.org/debian/'+path)+' -o '+name+'.deb',
          'printf "%s  '+name+'.deb\\n" '+q(sha)+' | sha256sum -c -',
          'dpkg-deb -x '+name+'.deb tools']
    lines += ['ldd tools/usr/bin/bsdtar tools/usr/bin/mcopy tools/usr/bin/sbattach > libraries.log',
      'qemu-system-x86_64 --version > qemu-version.log',
      'sha256sum tools/usr/share/OVMF/* > firmware.sha',
      'printf "download\\n" > phase',
      # Decode directly into sparse RAM storage: no simultaneous large ZIP copy.
      'curl -fLsS --connect-timeout 10 --max-time 240 '+q(extract.ORIGIN+'/download/'+job['id'])+
      ' | tee >(sha256sum > zip.sha) | tools/usr/bin/bsdtar -xOf - DebRescueStick-amd64.img | dd of=image.img bs=1M iflag=fullblock conv=sparse status=none',
      'wait','test "$(stat -c %s image.img)" = '+str(extract.RAW_SIZE),
      'test "$(cut -d\' \' -f1 zip.sha)" = '+q(job['sha256']),
      'sha256sum image.img > raw.sha','du -B1 image.img > allocation.txt',
      'sfdisk --json image.img > partitions.json',
      # The first FAT EFI partition is discovered from the actual GPT, never guessed.
      "offset=$(python3 -c 'import json; p=json.load(open(\"partitions.json\"))[\"partitiontable\"]; e=[x for x in p[\"partitions\"] if x.get(\"type\",\"\").upper()==\"C12A7328-F81F-11D2-BA4B-00A0C93EC93B\"]; assert len(e)==1; print(e[0][\"start\"]*p[\"sectorsize\"])')",
      'fat="image.img@@$offset"',
      'tools/usr/bin/mcopy -i "$fat" ::/EFI/BOOT/BOOTX64.EFI original.efi',
      'tools/usr/bin/sbverify --list original.efi > signatures.log 2>&1',
    ]
    for stage in STAGES:
        if stage=='unsigned-off':
            lines += strip_lines()+[
              'tools/usr/bin/mcopy -o -i "$fat" unsigned.efi ::/EFI/BOOT/BOOTX64.EFI',
              'sha256sum original.efi unsigned.efi > efi.sha']
        lines += ['mkdir '+stage,
          'cp tools/usr/share/OVMF/OVMF_VARS_4M'+('.ms' if stage!='unsigned-off' else '')+'.fd '+stage+'/vars.fd',
          'printf "%s\\n" '+q(stage)+' > phase']
        argv=['qemu-system-x86_64','-enable-kvm','-machine','q35,smm=on','-global','driver=cfi.pflash01,property=secure,value=on',
          '-m','1024','-smp','1','-display','none','-monitor','none','-no-reboot',
          '-serial','file:'+stage+'/serial.log','-qmp','unix:'+stage+'/qmp.sock,server=on,wait=off',
          '-drive','if=pflash,format=raw,readonly=on,file=tools/usr/share/OVMF/OVMF_CODE_4M.secboot.fd',
          '-drive','if=pflash,format=raw,file='+stage+'/vars.fd',
          '-snapshot','-device','qemu-xhci',
          '-drive','if=none,id=stick,format=raw,file=image.img',
          '-device','usb-storage,drive=stick,bootindex=1',
          '-nic','user,model=e1000,hostfwd=tcp:127.0.0.1:0-:22']
        lines += [shlex.join(argv)+' > '+stage+'/qemu.log 2>&1',
          'printf "%s\\n" '+q(stage+'-finished')+' > phase',
          'while ! test -f '+stage+'/accepted; do sleep 1; done']
    lines += ['printf "complete\\n" > phase','touch success']
    return '\n'.join(lines)


def start():
    token=secrets.token_hex(5);folder=ROOT/'artifacts'/('secure-'+token);folder.mkdir(mode=0o700)
    private=ROOT/'.private'/('secure-'+token);private.mkdir(mode=0o700,parents=True)
    identity=private/'owner'
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-C','Secure-Boot-acceptance','-f',str(identity)],check=True)
    pub,fingerprint=public_key(Path(str(identity)+'.pub').read_text())
    record={'key':token,'host':'browser.local','unit':'debrescuestick-secure-'+token+'.service',
      'remote_root':'/tmp/debrescuestick-secure-'+token,'cpu_max':1,'memory_max':4*1024**3,'swap_max':0,
      'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
      'operator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
      'owner_fingerprint':fingerprint,'started':time.time(),'success':False,'stages':{}}
    write(folder,record)
    status=extract.request('/api/status')
    if not status.get('available') or extract.TEMPLATE not in status.get('sources_url',''):raise RuntimeError('Exact qualified production base required')
    job=extract.request('/api/jobs',{'public_key':pub})
    if job['fingerprint']!=fingerprint:raise RuntimeError('Owner key differs')
    record['job']=job;write(folder,record)
    end=time.monotonic()+45
    while job['state']!='ready':
        if job['state']=='failed' or time.monotonic()>end:raise RuntimeError('Image request failed')
        time.sleep(1);job=extract.request('/api/jobs/'+job['id'])
    record['job']=job;write(folder,record)
    path,unit=paths(record)
    extract.remote('browser-session lease debrescuestick 30')
    # No recursive deletion: the service returns every large allocation even on timeout.
    cleanup='if [ ! -L '+shlex.quote(path)+' ] && [ "$(cat '+shlex.quote(path+'/.owner')+' 2>/dev/null)" = '+shlex.quote(token)+' ]; then rm -f -- '+shlex.quote(path+'/image.img')+' '+shlex.quote(path+'/vm-snapshot.tmp')+'; fi'
    argv=['systemd-run','--unit='+unit,'--property=CPUQuota=100%','--property=MemoryMax=4G',
      '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10','--property=TasksMax=64',
      '--property=RuntimeMaxSec=1200','--property=TimeoutStopSec=30','--property=KillMode=control-group',
      '--property=ExecStopPost='+shlex.join(['/bin/bash','-c',cleanup]),'/bin/bash','-c',script(record)]
    (folder/'operator.py').write_bytes(Path(__file__).read_bytes())
    (folder/'command.txt').write_text(script(record)+'\n')
    record['submit_output']=extract.remote(shlex.join(argv));write(folder,record)
    return {'key':token,'unit':unit,'artifacts':str(folder)}


def state(record):
    path,unit=paths(record)
    raw=extract.remote(shlex.join(['systemctl','show',unit,'--property=ActiveState,SubState,Result,ExecMainStatus,MainPID,MemoryPeak,CPUUsageNSec']))
    return dict(line.split('=',1) for line in raw.splitlines() if '=' in line)


def status(token):
    folder,record=load(token);path,unit=paths(record)
    if record.get('resources_returned'):
        return {k:record.get(k) for k in ('key','phase','systemd','stages','success','resources_returned')}
    record['systemd']=state(record)
    record['phase']=extract.remote('cat '+shlex.quote(path+'/phase')+' 2>/dev/null || true').strip()
    record['success']=record['phase']=='complete' and record['systemd']['Result']=='success' and record['systemd']['ExecMainStatus']=='0' and all(record['stages'].get(s,{}).get('success') for s in STAGES)
    write(folder,record)
    return {k:record.get(k) for k in ('key','phase','systemd','stages','success')}


def qmp(record,stage,command,arguments=None):
    path,unit=paths(record)
    if stage not in STAGES:raise ValueError('Exact stage required')
    # An ordinary Python stdlib socket client invoked over SSH; no source file installed.
    code='\n'.join(['import json,socket',
      's=socket.socket(socket.AF_UNIX);s.settimeout(8);s.connect('+repr(path+'/'+stage+'/qmp.sock')+')',
      'f=s.makefile("rwb",buffering=0);json.loads(f.readline())',
      'f.write(b\'{"execute":"qmp_capabilities"}\\n\');json.loads(f.readline())',
      'f.write('+repr(json.dumps({'execute':command,**({'arguments':arguments} if arguments else {})}).encode()+b'\n')+')',
      'while True:',
      ' r=json.loads(f.readline())',
      ' if "return" in r or "error" in r: print(json.dumps(r));break'])
    result=json.loads(extract.remote(shlex.join(['python3','-c',code])))
    if 'error' in result:raise RuntimeError(str(result['error']))
    return result.get('return')


def port(network):
    for line in network.splitlines():
        fields=line.split()
        if len(fields)>=6 and fields[0].startswith('TCP[HOST_FORWARD]') and fields[2]=='127.0.0.1' and fields[5]=='22':return int(fields[3])
    raise RuntimeError('Own loopback guest forwarding missing')


PROBE=r'''set -eu
printf 'SECURE_BOOT='
od -An -tu1 /sys/firmware/efi/efivars/SecureBoot-* | awk '{print $NF}'
printf 'SETUP_MODE='
od -An -tu1 /sys/firmware/efi/efivars/SetupMode-* | awk '{print $NF}'
printf 'LOCKDOWN='
cat /sys/kernel/security/lockdown
printf 'OWNER='
ssh-keygen -l -E sha256 -f /root/.ssh/authorized_keys
printf 'KERNEL='
uname -r
printf 'BOOT_ID='
cat /proc/sys/kernel/random/boot_id
sshd -T | awk '$1=="passwordauthentication" || $1=="kbdinteractiveauthentication"'
dmesg | grep -i 'secure boot\|secureboot\|lockdown' || true
printf 'DRS_SECURE_END\n'
'''


def validate_guest(text,stage,fingerprint):
    on=stage=='signed'
    for marker in ('SECURE_BOOT='+('1' if on else '0'), 'SETUP_MODE='+('0' if on else '1'),
                   fingerprint,'passwordauthentication no','kbdinteractiveauthentication no','DRS_SECURE_END'):
        if marker not in text:raise RuntimeError('Missing guest proof: '+marker)
    if on and '[integrity]' not in text and '[confidentiality]' not in text:raise RuntimeError('Secure Boot kernel lockdown not active')


def check(token,stage):
    if stage not in STAGES:raise ValueError('Exact stage required')
    folder,record=load(token);path,unit=paths(record)
    observed=status(token)
    if observed['phase']!=stage or observed['systemd']['ActiveState']!='active':raise RuntimeError('Expected own running stage '+stage+'; found '+observed['phase'])
    run=folder/stage;run.mkdir(exist_ok=True)
    network=qmp(record,stage,'human-monitor-command',{'command-line':'info usernet'})
    (run/'usernet.txt').write_text(network);guest_port=port(network)
    private=ROOT/'.private'/('secure-'+token)/'owner'
    argv=['ssh','-oBatchMode=yes','-oConnectTimeout=3','-oIdentitiesOnly=yes',
      '-oStrictHostKeyChecking=accept-new','-oUserKnownHostsFile='+str(run/'known_hosts'),
      '-oProxyCommand='+shlex.join(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','root@browser.local','-W','127.0.0.1:'+str(guest_port)]),
      '-i',str(private),'root@127.0.0.1']
    started=time.monotonic()
    if stage!='unsigned-on':
        while time.monotonic()-started<240:
            reply=subprocess.run(argv+[PROBE],capture_output=True,text=True,timeout=20)
            (run/'guest.log').write_text(reply.stdout+'\nSTDERR\n'+reply.stderr)
            if reply.returncode==0:break
            time.sleep(3)
        else:raise RuntimeError('Guest SSH did not become ready; inspect stage logs')
        validate_guest(reply.stdout,stage,record['owner_fingerprint'])
        record['stages'][stage]={'success':True,'ssh':True,'secure_boot':stage=='signed','port':guest_port}
        qmp(record,stage,'screendump',{'filename':path+'/'+stage+'/screen.png','format':'png'})
        subprocess.run(argv+['systemctl poweroff'],capture_output=True,text=True,timeout=20,check=True)
    else:
        while time.monotonic()-started<80:
            serial=extract.remote('tail -c 32768 '+shlex.quote(path+'/'+stage+'/serial.log'))
            (run/'serial.log').write_text(serial)
            if 'Security Violation' in serial or 'Access Denied' in serial:break
            time.sleep(2)
        else:raise RuntimeError('Unsigned loader rejection not observed')
        # Prior success with exactly this unsigned loader and SB off proves bootability.
        if not record['stages'].get('unsigned-off',{}).get('success'):raise RuntimeError('Bootable unsigned control missing')
        qmp(record,stage,'screendump',{'filename':path+'/'+stage+'/screen.png','format':'png'})
        record['stages'][stage]={'success':True,'unsigned_rejected':True,'port':guest_port}
        qmp(record,stage,'quit')
    write(folder,record)
    end=time.monotonic()+45
    while time.monotonic()<end:
        current=extract.remote('cat '+shlex.quote(path+'/phase')).strip()
        if current==stage+'-finished':break
        time.sleep(1)
    else:raise RuntimeError('Guest did not stop cleanly')
    extract.remote('touch '+shlex.quote(path+'/'+stage+'/accepted'))
    return record['stages'][stage]


def collect(token):
    folder,record=load(token);path,unit=paths(record)
    if record.get('resources_returned'):return status(token)
    names=['run.log','phase','allocation.txt','raw.sha','zip.sha','firmware.sha','libraries.log','qemu-version.log',
      'partitions.json','signatures.log','unsigned-signatures.log','efi.sha']
    names += [s+'/'+n for s in STAGES for n in ('serial.log','qemu.log')]
    for name in names:
        raw=extract.remote('if test -f '+shlex.quote(path+'/'+name)+'; then tail -c 65536 '+shlex.quote(path+'/'+name)+'; fi')
        target=folder/name;target.parent.mkdir(exist_ok=True);target.write_text(raw)
    for stage in STAGES:
        remote_file=path+'/'+stage+'/screen.png'
        reply=subprocess.run(['ssh','-oBatchMode=yes','-oStrictHostKeyChecking=yes','root@browser.local',
          'if test -f '+shlex.quote(remote_file)+'; then head -c 4194304 '+shlex.quote(remote_file)+'; fi'],capture_output=True,timeout=20,check=True)
        if reply.stdout:(folder/stage/'screen.png').write_bytes(reply.stdout)
    return status(token)


def finish(token):
    folder,record=load(token);path,unit=paths(record)
    if record.get('resources_returned'):
        return {'key':token,'success':record['success'],'resources_returned':True}
    current=state(record)
    if current['MainPID']!='0' or current['ActiveState'] in ('active','activating','deactivating'):raise RuntimeError('Own service must stop before resource return')
    # Narrow runtime only; files are individually unlinked, then empty dirs removed.
    code='\n'.join(['from pathlib import Path',
      'p=Path('+repr(path)+');assert not p.is_symlink() and p.resolve()==p',
      'assert (p/".owner").read_text().strip()=='+repr(token),
      'assert not (p/"image.img").exists()',
      'entries=list(p.rglob("*"))',
      'for x in entries:',
      ' if x.is_file() or x.is_symlink(): x.unlink()',
      'for x in sorted(entries,key=lambda x:len(x.parts),reverse=True):',
      ' if x.is_dir(): x.rmdir()',
      'p.rmdir()'])
    extract.remote(shlex.join(['python3','-c',code]))
    private=ROOT/'.private'/('secure-'+token)
    for name in ('owner','owner.pub'):(private/name).unlink(missing_ok=True)
    private.rmdir();extract.remote('browser-session release debrescuestick')
    record['resources_returned']=True;record['finished']=time.time();write(folder,record)
    return {'key':token,'success':record['success'],'resources_returned':True}


def abort(token):
    folder,record=load(token);path,unit=paths(record);current=state(record)
    if current['MainPID']!='0':
        code='\n'.join(['from pathlib import Path','import subprocess',
          'p=Path('+repr(path)+');assert not p.is_symlink() and p.resolve()==p',
          'assert (p/".owner").read_text().strip()=='+repr(token),
          'assert Path('+repr('/proc/'+current['MainPID']+'/cgroup')+').read_text().strip() == '+repr('0::/system.slice/'+unit),
          'subprocess.run(["systemctl","stop",'+repr(unit)+'],check=True,timeout=40)'])
        extract.remote(shlex.join(['python3','-c',code]))
    return status(token)


def auto(token=None):
    token=token or start()['key']
    folder,record=load(token)
    if record.get('resources_returned'):return finish(token)
    try:
        for stage in STAGES:
            end=time.monotonic()+360
            while True:
                row=status(token)
                if row['stages'].get(stage,{}).get('success'):break
                if row['systemd']['ActiveState'] not in ('active','activating'):raise RuntimeError('Own unit stopped in phase '+row['phase'])
                if row['phase']==stage:
                    print(json.dumps({'key':token,'checking':stage}),flush=True)
                    check(token,stage);break
                if time.monotonic()>end:raise RuntimeError('Timed out waiting for '+stage)
                time.sleep(3)
        end=time.monotonic()+30
        while state(load(token)[1])['MainPID']!='0':
            if time.monotonic()>end:raise RuntimeError('Final service exit timed out')
            time.sleep(1)
        result=collect(token)
        if not result['success']:raise RuntimeError('Acceptance did not complete')
    except Exception as error:
        abort(token);collect(token)
        folder,record=load(token);record['error']=type(error).__name__+': '+str(error);write(folder,record)
        finish(token)
        raise
    return finish(token)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('auto','start','status','check','collect','finish','abort'))
    p.add_argument('--key');p.add_argument('--stage',choices=STAGES);args=p.parse_args()
    value=start() if args.action=='start' else check(args.key,args.stage) if args.action=='check' else globals()[args.action](args.key)
    print(json.dumps(value))
