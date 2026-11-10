"""Derive a configuration-partition candidate without touching the live base."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import base
import fast
import image
import jobs

ROOT=Path(__file__).resolve().parent
FILES=('fastbuild.py','jobs.py','base.py','fast.py','image.py','debian.lock.json',
       'image/packages.txt','image/keys.sh','image/keys.service','image/info.sh','image/mdns.conf','COPYING','NOTICE')


def run(token,previous):
    base.admitted(token);base.key(previous)
    output=jobs.REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'success':False,'started':time.time(),'previous_template':previous}
    target=base.REMOTE/('image-'+token)
    try:
        target.mkdir(mode=0o700)
        source=base.REMOTE/('image-'+previous)
        proof=json.loads((source/'template.json').read_text())
        if proof['bytes']!=fast.OFFSET or base.digest(source/'base.img')!=proof['sha256']:
            raise ValueError('Exact original qualified cold template required')
        raw=target/'base.img'
        with (output/'build.log').open('xb',buffering=0) as log:
            env={**os.environ,'LIBGUESTFS_BACKEND':'direct','LIBGUESTFS_MEMSIZE':'768',
                 'LIBGUESTFS_CACHEDIR':'/var/cache/debrescuestick/guestfs'}
            def call(argv):
                result=subprocess.run(argv,check=True,stdout=log,stderr=subprocess.STDOUT,env=env,timeout=600)
                return result
            base.write(output/'progress.json',{'phase':'copy-once'})
            call(['cp','--reflink=auto','--sparse=always','--',str(source/'base.img'),str(raw)])
            before=json.loads(subprocess.check_output(['sfdisk','--json',str(raw)],text=True))['partitiontable']['partitions']
            base.write(output/'progress.json',{'phase':'install-boot-key-reader'})
            drop=output/'ssh.conf';drop.write_text('[Unit]\nRequires=debrescuestick-keys.service\nAfter=debrescuestick-keys.service\n')
            call(['virt-customize','--format','raw','-a',str(raw),'--no-network','--no-logfile',
                  '--mkdir','/etc/systemd/system/ssh.service.d',
                  '--mkdir','/usr/local/share/debrescuestick',
                  '--upload',str(ROOT/'COPYING')+':/usr/local/share/debrescuestick/COPYING',
                  '--upload',str(ROOT/'NOTICE')+':/usr/local/share/debrescuestick/NOTICE',
                  '--upload',str(ROOT/'image/keys.sh')+':/usr/local/sbin/debrescuestick-keys',
                  '--chmod','0755:/usr/local/sbin/debrescuestick-keys',
                  '--upload',str(ROOT/'image/keys.service')+':/etc/systemd/system/debrescuestick-keys.service',
                  '--upload',str(drop)+':/etc/systemd/system/ssh.service.d/debrescuestick.conf',
                  '--run-command','systemctl enable debrescuestick-keys.service; truncate -s 0 /etc/machine-id'])
            with raw.open('r+b') as stream:stream.truncate(fast.SIZE)
            start=fast.OFFSET//512;end=(fast.OFFSET+fast.SLOT)//512-1
            call(['sgdisk','-e','-n','4:'+str(start)+':'+str(end),'-t','4:0700','-c','4:DRSKEYS',str(raw)])
            after=json.loads(subprocess.check_output(['sfdisk','--json',str(raw)],text=True))['partitiontable']['partitions']
            def old(rows):return {(r['uuid'],r['start'],r['size'],r['type']) for r in rows if r.get('name')!='DRSKEYS'}
            if old(before)!=old(after):raise RuntimeError('Existing boot/root partition geometry changed')
            config=[r for r in after if r.get('name')=='DRSKEYS']
            if len(config)!=1 or config[0]['start']!=start or config[0]['size']!=fast.SLOT//512:
                raise RuntimeError('Exact trailing configuration partition required')
            fat=output/'blank.fat'
            with fat.open('xb') as stream:stream.truncate(fast.SLOT)
            call(['mkfs.fat','-F','16','-s','1','-S','512','-n','DRSKEYS',str(fat)])
            call(['fsck.fat','-n',str(fat)])
            with raw.open('r+b') as stream:stream.seek(fast.OFFSET);stream.write(fat.read_bytes())
            base.write(output/'progress.json',{'phase':'cold-readback'})
            pin=base.pin(json.loads((ROOT/'debian.lock.json').read_text()))
            proof=image.cold_readback(raw,target,log,env,pin,'fast-config-v1',expected_size=fast.SIZE)
            original=json.loads((source/'template.json').read_text())
            if proof['packages_sha256']!=original['packages_sha256']:raise RuntimeError('Unexpected distribution package change')
            for name,remote in [('keys.sh','/usr/local/sbin/debrescuestick-keys'),('keys.service','/etc/systemd/system/debrescuestick-keys.service')]:
                check=subprocess.check_output(['guestfish','--ro','--format=raw','-a',str(raw),'-i','download',remote,'-'],env=env,timeout=120)
                if check!=(ROOT/'image'/name).read_bytes():raise RuntimeError('Boot key reader changed')
            base.write(output/'progress.json',{'phase':'compress-system-once'})
            proof['fast']=fast.pack(raw,fast.OFFSET,fast.SLOT,target/'fast')
            proof['previous_sha256']=original['sha256']
            base.write(target/'template.json',proof)
            record.update(success=True,template=token,sha256=proof['sha256'],bytes=fast.SIZE,
                          unchanged_packages=True,partition_layout=after,fast=proof['fast'])
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();base.write(output/'result.json',record)
    base.write(target/'result.json',record)
    return 0 if record['success'] else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    p.add_argument('--key');p.add_argument('--template');a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.template))
    result=jobs.submit('fastbuild.py',FILES,['--template',base.key(a.template)],a.key) if a.action=='submit' else jobs.status(a.key)
    print(json.dumps(base.brief(result)))
