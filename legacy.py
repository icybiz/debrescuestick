#!/usr/bin/env python3
"""Move the old Mindbytez rescue section after live release, GUI and expiry proof."""
import argparse
import base64
import hashlib
import json
import os
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.request

import base

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/legacy')
WEB=Path('/var/www/mindbytez.com')
IMAGE='SystemRescueCd-x86-5.1.0-usbdisk.img'
URL='https://eorls.com/debrescuestick/'
FILES=('legacy.py','base.py','static/move.html','static/move.css')


def home(text):
    old='href="oss/index.html"';new='href="'+URL+'"'
    label='Open source section with SystemRescueImage'
    replacement='DebRescueStick - Debian USB rescue with your SSH key'
    if text.count(old)!=2 or text.count(label)!=1:raise ValueError('Exact old rescue card required')
    result=text.replace(old,new).replace(label,replacement)
    if result.replace(new,old).replace(replacement,label)!=text:raise ValueError('Unrelated homepage content changed')
    return result


def bundle():
    files={name:(ROOT/name).read_bytes() for name in FILES}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}
    return files,manifest,hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()


def atomic(path,raw,mode=0o644,uid=0,gid=0):
    if path.is_symlink():raise ValueError('Linked legacy page preserved')
    temporary=path.with_name(path.name+'.drs-'+secrets.token_hex(5))
    with temporary.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    temporary.chmod(mode);os.chown(temporary,uid,gid);os.replace(temporary,path)


def read(url,limit=2*1024**2):
    with urllib.request.urlopen(url,timeout=30) as reply:
        raw=reply.read(limit+1)
        if len(raw)>limit:raise ValueError('Bounded legacy page required')
        return raw


def run(token,publish_key,expiry_key,sha,before,gui_sha):
    unit=base.admitted(token)
    if bundle()[2]!=sha:raise RuntimeError('Frozen legacy migration required')
    for value in (publish_key,expiry_key):base.key(value)
    output=REMOTE/('run-'+base.key(token));output.mkdir(mode=0o700)
    record={'unit':unit,'started':time.time(),'success':False,'publish_job':publish_key,'expiry_job':expiry_key}
    backups={};written={};moved=False;backup=None
    try:
        published=json.loads((Path('/var/lib/debrescuestick/publish')/('run-'+publish_key)/'result.json').read_text())
        expiry=json.loads((Path('/var/lib/debrescuestick/canary')/('run-'+expiry_key)/'result.json').read_text())
        gui_file=ROOT/'gui.json'
        if base.digest(gui_file)!=gui_sha:raise ValueError('Exact real-browser proof required')
        gui=json.loads(gui_file.read_text())
        if published.get('success') is not True or published.get('url')!=URL:raise ValueError('Published HTTPS service required')
        if expiry.get('success') is not True or not all(expiry.get(k) is True for k in ('api_rejected','download_rejected','artifacts_removed','row_removed')):
            raise ValueError('Actual expiry and unprivileged cleanup proof required')
        if expiry.get('stage_job')!=published['stage_job'] or expiry.get('previous_canary')!=published['canary_job']:
            raise ValueError('Expiry must belong to the published canary')
        if gui.get('success') is not True or gui.get('live') is not True or gui.get('url')!=URL or not gui.get('browser',{}).get('success'):
            raise ValueError('Successful live browser proof required')
        for row in gui['browser']['snapshots']:
            if not row.get('ready') or row.get('checksum')!=published['image']['sha256'] or row.get('job')!=expiry.get('expired_job'):
                raise ValueError('Real ready-image browser view required')
        current=Path('/opt/debrescuestick/current').resolve()
        for name,value in gui['source_sha256'].items():
            if name not in ('server.py','keys.py','store.py','static/index.html','static/app.js','static/style.css') or base.digest(current/name)!=value:
                raise ValueError('Browser-tested source changed')
        targets={'index.html':WEB/'index.html','oss/index.html':WEB/'oss/index.html','oss/usb_inst_Mod.sh':WEB/'oss/usb_inst_Mod.sh'}
        for name,path in targets.items():
            if path.resolve()!=path or path.is_symlink() or base.digest(path)!=before[name]:
                raise ValueError('Existing historical page/source changed: '+name)
        css=WEB/'oss/move.css'
        if css.exists():raise ValueError('Existing legacy stylesheet preserved')
        backup=Path('/var/backups/debrescuestick')/('legacy-'+token);backup.mkdir(mode=0o700,parents=True)
        for name,path in targets.items():
            target=backup/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            shutil.copy2(path,target)
            info=path.stat();backups[name]={'mode':info.st_mode & 0o7777,'uid':info.st_uid,'gid':info.st_gid}
        image=WEB/'oss'/IMAGE
        if image.exists():
            if image.is_symlink() or not image.is_file() or image.stat().st_dev!=backup.stat().st_dev:
                raise ValueError('Original image preserved: unexpected type/filesystem')
            record['old_image']={'name':IMAGE,'bytes':image.stat().st_size,'sha256':base.digest(image)}
            os.rename(image,backup/IMAGE);moved=True
        replacements={'index.html':home(targets['index.html'].read_text()).encode(),
                      'oss/index.html':(ROOT/'static/move.html').read_bytes()}
        atomic(css,(ROOT/'static/move.css').read_bytes());written['oss/move.css']=base.digest(css)
        for name,raw in replacements.items():
            info=backups[name];atomic(targets[name],raw,info['mode'],info['uid'],info['gid'])
            written[name]=hashlib.sha256(raw).hexdigest()
        checks={}
        for name in ('index.html','oss/index.html','oss/move.css','oss/usb_inst_Mod.sh'):
            raw=read('https://mindbytez.com/'+name)
            expected=written.get(name,before.get(name))
            actual=hashlib.sha256(raw).hexdigest()
            if actual!=expected:raise RuntimeError('Full HTTPS legacy page/source readback mismatch: '+name)
            checks[name]={'bytes':len(raw),'sha256':actual}
        try:
            with urllib.request.urlopen('https://mindbytez.com/oss/'+IMAGE,timeout=30):pass
        except urllib.error.HTTPError as error:
            if error.code not in (404,410):raise
            record['old_image_http']=error.code
        else:raise RuntimeError('Retired old image still publicly served')
        if base.digest(targets['oss/usb_inst_Mod.sh'])!=before['oss/usb_inst_Mod.sh']:
            raise RuntimeError('Historical GPL2 converter changed')
        record.update(success=True,backup=str(backup),pages=checks,old_image_archived=moved,new_url=URL,
                      gui_sha256=gui_sha,before=before,metadata=backups)
        base.write(backup/'metadata.json',record)
    except Exception as error:
        record['error']=type(error).__name__+': '+str(error)
        for name,value in written.items():
            path=WEB/name
            if path.exists() and not path.is_symlink() and base.digest(path)==value:
                if name in backups:
                    info=backups[name];atomic(path,(backup/name).read_bytes(),info['mode'],info['uid'],info['gid'])
                else:path.unlink()
            else:record['rollback_refused']=name
        image=WEB/'oss'/IMAGE
        if moved and not image.exists():os.rename(backup/IMAGE,image)
        record['rolled_back']='rollback_refused' not in record
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','error','new_url','rolled_back','rollback_refused')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,publish_key,expiry_key,gui):
    for value in (token,publish_key,expiry_key):base.key(value)
    files,manifest,sha=bundle();gui_raw=Path(gui).read_bytes();gui_sha=hashlib.sha256(gui_raw).hexdigest()
    baseline=Path(os.environ['DRS_LEGACY_BASELINE']).resolve()
    before={name:base.digest(baseline/name) for name in ('index.html','oss/index.html','oss/usb_inst_Mod.sh')}
    unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import socket,json,base64,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/legacy');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/('run-'+KEY)).exists(),'Existing legacy migration preserved'
code=p/('code-'+SHA+'-'+GUI_SHA[:10]);code.mkdir(mode=0o700,exist_ok=True)
for name,data in FILES.items():
 f=code/name;f.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==MANIFEST[name]
f=code/'gui.json';raw=base64.b64decode(GUI)
if f.exists():assert f.read_bytes()==raw
else:f.write_bytes(raw);f.chmod(0o600)
assert hashlib.sha256(f.read_bytes()).hexdigest()==GUI_SHA
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=32','--property=RuntimeMaxSec=600','--property=TimeoutStopSec=30',
 '/usr/bin/python3',str(code/'legacy.py'),'run','--key',KEY,'--publish',PUBLISH,'--expiry',EXPIRY,
 '--sha',SHA,'--before',json.dumps(BEFORE),'--gui-sha',GUI_SHA]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'key':KEY,'unit':UNIT,'publish_job':PUBLISH,'expiry_job':EXPIRY,'bundle_sha256':SHA,'files':MANIFEST,'gui_sha256':GUI_SHA,'before':BEFORE}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'PUBLISH':publish_key,'EXPIRY':expiry_key,'UNIT':unit,
            'SHA':sha,'GUI_SHA':gui_sha,'GUI':base64.b64encode(gui_raw).decode(),'BEFORE':before,
            'FILES':{name:base64.b64encode(raw).decode() for name,raw in files.items()},'MANIFEST':manifest}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('legacy-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/legacy')/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
if (p/'result.json').exists():value['result']=json.loads((p/'result.json').read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code);base.write(ROOT/'artifacts'/('legacy-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    for name in ('key','publish','expiry','sha','before','gui','gui-sha'):p.add_argument('--'+name)
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.publish,a.expiry,a.sha,json.loads(a.before),a.gui_sha))
    print(json.dumps(submit(a.key or secrets.token_hex(5),a.publish,a.expiry,a.gui) if a.action=='submit' else status(a.key)))
