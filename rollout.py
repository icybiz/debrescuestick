#!/usr/bin/env python3
"""Stage the independent service only after exact native/source qualification."""
import argparse
import base64
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import socket
import subprocess
import time

import base

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/rollout')
FILES=('rollout.py','base.py','server.py','worker.py','keys.py','store.py','fast.py',
       'static/index.html','static/style.css','static/app.js','static/ui.js',
       'deploy/web.service','deploy/worker.service','deploy/apache.conf')


def bundle():
    files={name:(ROOT/name).read_bytes() for name in FILES}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}
    return files,manifest,hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()


def validate(qa,template,sources,inventory,worker_sha,expected_worker):
    digest=template['sha256']
    if (qa.get('success') is not True or qa.get('qualified') is not True or
        qa.get('sha256')!=digest or qa.get('architecture')!='amd64' or
        qa.get('key_isolation') is not True or qa.get('ssh_positive_negative') is not True):
        raise ValueError('Exact native qualification required')
    results=qa.get('results',[])
    if {row.get('firmware') for row in results}!={'bios','uefi'} or not all(
        all(row.get(k) is True for k in ('success','clean_shutdown','wrong_key_rejected','password_rejected','ssh_positive')) for row in results):
        raise ValueError('Both native boot/SSH/shutdown profiles required')
    if worker_sha!=expected_worker:raise ValueError('Tested production personalizer changed')
    if template.get('keyless') is not True or template.get('cold_identity') is not True:
        raise ValueError('Cold keyless template required')
    if (sources.get('success') is not True or sources.get('metadata_only') is not False or
        sources.get('includes_built_using') is not True or sources.get('template_sha256')!=digest or
        inventory.get('template_sha256')!=digest or inventory.get('includes_built_using') is not True):
        raise ValueError('Complete corresponding-source qualification required')
    actual={(row['name'],row['version']) for row in sources.get('sources',[])}
    if not actual or actual!={tuple(row) for row in inventory['sources']} or not sources.get('files'):
        raise ValueError('Exact complete extended source coverage required')


def account():
    marker=Path('/etc/debrescuestick/account.json')
    try:row=pwd.getpwnam('debrescuestick')
    except KeyError:
        subprocess.run(['useradd','--system','--user-group','--home-dir','/var/lib/debrescuestick/state',
                        '--no-create-home','--shell','/usr/sbin/nologin','debrescuestick'],check=True)
        row=pwd.getpwnam('debrescuestick')
        base.write(marker,{'uid':row.pw_uid,'gid':row.pw_gid})
    if not marker.is_file() or json.loads(marker.read_text())!={'uid':row.pw_uid,'gid':row.pw_gid}:
        raise RuntimeError('Unknown existing service account preserved')
    return row


def directory(path,mode=0o755,uid=0,gid=0):
    if path.is_symlink():raise ValueError('Linked deployment directory refused')
    path.mkdir(mode=mode,parents=True,exist_ok=True)
    if path.resolve()!=path:raise ValueError('Canonical deployment directory required')
    path.chmod(mode);os.chown(path,uid,gid)


def owned_file(path,raw,mode=0o644,uid=0,gid=0):
    if path.is_symlink():raise ValueError('Linked deployment file refused')
    temporary=path.with_name(path.name+'.drs-new')
    with temporary.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    temporary.chmod(mode);os.chown(temporary,uid,gid);os.replace(temporary,path)


def release_code(sha):
    release=Path('/opt/debrescuestick/releases')/sha
    directory(release)
    for name in ('server.py','worker.py','keys.py','store.py','fast.py','static/index.html','static/style.css','static/app.js','static/ui.js'):
        destination=release/name;directory(destination.parent)
        owned_file(destination,(ROOT/name).read_bytes())
    current=Path('/opt/debrescuestick/current')
    if current.exists() and not current.is_symlink():raise RuntimeError('Unknown current deployment preserved')
    link=current.with_name('current.drs-new');link.symlink_to(release);os.replace(link,current)
    return release


def stage_parent(before,previous):
    if before.get('success') is not True:raise ValueError('Successful owned deployment required')
    if before.get('phase') in ('private-services-staged','upgraded'):return base.key(previous)
    if before.get('phase')=='web-refreshed':return base.key(before.get('previous_stage',''))
    raise ValueError('Qualified initial stage or completed web refresh required')


def web(token,previous,sha):
    base.admitted(token);base.key(previous)
    _,manifest,actual=bundle()
    if actual!=sha:raise RuntimeError('Frozen web update required')
    before=json.loads((REMOTE/('run-'+previous)/'result.json').read_text())
    original=stage_parent(before,previous)
    output=REMOTE/('run-'+base.key(token));output.mkdir(mode=0o700)
    record={'started':time.time(),'previous_stage':original,'previous_web':previous if previous!=original else None,'success':False}
    try:
        current=Path('/opt/debrescuestick/current').resolve()
        if str(current)!=before['release']:raise ValueError('Different live release preserved')
        for name in ('worker.py','keys.py','store.py','fast.py'):
            if base.digest(current/name)!=manifest[name]:raise ValueError('Frontend refresh must preserve the qualified worker and store')
        unit=Path('/etc/systemd/system/debrescuestick-web.service')
        if unit.read_bytes()!=(ROOT/'deploy/web.service').read_bytes():raise ValueError('Different HTTP service preserved')
        release=release_code(sha)
        subprocess.run(['systemctl','restart','debrescuestick-web.service'],check=True)
        record.update(success=True,phase='web-refreshed',release=str(release),port=before['port'],bundle_sha256=sha)
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps(record),flush=True)
    return 0 if record['success'] else 1


def stage(token,qa_key,template_key,sources_key,sha):
    unit=base.admitted(token)
    _,manifest,actual=bundle()
    if actual!=sha:raise RuntimeError('Frozen deployment bundle required')
    for value in (qa_key,template_key,sources_key):base.key(value)
    output=REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'unit':unit,'started':time.time(),'bundle_sha256':sha,'success':False}
    try:
        qa=json.loads((Path('/var/lib/debrescuestick/qa')/qa_key/'result.json').read_text())
        factory=base.REMOTE/('image-'+template_key)
        template=json.loads((factory/'template.json').read_text())
        source_root=Path('/var/lib/debrescuestick/sources')/template['sha256']
        sources=json.loads((Path('/var/lib/debrescuestick/sources')/('run-'+sources_key)/'result.json').read_text())
        inventory=json.loads((source_root/'inventory.json').read_text())
        tested=Path('/var/lib/debrescuestick/qa')/('code-'+qa['bundle_sha256'])/'worker.py'
        validate(qa,template,sources,inventory,base.digest(tested),manifest['worker.py'])
        for name in ('keys.py','store.py'):
            if base.digest(tested.parent/name)!=manifest[name]:raise ValueError('Qualified key/store source changed')
        states=subprocess.check_output(['systemctl','show','debrescuestick-worker.service',
                                         '--property=LoadState,ActiveState'],text=True)
        if 'LoadState=not-found' not in states:raise RuntimeError('Existing worker unit preserved; finish QA first')
        if base.digest(factory/'base.img')!=template['sha256']:raise RuntimeError('Qualified raw template changed')
        record.update(template_sha256=template['sha256'],qa_job=qa_key,sources_job=sources_key)
        parent=Path('/var/lib/debrescuestick');directory(parent)
        config=Path('/etc/debrescuestick');directory(config)
        user=account();state=parent/'state'
        if state.exists() and not (config/'state.json').exists():raise RuntimeError('Unknown existing state preserved')
        directory(state,0o700,user.pw_uid,user.pw_gid)
        base.write(config/'state.json',{'path':str(state),'uid':user.pw_uid})
        target=state/'base';directory(target,0o750,0,user.pw_gid)
        raw=target/'base.img'
        if raw.exists():
            if raw.is_symlink() or base.digest(raw)!=template['sha256']:raise RuntimeError('Different deployed base preserved')
        else:os.link(factory/'base.img',raw)
        raw.chmod(0o640);os.chown(raw,0,user.pw_gid)
        for name,value in (('template.json',template),('qualified.json',qa)):
            owned_file(target/name,(json.dumps(value,indent=2)+'\n').encode(),0o640,0,user.pw_gid)
        if 'fast' in template:
            packed=target/'fast';directory(packed,0o750,0,user.pw_gid)
            archives=state/'archives';directory(archives,0o750,0,user.pw_gid)
            shared=archives/template['sha256'];directory(shared,0o750,0,user.pw_gid)
            for name in ('prefix.zip','blank.fat','suffix.deflate','archive.json'):
                source=factory/'fast'/name;destination=packed/name
                if destination.exists():
                    if destination.is_symlink() or not os.path.samefile(source,destination):raise ValueError('Different immutable archive preserved')
                else:os.link(source,destination)
                destination.chmod(0o640);os.chown(destination,0,user.pw_gid)
            destination=shared/'prefix.zip'
            if not destination.exists():os.link(packed/'prefix.zip',destination)
            elif destination.is_symlink() or not os.path.samefile(packed/'prefix.zip',destination):
                raise ValueError('Different download prefix preserved')
        cache=Path('/var/cache/debrescuestick/worker');directory(cache,0o700,user.pw_uid,user.pw_gid)
        release=release_code(sha)
        # Publish immutable source companions by hardlink; backend source stays private.
        public=parent/'public/sources'/template['sha256'];directory(public)
        for name,row in sources['files'].items():
            relative=Path(name)
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('Foreign source path refused')
            original=source_root/relative;destination=public/relative
            if original.is_symlink() or not original.is_file() or original.stat().st_size!=row['bytes']:
                raise ValueError('Corresponding-source artifact changed')
            directory(destination.parent)
            if destination.exists():
                if destination.is_symlink() or not os.path.samefile(original,destination):raise ValueError('Foreign public source preserved')
            else:os.link(original,destination)
            destination.chmod(0o644)
        data={k:sources[k] for k in ('template_sha256','package_inventory_sha256','sources','files','includes_built_using')}
        owned_file(public/'index.json',(json.dumps(data,indent=2)+'\n').encode())
        owned_file(public/'index.html',(source_root/'index.html').read_bytes())
        env=config/'web.env'
        if env.exists():
            content=env.read_text().strip();name,sep,value=content.partition('=')
            if name!='DRS_PORT' or not sep or not value.isdecimal():raise ValueError('Foreign web port configuration preserved')
            port=int(value)
        else:
            with socket.socket() as reservation:reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
            owned_file(env,('DRS_PORT='+str(port)+'\n').encode())
        for name in ('web','worker'):
            path=Path('/etc/systemd/system')/('debrescuestick-'+name+'.service')
            if path.exists() and path.read_bytes()!=(ROOT/'deploy'/(name+'.service')).read_bytes():
                raise RuntimeError('Different existing project unit preserved')
            owned_file(path,(ROOT/'deploy'/(name+'.service')).read_bytes())
        subprocess.run(['systemd-analyze','verify','/etc/systemd/system/debrescuestick-web.service',
                         '/etc/systemd/system/debrescuestick-worker.service'],check=True)
        subprocess.run(['systemctl','daemon-reload'],check=True)
        subprocess.run(['systemctl','start','debrescuestick-web.service','debrescuestick-worker.service'],check=True)
        record.update(success=True,phase='private-services-staged',port=port,release=str(release),
                      state=str(state),source_count=len(sources['sources']),source_files=len(sources['files']))
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    record['finished']=time.time();base.write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','error','phase','port')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,qa_key=None,template_key=None,sources_key=None,web_from=None):
    base.key(token)
    if web_from:base.key(web_from)
    else:
        for value in (qa_key,template_key,sources_key):base.key(value)
    files,manifest,sha=bundle();unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import socket,json,base64,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/rollout');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/('run-'+KEY)).exists(),'Existing rollout preserved'
code=p/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data in FILES.items():
 f=code/name;f.parent.mkdir(mode=0o700,parents=True,exist_ok=True);raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==MANIFEST[name]
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=64','--property=RuntimeMaxSec=1800','--property=TimeoutStopSec=45',
 '/usr/bin/python3',str(code/'rollout.py'),'web' if WEB_FROM else 'stage','--key',KEY,'--sha',SHA]
if WEB_FROM:argv+=['--web-from',WEB_FROM]
else:argv+=['--qa',QA,'--template',TEMPLATE,'--sources',SOURCES]
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'key':KEY,'unit':UNIT,'bundle_sha256':SHA,'files':MANIFEST,'qa_job':QA,'template_job':TEMPLATE,'sources_job':SOURCES}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'QA':qa_key,'TEMPLATE':template_key,'SOURCES':sources_key,'UNIT':unit,'SHA':sha,'WEB_FROM':web_from,
            'FILES':{name:base64.b64encode(raw).decode() for name,raw in files.items()},'MANIFEST':manifest}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('rollout-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/rollout')/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
if (p/'result.json').exists():value['result']=json.loads((p/'result.json').read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code);base.write(ROOT/'artifacts'/('rollout-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','stage','web'))
    for name in ('key','qa','template','sources','sha','web-from'):p.add_argument('--'+name)
    a=p.parse_args()
    if a.action=='stage':raise SystemExit(stage(a.key,a.qa,a.template,a.sources,a.sha))
    if a.action=='web':raise SystemExit(web(a.key,a.web_from,a.sha))
    print(json.dumps(submit(a.key or secrets.token_hex(5),a.qa,a.template,a.sources,a.web_from) if a.action=='submit' else status(a.key)))
