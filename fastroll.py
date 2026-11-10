"""Upgrade only this service after independent native and comparative proofs."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import sqlite3
import subprocess
import time
import urllib.request
import base
import jobs
import rollout

ROOT=Path(__file__).resolve().parent
RUNTIME=('server.py','worker.py','keys.py','store.py','fast.py','static/index.html','static/style.css','static/app.js')
FILES=('fastroll.py','jobs.py','base.py','rollout.py')+RUNTIME+('deploy/web.service','deploy/worker.service','deploy/apache.conf')
OLD='1cf4ef3ac928f9fc72f79a4a920a25350ff347e787fb74a26a0f3b0f48a551d2'
OLD_WORKER='74b4b71ac357cce09da23670b5ef41abe11da8ec00d00d9083a2900580cd9027'


def move_base(current,nextbase,backup):
    os.rename(current,backup)
    try:os.rename(nextbase,current)
    except BaseException:
        os.rename(backup,current)
        raise


def validate(proof,qa,measurement,worker_sha,qualified_sha):
    if (qa.get('success') is not True or not all(qa.get(k) is True for k in
        ('qualified','key_isolation','ssh_positive_negative')) or qa.get('sha256')!=proof['sha256']):
        raise ValueError('Exact native qualification required')
    if {r['firmware'] for r in qa['results'] if r.get('success') and r.get('clean_shutdown')}!={'bios','uefi'}:
        raise ValueError('Both native boot modes required')
    if measurement.get('success') is not True or measurement.get('sha256')!=proof['sha256'] or len(measurement.get('full',[]))<2 or len(measurement.get('reuse',[]))<2:
        raise ValueError('Two serial comparative samples required')
    if worker_sha!=qualified_sha:raise ValueError('Native producer changed')
    if max(r['personalization_seconds'] for r in qa['results'])>5:
        raise ValueError('Candidate does not meet five-second personalization target')


def copy_sources(proof,parent):
    old=parent/'public/sources'/OLD;catalog=json.loads((old/'index.json').read_text())
    if proof['previous_sha256']!=OLD or catalog['package_inventory_sha256']!=proof['packages_sha256']:
        raise ValueError('Distribution package identity changed')
    if not catalog['includes_built_using'] or len(catalog['sources'])!=410 or len(catalog['files'])!=1285:
        raise ValueError('Complete original corresponding sources required')
    new=parent/'public/sources'/proof['sha256'];new.mkdir(mode=0o755,exist_ok=True)
    if new.is_symlink():raise ValueError('Linked source destination preserved')
    for name,row in catalog['files'].items():
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts:raise ValueError('Foreign source path')
        source=old/relative;target=new/relative
        if source.is_symlink() or source.stat().st_size!=row['bytes'] or base.digest(source)!=row['sha256']:
            raise ValueError('Corresponding source changed')
        target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        if target.exists():
            if target.is_symlink() or not os.path.samefile(source,target):raise ValueError('Foreign existing source preserved')
        else:os.link(source,target)
    catalog['template_sha256']=proof['sha256']
    content=json.dumps(catalog,indent=2)+'\n'
    if (new/'index.json').exists() and (new/'index.json').read_text()!=content:raise ValueError('Different source index preserved')
    (new/'index.json').write_text(content)
    text=(old/'index.html').read_text()
    content=text.replace(OLD,proof['sha256'])
    if (new/'index.html').exists() and (new/'index.html').read_text()!=content:raise ValueError('Different source page preserved')
    (new/'index.html').write_text(content)
    return {'versions':410,'files':1285,'same_package_inventory':True,'index':str(new/'index.json')}


def run(token,template,qa,benchmark):
    base.admitted(token)
    for value in (template,qa,benchmark):base.key(value)
    output=jobs.REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'success':False,'started':time.time(),'template_job':template,'qa_job':qa,'benchmark_job':benchmark}
    stopped=False;moved=False;backup=Path('/var/backups/debrescuestick')/('fast-'+token)
    parent=Path('/var/lib/debrescuestick');state=parent/'state';oldbase=state/'base'
    try:
        source=base.REMOTE/('image-'+template);proof=json.loads((source/'template.json').read_text())
        qualification=json.loads((parent/'qa'/qa/'result.json').read_text())
        measurement=json.loads((jobs.REMOTE/('run-'+benchmark)/'result.json').read_text())
        tested=parent/'qa'/('code-'+qualification['bundle_sha256'])
        validate(proof,qualification,measurement,base.digest(ROOT/'worker.py'),base.digest(tested/'worker.py'))
        for name in ('keys.py','store.py','fast.py'):
            if base.digest(ROOT/name)!=base.digest(tested/name):raise ValueError('Qualified module changed: '+name)
        if base.digest(source/'base.img')!=proof['sha256']:raise ValueError('Qualified raw changed')
        current=Path('/opt/debrescuestick/current');previous=current.resolve()
        if base.digest(previous/'worker.py')!=OLD_WORKER:raise ValueError('Unexpected production preserved')
        before_proof=json.loads((oldbase/'template.json').read_text())
        if before_proof['sha256']!=OLD:raise ValueError('Unexpected live template preserved')
        backup.mkdir(mode=0o700)
        runtime={name:(ROOT/name).read_bytes() for name in RUNTIME}
        release_sha=hashlib.sha256(json.dumps({n:hashlib.sha256(v).hexdigest() for n,v in runtime.items()},sort_keys=True).encode()).hexdigest()
        release=Path('/opt/debrescuestick/releases')/release_sha;release.mkdir(mode=0o755,exist_ok=True)
        for name,raw in runtime.items():
            dest=release/name;dest.parent.mkdir(mode=0o755,exist_ok=True)
            if dest.exists() and (dest.is_symlink() or dest.read_bytes()!=raw):raise ValueError('Different release file preserved')
            dest.write_bytes(raw);dest.chmod(0o644)
        record['sources']=copy_sources(proof,parent)
        user=pwd.getpwnam('debrescuestick');gid=user.pw_gid
        nextbase=state/('base-next-'+token);nextbase.mkdir(mode=0o750);os.chown(nextbase,0,gid)
        os.link(source/'base.img',nextbase/'base.img');os.chown(nextbase/'base.img',0,gid);(nextbase/'base.img').chmod(0o640)
        for name,value in [('template.json',proof),('qualified.json',qualification)]:
            dest=nextbase/name;dest.write_text(json.dumps(value,indent=2)+'\n');dest.chmod(0o640);os.chown(dest,0,gid)
        packed=nextbase/'fast';packed.mkdir(mode=0o750);os.chown(packed,0,gid)
        for name in ('prefix.zip','blank.fat','suffix.deflate','archive.json'):
            os.link(source/'fast'/name,packed/name);(packed/name).chmod(0o640);os.chown(packed/name,0,gid)
        archives=state/'archives';archives.mkdir(mode=0o750,exist_ok=True);os.chown(archives,0,gid)
        shared=archives/proof['sha256'];shared.mkdir(mode=0o750,exist_ok=True);os.chown(shared,0,gid)
        if (shared/'prefix.zip').exists():
            if (shared/'prefix.zip').is_symlink() or not os.path.samefile(packed/'prefix.zip',shared/'prefix.zip'):raise ValueError('Different shared prefix preserved')
        else:os.link(packed/'prefix.zip',shared/'prefix.zip')
        units={}
        for short in ('web','worker'):
            path=Path('/etc/systemd/system')/('debrescuestick-'+short+'.service')
            units[short]=path.read_bytes();(backup/path.name).write_bytes(units[short])
            expected=(ROOT/('deploy/'+short+'.service')).read_bytes().replace(b'ReadOnlyPaths=-/var/lib/debrescuestick/state/archives\n',b'')
            if units[short]!=expected:raise ValueError('Different production unit preserved')
        # Admission stops briefly; already-ready old ZIPs remain readable after restart.
        subprocess.run(['systemctl','stop','debrescuestick-web.service'],check=True,timeout=30);stopped=True
        end=time.monotonic()+300
        while True:
            with sqlite3.connect(state/'jobs.sqlite3') as db:
                busy=db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','personalizing','compressing')").fetchone()[0]
            if not busy:break
            if time.monotonic()>end:raise RuntimeError('Active user requests preserved; upgrade deferred')
            time.sleep(2)
        subprocess.run(['systemctl','stop','debrescuestick-worker.service'],check=True,timeout=60)
        for short in ('web','worker'):
            path=Path('/etc/systemd/system')/('debrescuestick-'+short+'.service')
            path.write_bytes((ROOT/('deploy/'+short+'.service')).read_bytes())
        move_base(oldbase,nextbase,backup/'base');moved=True
        link=current.with_name('current.fast-new');link.symlink_to(release);os.replace(link,current)
        subprocess.run(['systemctl','daemon-reload'],check=True,timeout=30)
        subprocess.run(['systemctl','start','debrescuestick-worker.service','debrescuestick-web.service'],check=True,timeout=45)
        end=time.monotonic()+60
        while True:
            try:
                with urllib.request.urlopen('http://127.0.0.1:36037/debrescuestick/api/status',timeout=5) as response:value=json.load(response)
                if value.get('available') and proof['sha256'] in value.get('sources_url',''):break
            except OSError:pass
            if time.monotonic()>end:raise RuntimeError('New service did not become ready')
            time.sleep(1)
        record.update(success=True,phase='upgraded',template_sha256=proof['sha256'],
                      release=str(release),previous_release=str(previous),port=36037,backup=str(backup),
                      worker_sha256=base.digest(ROOT/'worker.py'),source_count=410,source_files=1285,published=True)
    except Exception as error:
        record['error']=type(error).__name__+': '+str(error)
        if stopped:
            for short in ('web','worker'):subprocess.run(['systemctl','stop','debrescuestick-'+short+'.service'],timeout=60)
            if moved:
                if oldbase.exists():os.rename(oldbase,state/('base-rejected-'+token))
                os.rename(backup/'base',oldbase)
                link=current.with_name('current.fast-rollback');link.symlink_to(previous);os.replace(link,current)
            for short,raw in units.items():(Path('/etc/systemd/system')/('debrescuestick-'+short+'.service')).write_bytes(raw)
            subprocess.run(['systemctl','daemon-reload'],check=True,timeout=30)
            subprocess.run(['systemctl','start','debrescuestick-worker.service','debrescuestick-web.service'],check=True,timeout=45)
            record['rolled_back']=True
    record['finished']=time.time();base.write(output/'result.json',record)
    stage=Path('/var/lib/debrescuestick/rollout')/('run-'+token);stage.mkdir(mode=0o700)
    base.write(stage/'result.json',record)
    return 0 if record['success'] else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    for n in ('key','template','qa','benchmark'):p.add_argument('--'+n)
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.template,a.qa,a.benchmark))
    args=['--template',base.key(a.template),'--qa',base.key(a.qa),'--benchmark',base.key(a.benchmark)] if a.action=='submit' else []
    print(json.dumps(base.brief(jobs.submit('fastroll.py',FILES,args,a.key) if a.action=='submit' else jobs.status(a.key))))
