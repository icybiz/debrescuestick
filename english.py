"""Final acceptance and guarded publication of the English website only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.error
import urllib.request

import base
import jobs
import rollout

ROOT=Path(__file__).resolve().parent
FILES=tuple(dict.fromkeys(('english.py','jobs.py')+rollout.FILES+('static/move.html','static/move.css')))
CONVERTER_SHA='345cd1fce0033ad29ffe4ff8cc978e549355ea14bbd9be49612f794573d945f3'


def atomic_page(path,data,info,token):
    base.key(token)
    if path.is_symlink():raise ValueError('Linked archive page preserved')
    temporary=path.with_name(path.name+'.english-'+token)
    with temporary.open('xb') as stream:stream.write(data)
    temporary.chmod(info.st_mode&0o777);os.chown(temporary,info.st_uid,info.st_gid)
    os.replace(temporary,path)


def read(url):
    with urllib.request.urlopen(url,timeout=20) as response:
        data=response.read(2*1024**2+1)
        if response.status!=200 or len(data)>2*1024**2:raise RuntimeError('Bounded successful page required')
        return data


def web_ready(port,timeout=20):
    end=time.monotonic()+timeout;attempts=0;last='not available'
    while True:
        attempts+=1
        try:
            value=json.loads(read('http://127.0.0.1:'+str(port)+'/debrescuestick/api/status'))
            if value.get('available') is True:return {'attempts':attempts,'status':value}
        except urllib.error.HTTPError as error:
            if error.code!=503:raise
            last=str(error)
        except OSError as error:last=str(error)
        if time.monotonic()>=end:raise RuntimeError('Image service did not become ready: '+last)
        time.sleep(.25)


def run(token,previous,archive_sha,purpose):
    base.admitted(token)
    if purpose!='final':raise ValueError('Prox is reserved for final staging acceptance')
    base.key(previous)
    output=jobs.REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'started':time.time(),'success':False,'purpose':'final-staging-and-publication','previous_web':previous}
    page=Path('/var/www/mindbytez.com/oss/index.html')
    current=Path('/opt/debrescuestick/current');previous_release=current.resolve()
    expected_release=Path('/opt/debrescuestick/releases')/rollout.bundle()[2]
    old_page=None;written=False
    try:
        before=json.loads((rollout.REMOTE/('run-'+previous)/'result.json').read_text())
        rollout.stage_parent(before,previous)
        if str(previous_release)!=before['release']:raise ValueError('Different current release preserved')
        if page.is_symlink() or base.digest(page)!=archive_sha:raise ValueError('Changed archive page preserved')
        info=page.stat();old_page=page.read_bytes()
        if base.digest(page.with_name('move.css'))!=base.digest(ROOT/'static/move.css'):
            raise ValueError('Changed archive styling preserved')
        if base.digest(page.with_name('usb_inst_Mod.sh'))!=CONVERTER_SHA:
            raise ValueError('Changed historical converter preserved')
        backup=Path('/var/backups/debrescuestick')/('english-'+token);backup.mkdir(mode=0o700)
        (backup/'index.html').write_bytes(old_page)
        base.write(backup/'metadata.json',{'previous_release':str(previous_release),'archive_sha256':archive_sha,
            'mode':info.st_mode&0o777,'uid':info.st_uid,'gid':info.st_gid})
        code=rollout.web(token,previous,rollout.bundle()[2])
        staged=json.loads((rollout.REMOTE/('run-'+token)/'result.json').read_text())
        if code or not staged['success']:raise RuntimeError(staged.get('error','Web publication failed'))
        record.update(staged)
        record['readiness']=web_ready(staged['port'])
        if base.digest(page)!=archive_sha:raise ValueError('Concurrent archive change preserved')
        atomic_page(page,(ROOT/'static/move.html').read_bytes(),info,token);written=True
        pages={}
        for suffix,name in [('', 'static/index.html'),('app.js','static/app.js'),('style.css','static/style.css')]:
            data=read('https://eorls.com/debrescuestick/'+suffix)
            if data!=(ROOT/name).read_bytes():raise RuntimeError('HTTPS page differs: '+name)
            pages[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        data=read('https://mindbytez.com/oss/')
        if data!=(ROOT/'static/move.html').read_bytes():raise RuntimeError('English archive HTTPS differs')
        if b'<html lang="en"' not in data:raise RuntimeError('English archive language missing')
        status=json.loads(read('https://eorls.com/debrescuestick/api/status'))
        if status.get('available') is not True:raise RuntimeError('Qualified image service unavailable')
        request=urllib.request.Request('http://127.0.0.1:'+str(staged['port'])+'/debrescuestick/api/jobs',
            data=json.dumps({'public_key':'-----BEGIN PRIVATE KEY-----\nsynthetic final-acceptance marker'}).encode(),
            headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request,timeout=10):raise RuntimeError('Private-key marker was accepted')
        except urllib.error.HTTPError as error:
            response=json.load(error)
            if error.code!=400 or response.get('error')!='Paste one public key line, never a private key.':
                raise RuntimeError('English key validation failed')
        if base.digest(page.with_name('usb_inst_Mod.sh'))!=CONVERTER_SHA:raise RuntimeError('Converter changed')
        record.update(success=True,phase='web-refreshed',english=True,backup=str(backup),pages=pages,
                      archive_sha256=hashlib.sha256(data).hexdigest(),api_status=status,english_validation=True,
                      producer_unchanged=True,converter_unchanged=True)
    except Exception as error:
        record.update(success=False,error=type(error).__name__+': '+str(error))
        # Restore only our own known replacements. Preserve concurrent edits.
        if written:
            if page.read_bytes()==(ROOT/'static/move.html').read_bytes():atomic_page(page,old_page,info,token)
            else:record['archive_rollback_refused']='Concurrent archive change preserved'
        actual=current.resolve()
        if actual==expected_release:
            link=current.with_name('current.english-rollback-'+token);link.symlink_to(previous_release);os.replace(link,current)
            subprocess.run(['systemctl','restart','debrescuestick-web.service'],check=True,timeout=30)
            record['web_rolled_back']=True
        elif actual!=previous_release:record['web_rollback_refused']='Concurrent release change preserved'
    record['finished']=time.time()
    base.write(output/'result.json',record)
    stage=rollout.REMOTE/('run-'+token)
    if stage.exists():base.write(stage/'result.json',record)
    return 0 if record['success'] else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('publish','status','run'))
    for name in ('key','previous','archive-sha','purpose'):p.add_argument('--'+name)
    a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.previous,a.archive_sha,a.purpose))
    if a.action=='publish':
        previous=base.key(a.previous)
        original=ROOT/'checkpoints/english/before/static/move.html'
        result=jobs.submit('english.py',FILES,['--previous',previous,'--archive-sha',base.digest(original),'--purpose','final'],a.key)
    else:result=jobs.status(a.key)
    print(json.dumps(base.brief(result)))
