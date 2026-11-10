#!/usr/bin/env python3
"""Preserve exact Debian corresponding sources for a built rescue template."""
import argparse
import base64
import fcntl
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

import base
import inventory as inv

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/sources')
FILES=('sources.py','inventory.py','base.py')


def bundle():
    files={name:(ROOT/name).read_bytes() for name in FILES}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in files.items()}
    return files,manifest,hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()


def package(name):
    if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789+-.' for c in name) or not name[0].isalnum():
        raise ValueError('Exact Debian source package name required')
    return name


def version(value):
    if not value or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-.~:' for c in value):
        raise ValueError('Exact Debian source version required')
    return value


def inventory(text):
    result=set()
    for line in text.splitlines():
        fields=line.split('\t')
        if len(fields)!=4:raise ValueError('Actual four-column dpkg inventory required')
        result.add((package(fields[2]),version(fields[3])))
    if not result:raise ValueError('Nonempty distribution inventory required')
    return sorted(result)


def dsc_files(text,name,release):
    fields={};last=None
    for line in text.splitlines():
        if line.startswith('-----BEGIN PGP SIGNATURE-----'):break
        if line.startswith(' ') and last:fields[last]+='\n'+line.strip()
        elif ':' in line:
            key,sep,value=line.partition(':');fields[key]=value.strip();last=key
    if fields.get('Source')!=name or fields.get('Version')!=release:raise ValueError('Exact Debian source version mismatch')
    result=[]
    for line in fields.get('Checksums-Sha256','').splitlines():
        if not line:continue
        sha,size,filename=line.split();amount=int(size)
        if filename in ('.','..') or not filename or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-.~' for c in filename):
            raise ValueError('Unsafe source archive filename')
        if len(sha)!=64 or any(c not in '0123456789abcdef' for c in sha) or not 0<amount<=2*1024**3:
            raise ValueError('Bounded source length and SHA256 required')
        result.append({'name':filename,'sha256':sha,'bytes':amount})
    if not result:raise ValueError('Complete DSC SHA256 list required')
    return result


def fetch(url,target,sha=None,amount=None,limit=2*1024**3):
    host=urllib.parse.urlsplit(url)
    if host.scheme!='https' or host.hostname!='deb.debian.org':raise ValueError('Official Debian HTTPS pool required')
    if target.is_symlink():raise ValueError('Linked source artifact refused')
    if target.exists():
        digest=base.digest(target)
        if sha and digest!=sha or amount is not None and target.stat().st_size!=amount:
            raise ValueError('Different existing source artifact preserved')
        return {'sha256':digest,'bytes':target.stat().st_size,'url':url}
    stat=os.statvfs(target.parent)
    if stat.f_bavail*stat.f_frsize<50*1024**3+(amount or limit):raise RuntimeError('50GiB host reserve required')
    part=target.with_name(target.name+'.part')
    if part.exists():raise ValueError('Previous partial source preserved')
    size=0;digest=hashlib.sha256()
    request=urllib.request.Request(url,headers={'User-Agent':'DebRescueStick-sources'})
    with urllib.request.urlopen(request,timeout=90) as reply,part.open('xb') as stream:
        if not reply.url.startswith('https://'):raise ValueError('HTTPS source redirect required')
        while block:=reply.read(1024*1024):
            size+=len(block)
            if size>(amount or limit):raise ValueError('Source length exceeded')
            stream.write(block);digest.update(block)
        stream.flush();os.fsync(stream.fileno())
    if sha and digest.hexdigest()!=sha or amount is not None and size!=amount:raise ValueError('Source SHA256 or length mismatch')
    os.replace(part,target)
    return {'sha256':digest.hexdigest(),'bytes':size,'url':url}


def source_files(root,name,release):
    package(name);version(release)
    folder=root/name/release.replace(':','_');folder.mkdir(mode=0o755,parents=True,exist_ok=True)
    filename=name+'_'+release.split(':',1)[-1]+'.dsc'
    prefix=name[:4] if name.startswith('lib') else name[0]
    urls=['https://deb.debian.org/'+section+'/pool/'+component+'/'+prefix+'/'+name+'/'
          for section,component in (('debian','main'),('debian-security','updates/main'))]
    origin=folder/'origin.txt'
    if origin.exists():
        previous=origin.read_text().strip()
        if previous not in urls:raise ValueError('Foreign source pool origin preserved')
        urls=[previous]
    for url in urls:
        try:row=fetch(url+urllib.parse.quote(filename,safe=''),folder/filename,limit=2*1024**2);break
        except urllib.error.HTTPError as error:
            if error.code!=404:raise
    else:raise RuntimeError('Exact Debian DSC not in current official pools: '+name+' '+release)
    if not origin.exists():origin.write_text(url+'\n')
    result={str((folder/filename).relative_to(root)):row}
    for item in dsc_files((folder/filename).read_text(),name,release):
        target=folder/item['name']
        result[str(target.relative_to(root))]=fetch(url+urllib.parse.quote(item['name'],safe=''),target,item['sha256'],item['bytes'])
    return result


def provenance(token,source,root,output,proof,basic):
    with (root/'inventory.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        status=root/'dpkg-status.txt';meta=root/'inventory.json'
        if meta.exists():
            record=json.loads(meta.read_text())
            if record['template_sha256']!=proof['sha256'] or base.digest(status)!=record['status_sha256']:
                raise RuntimeError('Actual package provenance changed')
            rows=inv.source_set(status.read_text())
        else:
            if status.exists():raise RuntimeError('Partial provenance artifact preserved')
            rows=inv.collect(token,source/'base.img',output/'dpkg-status.txt')
            os.link(output/'dpkg-status.txt',status)
            base.write(meta,{'template_sha256':proof['sha256'],'status_sha256':base.digest(status),
                            'includes_built_using':True,'sources':sorted(rows)})
        if not set(basic)<=rows:raise RuntimeError('Full status differs from the cold package source inventory')
        return sorted((package(name),version(release)) for name,release in rows)


def run(token,template,sha,metadata_only=False):
    unit=base.admitted(token)
    if bundle()[2]!=sha:raise RuntimeError('Frozen source downloader bundle required')
    base.key(template);source=base.REMOTE/('image-'+template)
    proof=json.loads((source/'template.json').read_text());packages=(source/'installed-packages.txt').read_text()
    if hashlib.sha256(packages.encode()).hexdigest()!=proof['packages_sha256']:raise RuntimeError('Actual template package inventory changed')
    basic=inventory(packages);root=REMOTE/proof['sha256'];root.mkdir(mode=0o700,parents=True,exist_ok=True)
    output=REMOTE/('run-'+token);output.mkdir(mode=0o700)
    record={'started':time.time(),'unit':unit,'template_job':template,'template_sha256':proof['sha256'],
            'package_inventory_sha256':proof['packages_sha256'],'success':False,'files':{},'sources':[],
            'metadata_only':metadata_only}
    try:
        base.write(output/'progress.json',{'phase':'full-package-provenance'})
        rows=provenance(token,source,root,output,proof,basic)
        record.update(includes_built_using=True,source_count=len(rows),basic_source_count=len(basic))
    except Exception as error:
        record.update(error=type(error).__name__+': '+str(error),finished=time.time())
        base.write(output/'result.json',record);return 1
    if metadata_only:
        record.update(success=True,finished=time.time());base.write(output/'result.json',record);return 0
    lock=(root/'fetch.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    index=root/'index.json'
    if index.exists():
        old=json.loads(index.read_text())
        if old.get('template_sha256')!=proof['sha256']:raise RuntimeError('Foreign source index preserved')
    try:
        for name,release in rows:
            base.write(output/'progress.json',{'phase':'sources','name':name,'version':release,'completed':len(record['sources']),'total':len(rows)})
            record['files'].update(source_files(root,name,release));record['sources'].append({'name':name,'version':release})
            base.write(index,record)
        table=''.join('<li><a href="'+urllib.parse.quote(name,safe='/')+'">'+html.escape(name)+'</a> ('+str(row['bytes'])+' bytes) · SHA256 '+row['sha256']+'</li>' for name,row in sorted(record['files'].items()))
        (root/'index.html').write_text('<!doctype html><meta charset="utf-8"><title>DebRescueStick — Debian sources</title><h1>Corresponding Debian sources</h1><p>Exact source versions for template SHA256 '+proof['sha256']+'. Original DSC, upstream archives and Debian patches; all archive lengths and SHA256 hashes verified against their DSC.</p><p><a href="index.json">Machine-readable manifest</a></p><ul>'+table+'</ul>')
        record.update(success=True,directory=str(root),completed=len(rows))
    except Exception as error:record['error']=type(error).__name__+': '+str(error)
    finally:lock.close()
    record['finished']=time.time();base.write(index,record);base.write(output/'result.json',record)
    print(json.dumps({k:record.get(k) for k in ('success','error','completed','directory')}),flush=True)
    return 0 if record['success'] else 1


def submit(token,template,metadata_only=False):
    base.key(token);base.key(template)
    files,manifest,sha=bundle();unit='debrescuestick-base-'+token
    code=r'''from pathlib import Path
import socket,json,base64,subprocess,hashlib
assert socket.gethostname()==HOSTNAME
p=Path('/var/lib/debrescuestick/sources');p.mkdir(mode=0o700,parents=True,exist_ok=True)
assert p.resolve()==p and p.stat().st_uid==0 and not p.stat().st_mode & 0o077
assert not (p/('run-'+KEY)).exists(),'Existing source run preserved'
code=p/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data in FILES.items():
 f=code/name;raw=base64.b64decode(data)
 if f.exists():assert f.read_bytes()==raw
 else:f.write_bytes(raw);f.chmod(0o600)
 assert hashlib.sha256(f.read_bytes()).hexdigest()==MANIFEST[name]
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit='+UNIT,'--property=CPUQuota=100%','--property=MemoryMax=2G',
 '--property=MemorySwapMax=0','--property=Nice=10','--property=IOWeight=10',
 '--property=TasksMax=32','--property=RuntimeMaxSec=3600','--property=TimeoutStopSec=30',
 '/usr/bin/python3',str(code/'sources.py'),'run','--key',KEY,'--template',TEMPLATE,'--sha',SHA]
if METADATA_ONLY:argv.append('--metadata-only')
subprocess.run(argv,capture_output=True,text=True,check=True,timeout=20)
print(json.dumps({'unit':UNIT,'key':KEY,'template_job':TEMPLATE,'bundle_sha256':SHA,'files':MANIFEST,'metadata_only':METADATA_ONLY}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'TEMPLATE':template,'UNIT':unit,'SHA':sha,
            'FILES':{name:base64.b64encode(raw).decode() for name,raw in files.items()},'MANIFEST':manifest,'METADATA_ONLY':metadata_only}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('sources-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code=r'''from pathlib import Path
import json,subprocess
p=Path('/var/lib/debrescuestick/sources')/('run-'+KEY)
raw=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=ActiveState,SubState,Result,ExecMainStatus'],text=True)
value={'key':KEY,'systemd':dict(line.split('=',1) for line in raw.splitlines())}
for name in ('result','progress'):
 if (p/(name+'.json')).exists():value[name]=json.loads((p/(name+'.json')).read_text())
print(json.dumps(value))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code);base.write(ROOT/'artifacts'/('sources-status-'+token+'.json'),result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('submit','status','run'))
    p.add_argument('--key');p.add_argument('--template');p.add_argument('--sha');p.add_argument('--metadata-only',action='store_true');p.add_argument('--verbose',action='store_true');a=p.parse_args()
    if a.action=='run':raise SystemExit(run(a.key,a.template,a.sha,a.metadata_only))
    result=submit(a.key or secrets.token_hex(5),a.template,a.metadata_only) if a.action=='submit' else status(a.key)
    print(json.dumps(result if a.action=='submit' or a.verbose else base.brief(result)))
