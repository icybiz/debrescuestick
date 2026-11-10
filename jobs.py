"""Small frozen-code transport for bounded operator jobs on the assigned Prox."""
import base64
import hashlib
import json
from pathlib import Path
import secrets
import base

ROOT=Path(__file__).resolve().parent
REMOTE=Path('/var/lib/debrescuestick/fast')


def submit(tool,files,arguments,key=None):
    token=base.key(key or secrets.token_hex(5))
    if tool not in ('fastbuild.py','fastprobe.py','fastroll.py','english.py','update.py','qa_clean.py'):raise ValueError('Known operator tool required')
    payload={name:(ROOT/name).read_bytes() for name in files}
    manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in payload.items()}
    sha=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
    code='''from pathlib import Path
import os,json,socket,base64,hashlib,subprocess,shutil
assert socket.gethostname()==HOSTNAME and os.geteuid()==0
root=Path('/var/lib/debrescuestick/fast');root.mkdir(mode=0o700,exist_ok=True)
assert root.resolve()==root and root.stat().st_uid==0 and not root.stat().st_mode & 0o077
assert not (root/('run-'+KEY)).exists(),'Existing own operator job preserved'
assert shutil.disk_usage(root).free>50*1024**3,'50GiB host reserve required'
code=root/('code-'+SHA);code.mkdir(mode=0o700,exist_ok=True)
for name,data in FILES.items():
 relative=Path(name)
 assert not relative.is_absolute() and '..' not in relative.parts
 path=code/relative;path.parent.mkdir(mode=0o700,exist_ok=True)
 raw=base64.b64decode(data)
 if path.exists():assert not path.is_symlink() and path.read_bytes()==raw
 else:path.write_bytes(raw);path.chmod(0o600)
 assert hashlib.sha256(path.read_bytes()).hexdigest()==MANIFEST[name]
argv=['systemd-run','--setenv=DRS_BUILD_HOST='+HOSTNAME,'--unit=debrescuestick-base-'+KEY,'--property=CPUQuota=100%',
 '--property=MemoryMax=2G','--property=MemorySwapMax=0','--property=Nice=10',
 '--property=IOWeight=10','--property=TasksMax=128','--property=RuntimeMaxSec=3600',
 '--property=TimeoutStopSec=45','/usr/bin/python3',str(code/TOOL),'run','--key',KEY]+ARGS
subprocess.run(argv,check=True,capture_output=True,text=True,timeout=20)
print(json.dumps({'key':KEY,'tool':TOOL,'bundle_sha256':SHA,'manifest':MANIFEST}))
'''
    values={'HOSTNAME':base.HOSTNAME,'KEY':token,'SHA':sha,'TOOL':tool,'ARGS':arguments,
            'MANIFEST':manifest,'FILES':{n:base64.b64encode(v).decode() for n,v in payload.items()}}
    result=base.remote('\n'.join(n+'='+repr(v) for n,v in values.items())+'\n'+code)
    base.write(ROOT/'artifacts'/('fast-job-'+token+'.json'),result);return result


def status(token):
    base.key(token)
    code='''from pathlib import Path
import json,subprocess
root=Path('/var/lib/debrescuestick/fast')/('run-'+KEY)
text=subprocess.check_output(['systemctl','show','debrescuestick-base-'+KEY+'.service','--property=Result,ExecMainStatus,ActiveState,SubState'],text=True)
result={'key':KEY,'systemd':dict(line.split('=',1) for line in text.splitlines())}
for name in ('result','progress','partial'):
 path=root/(name+'.json')
 if path.exists():result[name]=json.loads(path.read_text())
print(json.dumps(result))
'''
    result=base.remote('KEY='+repr(token)+'\n'+code)
    base.write(ROOT/'artifacts'/('fast-status-'+token+'.json'),result);return result
