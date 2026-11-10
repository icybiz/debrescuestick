from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil

BASE=Path('/tmp/debrescuestick-tests')
SESSION=secrets.token_hex(16)


def child(token):
    if not isinstance(token,str) or len(token)!=32 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('Exact fixture UUID required')
    root=BASE.resolve();target=(BASE/token).resolve()
    if root!=BASE or target!=BASE/token or target==root or not target.is_relative_to(root):
        raise ValueError('Fixture root/path escape refused')
    return target


@contextmanager
def workspace():
    BASE.mkdir(mode=0o700,exist_ok=True)
    if BASE.is_symlink() or BASE.stat().st_uid!=os.getuid() or BASE.stat().st_mode & 0o077:
        raise ValueError('Foreign fixture root preserved')
    token=secrets.token_hex(16);path=child(token)
    path.mkdir();owner={'session':SESSION,'pid':os.getpid(),'uid':os.getuid()}
    (path/'.owner').write_text(json.dumps(owner))
    try:yield path
    finally:
        if path.is_symlink() or json.loads((path/'.owner').read_text())!=owner:raise ValueError('Foreign fixture preserved')
        child(token)
        shutil.rmtree('/tmp/debrescuestick-tests/'+token)
