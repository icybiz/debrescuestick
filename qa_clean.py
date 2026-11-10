"""Return only stopped qualification disks and ephemeral keys, retaining proofs."""
import argparse
import json
import os
from pathlib import Path
import time
import subprocess

import base
import jobs

FILES = ('qa_clean.py', 'base.py', 'jobs.py')


def targets(profile, uid=0):
    if profile.resolve() != profile or profile.stat().st_uid != uid or profile.stat().st_mode & 0o077:
        raise ValueError('Protected own QA directory required')
    record = json.loads((profile / 'result.json').read_text())
    base.key(record['template_job'])
    if not isinstance(record.get('success'), bool) or not record.get('finished'):
        raise ValueError('Finished QA receipt required')
    values = []
    for name in ('bios', 'uefi', 'secure'):
        folder = profile / name
        if folder.exists():
            proof = json.loads((folder / 'result.json').read_text())
            if proof.get('qemu_exit') != 0:
                raise ValueError('Stopped guest receipt required')
            values.append(folder / 'OVMF_VARS.fd')
    for job in (profile / 'jobs').iterdir():
        if len(job.name) != 48 or any(c not in '0123456789abcdef' for c in job.name):
            raise ValueError('Exact own QA job required')
        if json.loads((job / '.owner').read_text()) != {'job': job.name, 'schema': 'drs-job-v1'}:
            raise ValueError('Foreign QA job preserved')
        values.extend(job / name for name in ('image.img', 'image.tail', 'public.key', 'keys.fat'))
    values.extend(profile / name for name in ('key-a', 'key-a.pub', 'key-b', 'key-b.pub'))
    checked = []
    for path in values:
        if path.resolve() != path or path.is_symlink() or not path.is_relative_to(profile):
            raise ValueError('Linked or foreign QA artifact preserved')
        if not path.exists():
            continue
        info = path.stat()
        if not path.is_file() or info.st_uid != uid or info.st_nlink != 1:
            raise ValueError('Foreign or shared QA artifact preserved')
        checked.append(path)
    return checked


def run(token, qa):
    base.admitted(token)
    base.key(qa)
    profile = Path('/var/lib/debrescuestick/qa') / qa
    unit = 'debrescuestick-qa-worker-' + qa + '.service'
    text = subprocess.check_output(['systemctl', 'show', unit, '--property=ActiveState,MainPID'], text=True)
    state = dict(line.split('=', 1) for line in text.splitlines())
    if state.get('ActiveState') not in ('inactive', 'failed') or state.get('MainPID') != '0':
        raise RuntimeError('Own QA unit must have stopped')
    cgroup = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
    if cgroup.exists() and cgroup.read_text().strip():
        raise RuntimeError('Own QA cgroup still has processes')
    paths = targets(profile)
    removed = [{'path': str(path), 'bytes': path.stat().st_size} for path in paths]
    for path in paths:
        path.unlink()
    result = {'success': True, 'qa': qa, 'removed': removed, 'finished': time.time(),
              'proofs_preserved': True, 'factory_and_production_preserved': True}
    base.write(profile / 'returned.json', result)
    base.write(jobs.REMOTE / ('run-' + token) / 'result.json', result)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('submit', 'status', 'run'))
    parser.add_argument('--key')
    parser.add_argument('--qa')
    args = parser.parse_args()
    if args.action == 'run':
        raise SystemExit(run(args.key, args.qa))
    result = (jobs.submit('qa_clean.py', FILES, ['--qa', base.key(args.qa)], args.key)
              if args.action == 'submit' else jobs.status(args.key))
    print(json.dumps(base.brief(result)))
