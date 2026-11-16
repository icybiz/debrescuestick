#!/usr/bin/env python3
"""Switch only the five qualified backend modules after explicit operator approval.

EORLS, service definitions, configuration and image inputs are outside this tool.
The plan is an operator-local JSON artifact, never a public credential store.
"""
import argparse
import base64
from contextlib import closing
import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import time
import urllib.request

MODULES = ('server.py', 'worker.py', 'store.py', 'keys.py', 'fast.py')
WEB = 'debrescuestick-web.service'
WORKER = 'debrescuestick-worker.service'


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def plan_hash(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def approved(plan, approval):
    if (approval.get('approved') is not True or
            approval.get('plan_sha256') != plan_hash(plan) or
            not isinstance(approval.get('approved_by'), str) or not approval['approved_by'].strip() or
            not isinstance(approval.get('approved_at'), str) or not approval['approved_at'].strip()):
        raise ValueError('Explicit operator approval of this exact plan is required')
    stamp = datetime.datetime.fromisoformat(approval['approved_at'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Approval time must include its timezone')


def sources(plan, root):
    manifest = plan['runtime_only']
    if set(manifest) != set(MODULES):
        raise ValueError('Exactly five qualified runtime modules required')
    result = {}
    for name in MODULES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Canonical runtime file required')
        raw = path.read_bytes()
        if identity(raw) != manifest[name]:
            raise ValueError('Qualified runtime source changed: ' + name)
        compile(raw, name, 'exec')
        result[name] = raw
    return result


def release_files(root):
    """Bounded ordinary source/static files; never follow links or read images."""
    if root.is_symlink() or root.resolve() != root:
        raise ValueError('Canonical release directory required')
    result = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Linked release asset refused')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('Unexpected release asset')
        result[path.relative_to(root).as_posix()] = path.read_bytes()
        if len(result) > 128 or sum(map(len, result.values())) > 4 * 1024 * 1024:
            raise ValueError('Release exceeds small source/static budget')
    return result


def candidate(plan, previous, runtime):
    if set(runtime) != set(MODULES):
        raise ValueError('Exactly five runtime payloads required')
    for name in MODULES:
        if identity(previous[name]) != plan['expected_previous_runtime5'][name]:
            raise ValueError('Different live runtime preserved: ' + name)
        if identity(runtime[name]) != plan['runtime_only'][name]:
            raise ValueError('Unqualified runtime payload')
    return dict(previous, **runtime)


def queue_counts(database):
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        return dict(db.execute('SELECT state,COUNT(*) FROM jobs GROUP BY state'))


def backup(database, destination):
    # SQLite backup includes committed WAL content without copying a live WAL trio.
    with destination.open('xb'):
        pass
    destination.chmod(0o600)
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as src:
        with closing(sqlite3.connect(destination)) as dst:
            src.backup(dst)
            if dst.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                raise RuntimeError('Queue backup integrity check failed')


def run_unit(action, unit):
    if unit not in (WEB, WORKER) or action not in ('start', 'stop'):
        raise ValueError('Only the two own service units may be controlled')
    subprocess.run(['systemctl', action, unit], check=True, capture_output=True, timeout=75)


def unit_info(unit):
    raw = subprocess.check_output(['systemctl', 'show', unit,
        '--property=ActiveState,MainPID,User,WorkingDirectory'], text=True, timeout=15)
    return dict(line.split('=', 1) for line in raw.splitlines())


def wait_for(check, seconds, message):
    deadline = time.monotonic() + seconds
    while not check():
        if time.monotonic() >= deadline:
            raise RuntimeError(message)
        time.sleep(.5)


def execute(plan, runtime, approval, hostname):
    approved(plan, approval)
    if not hostname or socket.gethostname() != hostname or os.geteuid() != 0:
        raise RuntimeError('Assigned backend host and root operator required')
    os.umask(0o077)
    import fcntl
    lock = os.open('/run/lock/debrescuestick-runtime.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return switch(plan, runtime)
    finally:
        os.close(lock)


def switch(plan, runtime, *, application=Path('/opt/debrescuestick'),
           state=Path('/var/lib/debrescuestick/state'),
           operations=Path('/var/lib/debrescuestick/ops')):
    current = application / 'current'
    releases = current.parent / 'releases'
    old = current.resolve(strict=True)
    if (not current.is_symlink() or old.parent != releases or
            str(old) != plan['expected_previous_release']):
        raise RuntimeError('Different live release preserved')
    values = candidate(plan, release_files(old), runtime)
    for unit in (WEB, WORKER):
        info = unit_info(unit)
        if (info['ActiveState'] != 'active' or int(info['MainPID']) <= 0 or
                info['User'] != 'debrescuestick' or info['WorkingDirectory'] != str(current)):
            raise RuntimeError('Unexpected own service state preserved')
    database = state / 'jobs.sqlite3'
    if database.is_symlink() or database.resolve() != database or not database.is_file():
        raise RuntimeError('Canonical own queue database required')
    if queue_counts(database):
        raise RuntimeError('Wait for existing jobs to finish and expire before switching')
    digest = plan_hash(plan)
    target = releases / hashlib.sha256(json.dumps(
        {n: identity(raw) for n, raw in values.items()}, sort_keys=True).encode()).hexdigest()
    if target.exists():
        if release_files(target) != values:
            raise RuntimeError('Different existing candidate preserved')
    else:
        target.mkdir(mode=0o755)
        for name, raw in values.items():
            path = target / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with path.open('xb') as out:
                out.write(raw)
            path.chmod(0o644)
        if release_files(target) != values:
            raise RuntimeError('Written candidate differs')
    operation = operations / ('runtime-' + digest)
    operation.mkdir(parents=True, mode=0o700, exist_ok=False)
    proof = {'success': False, 'plan_sha256': digest, 'old_release': str(old),
             'new_release': str(target), 'phase': 'prepared', 'admission_closed': False}

    def record():
        temporary = operation / 'result.new'
        temporary.write_text(json.dumps(proof, indent=2) + '\n')
        os.replace(temporary, operation / 'result.json')

    stopped = []
    switched = False
    record()
    try:
        stopped.append(WEB)
        run_unit('stop', WEB)
        proof.update(phase='draining', admission_closed=True)
        record()
        wait_for(lambda: not any(queue_counts(database).get(k, 0)
                 for k in ('queued', 'personalizing', 'compressing')), 120,
                 'Admitted jobs still active; previous runtime retained')
        stopped.append(WORKER)
        run_unit('stop', WORKER)
        backup(database, operation / 'jobs.sqlite3')
        proof.update(phase='backed-up')
        record()
        if current.resolve(strict=True) != old:
            raise RuntimeError('Concurrent release change preserved')
        link = current.with_name('current.runtime-' + digest[:12])
        link.symlink_to(target)
        if current.resolve(strict=True) != old:
            link.unlink()
            raise RuntimeError('Concurrent release change preserved')
        os.replace(link, current)
        switched = True
        proof.update(phase='runtime-switched')
        record()
        started = time.time()
        run_unit('start', WORKER)

        def ready():
            try:
                info = unit_info(WORKER)
                pulse = json.loads((state / 'heartbeat.json').read_text())
                return (info['ActiveState'] == 'active' and pulse['pid'] == int(info['MainPID'])
                        and started <= pulse['time'] <= time.time() and time.time() - pulse['time'] <= 5)
            except (ValueError, OSError, KeyError):
                return False

        wait_for(ready, 30, 'New worker readiness missing; admission remains closed')
        run_unit('start', WEB)

        def available():
            try:
                with urllib.request.urlopen('http://127.0.0.1:36037/debrescuestick/api/status', timeout=2) as response:
                    return json.load(response).get('available') is True
            except (OSError, ValueError):
                return False

        wait_for(available, 20, 'Qualified API readiness missing')
        with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)) as db:
            columns = {row[1] for row in db.execute('PRAGMA table_info(jobs)')}
            indexes = {row[1] for row in db.execute('PRAGMA index_list(jobs)') if row[2]}
        if not {'request_hash', 'replay_until'} <= columns or 'jobs_request_hash' not in indexes:
            raise RuntimeError('Replay metadata migration missing')
        proof.update(success=True, phase='ready', admission_closed=False)
    except Exception as error:
        proof['error'] = str(error)
        if switched:
            # New request bindings may already exist: never restore stale metadata
            # or run an older worker beneath them. Keep the new worker for drainage.
            run_unit('stop', WEB)
            proof.update(phase='held-for-compatible-repair', admission_closed=True)
        elif current.resolve(strict=True) == old:
            try:
                for unit in reversed(stopped):
                    run_unit('start', unit)
                def old_ready():
                    try:
                        web = unit_info(WEB)
                        worker = unit_info(WORKER)
                        pulse = json.loads((state / 'heartbeat.json').read_text())
                        return (web['ActiveState'] == 'active' and worker['ActiveState'] == 'active'
                                and pulse['pid'] == int(worker['MainPID'])
                                and 0 <= time.time() - pulse['time'] <= 5)
                    except (ValueError, OSError, KeyError):
                        return False
                wait_for(old_ready, 30, 'Previous runtime readiness missing')
                proof.update(phase='previous-runtime-restored', admission_closed=False)
            except Exception as restore_error:
                proof['restore_error'] = str(restore_error)
                try:
                    run_unit('stop', WEB)
                except Exception as close_error:
                    proof['close_error'] = str(close_error)
                proof.update(phase='previous-runtime-recovery-incomplete', admission_closed=True)
        else:
            proof.update(phase='concurrent-release-preserved', admission_closed=True)
    finally:
        record()
    return dict(proof, proof_path=str(operation / 'result.json'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'apply'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--approval', type=Path)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text())
    runtime = sources(plan, Path(__file__).resolve().parent)
    if args.action == 'inspect':
        print(json.dumps({'plan_sha256': plan_hash(plan), 'runtime_files': len(runtime),
                          'runtime_bytes': sum(map(len, runtime.values())), 'activated': False}))
        return
    if args.approval is None:
        parser.error('--approval is required; inspect never activates a release')
    approval = json.loads(args.approval.read_text())
    approved(plan, approval)
    import base
    payload = {n: base64.b64encode(raw).decode('ascii') for n, raw in runtime.items()}
    script = Path(__file__).read_text()
    code = 'import base64,json\nnamespace={"__name__":"drs_switch_remote"}\n'
    code += 'exec(compile(' + repr(script) + ',"switch.py","exec"),namespace)\n'
    code += 'payload=' + repr(payload) + '\n'
    code += 'runtime={n:base64.b64decode(v) for n,v in payload.items()}\n'
    code += 'print(json.dumps(namespace["execute"](' + repr(plan) + ',runtime,' + repr(approval) + ',' + repr(base.HOSTNAME) + ')))\n'
    result = base.remote(code, timeout=600)
    print(json.dumps(result))
    if not result['success']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
