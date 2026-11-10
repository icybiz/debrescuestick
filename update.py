"""Promote an exactly qualified rescue base during final acceptance only.

The previous base and ready archives remain available for rollback and existing
downloads. This operator leaves application code and service units unchanged.
"""
import argparse
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import pwd
import sqlite3
import subprocess
import time
import urllib.request

import base
import jobs
import rollout

ROOT = Path(__file__).resolve().parent
PRODUCER = ('worker.py', 'fast.py', 'keys.py', 'store.py')
FILES = ('update.py', 'jobs.py', 'base.py', 'rollout.py') + PRODUCER + (
    'deploy/web.service', 'deploy/worker.service')
PARENT = Path('/var/lib/debrescuestick')


def validate(proof, qualification, sources, inventory, actual, tested):
    sha = proof['sha256']
    if len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError('Exact candidate SHA required')
    if proof.get('bytes') != 8598323200 or not proof.get('fast') or not all(
            proof.get(k) is True for k in ('keyless', 'cold_identity')):
        raise ValueError('Cold fast template required')
    if proof.get('mdns', {}).get('fqdn') != 'debrstick.local':
        raise ValueError('Expected rescue hostname required')
    if qualification.get('sha256') != sha or qualification.get('architecture') != 'amd64' or not all(
            qualification.get(k) is True for k in
            ('success', 'qualified', 'key_isolation', 'ssh_positive_negative', 'secure_boot', 'mdns', 'console', 'own_license')):
        raise ValueError('Complete native qualification of this candidate required')
    results = qualification.get('results', [])
    profiles = {row.get('profile') for row in results}
    if len(results) != 3 or profiles != {'bios', 'uefi', 'secure'}:
        raise ValueError('BIOS, UEFI and Secure Boot profiles required')
    for row in results:
        if not all(row.get(k) is True for k in
                   ('success', 'clean_shutdown', 'wrong_key_rejected', 'password_rejected', 'ssh_positive', 'console', 'own_license')):
            raise ValueError('Native access, isolation and console proof missing')
        peer = row.get('mdns', {})
        if peer.get('hostname') != 'debrstick.local' or not all(peer.get(k) is True for k in
                ('success', 'independent_network_stack', 'ssh_banner')):
            raise ValueError('Independent multicast/SSH peer proof required')
        if row.get('profile') == 'secure' and row.get('secure_boot') is not True:
            raise ValueError('Enforced Secure Boot proof required')
    if set(actual) != set(PRODUCER) or actual != tested:
        raise ValueError('Qualified producer modules changed')
    if sources.get('template_sha256') != sha or inventory.get('template_sha256') != sha or not all(
            sources.get(k) is True for k in ('success', 'includes_built_using')) or sources.get('metadata_only') is not False or inventory.get('includes_built_using') is not True:
        raise ValueError('Complete corresponding sources required')
    if sources.get('package_inventory_sha256') != proof['packages_sha256']:
        raise ValueError('Corresponding-source package inventory differs')
    rows = {(row['name'], row['version']) for row in sources.get('sources', [])}
    if not rows or rows != {tuple(row) for row in inventory.get('sources', [])} or not sources.get('files'):
        raise ValueError('Exact extended source coverage required')


def move_base(current, candidate, backup):
    if backup.exists() or backup.is_symlink():
        raise ValueError('Existing backup preserved')
    os.rename(current, backup)
    try:
        os.rename(candidate, current)
    except BaseException:
        os.rename(backup, current)
        raise


def public_sources(proof, receipt):
    source = PARENT / 'sources' / proof['sha256']
    index = json.loads((source / 'index.json').read_text())
    for field in ('success', 'template_sha256', 'package_inventory_sha256', 'includes_built_using', 'files', 'sources'):
        if index.get(field) != receipt.get(field):
            raise ValueError('Verified source index changed')
    destination = PARENT / 'public/sources' / proof['sha256']
    rollout.directory(destination)
    for name, item in receipt['files'].items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Foreign source path refused')
        original = source / relative
        target = destination / relative
        if original.resolve() != original or original.stat().st_size != item['bytes'] or base.digest(original) != item['sha256']:
            raise ValueError('Corresponding-source archive differs')
        rollout.directory(target.parent)
        if target.exists():
            if target.is_symlink() or not os.path.samefile(original, target):
                raise ValueError('Different existing source archive preserved')
        else:
            os.link(original, target)
        target.chmod(0o644)
    for name in ('index.html', 'index.json'):
        raw = (source / name).read_bytes()
        target = destination / name
        if target.exists():
            if target.is_symlink() or target.read_bytes() != raw:
                raise ValueError('Different public source index preserved')
        else:
            rollout.owned_file(target, raw)
    return {'versions': len(receipt['sources']), 'files': len(receipt['files'])}


def prepare_base(state, source, token, proof, qualification):
    group = pwd.getpwnam('debrescuestick').pw_gid
    candidate = state / ('base-next-' + token)
    if candidate.exists() or candidate.is_symlink():
        raise ValueError('Existing candidate directory preserved')
    rollout.directory(candidate, 0o750, 0, group)
    for name in ('base.img',):
        os.link(source / name, candidate / name)
        os.chown(candidate / name, 0, group)
        (candidate / name).chmod(0o640)
    for name, value in (('template.json', proof), ('qualified.json', qualification)):
        rollout.owned_file(candidate / name, (json.dumps(value, indent=2) + '\n').encode(), 0o640, 0, group)
    packed = candidate / 'fast'
    rollout.directory(packed, 0o750, 0, group)
    for name in ('prefix.zip', 'blank.fat', 'suffix.deflate', 'archive.json'):
        os.link(source / 'fast' / name, packed / name)
        os.chown(packed / name, 0, group)
        (packed / name).chmod(0o640)
    shared = state / 'archives' / proof['sha256']
    rollout.directory(shared, 0o750, 0, group)
    prefix = shared / 'prefix.zip'
    if prefix.exists():
        if prefix.is_symlink() or not os.path.samefile(prefix, packed / 'prefix.zip'):
            raise ValueError('Different existing archive prefix preserved')
    else:
        os.link(packed / 'prefix.zip', prefix)
    return candidate



def clear_heartbeat(state):
    """Readiness must come from the new worker, never a fresh old heartbeat."""
    path = state / 'heartbeat.json'
    if path.is_symlink() or path.resolve() != path:
        raise ValueError('Linked heartbeat preserved')
    path.unlink(missing_ok=True)


def wait_idle(state, timeout=30):
    database_path = state / 'jobs.sqlite3'
    if database_path.is_symlink() or not database_path.is_file():
        raise ValueError('Existing queue database required')
    end = time.monotonic() + timeout
    while True:
        with closing(sqlite3.connect(database_path.as_uri() + '?mode=ro', uri=True)) as database:
            busy = database.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','personalizing','compressing')").fetchone()[0]
        if not busy:
            return
        if time.monotonic() >= end:
            raise RuntimeError('Active accepted requests preserved; update deferred')
        time.sleep(.5)


def ready(port, sha):
    end = time.monotonic() + 60
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:' + str(port) + '/debrescuestick/api/status', timeout=5) as response:
                value = json.load(response)
            if value.get('available') is True and value.get('sources_url') == '/debrescuestick/sources/' + sha + '/':
                return
        except OSError:
            pass
        if time.monotonic() >= end:
            raise RuntimeError('Promoted service did not become ready')
        time.sleep(.25)


def run(token, template, qa, sources, previous, purpose):
    base.admitted(token)
    if purpose != 'final':
        raise ValueError('Final acceptance/publication purpose required')
    for value in (template, qa, sources, previous):
        base.key(value)
    output = jobs.REMOTE / ('run-' + token)
    output.mkdir(mode=0o700)
    record = {'started': time.time(), 'success': False, 'template_job': template, 'qa_job': qa,
              'sources_job': sources, 'previous_stage': previous}
    stopped = False
    moved = False
    state = PARENT / 'state'
    current_base = state / 'base'
    backup = Path('/var/backups/debrescuestick') / ('mdns-' + token)
    lock_fd = os.open(PARENT / 'upgrade.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            source = base.REMOTE / ('image-' + template)
            proof = json.loads((source / 'template.json').read_text())
            qualification = json.loads((PARENT / 'qa' / qa / 'result.json').read_text())
            receipt = json.loads((PARENT / 'sources' / ('run-' + sources) / 'result.json').read_text())
            inventory = json.loads((PARENT / 'sources' / proof['sha256'] / 'inventory.json').read_text())
            tested = PARENT / 'qa' / ('code-' + qualification['bundle_sha256'])
            actual = {name: base.digest(ROOT / name) for name in PRODUCER}
            validate(proof, qualification, receipt, inventory, actual, {name: base.digest(tested / name) for name in PRODUCER})
            if base.digest(source / 'base.img') != proof['sha256']:
                raise ValueError('Qualified candidate disk changed')
            before = json.loads((rollout.REMOTE / ('run-' + previous) / 'result.json').read_text())
            initial = rollout.stage_parent(before, previous)
            initial_proof = json.loads((rollout.REMOTE / ('run-' + initial) / 'result.json').read_text())
            if current_base.is_symlink() or current_base.resolve() != current_base:
                raise ValueError('Linked live base preserved')
            old_proof = json.loads((current_base / 'template.json').read_text())
            old_sha = old_proof['sha256']
            if old_sha != initial_proof['template_sha256']:
                raise ValueError('Different live base preserved')
            release = Path('/opt/debrescuestick/current').resolve()
            if str(release) != before['release'] or any(base.digest(release / name) != actual[name] for name in PRODUCER):
                raise ValueError('Different live application code preserved')
            for short in ('web', 'worker'):
                unit = Path('/etc/systemd/system') / ('debrescuestick-' + short + '.service')
                if unit.is_symlink() or unit.read_bytes() != (ROOT / 'deploy' / (short + '.service')).read_bytes():
                    raise ValueError('Different service unit preserved')
            record['sources'] = public_sources(proof, receipt)
            candidate = prepare_base(state, source, token, proof, qualification)
            backup.mkdir(mode=0o700)
            base.write(backup / 'before.json', {'template_sha256': old_sha, 'release': str(release), 'previous': previous})
            # Stop admission, let already accepted requests finish, then swap.
            subprocess.run(['systemctl', 'stop', 'debrescuestick-web.service'], check=True, timeout=30)
            stopped = True
            wait_idle(state)
            subprocess.run(['systemctl', 'stop', 'debrescuestick-worker.service'], check=True, timeout=45)
            clear_heartbeat(state)
            move_base(current_base, candidate, backup / 'base')
            moved = True
            subprocess.run(['systemctl', 'start', 'debrescuestick-worker.service', 'debrescuestick-web.service'], check=True, timeout=45)
            ready(before['port'], proof['sha256'])
            record.update(success=True, phase='upgraded', template_sha256=proof['sha256'],
                          previous_template_sha256=old_sha, release=str(release), port=before['port'],
                          backup=str(backup), producer_sha256=actual, old_archives_preserved=True)
        except Exception as error:
            record['error'] = type(error).__name__ + ': ' + str(error)
            if stopped:
                if moved:
                    for short in ('web', 'worker'):
                        subprocess.run(['systemctl', 'stop', 'debrescuestick-' + short + '.service'], timeout=45)
                    observed = json.loads((current_base / 'template.json').read_text())
                    if observed['sha256'] != proof['sha256']:
                        raise RuntimeError('Concurrent base change preserved; rollback refused') from error
                    os.rename(current_base, state / ('base-rejected-' + token))
                    os.rename(backup / 'base', current_base)
                    clear_heartbeat(state)
                subprocess.run(['systemctl', 'start', 'debrescuestick-worker.service', 'debrescuestick-web.service'], check=True, timeout=45)
                ready(before['port'], old_sha)
                record['rolled_back'] = True
        finally:
            record['finished'] = time.time()
            base.write(output / 'result.json', record)
            stage = rollout.REMOTE / ('run-' + token)
            stage.mkdir(mode=0o700)
            base.write(stage / 'result.json', record)
    return 0 if record['success'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('submit', 'status', 'run'))
    for name in ('key', 'template', 'qa', 'sources', 'previous', 'purpose'):
        parser.add_argument('--' + name)
    args = parser.parse_args()
    if args.action == 'run':
        raise SystemExit(run(args.key, args.template, args.qa, args.sources, args.previous, args.purpose))
    if args.action == 'submit':
        if args.purpose != 'final':
            parser.error('--purpose final is required')
        arguments = []
        for name in ('template', 'qa', 'sources', 'previous'):
            arguments += ['--' + name, base.key(getattr(args, name))]
        arguments += ['--purpose', 'final']
        result = jobs.submit('update.py', FILES, arguments, args.key)
    else:
        result = jobs.status(args.key)
    print(json.dumps(base.brief(result)))
