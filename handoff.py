"""Prepare a small VM payload binding one live ZIP to its independent IMG hash.

The large ZIP is downloaded only on browser.local for reference extraction and
inside the eventual Windows guest. This operator never creates or boots a VM.
"""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import time
import zipfile

import extract

ROOT = Path(__file__).resolve().parent
MARGIN = 300 + 900 + 60
LOGS = ('run.log', 'python.log', 'bsd.sha', 'seven.sha', 'bsd.bytes', 'seven.bytes',
        'bsd-version.log', 'seven-version.log')


def hex_value(value, length):
    if not isinstance(value, str) or len(value) != length or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Exact hexadecimal identity required')
    return value


def decoded_bytes(text):
    rows = [line.split() for line in text.splitlines() if len(line.split()) > 1 and line.split()[1] == 'bytes']
    if len(rows) != 1:
        raise ValueError('One exact independent byte count required')
    return int(rows[0][0])


def reference(record, logs, now):
    if (record.get('reference_schema') != 'drs-extraction-reference-v1' or
            record.get('success') is not True or record.get('resources_returned') is not True or
            record.get('template_sha256') != extract.TEMPLATE or record.get('raw_bytes') != extract.RAW_SIZE or
            record.get('remote_phase') != 'complete'):
        raise ValueError('Completed, cleaned reference extraction of the exact base required')
    state = record['systemd']
    if any(state.get(k) != v for k, v in {'Result': 'success', 'ExecMainStatus': '0',
                                         'ActiveState': 'inactive', 'MainPID': '0'}.items()):
        raise ValueError('Reference worker must have finished successfully')
    job = record['job']
    hex_value(job['id'], 48); hex_value(job['sha256'], 64); hex_value(record['raw_sha256'], 64)
    if (job.get('state') != 'ready' or not 0 < job['bytes'] < 1400 * 1024**2 or
            not job['created'] <= now or job['expires'] - now < MARGIN):
        raise ValueError('Live exact download with sufficient remaining test time required')
    if 'image.zip: OK' not in logs['run.log'].splitlines() or 'Done testing' not in logs['python.log'].splitlines():
        raise ValueError('Downloaded ZIP SHA and Python CRC proof required')
    for name in ('bsd', 'seven'):
        fields = logs[name + '.sha'].split()
        if len(fields) != 2 or fields != [record['raw_sha256'], '-'] or decoded_bytes(logs[name + '.bytes']) != extract.RAW_SIZE:
            raise ValueError('Both independent IMG hashes and full lengths must agree')
    if 'bsdtar' not in logs['bsd-version.log'] or '7-Zip' not in logs['seven-version.log']:
        raise ValueError('Independent decoder identities required')
    return job


def read_reference(path):
    path = Path(path).absolute()
    if path.resolve() != path or path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError('Canonical small reference receipt required')
    record = json.loads(path.read_text())
    logs = {}
    for name in LOGS:
        file = path.parent / name
        if file.resolve() != file or file.stat().st_size > 65536:
            raise ValueError('Canonical bounded decoder proof required')
        logs[name] = file.read_text()
    return record, logs


def prepare(path, now=None):
    now = int(time.time()) if now is None else now
    record, logs = read_reference(path)
    job = reference(record, logs, now)
    current = extract.request('/api/jobs/' + job['id'])
    if any(current.get(name) != job[name] for name in ('id', 'sha256', 'bytes', 'created', 'expires', 'state')):
        raise ValueError('Authoritative live download differs from the reference')
    token = secrets.token_hex(16)
    scripts = {name: (ROOT / name).read_bytes() for name in ('explorer.ps1', 'receive.ps1')}
    manifest = {'schema': 'drs-windows-handoff-v1', 'id': token, 'created': now,
                'expires': job['expires'], 'download_timeout': 300, 'check_timeout': 900,
                'archive': {'url': extract.ORIGIN + '/download/' + job['id'], 'job': job['id'],
                            'sha256': job['sha256'], 'bytes': job['bytes']},
                'image': {'name': 'DebRescueStick-amd64.img', 'bytes': extract.RAW_SIZE,
                          'sha256': record['raw_sha256'], 'template_sha256': extract.TEMPLATE},
                'scripts': {name: hashlib.sha256(raw).hexdigest() for name, raw in scripts.items()},
                'reference_sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    raw = (json.dumps(manifest, sort_keys=True, separators=(',', ':')) + '\n').encode()
    digest = hashlib.sha256(raw).hexdigest()
    launch = ('powershell.exe -NoLogo -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass '
              '-File "%~dp0receive.ps1" -ManifestPath "%~dp0manifest.json" -ManifestSha256 ' + digest)
    command = ('@echo off\r\nif defined DRS_REPORT_PATH (\r\n  ' + launch +
               ' -ReportPath "%DRS_REPORT_PATH%"\r\n) else (\r\n  ' + launch +
               '\r\n)\r\nexit /b %ERRORLEVEL%\r\n').encode('ascii')
    folder = ROOT / 'build' / ('handoff-' + token)
    folder.mkdir(mode=0o700, parents=True)
    files = {**scripts, 'manifest.json': raw, 'start.cmd': command}
    for name, data in files.items():
        (folder / name).write_bytes(data); (folder / name).chmod(0o600)
    # Source/metadata only, never the 1.25 GB image archive.
    with zipfile.ZipFile(folder / 'payload.zip', 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, data in files.items():
            bundle.writestr(name, data)
    (folder / 'payload.zip').chmod(0o600)
    result = {'success': True, 'scope': 'prepared-vm-handoff', 'nativeWindowsTested': False,
              'folder': str(folder), 'manifest_sha256': digest, 'expires': job['expires'],
              'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    (folder / 'prepared.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def new():
    """The host operator supplies the existing browser lease; no VM is started."""
    token = None
    try:
        submitted = extract.start(); token = extract.key(submitted['key'])
        end = time.monotonic() + 960
        while True:
            status = extract.status(token)
            if status['systemd']['ActiveState'] not in ('active', 'activating'):
                if not status['success']:
                    raise RuntimeError('Independent reference extraction failed')
                break
            if time.monotonic() > end:
                raise RuntimeError('Reference extraction deadline exceeded')
            time.sleep(5)
        extract.finish(token)
        return prepare(ROOT / 'artifacts' / ('extract-' + token) / 'run.json')
    finally:
        if token:
            path = ROOT / 'artifacts' / ('extract-' + token) / 'run.json'
            record = json.loads(path.read_text())
            if not record.get('resources_returned'):
                # This is only the exact client unit just submitted by this run.
                extract.runtime(record, token)
                extract.remote(shlex.join(['systemctl', 'stop', record['unit']]))
                extract.status(token)
                extract.finish(token)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'new'))
    parser.add_argument('--reference')
    args = parser.parse_args()
    if args.action == 'prepare' and not args.reference:
        parser.error('--reference is required')
    print(json.dumps(prepare(args.reference) if args.action == 'prepare' else new()))
