#!/usr/bin/env python3
"""Export all project software, without operator state or private Git history."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parent
DIRECTORIES = ('deploy', 'image', 'static', 'tests')
SUFFIXES = {'.py', '.sh', '.service', '.conf', '.txt', '.js', '.mjs',
            '.html', '.css', '.svg', '.ps1'}


def files(root=ROOT):
    result = {p.name: p for pattern in ('*.py', '*.sh', '*.js', '*.mjs', '*.ps1') for p in root.glob(pattern)}
    for name in ('.gitignore', 'COPYING', 'NOTICE', 'debian.lock.json', 'ps.lock.json', 'operator.env.example', 'API.md', 'site.json'):
        result[name] = root / name
    result['README.md'] = root / ('PUBLIC.md' if (root / 'PUBLIC.md').is_file() else 'README.md')
    for directory in DIRECTORIES:
        for path in (root / directory).rglob('*'):
            if '__pycache__' in path.parts or path.is_dir():
                continue
            if path.suffix not in SUFFIXES or path.name.endswith('.PFL.md'):
                raise ValueError('Unexpected software asset: ' + str(path.relative_to(root)))
            result[path.relative_to(root).as_posix()] = path
    for name, path in result.items():
        if path.is_symlink() or path.resolve() != path or not path.is_file():
            raise ValueError('Canonical regular source required: ' + name)
    return dict(sorted(result.items()))


def audit(values):
    """Refuse known internal paths and complete private-key blocks, not test markers."""
    forbidden = ('/z' + 'Data/', '/home/' + 'user/.nvm/')
    for name, raw in values.items():
        text = raw.decode('utf-8')
        if any(value in text for value in forbidden):
            raise ValueError('Internal configuration in source: ' + name)
        lines = text.splitlines()
        if (any(line.startswith('-----BEGIN ') and line.endswith('PRIVATE KEY-----') for line in lines)
                and any(line.startswith('-----END ') and line.endswith('PRIVATE KEY-----') for line in lines)):
            raise ValueError('Possible private key in source: ' + name)
        if any(prefix in text for prefix in ('github' + '_pat_', 'gh' + 'p_')):
            raise ValueError('Possible access token in source: ' + name)


def export(root=ROOT):
    values = {name: path.read_bytes() for name, path in files(root).items()}
    audit(values)
    directory = root / 'build' / ('public-' + secrets.token_hex(5))
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {}
    for name, raw in values.items():
        target = directory / name
        target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o644)
        manifest[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    (directory / 'SOURCES.json').write_text(json.dumps({
        'project': 'DebRescueStick', 'license': 'GPL-3.0-or-later', 'files': manifest
    }, indent=2) + '\n')
    return {'directory': str(directory), 'files': len(manifest)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('audit', 'export'))
    args = parser.parse_args()
    if args.action == 'audit':
        selected = files()
        audit({name: path.read_bytes() for name, path in selected.items()})
        print(json.dumps({'success': True, 'files': len(selected)}))
    else:
        print(json.dumps(export()))
