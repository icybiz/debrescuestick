import hashlib
import json
from pathlib import Path
import unittest

import public
from support import workspace


class ExportTests(unittest.TestCase):
    def fixture(self, root):
        for name in ('.gitignore', 'COPYING', 'NOTICE', 'debian.lock.json', 'operator.env.example', 'README.md'):
            (root / name).write_text('synthetic source\n')
        for name in ('server.py', 'worker.py', 'image.py', 'public.py', 'preview.mjs'):
            (root / name).write_text('# synthetic project software\n')
        for name in ('deploy/web.service', 'image/setup.sh', 'static/app.js', 'tests/test_example.py'):
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_text('# synthetic asset\n')
        for directory in ('.private', '.git', 'artifacts', 'checkpoints'):
            path = root / directory
            path.mkdir()
            (path / 'must-stay-private').write_text('synthetic sensitive state\n')

    def test_complete_software_manifest_without_runtime_or_history(self):
        with workspace() as root:
            self.fixture(root)
            selected = public.files(root)
            self.assertTrue({'server.py', 'worker.py', 'image.py', 'preview.mjs',
                             'deploy/web.service', 'image/setup.sh', 'static/app.js',
                             'tests/test_example.py'} <= set(selected))
            result = public.export(root)
            target = Path(result['directory'])
            manifest = json.loads((target / 'SOURCES.json').read_text())['files']
            self.assertEqual(set(manifest), set(selected))
            for name, source in selected.items():
                raw = (target / name).read_bytes()
                self.assertEqual(raw, source.read_bytes())
                self.assertEqual(manifest[name]['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(set(public.files(target)), set(selected))
            for name in ('.private', '.git', 'artifacts', 'checkpoints'):
                self.assertFalse((target / name).exists())

    def test_linked_software_and_unknown_binary_assets_are_refused(self):
        with workspace() as root:
            self.fixture(root)
            (root / 'server.py').unlink()
            (root / 'server.py').symlink_to(root / 'worker.py')
            with self.assertRaises(ValueError):
                public.files(root)
            (root / 'server.py').unlink()
            (root / 'static/old.exe').write_bytes(b'synthetic executable')
            with self.assertRaises(ValueError):
                public.files(root)

    def test_private_content_refused_and_public_synthetic_markers_preserved(self):
        for value in ('/z' + 'Data/private/file', 'gh' + 'p_synthetic',
                      '-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----'):
            with self.assertRaises(ValueError):
                public.audit({'example.py': value.encode()})
        public.audit({'test.py': b"rejected_input = '-----BEGIN PRIVATE KEY-----'\n"})
