import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import base
import host
import native


class OperatorTests(unittest.TestCase):
    def test_missing_configuration_and_foreign_host_fail_before_operations(self):
        command = ('import base,host,native; '
                   'assert base.HOSTNAME == host.HOSTNAME == native.HOSTNAME == ""')
        env = {k: v for k, v in os.environ.items() if k != 'DRS_BUILD_HOST'}
        subprocess.run([sys.executable, '-c', command], env=env, check=True)
        for module, call in ((base, lambda: base.admitted('012345abcd')),
                             (native, lambda: native.admitted('debrescuestick-probe-012345abcd')),
                             (host, lambda: host.install('unused', 'unused'))):
            with patch.object(module, 'HOSTNAME', 'builder.example.org'), \
                    patch.object(module.socket, 'gethostname', return_value='foreign.example.org'), \
                    patch.object(Path, 'mkdir') as mkdir, \
                    patch.object(module.subprocess, 'run') as run:
                with self.assertRaises(RuntimeError):
                    call()
                mkdir.assert_not_called()
                run.assert_not_called()

    def test_exact_configured_host_still_requires_own_cgroup_and_limits(self):
        expected = 'builder.example.org'
        for module, call in ((base, lambda: base.admitted('012345abcd')),
                             (native, lambda: native.admitted('debrescuestick-probe-012345abcd'))):
            with patch.object(module, 'HOSTNAME', expected), \
                    patch.object(module.socket, 'gethostname', return_value=expected), \
                    patch.object(module.os, 'geteuid', return_value=0), \
                    patch.object(Path, 'read_text', return_value='0::/foreign.service\n'):
                with self.assertRaises(RuntimeError):
                    call()

    def test_ssh_configuration_is_an_argument_and_not_shell_interpolation(self):
        with patch.dict(os.environ, {'DRS_BUILD_SSH': 'root@builder.example.org'}), \
                patch('base.subprocess.run') as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{}'
            base.remote('print("{}")')
            self.assertIn('root@builder.example.org', run.call_args.args[0])
            self.assertFalse(run.call_args.kwargs.get('shell', False))
