import copy
import hashlib
from pathlib import Path
import unittest

import pscheck


class PowerShellTests(unittest.TestCase):
    def proof(self):
        return {'success': True, 'scope': 'portable-powershell-fixtures',
                'nativeWindowsTested': False, 'explorerUiTested': False,
                'source_sha256': hashlib.sha256(b'source').hexdigest(),
                'tests_sha256': hashlib.sha256(b'tests').hexdigest(),
                'cases': ['hashes-and-lengths', 'real-lock-and-unchanged-metadata', 'asynchronous-forward-progress',
                          'timeouts-and-false-green-refusal', 'zip-layout-validation',
                          'nonrecursive-owned-cleanup', 'non-windows-refusal']}

    def test_portable_proof_requires_exact_sources_and_cannot_claim_native_pass(self):
        proof = self.proof()
        pscheck.validate(proof, 'source', 'tests')
        for name, value in (('success', False), ('scope', 'windows-shell-zip'),
                            ('nativeWindowsTested', True), ('explorerUiTested', True),
                            ('source_sha256', '0' * 64), ('tests_sha256', '0' * 64), ('cases', [])):
            bad = copy.deepcopy(proof)
            bad[name] = value
            with self.assertRaises(ValueError):
                pscheck.validate(bad, 'source', 'tests')

    def test_runtime_root_and_recursive_cleanup_reject_bad_segments_before_deletion(self):
        self.assertEqual(pscheck.runtime('a' * 10), Path('/tmp/debrescuestick-pscheck') / ('a' * 10))
        for token in ('', ' ', '/', '.', '..', '../x', 'a/b', 'a\\b', '%2f', 'g' * 10, 'a' * 11):
            with self.assertRaises(ValueError):
                pscheck.remove_runtime(token)
            with self.assertRaises(ValueError):
                pscheck.cleanup_source(token)

    def test_remote_source_is_compilable_with_no_production_host_or_unbounded_delete(self):
        source = pscheck.bootstrap_source('a' * 10)
        cleanup = pscheck.cleanup_source('a' * 10)
        compile(source, '<PowerShell-bootstrap>', 'exec')
        compile(cleanup, '<PowerShell-cleanup>', 'exec')
        self.assertNotIn('prox', source)
        self.assertNotIn('aiserver', source)
        self.assertIn('memory.max', source)
        self.assertIn('memory.swap.max', source)


if __name__ == '__main__':
    unittest.main()
