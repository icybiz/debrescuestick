from pathlib import Path
import secrets
import subprocess
import unittest


class BrowserStateTests(unittest.TestCase):
    def test_job_recovery_expiry_and_response_order(self):
        root=Path(__file__).resolve().parents[1]
        result=subprocess.run(['node','--test',str(root/'tests/ui.mjs')],capture_output=True,text=True,timeout=15)
        log=root/'artifacts'/('ui-'+secrets.token_hex(5)+'.log')
        log.parent.mkdir(exist_ok=True)
        log.write_text(result.stdout+result.stderr)
        self.assertEqual(result.returncode,0,'UI state contracts failed: '+str(log)+'\n'+result.stdout+result.stderr)
