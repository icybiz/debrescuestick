import subprocess
import unittest

import secure


class SecureTests(unittest.TestCase):
    def record(self):
        return {'key':'a'*10,'unit':'debrescuestick-secure-'+'a'*10+'.service',
                'remote_root':'/tmp/debrescuestick-secure-'+'a'*10,
                'job':{'id':'b'*48,'sha256':'c'*64,'bytes':1221038090}}

    def test_cleanup_cannot_target_foreign_paths_or_units(self):
        record=self.record()
        self.assertEqual(secure.paths(record)[0],record['remote_root'])
        for value in ('','/','/tmp','/tmp/debrescuestick-secure-','../foreign',record['remote_root']+'/../other'):
            with self.assertRaises(ValueError):secure.paths({**record,'remote_root':value})
        with self.assertRaises(ValueError):secure.paths({**record,'unit':'foreign.service'})
        for value in ('','..','A'*10,'/tmp/a'):
            with self.assertRaises(ValueError):secure.paths({**record,'key':value})

    def test_remote_script_is_ram_and_host_confined_and_has_three_controls(self):
        text=secure.script(self.record())
        self.assertIn('test "$(hostname -s)" = browser',text)
        self.assertIn('/proc/self/cgroup',text)
        self.assertIn('--target /tmp',text)
        self.assertIn('conv=sparse',text)
        self.assertEqual(text.count('qemu-system-x86_64 -enable-kvm'),3)
        self.assertEqual(text.count('OVMF_VARS_4M.ms.fd'),2)
        self.assertIn('OVMF_VARS_4M.fd',text)
        self.assertIn('sbattach --remove unsigned.efi',text)
        self.assertNotIn('root@prox',text);self.assertNotIn('aiserver',text)
        checked=subprocess.run(['bash','-n'],input=text,text=True,capture_output=True)
        self.assertEqual(checked.returncode,0,checked.stderr)
        for field in ('id','sha256'):
            with self.assertRaises(ValueError):secure.script({**self.record(),'job':{**self.record()['job'],field:'../foreign'}})

    def test_both_secure_state_and_forward_progress_are_required(self):
        signed='SECURE_BOOT=1\nSETUP_MODE=0\nLOCKDOWN=none [integrity] confidentiality\nSHA256:owner\npasswordauthentication no\nkbdinteractiveauthentication no\nDRS_SECURE_END\n'
        secure.validate_guest(signed,'signed','SHA256:owner')
        for broken in (signed.replace('SECURE_BOOT=1','SECURE_BOOT=0'),signed.replace('[integrity]','integrity'),signed.replace('DRS_SECURE_END',''),signed.replace('SHA256:owner','SHA256:other')):
            with self.assertRaises(RuntimeError):secure.validate_guest(broken,'signed','SHA256:owner')
        control=signed.replace('SECURE_BOOT=1','SECURE_BOOT=0').replace('SETUP_MODE=0','SETUP_MODE=1').replace('[integrity]','integrity')
        secure.validate_guest(control,'unsigned-off','SHA256:owner')
        with self.assertRaises(RuntimeError):secure.validate_guest(control,'signed','SHA256:owner')

    def test_only_owned_loopback_ssh_forward_is_accepted(self):
        row='  TCP[HOST_FORWARD] 13 127.0.0.1 34123 10.0.2.15 22 0 0'
        self.assertEqual(secure.port(row),34123)
        for bad in (row.replace('127.0.0.1','0.0.0.0'),row.replace(' 22 ',' 80 '),''):
            with self.assertRaises(RuntimeError):secure.port(bad)

    def test_auto_runs_all_controls_then_returns_resources(self):
        from unittest.mock import patch
        record={'stages':{}}
        def status(token):
            pending=next((s for s in secure.STAGES if s not in record['stages']),'complete')
            return {'phase':pending,'systemd':{'ActiveState':'active'},'stages':record['stages']}
        def check(token,stage):record['stages'][stage]={'success':True}
        with patch.object(secure,'status',side_effect=status), patch.object(secure,'check',side_effect=check) as checking, \
             patch.object(secure,'load',return_value=(None,record)), patch.object(secure,'state',return_value={'MainPID':'0'}), \
             patch.object(secure,'collect',return_value={'success':True}) as collecting, \
             patch.object(secure,'finish',return_value={'resources_returned':True}) as finishing, patch.object(secure,'abort') as aborting:
            self.assertTrue(secure.auto('a'*10)['resources_returned'])
        self.assertEqual([c.args[1] for c in checking.call_args_list],list(secure.STAGES))
        collecting.assert_called_once();finishing.assert_called_once();aborting.assert_not_called()

    def test_failed_control_stops_only_own_run_and_still_returns_resources(self):
        from unittest.mock import patch
        row={'phase':'signed','systemd':{'ActiveState':'active'},'stages':{}}
        with patch.object(secure,'status',return_value=row), patch.object(secure,'check',side_effect=RuntimeError('bad proof')), \
             patch.object(secure,'abort') as aborting, patch.object(secure,'collect') as collecting, \
             patch.object(secure,'load',return_value=(None,{})), patch.object(secure,'write'), \
             patch.object(secure,'finish') as finishing:
            with self.assertRaisesRegex(RuntimeError,'bad proof'):secure.auto('a'*10)
        aborting.assert_called_once_with('a'*10);collecting.assert_called_once_with('a'*10);finishing.assert_called_once_with('a'*10)

    def test_completed_runs_remain_readable_after_resource_return(self):
        from unittest.mock import patch
        token='a'*10
        record={**self.record(),'success':True,'resources_returned':True,'phase':'complete',
                'systemd':{'ActiveState':'inactive','MainPID':'0','Result':'success','ExecMainStatus':'0'},
                'stages':{s:{'success':True} for s in secure.STAGES}}
        with patch.object(secure,'load',return_value=(None,record)), \
             patch.object(secure,'state',return_value=record['systemd']), \
             patch.object(secure.extract,'remote',return_value='') as remote, patch.object(secure,'write'):
            self.assertTrue(secure.status(token)['success'])
            self.assertTrue(secure.collect(token)['success'])
            self.assertTrue(secure.auto(token)['success'])
            self.assertTrue(secure.finish(token)['resources_returned'])
            remote.assert_not_called()
