import copy
import json
import os
from pathlib import Path
import sqlite3
import time
import unittest
from unittest.mock import patch

import update
from server import App
from support import workspace


class UpdateTests(unittest.TestCase):
    def records(self):
        sha='a'*64
        proof={'sha256':sha,'bytes':8598323200,'fast':{'schema':'fixture'},'keyless':True,
               'cold_identity':True,'packages_sha256':'b'*64,'mdns':{'fqdn':'debrstick.local'}}
        qa={'sha256':sha,'architecture':'amd64',**{k:True for k in ('success','qualified','key_isolation','ssh_positive_negative','secure_boot','mdns','console','own_license')},'results':[]}
        for name in ('bios','uefi','secure'):
            qa['results'].append({'profile':name,'firmware':'bios' if name=='bios' else 'uefi',
                **{k:True for k in ('success','clean_shutdown','wrong_key_rejected','password_rejected','ssh_positive','console','own_license')},
                'secure_boot':name=='secure','mdns':{'hostname':'debrstick.local','success':True,'independent_network_stack':True,'ssh_banner':True}})
        sources={'success':True,'includes_built_using':True,'metadata_only':False,'template_sha256':sha,
                 'package_inventory_sha256':'b'*64,'sources':[{'name':'example','version':'1'}], 'files':{'example.dsc':{}}}
        inventory={'template_sha256':sha,'includes_built_using':True,'sources':[['example','1']]}
        producers={name:'c'*64 for name in update.PRODUCER}
        return proof,qa,sources,inventory,producers,dict(producers)

    def test_only_exact_complete_native_and_source_proofs_are_accepted(self):
        update.validate(*self.records())
        for part,key,value in ((1,'sha256','d'*64),(1,'secure_boot',False),(1,'console',False),
                               (1,'mdns',False),(1,'own_license',False),(2,'metadata_only',True),(2,'includes_built_using',False),
                               (3,'includes_built_using',False),(2,'package_inventory_sha256','d'*64)):
            records=list(copy.deepcopy(self.records()));records[part][key]=value
            with self.assertRaises(ValueError):update.validate(*records)
        records=list(self.records());records[1]['results'][0]['mdns']['independent_network_stack']=False
        with self.assertRaises(ValueError):update.validate(*records)
        records=list(self.records());records[1]['results'].pop()
        with self.assertRaises(ValueError):update.validate(*records)
        records=list(self.records());records[5]['worker.py']='e'*64
        with self.assertRaises(ValueError):update.validate(*records)

    def test_old_heartbeat_cannot_prove_the_new_worker_ready(self):
        with workspace() as state:
            (state/'base').mkdir();sha='a'*64
            (state/'base/template.json').write_text(json.dumps({'sha256':sha}))
            (state/'base/qualified.json').write_text(json.dumps({'sha256':sha,'architecture':'amd64','qualified':True,'key_isolation':True,'ssh_positive_negative':True}))
            (state/'heartbeat.json').write_text(json.dumps({'time':time.time()}))
            app=App(state);self.assertTrue(app.available())
            update.clear_heartbeat(state);self.assertFalse(app.available())
            (state/'heartbeat.json').write_text(json.dumps({'time':time.time()}));self.assertTrue(app.available())
            (state/'heartbeat.json').unlink();foreign=state/'foreign';foreign.write_text('preserve')
            (state/'heartbeat.json').symlink_to(foreign)
            with self.assertRaises(ValueError):update.clear_heartbeat(state)
            self.assertEqual(foreign.read_text(),'preserve')

    def test_queue_drains_to_progress_but_busy_timeout_preserves_requests(self):
        with workspace() as state:
            database=state/'jobs.sqlite3'
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE jobs(state TEXT)');db.execute('INSERT INTO jobs VALUES (?)',('queued',))
            with self.assertRaises(RuntimeError):update.wait_idle(state,timeout=0)
            def progress(delay):
                with sqlite3.connect(database) as db:db.execute("UPDATE jobs SET state='ready'")
            with patch('update.time.sleep',side_effect=progress):update.wait_idle(state)
            with sqlite3.connect(database) as db:self.assertEqual(db.execute('SELECT state FROM jobs').fetchone()[0],'ready')

    def test_failed_base_swap_restores_the_previous_directory(self):
        with workspace() as state:
            current=state/'base';candidate=state/'next';backup=state/'backup'
            current.mkdir();candidate.mkdir();(current/'identity').write_text('old');(candidate/'identity').write_text('new')
            rename=os.rename
            def fail(source,target):
                if source==candidate:raise OSError('probe failure')
                return rename(source,target)
            with patch('update.os.rename',side_effect=fail):
                with self.assertRaises(OSError):update.move_base(current,candidate,backup)
            self.assertEqual((current/'identity').read_text(),'old')
            update.move_base(current,candidate,backup)
            self.assertEqual((current/'identity').read_text(),'new');self.assertEqual((backup/'identity').read_text(),'old')
            with self.assertRaises(ValueError):update.move_base(current,backup,backup)

    def test_update_refuses_local_host_before_any_output_or_state_access(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('update.Path.mkdir') as mkdir:
            with self.assertRaises(RuntimeError):update.run('a'*10,'b'*10,'c'*10,'d'*10,'e'*10,'final')
        mkdir.assert_not_called()
