import io
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import switch
from store import Store


class SwitchTests(unittest.TestCase):
    def test_exact_approval_precedes_host_or_service_access(self):
        with patch('switch.socket.gethostname') as host, patch('switch.switch') as apply:
            for approval in ({}, {'approved': True, 'plan_sha256': 'wrong',
                                  'approved_by': 'operator', 'approved_at': 'now'}):
                with self.assertRaises(ValueError):
                    switch.execute({}, {}, approval, 'example')
            host.assert_not_called()
            apply.assert_not_called()

    def test_approval_cannot_be_reused_after_plan_change(self):
        plan = {'runtime_only': {'example': 'one'}}
        approval = {'approved': True, 'plan_sha256': switch.plan_hash(plan),
                    'approved_by': 'operator', 'approved_at': '2026-11-16T00:00:00Z'}
        switch.approved(plan, approval)
        with self.assertRaises(ValueError):
            switch.approved({'runtime_only': {'example': 'two'}}, approval)

    def test_valid_approval_does_not_bypass_host_guard(self):
        approval = {'approved': True, 'plan_sha256': switch.plan_hash({}),
                    'approved_by': 'operator', 'approved_at': '2026-11-16T00:00:00Z'}
        with patch('switch.socket.gethostname', return_value='wrong-host'), patch('switch.switch') as apply:
            with self.assertRaises(RuntimeError):
                switch.execute({}, {}, approval, 'assigned-host')
            apply.assert_not_called()

    def test_runtime_changes_preserve_every_other_release_byte(self):
        before = {name: ('old ' + name).encode() for name in switch.MODULES}
        before['static/index.html'] = b'original frontend'
        before['static/asset.svg'] = b'<svg/>'
        runtime = {name: ('new ' + name).encode() for name in switch.MODULES}
        plan = {'runtime_only': {n: switch.identity(v) for n, v in runtime.items()},
                'expected_previous_runtime5': {n: switch.identity(before[n]) for n in switch.MODULES}}
        result = switch.candidate(plan, before, runtime)
        self.assertEqual(set(before), set(result))
        self.assertEqual(runtime, {n: result[n] for n in switch.MODULES})
        self.assertEqual(before['static/index.html'], result['static/index.html'])
        self.assertEqual(before['static/asset.svg'], result['static/asset.svg'])
        with self.assertRaises(ValueError):
            switch.candidate(plan, before, dict(runtime, unexpected=b'bad'))
        with self.assertRaises(ValueError):
            switch.candidate(plan, dict(before, **{'worker.py': b'changed live worker'}), runtime)
        with self.assertRaises(ValueError):
            switch.candidate(plan, before, dict(runtime, **{'store.py': b'changed candidate'}))

    def test_source_packet_is_complete_and_hash_bound(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in switch.MODULES:
                (root / name).write_bytes(b'x=1\n')
            plan = {'runtime_only': {n: switch.identity(b'x=1\n') for n in switch.MODULES}}
            self.assertEqual(set(switch.sources(plan, root)), set(switch.MODULES))
            (root / 'worker.py').write_bytes(b'x=2\n')
            with self.assertRaises(ValueError):
                switch.sources(plan, root)
            plan['runtime_only']['extra.py'] = switch.identity(b'')
            with self.assertRaises(ValueError):
                switch.sources(plan, root)

    def test_release_links_and_large_assets_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'normal.py').write_bytes(b'x=1')
            self.assertEqual({'normal.py': b'x=1'}, switch.release_files(root))
            (root / 'linked').symlink_to(root / 'normal.py')
            with self.assertRaises(ValueError):
                switch.release_files(root)
            (root / 'linked').unlink()
            (root / 'large').write_bytes(b'\0' * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                switch.release_files(root)

    def test_sqlite_backup_keeps_committed_wal_rows_and_original_untouched(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); path = root / 'jobs.sqlite3'; target = root / 'backup.sqlite3'
            db = sqlite3.connect(path)
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE jobs(id TEXT,state TEXT)')
            db.execute('INSERT INTO jobs VALUES(?,?)', ('synthetic', 'ready')); db.commit()
            self.assertTrue(path.with_name('jobs.sqlite3-wal').exists())
            self.assertEqual({'ready': 1}, switch.queue_counts(path))
            switch.backup(path, target)
            with closing(sqlite3.connect(target)) as saved:
                self.assertEqual([('synthetic', 'ready')], saved.execute('SELECT * FROM jobs').fetchall())
            self.assertEqual([('synthetic', 'ready')], db.execute('SELECT * FROM jobs').fetchall())
            self.assertEqual(0o600, target.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                switch.backup(path, target)
            db.close()

    def test_foreign_unit_controls_are_rejected_before_subprocess(self):
        with patch('switch.subprocess.run') as run:
            for action, unit in [('stop', 'other.service'), ('kill', switch.WORKER)]:
                with self.assertRaises(ValueError):
                    switch.run_unit(action, unit)
            run.assert_not_called()

    def transaction(self, fault=None):
        """Entire switch on small real files/SQLite; service commands are fakes."""
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        app = root / 'app'; old = app / 'releases' / 'previous'; old.mkdir(parents=True)
        state = root / 'state'; state.mkdir()
        previous = {n: b'old=1\n' for n in switch.MODULES}
        previous['static/index.html'] = b'original static frontend'
        for name, raw in previous.items():
            path = old / name; path.parent.mkdir(exist_ok=True); path.write_bytes(raw)
        (app / 'current').symlink_to(old)
        database = state / 'jobs.sqlite3'
        (state / 'heartbeat.json').write_text(json.dumps({'time': time.time(), 'pid': 102}))
        with closing(sqlite3.connect(database)) as db:
            db.execute('''CREATE TABLE jobs(id TEXT PRIMARY KEY,key TEXT NOT NULL,
                fingerprint TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,
                state TEXT NOT NULL,bytes INTEGER,sha256 TEXT,error TEXT)''')
        runtime = {n: b'new=1\n' for n in switch.MODULES}
        plan = {'expected_previous_release': str(old),
                'expected_previous_runtime5': {n: switch.identity(previous[n]) for n in switch.MODULES},
                'runtime_only': {n: switch.identity(v) for n, v in runtime.items()}}
        commands = []
        self.transaction_commands = commands

        def unit(action, name):
            commands.append((action, name))
            if action == 'start' and name == switch.WEB and fault in ('restore', 'drain-restore'):
                raise RuntimeError('synthetic prior web restart failure')
            if action == 'start' and name == switch.WORKER:
                if fault == 'new-worker':
                    raise RuntimeError('synthetic new worker failure')
                (state / 'heartbeat.json').write_text(json.dumps({'time': time.time(), 'pid': 102}))
            if action == 'start' and name == switch.WEB and fault != 'drain':
                Store(database).close()

        def wait(check, seconds, message):
            if fault in ('drain', 'drain-restore') and seconds == 120:
                raise RuntimeError('synthetic admitted job still running')
            if not check():
                raise RuntimeError(message)

        info = lambda name: {'ActiveState': 'active', 'MainPID': '102' if name == switch.WORKER else '101',
                             'User': 'debrescuestick', 'WorkingDirectory': str(app / 'current')}
        with patch('switch.run_unit', side_effect=unit), patch('switch.unit_info', side_effect=info), \
                patch('switch.wait_for', side_effect=wait), \
                patch('switch.urllib.request.urlopen', side_effect=lambda *a, **k: io.BytesIO(b'{"available":true}')):
            result = switch.switch(plan, runtime, application=app, state=state, operations=root / 'ops')
        return result, commands, app, old, previous, runtime, database

    def test_transaction_reaches_ready_and_keeps_assets_queue_and_previous_release(self):
        result, commands, app, old, previous, runtime, database = self.transaction()
        self.assertTrue(result['success'])
        self.assertEqual('ready', result['phase'])
        self.assertFalse(result['admission_closed'])
        self.assertEqual(switch.WEB, commands[0][1])
        self.assertEqual([('stop', switch.WEB), ('stop', switch.WORKER),
                          ('start', switch.WORKER), ('start', switch.WEB)], commands)
        self.assertEqual(previous, switch.release_files(old))
        after = switch.release_files((app / 'current').resolve())
        self.assertEqual(runtime, {n: after[n] for n in switch.MODULES})
        self.assertEqual(previous['static/index.html'], after['static/index.html'])
        saved = Path(result['proof_path']).parent / 'jobs.sqlite3'
        self.assertTrue(saved.exists())
        self.assertEqual({}, switch.queue_counts(saved))
        self.assertEqual({}, switch.queue_counts(database))

    def test_pre_switch_drain_failure_resumes_previous_web_without_replacing_source(self):
        result, commands, app, old, previous, runtime, database = self.transaction('drain')
        self.assertFalse(result['success'])
        self.assertEqual('previous-runtime-restored', result['phase'])
        self.assertEqual(old, (app / 'current').resolve())
        self.assertEqual([('stop', switch.WEB), ('start', switch.WEB)], commands)
        self.assertEqual(previous, switch.release_files(old))

    def test_failed_previous_runtime_restart_records_closed_admission(self):
        result, commands, app, old, previous, runtime, database = self.transaction('drain-restore')
        self.assertFalse(result['success'])
        self.assertEqual('previous-runtime-recovery-incomplete', result['phase'])
        self.assertTrue(result['admission_closed'])
        self.assertEqual(old, (app / 'current').resolve())
        self.assertEqual(('stop', switch.WEB), commands[-1])

    def test_existing_download_refuses_switch_before_service_stop(self):
        with patch('switch.queue_counts', return_value={'ready': 1}):
            with self.assertRaises(RuntimeError) as caught:
                self.transaction()
        self.assertEqual('Wait for existing jobs to finish and expire before switching', str(caught.exception))
        self.assertEqual([], self.transaction_commands)

    def test_post_switch_failure_keeps_admission_closed_and_never_downgrades_worker(self):
        result, commands, app, old, previous, runtime, database = self.transaction('new-worker')
        self.assertFalse(result['success'])
        self.assertEqual('held-for-compatible-repair', result['phase'])
        self.assertTrue(result['admission_closed'])
        self.assertNotEqual(old, (app / 'current').resolve())
        self.assertNotIn(('start', switch.WEB), commands)
        self.assertEqual(('stop', switch.WEB), commands[-1])
        self.assertEqual(previous, switch.release_files(old))

