import sqlite3
import threading
import time
import unittest
from unittest.mock import patch

import canary
from support import workspace


class CanaryTests(unittest.TestCase):
    def test_missing_only_one_cleanup_half_is_not_a_pass(self):
        with workspace() as root:
            state=root/'state';state.mkdir();(state/'jobs').mkdir();identifier='b'*48
            db=sqlite3.connect(state/'jobs.sqlite3');db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY)');db.commit();db.close()
            artifact=state/'jobs'/identifier;artifact.mkdir()
            with self.assertRaises(RuntimeError):canary.wait_removed(state,identifier,timeout=.05,interval=.01)
            artifact.rmdir()
            db=sqlite3.connect(state/'jobs.sqlite3');db.execute('INSERT INTO jobs VALUES(?)',(identifier,));db.commit();db.close()
            with self.assertRaises(RuntimeError):canary.wait_removed(state,identifier,timeout=.05,interval=.01)

    def test_cleanup_observer_waits_for_later_authoritative_row_removal(self):
        with workspace() as root:
            state=root/'state';state.mkdir();(state/'jobs').mkdir()
            identifier='a'*48
            db=sqlite3.connect(state/'jobs.sqlite3')
            db.execute('CREATE TABLE jobs(id TEXT PRIMARY KEY)')
            db.execute('INSERT INTO jobs VALUES(?)',(identifier,));db.commit();db.close()
            # The artifact directory is already removed, while the worker's
            # next SQLite operation has not committed yet.
            def finish():
                time.sleep(.15)
                db=sqlite3.connect(state/'jobs.sqlite3')
                db.execute('DELETE FROM jobs WHERE id=?',(identifier,));db.commit();db.close()
            thread=threading.Thread(target=finish);thread.start()
            try:canary.wait_removed(state,identifier,timeout=2,interval=.02)
            finally:thread.join(3)
            self.assertFalse(thread.is_alive())

    def test_no_local_canary_or_payload_read(self):
        with patch('base.socket.gethostname',return_value='aicoder2'),patch('base.digest') as digest:
            with self.assertRaises(RuntimeError):canary.run('a'*10,'b'*10,'x','y')
        digest.assert_not_called()
