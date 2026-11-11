"""Small queue/HTTP fixtures for durable retry binding; no images or appliances."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import sqlite3
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from pathlib import Path

from keys import public_key
import store as jobs
from store import Store, Busy, Missing
from support import workspace
from test_keys import sample
from test_server import serving
import worker
import replay


REQUEST = 'a' * 64
FIELDS = {'id', 'fingerprint', 'created', 'expires', 'state', 'bytes', 'sha256', 'error'}


class ReplayTests(unittest.TestCase):
    def test_parallel_first_acceptance_binds_one_job_and_one_limit(self):
        with workspace() as root:
            # The real listener initializes its database before accepting requests.
            initialized = Store(root/'jobs.db');initialized.close()
            barrier = threading.Barrier(4)
            def start(client):
                store = Store(root/'jobs.db', clock=lambda:1000, max_jobs=1)
                try:
                    barrier.wait(timeout=10)
                    return store.create(*public_key(sample()), client, request_key=REQUEST)
                finally:store.close()
            with ThreadPoolExecutor(max_workers=4) as pool:
                records = list(pool.map(start, ['a', 'b', 'c', 'd']))
            self.assertTrue(all(record == records[0] for record in records))
            store = Store(root/'jobs.db', clock=lambda:1000)
            try:
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM limits').fetchone()[0], 1)
                self.assertEqual(set(records[0]), FIELDS)
                row = dict(store.db.execute('SELECT * FROM jobs').fetchone())
                self.assertEqual(row['request_hash'], hashlib.sha256(REQUEST.encode()).hexdigest())
                self.assertNotIn(REQUEST, row.values())
            finally:store.close()

    def test_lost_reply_and_restart_lookup_keep_identity_deadlines_and_result(self):
        with workspace() as root:
            now = [1000]
            store = Store(root/'jobs.db', clock=lambda:now[0])
            try:
                # Acceptance commits, but the caller loses its response and its process.
                store.create(*public_key(sample()), 'client', request_key=REQUEST)
            finally:store.close()
            store = Store(root/'jobs.db', clock=lambda:now[0])
            try:
                recovered = store.lookup(REQUEST)
                same = store.create(*public_key(sample()+' changed comment'), 'other', request_key=REQUEST)
                self.assertEqual(same, recovered)
                claimed = store.claim(); self.assertEqual(claimed['id'], recovered['id'])
                self.assertIsNone(store.claim())
                store.progress(claimed['id']); store.finish(claimed['id'], 7, 'b'*64)
                now[0] += 30
                result = store.create(*public_key(sample()), 'client', request_key=REQUEST, available=False)
                self.assertEqual(result['state'], 'ready')
                self.assertEqual((result['id'], result['created'], result['expires']),
                                 (recovered['id'], 1000, 8200))
                self.assertEqual((result['bytes'], result['sha256']), (7, 'b'*64))
                self.assertEqual(set(result), FIELDS)
            finally:store.close()

    def test_mismatch_has_no_mutation_and_replay_ignores_new_job_limits(self):
        with workspace() as root:
            now = [1000]; store = Store(root/'jobs.db', clock=lambda:now[0], max_jobs=1)
            try:
                first = store.create(*public_key(sample()), 'original', request_key=REQUEST)
                with self.assertRaises(jobs.Conflict):
                    store.create(*public_key(sample(1)), 'other', request_key=REQUEST)
                with self.assertRaises(Busy):store.create(*public_key(sample()), 'other', request_key='b'*64)
                self.assertEqual(store.create(*public_key(sample()), 'other', request_key=REQUEST), first)
                self.assertIsNone(store.db.execute("SELECT * FROM limits WHERE client='other'").fetchone())
                now[0] += 61
                self.assertEqual(store.create(*public_key(sample()), 'original', request_key=REQUEST), first)
                self.assertEqual(store.db.execute('SELECT until FROM limits').fetchone()[0], 1060)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)
            finally:store.close()

    def test_failed_job_stays_failed_after_restart_and_does_not_take_capacity(self):
        with workspace() as root:
            store = Store(root/'jobs.db', clock=lambda:1000, max_jobs=1)
            first = store.create(*public_key(sample()), 'original', request_key=REQUEST)
            store.claim(); store.fail(first['id']); store.close()
            store = Store(root/'jobs.db', clock=lambda:1000, max_jobs=1)
            try:
                failed = store.create(*public_key(sample()), 'another', request_key=REQUEST)
                self.assertEqual((failed['id'], failed['state']), (first['id'], 'failed'))
                self.assertIsNone(store.claim())
                next_job = store.create(*public_key(sample(1)), 'another', request_key='b'*64)
                self.assertEqual(store.claim()['id'], next_job['id'])
            finally:store.close()

    def test_expiry_retains_binding_cleans_files_once_then_purges_metadata(self):
        with workspace() as root:
            now = [1000]; store = Store(root/'jobs.db', clock=lambda:now[0], ttl=10)
            try:
                first = store.create(*public_key(sample()), 'original', request_key=REQUEST)
                path = worker.folder(root, first['id']); path.mkdir(parents=True)
                (path/'.owner').write_text(json.dumps({'job':first['id'], 'schema':'drs-job-v1'}))
                (path/'public.key').write_text(public_key(sample())[0])
                now[0] = 1010
                for operation in (lambda:store.lookup(REQUEST),
                                  lambda:store.create(*public_key(sample()), 'client', request_key=REQUEST)):
                    with self.assertRaises(jobs.Gone) as caught:operation()
                    self.assertEqual(caught.exception.record['id'], first['id'])
                    self.assertEqual(caught.exception.record['state'], 'expired')
                    self.assertEqual(set(caught.exception.record), FIELDS)
                with patch.object(worker, 'cleanup', wraps=worker.cleanup) as cleanup:
                    worker.reap(store, root); worker.reap(store, root)
                    self.assertEqual(cleanup.call_count, 1)
                self.assertFalse(path.exists()); self.assertEqual(store.expired(), [])
                row = store.db.execute('SELECT * FROM jobs').fetchone()
                self.assertEqual(row['key'], ''); self.assertEqual(row['state'], 'expired')
                self.assertEqual(row['replay_until'], 87400)
                with self.assertRaises(Missing):store.get(first['id'])
                now[0] = 87399
                with self.assertRaises(jobs.Gone):store.lookup(REQUEST)
                worker.reap(store, root)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)
                now[0] = 87400
                with self.assertRaises(Missing):store.lookup(REQUEST)
                worker.reap(store, root)
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 0)
            finally:store.close()

    def test_expired_active_files_wait_for_worker_and_failure_keeps_binding(self):
        with workspace() as root:
            now = [1000]; store = Store(root/'jobs.db', clock=lambda:now[0], ttl=10)
            try:
                first = store.create(*public_key(sample()), 'client', request_key=REQUEST)
                store.claim()
                path = worker.folder(root, first['id']); path.mkdir(parents=True)
                (path/'.owner').write_text(json.dumps({'job':first['id'], 'schema':'drs-job-v1'}))
                now[0] = 1011; worker.reap(store, root)
                self.assertTrue(path.exists()); self.assertEqual(store.expired(), [])
                with self.assertRaises(jobs.Gone):store.lookup(REQUEST)
                self.assertEqual(store.db.execute('SELECT state FROM jobs').fetchone()[0], 'personalizing')
                store.fail(first['id']); worker.reap(store, root)
                self.assertFalse(path.exists())
                with self.assertRaises(jobs.Gone):store.lookup(REQUEST)
            finally:store.close()

    def test_request_key_validation_and_legacy_jobs_remain_independent(self):
        with workspace() as root:
            store = Store(root/'jobs.db', clock=lambda:1000)
            try:
                for bad in ('', 'a'*63, 'a'*65, 'A'*64, '../'+('a'*61), 42, ['a'*64]):
                    with self.subTest(bad=type(bad).__name__):
                        with self.assertRaises(ValueError):
                            store.create(*public_key(sample()), 'client', request_key=bad)
                with self.assertRaises(Missing):store.lookup(REQUEST)
                first = store.create(*public_key(sample()), 'a')
                second = store.create(*public_key(sample()), 'b')
                self.assertNotEqual(first['id'], second['id'])
                self.assertEqual(set(store.get(first['id'])), FIELDS)
            finally:store.close()

    def test_existing_database_migrates_without_losing_queue_or_key(self):
        with workspace() as root:
            db = sqlite3.connect(root/'jobs.db')
            db.executescript('''CREATE TABLE jobs(id TEXT PRIMARY KEY,key TEXT NOT NULL,
              fingerprint TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER NOT NULL,
              state TEXT NOT NULL,bytes INTEGER,sha256 TEXT,error TEXT);
              CREATE TABLE limits(client TEXT PRIMARY KEY,until INTEGER NOT NULL);''')
            key, fingerprint = public_key(sample())
            db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?)',
                       ('c'*48, key, fingerprint, 1000, 8200, 'queued', None, None, None))
            db.commit(); db.close()
            for iteration in range(2):
                store = Store(root/'jobs.db', clock=lambda:1000)
                try:
                    self.assertEqual(store.get('c'*48, private=True)['key'], key)
                    if iteration == 0:
                        bound = store.create(key, fingerprint, 'new', request_key=REQUEST)
                    else:self.assertEqual(store.lookup(REQUEST)['id'], bound['id'])
                finally:store.close()


class ReplayHTTPTests(unittest.TestCase):
    def request(self, url, data=None):
        request = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                         headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:return reply.status, json.load(reply)
        except urllib.error.HTTPError as error:
            with error:return error.code, json.load(error)

    def test_lost_start_reply_can_be_recovered_without_creating_another_job(self):
        with workspace() as root, serving(root) as (app, url):
            with patch.object(app, 'available', return_value=True):
                address = url+'/debrescuestick/api/jobs'
                status, first = self.request(address, {'public_key':sample(), 'request_key':REQUEST})
                self.assertEqual(status, 202)
                # The caller did not retain first; it still has its original request key.
                status, retry = self.request(address, {'public_key':sample(), 'request_key':REQUEST})
                self.assertEqual(status, 202)
                self.assertEqual(retry, first)
                self.assertEqual(self.request(url+'/debrescuestick/api/requests/'+REQUEST), (200, first))
                self.assertEqual(self.request(address, {'public_key':sample(), 'request_key':'b'*64})[0], 429)
                with app.store() as store:
                    self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)

    def test_retry_and_lookup_work_without_worker_conflict_and_new_start_do_not(self):
        with workspace() as root, serving(root) as (app, url):
            with app.store() as store:
                first = store.create(*public_key(sample()), 'initial', request_key=REQUEST)
            start = url+'/debrescuestick/api/jobs'
            status, result = self.request(start, {'public_key':sample()+' new comment', 'request_key':REQUEST})
            self.assertEqual((status, result), (202, first))
            self.assertEqual(self.request(url+'/debrescuestick/api/requests/'+REQUEST), (200, first))
            self.assertEqual(self.request(start, {'public_key':sample(1), 'request_key':REQUEST})[0], 409)
            self.assertEqual(self.request(start, {'public_key':sample(), 'request_key':'b'*64})[0], 503)
            self.assertEqual(self.request(url+'/debrescuestick/api/requests/'+'b'*64)[0], 404)
            for bad in (None, '', 'A'*64, 123):
                self.assertEqual(self.request(start, {'public_key':sample(), 'request_key':bad})[0], 400)
            self.assertEqual(self.request(url+'/debrescuestick/api/requests/not-a-key')[0], 400)
            with app.store() as store:
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)

    def test_known_expiry_returns_original_identity_but_no_download(self):
        with workspace() as root, serving(root) as (app, url):
            with app.store() as store:
                first = store.create(*public_key(sample()), 'initial', request_key=REQUEST)
                store.db.execute('UPDATE jobs SET expires=0 WHERE id=?', (first['id'],))
                worker.reap(store, root)
            for address, data in ((url+'/debrescuestick/api/requests/'+REQUEST, None),
                                  (url+'/debrescuestick/api/jobs', {'public_key':sample(), 'request_key':REQUEST})):
                status, result = self.request(address, data)
                self.assertEqual(status, 410)
                self.assertEqual(result['job']['id'], first['id'])
                self.assertEqual(result['job']['state'], 'expired')
                self.assertEqual(set(result['job']), FIELDS)
                self.assertIn('error', result)
            self.assertEqual(self.request(url+'/debrescuestick/api/jobs/'+first['id'])[0], 404)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(url+'/debrescuestick/download/'+first['id'])
            self.assertEqual(caught.exception.code, 404)


class ReplayNativeTests(unittest.TestCase):
    def test_native_probe_refuses_local_host_before_reading_any_files(self):
        with patch('worker.socket.gethostname', return_value='aicoder2'), patch.object(Path, 'open') as opening:
            with self.assertRaises(RuntimeError):replay.qualify('/no/real/state')
        opening.assert_not_called()

    def test_native_probe_contract_with_small_synthetic_worker_output(self):
        with workspace() as root:
            base = root/'base';(base/'fast').mkdir(parents=True)
            (base/'template.json').write_text(json.dumps({'fast':{}}))
            prefix = b'fixed system prefix';tail = b'personal partition and ZIP end'
            (base/'fast/prefix.zip').write_bytes(prefix)
            (root/'key-a.pub').write_text(sample());(root/'key-b.pub').write_text(sample(1))
            def prepare(state, job):
                output = worker.folder(state, job['id']);output.mkdir(parents=True)
                (output/'.owner').write_text(json.dumps({'job':job['id'], 'schema':'drs-job-v1'}))
                (output/'image.tail').write_bytes(tail)
                (output/'archive.json').write_text(json.dumps({'base_sha256':'b'*64,
                    'bytes':len(prefix)+len(tail), 'prefix_bytes':len(prefix),
                    'sha256':hashlib.sha256(prefix+tail).hexdigest()}))
                return output
            original = worker.process
            with patch.object(worker, 'require_host'), patch.object(worker, 'process',
                    side_effect=lambda store, state, job:original(store, state, job, prepare=prepare)):
                result = replay.qualify(root)
            self.assertTrue(result['success']);self.assertTrue(result['bounded_metadata'])
            self.assertTrue(result['own_files_reaped']);self.assertFalse(result['boot_tested'])
            self.assertEqual(result['zip_bytes'], len(prefix)+len(tail))
