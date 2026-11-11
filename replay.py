"""Final queue/retry acceptance with one real fast-worker result, never a VM."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time
import urllib.error
import urllib.request

from keys import public_key
import server
from store import Store, REPLAY_TTL
import worker


def qualify(state):
    worker.require_host()
    state = Path(state)
    proof = json.loads((state/'base/template.json').read_text())
    if 'fast' not in proof:raise ValueError('Existing fast template required; no raw-copy fallback')
    key, fingerprint = public_key((state/'key-a.pub').read_text())
    other, unused = public_key((state/'key-b.pub').read_text())
    request_key = secrets.token_hex(32)
    now = [int(time.time())]
    database = state/'jobs.sqlite3'
    # The virtual clock exercises hour/day boundaries without holding resources.
    def connect():return Store(database, clock=lambda:now[0])
    store = connect();store.close()
    barrier = threading.Barrier(4)
    def start(client):
        store = connect()
        try:
            barrier.wait(timeout=10)
            return store.create(key, fingerprint, client, request_key=request_key)
        finally:store.close()
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(start, ('a', 'b', 'c', 'd')))
    first = records[0]
    if not all(record == first for record in records):raise ValueError('Parallel retry identity changed')
    # All accepting connections are closed: recovery uses a new connection.
    store = connect()
    class ProbeApp(server.App):
        @contextmanager
        def store(self):
            connection = connect()
            try:yield connection
            finally:connection.close()
    listener = server.HTTPServer(('127.0.0.1', 0), server.Handler)
    listener.app = ProbeApp(state)
    thread = threading.Thread(target=listener.serve_forever, daemon=True);thread.start()
    url = 'http://127.0.0.1:'+str(listener.server_address[1])+server.PREFIX
    def call(path, data=None):
        request = urllib.request.Request(url+path, data=json.dumps(data).encode() if data is not None else None,
                                         headers={'Content-Type':'application/json'})
        try:reply = urllib.request.urlopen(request, timeout=15)
        except urllib.error.HTTPError as error:reply = error
        with reply:return reply.status, json.load(reply)
    def require(condition, message):
        if not condition:raise ValueError(message)
    try:
        require(store.lookup(request_key) == first, 'Restart recovery changed identity')
        require(call('/api/jobs', {'public_key':key, 'request_key':request_key}) == (202, first),
                'Retry while worker unavailable failed')
        require(call('/api/jobs', {'public_key':other, 'request_key':request_key})[0] == 409,
                'Different input was not rejected')
        require(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0] == 1, 'Duplicate job row')
        require(store.db.execute('SELECT COUNT(*) FROM limits').fetchone()[0] == 1, 'Duplicate client limit')
        require(worker.process(store, state, store.claim()), 'Real worker did not complete')
        ready = store.get(first['id'])
        require(ready['state'] == 'ready', 'Result not ready')
        require(call('/api/requests/'+request_key) == (200, ready), 'Ready recovery changed result')
        require(call('/api/jobs', {'public_key':key, 'request_key':request_key}) == (202, ready),
                'Ready retry changed result')
        output = worker.folder(state, first['id'])
        meta = json.loads((output/'archive.json').read_text())
        # Use the real public reader layout, retaining the qualified shared prefix.
        shared = state/'archives'/meta['base_sha256'];shared.mkdir(parents=True)
        prefix = shared/'prefix.zip';prefix.hardlink_to(state/'base/fast/prefix.zip')
        identity = prefix.stat()
        digest = hashlib.sha256();length = 0
        with server.archive(state, ready) as stream:
            while block := stream.read(1024*1024):digest.update(block);length += len(block)
            boundary = meta['prefix_bytes']-8;stream.seek(boundary);expected = stream.read(16)
        require((length, digest.hexdigest()) == (ready['bytes'], ready['sha256']), 'Real ZIP identity mismatch')
        download = url+'/download/'+first['id']
        request = urllib.request.Request(download, headers={'Range':f'bytes={boundary}-{boundary+15}'})
        with urllib.request.urlopen(request, timeout=15) as reply:
            require(reply.status == 206 and reply.read() == expected, 'Cross-part HTTP range changed bytes')
            require(reply.headers['ETag'] == '"'+ready['sha256']+'"', 'ZIP ETag changed')
        now[0] = first['expires']
        for path, data in (('/api/requests/'+request_key, None),
                           ('/api/jobs', {'public_key':key, 'request_key':request_key})):
            status, value = call(path, data)
            require(status == 410 and value['job']['id'] == first['id'] and value['job']['state'] == 'expired',
                    'Expired retry recreated or lost original identity')
        worker.reap(store, state);worker.reap(store, state)
        require(not output.exists() and store.expired() == [], 'Expired files not reaped exactly once')
        require(prefix.stat().st_ino == identity.st_ino and prefix.stat().st_size == identity.st_size,
                'Shared prefix changed during cleanup')
        # A distinct intentional attempt remains possible; its failure stays bound.
        failed_key = secrets.token_hex(32)
        failed = store.create(key, fingerprint, 'intentional-new', request_key=failed_key)
        require(store.claim()['id'] == failed['id'], 'Queue did not advance')
        store.fail(failed['id'])
        status, value = call('/api/jobs', {'public_key':key, 'request_key':failed_key})
        require(status == 202 and value['id'] == failed['id'] and value['state'] == 'failed',
                'Failed retry silently created a new job')
        now[0] = failed['created']+REPLAY_TTL
        worker.reap(store, state)
        require(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0] == 0, 'Replay metadata unbounded')
        require(call('/api/requests/'+request_key)[0] == 404, 'Expired replay window still available')
        return {'success':True, 'parallel_single_job':True, 'restart_recovery':True,
                'input_conflict':True, 'worker_unavailable_recovery':True,
                'real_worker_ready':True, 'zip_bytes':length, 'zip_sha256':digest.hexdigest(),
                'http_range_identity':True, 'expiry_identity':True, 'failed_identity':True,
                'own_files_reaped':True, 'shared_prefix_preserved':True, 'bounded_metadata':True,
                'virtual_clock':True, 'boot_tested':False}
    finally:
        listener.shutdown();listener.server_close();thread.join(5);store.close()
