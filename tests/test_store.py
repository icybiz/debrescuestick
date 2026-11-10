import hashlib
import unittest
from store import Store,Busy,Missing
from support import workspace
from test_keys import sample
from keys import public_key


class StoreTests(unittest.TestCase):
    def test_distinct_keys_ids_fifo_single_worker_and_capacity(self):
        with workspace() as folder:
            store=Store(folder/'queue.db',clock=lambda:1000,max_jobs=2)
            try:
                a=store.create(*public_key(sample()),'client-a')
                with self.assertRaises(Busy):store.create(*public_key(sample()),'client-a')
                b=store.create(*public_key(sample(1)),'client-b')
                self.assertNotEqual(a['id'],b['id']);self.assertNotIn('key',a)
                with self.assertRaises(Busy):store.create(*public_key(sample(2)),'client-c')
                claimed=store.claim();self.assertEqual(claimed['id'],a['id'])
                self.assertEqual(claimed['key'],public_key(sample())[0]);self.assertIsNone(store.claim())
                store.progress(a['id']);store.finish(a['id'],123,hashlib.sha256(b'image').hexdigest())
                self.assertEqual(store.get(a['id'],True)['key'],'')
                self.assertEqual(store.claim()['id'],b['id'])
            finally:store.close()

    def test_expired_jobs_cannot_finish_or_download_and_active_files_are_preserved(self):
        with workspace() as folder:
            now=[1000];store=Store(folder/'queue.db',clock=lambda:now[0],ttl=10)
            try:
                a=store.create(*public_key(sample()),'a');b=store.create(*public_key(sample(1)),'b')
                store.claim();store.progress(a['id']);now[0]=1011
                for token in (a['id'],b['id'],'../escape'):
                    with self.assertRaises(Missing):store.get(token)
                with self.assertRaises(Missing):store.finish(a['id'],1,'a'*64)
                self.assertEqual(store.expired(),[b['id']]);store.forget(a['id'])
                self.assertIsNotNone(store.db.execute('SELECT id FROM jobs WHERE id=?',(a['id'],)).fetchone())
                store.fail(a['id']);self.assertEqual(set(store.expired()),{a['id'],b['id']})
                store.forget(a['id']);store.forget(b['id'])
                self.assertEqual(store.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],0)
            finally:store.close()


if __name__=='__main__':unittest.main()
