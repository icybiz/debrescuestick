"""Transactional bounded job queue with expiring, unguessable download links."""
import hashlib
import secrets
import sqlite3
import time


class Busy(ValueError):pass
class Missing(ValueError):pass
class Conflict(ValueError):pass
class Unavailable(ValueError):pass


class Gone(Missing):
    def __init__(self,record):
        super().__init__('The download has expired.')
        self.record=record


PUBLIC_FIELDS=('id','fingerprint','created','expires','state','bytes','sha256','error')
REPLAY_TTL=24*60*60


def request_digest(value):
    if not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
        raise ValueError('Expected a secret request key of64 lowercase hexadecimal characters.')
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def record(row,private=False):
    result={field:row[field] for field in PUBLIC_FIELDS}
    if private:result['key']=row['key']
    return result


class Store:
    def __init__(self,path,clock=time.time,ttl=2*60*60,max_jobs=3):
        self.clock=clock;self.ttl=ttl;self.max_jobs=max_jobs
        self.db=sqlite3.connect(path,timeout=10,isolation_level=None)
        self.db.row_factory=sqlite3.Row
        self.db.executescript('''PRAGMA journal_mode=WAL;
          CREATE TABLE IF NOT EXISTS jobs(
            id TEXT PRIMARY KEY,key TEXT NOT NULL,fingerprint TEXT NOT NULL,
            created INTEGER NOT NULL,expires INTEGER NOT NULL,state TEXT NOT NULL,
            bytes INTEGER,sha256 TEXT,error TEXT);
          CREATE TABLE IF NOT EXISTS limits(client TEXT PRIMARY KEY,until INTEGER NOT NULL);
        ''')
        # Serialize the additive migration across independently opened HTTP stores.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            columns={row['name'] for row in self.db.execute('PRAGMA table_info(jobs)')}
            for name,kind in (('request_hash','TEXT'),('replay_until','INTEGER')):
                if name not in columns:self.db.execute('ALTER TABLE jobs ADD COLUMN '+name+' '+kind)
            self.db.execute('CREATE UNIQUE INDEX IF NOT EXISTS jobs_request_hash ON jobs(request_hash)')
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');self.db.close();raise

    def close(self):self.db.close()

    def replay(self,row,now):
        if row['replay_until']<=now:raise Missing('Die Wiederherstellungsfrist ist abgelaufen.')
        result=record(row)
        if row['expires']<=now:
            result['state']='expired'
            raise Gone(result)
        return result

    def lookup(self,request_key):
        digest=request_digest(request_key)
        row=self.db.execute('SELECT * FROM jobs WHERE request_hash=?',(digest,)).fetchone()
        if not row:raise Missing('Auftrag nicht gefunden.')
        return self.replay(row,int(self.clock()))

    def create(self,key,fingerprint,client,*,request_key=None,available=True):
        digest=request_digest(request_key) if request_key is not None else None
        self.db.execute('BEGIN IMMEDIATE')
        try:
            now=int(self.clock())
            if digest is not None:
                existing=self.db.execute('SELECT * FROM jobs WHERE request_hash=?',(digest,)).fetchone()
                if existing:
                    if existing['fingerprint']!=fingerprint:
                        raise Conflict('The request key is already bound to different input.')
                    result=self.replay(existing,now)
                    self.db.execute('COMMIT')
                    return result
            # Recovery never depends on a live worker or consumes new-job limits.
            if not available:
                raise Unavailable('Image preparation is currently unavailable. Please try again later.')
            row=self.db.execute('SELECT until FROM limits WHERE client=?',(client,)).fetchone()
            if row and row['until']>now:raise Busy('Bitte vor einer weiteren Anfrage kurz warten.')
            count=self.db.execute("SELECT COUNT(*) FROM jobs WHERE expires>? AND state NOT IN ('failed','expired')",(now,)).fetchone()[0]
            if count>=self.max_jobs:raise Busy('Die Warteschlange ist gerade voll. Bitte später erneut versuchen.')
            token=secrets.token_hex(24)
            self.db.execute('INSERT INTO jobs(id,key,fingerprint,created,expires,state,request_hash,replay_until) VALUES(?,?,?,?,?,?,?,?)',
                            (token,key,fingerprint,now,now+self.ttl,'queued',digest,now+REPLAY_TTL if digest else None))
            self.db.execute('INSERT OR REPLACE INTO limits VALUES(?,?)',(client,now+60))
            self.db.execute('DELETE FROM limits WHERE until<=?',(now,));self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
        return self.get(token)

    def get(self,token,private=False):
        if not isinstance(token,str) or len(token)!=48 or any(c not in '0123456789abcdef' for c in token):raise Missing('Auftrag nicht gefunden.')
        row=self.db.execute('SELECT * FROM jobs WHERE id=?',(token,)).fetchone()
        if not row:raise Missing('Auftrag nicht gefunden oder bereits gelöscht.')
        if row['expires']<=int(self.clock()):raise Missing('Der Download ist abgelaufen.')
        return record(row,private)

    def claim(self):
        now=int(self.clock());self.db.execute('BEGIN IMMEDIATE')
        try:
            active=self.db.execute("SELECT id FROM jobs WHERE state IN ('personalizing','compressing') LIMIT 1").fetchone()
            if active:self.db.execute('COMMIT');return None
            row=self.db.execute("SELECT id FROM jobs WHERE state='queued' AND expires>? ORDER BY created,rowid LIMIT 1",(now,)).fetchone()
            if row:self.db.execute("UPDATE jobs SET state='personalizing' WHERE id=?",(row['id'],))
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise
        return self.get(row['id'],private=True) if row else None

    def progress(self,token):
        self.get(token)
        changed=self.db.execute("UPDATE jobs SET state='compressing' WHERE id=? AND state='personalizing'",(token,)).rowcount
        if changed!=1:raise ValueError('Invalid job progress transition')

    def finish(self,token,size,sha256):
        self.get(token)
        if size<=0 or len(sha256)!=64 or any(c not in '0123456789abcdef' for c in sha256):raise ValueError('Complete artifact identity required')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            changed=self.db.execute("UPDATE jobs SET state='ready',bytes=?,sha256=?,key='' WHERE id=? AND state='compressing' AND expires>?",
                (size,sha256,token,int(self.clock()))).rowcount
            if changed!=1:raise ValueError('Expired or invalid completion refused')
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise

    def fail(self,token):
        self.db.execute("UPDATE jobs SET state='failed',error=?,key='' WHERE id=? AND state IN ('personalizing','compressing')",
                        ('Das Image konnte nicht erstellt werden. Bitte später erneut versuchen.',token))

    def expired(self):
        now=int(self.clock())
        # A live worker owns its files until it exits; never delete below it.
        rows=self.db.execute("SELECT id FROM jobs WHERE expires<=? AND state NOT IN ('personalizing','compressing','expired')",(now,)).fetchall()
        return [r['id'] for r in rows]

    def forget(self,token):
        now=int(self.clock())
        # Called only after owned-file cleanup; retain bounded retry identity.
        self.db.execute("UPDATE jobs SET state='expired',key='' WHERE id=? AND expires<=? AND replay_until>? AND state NOT IN ('personalizing','compressing')",(token,now,now))
        self.db.execute("DELETE FROM jobs WHERE id=? AND expires<=? AND (replay_until IS NULL OR replay_until<=?) AND state NOT IN ('personalizing','compressing')",(token,now,now))

    def purge(self):
        self.db.execute("DELETE FROM jobs WHERE state='expired' AND replay_until<=?",(int(self.clock()),))
