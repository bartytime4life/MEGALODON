"""Versioned offline security reference store, separate from private evidence."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
from threading import Event, RLock, Thread
import time
from uuid import uuid4
import zlib

from .evidence_storage import utc
from .local_install import _owned_directory, _regular_owned_file, _atomic_write
from .knowledge_sources import SOURCES, ATLAS, OWASP, OWASP_FILES, fetch, parse, digest, LICENSE_URLS, license_identity
from .reporting import latest_slot, local_zone

CAP = 512 * 1024**2
GENERATION_CAP = 160 * 1024**2
SCHEMA = 'megalodon-knowledge-v1'


class KnowledgeLibrary:
    def __init__(self, home=None, *, clock=time.time, downloader=fetch):
        self.root = (Path.home() if home is None else Path(home))/'.local/share/megalodon/knowledge'
        _owned_directory(self.root, private=True)
        self.clock, self.downloader = clock, downloader
        self.lock = RLock()
        self.stop = Event()
        self.thread = self.worker = None
        self.token = secrets.token_hex(16)
        self.busy = False
        self.verified = {}
        self.path = self.root/'manifest.json'
        self.state = dict(schema=SCHEMA, active=None, previous=None, enabled=True,
                          last_slot=None, last_check=None, error=None, slot_at=0, digests={})
        if self.path.exists():
            value = json.loads(_regular_owned_file(self.path, maximum=32768))
            if value.get('schema') != SCHEMA or type(value.get('enabled')) is not bool:
                raise ValueError('Knowledge manifest needs review')
            for key in ('active', 'previous'):
                if value.get(key): self._generation(value[key])
            self.state.update(value)
        seed_root=files('megalodon.reference').joinpath('security-v1')
        raw=seed_root.joinpath('starter.json').read_bytes()
        if digest(raw)!=seed_root.joinpath('starter.sha256').read_text().strip():
            raise ValueError('The offline reference pack failed its content check')
        self.seed = json.loads(raw)
        # Unknown leftover generations are never activated. Only files bearing
        # our generated identity inside this private directory can be retired.
        self._cleanup()
        if not self.state['active']:
            name = self._build(self.seed['entries'], self.seed['sources'], {})
            self._activate(name)
        try:
            with self._db() as db:
                if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('Knowledge integrity check failed')
                db.execute('SELECT COUNT(*) FROM documents').fetchone()
                db.execute('SELECT COUNT(*) FROM search').fetchone()
                db.execute('SELECT COUNT(*) FROM workflow_links').fetchone()
        except (OSError, sqlite3.Error, ValueError):
            # Preserve damaged generations for review; use packaged references
            # in memory instead of replacing evidence or trusting damaged text.
            self.state['error'] = 'The installed library needs review; offline starter references remain available.'
            self.fallback = True
        else:
            self.fallback = False

    def _generation(self, name):
        if not isinstance(name, str) or not re.fullmatch(r'[a-f0-9]{32}\.sqlite', name):
            raise ValueError('Invalid library identity')
        return self.root/name

    def _save(self):
        _atomic_write(self.path, (json.dumps(self.state, sort_keys=True)+'\n').encode(), 0o600)

    def _db(self, name=None):
        path = self._generation(name or self.state['active'])
        # Validate ownership, link count and permissions without reading a large file.
        import stat
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > GENERATION_CAP):
            raise ValueError('Unsafe library file')
        expected=self.state.get('digests',{}).get(path.name)
        identity=(info.st_ino,info.st_size,info.st_mtime_ns)
        if expected and self.verified.get(path.name)!=identity:
            with path.open('rb') as handle: actual=hashlib.file_digest(handle,'sha256').hexdigest()
            if actual!=expected:raise ValueError('Library content digest changed')
            self.verified[path.name]=identity
        db = sqlite3.connect(f'{path.as_uri()}?mode=ro&immutable=1', uri=True)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA trusted_schema=OFF')
        return db

    def _used(self):
        return sum(p.lstat().st_size for p in self.root.iterdir())

    def _cleanup(self):
        keep = {self.state.get('active'), self.state.get('previous')}
        for p in self.root.iterdir():
            if re.fullmatch(r'[a-f0-9]{32}\.sqlite(?:-journal)?', p.name) and p.name not in keep:
                if p.is_symlink(): raise ValueError('Unsafe library staging file')
                p.unlink()

    def _build(self, entries, sources, assets):
        if self._used()+GENERATION_CAP > CAP or shutil.disk_usage(self.root).free < GENERATION_CAP+16*1024**2:
            raise ValueError('Not enough reference storage for a recoverable update')
        name = uuid4().hex+'.sqlite'
        path = self._generation(name)
        descriptor = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        try:
            with sqlite3.connect(path) as db:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('PRAGMA temp_store=MEMORY')
                db.execute(f'PRAGMA max_page_count={GENERATION_CAP//4096}')
                db.executescript('''
                CREATE TABLE documents(id TEXT PRIMARY KEY, source TEXT, edition TEXT, identifier TEXT, title TEXT, text TEXT, url TEXT);
                CREATE VIRTUAL TABLE search USING fts5(id UNINDEXED,title,text,tokenize='unicode61');
                CREATE TABLE relationships(origin TEXT, relation TEXT, target TEXT, PRIMARY KEY(origin,relation,target));
                CREATE INDEX relation_target ON relationships(target);
                CREATE TABLE workflow_links(pattern TEXT, document TEXT, workflow TEXT, PRIMARY KEY(pattern,document));
                CREATE INDEX document_workflows ON workflow_links(document);
                CREATE TABLE sources(id TEXT PRIMARY KEY, data TEXT);
                CREATE TABLE assets(url TEXT PRIMARY KEY, etag TEXT, body BLOB);
                ''')
                ids = {r['id'] for r in entries}
                from .security_patterns import REFERENCE_LINKS,CONTEXT
                for row in entries:
                    if self.stop.is_set(): raise ValueError('Update cancelled')
                    db.execute('INSERT INTO documents VALUES(?,?,?,?,?,?,?)', tuple(row[k] for k in ('id','source','edition','identifier','title','text','url')))
                    db.execute('INSERT INTO search VALUES(?,?,?)', (row['id'],row['title'],row['text']))
                    for pattern,links in REFERENCE_LINKS.items():
                        if (row['source'],row['identifier']) in links:
                            db.execute('INSERT INTO workflow_links VALUES(?,?,?)',(pattern,row['id'],CONTEXT[pattern][3]))
                    for relation, target in row.get('links', []):
                        qualified = f"{row['source']}@{row['edition']}:{target}"
                        if qualified in ids:
                            db.execute('INSERT OR IGNORE INTO relationships VALUES(?,?,?)', (row['id'],relation,qualified))
                db.executemany('INSERT INTO sources VALUES(?,?)', [(k,json.dumps(v)) for k,v in sources.items()])
                db.executemany('INSERT INTO assets VALUES(?,?,?)', [(url,tag,zlib.compress(raw)) for url,(tag,raw) in assets.items()])
                db.commit()
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok': raise ValueError('Invalid reference index')
            if self._used() > CAP: raise ValueError('Reference storage limit reached')
            with path.open('rb') as handle: os.fsync(handle.fileno())
            return name
        except BaseException:
            path.unlink(missing_ok=True)
            Path(str(path)+'-journal').unlink(missing_ok=True)
            raise

    def _activate(self, name):
        with self.lock:
            old = deepcopy(self.state)
            self.state.update(previous=self.state['active'], active=name, error=None)
            with self._generation(name).open('rb') as handle:
                content_digest=hashlib.file_digest(handle,'sha256').hexdigest()
            self.state['digests']={k:v for k,v in self.state.get('digests',{}).items() if k==self.state['previous']}
            self.state['digests'][name]=content_digest
            try: self._save()
            except BaseException:
                self.state = old
                raise
            self.fallback = False
            self._cleanup()

    def snapshot(self, include_token=False):
        with self.lock:
            if self.fallback:
                sources = self.seed['sources']
                count = len(self.seed['entries'])
            else:
                with self._db() as db:
                    sources = {r['id']:json.loads(r['data']) for r in db.execute('SELECT * FROM sources')}
                    count = db.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
            result = dict(schema=SCHEMA, state='updating' if self.busy else 'needs_review' if self.state['error'] else 'ready',
                          entries=count, sources=sources, used_bytes=self._used(), cap_bytes=CAP,
                          enabled=self.state['enabled'], update_time='08:00', timezone=str(local_zone()),
                          last_check=self.state['last_check'], error=self.state['error'],
                          rollback_available=bool(self.state['previous']), generation=self.state['active'],
                          iana='Bundled, verified IANA protocol and service library; port registrations are context only.')
            if include_token: result['token'] = self.token
            return result

    def usage(self):
        with self.lock:
            return dict(used_bytes=self._used(),cap_bytes=CAP,separate_from_evidence=True,
                        last_check=self.state['last_check'],error=self.state['error'])

    def search(self, query, limit=6):
        if type(query) is not str or not 1 <= len(query) <= 160 or type(limit) is not int or not 1 <= limit <= 8:
            raise ValueError('Use a short reference search')
        words = re.findall(r'[\w.-]+', query, re.UNICODE)[:12]
        if not words: return []
        with self.lock:
            if self.fallback:
                rows = [r for r in self.seed['entries'] if any(w.casefold() in (r['title']+' '+r['text']).casefold() for w in words)][:limit]
            else:
                with self._db() as db:
                    expression = ' OR '.join('"'+w.replace('"','""')+'"' for w in words)
                    rows = [dict(r) for r in db.execute('SELECT d.* FROM search JOIN documents d ON d.id=search.id WHERE search MATCH ? ORDER BY rank LIMIT ?', (expression,limit))]
            return [{k:r[k] for k in ('id','source','edition','identifier','title','url')} |
                    {'excerpt':r['text'][:1000], 'context_only':True} for r in rows]

    def for_pattern(self,pattern):
        from .security_patterns import CONTEXT
        if pattern not in CONTEXT:raise ValueError('Unknown reviewed pattern')
        if not self.fallback:
            with self.lock,self._db() as db:
                rows=[dict(r) for r in db.execute('SELECT d.* FROM workflow_links w JOIN documents d ON d.id=w.document WHERE w.pattern=? LIMIT 3',(pattern,))]
            if rows:
                return [{k:r[k] for k in ('id','source','edition','identifier','title','url')}|{'excerpt':r['text'][:1000],'context_only':True} for r in rows]
        return self.search(CONTEXT[pattern][2],3)

    def action(self, body):
        if body == {'action':'update'}:
            return self.update()
        with self.lock:
            if self.busy: raise ValueError('A reference update is already running')
            if body == {'action':'rollback'} and self.state['previous']:
                previous = self.state['previous']
                with self._db(previous) as db:
                    if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok': raise ValueError('Rollback library failed validation')
                old = deepcopy(self.state)
                self.state.update(active=previous,previous=self.state['active'],error=None)
                try: self._save()
                except BaseException:
                    self.state=old
                    raise
                self.fallback=False
            elif set(body)=={'action','enabled'} and body['action']=='configure' and type(body['enabled']) is bool:
                old=deepcopy(self.state)
                self.state['enabled']=body['enabled']
                try:self._save()
                except BaseException:
                    self.state=old
                    raise
            else: raise ValueError('Unsupported knowledge action')
        return self.snapshot()

    def update(self):
        with self.lock:
            if self.busy: return self.snapshot()
            self.busy=True
            self.worker=Thread(target=self._update, name='megalodon-knowledge-update', daemon=True)
            self.worker.start()
        return self.snapshot()

    def _update(self):
        try:
            assets={}
            if not self.fallback:
                with self.lock, self._db() as db:
                    assets = {r['url']:(r['etag'],bytes(r['body'])) for r in db.execute('SELECT * FROM assets')}
            downloaded = {}; changed = False
            def get(url, maximum):
                nonlocal changed
                previous = assets.get(url)
                raw, tag = self.downloader(url, maximum, previous[0] if previous else None, stop=self.stop)
                if raw is None:
                    if previous is None: raise ValueError('A source returned no initial content')
                    decoder=zlib.decompressobj()
                    raw=decoder.decompress(previous[1],maximum+1)
                    if len(raw)>maximum or not decoder.eof: raise ValueError('Invalid cached source')
                else: changed=changed or previous is None or zlib.compress(raw)!=previous[1]
                downloaded[url]=(tag,raw)
                return raw
            entries=[];sources={}
            for source, definition in SOURCES.items():
                license_raw=get(LICENSE_URLS[source],256*1024)
                license_sha=license_identity(source,license_raw)
                if license_sha!=self.seed['sources'][source]['license_sha256']:
                    raise ValueError('Publisher license changed; a reviewed application update is required')
                url=definition['url']
                if source=='atlas':
                    pointer=get(url,128).decode().strip()
                    if not re.fullmatch(r'ATLAS-20[0-9]{2}\.(?:0[1-9]|1[0-2])\.yaml',pointer):
                        raise ValueError('Unsupported ATLAS release pointer')
                    url=ATLAS+pointer
                    raw=get(url,definition['limit'])
                elif source=='owasp':
                    raw=json.dumps({name:get(OWASP+name+'.md',128*1024).decode() for name in OWASP_FILES}).encode()
                else: raw=get(url,definition['limit'])
                rows,edition=parse(source,raw)
                entries+=rows
                sources[source]=dict(name=definition['name'],url=url,edition=edition,
                    retrieved_at=utc(self.clock()),sha256=digest(raw),entries=len(rows),
                    license=self.seed['sources'][source]['license'],attribution=self.seed['sources'][source]['attribution'],
                    license_sha256=license_sha,
                    license_text=self.seed['sources'][source]['license_text'],coverage='Supported published records')
            if changed or self.fallback:
                name=self._build(entries,sources,downloaded)
                self._activate(name)
            with self.lock:
                self.state.update(last_check=utc(self.clock()),error=None)
                self._save()
        except Exception:
            with self.lock:
                self.state.update(last_check=utc(self.clock()),error='Update was not activated. The previous library is still available; check source availability, format and free disk space.')
                try:self._save()
                except OSError:pass
        finally:
            with self.lock:self.busy=False

    def tick(self):
        schedule=dict(enabled=True,time='08:00',frequency='daily',weekday=0)
        slot, slot_at = latest_slot(schedule,self.clock(),local_zone())
        with self.lock:
            if not self.state['enabled'] or self.busy or self.state['last_slot']==slot or slot_at<=self.state.get('slot_at',0): return
            # A checked slot survives failure and restart: no hammering sources.
            self.state['last_slot']=slot
            self.state['slot_at']=slot_at
            self._save()
        self.update()

    def start(self):
        if self.thread and self.thread.is_alive():return
        self.stop.clear()
        def run():
            while not self.stop.wait(30):
                try:self.tick()
                except (OSError,ValueError,sqlite3.Error):pass
        self.thread=Thread(target=run,name='megalodon-knowledge-schedule',daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        for thread in (self.thread,self.worker):
            if thread:thread.join(timeout=20)
