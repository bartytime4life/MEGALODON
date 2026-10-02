"""Local managed evidence: finite segments, reviewed policy, and oldest-first eviction.

All mutations are serialized by one owner; readers hold the same lease during a
bounded query. Closed segments are deleted as complete units, never an open
SQLite database or a partial event/detection transaction. External inputs are
not enrolled by directory discovery.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
try:
    import fcntl
except ImportError:  # Local collectors and managed evidence run on Linux.
    fcntl=None
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
from threading import Event, RLock, Thread
import time
from uuid import uuid4

from .local_install import _owned_directory, _regular_owned_file, _atomic_write, _validate_directory_chain
from .storage import Store, StorageCapacityError, StorageSchemaError

GIB = 1024**3
SEGMENT_BYTES = 512 * 1024**2
WORK_RESERVE = 16 * 1024**2
MAX_ENTRIES = 16384
MAX_CATALOG_BYTES = 16 * 1024**2
CATEGORIES = {'packets':'Packet metadata and linked findings', 'flows':'Connection summaries',
              'packet_rollups':'Compacted packet conversations and preserved findings',
              'findings':'Sensor findings', 'network':'Network inventory',
              'companions':'Inventory and scan results', 'cases':'Saved cases',
              'audit':'Qwen and response receipts', 'sensor_logs':'Managed sensor metadata',
              'resources':'Resource and speed history', 'reports':'Generated visual reports',
              'baselines':'Hourly activity baselines', 'intelligence':'Pattern reviews, AI explanations and feedback'}
PROFILES = [dict(id='home',label='Home / workstation',retention_days=14,cap_bytes=20*GIB,recording_mode='packet_metadata'),
            dict(id='lab',label='Home lab / small office',retention_days=14,cap_bytes=100*GIB,recording_mode='packet_metadata'),
            dict(id='server',label='Busy server',retention_days=7,cap_bytes=500*GIB,recording_mode='connection_summaries')]


def utc(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value,timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')


def epoch(value):
    if type(value) is not str or len(value)>40:
        raise ValueError('Invalid evidence time.')
    stamp = datetime.fromisoformat(value.replace('Z','+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('Evidence time must include a timezone.')
    return stamp.timestamp()


def policy_value(value):
    if type(value) is not dict or set(value) != {'profile','retention_days','cap_bytes'}:
        raise ValueError('Choose a profile, retention days and storage cap.')
    profile = next((p for p in PROFILES if p['id']==value['profile']),None)
    if (profile is None or type(value['retention_days']) is not int or not 7<=value['retention_days']<=30
            or type(value['cap_bytes']) is not int or not GIB<=value['cap_bytes']<=4*1024*GIB):
        raise ValueError('Use 7–30 days and a cap from 1 GiB to 4 TiB.')
    return dict(value,recording_mode=profile['recording_mode'])


class EvidenceStorage:
    def __init__(self, settings, *, home=None, clock=time.time, monotonic=time.monotonic, segment_bytes=SEGMENT_BYTES):
        if fcntl is None:raise ValueError('Managed evidence requires the local Linux HUD.')
        self.settings = settings
        self.home = Path.home() if home is None else Path(home)
        self.root = self.home/'.local/share/megalodon/evidence'
        self.catalog_path = self.root/'catalog.json'
        self.clock, self.segment_bytes = clock, segment_bytes
        self.monotonic=monotonic;self._wall_anchor=clock();self._mono_anchor=monotonic()
        self.token = secrets.token_urlsafe(24)
        self.lock = RLock()
        self._stop = Event(); self._thread = None
        self._compaction_thread = None
        self._writers = set(); self._generic = {}; self._preview = {}; self._working_reserved=0
        self._error = None; self._last_save = 0; self._last_sweep = 0
        self._write_dbs = {}; self._checkpoint_times = {}; self._last_catalog_raw = None
        self._recording = {}; self._write_metrics = dict(commits=0,write_failures=0,checkpoint_busy=0,last_checkpoint_at=None)
        self._checkpoint_frames = {}
        self.telemetry = None
        self._lease_fd = None
        _owned_directory(self.root,private=True)
        self._lease_fd=os.open(self.root/'owner.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info=os.fstat(self._lease_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode & 0o077:
            os.close(self._lease_fd);self._lease_fd=None
            raise ValueError('Evidence owner lease identity is unsafe.')
        try:fcntl.flock(self._lease_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except OSError:
            os.close(self._lease_fd);self._lease_fd=None
            raise ValueError('Another HUD owns managed evidence. Use its existing window.') from None
        try:
            self._catalog = dict(version=1,policy=None,entries=[],growth=[],last_cleanup_at=None,
                                 evicted_records=0,evicted_bytes=0,checkpoints={},audit_boundaries={},last_clock=None,started_at=utc(self.clock()))
            if self.catalog_path.exists():
                raw = _regular_owned_file(self.catalog_path,maximum=MAX_CATALOG_BYTES)
                value = json.loads(raw)
                if type(value) is not dict or value.get('version')!=1 or type(value.get('entries')) is not list or len(value['entries'])>MAX_ENTRIES:
                    raise ValueError('Managed evidence catalog requires review.')
                if value.get('policy'):
                    policy_value({k:value['policy'][k] for k in ('profile','retention_days','cap_bytes')})
                self._catalog = value
                self._catalog.setdefault('audit_boundaries',{})
                self._catalog.setdefault('started_at',utc(self.clock()))
                self._catalog.setdefault('checkpoint_generation',0)
                # An interrupted writer must be checked before its segment can expire.
                for entry in self._catalog['entries']:
                    self._path(entry)
                    if entry.get('state') == 'deleting':
                        self._recover_deletion(entry)
                    elif entry.get('state') == 'open' or entry.get('pending_receipts'):
                        self._recover_open(entry)
                self._catalog['entries'] = [e for e in self._catalog['entries'] if e['state']!='deleted']
                for entry in self._catalog['entries']:
                    if entry.get('state')=='building' and entry.get('category')!='packet_rollups':
                        raise ValueError('Unexpected building evidence segment needs review.')
                if any(e['state']=='needs_review' for e in self._catalog['entries']):
                    self._error='An evidence segment needs recovery review and remains protected from deletion.'
                self._save()
        except BaseException:
            os.close(self._lease_fd);self._lease_fd=None
            raise

    @property
    def enabled(self):
        return self._catalog['policy'] is not None

    @property
    def recording_mode(self):
        return self._catalog['policy']['recording_mode'] if self.enabled else 'packet_metadata'

    @property
    def retention_days(self):
        return self._catalog['policy']['retention_days'] if self.enabled else 14

    def _save(self, *, force=True):
        if self._lease_fd is None:raise ValueError('Evidence owner lease is closed.')
        if not force and self.clock()-self._last_save < 30:return
        _owned_directory(self.root,private=True)
        raw = json.dumps(self._catalog,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        if len(raw)>MAX_CATALOG_BYTES:
            raise ValueError('Evidence catalog capacity reached.')
        if raw == self._last_catalog_raw:return
        _atomic_write(self.catalog_path,raw,0o600)
        descriptor=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        self._last_catalog_raw = raw
        self._last_save = self.clock()

    def _path(self,entry):
        if not re.fullmatch(r'[a-f0-9]{32}',entry.get('id','')):
            raise ValueError('Invalid evidence segment identity.')
        if entry.get('legacy'):
            path = Path(entry['path'])
            allowed = {Path(self.settings.db_path).absolute(),self.home/'.local/share/megalodon/defense/receipts.db',
                       Path(self.settings.db_path).absolute().parent/'megalodon-ai-receipts.db'}
            if path not in allowed:
                raise ValueError('Unregistered legacy evidence path.')
        else:
            if entry.get('path')!=entry['id']+'.db':
                raise ValueError('Invalid managed evidence path.')
            path = self.root/entry['path']
        return path

    def _size(self,entry,*,missing=False):
        path = self._path(entry)
        total = 0
        for suffix in ('','-wal','-shm','-journal'):
            try: info = Path(str(path)+suffix).lstat()
            except FileNotFoundError:
                if not suffix and not missing: raise ValueError('Managed evidence segment is missing.')
                continue
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                    or info.st_mode & 0o077):
                raise ValueError('Managed evidence identity or permissions changed.')
            if not suffix and (info.st_dev!=entry['dev'] or info.st_ino!=entry['ino']):
                raise ValueError('Managed evidence segment was replaced.')
            total += info.st_size
        return total

    @contextmanager
    def _db(self,entry,*,write=False):
        # Reuse descriptor-anchored storage admission for generic segments.
        from .storage import (_open_private_directory,_open_private_database,_validate_sqlite_sidecars,
                              _anchored_database_path,_validate_connection_path)
        path = self._path(entry)
        directory = _open_private_directory(path.parent,create=False,prefix='EVIDENCE')
        descriptor = None; connection = None
        try:
            self._size(entry)
            descriptor,_ = _open_private_database(path,directory,writable=write,create=False,prefix='EVIDENCE')
            _validate_sqlite_sidecars(path,directory,writable=write,prefix='EVIDENCE')
            anchor = _anchored_database_path(descriptor,path,'EVIDENCE')
            connection = sqlite3.connect(f'{anchor.as_uri()}?mode={"rw" if write else "ro"}&cache=private',uri=True,timeout=.25,check_same_thread=False)
            _validate_connection_path(connection,path,'EVIDENCE')
            connection.row_factory = sqlite3.Row
            if not write: connection.execute('PRAGMA query_only=ON')
            deadline = time.monotonic()+2
            connection.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
            yield connection
        finally:
            if connection is not None: connection.close()
            if descriptor is not None: os.close(descriptor)
            os.close(directory)

    @contextmanager
    def _writer_db(self, entry):
        """One persistent, descriptor-anchored connection per active generic segment."""
        self._size(entry)
        item = self._write_dbs.get(entry['id'])
        if item is None:
            context = self._db(entry, write=True)
            db = context.__enter__()
            try:
                db.execute('PRAGMA synchronous=FULL')
                db.execute('PRAGMA wal_autocheckpoint=0')
            except BaseException:
                context.__exit__(None, None, None)
                raise
            item = (context, db)
            self._write_dbs[entry['id']] = item
            self._checkpoint_times[entry['id']] = self.monotonic()
        db = item[1]
        deadline = time.monotonic()+2
        db.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
        try:
            yield db
        except BaseException:
            db.rollback()
            self._write_metrics['write_failures'] += 1
            raise

    def _wal_work(self, entry):
        """Scheduling hint only; SQLite remains responsible for WAL validation.

        A reused WAL retains allocation beyond its current frame generation.
        Match frame salts to distinguish those old bytes without a checkpoint
        on every batch. The owner lock excludes our writer during this read.
        See sqlite.org/fileformat2.html#walformat (32-byte/24-byte headers).
        """
        path = Path(str(self._path(entry))+'-wal')
        try:descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        except FileNotFoundError:return 0,None,0,1
        try:
            info=os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_mode&0o077:
                raise ValueError('Managed WAL identity or permissions changed.')
            size=info.st_size;header=os.pread(descriptor,32,0)
            if not size:return 0,None,0,1
            page=int.from_bytes(header[8:12],'big')
            if len(header)!=32 or header[:4] not in (b'\x37\x7f\x06\x82',b'\x37\x7f\x06\x83') or page<512 or page>65536 or page&(page-1):
                return size,None,size,1  # Let SQLite check unfamiliar state.
            stride=page+24;low=0;high=max(0,(size-32)//stride)
            while low<high:
                middle=(low+high+1)//2
                if os.pread(descriptor,8,32+(middle-1)*stride+8)==header[16:24]:low=middle
                else:high=middle-1
            return size,header[12:24],low,stride
        finally:os.close(descriptor)

    def _checkpoint(self, entry, db, *, force=False):
        size,generation,frames,stride=self._wal_work(entry)
        prior=self._checkpoint_frames.get(entry['id'])
        pending=max(0,frames-prior[1]) if generation is not None and prior and prior[0]==generation else frames
        last = self._checkpoint_times.get(entry['id'],self.monotonic())
        if not force and (not pending or (pending*stride < 8*1024**2 and self.monotonic()-last < 60)):
            return
        row = db.execute('PRAGMA wal_checkpoint('+('TRUNCATE' if force else 'PASSIVE')+')').fetchone()
        self._checkpoint_frames[entry['id']]=(generation,max(0,row[2]))
        blocked = bool(row[0] or row[1] != row[2])
        if blocked:
            self._write_metrics['checkpoint_busy'] += 1
            if force or size >= 32*1024**2:
                raise StorageCapacityError('Checkpoint is held by a reader; recording waits for safe reclamation.')
        else:
            self._checkpoint_times[entry['id']] = self.monotonic()
            self._write_metrics['last_checkpoint_at'] = utc(self.clock())

    def disk_activity(self):
        result = dict(recording_mode='balanced',pending_records=0,pending_bytes=0,
                      oldest_pending_seconds=0,**self._write_metrics)
        result.update(self._recording)
        # The packet buffer also reports its own failed commits. Keep the
        # all-writer counter authoritative so it includes flow/report failures.
        result['buffer_write_failures'] = self._recording.get('write_failures',0)
        result['write_failures'] = self._write_metrics['write_failures']
        result['current_write_bytes_per_second'] = None
        if self.telemetry is not None:
            sample = self.telemetry.snapshot()
            apps = sample.get('apps',[])
            if isinstance(apps,list):
                rates = [r.get('write_bps') for r in apps if r.get('process_count',0)]
                known = [n for n in rates if isinstance(n,(int,float)) and n>=0]
                result['unavailable_app_counters'] = len(rates)-len(known)
                if known:result['current_write_bytes_per_second'] = sum(known)
        rate = result['current_write_bytes_per_second']
        result['estimated_write_bytes_per_day'] = rate*86400 if rate is not None else None
        result['estimate_provisional'] = True
        result['measurement_note'] = 'OS process write counters; daily projection assumes this rate continues. Physical drive wear is not measured.'
        return result

    def _recover_open(self,entry):
        try:
            with self._db(entry) as db:
                if db.execute('PRAGMA quick_check').fetchone()[0]!='ok': raise ValueError('Integrity check failed.')
                if entry['kind']=='core':
                    row=db.execute('SELECT COUNT(*),MIN(observed_at),MAX(observed_at) FROM events').fetchone()
                    entry.update(records=row[0],first_at=row[1],last_at=row[2])
                    pending=db.execute("SELECT id,status FROM ingestion_runs WHERE status IN ('running','reconciliation_required')").fetchall()
                    if db.execute('PRAGMA foreign_key_check').fetchone():raise ValueError('Interrupted relationships require review.')
                else:
                    row = db.execute('SELECT COUNT(*), MIN(observed_at), MAX(observed_at) FROM records').fetchone()
                    entry.update(records=row[0],first_at=row[1],last_at=row[2])
                    for saved in db.execute('SELECT key,value FROM checkpoints'):
                        candidate=json.loads(saved[1]);current=self._catalog['checkpoints'].get(saved[0],{})
                        if saved[0]=='derived_sources':
                            entry['derived_sources']=candidate['sources'];continue
                        if saved[0].startswith('audit_'):
                            if candidate.get('sequence',0)>=current.get('sequence',0):self._catalog['checkpoints'][saved[0]]=candidate
                        elif candidate.get('generation',0)>=current.get('generation',0):
                            self._catalog['checkpoints'][saved[0]]=candidate
                        self._catalog['checkpoint_generation']=max(self._catalog.get('checkpoint_generation',0),candidate.get('generation',0))
                    if entry['category']=='audit':
                        states={}
                        for r in db.execute('SELECT source,data FROM records ORDER BY id'):
                            data=json.loads(r[1]);states[(r[0],data['receipt_id'])]=data['state']
                        entry['pending_receipts']=sum(v=='not_attempted' for v in states.values())
            if entry['kind']=='core' and pending:
                if any(row['status']!='running' for row in pending):raise ValueError('Interrupted ingestion requires reconciliation.')
                # The exclusive owner lease proves no managed segment writer
                # remains. The core store verifies committed bundles/counters
                # and records an incomplete run, never a completed capture.
                with Store(self._path(entry),max_database_bytes=4*GIB) as store:
                    for row in pending:
                        receipt=store.finish_ingestion_run(row['id'],'interrupted',failure_code='INTERRUPTED')
                        if receipt['status']=='reconciliation_required':raise ValueError('Interrupted receipt needs review.')
                entry['recovered_incomplete']=True
            entry['state']='open' if entry.get('pending_receipts') else 'closed'
            if entry.get('pending_receipts'):self._generic['audit']=entry
        except (OSError,ValueError,sqlite3.Error):
            entry['state']='needs_review'
            self._error='An interrupted segment needs review; it will not be silently removed.'

    def _recover_deletion(self,entry):
        # A persisted deletion intent can only complete against the same inode.
        self._size(entry,missing=True)
        path=self._path(entry)
        for suffix in ('-wal','-shm','-journal',''):
            try: Path(str(path)+suffix).unlink()
            except FileNotFoundError: pass
        self._catalog['evicted_records']+=entry.get('deletion_records',entry['records'])
        self._catalog['evicted_bytes']+=entry.get('deletion_bytes',0)
        if entry.get('category')=='packets' and entry.get('compaction_state')=='complete':
            self._catalog['compacted_reclaimed_bytes']=self._catalog.get('compacted_reclaimed_bytes',0)+entry.get('deletion_bytes',0)
        self._catalog['last_cleanup_at']=entry.get('deletion_at',utc(self.clock()))
        entry['state']='deleted'

    def _new(self,category,kind='generic',*,state='open',source_segment=None):
        if len(self._catalog['entries'])>=MAX_ENTRIES:
            raise ValueError('Evidence segment count reached its bound.')
        self._ensure_space(WORK_RESERVE)
        _owned_directory(self.root,private=True)
        identifier=uuid4().hex; path=self.root/(identifier+'.db')
        fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        info=os.fstat(fd);os.close(fd)
        entry=dict(id=identifier,path=path.name,legacy=False,kind=kind,category=category,dev=info.st_dev,ino=info.st_ino,
                   state=state,created_at=utc(self.clock()),first_at=None,last_at=None,records=0)
        if source_segment is not None:entry['source_segment']=source_segment
        self._catalog['entries'].append(entry)
        # Register the inode before schema work. A crash during creation then
        # leaves a known, protected unit instead of an unaccounted file.
        self._save()
        if kind=='generic':
            try:
                with self._db(entry,write=True) as db:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('CREATE TABLE records(id INTEGER PRIMARY KEY,observed_at TEXT NOT NULL,recorded_at TEXT NOT NULL,source TEXT NOT NULL,data TEXT NOT NULL)')
                    db.execute('CREATE INDEX records_time ON records(observed_at)')
                    if category=='reports':
                        db.execute('CREATE INDEX reports_source ON records(source,id)')
                    db.execute('CREATE TABLE checkpoints(key TEXT PRIMARY KEY,value TEXT NOT NULL)')
                    db.commit()
            except BaseException:
                entry['state']='needs_review';self._save()
                raise
        return entry

    def _working_bytes(self):
        # Only the fixed private Zeek temporary workspace is accounted here.
        # External sensor sources, user exports and installed models are not
        # enrolled or removed. The 16 MiB admission headroom covers atomic
        # catalog replacement and journal growth during the next transaction.
        root=self.home/'.local/share/megalodon/support/sensor-samples'
        if not root.exists():return 0
        _validate_directory_chain(root)
        total=0
        directories=[]
        for directory in root.iterdir():
            directories.append(directory)
            if len(directories)>64:raise ValueError('Managed temporary workspace count needs review; accounting cannot be truncated.')
        for directory in directories:
            if not directory.name.startswith('zeek-'):continue
            _validate_directory_chain(directory)
            try:
                paths=[]
                for path in directory.iterdir():
                    paths.append(path)
                    if len(paths)>64:raise ValueError('Managed temporary file count needs review; accounting cannot be truncated.')
            except FileNotFoundError:continue
            for path in paths:
                try:info=path.lstat()
                except FileNotFoundError:continue
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1:
                    raise ValueError('Managed sensor workspace identity changed.')
                total+=info.st_size
        return total

    @contextmanager
    def working_reservation(self,amount):
        if type(amount) is not int or not 0<amount<=WORK_RESERVE:raise ValueError('Invalid working reservation.')
        with self.lock:
            self._ensure_space(WORK_RESERVE+amount)
            self._working_reserved+=amount
        try:yield
        finally:
            with self.lock:self._working_reserved-=amount

    def _used(self):
        size=sum(self._size(e) for e in self._catalog['entries'] if e['state']!='deleted')
        if self.catalog_path.exists(): size+=self.catalog_path.stat().st_size
        for name in ('report-settings.json','intelligence-settings.json'):
            settings=self.root/name
            if settings.exists():size+=len(_regular_owned_file(settings,maximum=65536))
        return size+self._working_bytes()

    def _expired(self,entry,policy):
        # Closed hourly units may expire up to one segment early. The displayed
        # actual interval is authoritative; no record is promised a minimum age.
        return epoch(entry.get('first_at') or entry['created_at'])<=self.clock()-policy['retention_days']*86400

    def available_sources(self, entries=None, *, readable=True):
        values=self._catalog['entries'] if entries is None else entries
        live=[e for e in values if e['state'] in ({'open','closed'} if readable else {'open','closed','needs_review','building'})]
        return {e['id'] for e in live}|{e['source_segment'] for e in live if e['category']=='packet_rollups' and e['state']=='closed' and e.get('source_segment')}

    def derived_available(self, entry):
        return not entry.get('derived_sources') or set(entry['derived_sources'])<=self.available_sources()

    def _cascade(self, entries, selected):
        # A whole bounded derived segment expires early when any source retires.
        # This reclaims pages without VACUUM or rewriting records individually.
        result=list(selected);removed={e['id'] for e in result}
        while True:
            available=self.available_sources([e for e in entries if e['id'] not in removed],readable=False)
            extra=[e for e in entries if e['id'] not in removed and e['state'] in {'open','closed'}
                   and e.get('derived_sources') and not set(e['derived_sources'])<=available]
            if not extra:return result
            result+=extra;removed.update(e['id'] for e in extra)

    def _candidates(self,policy,reserve=WORK_RESERVE):
        used=self._used(); result=[]
        eligible=[e for e in self._catalog['entries'] if e['state']=='closed' and not e.get('pending_receipts')
                  and e.get('compaction_state')!='building']
        ordered=sorted(eligible,key=lambda e:e.get('first_at') or e['created_at'])
        by_id={e['id']:e for e in self._catalog['entries']}
        for entry in sorted(ordered,key=lambda e:(0 if e['category']=='packets' and e.get('compaction_state')=='complete' else 1,
                                                  e.get('first_at') or e['created_at'])):
            if self._expired(entry,policy):
                if entry['category']=='packet_rollups':
                    source=by_id.get(entry.get('source_segment'))
                    if source and source.get('compacted_to')==entry['id'] and not self._expired(source,policy):
                        continue
                result.append(entry);used-=self._size(entry)
        # When capacity is tight, retain verified, much smaller summaries and
        # saved evidence ahead of their original packet detail. Every category
        # still follows the same upper age and total-byte limit.
        remaining=[e for e in ordered if e not in result]
        remaining.sort(key=lambda e:(0 if e['category']=='packets' and e.get('compaction_state')=='complete' else
                                     1 if e['category']=='packets' else
                                     2 if e['category']=='flows' else
                                     3 if e['category']=='packet_rollups' else
                                     4 if e['category'] in {'resources','network','companions','sensor_logs'} else
                                     5, e.get('first_at') or e['created_at']))
        for entry in remaining:
            if used+reserve<=policy['cap_bytes']:break
            result.append(entry);used-=self._size(entry)
        return self._cascade(self._catalog['entries'],result)

    def _check_compact_source(self,source):
        target=next((e for e in self._catalog['entries'] if e['id']==source.get('compacted_to')
                     and e['category']=='packet_rollups' and e['state']=='closed'
                     and e.get('source_segment')==source['id']),None)
        if target is None:
            raise ValueError('Verified compact history is missing; original packet detail remains protected.')
        with self._db(target) as db:
            row=db.execute("SELECT value FROM checkpoints WHERE key='packet_compaction'").fetchone()
            if row is None or db.execute('PRAGMA quick_check').fetchone()[0]!='ok':
                raise ValueError('Compact history integrity changed; original packet detail remains protected.')
            progress=json.loads(row[0])
            if progress.get('stage')!='done' or progress.get('processed_count')!=source['records']:
                raise ValueError('Compact history no longer matches its source; original detail remains protected.')
            packet_count=byte_count=0
            kinds=dict(finding_v1=0,action_v1=0,run_v1=0)
            labels={'preserved-packet-finding':'finding_v1','preserved-packet-action':'action_v1',
                    'preserved-capture-receipt':'run_v1'}
            for label,raw in db.execute('SELECT source,data FROM records'):
                value=json.loads(raw)
                if type(value) is not dict or value.get('source_segment')!=source['id']:
                    raise ValueError('Compact history source changed; original packet detail remains protected.')
                if label=='packet-conversation-summary' and value.get('kind')=='conversation_v1':
                    count=value.get('packet_count'); size=value.get('byte_count')
                    if type(count) is not int or count<=0 or type(size) is not int or size<0:
                        raise ValueError('Compact history counts changed; original packet detail remains protected.')
                    packet_count+=count;byte_count+=size
                elif label in labels and value.get('kind')==labels[label]:
                    kinds[labels[label]]+=1
                else:
                    raise ValueError('Compact history record changed; original packet detail remains protected.')
            if (packet_count!=progress.get('processed_count') or byte_count!=progress.get('processed_bytes')
                    or kinds['finding_v1']!=progress.get('finding_count')
                    or kinds['action_v1']!=progress.get('action_count')
                    or kinds['run_v1']!=progress.get('run_count')):
                raise ValueError('Compact history totals changed; original packet detail remains protected.')

    def _ensure_space(self,reserve=WORK_RESERVE):
        if not self.enabled:return
        reserve+=self._working_reserved
        stamp=self.clock(); prior=self._catalog.get('last_clock')
        if abs((stamp-self._wall_anchor)-(self.monotonic()-self._mono_anchor))>300:
            raise ValueError('System clock changed abruptly; storage maintenance needs review.')
        if prior is not None and stamp<prior-300:
            raise ValueError('System clock moved backwards; storage maintenance needs review.')
        self._catalog['last_clock']=stamp
        if self._used()+reserve>self._catalog['policy']['cap_bytes']:
            # All callers enter before their next transaction. Seal completed
            # units first so a small cap can keep recording across categories.
            for writer in list(self._writers):writer.rotate()
            for key,entry in list(self._generic.items()):
                if entry.get('pending_receipts'):continue
                self._seal(entry);self._generic.pop(key)
        for entry in self._candidates(self._catalog['policy'],reserve):
            if entry['state']=='open':
                self._seal(entry)
                if self._generic.get(entry['category']) is entry:self._generic.pop(entry['category'])
            if entry['category']=='packets' and entry.get('compaction_state')=='complete':
                self._check_compact_source(entry)
            size=self._size(entry)
            if entry['category']=='audit':
                if entry['kind']=='generic':
                    with self._db(entry) as db:
                        for saved in db.execute("SELECT key,value FROM checkpoints WHERE key LIKE 'audit_%'"):
                            anchor=json.loads(saved[1]);anchor.pop('pending',None)
                            self._catalog['audit_boundaries'][saved[0]]=dict(anchor,expired_at=utc(stamp),segment=entry['id'])
                elif entry['kind']=='receipt':
                    self._catalog['audit_boundaries']['legacy_'+entry['id']]=dict(head=entry['chain_head'],expired_at=utc(stamp),segment=entry['id'])
            entry.update(state='deleting',deletion_bytes=size,deletion_records=entry['records'],deletion_at=utc(stamp));self._save()
            self._recover_deletion(entry)
            if self._size(entry,missing=True): raise ValueError('Space reclamation was not verified.')
            self._catalog['entries'].remove(entry)
            self._save()
        if self._used()+reserve>self._catalog['policy']['cap_bytes']:
            raise StorageCapacityError('Managed evidence cap cannot fit the active transaction and protected incomplete segments.')
        free=shutil.disk_usage(self.root).free
        if free<max(2*GIB,reserve):
            raise StorageCapacityError('Insufficient disk reserve; collection paused without discarding uncertain evidence.')

    def _sample_growth(self,used):
        # Net retained allocation plus reclaimed units measures required
        # capacity. Summing positive WAL growth per write counts the same
        # working pages repeatedly every checkpoint and inflates estimates.
        samples=self._catalog.setdefault('growth_samples',[])
        if not samples or self.clock()-samples[-1][0]>=60:
            samples.append([self.clock(),used+self._catalog['evicted_bytes']])
            self._catalog['growth_samples']=samples[-1441:]

    def append_records(self,category,records,*,checkpoint=None,dependencies=None):
        if self._lease_fd is None:raise ValueError('Evidence owner lease is closed.')
        if not self.enabled:return 0
        if category not in CATEGORIES or category=='packets' or type(records) is not list or len(records)>256:
            raise ValueError('Invalid bounded evidence batch.')
        dependencies=set(dependencies or [])
        if category in {'baselines','intelligence'}:
            dependencies.update(v for row in records for v in row.get('data',{}).get('source_segments',[]))
        if len(dependencies)>256 or any(not isinstance(v,str) or not re.fullmatch(r'[a-f0-9]{32}',v) for v in dependencies):
            raise ValueError('Invalid derived source dependencies')
        prepared=[]
        for row in records:
            if type(row) is not dict or set(row)!={'observed_at','source','data'} or type(row['data']) is not dict:
                raise ValueError('Invalid evidence record.')
            stamp=epoch(row['observed_at'])
            if stamp>self.clock()+60 or stamp<self.clock()-self._catalog['policy']['retention_days']*86400:
                raise ValueError('Evidence timestamp is outside the configured retention window.')
            if type(row['source']) is not str or not 1<=len(row['source'])<=96:raise ValueError('Invalid source label.')
            raw=json.dumps(row['data'],separators=(',',':'),sort_keys=True,allow_nan=False)
            if len(raw.encode())>32768:raise ValueError('Evidence record exceeds its bound.')
            prepared.append((utc(stamp),utc(self.clock()),row['source'],raw))
        if not prepared:return 0
        with self.lock:
            if self._lease_fd is None:raise ValueError('Evidence owner lease is closed.')
            cutoff=self.clock()-self._catalog['policy']['retention_days']*86400
            if any(not cutoff<=epoch(r[0])<=self.clock()+60 for r in prepared):
                raise ValueError('The retention policy or clock changed before this batch was admitted.')
            if checkpoint is not None:
                self._catalog['checkpoint_generation']=self._catalog.get('checkpoint_generation',0)+1
                checkpoint=(checkpoint[0],dict(checkpoint[1],generation=self._catalog['checkpoint_generation']))
            self._ensure_space(max(WORK_RESERVE,sum(len(r[3]) for r in prepared)*4))
            if not dependencies<=self.available_sources():raise ValueError('Derived source history expired before persistence')
            entry=self._generic.get(category)
            if entry and len(set(entry.get('derived_sources',[]))|dependencies)>256:
                self._seal(entry);self._generic.pop(category,None);entry=None
            if entry and not entry.get('pending_receipts') and (self.clock()-epoch(entry['created_at'])>=3600 or self._size(entry)>=self.segment_bytes):
                self._seal(entry);self._generic.pop(category,None);entry=None
            if entry is None:entry=self._new(category);self._generic[category]=entry
            if not dependencies<=self.available_sources():raise ValueError('Derived sources retired during admission')
            combined=sorted(set(entry.get('derived_sources',[]))|dependencies)
            with self._writer_db(entry) as db:
                self._checkpoint(entry,db)
                db.executemany('INSERT INTO records(observed_at,recorded_at,source,data) VALUES(?,?,?,?)',prepared)
                if combined:db.execute("INSERT OR REPLACE INTO checkpoints VALUES('derived_sources',?)",(json.dumps(dict(sources=combined)),))
                if checkpoint is not None:
                    key,value=checkpoint
                    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',key) or len(json.dumps(value))>2048:
                        raise ValueError('Invalid ingestion checkpoint.')
                    db.execute('INSERT OR REPLACE INTO checkpoints VALUES(?,?)',(key,json.dumps(value,sort_keys=True)))
                db.commit()
                self._write_metrics['commits'] += 1
            if checkpoint is not None:
                self._catalog['checkpoints'][checkpoint[0]]=checkpoint[1]
                if category=='audit':
                    with self._db(entry) as db:
                        entry['pending_receipts']=sum(len(json.loads(r[0]).get('pending',[])) for r in db.execute("SELECT value FROM checkpoints WHERE key LIKE 'audit_%'"))
            if combined:entry['derived_sources']=combined
            stamps=[r[0] for r in prepared]
            entry['records']+=len(prepared)
            entry['first_at']=min([entry['first_at']] + stamps) if entry['first_at'] else min(stamps)
            entry['last_at']=max([entry['last_at']] + stamps) if entry['last_at'] else max(stamps)
            self._save(force=category in {'audit','reports'})
            return len(prepared)

    def _seal(self,entry):
        with self._writer_db(entry) as db:
            self._checkpoint(entry,db,force=True)
        context,_ = self._write_dbs.pop(entry['id'])
        context.__exit__(None,None,None)
        self._checkpoint_times.pop(entry['id'],None)
        self._checkpoint_frames.pop(entry['id'],None)
        entry['state']='closed'
        self._save()

    def _adopt_legacy(self):
        path=Path(self.settings.db_path).absolute()
        if not path.exists() or any(e.get('legacy') and e['path']==str(path) for e in self._catalog['entries']):return
        # Use established admission, reconciliation and exact-schema checks.
        with Store(path,max_database_bytes=4*GIB) as store:
            store._assert_retention_ready()
            if store.connection.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('Legacy evidence needs recovery.')
            count,first,last=store.connection.execute('SELECT COUNT(*),MIN(observed_at),MAX(observed_at) FROM events').fetchone()
            store.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        info=path.lstat()
        entry=dict(id=uuid4().hex,path=str(path),legacy=True,kind='core',category='packets',dev=info.st_dev,ino=info.st_ino,
                   state='closed',created_at=utc(self.clock()),first_at=first,last_at=last,records=count)
        self._size(entry)
        self._catalog['entries'].append(entry)

    def _adopt_receipts(self):
        from .ai_broker import ReceiptStore
        paths=[self.home/'.local/share/megalodon/defense/receipts.db',Path(self.settings.db_path).absolute().parent/'megalodon-ai-receipts.db']
        for path in paths:
            if not path.exists() or any(e.get('legacy') and e['path']==str(path) for e in self._catalog['entries']):continue
            with ReceiptStore(path) as ledger:
                verified=ledger.verify_chain()
                if verified['incomplete_count']:raise ValueError('A legacy AI/response receipt needs reconciliation before retention can manage it.')
                count,first,last=ledger.connection.execute('SELECT COUNT(*),MIN(timestamp),MAX(timestamp) FROM ai_receipt_events').fetchone()
                ledger.connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            info=path.lstat()
            entry=dict(id=uuid4().hex,path=str(path),legacy=True,kind='receipt',category='audit',dev=info.st_dev,ino=info.st_ino,
                       state='closed',created_at=utc(self.clock()),first_at=first,last_at=last,records=count,chain_head=verified['head'])
            self._size(entry);self._catalog['entries'].append(entry)

    def _legacy_inventory(self):
        """Read-only inventory for the same evidence that apply will enroll."""
        result=[]
        for path,kind,category in [(Path(self.settings.db_path).absolute(),'core','packets'),
                (self.home/'.local/share/megalodon/defense/receipts.db','receipt','audit'),
                (Path(self.settings.db_path).absolute().parent/'megalodon-ai-receipts.db','receipt','audit')]:
            if not path.exists() or any(e.get('legacy') and e['path']==str(path) for e in self._catalog['entries']):continue
            info=path.lstat()
            entry=dict(id=hashlib.sha256(str(path).encode()).hexdigest()[:32],path=str(path),legacy=True,kind=kind,category=category,
                dev=info.st_dev,ino=info.st_ino,state='closed',created_at=utc(self.clock()),first_at=None,last_at=None,records=0)
            with self._db(entry) as db:
                table,column=('events','observed_at') if kind=='core' else ('ai_receipt_events','timestamp')
                count,first,last=db.execute(f'SELECT COUNT(*),MIN({column}),MAX({column}) FROM {table}').fetchone()
            entry.update(records=count,first_at=first,last_at=last)
            result.append(entry)
        return result

    def _impact(self,policy,legacy):
        entries=self._catalog['entries']+legacy
        used=self._used()+sum(self._size(e) for e in legacy)
        result=[]
        # Apply seals open writers first. Use the same category priority as the
        # active cap path so the review names the units that will actually go.
        eligible=[e for e in entries if e['state'] in {'closed','open'} and not e.get('pending_receipts')
                  and e.get('compaction_state')!='building']
        ordered=sorted(eligible,key=lambda e:e.get('first_at') or e['created_at'])
        by_id={e['id']:e for e in entries}
        for entry in sorted(ordered,key=lambda e:(0 if e['category']=='packets' and e.get('compaction_state')=='complete' else 1,
                                                  e.get('first_at') or e['created_at'])):
            if self._expired(entry,policy):
                if entry['category']=='packet_rollups':
                    source=by_id.get(entry.get('source_segment'))
                    if source and source.get('compacted_to')==entry['id'] and not self._expired(source,policy):
                        continue
                size=self._size(entry);result.append((entry,size));used-=size
        remaining=[e for e in ordered if all(e is not selected for selected,_ in result)]
        remaining.sort(key=lambda e:(0 if e['category']=='packets' and e.get('compaction_state')=='complete' else
                                     1 if e['category']=='packets' else
                                     2 if e['category']=='flows' else
                                     3 if e['category']=='packet_rollups' else
                                     4 if e['category'] in {'resources','network','companions','sensor_logs'} else
                                     5, e.get('first_at') or e['created_at']))
        for entry in remaining:
            if used+WORK_RESERVE<=policy['cap_bytes']:break
            size=self._size(entry);result.append((entry,size));used-=size
        selected={e['id'] for e,_ in result}
        result += [(e,self._size(e)) for e in self._cascade(entries,[e for e,_ in result]) if e['id'] not in selected]
        return result

    @staticmethod
    def _impact_signature(impact):
        return sorted((e['path'],e['dev'],e['ino'],e['records'],e['first_at'],e['last_at'],e.get('compaction_state'),size) for e,size in impact)

    def preview(self,policy):
        parsed=policy_value(policy)
        with self.lock:
            legacy=self._legacy_inventory()
            impact=self._impact(parsed,legacy)
            identifier=uuid4().hex
            self._preview={identifier:(self.clock()+300,parsed,self._impact_signature(impact))}
            warnings=[]
            if self.recording_mode!=parsed['recording_mode']:
                warnings.append(dict(level='warning',message='Recording detail changes with this profile. Existing evidence keeps its original source and detail.'))
            if parsed['cap_bytes']>shutil.disk_usage(self.root).free+self._used()-2*GIB:
                warnings.append(dict(level='warning',message='The cap exceeds current usable disk space. It is a limit, not reserved capacity.'))
            if legacy:
                warnings.append(dict(level='info',message='Existing packet and receipt stores are included in this review. Applying enrolls them in the same oldest-first limits.'))
            return dict(schema='megalodon-storage-preview-v1',preview_id=identifier,expires_at=utc(self.clock()+300),policy=parsed,
                eligible_bytes=sum(size for _,size in impact),eligible_records=sum(e['records'] for e,_ in impact),warnings=warnings)

    def validate_preview(self,preview_id):
        if type(preview_id) is not str or not re.fullmatch(r'[a-f0-9]{32}',preview_id):
            raise ValueError('Choose a valid storage preview.')
        with self.lock:
            preview=self._preview.get(preview_id)
            if not preview or preview[0]<self.clock():raise ValueError('Storage preview expired; review settings again.')
            return preview

    def apply(self,preview_id):
        with self.lock:
            preview=self.validate_preview(preview_id)
            legacy=self._legacy_inventory()
            if self._impact_signature(self._impact(preview[1],legacy))!=preview[2]:
                raise ValueError('Evidence changed since the deletion preview; review the current impact again.')
            for writer in list(self._writers):writer.rotate()
            for key,entry in list(self._generic.items()):
                if not entry.get('pending_receipts'):self._seal(entry);self._generic.pop(key)
            # Validation may enroll files, but no deletion or policy change is
            # persisted until all legacy integrity checks have succeeded.
            previous=deepcopy(self._catalog)
            try:
                self._adopt_legacy();self._adopt_receipts()
                self._catalog['policy']=preview[1]
                if not previous['policy']:
                    self._catalog['growth_samples']=[[self.clock(),self._used()+self._catalog['evicted_bytes']]]
                self._save()
            except Exception:
                self._catalog=previous
                raise
            self._preview.clear()
            try:self._ensure_space()
            except (OSError,ValueError,sqlite3.Error):
                self._error='The reviewed policy is saved; cleanup needs review. Uncertain evidence remains retained.'
                self._save()
            return self.snapshot()

    def checkpoint(self,key,value=None):
        if not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}',key):raise ValueError('Invalid checkpoint key.')
        with self.lock:
            if value is not None:
                if len(json.dumps(value))>2048:raise ValueError('Checkpoint too large.')
                self._catalog['checkpoint_generation']=self._catalog.get('checkpoint_generation',0)+1
                self._catalog['checkpoints'][key]=dict(value,generation=self._catalog['checkpoint_generation']);self._save()
            return deepcopy(self._catalog['checkpoints'].get(key))

    def snapshot(self,include_token=False):
        with self.lock:
            policy=self._catalog['policy'] or policy_value(dict(profile='home',retention_days=14,cap_bytes=20*GIB))
            entries=self._catalog['entries'];used=self._used()
            categories=[];first=[];last=[]
            for key,label in CATEGORIES.items():
                rows=[e for e in entries if e['category']==key and e['state']!='deleted']
                starts=[e['first_at'] for e in rows if e['first_at']];ends=[e['last_at'] for e in rows if e['last_at']]
                first+=starts;last+=ends
                categories.append(dict(id=key,label=label,bytes=sum(self._size(e) for e in rows),records=sum(e['records'] for e in rows),
                    oldest_at=min(starts) if starts else None,newest_at=max(ends) if ends else None))
            if not self.enabled and Path(self.settings.db_path).exists():
                legacy=sum(Path(str(self.settings.db_path)+s).stat().st_size for s in ('','-wal','-shm') if Path(str(self.settings.db_path)+s).exists())
                used+=legacy;categories[0]['bytes']+=legacy
            categories.append(dict(id='working',label='Temporary sensor workspace',bytes=self._working_bytes(),records=0,oldest_at=None,newest_at=None))
            packets=[e for e in entries if e['category']=='packets' and e['state']!='deleted']
            rollups=[e for e in entries if e['category']=='packet_rollups' and e['state']=='closed']
            rollup_ids={e['id'] for e in rollups}
            complete=[e for e in packets if e.get('compaction_state')=='complete' and
                      e.get('compacted_to') in rollup_ids]
            raw_times=[e['first_at'] for e in packets if e.get('first_at')]
            raw_ends=[e['last_at'] for e in packets if e.get('last_at')]
            compact_times=[e['first_at'] for e in rollups if e.get('first_at')]
            compact_ends=[e['last_at'] for e in rollups if e.get('last_at')]
            compaction=dict(state='preparing' if any(e.get('compaction_state')=='building' for e in packets) else
                            'ready' if rollups else 'awaiting_closed_packets',
                            building_sources=sum(e.get('compaction_state')=='building' for e in packets),
                            completed_sources=len(complete),retained_summary_segments=len(rollups),
                            represented_packet_records=sum(e.get('records',0) for e in complete),
                            reclaimable_detail_bytes=sum(self._size(e) for e in complete),
                            reclaimed_detail_bytes=self._catalog.get('compacted_reclaimed_bytes',0),
                            raw_oldest_at=min(raw_times) if raw_times else None,
                            raw_newest_at=max(raw_ends) if raw_ends else None,
                            summary_oldest_at=min(compact_times) if compact_times else None,
                            summary_newest_at=max(compact_ends) if compact_ends else None,
                            note='Compacted conversations preserve direction, addresses, ports, counts, findings and action receipts. Individual packet detail expires under the shared age and capacity limits.')
            if self.enabled:self._sample_growth(used)
            samples=self._catalog.get('growth_samples',[])
            duration=samples[-1][0]-samples[0][0] if len(samples)>1 else 0
            increase=samples[-1][1]-samples[0][1] if len(samples)>1 else 0
            rate=increase*86400/duration if duration>=900 and increase>0 else None
            estimate=max(0,policy['cap_bytes']-WORK_RESERVE)/rate if rate and rate>0 else None
            warnings=[]
            if estimate is not None and estimate<policy['retention_days']:
                warnings.append(dict(level='critical' if estimate<7 else 'warning',message=f'Current gross write growth would fill this cap in about {estimate:.1f} days. Compact summaries may extend useful history; measured coverage by detail tier is authoritative.'))
            if self._error:warnings.append(dict(level='critical',message=self._error))
            actual=(epoch(max(last))-epoch(min(first)))/86400 if first and last else None
            if actual is not None and self._catalog['evicted_records'] and actual<7:
                warnings.append(dict(level='critical',message='Oldest-first cleanup has reduced retained coverage below seven days.'))
            result=dict(schema='megalodon-storage-v1',enabled=self.enabled,policy=deepcopy(policy),profiles=deepcopy(PROFILES),
                used_bytes=used,free_disk_bytes=shutil.disk_usage(self.root if self.root.exists() else self.home).free,
                percent=round(used/policy['cap_bytes']*100,2),oldest_at=min(first) if first else None,newest_at=max(last) if last else None,
                actual_days=actual,estimated_days=estimate,required_bytes=int(rate*policy['retention_days']*1.3+WORK_RESERVE) if rate else None,
                estimate_provisional=duration<86400,growth_bytes_per_day=rate,categories=categories,warnings=warnings,
                state='needs_review' if self._error else 'managed' if self.enabled else 'not_enabled',
                message=self._error or ('Oldest evidence rotates automatically to meet the age and space limits.' if self.enabled else 'Review a storage policy to enable automatic cleanup.'),
                last_cleanup_at=self._catalog['last_cleanup_at'],history_count=sum(e['records'] for e in entries),
                evicted_records=self._catalog['evicted_records'],evicted_bytes=self._catalog['evicted_bytes'],
                working_reserved_bytes=self._working_reserved,admission_headroom_bytes=WORK_RESERVE,
                external_stores=['Source Suricata EVE logs (OS service rotation)', 'User-selected source reports', 'User exports', 'Installed applications and Ollama model files'],
                audit_boundaries=deepcopy(self._catalog['audit_boundaries']),disk_activity=self.disk_activity())
            result['compaction']=compaction
            reference_library=getattr(self,'reference_library',None)
            if reference_library is not None:result['reference_storage']=reference_library.usage()
            if include_token:result['token']=self.token
            return result

    def history(self,*,offset=0,limit=50,category='all',cursor=None,order='newest'):
        if type(offset) is not int or not 0<=offset<=10000 or type(limit) is not int or not 1<=limit<=100 or category not in {'all',*CATEGORIES} or order not in {'newest','oldest'}:
            raise ValueError('Invalid history page.')
        with self.lock:
            order_index={e['id']:i for i,e in enumerate(self._catalog['entries'])}
            entries=sorted([e for e in self._catalog['entries'] if e['state'] in {'open','closed'} and (category=='all' or e['category']==category) and self.derived_available(e)],key=lambda e:(e.get('first_at') or e['created_at'],order_index[e['id']]),reverse=order=='newest')
            total=sum(e['records'] for e in entries)
            boundary=2**63-1 if order=='newest' else 0
            comparison='<' if order=='newest' else '>'
            direction='DESC' if order=='newest' else 'ASC'
            before=boundary;start_id=None
            if cursor:
                match=re.fullmatch(r'([a-f0-9]{32}):([0-9]{1,19})',cursor)
                if not match:raise ValueError('Invalid history cursor.')
                start_id,before=match[1],int(match[2])
                if start_id not in {e['id'] for e in entries}:
                    return dict(schema='megalodon-history-v1',records=[],total=total,offset=offset,limit=limit,truncated=True,next_cursor=None,gaps=['The requested segment expired; start a new history page.'])
                entries=entries[next(i for i,e in enumerate(entries) if e['id']==start_id):]
            result=[];gaps=[];next_cursor=None;skip=offset
            if any(e.get('recovered_incomplete') for e in entries):gaps.append('An interrupted capture has verified committed records; the uncaptured interval is unknown.')
            if any(e['state']=='needs_review' for e in self._catalog['entries']):gaps.append('A protected segment needs review and is excluded from this history page.')
            for index,entry in enumerate(entries[:64]):
                if skip>=entry['records']:skip-=entry['records'];continue
                take=limit-len(result)
                try:
                    with self._db(entry) as db:
                        if entry['kind']=='core':
                            rows=db.execute(f'SELECT id,observed_at,src_ip,dst_ip,protocol,src_port,dst_port,byte_count,tcp_flags,dns_query_length,interface,metadata_json FROM events WHERE id {comparison} ? ORDER BY id {direction} LIMIT ? OFFSET ?',
                                            (before if index==0 else boundary,take+1,skip)).fetchall()
                            values=[dict(id=r['id'],observed_at=r['observed_at'],recorded_at=None,source='accepted packet metadata',data=dict(r)) for r in rows]
                            for v in values:
                                raw=v['data'].pop('metadata_json')
                                if len(raw)>32768:raise ValueError('Event metadata exceeds read bounds.')
                                v['data']['metadata']=json.loads(raw)
                                v['data']['qualified_id']=entry['id']+':'+str(v['id'])
                                linked=db.execute('SELECT * FROM detections WHERE event_id=? LIMIT 33',(v['id'],)).fetchall()
                                v['data']['findings_truncated']=len(linked)>32
                                v['data']['findings']=[]
                                for detection in linked[:32]:
                                    finding=dict(detection);raw=finding.pop('evidence_json')
                                    if len(raw)>32768:raise ValueError('Finding exceeds read bounds.')
                                    finding['evidence']=json.loads(raw)
                                    finding['qualified_id']=entry['id']+':finding:'+str(finding['id'])
                                    finding['qualified_event_id']=v['data']['qualified_id']
                                    actions=db.execute('SELECT a.* FROM actions a JOIN detection_actions l ON l.action_id=a.id WHERE l.detection_id=? LIMIT 8',(finding['id'],)).fetchall()
                                    finding['actions']=[]
                                    for action in actions:
                                        item=dict(action);raw=item.pop('details_json')
                                        if len(raw)>32768:raise ValueError('Action exceeds read bounds.')
                                        item['details']=json.loads(raw);item['qualified_id']=entry['id']+':action:'+str(item['id'])
                                        finding['actions'].append(item)
                                    v['data']['findings'].append(finding)
                                runs=db.execute('SELECT r.* FROM ingestion_runs r JOIN ingestion_run_events l ON l.run_id=r.id WHERE l.event_id=? LIMIT 1',(v['id'],)).fetchall()
                                v['data']['ingestion']=[dict(r,qualified_id=entry['id']+':run:'+str(r['id'])) for r in runs]
                        elif entry['kind']=='receipt':
                            rows=db.execute(f'SELECT sequence,timestamp,receipt_id,payload_json,previous_hash,event_hash FROM ai_receipt_events WHERE sequence {comparison} ? ORDER BY sequence {direction} LIMIT ? OFFSET ?',
                                            (before if index==0 else boundary,take+1,skip)).fetchall()
                            values=[dict(id=r['sequence'],observed_at=r['timestamp'],recorded_at=r['timestamp'],source='legacy receipt ledger',data=dict(receipt_id=r['receipt_id'],previous_hash=r['previous_hash'],event_hash=r['event_hash'],**json.loads(r['payload_json']))) for r in rows]
                        else:
                            rows=db.execute(f'SELECT * FROM records WHERE id {comparison} ? ORDER BY id {direction} LIMIT ? OFFSET ?',
                                            (before if index==0 else boundary,take+1,skip)).fetchall()
                            values=[dict(id=r['id'],observed_at=r['observed_at'],recorded_at=r['recorded_at'],source=r['source'],data=json.loads(r['data'])) for r in rows]
                    for value in values[:take]:
                        value['id']=entry['id']+':'+str(value['id']);value['category']=entry['category'];result.append(value)
                    if len(values)>take:
                        next_cursor=result[-1]['id'];break
                    if len(result)>=limit:
                        if index+1<len(entries):next_cursor=entries[index+1]['id']+':'+str(boundary)
                        break
                except (OSError,ValueError,sqlite3.Error):gaps.append('A retained segment could not be read.')
                skip=0
            if len(entries)>64 and not next_cursor:next_cursor=entries[64]['id']+':'+str(boundary)
            return dict(schema='megalodon-history-v1',records=result,total=total,offset=offset,limit=limit,
                        truncated=bool(next_cursor or gaps),next_cursor=next_cursor,gaps=gaps)

    def save_case(self,ids):
        if not self.enabled or type(ids) is not list or not 1<=len(ids)<=50 or any(type(v) is not str or not re.fullmatch(r'[a-f0-9]{32}:[1-9][0-9]{0,18}',v) for v in ids):
            raise ValueError('Select up to 50 retained evidence records.')
        with self.lock:
            rows=[];dependencies=set()
            for identifier in dict.fromkeys(ids):
                segment,number=identifier.split(':')
                entry=next((e for e in self._catalog['entries'] if e['id']==segment),{})
                dependencies.update(entry.get('derived_sources',[]))
                page=self.history(cursor=segment+':'+str(int(number)+1),limit=1)
                value=next((r for r in page['records'] if r['id']==identifier),None)
                if value is None:raise ValueError('A selected record expired; refresh evidence.')
                if value['category']=='cases':raise ValueError('A saved case cannot recursively include another case.')
                rows.append(dict(observed_at=value['observed_at'],source='operator-saved-case',data=dict(reference=identifier,category=value['category'],source=value['source'],evidence=value['data'])))
            dependencies.update(v for row in rows for v in row['data']['evidence'].get('source_segments',[]))
            saved=self.append_records('cases',rows,dependencies=dependencies)
            return dict(schema='megalodon-case-v1',saved=saved,message='Case evidence uses the same age and space limits; its original observation time is preserved.')

    def start(self):
        if self._thread:return
        self._thread=Thread(target=self._run,daemon=True,name='megalodon-evidence-maintenance');self._thread.start()
        self._compaction_thread=Thread(target=self._run_compaction,daemon=True,name='megalodon-evidence-compaction')
        self._compaction_thread.start()

    def compact_step(self):
        """Prepare one bounded batch; no original segment is removed here."""
        from .packet_compaction import step
        with self.lock:
            if not self.enabled:return False
            # Capture and prompt finding commits take priority over a derived
            # history build. The worker retries after the write queue drains.
            if self._recording.get('pending_records',0)>128:return False
            sources=[e for e in self._catalog['entries'] if e['category']=='packets' and e['state']=='closed'
                     and not e.get('legacy') and e.get('records',0)>0 and e.get('compaction_state') not in {'complete','inefficient','ineligible'}]
            if not sources:return False
            source=min(sources,key=lambda e:e.get('first_at') or e['created_at'])
            if source.get('compaction_state')!='building':
                source['compaction_state']='building';self._save()
            targets=[e for e in self._catalog['entries'] if e.get('source_segment')==source['id'] and e['category']=='packet_rollups'
                     and e['state']!='deleted']
            if len(targets)>1:raise ValueError('Multiple compact histories for one source need review.')
            if targets and targets[0]['state'] not in {'building','closed'}:
                raise ValueError('An interrupted compact history needs review; the original remains protected.')
            target=targets[0] if targets else self._new('packet_rollups',state='building',source_segment=source['id'])
            outcome=step(self,source,target) if target['state']=='building' else True
            if outcome in {'inefficient','ineligible'}:
                # A high-cardinality source did not compress. Remove only the
                # incomplete derivative, never its original packet evidence.
                context=self._write_dbs.pop(target['id'],None)
                if context:context[0].__exit__(None,None,None)
                target.update(state='deleting',deletion_bytes=0,deletion_records=0,deletion_at=utc(self.clock()))
                self._save();self._recover_deletion(target)
                self._catalog['entries'].remove(target)
                source['compaction_state']=outcome;self._save()
                return True
            if outcome is True:
                if target['state']=='building':self._seal(target)
                with self._db(target) as db:
                    row=db.execute('SELECT COUNT(*),MIN(observed_at),MAX(observed_at) FROM records').fetchone()
                with self._db(source) as db:
                    incomplete=db.execute("SELECT COUNT(*) FROM ingestion_runs WHERE status!='completed'").fetchone()[0]
                target.update(records=row[0],first_at=row[1],last_at=row[2],source_incomplete=bool(incomplete or source.get('recovered_incomplete')))
                source.update(compaction_state='complete',compacted_to=target['id'])
                self._save()
            if self._error and self._error.startswith('Compact history paused:'):
                self._error=None
            return True

    def _run_compaction(self):
        while not self._stop.is_set():
            try:
                worked=self.compact_step()
                self._stop.wait(.05 if worked else 5)
            except (OSError,ValueError,sqlite3.Error) as exc:
                with self.lock:self._error='Compact history paused: '+str(exc)[:150]
                self._stop.wait(30)

    def _run(self):
        while not self._stop.wait(30):
            try:
                with self.lock:
                    if self.enabled:
                        for key,entry in list(self._generic.items()):
                            if not entry.get('pending_receipts') and self.clock()-epoch(entry['created_at'])>=3600:
                                self._seal(entry);self._generic.pop(key)
                        self._ensure_space();self._sample_growth(self._used());self._save(force=False)
                        for entry in list(self._generic.values()):
                            with self._writer_db(entry) as db:self._checkpoint(entry,db)
                        if self.telemetry is not None:
                            sample=self.telemetry.snapshot()
                            if sample.get('status') in {'ready','partial'} and sample.get('observed_at'):
                                self.append_records('resources',[dict(observed_at=sample['observed_at'],source='local host counters',
                                    data={k:sample[k] for k in ('system','suite','apps','network','sockets','coverage')})])
            except (OSError,ValueError,sqlite3.Error) as exc:
                self._error=str(exc)[:200]

    def close(self):
        self._stop.set()
        if self._thread:self._thread.join(3)
        if self._compaction_thread:
            self._compaction_thread.join(10)
            if self._compaction_thread.is_alive():
                raise ValueError('Compact evidence is still finishing a bounded transaction.')
        with self.lock:
            if self._lease_fd is None:return
            try:
                for writer in list(self._writers):writer.close()
                for entry in list(self._generic.values()):
                    if not entry.get('pending_receipts'):self._seal(entry)
                self._generic.clear()
                if self.enabled:self._save()
            finally:
                for context,_ in self._write_dbs.values():context.__exit__(None,None,None)
                self._write_dbs.clear()
                if self._lease_fd is not None:
                    os.close(self._lease_fd);self._lease_fd=None

    def packet_writer(self):
        writer=SegmentedPacketWriter(self)
        with self.lock:self._writers.add(writer)
        return writer


class SegmentedPacketWriter:
    """Keep core event/finding/action atomicity and detector state across rotation."""
    def __init__(self,manager):
        self.manager=manager;self.store=None;self.entry=None;self.run_id=None;self.source='jsonl'

    def start_ingestion_run(self,source):
        self.source=source
        with self.manager.lock:self._open()
        return 1  # session handle; each segment has its own immutable run receipt

    def _open(self):
        self.entry=self.manager._new('packets','core')
        self.store=Store(self.manager._path(self.entry),max_database_bytes=min(4*GIB,max(1024**2,self.manager.segment_bytes+WORK_RESERVE)))
        self.store.connection.execute('PRAGMA wal_autocheckpoint=0')
        self.manager._checkpoint_times[self.entry['id']] = self.manager.monotonic()
        self.run_id=self.store.start_ingestion_run(self.source)

    def rotate(self):
        if self.store is None:return
        self.store.finish_ingestion_run(self.run_id,'source_exhausted')
        self.store.close();self.store=None
        self.manager._seal(self.entry)

    def record_event_bundle(self,event,detections,actions,*,run_id=None):
        return self.record_event_bundles([(event,detections,actions)],run_id=run_id)[0]

    def record_event_bundles(self,bundles,*,run_id=None):
        with self.manager.lock:
            try:
                if self.store and self.entry['records'] and (self.manager.clock()-epoch(self.entry['created_at'])>=3600 or self.manager._size(self.entry)>=self.manager.segment_bytes):self.rotate()
                self.manager._ensure_space()
                if self.store is None:self._open()
                self.manager._checkpoint(self.entry,self.store.connection)
                result=self.store.record_event_bundles(bundles,run_id=self.run_id)
                self.manager._write_metrics['commits'] += 1
                self.entry['records']+=len(bundles)
                stamps=[event.observed_at.isoformat().replace('+00:00','Z') for event,_,_ in bundles]
                self.entry['first_at']=min([self.entry['first_at'],*stamps]) if self.entry['first_at'] else min(stamps)
                self.entry['last_at']=max([self.entry['last_at'],*stamps]) if self.entry['last_at'] else max(stamps)
                self.manager._save(force=any(detections or actions for _,detections,actions in bundles))
                return result
            except BaseException:
                self.manager._write_metrics['write_failures'] += 1
                raise

    def finish_ingestion_run(self,run_id,reason,*,failure_code=None):
        with self.manager.lock:
            if self.store:
                self.store.finish_ingestion_run(self.run_id,reason,failure_code=failure_code)
                self.store.close();self.store=None;self.manager._seal(self.entry)

    def close(self):
        with self.manager.lock:
            if self.store:
                self.store.close();self.store=None
                self.entry['state']='needs_review';self.manager._save()
            self.manager._writers.discard(self)


class ManagedDashboardReader:
    """Legacy bounded projections track the newest packet segment; full history has its own API."""
    def __init__(self,manager):self.manager=manager

    def _read(self,method,*args,**kwargs):
        from .dashboard_traffic import TrafficDashboardStore
        with self.manager.lock:
            entries=[e for e in self.manager._catalog['entries'] if e['kind']=='core' and e['state'] in {'open','closed'} and e['records']]
            path=self.manager._path(max(entries,key=lambda e:e['created_at'])) if entries else Path(self.manager.settings.db_path)
            if not path.exists():
                from .dashboard import UnconfiguredDashboardReader
                return getattr(UnconfiguredDashboardReader(path),method)(*args,**kwargs)
            with TrafficDashboardStore(path) as reader:return getattr(reader,method)(*args,**kwargs)

    def summary(self):return self._read('summary')
    def recent(self,limit=50):return self._read('recent',limit)
    def ingestion_runs(self,limit=8,*,source=None):return self._read('ingestion_runs',limit,source=source)
    def traffic(self):return self._read('traffic')
    def traffic_history(self,**kwargs):return self._read('traffic_history',**kwargs)
