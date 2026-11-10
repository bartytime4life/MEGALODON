"""Knowledge admission preserves an available, local, data-only library."""
import json
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

from megalodon.knowledge import KnowledgeLibrary, CAP, FALLBACK_MESSAGE
from megalodon.knowledge_sources import approved_url, SOURCES, parse, ATLAS, fetch


@pytest.fixture
def library(tmp_path):
    value=KnowledgeLibrary(tmp_path)
    yield value
    value.close()


def test_starter_search_and_source_identity(library):
    status=library.snapshot()
    assert status['entries'] >= 150
    assert status['cap_bytes']==512*1024**2
    assert set(status['sources'])==set(SOURCES)
    rows=library.search('prompt injection')
    assert rows and all('@' in row['id'] and row['url'].startswith('https://') for row in rows)
    assert all(row['context_only'] for row in rows)
    for source in status['sources'].values():
        assert source['license_text'] and len(source['sha256'])==64
        assert 'subset' in source['coverage']


def test_query_is_data_not_sql_or_fts_program(library):
    library.search('" OR * DROP TABLE documents; --')
    assert library.snapshot()['entries'] >= 150
    with pytest.raises(ValueError):library.search('a'*161)


def test_failed_update_preserves_active_and_rollback(library):
    before=library.snapshot()['generation']
    library.downloader=lambda *a,**k:(_ for _ in ()).throw(ValueError('corrupt'))
    library._update()
    assert library.snapshot()['generation']==before
    assert library.snapshot()['error']
    assert library.search('network')


def test_interrupted_activation_preserves_manifest(library):
    before=library.snapshot()['generation']
    name=library._build(library.seed['entries'],library.seed['sources'],{})
    with patch.object(library,'_save',side_effect=OSError('disk full')):
        with pytest.raises(OSError):library._activate(name)
    assert library.snapshot()['generation']==before
    recovered=KnowledgeLibrary(library.root.parents[3])
    assert recovered.snapshot()['generation']==before
    recovered.close()


def test_rollback_and_capacity(library):
    old=library.snapshot()['generation']
    new=library._build(library.seed['entries'],library.seed['sources'],{})
    library._activate(new)
    library.action({'action':'rollback'})
    assert library.snapshot()['generation']==old
    with patch.object(library,'_used',return_value=CAP):
        with pytest.raises(ValueError):library._build(library.seed['entries'],library.seed['sources'],{})


def test_urls_cannot_redirect_or_escape_sources():
    assert approved_url(ATLAS+'ATLAS-2026.09.yaml')
    for value in ['http://127.0.0.1:11434/api/pull',ATLAS+'../LICENSE',ATLAS+'ATLAS-2026.09.yaml?x=1','file:///etc/passwd']:
        assert not approved_url(value)
        with pytest.raises(ValueError):fetch(value,100)


def test_unsafe_or_unknown_formats_rejected():
    for raw in (b'!!python/object/apply:os.system [echo bad]',b'a: &a [*a]',b'format-version: 100'):
        with pytest.raises((ValueError,KeyError)):parse('atlas',raw)
    with pytest.raises(ValueError):parse('attack',b'{"type":"other"}')
    with pytest.raises(ValueError):parse('kev',json.dumps(dict(catalogVersion='v1',count=1,vulnerabilities=[])).encode())


def test_scheduler_catchup_once_even_after_failure(library):
    with patch.object(library,'update') as run:
        library.tick();library.tick()
        assert run.call_count==1
    assert library.state['last_slot']


def test_file_symlink_uses_starter_without_following_it(library,tmp_path):
    path=library._generation(library.state['active'])
    path.unlink();path.symlink_to(tmp_path/'external')
    with patch('megalodon.knowledge.sqlite3.connect',side_effect=AssertionError('Unsafe file must not be opened')):
        assert library.search('network')
    assert library.snapshot()['state']=='needs_review'
    assert path.is_symlink() and not (tmp_path/'external').exists()


def damage_active(library):
    good=library.state['active']
    active=library._build(library.seed['entries'],library.seed['sources'],{})
    library._activate(active)
    path=library._generation(active)
    with path.open('r+b') as handle:
        handle.seek(5000);value=handle.read(1);handle.seek(5000);handle.write(bytes([value[0]^0xff]))
    return good,path


@pytest.mark.parametrize('entry_point',['snapshot','search','for_pattern'])
def test_live_corruption_uses_verified_starter_without_effects(library,entry_point):
    import hashlib
    from importlib.resources import files
    good,path=damage_active(library)
    before={p.name:p.read_bytes() for p in library.root.iterdir()}
    read=dict(snapshot=library.snapshot,search=lambda:library.search('prompt injection'),
              for_pattern=lambda:library.for_pattern('OBSERVED_ACTIVITY'))[entry_point]
    with patch.object(library,'_save') as save,patch.object(library,'downloader') as download,patch('megalodon.knowledge.Thread') as worker:
        result=read()
        if entry_point=='snapshot':assert result['state']=='needs_review'
        else:assert result and all(r['context_only'] for r in result)
        # Fallback remains latched: subsequent reads must never reopen SQLite,
        # rewrite metadata, start a worker or contact a publisher.
        with patch.object(library,'_db',side_effect=AssertionError('Fallback reopened a damaged index')):
            for _ in range(2):
                status=library.snapshot()
                assert library.search('prompt injection') and library.for_pattern('OBSERVED_ACTIVITY')
        save.assert_not_called();download.assert_not_called();worker.assert_not_called()
    raw=files('megalodon.reference').joinpath('security-v1/starter.json').read_bytes()
    assert status['generation']=='starter:'+hashlib.sha256(raw).hexdigest()
    assert status['state']=='needs_review' and status['error']==FALLBACK_MESSAGE
    assert status['entries']==len(library.seed['entries']) and status['sources']==library.seed['sources']
    assert library.fallback and library.state['active']==path.name and library.state['previous']==good
    assert before=={p.name:p.read_bytes() for p in library.root.iterdir()}
    assert library.worker is None and library.thread is None


@pytest.mark.parametrize('failure',[OSError('PRIVATE_READ_FAILURE'),sqlite3.DatabaseError('PRIVATE_READ_FAILURE')])
def test_live_read_failure_never_returns_cached_health(library,failure):
    before=library.path.read_bytes()
    with patch('megalodon.knowledge.sqlite3.connect',side_effect=failure):
        status=library.snapshot()
    assert status['state']=='needs_review' and status['error']==FALLBACK_MESSAGE
    assert 'PRIVATE_READ_FAILURE' not in json.dumps(status)
    assert library.path.read_bytes()==before


def test_same_size_edit_with_restored_mtime_requalifies_cached_digest(library):
    import hashlib,os
    row=library.search('prompt injection',limit=1)[0]
    path=library._generation(library.state['active']);before=path.stat()
    changed=('X' if row['title'][0]!='X' else 'Y')+row['title'][1:]
    assert len(changed.encode())==len(row['title'].encode())
    with sqlite3.connect(path) as db:db.execute('UPDATE documents SET title=? WHERE id=?',(changed,row['id']))
    os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
    after=path.stat()
    assert (after.st_ino,after.st_size,after.st_mtime_ns)==(before.st_ino,before.st_size,before.st_mtime_ns)
    assert after.st_ctime_ns!=before.st_ctime_ns
    assert hashlib.sha256(path.read_bytes()).hexdigest()!=library.state['digests'][path.name]
    manifest=library.path.read_bytes()
    results=library.search('prompt injection')
    assert results and all(r['title']!=changed for r in results)
    assert library.snapshot()['state']=='needs_review' and library.fallback
    assert library.path.read_bytes()==manifest


def test_change_during_digest_verification_is_refused(library):
    import hashlib
    path=library._generation(library.state['active']);library.verified.clear()
    real=hashlib.file_digest
    def changed(handle,algorithm):
        result=real(handle,algorithm)
        with path.open('r+b') as writer:
            writer.seek(5000);byte=writer.read(1);writer.seek(5000);writer.write(bytes([byte[0]^0xff]))
        return result
    with patch('megalodon.knowledge.hashlib.file_digest',changed),patch('megalodon.knowledge.sqlite3.connect') as connect:
        assert library.search('network')
        connect.assert_not_called()
    assert library.fallback and library.snapshot()['error']==FALLBACK_MESSAGE


def test_change_during_query_discards_projection_and_closes_connection(library):
    path=library._generation(library.state['active']);opened=[];real=sqlite3.connect
    class ChangedConnection(sqlite3.Connection):
        def execute(self,sql,*args,**kwargs):
            cursor=super().execute(sql,*args,**kwargs)
            if sql=='SELECT * FROM sources':
                with path.open('r+b') as writer:
                    writer.seek(5000);byte=writer.read(1);writer.seek(5000);writer.write(bytes([byte[0]^0xff]))
            return cursor
    def connect(*args,**kwargs):
        db=real(*args,**kwargs,factory=ChangedConnection);opened.append(db);return db
    with patch('megalodon.knowledge.sqlite3.connect',connect):status=library.snapshot()
    assert library.fallback and status['state']=='needs_review' and status['sources']==library.seed['sources']
    assert opened
    for db in opened:
        with pytest.raises(sqlite3.ProgrammingError,match='closed'):db.execute('SELECT 1')


def test_restored_bytes_do_not_silently_clear_fallback(library):
    good=library.state['active'];path=library._generation(good);original=path.read_bytes()
    with path.open('r+b') as handle:handle.seek(5000);handle.write(b'!')
    status=library.snapshot();assert library.fallback
    path.write_bytes(original)
    with patch.object(library,'_db',side_effect=AssertionError('Read attempted implicit recovery')):
        assert library.snapshot()['generation']==status['generation']
        assert library.search('network') and library.for_pattern('OBSERVED_ACTIVITY')
    assert library.fallback and library.state['active']==good


@pytest.mark.parametrize('failure',['missing','unreadable','invalid','save'])
def test_failed_activation_preserves_fallback_and_recovery_metadata(library,failure,monkeypatch):
    from copy import deepcopy
    damage_active(library);library.snapshot()
    candidate=library._build(library.seed['entries'],library.seed['sources'],{})
    path=library._generation(candidate)
    if failure=='missing':path.unlink()
    elif failure=='unreadable':
        original=library._content_digest
        def unreadable(target,identity):
            if target==path:raise OSError('PRIVATE_CANDIDATE_PATH')
            return original(target,identity)
        monkeypatch.setattr(library,'_content_digest',unreadable)
    elif failure=='invalid':path.write_bytes(b'not a SQLite index')
    else:monkeypatch.setattr(library,'_save',lambda:(_ for _ in ()).throw(OSError('disk full')))
    before=deepcopy(library.state);manifest=library.path.read_bytes()
    with pytest.raises((OSError,ValueError,sqlite3.Error)):library._activate(candidate)
    assert library.state==before and library.path.read_bytes()==manifest and library.fallback
    assert library.snapshot()['error']==FALLBACK_MESSAGE


@pytest.mark.parametrize('recovery',['rollback','update'])
def test_explicit_validated_recovery_clears_live_fallback(library,recovery):
    good,damaged=damage_active(library)
    fallback=library.snapshot()['generation']
    if recovery=='rollback':
        status=library.action({'action':'rollback'})
        assert library.state['active']==good and damaged.exists()
    else:
        with kev_only(library):library._update()
        status=library.snapshot()
        assert library.state['previous']==good and library._generation(good).exists() and not damaged.exists()
    assert not library.fallback and status['state']=='ready' and status['error'] is None
    assert status['generation']!=fallback and status['generation']==library.state['active']
    assert library.search('network' if recovery=='rollback' else 'Vuln')


def test_failed_rollback_and_update_keep_starter_identity_and_warning(library):
    good,damaged=damage_active(library)
    status=library.snapshot();manifest=library.path.read_bytes()
    previous=library._generation(good)
    with previous.open('r+b') as handle:handle.seek(5000);handle.write(b'!')
    with pytest.raises(ValueError):library.action({'action':'rollback'})
    assert library.path.read_bytes()==manifest
    library.downloader=lambda *a,**k:(_ for _ in ()).throw(ValueError('PRIVATE_DOWNLOAD_FAILURE'))
    library._update()
    library.action({'action':'configure','enabled':False})
    current=library.snapshot()
    assert library.fallback and current['state']=='needs_review' and current['error']==FALLBACK_MESSAGE
    assert current['generation']==status['generation']
    assert library.state['active']==damaged.name and library.state['previous']==good


def test_structural_limits_precede_json_materialization():
    from megalodon.knowledge_sources import bounded_json
    raw=b'{"padding":['+b'{},'*300001+b'{}]}'
    with patch('megalodon.knowledge_sources.json.loads') as decode:
        with pytest.raises(ValueError,match='structure'):bounded_json(raw)
        assert not decode.called
    with pytest.raises(ValueError,match='structure'):bounded_json(b'['*33+b'0'+b']'*33)
    with pytest.raises(ValueError,match='nesting'):parse('atlas',b'a: '+b'['*33+b'0'+b']'*33)


def test_multibyte_json_cannot_bypass_structure_preflight():
    from megalodon.knowledge_sources import bounded_json
    text=json.dumps({'a':'"','p':[{}]*110000,'q':[{}]*110000,'r':[{}]*110000,'z':'"'})
    for encoding in ('utf-16-le','utf-16-be','utf-32-le','utf-32-be'):
        with patch('megalodon.knowledge_sources.json.loads') as decode:
            with pytest.raises(ValueError,match='UTF-8'):bounded_json(text.encode(encoding))
            decode.assert_not_called()


def test_download_worker_has_outer_deadline_and_cancellation():
    import subprocess
    from threading import Event
    from unittest.mock import Mock
    worker=Mock();worker.communicate.side_effect=[subprocess.TimeoutExpired('fixed worker',.25),(b'',None)];worker.poll.return_value=None
    with patch('megalodon.knowledge_sources.subprocess.Popen',return_value=worker),patch('megalodon.knowledge_sources.time.monotonic',side_effect=[0,1,2,100]):
        with pytest.raises(ValueError,match='timed out'):fetch(SOURCES['attack']['url'],100)
    worker.kill.assert_called_once()
    stop=Event();stop.set()
    with patch('megalodon.knowledge_sources.subprocess.Popen') as spawn:
        with pytest.raises(ValueError,match='cancelled'):fetch(SOURCES['attack']['url'],100,stop=stop)
        spawn.assert_not_called()


def test_cancelled_build_never_activates(library):
    before=library.snapshot()['generation'];library.stop.set()
    with pytest.raises(ValueError,match='cancelled'):library._build(library.seed['entries'],library.seed['sources'],{})
    assert library.snapshot()['generation']==before


def test_download_worker_ignores_working_directory_modules(tmp_path,monkeypatch):
    import subprocess
    from megalodon import knowledge_sources
    marker=tmp_path/'planted-ran';(tmp_path/'json.py').write_text(f'open({str(marker)!r},"w").close()\n')
    monkeypatch.chdir(tmp_path)
    # A source-checkout launch; the isolated worker must not depend on this variable.
    monkeypatch.setenv('PYTHONPATH',str(Path(knowledge_sources.__file__).resolve().parents[1]))
    # The worker's own allowlist refuses this loopback URL before any connection.
    monkeypatch.setattr(knowledge_sources,'approved_url',lambda url:True)
    spawned=[];real=subprocess.Popen
    def spawn(command,**options):
        spawned.append((command,options));return real(command,**options)
    with patch('megalodon.knowledge_sources.subprocess.Popen',spawn):
        with pytest.raises(ValueError,match='unavailable'):fetch('https://127.0.0.1:9/unapproved',100)
    assert not marker.exists()
    command,options=spawned[0]
    assert options.get('cwd') not in {None,str(tmp_path)} and '-I' in command
    # The isolated worker still imports this package and exits cleanly on refusal.
    result=subprocess.run(command,cwd=options['cwd'],capture_output=True,timeout=30)
    assert (result.returncode,result.stdout,result.stderr)==(1,b'',b'')


def test_damaged_active_keeps_good_rollback_target(library):
    good=library.state['active']
    damaged=library._build(library.seed['entries'],library.seed['sources'],{});library._activate(damaged)
    with open(library._generation(damaged),'r+b') as handle:
        handle.seek(5000);value=handle.read(1);handle.seek(5000);handle.write(bytes([value[0]^0xFF]))
    reopened=KnowledgeLibrary(library.root.parents[3])
    assert reopened.fallback and reopened.state['previous']==good
    reopened._activate(reopened._build(reopened.seed['entries'],reopened.seed['sources'],{}))
    assert reopened.state['previous']==good and reopened._generation(good).exists()
    assert reopened.action({'action':'rollback'})['generation']==good
    reopened.close()


def kev_only(library):
    from megalodon.knowledge_sources import LICENSE_URLS
    kev=json.dumps(dict(catalogVersion='2026.10.01',count=1,vulnerabilities=[dict(cveID='CVE-2024-0001',vendorProject='V',
        product='P',shortDescription='s',requiredAction='a',dateAdded='2026-01-01',vulnerabilityName='Vuln')])).encode()
    bodies={LICENSE_URLS['kev']:b'license',SOURCES['kev']['url']:kev}
    library.downloader=lambda url,limit,etag=None,*,stop=None:(bodies[url],'"1"')
    return patch.multiple('megalodon.knowledge',SOURCES={'kev':SOURCES['kev']},
                          license_identity=lambda source,raw:library.seed['sources'][source]['license_sha256'])


def test_activation_reported_when_final_status_save_fails(library):
    before=library.state['active'];saved=library._save;calls=[]
    def save():
        calls.append(1)
        if len(calls)==2:raise OSError(28,'No space left on device')
        saved()
    with kev_only(library),patch.object(library,'_save',save):library._update()
    assert library.state['active']!=before and library.snapshot()['sources']['kev']['edition']=='2026.10.01'
    assert 'was activated' in library.state['error'] and 'not activated' not in library.state['error']


def test_shutdown_during_scheduled_update_leaves_slot_retryable(library):
    from threading import Event
    started=Event()
    def blocked(url,limit,etag=None,*,stop=None):
        started.set();stop.wait(10)
        raise ValueError('Knowledge download cancelled or timed out')
    library.downloader=blocked
    library.tick();assert started.wait(5)
    library.close()
    assert library.state['error'] is None and library.state['last_check'] is None
    restarted=KnowledgeLibrary(library.root.parents[3])
    assert restarted.snapshot()['state']=='ready' and restarted.state['last_check'] is None
    with patch.object(restarted,'update') as run:
        restarted.tick()
        assert run.call_count==1
    restarted.close()


def test_vanished_journal_does_not_break_usage(library,monkeypatch):
    journal=library.root/(library.state['active']+'-journal');journal.write_bytes(b'')
    real=Path.lstat
    def lstat(path,*args,**kwargs):
        if path.name.endswith('-journal'):raise FileNotFoundError(path)
        return real(path,*args,**kwargs)
    monkeypatch.setattr(Path,'lstat',lstat)
    assert library.usage()['used_bytes']>0 and library.snapshot()['used_bytes']>0


def test_attack_platform_context_survives_sql_search(library):
    technique = dict(type='attack-pattern', id='attack-pattern--example',
                     modified='2026-10-23T00:00:00Z', name='Synthetic reference',
                     description='Synthetic technique description.',
                     external_references=[dict(source_name='mitre-attack', external_id='T1046')],
                     x_mitre_platforms=['Windows', 'Linux', 'macOS', 'Linux'])
    rows, _ = parse('attack', json.dumps(dict(type='bundle', objects=[technique])).encode())
    generation = library._build(rows, library.seed['sources'], {})
    library._activate(generation)
    for platform in ('Windows', 'Linux', 'macOS'):
        hits = library.search(platform)
        assert len(hits) == 1
        assert hits[0]['context_only']
        assert 'not an observed host operating system' in hits[0]['excerpt']
    assert rows[0]['text'].count('Linux') == 1
    technique.pop('x_mitre_platforms')
    rows, _ = parse('attack', json.dumps(dict(type='bundle', objects=[technique])).encode())
    assert 'Source-listed platforms' not in rows[0]['text']
    for invalid in ('Linux', [None], ['x' * 65], ['Linux'] * 33):
        technique['x_mitre_platforms'] = invalid
        with pytest.raises(ValueError):
            parse('attack', json.dumps(dict(type='bundle', objects=[technique])).encode())
