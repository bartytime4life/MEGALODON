"""Knowledge admission preserves an available, local, data-only library."""
import json
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

from megalodon.knowledge import KnowledgeLibrary, CAP
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


def test_file_symlink_rejected(library,tmp_path):
    path=library._generation(library.state['active'])
    path.unlink();path.symlink_to(tmp_path/'external')
    with pytest.raises((ValueError,FileNotFoundError)):library.search('network')


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
