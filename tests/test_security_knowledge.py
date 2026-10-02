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
