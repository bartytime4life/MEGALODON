"""Pinned transfers, private staging and bounded SQLite job outcomes.

Orchestration tests isolate the store admission with a real tiny SQLite fixture;
the native tests below exercise the actual descriptor/ownership/flock boundary.
No test downloads weights or contacts an external server.
"""
from contextlib import contextmanager
from dataclasses import replace
from email.message import Message
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from threading import Event
import time
from types import SimpleNamespace

import pytest

from megalodon import model_library as library
from megalodon.support_config import validate_action

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux-only private staging implementation')


DATA = b"GGUF synthetic inert file\x00" * 4096


@pytest.fixture
def staged(tmp_path, monkeypatch):
    entry = replace(library.CATALOG[0], size=len(DATA), digest=sha256(DATA).hexdigest())
    monkeypatch.setattr(library, "CATALOG", (entry,))
    model = library.ModelLibrary(tmp_path)
    model.root.mkdir(parents=True, mode=0o700)
    original = library._Store

    class FixtureStore:
        def __init__(self, root):
            self.directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            self.connection = sqlite3.connect(root / "fixture.sqlite3")
            if not self.connection.execute("SELECT name FROM sqlite_master").fetchall():
                self.connection.execute(library._MODEL_SQL)
                self.connection.execute(library._JOB_SQL)
                self.connection.execute(library._LOCAL_SQL)
                self.connection.commit()

        job = original.job
        model = original.model

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.connection.close()
            os.close(self.directory)

    monkeypatch.setattr(library, "_Store", FixtureStore)
    calls = []

    @contextmanager
    def response(*args):
        calls.append(args[0].id)
        yield SimpleNamespace(read1=io.BytesIO(DATA).read)

    monkeypatch.setattr(library, "_response", response)
    return model, entry, calls


def query(model, sql):
    with sqlite3.connect(model.root / "fixture.sqlite3") as connection:
        return connection.execute(sql).fetchall()


def test_init_and_snapshot_have_no_files_network_or_model_use(tmp_path, monkeypatch):
    monkeypatch.setattr(library, "_Store", lambda *_: pytest.fail("passive store open"))
    monkeypatch.setattr(library, "_response", lambda *_: pytest.fail("passive network"))
    model = library.ModelLibrary(tmp_path)
    assert model.snapshot()["state"] == "unchecked"
    assert not model.root.exists()
    copy = model.snapshot()
    copy["catalog"].clear()
    assert model.snapshot()["catalog"]


def test_store_refuses_ambiguous_home_before_any_file_access(tmp_path, monkeypatch):
    monkeypatch.setattr(library.storage, '_open_private_directory', lambda *_a, **_kw: pytest.fail('ambiguous path opened'))
    with pytest.raises(library.storage.StorageSchemaError, match='AMBIGUOUS_PATH'):
        library._Store(tmp_path / '..' / 'elsewhere')


@pytest.mark.parametrize('tables', [(), ('models',), ('jobs',), ('models','jobs')])
def test_known_empty_interrupted_schema_initialization_recovers_atomically(tmp_path, tables):
    path = tmp_path / 'inert.sqlite3'
    path.touch()  # Also exercise an already-existing zero-byte database.
    with sqlite3.connect(path) as connection:
        for name in tables:
            connection.execute(library._MODEL_SQL if name == 'models' else library._JOB_SQL)
        connection.commit()
        library._admit_schema(connection)
        assert connection.execute('PRAGMA user_version').fetchone() == (2,)
        assert connection.execute('SELECT count(*) FROM models').fetchone() == (0,)
        assert connection.execute('SELECT count(*) FROM jobs').fetchone() == (0,)
    with sqlite3.connect(path) as connection:
        library._admit_schema(connection)
        assert connection.execute('PRAGMA user_version').fetchone() == (2,)


def test_interrupted_initialization_rolls_back_all_schema_writes(tmp_path):
    path = tmp_path / 'inert.sqlite3'
    connection = sqlite3.connect(path)
    connection.set_authorizer(lambda action, *_: sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_CREATE_TABLE and _[0] == 'jobs' else sqlite3.SQLITE_OK)
    with pytest.raises(sqlite3.DatabaseError): library._admit_schema(connection)
    connection.close()
    with sqlite3.connect(path) as connection:
        assert connection.execute('SELECT name FROM sqlite_master').fetchall() == []
        assert connection.execute('PRAGMA user_version').fetchone() == (0,)
        library._admit_schema(connection)


@pytest.mark.parametrize('kind', ['unknown','populated','wrong_version','changed_sql'])
def test_schema_recovery_never_resets_unknown_or_populated_data(tmp_path, kind):
    with sqlite3.connect(tmp_path / 'inert.sqlite3') as connection:
        if kind == 'unknown': connection.execute('CREATE TABLE unrelated(value)')
        elif kind == 'changed_sql': connection.execute('CREATE TABLE models(value)')
        else:
            connection.execute(library._MODEL_SQL)
            if kind == 'populated': connection.execute("INSERT INTO models VALUES ('x','missing','x',1,1)")
            else: connection.execute('PRAGMA user_version=3')
        connection.commit()
        before = connection.execute('SELECT name,sql FROM sqlite_master').fetchall()
        with pytest.raises(library.LibraryError): library._admit_schema(connection)
        assert connection.execute('SELECT name,sql FROM sqlite_master').fetchall() == before


def test_schema_admission_rejects_trigger_with_a_known_table_name(tmp_path):
    with sqlite3.connect(tmp_path / 'inert.sqlite3') as connection:
        library._admit_schema(connection)
        connection.execute('CREATE TRIGGER jobs AFTER INSERT ON jobs BEGIN SELECT 1; END')
        connection.commit()
        with pytest.raises(library.LibraryError): library._admit_schema(connection)


def test_stage_verify_sqlite_readback_and_reuse_without_second_transfer(staged):
    model, entry, calls = staged
    assert "not been imported" in model.execute(entry.id)
    file = model.root / (entry.id + ".gguf")
    assert file.read_bytes() == DATA
    assert file.stat().st_mode & 0o777 == 0o600
    assert file.stat().st_nlink == 1
    assert query(model, "SELECT state,sha256,size_bytes FROM models") == [("staged_verified", entry.digest, len(DATA))]
    assert query(model, "SELECT state,bytes_received,error_code FROM jobs") == [("staged_verified", len(DATA), None)]
    assert not list(model.root.glob("*.part"))
    model.execute(entry.id)
    assert calls == [entry.id]
    assert len(model.snapshot()["jobs"]) == 2
    assert "http" not in json.dumps(model.snapshot()["jobs"])


def test_explicit_check_is_local_and_checks_files_before_receipts(staged):
    model, entry, calls = staged
    model.execute()
    assert calls == []
    assert model.snapshot()["models"][0]["state"] == "missing"
    model.execute(entry.id)
    (model.root / (entry.id + ".gguf")).write_bytes(b"X" * len(DATA))
    with pytest.raises(library.LibraryError, match="pinned SHA"):
        model.execute()
    assert query(model, "SELECT state FROM models") == [("unverified",)]
    assert calls == [entry.id]


@pytest.mark.parametrize("kind", ["short", "oversized", "digest", "disconnect", "cancel", "deadline"])
def test_failure_never_publishes_verified_file_and_removes_owned_partial(staged, monkeypatch, kind):
    model, entry, _ = staged
    @contextmanager
    def response(*_):
        body = io.BytesIO(DATA[:-1] if kind == "short" else b"X" * len(DATA) if kind == "digest" else DATA)
        def read(size):
            if kind == "oversized":
                return b"X" * (size + 1)
            if kind == "disconnect":
                raise ConnectionResetError("never log this remote URL or secret")
            if kind == "cancel":
                model.cancel()
            if kind == "deadline":
                monkeypatch.setattr(library.time, "monotonic", lambda: float("inf"))
            return body.read(size)
        yield SimpleNamespace(read1=read)
    monkeypatch.setattr(library, "_response", response)
    with pytest.raises(library.LibraryError) as error:
        model.execute(entry.id)
    expected = {"short":"SIZE", "oversized":"SIZE", "digest":"DIGEST", "disconnect":"NETWORK", "cancel":"CANCELLED", "deadline":"DEADLINE"}[kind]
    assert error.value.code == expected
    assert not list(model.root.glob("*.part")) and not list(model.root.glob("*.gguf"))
    assert query(model, "SELECT state,error_code FROM jobs") == [("cancelled" if kind == "cancel" else "failed", expected)]
    assert "secret" not in json.dumps(model.snapshot())
    assert model.snapshot()["active"]["error_code"] == expected


def test_cancel_before_worker_start_is_not_lost(staged):
    model, entry, calls = staged
    model.prepare()
    model.cancel()
    with pytest.raises(library.LibraryError) as error:
        model.execute(entry.id)
    assert error.value.code == "CANCELLED"
    assert not calls
    model.prepare()
    model.execute(entry.id)
    assert calls == [entry.id]


def test_no_space_or_full_history_refuses_before_network(staged, monkeypatch):
    model, entry, calls = staged
    monkeypatch.setattr(library.os, "fstatvfs", lambda *_: SimpleNamespace(f_bavail=0, f_frsize=4096))
    with pytest.raises(library.LibraryError) as error:
        model.execute(entry.id)
    assert error.value.code == "NO_SPACE" and not calls
    monkeypatch.setattr(library, "MAX_JOBS", 1)
    with pytest.raises(library.LibraryError) as error:
        model.execute(entry.id)
    assert error.value.code == "JOB_LIMIT" and not calls


def test_interrupted_job_is_not_resumed_and_verified_orphan_is_rechecked(staged):
    model, entry, calls = staged
    model.execute()
    with library._Store(model.root) as store:
        store.job("a" * 32, entry, "downloading", 3)
    (model.root / (entry.id + ".part")).write_bytes(b"abc")
    (model.root / (entry.id + ".part")).chmod(0o600)
    model.execute()
    assert not calls
    assert query(model, "SELECT state,error_code FROM jobs") == [("interrupted", "INTERRUPTED")]
    assert not list(model.root.glob("*.part"))
    orphan = model.root / (entry.id + ".gguf")
    orphan.write_bytes(DATA)
    orphan.chmod(0o600)
    model.execute()
    assert model.snapshot()["models"][0]["state"] == "staged_verified"
    assert not calls


def test_publication_crash_with_exactly_two_owned_names_is_reconciled(staged):
    model, entry, calls = staged
    part, final = model.root / (entry.id + '.part'), model.root / (entry.id + '.gguf')
    part.write_bytes(DATA)
    part.chmod(0o600)
    os.link(part, final)
    model.execute()
    assert not part.exists() and final.stat().st_nlink == 1
    assert model.snapshot()['models'][0]['state'] == 'staged_verified'
    assert not calls


@pytest.mark.parametrize("shape", ["symlink", "hardlink", "fifo", "public", "directory"])
def test_unsafe_final_refused_without_touching_target(staged, tmp_path, shape):
    model, entry, calls = staged
    target = tmp_path / "unrelated"
    target.write_bytes(DATA)
    target.chmod(0o600)
    final = model.root / (entry.id + ".gguf")
    if shape == "symlink": final.symlink_to(target)
    elif shape == "hardlink": os.link(target, final)
    elif shape == "fifo": os.mkfifo(final, 0o600)
    elif shape == "directory": final.mkdir()
    else:
        final.write_bytes(DATA)
        final.chmod(0o644)
    with pytest.raises(library.LibraryError): model.execute(entry.id)
    assert target.read_bytes() == DATA
    assert not calls
    assert query(model, "SELECT state FROM models") == [("unverified",)]


def test_written_bytes_are_read_back_before_success(staged, monkeypatch):
    model, entry, _ = staged
    original = os.write
    def corrupt(fd, value):
        return original(fd, b"X" * len(value))
    monkeypatch.setattr(library.os, "write", corrupt)
    with pytest.raises(library.LibraryError) as error: model.execute(entry.id)
    assert error.value.code == "DIGEST"
    assert query(model, "SELECT state FROM models") == [("unverified",)]
    assert query(model, "SELECT state FROM jobs") == [("failed",)]


@pytest.mark.parametrize("url", ["http://huggingface.co/x", "https://evil.invalid/x", "https://huggingface.co.evil.invalid/x", "https://user:secret@huggingface.co/x", "https://huggingface.co:444/x", "https://huggingface.co/x#fragment", "https://127.0.0.1/x", "https://huggingface.co/x\nHeader:x", "https://huggingface.co/" + "x" * 8192])
def test_closed_https_url_policy(url):
    with pytest.raises(library.LibraryError): library._url(url)


@pytest.mark.parametrize("status,headers", [(206, []), (200, []), (200, [("Content-Length","1")]), (200, [("Transfer-Encoding","chunked")]), (200, [("Content-Encoding","gzip")]), (302, [("Location","https://evil.invalid/file")])])
def test_transport_rejects_status_headers_and_redirect_before_next_connection(monkeypatch, status, headers):
    entry = library.CATALOG[0]
    connections = []
    class FakeConnection:
        def __init__(self, host, *_a, **_kw): connections.append(host)
        def request(self, *_a, **_kw): pass
        def getresponse(self):
            message = Message()
            if headers: message['Content-Length'] = str(entry.size)
            for key, value in headers: message[key] = value
            return SimpleNamespace(status=status, headers=message, close=lambda:None)
        def close(self): pass
    monkeypatch.setattr(library, "_PinnedHTTPS", FakeConnection)
    with pytest.raises(library.LibraryError):
        with library._response(entry, Event(), time.monotonic() + 20): pytest.fail("unaccepted body")
    assert connections == ['huggingface.co']


def test_transport_bounded_redirects_exact_headers_no_auth_or_ambient_proxy(monkeypatch):
    entry = library.CATALOG[0]
    requests = []
    class FakeConnection:
        def __init__(self, host, *_a, **_kw): self.host = host
        def request(self, method, path, headers): requests.append((self.host, method, path, headers))
        def getresponse(self):
            headers = Message()
            if len(requests) == 1:
                headers['Location'] = 'https://us.aws.cdn.hf.co/model?signature=do-not-persist'
                return SimpleNamespace(status=302, headers=headers, close=lambda:None)
            headers['Content-Length'] = str(entry.size)
            return SimpleNamespace(status=200, headers=headers, close=lambda:None)
        def close(self): pass
    monkeypatch.setattr(library, "_PinnedHTTPS", FakeConnection)
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.invalid")
    monkeypatch.setenv("HF_TOKEN", "secret")
    with library._response(entry, Event(), time.monotonic() + 20) as response: assert response.status == 200
    assert [r[0] for r in requests] == ['huggingface.co', 'us.aws.cdn.hf.co']
    assert all(set(r[3]) == {'Accept-Encoding', 'User-Agent'} for r in requests)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0", "224.0.0.1"])
def test_dns_cannot_redirect_fixed_host_to_local_service(monkeypatch, address):
    monkeypatch.setattr(library.socket, "getaddrinfo", lambda *_a, **_kw: [(2, 1, 6, '', (address, 443))])
    monkeypatch.setattr(library.socket, "socket", lambda *_: pytest.fail("private connection"))
    with pytest.raises(library.LibraryError): library._PinnedHTTPS('huggingface.co').connect()


@pytest.mark.parametrize("body", [
    {'action':'model_stage_download','catalog_id':'../evil'},
    {'action':'model_stage_download','catalog_id':[]},
    {'action':'model_stage_download','catalog_id':'latest'},
    {'action':'model_stage_download','catalog_id':library.CATALOG[0].id,'url':'https://evil.invalid'},
    {'action':'model_library_check','path':'/tmp/model'},
    {'action':'model_stage_cancel','command':'anything'},
])
def test_browser_cannot_supply_paths_urls_commands_or_unknown_catalog_ids(body):
    with pytest.raises(ValueError): validate_action(body)


def test_native_private_sqlite_modes_flock_and_schema(private_tmp_path):
    root = private_tmp_path / 'model-library'
    with library._Store(root) as store:
        assert store.connection.execute('PRAGMA user_version').fetchone() == (2,)
        assert (root / 'library.sqlite3').stat().st_mode & 0o777 == 0o600
        with pytest.raises(library.LibraryError) as error: library._Store(root)
        assert error.value.code == 'BUSY'
    with library._Store(root) as store:
        store.connection.execute('CREATE TABLE unexpected(value)')
        store.connection.commit()
    with pytest.raises(library.LibraryError): library._Store(root)


def test_native_first_connect_interruption_recovers_existing_zero_byte_database(private_tmp_path, monkeypatch):
    root = private_tmp_path / 'model-library'
    def interrupted(*_a, **_kw): raise OSError('synthetic initial connect interruption')
    with monkeypatch.context() as patch:
        patch.setattr(library.storage, '_connect_verified_sqlite', interrupted)
        with pytest.raises(OSError): library._Store(root)
    assert (root / 'library.sqlite3').stat().st_size == 0
    with library._Store(root) as store:
        assert store.connection.execute('PRAGMA user_version').fetchone() == (2,)


def test_native_stage_end_to_end(private_tmp_path, monkeypatch):
    entry = replace(library.CATALOG[0], size=len(DATA), digest=sha256(DATA).hexdigest())
    monkeypatch.setattr(library, 'CATALOG', (entry,))
    @contextmanager
    def response(*_): yield SimpleNamespace(read1=io.BytesIO(DATA).read)
    monkeypatch.setattr(library, '_response', response)
    model = library.ModelLibrary(private_tmp_path)
    model.execute(entry.id)
    assert model.snapshot()['state'] == 'staged_verified'
    model = library.ModelLibrary(private_tmp_path)
    model.execute()
    assert model.snapshot()['models'][0]['state'] == 'staged_verified'


@pytest.fixture
def existing(staged):
    model, entry, calls = staged
    root = model.home / '.ollama/models'
    manifest = root / 'manifests/registry.ollama.ai/library/local-fixture/fixed'
    manifest.parent.mkdir(parents=True)
    blobs = root / 'blobs'
    blobs.mkdir()
    rows = []
    for media, data in [('application/vnd.docker.container.image.v1+json', b'{}'),
                        ('application/vnd.ollama.image.model', b'inert existing weights')]:
        digest = sha256(data).hexdigest()
        (blobs / ('sha256-' + digest)).write_bytes(data)
        rows.append(dict(mediaType=media, digest='sha256:' + digest, size=len(data)))
    manifest.write_text(json.dumps(dict(schemaVersion=2, mediaType='application/vnd.docker.distribution.manifest.v2+json',
                                       config=rows[0], layers=rows[1:])))
    provider = model.home / 'ollama'
    provider.write_bytes(b'inert provider never executed')
    provider.chmod(0o700)
    pin = sha256(manifest.read_bytes()).hexdigest()
    return model, manifest, provider, pin, calls


def reuse(existing, **kw):
    model, _, provider, pin, _ = existing
    return model.reuse('user', 'local-fixture:fixed', pin, provider, **kw)


def test_existing_model_reference_uses_real_verifier_without_copy_network_or_provider(existing, monkeypatch):
    import socket
    import subprocess
    from megalodon import local_model_runtime
    model, manifest, provider, pin, calls = existing
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in manifest.parents[4].rglob('*') if p.is_file()}
    def forbidden(*_a, **_kw): pytest.fail('offline reuse attempted network, process or download')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(library, '_response', forbidden)
    assert 'referenced in place' in reuse(existing)
    row = model.snapshot()['local_models'][0]
    assert row['state'] == 'files_verified' and row['manifest_sha256'] == pin
    assert row['provider_sha256'] == sha256(provider.read_bytes()).hexdigest()
    assert row['verified_bytes'] > 0 and row['error_code'] is None
    assert not calls and not list(model.root.glob('*.gguf'))
    assert all((p.read_bytes(), p.stat().st_mtime_ns) == value for p, value in before.items())
    assert local_model_runtime.binding_failure() == 'OWNER_MODEL_BINDING_NOT_RECORDED'
    assert str(model.home) not in json.dumps(model.snapshot())
    assert query(model, 'SELECT count(*) FROM jobs') == [(0,)]


@pytest.mark.parametrize('failure,expected', [('missing', 'FILES_UNAVAILABLE'), ('corrupt', 'MANIFEST'),
    ('changed_identity', 'IDENTITY'), ('component', 'DIGEST'), ('provider', 'FILES_UNAVAILABLE')])
def test_reuse_failure_clears_old_verification_and_never_downloads(existing, failure, expected):
    model, manifest, provider, pin, calls = existing
    reuse(existing)
    if failure == 'missing': manifest.unlink()
    elif failure == 'provider': provider.unlink()
    elif failure == 'corrupt':
        manifest.write_bytes(b'{broken manifest')
        pin = sha256(manifest.read_bytes()).hexdigest()
    elif failure == 'changed_identity': manifest.write_bytes(manifest.read_bytes() + b' ')
    else:
        row = json.loads(manifest.read_bytes())['layers'][0]
        (manifest.parents[4] / 'blobs' / row['digest'].replace(':', '-')).write_bytes(b'X' * row['size'])
    with pytest.raises(library.LibraryError) as exc:
        model.reuse('user', 'local-fixture:fixed', pin, provider)
    assert exc.value.code == expected
    row = model.snapshot()['local_models'][0]
    assert row['state'] == 'failed' and row['error_code'] == expected
    assert row['provider_sha256'] is None and row['verified_bytes'] == 0 and not calls


def test_changed_manifest_during_read_is_refused(existing, monkeypatch):
    model, manifest, _, _, calls = existing
    original = library.model_artifact._Reader.read
    def read(self, directory, name, *args, **kwargs):
        result = original(self, directory, name, *args, **kwargs)
        if name.startswith('sha256-'): manifest.write_bytes(manifest.read_bytes() + b' ')
        return result
    monkeypatch.setattr(library.model_artifact._Reader, 'read', read)
    with pytest.raises(library.LibraryError) as exc: reuse(existing)
    assert exc.value.code == 'FILE' and not calls
    assert model.snapshot()['local_models'][0]['state'] == 'failed'


def test_reuse_crash_and_explicit_recovery_never_resume_verification_or_network(existing, monkeypatch):
    model, _, _, _, calls = existing
    class Crash(BaseException): pass
    def crash(*_a, **_kw): raise Crash()
    monkeypatch.setattr(library.model_artifact, 'observe_artifact', crash)
    with pytest.raises(Crash): reuse(existing)
    assert query(model, 'SELECT state FROM local_models') == [('verifying',)]
    replacement = library.ModelLibrary(model.home)
    assert replacement.snapshot()['local_models'] == []
    # Same fixture database; no observer called during explicit offline recovery.
    replacement.execute()
    assert replacement.snapshot()['local_models'][0]['state'] == 'interrupted'
    assert replacement.snapshot()['local_models'][0]['error_code'] == 'INTERRUPTED'
    assert not calls


def test_reuse_cancel_before_worker_does_not_touch_external_files(existing):
    model, _, _, _, calls = existing
    model.prepare()
    model.cancel()
    with pytest.raises(library.LibraryError) as exc: reuse(existing)
    assert exc.value.code == 'CHECK_CANCELLED' and not calls
    assert model.snapshot()['local_models'][0]['state'] == 'interrupted'
    model.prepare()
    reuse(existing)
    assert model.snapshot()['local_models'][0]['state'] == 'files_verified'


def test_reuse_commit_failure_never_projects_verified_and_restart_requires_recheck(existing, monkeypatch):
    model, _, _, _, calls = existing
    original = library._Store
    class DeniedStore(original):
        def __init__(self, root):
            super().__init__(root)
            self.connection.set_authorizer(lambda op, name, column, *_: sqlite3.SQLITE_DENY
                if op == sqlite3.SQLITE_UPDATE and name == 'local_models' and column == 'provider_sha256' else sqlite3.SQLITE_OK)
    with monkeypatch.context() as guard:
        guard.setattr(library, '_Store', DeniedStore)
        with pytest.raises(library.LibraryError) as exc: reuse(existing)
    assert exc.value.code == 'UNAVAILABLE' and model.snapshot()['local_models'] == []
    assert query(model, 'SELECT state,provider_sha256,verified_bytes FROM local_models') == [('verifying', None, 0)]
    model.execute()
    assert model.snapshot()['local_models'][0]['state'] == 'interrupted' and not calls


def test_local_reference_bound_allows_recheck_but_no_new_identity(existing, monkeypatch):
    model, _, provider, pin, calls = existing
    monkeypatch.setattr(library, 'MAX_LOCAL_MODELS', 1)
    reuse(existing)
    reuse(existing)
    with pytest.raises(library.LibraryError) as exc:
        model.reuse('user', 'another:fixed', pin, provider)
    assert exc.value.code == 'LOCAL_LIMIT'
    assert query(model, 'SELECT count(*) FROM local_models') == [(1,)] and not calls


@pytest.mark.parametrize('profile,seconds', [('standard', 120), ('large-local', 300)])
def test_reuse_deadline_is_recorded_without_network(existing, monkeypatch, profile, seconds):
    model, _, _, _, calls = existing
    ticks = iter([0, seconds + 1])
    monkeypatch.setattr(library.time, 'monotonic', lambda: next(ticks, seconds + 1))
    with pytest.raises(library.LibraryError) as exc: reuse(existing, profile=profile)
    assert exc.value.code == 'DEADLINE'
    assert model.snapshot()['local_models'][0]['error_code'] == 'DEADLINE' and not calls


def test_native_existing_model_reference_persists_privately_without_copy(private_tmp_path, monkeypatch):
    # Inert weights use the catalog's known digest; closure and provider are
    # still hashed by the real verifier, with the real private SQLite store.
    home = private_tmp_path
    folder = home / '.ollama/models/manifests/registry.ollama.ai/library/fixture'
    folder.mkdir(parents=True)
    blobs = home / '.ollama/models/blobs'
    blobs.mkdir()
    rows=[]
    for media,data in [('application/vnd.docker.container.image.v1+json',b'{}'),
                       ('application/vnd.ollama.image.model',b'inert')]:
        digest=sha256(data).hexdigest()
        (blobs/('sha256-'+digest)).write_bytes(data)
        rows.append(dict(mediaType=media,digest='sha256:'+digest,size=len(data)))
    raw=json.dumps(dict(schemaVersion=2,mediaType='application/vnd.docker.distribution.manifest.v2+json',config=rows[0],layers=rows[1:])).encode()
    (folder/'fixed').write_bytes(raw)
    provider=home/'ollama';provider.write_bytes(b'inert provider');provider.chmod(0o700)
    monkeypatch.setattr(library,'_response',lambda *_a,**_kw:pytest.fail('unexpected transfer'))
    model=library.ModelLibrary(home)
    model.reuse('user','fixture:fixed',sha256(raw).hexdigest(),provider)
    assert (model.root/'library.sqlite3').stat().st_mode & 0o777 == 0o600
    restored=library.ModelLibrary(home)
    assert restored.snapshot()['local_models']==[]
    restored.execute()
    assert restored.snapshot()['local_models'][0]['state']=='files_verified'
    assert not list(model.root.glob('*.gguf'))


def test_invalid_local_record_refuses_before_recovery_mutations_or_cleanup(staged):
    model, entry, calls = staged
    model.execute()
    part = model.root / (entry.id + '.part')
    part.write_bytes(b'keep')
    part.chmod(0o600)
    with library._Store(model.root) as store:
        store.job('f' * 32, entry, 'downloading', 1)
        store.connection.execute("INSERT INTO local_models VALUES ('user','model:fixed',?,NULL,0,'standard','unknown',NULL,1)", ('a' * 64,))
        store.connection.commit()
    with pytest.raises(library.LibraryError): model.execute()
    assert query(model, 'SELECT state FROM jobs') == [('downloading',)]
    assert part.read_bytes() == b'keep' and not calls


def test_v1_schema_migration_preserves_rows_and_rolls_back_if_interrupted(tmp_path):
    with sqlite3.connect(tmp_path / 'v1.sqlite3') as connection:
        connection.execute(library._MODEL_SQL)
        connection.execute(library._JOB_SQL)
        connection.execute('PRAGMA user_version=1')
        entry = library.CATALOG[0]
        connection.execute('INSERT INTO models VALUES (?,?,?,?,?)', (entry.id, 'missing', entry.digest, entry.size, 1))
        connection.commit()
        connection.set_authorizer(lambda op, name, *_: sqlite3.SQLITE_DENY
            if op == sqlite3.SQLITE_CREATE_TABLE and name == 'local_models' else sqlite3.SQLITE_OK)
        with pytest.raises(sqlite3.DatabaseError): library._admit_schema(connection)
        assert connection.execute('PRAGMA user_version').fetchone() == (1,)
        connection.set_authorizer(None)
        library._admit_schema(connection)
        assert connection.execute('PRAGMA user_version').fetchone() == (2,)
        assert connection.execute('SELECT catalog_id,state FROM models').fetchall() == [(entry.id, 'missing')]
        assert connection.execute('SELECT count(*) FROM local_models').fetchone() == (0,)


@pytest.mark.parametrize('change', [dict(store_id='/tmp/weights'), dict(model='model:latest'),
    dict(model='https://evil/model:tag'), dict(model_digest='no'), dict(verification_profile='unlimited'), dict(path='/tmp/model')])
def test_reuse_action_has_closed_scope_and_no_browser_paths(change):
    request = dict(action='model_library_reuse', store_id='user', model='model:fixed', model_digest='a' * 64,
                   verification_profile='standard')
    assert validate_action(request) == request
    with pytest.raises(ValueError): validate_action({**request, **change})
