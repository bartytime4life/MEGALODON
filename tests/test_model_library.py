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
        assert store.connection.execute('PRAGMA user_version').fetchone() == (1,)
        assert (root / 'library.sqlite3').stat().st_mode & 0o777 == 0o600
        with pytest.raises(library.LibraryError) as error: library._Store(root)
        assert error.value.code == 'BUSY'
    with library._Store(root) as store:
        store.connection.execute('CREATE TABLE unexpected(value)')
        store.connection.commit()
    with pytest.raises(library.LibraryError): library._Store(root)


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
