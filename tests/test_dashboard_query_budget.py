"""Bound SQLite work without returning partial or misleading dashboard data."""
from datetime import datetime, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import sqlite3
from threading import Event, Thread

import pytest

from megalodon.dashboard import DashboardHandler
from megalodon.models import PacketEvent
import megalodon.storage as storage


@pytest.fixture
def audit(tmp_path):
    path = tmp_path / 'private' / 'audit.db'
    with storage.Store(path) as writer:
        event = PacketEvent(datetime(2026, 1, 1, tzinfo=timezone.utc),
                            '192.0.2.1', '198.51.100.2', 'TCP')
        event_id = writer.record_event(event)
        writer.connection.executemany(
            'INSERT INTO detections (event_id, detected_at, rule_id, severity, '
            'src_ip, dst_ip, message, evidence_json, recommendation) '
            "VALUES (?, ?, 'TEST', 'HIGH', ?, ?, 'synthetic', '{}', 'ALERT')",
            [(event_id, event.observed_at.isoformat(), event.src_ip, event.dst_ip)] * 500,
        )
        writer.connection.commit()
        with storage.DashboardStore(path) as reader:
            yield path, writer, reader


@pytest.mark.parametrize('method', ['summary', 'recent'])
def test_vm_budget_aborts_real_sql_and_next_read_recovers(audit, monkeypatch, method):
    _, writer, reader = audit
    before = writer.summary()
    with monkeypatch.context() as patch:
        patch.setattr(storage, 'DASHBOARD_QUERY_PROGRESS_STEPS', 1)
        patch.setattr(storage, 'DASHBOARD_QUERY_VM_STEPS', 5)
        with pytest.raises(storage.StorageSchemaError,
                           match='^DASHBOARD_STORE:READ_BUDGET_EXCEEDED$'):
            getattr(reader, method)()
        assert not reader._connection.in_transaction
        # Callback was removed, even though the reduced limit remains in effect.
        assert reader._connection.execute('SELECT COUNT(*) FROM detections').fetchone()[0] == 500
    assert writer.summary() == before
    assert reader.summary()['detections'] == 500
    assert len(reader.recent()) == 50
    assert reader._connection.execute('PRAGMA query_only').fetchone()[0] == 1
    with pytest.raises(sqlite3.DatabaseError):
        reader._connection.execute('SELECT evidence_json FROM detections')
    with pytest.raises(sqlite3.DatabaseError):
        reader._connection.execute('DELETE FROM detections')


@pytest.mark.parametrize('method', ['summary', 'recent'])
@pytest.mark.parametrize('progress_interval', [1, 10_000_000])
def test_deadline_covers_callbacks_and_short_queries(audit, monkeypatch, method, progress_interval):
    _, _, reader = audit
    clock = iter([100.0, 102.0])
    with monkeypatch.context() as patch:
        patch.setattr(storage, 'DASHBOARD_QUERY_PROGRESS_STEPS', progress_interval)
        patch.setattr(storage, 'monotonic', lambda: next(clock, 102.0))
        with pytest.raises(storage.StorageSchemaError,
                           match='^DASHBOARD_STORE:READ_BUDGET_EXCEEDED$'):
            getattr(reader, method)()
    assert reader.summary()['detections'] == 500


@pytest.mark.parametrize('failure', [KeyboardInterrupt, RuntimeError, sqlite3.OperationalError])
def test_fetch_failure_always_clears_budget_and_releases_lock(audit, monkeypatch, failure):
    _, _, reader = audit
    def fail_row(*_):
        raise failure('PRIVATE_MARKER')
    original = reader._connection.row_factory
    reader._connection.row_factory = fail_row
    expected = storage.StorageSchemaError if failure is sqlite3.OperationalError else failure
    with pytest.raises(expected):
        reader.recent()
    reader._connection.row_factory = original
    # A different thread proves lock release (RLock reacquisition in the same
    # thread would not prove it). A subsequent read proves callback reset.
    results = []
    thread = Thread(target=lambda: results.append(reader.summary()))
    thread.start()
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert results[0]['detections'] == 500


@pytest.mark.parametrize('method', ['summary', 'recent'])
def test_concurrent_request_refuses_when_reader_is_occupied(audit, monkeypatch, method):
    _, _, reader = audit
    results = []
    # The test holds the real lock in this thread; the other thread must refuse
    # within its acquisition timeout without replacing an active callback.
    monkeypatch.setattr(storage, 'DASHBOARD_READ_LOCK_SECONDS', 0.01)
    def read():
        try:
            getattr(reader, method)()
        except storage.StorageSchemaError as error:
            results.append(str(error))
    with reader._lock:
        thread = Thread(target=read)
        thread.start()
        thread.join(timeout=2)
        assert not thread.is_alive()
    assert results == ['DASHBOARD_STORE:READ_BUSY']
    assert reader.summary()['detections'] == 500


def test_busy_timeout_changes_only_dashboard_connections(audit):
    _, writer, reader = audit
    assert writer.connection.execute('PRAGMA busy_timeout').fetchone()[0] == 10000
    # Inspect the internal connection with only this pragma added by the test;
    # production authorizer deliberately does not allow arbitrary pragmas.
    original = reader._authorize
    def authorize(action, first, second, database, source):
        if action == sqlite3.SQLITE_PRAGMA and first == 'busy_timeout' and second is None:
            return sqlite3.SQLITE_OK
        return original(action, first, second, database, source)
    reader._connection.set_authorizer(authorize)
    try:
        assert reader._connection.execute('PRAGMA busy_timeout').fetchone()[0] == 250
    finally:
        reader._install_authorizer()


def test_default_budget_stops_large_summary_but_keeps_indexed_recent_available(audit):
    _, writer, reader = audit
    # Use one transaction; these are synthetic metadata rows, not sensor traffic.
    writer.connection.execute(
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<260000) "
        "INSERT INTO detections (event_id, detected_at, rule_id, severity, src_ip, "
        "dst_ip, message, evidence_json, recommendation) "
        "SELECT 1, '2026-01-01T00:00:00+00:00', 'TEST', 'HIGH', '192.0.2.1', "
        "'198.51.100.2', 'synthetic', '{}', 'ALERT' FROM n"
    )
    writer.connection.commit()
    with pytest.raises(storage.StorageSchemaError,
                       match='^DASHBOARD_STORE:READ_BUDGET_EXCEEDED$'):
        reader.summary()
    assert len(reader.recent(200)) == 200
    assert not reader._connection.in_transaction


@pytest.mark.parametrize('route', ['/api/summary', '/api/events'])
def test_http_budget_refusal_is_503_without_partial_data_and_recovers(audit, monkeypatch, route):
    _, _, reader = audit
    handler = type('BudgetTestHandler', (DashboardHandler,), {'store': reader})
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
    thread.start()
    client = HTTPConnection('127.0.0.1', server.server_port, timeout=3)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(storage, 'DASHBOARD_QUERY_PROGRESS_STEPS', 1)
            patch.setattr(storage, 'DASHBOARD_QUERY_VM_STEPS', 5)
            client.request('GET', route)
            response = client.getresponse()
            assert response.status == 503
            assert response.getheader('Cache-Control') == 'no-store'
            assert json.loads(response.read()) == {'error': 'telemetry unavailable'}
        client.request('GET', route)
        response = client.getresponse()
        assert response.status == 200
        assert json.loads(response.read())
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()
