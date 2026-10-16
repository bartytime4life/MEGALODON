"""A writing connection must open the admitted file, not whatever its name reaches.

On Linux the admitted descriptor is handed to SQLite as /proc/self/fd/N, but
SQLite reads that link and reopens the pathname it names. A same-owner process
that swaps an ancestor directory between the readlink and the open makes the
expected pathname reach another file, which SQLite then reports under the
expected name. The race window is inside SQLite, so these tests reproduce its
outcome deterministically: during the anchored connect, an ancestor is swapped
for a copy holding a same-named database and SQLite opens the expected
pathname, then the swap is undone before any post-connect path check.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from megalodon.ai_broker import ReceiptStore
from megalodon.models import ActionRecord
from megalodon.storage import StorageSchemaError, Store

pytestmark = pytest.mark.skipif(
    not os.path.isdir("/proc/self/fd"), reason="Linux /proc/self/fd anchor"
)

STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _substitute_during_connect(monkeypatch, swapped: Path, replacement: Path, target: Path):
    real_connect = sqlite3.connect
    held = swapped.with_name(swapped.name + "-held")
    calls = []

    def connect(database, *args, **kwargs):
        text = str(database)
        if "/proc/self/fd/" not in text and "/dev/fd/" not in text:
            return real_connect(database, *args, **kwargs)
        calls.append(text)
        swapped.rename(held)
        replacement.rename(swapped)
        try:
            return real_connect(
                f"{target.as_uri()}?{text.partition('?')[2]}", *args, **kwargs
            )
        finally:
            swapped.rename(replacement)
            held.rename(swapped)

    monkeypatch.setattr(sqlite3, "connect", connect)
    return calls


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _trees(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.chmod(0o700)
    admitted, other = tmp_path / "admitted", tmp_path / "other"
    for root in (admitted, other):
        # Explicit modes: a group-writable ancestor (umask 002) is refused.
        root.mkdir(mode=0o700)
        (root / "private").mkdir(mode=0o700)
    return admitted, other


def test_store_refuses_a_file_substituted_while_sqlite_resolves_the_anchor(
    tmp_path, monkeypatch
):
    admitted, other = _trees(tmp_path)
    database = admitted / "private" / "audit.db"
    with Store(database):
        pass
    with Store(other / "private" / "audit.db") as foreign:
        foreign.record_action(ActionRecord(STAMP, "OTHER", "192.0.2.1", "not_attempted", "x"))
    before = _digest(other / "private" / "audit.db")
    calls = _substitute_during_connect(monkeypatch, admitted, other, database)

    with pytest.raises(StorageSchemaError, match="^STORAGE_PATH:DATABASE_CHANGED$"):
        Store(database, create=False)
    assert calls
    assert _digest(other / "private" / "audit.db") == before

    monkeypatch.undo()
    with Store(database, create=False) as store:
        assert store.summary()["actions"] == 0


def test_receipt_store_refuses_a_file_substituted_while_sqlite_resolves_the_anchor(
    tmp_path, monkeypatch
):
    admitted, other = _trees(tmp_path)
    database = admitted / "private" / "receipts.db"
    ReceiptStore(database).close()
    ReceiptStore(other / "private" / "receipts.db").close()
    before = _digest(other / "private" / "receipts.db")
    calls = _substitute_during_connect(monkeypatch, admitted, other, database)

    with pytest.raises(StorageSchemaError, match="^AI_RECEIPT:DATABASE_CHANGED$"):
        ReceiptStore(database)
    assert calls
    assert _digest(other / "private" / "receipts.db") == before


def test_evidence_segment_writer_refuses_a_substituted_segment(tmp_path, monkeypatch):
    from megalodon.config import Settings
    from megalodon.evidence_storage import GIB, EvidenceStorage
    from megalodon.models import PacketEvent

    tmp_path.chmod(0o700)
    clock = [datetime.now(timezone.utc).timestamp()]
    manager = EvidenceStorage(
        Settings(db_path=tmp_path / "old.db"), home=tmp_path,
        clock=lambda: clock[0], monotonic=lambda: clock[0], segment_bytes=65536,
    )
    try:
        preview = manager.preview(dict(profile="home", retention_days=14, cap_bytes=20 * GIB))
        manager.apply(preview["preview_id"])
        writer = manager.packet_writer()
        run = writer.start_ingestion_run("jsonl")
        writer.record_event_bundle(
            PacketEvent(datetime.fromtimestamp(clock[0], timezone.utc),
                        "10.0.0.2", "1.1.1.1", "TCP", 50000, 443, byte_count=1),
            [], [], run_id=run,
        )
        writer.finish_ingestion_run(run, "source_exhausted")
        writer.close()
        entry = manager._catalog["entries"][0]
        segment = manager._path(entry)
        replacement = segment.parent.with_name(segment.parent.name + "-copy")
        shutil.copytree(segment.parent, replacement)
        before = _digest(replacement / segment.name)
        calls = _substitute_during_connect(monkeypatch, segment.parent, replacement, segment)

        with pytest.raises(StorageSchemaError, match="^EVIDENCE:DATABASE_CHANGED$"):
            with manager._db(entry, write=True):
                pass
        assert calls
        assert _digest(replacement / segment.name) == before
    finally:
        monkeypatch.undo()
        manager.close()


def test_verified_connect_refuses_same_directory_swap_with_reused_descriptor(
    tmp_path, monkeypatch
):
    import megalodon.storage as storage

    tmp_path.chmod(0o700)
    database = tmp_path / "admitted.db"
    foreign = tmp_path / "foreign.db"
    held = tmp_path / "admitted-held.db"
    for path, marker in ((database, "ADMITTED"), (foreign, "FOREIGN")):
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE marker(value TEXT)")
        connection.execute("INSERT INTO marker VALUES(?)", (marker,))
        connection.commit()
        connection.close()
        path.chmod(0o600)
    before_bytes = foreign.read_bytes()

    # A live reader makes SQLite defer closing a second descriptor to this
    # inode. The substituted connect can reuse it without opening a new fd.
    holder = sqlite3.connect(foreign)
    holder.execute("BEGIN")
    holder.execute("SELECT value FROM marker").fetchall()
    spare = sqlite3.connect(foreign)
    spare.execute("SELECT value FROM marker").fetchall()
    spare.close()
    directory = storage._open_private_directory(
        tmp_path, create=False, prefix="PROBE"
    )
    descriptor, _ = storage._open_private_database(
        database, directory, writable=True, create=False, prefix="PROBE"
    )
    anchor = storage._anchored_database_path(descriptor, database, "PROBE")
    real_connect = sqlite3.connect
    real_identities = storage._open_regular_file_identities
    samples = []
    calls = []

    def substituted_connect(database_uri, *args, **kwargs):
        calls.append(database_uri)
        database.rename(held)
        foreign.rename(database)
        try:
            return real_connect(
                f"{database.as_uri()}?{str(database_uri).partition('?')[2]}",
                *args, **kwargs,
            )
        finally:
            database.rename(foreign)
            held.rename(database)

    def identities():
        observed = real_identities()
        samples.append(observed)
        return observed

    monkeypatch.setattr(sqlite3, "connect", substituted_connect)
    monkeypatch.setattr(storage, "_open_regular_file_identities", identities)
    try:
        with pytest.raises(StorageSchemaError, match="^PROBE:DATABASE_CHANGED$"):
            connection = storage._connect_verified_sqlite(
                f"{anchor.as_uri()}?mode=rw", database, descriptor, directory, "PROBE"
            )
            connection.close()
        assert len(calls) == storage._VERIFIED_CONNECT_ATTEMPTS
        assert len(samples) == 2 * len(calls)
        assert all(
            not {fd for fd, identity in after.items() if before.get(fd) != identity}
            for before, after in zip(samples[::2], samples[1::2])
        )
        assert foreign.read_bytes() == before_bytes
    finally:
        os.close(descriptor)
        os.close(directory)
        holder.close()


@pytest.mark.parametrize("proc_available", [True, False])
def test_writer_descriptor_inventory_uses_available_alias(
    tmp_path, monkeypatch, proc_available
):
    real_listdir = os.listdir

    def listdir(path):
        if path == "/dev/fd" or (path == "/proc/self/fd" and not proc_available):
            raise FileNotFoundError(path)
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", listdir)
    database = tmp_path / "audit.db"
    if proc_available:
        with Store(database) as store:
            assert store.summary()["actions"] == 0
    else:
        with pytest.raises(
            StorageSchemaError, match="^STORAGE_PATH:DESCRIPTOR_PATH_UNAVAILABLE$"
        ):
            Store(database)
