"""Schema ownership and private opening for the Suricata durable store.

Public functions still only initialize or validate an explicitly selected
store.  The private writer context is reserved for the bounded durable consumer;
it never creates, migrates, repairs, purges, or exposes a generic write API.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from typing import Callable, Iterator

from .storage import (
    PRIVATE_DATABASE_MODE,
    _absolute_database_path,
    _anchored_database_path,
    _open_private_database,
    _open_private_directory,
    _path_matches_descriptor,
    _validate_connection_path,
    _validate_private_database_stat,
    _validate_schema,
    _validate_sqlite_sidecars,
)


SCHEMA_VERSION = 1
_STORE_PAGE_SIZE_BYTES = 4_096
_STORE_MAX_PAGES = 131_072
_STORE_MAX_BYTES = _STORE_PAGE_SIZE_BYTES * _STORE_MAX_PAGES

SCHEMA_STATEMENTS = (
    """CREATE TABLE consumer_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engine TEXT NOT NULL CHECK(engine = 'suricata'),
    adapter_profile TEXT NOT NULL CHECK(adapter_profile = 'suricata-eve-alert-v1'),
    declared_version TEXT NOT NULL,
    version_basis TEXT NOT NULL CHECK(version_basis = 'operator_declared'),
    sensor_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ruleset_id TEXT NOT NULL,
    ruleset_basis TEXT NOT NULL CHECK(ruleset_basis = 'operator_declared'),
    consumer_attempt_id TEXT NOT NULL UNIQUE,
    UNIQUE(id, consumer_attempt_id),
    UNIQUE(
        engine, adapter_profile, declared_version, version_basis,
        sensor_id, run_id, ruleset_id, ruleset_basis
    )
)""",
    """CREATE TABLE consumer_alerts (
    run_row_id INTEGER NOT NULL REFERENCES consumer_runs(id) ON DELETE CASCADE,
    source_record_index INTEGER NOT NULL CHECK(source_record_index >= 1),
    record_json TEXT NOT NULL,
    PRIMARY KEY (run_row_id, source_record_index)
)""",
    """CREATE TABLE consumer_receipts (
    run_row_id INTEGER PRIMARY KEY,
    consumer_attempt_id TEXT NOT NULL UNIQUE,
    receipt_json TEXT NOT NULL,
    FOREIGN KEY (run_row_id, consumer_attempt_id)
        REFERENCES consumer_runs(id, consumer_attempt_id) ON DELETE CASCADE
)""",
    "CREATE INDEX idx_consumer_runs_run_id ON consumer_runs(run_id)",
)

_TABLE_COLUMNS = {
    "consumer_runs": (
        ("id", "INTEGER", 0, 1),
        ("engine", "TEXT", 1, 0),
        ("adapter_profile", "TEXT", 1, 0),
        ("declared_version", "TEXT", 1, 0),
        ("version_basis", "TEXT", 1, 0),
        ("sensor_id", "TEXT", 1, 0),
        ("run_id", "TEXT", 1, 0),
        ("ruleset_id", "TEXT", 1, 0),
        ("ruleset_basis", "TEXT", 1, 0),
        ("consumer_attempt_id", "TEXT", 1, 0),
    ),
    "consumer_alerts": (
        ("run_row_id", "INTEGER", 1, 1),
        ("source_record_index", "INTEGER", 1, 2),
        ("record_json", "TEXT", 1, 0),
    ),
    "consumer_receipts": (
        ("run_row_id", "INTEGER", 0, 1),
        ("consumer_attempt_id", "TEXT", 1, 0),
        ("receipt_json", "TEXT", 1, 0),
    ),
}

_INDEX_COLUMNS = {
    "idx_consumer_runs_run_id": ("consumer_runs", ("run_id",)),
}

_FOREIGN_KEYS = {
    "consumer_runs": set(),
    "consumer_alerts": {
        ("consumer_runs", "run_row_id", "id", "CASCADE"),
    },
    "consumer_receipts": {
        ("consumer_runs", "run_row_id", "id", "CASCADE"),
        (
            "consumer_runs",
            "consumer_attempt_id",
            "consumer_attempt_id",
            "CASCADE",
        ),
    },
}

_UNIQUE_INDEXES = {
    "consumer_runs": {
        ("u", ("consumer_attempt_id",)),
        ("u", ("id", "consumer_attempt_id")),
        (
            "u",
            (
                "engine",
                "adapter_profile",
                "declared_version",
                "version_basis",
                "sensor_id",
                "run_id",
                "ruleset_id",
                "ruleset_basis",
            ),
        ),
    },
    "consumer_alerts": {
        ("pk", ("run_row_id", "source_record_index")),
    },
    "consumer_receipts": {
        ("u", ("consumer_attempt_id",)),
    },
}


class SuricataStoreError(ValueError):
    """The dedicated Suricata store is missing or incompatible."""


class _SuricataWriterHandle:
    """Descriptor-pinned existing-store connection for the consumer only."""

    def __init__(
        self,
        path: Path,
        connection: sqlite3.Connection,
        database_descriptor: int,
        directory_descriptor: int | None,
    ) -> None:
        self.path = path
        self.connection = connection
        self._database_descriptor = database_descriptor
        self._directory_descriptor = directory_descriptor

    def verify_identity(self) -> None:
        _assert_path_identity(
            self.path,
            self._database_descriptor,
            self._directory_descriptor,
        )


@contextmanager
def _open_suricata_store_writer(
    path: str | Path,
    *,
    progress_handler: Callable[[], int] | None = None,
) -> Iterator[_SuricataWriterHandle]:
    """Open one existing exact v1 store without creation or migration."""

    directory_descriptor: int | None = None
    database_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        try:
            database_path = _absolute_database_path(path, "SURICATA_STORE")
            directory_descriptor = _open_private_directory(
                database_path.parent, create=False, prefix="SURICATA_STORE"
            )
            _assert_path_identity(database_path, None, directory_descriptor)
            database_descriptor, created = _open_private_database(
                database_path,
                directory_descriptor,
                writable=True,
                create=False,
                prefix="SURICATA_STORE",
            )
            if created:
                raise SuricataStoreError("SURICATA_STORE:UNEXPECTED_CREATION")
            _assert_path_identity(
                database_path, database_descriptor, directory_descriptor
            )
            if _validate_sqlite_sidecars(
                database_path,
                directory_descriptor,
                writable=True,
                prefix="SURICATA_STORE",
            ):
                raise SuricataStoreError("SURICATA_STORE:RECOVERY_REQUIRED")
            sqlite_path = _anchored_database_path(
                database_descriptor, database_path, "SURICATA_STORE"
            )
            connection = sqlite3.connect(
                f"{sqlite_path.as_uri()}?mode=rw&cache=private",
                uri=True,
                timeout=30,
                isolation_level=None,
            )
            _validate_connection_path(connection, database_path, "SURICATA_STORE")
            _assert_path_identity(
                database_path, database_descriptor, directory_descriptor
            )
            connection.execute("PRAGMA foreign_keys=ON")
            if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                raise SuricataStoreError("SURICATA_STORE:FOREIGN_KEYS_DISABLED")
            if progress_handler is not None:
                connection.set_progress_handler(progress_handler, 1_000)
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            if page_size != _STORE_PAGE_SIZE_BYTES:
                raise SuricataStoreError("SURICATA_STORE:INCOMPATIBLE_PAGE_SIZE")
            max_pages = int(connection.execute(
                f"PRAGMA max_page_count={_STORE_MAX_PAGES}"
            ).fetchone()[0])
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            if (
                max_pages != _STORE_MAX_PAGES
                or not 0 <= page_count <= _STORE_MAX_PAGES
            ):
                raise SuricataStoreError("SURICATA_STORE:CAPACITY_EXCEEDED")
            _validate_current(connection)
            handle = _SuricataWriterHandle(
                database_path,
                connection,
                database_descriptor,
                directory_descriptor,
            )
            handle.verify_identity()
        except SuricataStoreError:
            raise
        except (OSError, sqlite3.Error, ValueError) as exc:
            raise SuricataStoreError("SURICATA_STORE:WRITER_OPEN_FAILED") from exc
        yield handle
    finally:
        if connection is not None:
            try:
                connection.set_progress_handler(None, 0)
            except sqlite3.Error:
                pass
            if connection.in_transaction:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
            try:
                connection.close()
            except sqlite3.Error:
                pass
        _close_descriptor(database_descriptor)
        _close_descriptor(directory_descriptor)


def _close_descriptor(descriptor: int | None) -> None:
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _create_private_database(
    path: Path, directory_descriptor: int | None
) -> int:
    """Create a new database leaf exclusively without touching an existing file."""

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    target: str | Path = path.name if directory_descriptor is not None else path
    kwargs = (
        {"dir_fd": directory_descriptor}
        if directory_descriptor is not None
        else {}
    )
    try:
        descriptor = os.open(target, flags, PRIVATE_DATABASE_MODE, **kwargs)
    except FileExistsError as exc:
        raise SuricataStoreError("SURICATA_STORE:EXISTING_DATABASE") from exc
    try:
        if os.name == "posix":
            os.fchmod(descriptor, PRIVATE_DATABASE_MODE)
        _validate_private_database_stat(
            os.fstat(descriptor), writable=False, prefix="SURICATA_STORE"
        )
        return descriptor
    except Exception:
        _discard_created_database(path, descriptor, directory_descriptor)
        _close_descriptor(descriptor)
        raise


def _assert_path_identity(
    path: Path,
    database_descriptor: int | None,
    directory_descriptor: int | None,
) -> None:
    if database_descriptor is not None and not _path_matches_descriptor(
        path, database_descriptor
    ):
        raise SuricataStoreError("SURICATA_STORE:DATABASE_CHANGED")
    if directory_descriptor is not None and not _path_matches_descriptor(
        path.parent, directory_descriptor
    ):
        raise SuricataStoreError("SURICATA_STORE:DIRECTORY_CHANGED")


def _validate_current(connection: sqlite3.Connection) -> None:
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != SCHEMA_VERSION:
        raise SuricataStoreError("SURICATA_STORE:INCOMPATIBLE_VERSION")
    try:
        _validate_schema(
            connection,
            _TABLE_COLUMNS,
            _INDEX_COLUMNS,
            _FOREIGN_KEYS,
            _UNIQUE_INDEXES,
            SCHEMA_STATEMENTS,
        )
    except ValueError as exc:
        raise SuricataStoreError("SURICATA_STORE:INCOMPATIBLE_SCHEMA") from exc
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SuricataStoreError("SURICATA_STORE:INCOMPATIBLE_DATA")
    if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        raise SuricataStoreError("SURICATA_STORE:INTEGRITY_CHECK_FAILED")


def _discard_created_database(
    path: Path,
    descriptor: int | None,
    directory_descriptor: int | None,
) -> None:
    if descriptor is None or not _path_matches_descriptor(path, descriptor):
        return
    try:
        if directory_descriptor is None:
            path.unlink()
        else:
            os.unlink(path.name, dir_fd=directory_descriptor)
    except OSError:
        pass


def _refuse_orphaned_sidecars(
    path: Path, directory_descriptor: int | None
) -> None:
    sidecars = _validate_sqlite_sidecars(
        path,
        directory_descriptor,
        writable=False,
        prefix="SURICATA_STORE",
    )
    if sidecars:
        raise SuricataStoreError("SURICATA_STORE:ORPHANED_SIDECAR_REFUSED")


def initialize_suricata_store(path: str | Path) -> dict[str, object]:
    """Explicitly create the exact v1 store; never open an existing database."""

    database_path = _absolute_database_path(path, "SURICATA_STORE")
    directory_descriptor: int | None = None
    database_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    created = False
    try:
        directory_descriptor = _open_private_directory(
            database_path.parent, create=True, prefix="SURICATA_STORE"
        )
        _assert_path_identity(database_path, None, directory_descriptor)
        database_descriptor = _create_private_database(
            database_path, directory_descriptor
        )
        created = True
        _assert_path_identity(
            database_path, database_descriptor, directory_descriptor
        )
        _refuse_orphaned_sidecars(database_path, directory_descriptor)
        sqlite_path = _anchored_database_path(
            database_descriptor, database_path, "SURICATA_STORE"
        )
        connection = sqlite3.connect(
            f"{sqlite_path.as_uri()}?mode=rw&cache=private",
            uri=True,
            timeout=10,
            isolation_level=None,
        )
        _validate_connection_path(connection, database_path, "SURICATA_STORE")
        _assert_path_identity(
            database_path, database_descriptor, directory_descriptor
        )
        _refuse_orphaned_sidecars(database_path, directory_descriptor)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        _validate_current(connection)
        connection.commit()
        _refuse_orphaned_sidecars(database_path, directory_descriptor)
        _assert_path_identity(
            database_path, database_descriptor, directory_descriptor
        )
        os.fsync(database_descriptor)
        if directory_descriptor is not None:
            os.fsync(directory_descriptor)
        return {
            "status": "created",
            "schema_version": SCHEMA_VERSION,
            "tables": tuple(_TABLE_COLUMNS),
        }
    except SuricataStoreError:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        if created:
            _discard_created_database(
                database_path, database_descriptor, directory_descriptor
            )
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        if created:
            _discard_created_database(
                database_path, database_descriptor, directory_descriptor
            )
        raise SuricataStoreError("SURICATA_STORE:INITIALIZATION_FAILED") from exc
    finally:
        if connection is not None:
            connection.close()
        _close_descriptor(database_descriptor)
        _close_descriptor(directory_descriptor)


def validate_suricata_store(path: str | Path) -> dict[str, object]:
    """Validate an existing store through a read-only, query-only connection."""

    database_path = _absolute_database_path(path, "SURICATA_STORE")
    directory_descriptor: int | None = None
    database_descriptor: int | None = None
    connection: sqlite3.Connection | None = None
    try:
        directory_descriptor = _open_private_directory(
            database_path.parent, create=False, prefix="SURICATA_STORE"
        )
        _assert_path_identity(database_path, None, directory_descriptor)
        database_descriptor, _ = _open_private_database(
            database_path,
            directory_descriptor,
            writable=False,
            create=False,
            prefix="SURICATA_STORE",
        )
        _assert_path_identity(
            database_path, database_descriptor, directory_descriptor
        )
        sidecars = _validate_sqlite_sidecars(
            database_path,
            directory_descriptor,
            writable=False,
            prefix="SURICATA_STORE",
        )
        if ("-wal" in sidecars) != ("-shm" in sidecars):
            raise SuricataStoreError("SURICATA_STORE:INCOMPLETE_WAL_STATE")
        if "-journal" in sidecars:
            raise SuricataStoreError("SURICATA_STORE:ACTIVE_JOURNAL_REFUSED")
        sqlite_path = _anchored_database_path(
            database_descriptor, database_path, "SURICATA_STORE"
        )
        connection = sqlite3.connect(
            f"{sqlite_path.as_uri()}?mode=ro&cache=private",
            uri=True,
            timeout=10,
            isolation_level=None,
        )
        _validate_connection_path(connection, database_path, "SURICATA_STORE")
        _assert_path_identity(
            database_path, database_descriptor, directory_descriptor
        )
        connection.execute("PRAGMA query_only=ON")
        _validate_current(connection)
        _assert_path_identity(
            database_path, database_descriptor, directory_descriptor
        )
        return {
            "status": "compatible",
            "schema_version": SCHEMA_VERSION,
            "tables": tuple(_TABLE_COLUMNS),
        }
    except SuricataStoreError:
        raise
    except (OSError, sqlite3.Error, ValueError) as exc:
        raise SuricataStoreError("SURICATA_STORE:VALIDATION_FAILED") from exc
    finally:
        if connection is not None:
            connection.close()
        _close_descriptor(database_descriptor)
        _close_descriptor(directory_descriptor)


__all__ = [
    "SCHEMA_VERSION",
    "SuricataStoreError",
    "initialize_suricata_store",
    "validate_suricata_store",
]
