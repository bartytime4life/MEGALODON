"""Fail-closed, local-only SQLite backup and restore-to-new-destination."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Callable, TypeVar

from .storage import (
    PRIVATE_DATABASE_MODE,
    SCHEMA_VERSION,
    StorageSchemaError,
    _absolute_database_path,
    _anchored_database_path,
    _open_private_directory,
    _path_matches_descriptor,
    _schema_contract,
    _validate_connection_path,
    _validate_private_directory_stat,
    _validate_schema,
    _validate_sqlite_sidecars,
)


MAX_SOURCE_BYTES = 4 * 1024**3
MAX_ARTIFACT_BYTES = 4 * 1024**3
MIN_FREE_RESERVE_BYTES = 16 * 1024**2
MAX_ELAPSED_MS = 300_000
MAX_BUSY_RETRIES = 60
PAGES_PER_STEP = 1024
MAX_MANIFEST_BYTES = 16 * 1024
BUSY_SLEEP_SECONDS = 0.05
MANIFEST_SCHEMA = "megalodon-sqlite-recovery-manifest-v1"
RECEIPT_SCHEMA = "megalodon-sqlite-recovery-receipt-v1"
_OPERATION_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PAGE_SIZES = frozenset((512, 1024, 2048, 4096, 8192, 16384, 32768, 65536))
_SQLITE_BUSY = getattr(sqlite3, "SQLITE_BUSY", 5)
_SQLITE_LOCKED = getattr(sqlite3, "SQLITE_LOCKED", 6)
_EFFECTS = {
    "source_mutated": False,
    "network_access_performed": False,
    "ordinary_copy_performed": False,
    "migration_performed": False,
    "repair_performed": False,
    "deletion_performed": False,
    "path_disclosed": False,
}
_LIMITS = {
    "max_source_bytes": MAX_SOURCE_BYTES,
    "max_artifact_bytes": MAX_ARTIFACT_BYTES,
    "min_free_reserve_bytes": MIN_FREE_RESERVE_BYTES,
    "max_elapsed_ms": MAX_ELAPSED_MS,
    "max_busy_retries": MAX_BUSY_RETRIES,
    "pages_per_step": PAGES_PER_STEP,
}


class _RecoveryFailure(Exception):
    def __init__(
        self,
        reason: str,
        *,
        source_state: str = "not_admitted",
        completion_uncertain: bool = False,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.source_state = source_state
        self.completion_uncertain = completion_uncertain


@dataclass
class _Operation:
    operation: str
    operation_id: str
    started_wall: datetime
    started_monotonic: float
    destination_created: bool = False
    artifact_sha256: str | None = None
    manifest_sha256: str | None = None
    busy_retries: int = 0

    @property
    def deadline(self) -> float:
        return self.started_monotonic + MAX_ELAPSED_MS / 1000

    def check_deadline(self) -> None:
        if _monotonic() >= self.deadline:
            raise _RecoveryFailure(
                "DEADLINE_EXCEEDED", source_state="admitted"
            )

    def record_busy(self) -> None:
        self.check_deadline()
        self.busy_retries += 1
        if self.busy_retries > MAX_BUSY_RETRIES:
            raise _RecoveryFailure("LOCK_TIMEOUT", source_state="admitted")


@dataclass
class _Database:
    path: Path
    directory_descriptor: int | None
    descriptor: int
    sqlite_path: Path
    connection: sqlite3.Connection | None = None

    def close(self) -> None:
        primary: BaseException | None = None
        if self.connection is not None:
            try:
                if self.connection.in_transaction:
                    self.connection.rollback()
                self.connection.close()
            except BaseException as exc:  # pragma: no cover - defensive close path
                primary = exc
            finally:
                self.connection = None
        for descriptor in (self.descriptor, self.directory_descriptor):
            if descriptor is None:
                continue
            try:
                os.close(descriptor)
            except BaseException as exc:  # pragma: no cover - defensive close path
                if primary is None:
                    primary = exc
        if primary is not None:
            raise primary


def _wall_now() -> datetime:
    return datetime.now(timezone.utc)


def _monotonic() -> float:
    return time.monotonic()


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _identity(descriptor: int) -> dict[str, object]:
    info = os.fstat(descriptor)
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "uid": int(info.st_uid),
        "mode": "0600",
        "link_count": 1,
        "path_disclosed": False,
    }


def _file_generation(descriptor: int) -> tuple[int, int, int, int, int, int]:
    info = os.fstat(descriptor)
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_nlink),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _safe_operation_id(value: object) -> str:
    return value if isinstance(value, str) and _OPERATION_ID.fullmatch(value) else "invalid-request"


def _absolute_path(value: str | Path, *, destination: bool) -> Path:
    try:
        if not isinstance(value, (str, os.PathLike)):
            raise TypeError
        return _absolute_database_path(
            value, "RECOVERY_DESTINATION" if destination else "RECOVERY_SOURCE"
        )
    except (OSError, TypeError, ValueError, StorageSchemaError) as exc:
        reason = "DESTINATION_UNSAFE" if destination else "INPUT_INVALID"
        raise _RecoveryFailure(reason) from exc


def _validate_private_file(descriptor: int, *, source: bool) -> None:
    try:
        info = os.fstat(descriptor)
    except OSError as exc:
        raise _RecoveryFailure("SOURCE_UNAVAILABLE" if source else "DESTINATION_UNSAFE") from exc
    if not stat.S_ISREG(info.st_mode):
        raise _RecoveryFailure("SOURCE_UNSAFE" if source else "DESTINATION_UNSAFE")
    if info.st_nlink != 1:
        raise _RecoveryFailure("SOURCE_NOT_PRIVATE" if source else "DESTINATION_UNSAFE")
    if os.name == "posix" and (
        info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != PRIVATE_DATABASE_MODE
    ):
        raise _RecoveryFailure("SOURCE_NOT_PRIVATE" if source else "DESTINATION_UNSAFE")


def _open_existing_file(path: Path) -> tuple[int | None, int]:
    directory_descriptor: int | None = None
    descriptor: int | None = None
    try:
        directory_descriptor = _open_private_directory(
            path.parent, create=False, prefix="RECOVERY_SOURCE"
        )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        target: str | Path = path.name if directory_descriptor is not None else path
        kwargs = {"dir_fd": directory_descriptor} if directory_descriptor is not None else {}
        descriptor = os.open(target, flags, **kwargs)
        _validate_private_file(descriptor, source=True)
        return directory_descriptor, descriptor
    except _RecoveryFailure:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise
    except FileNotFoundError as exc:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise _RecoveryFailure("SOURCE_UNAVAILABLE", source_state="unavailable") from exc
    except StorageSchemaError as exc:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        message = str(exc)
        if "NO_DIRECTORY" in message:
            reason, state = "SOURCE_UNAVAILABLE", "unavailable"
        elif "UNSAFE_DIRECTORY" in message:
            reason, state = "SOURCE_NOT_PRIVATE", "unsafe"
        else:
            reason, state = "SOURCE_UNSAFE", "unsafe"
        raise _RecoveryFailure(reason, source_state=state) from exc
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        reason = (
            "SOURCE_UNSAFE"
            if exc.errno in (errno.ELOOP, errno.ENXIO)
            else "SOURCE_UNAVAILABLE"
        )
        state = "unsafe" if reason == "SOURCE_UNSAFE" else "unavailable"
        raise _RecoveryFailure(reason, source_state=state) from exc


def _open_source_database(path: Path, *, immutable: bool) -> _Database:
    directory_descriptor, descriptor = _open_existing_file(path)
    connection: sqlite3.Connection | None = None
    try:
        if os.fstat(descriptor).st_size > MAX_SOURCE_BYTES:
            raise _RecoveryFailure("ARTIFACT_LIMIT_EXCEEDED", source_state="admitted")
        sqlite_path = _anchored_database_path(descriptor, path, "RECOVERY_SOURCE")
        sidecars = _validate_sqlite_sidecars(
            path,
            directory_descriptor,
            writable=False,
            prefix="RECOVERY_SOURCE",
        )
        if "-journal" in sidecars or (("-wal" in sidecars) != ("-shm" in sidecars)):
            raise _RecoveryFailure("SOURCE_UNSAFE", source_state="unsafe")
        if immutable and sidecars:
            raise _RecoveryFailure("ARTIFACT_CORRUPT", source_state="corrupt")
        observed_bytes = int(os.fstat(descriptor).st_size)
        for suffix in sidecars:
            sidecar = path.with_name(path.name + suffix)
            sidecar_directory, sidecar_descriptor = _open_existing_file(sidecar)
            try:
                observed_bytes += int(os.fstat(sidecar_descriptor).st_size)
            finally:
                os.close(sidecar_descriptor)
                if sidecar_directory is not None:
                    os.close(sidecar_directory)
        if observed_bytes > MAX_SOURCE_BYTES:
            raise _RecoveryFailure("ARTIFACT_LIMIT_EXCEEDED", source_state="admitted")
        parameters = "mode=ro&cache=private"
        if immutable:
            parameters += "&immutable=1"
        connection = sqlite3.connect(
            f"{sqlite_path.as_uri()}?{parameters}",
            uri=True,
            timeout=0,
            isolation_level=None,
            check_same_thread=False,
        )
        _validate_connection_path(connection, path, "RECOVERY_SOURCE")
        connection.execute("PRAGMA query_only=ON")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            raise _RecoveryFailure("SOURCE_UNSAFE", source_state="unsafe")
        database = _Database(path, directory_descriptor, descriptor, sqlite_path, connection)
        _assert_database_identity(database, source=True)
        return database
    except _RecoveryFailure:
        if connection is not None:
            connection.close()
        os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise
    except sqlite3.DatabaseError as exc:
        if connection is not None:
            connection.close()
        os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        reason = "ARTIFACT_CORRUPT" if immutable else "SOURCE_CORRUPT"
        raise _RecoveryFailure(reason, source_state="corrupt") from exc
    except StorageSchemaError as exc:
        if connection is not None:
            connection.close()
        os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        state = "identity_changed" if "CHANGED" in str(exc) else "unsafe"
        reason = (
            "SOURCE_IDENTITY_CHANGED"
            if state == "identity_changed"
            else "SOURCE_UNSAFE"
        )
        raise _RecoveryFailure(reason, source_state=state) from exc
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if connection is not None:
            connection.close()
        os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise _RecoveryFailure("SOURCE_UNAVAILABLE", source_state="unavailable") from exc


def _preflight_new_path(path: Path, directory_descriptor: int | None) -> None:
    target: str | Path = path.name if directory_descriptor is not None else path
    kwargs = {"dir_fd": directory_descriptor} if directory_descriptor is not None else {}
    try:
        info = os.stat(target, follow_symlinks=False, **kwargs)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise _RecoveryFailure("DESTINATION_UNSAFE", source_state="admitted") from exc
    reason = "DESTINATION_EXISTS" if stat.S_ISREG(info.st_mode) else "DESTINATION_UNSAFE"
    raise _RecoveryFailure(reason, source_state="admitted")


def _open_destination_directory(path: Path) -> int | None:
    try:
        return _open_private_directory(
            path.parent, create=False, prefix="RECOVERY_DESTINATION"
        )
    except (OSError, StorageSchemaError) as exc:
        raise _RecoveryFailure("DESTINATION_UNSAFE", source_state="admitted") from exc


def _create_destination(
    operation: _Operation, path: Path, directory_descriptor: int | None
) -> _Database:
    descriptor: int | None = None
    database: _Database | None = None
    completed = False
    try:
        _preflight_new_path(path, directory_descriptor)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        target: str | Path = path.name if directory_descriptor is not None else path
        kwargs = {"dir_fd": directory_descriptor} if directory_descriptor is not None else {}
        descriptor = os.open(target, flags, PRIVATE_DATABASE_MODE, **kwargs)
        operation.destination_created = True
        # Retain the binding before any further validation or SQLite work can
        # fail. The caller cannot classify it until this function returns.
        database = _Database(path, directory_descriptor, descriptor, path)
        if os.name == "posix":
            os.fchmod(descriptor, PRIVATE_DATABASE_MODE)
        _validate_private_file(descriptor, source=False)
        sqlite_path = _anchored_database_path(descriptor, path, "RECOVERY_DESTINATION")
        database.sqlite_path = sqlite_path
        database.connection = sqlite3.connect(
            f"{sqlite_path.as_uri()}?mode=rw&cache=private",
            uri=True,
            timeout=0,
            isolation_level=None,
            check_same_thread=False,
        )
        _validate_connection_path(database.connection, path, "RECOVERY_DESTINATION")
        _assert_database_identity(database, source=False)
        completed = True
        return database
    except BaseException as exc:
        if isinstance(exc, _RecoveryFailure):
            failure = exc
        elif isinstance(exc, KeyboardInterrupt):
            failure = _RecoveryFailure(
                "INTERRUPTED_AFTER_CREATE" if operation.destination_created
                else "INTERRUPTED_BEFORE_CREATE", source_state="admitted"
            )
        elif isinstance(exc, Exception):
            reason = "DESTINATION_EXISTS" if isinstance(exc, FileExistsError) else (
                "DESTINATION_UNSAFE" if isinstance(exc, OSError)
                and exc.errno in (errno.ELOOP, errno.ENXIO) else "IO_ERROR"
            )
            failure = _RecoveryFailure(reason, source_state="admitted")
        else:
            raise
        # Identity loss outranks a lower-level error, including interruption.
        # Classify while the descriptors are still held, before cleanup.
        classified = _classify_destination_binding(failure, database)
        if classified is exc:
            raise
        raise classified from exc
    finally:
        if not completed:
            if database is not None:
                # The directory remains the caller's responsibility on failure.
                database.directory_descriptor = None
                try:
                    database.close()
                except BaseException:
                    pass
            elif descriptor is not None:
                os.close(descriptor)


def _assert_database_identity(database: _Database, *, source: bool) -> None:
    reason = "SOURCE_IDENTITY_CHANGED" if source else "COMPLETION_UNCERTAIN"
    if not _path_matches_descriptor(database.path, database.descriptor):
        raise _RecoveryFailure(
            reason,
            source_state="identity_changed" if source else "admitted",
            completion_uncertain=not source,
        )
    if database.directory_descriptor is not None and not _path_matches_descriptor(
        database.path.parent, database.directory_descriptor
    ):
        raise _RecoveryFailure(
            reason,
            source_state="identity_changed" if source else "admitted",
            completion_uncertain=not source,
        )
    try:
        _validate_private_file(database.descriptor, source=source)
        if database.directory_descriptor is not None:
            _validate_private_directory_stat(
                os.fstat(database.directory_descriptor),
                "RECOVERY_SOURCE" if source else "RECOVERY_DESTINATION",
            )
        sidecars = _validate_sqlite_sidecars(
            database.path,
            database.directory_descriptor,
            writable=False,
            prefix="RECOVERY_SOURCE" if source else "RECOVERY_DESTINATION",
        )
        if "-journal" in sidecars or (("-wal" in sidecars) != ("-shm" in sidecars)):
            raise StorageSchemaError("RECOVERY:UNSAFE_SIDECAR_STATE")
    except StorageSchemaError as exc:
        raise _RecoveryFailure(
            reason,
            source_state="identity_changed" if source else "admitted",
            completion_uncertain=not source,
        ) from exc


def _classify_destination_binding(
    failure: _RecoveryFailure, database: _Database | None
) -> _RecoveryFailure:
    """Give a broken held destination binding precedence over a lower-level error."""

    if database is None:
        return failure
    path_matches = _path_matches_descriptor(database.path, database.descriptor)
    directory_matches = (
        database.directory_descriptor is None
        or _path_matches_descriptor(
            database.path.parent, database.directory_descriptor
        )
    )
    if path_matches and directory_matches:
        return failure
    return _RecoveryFailure(
        "COMPLETION_UNCERTAIN",
        source_state="admitted",
        completion_uncertain=True,
    )


_T = TypeVar("_T")


def _retry_busy(operation: _Operation, callback: Callable[[], _T]) -> _T:
    while True:
        operation.check_deadline()
        try:
            return callback()
        except sqlite3.Error as exc:
            message = str(exc).lower()
            if "locked" not in message and "busy" not in message:
                raise
            operation.record_busy()
            time.sleep(BUSY_SLEEP_SECONDS)


def _run_bounded_query(
    operation: _Operation,
    connection: sqlite3.Connection,
    callback: Callable[[], _T],
) -> _T:
    expired = False

    def progress() -> int:
        nonlocal expired
        expired = _monotonic() >= operation.deadline
        return int(expired)

    connection.set_progress_handler(progress, 1000)
    try:
        return _retry_busy(operation, callback)
    except sqlite3.Error as exc:
        if expired or _monotonic() >= operation.deadline:
            raise _RecoveryFailure("DEADLINE_EXCEEDED", source_state="admitted") from exc
        raise
    finally:
        connection.set_progress_handler(None, 0)


def _inspect_database(
    operation: _Operation,
    database: _Database,
    *,
    corrupt_reason: str,
) -> dict[str, object]:
    connection = database.connection
    if connection is None:
        raise _RecoveryFailure(
            "COMPLETION_UNCERTAIN",
            source_state="admitted",
            completion_uncertain=True,
        )

    def inspect() -> dict[str, object]:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != SCHEMA_VERSION:
            raise _RecoveryFailure("SCHEMA_INCOMPATIBLE", source_state="incompatible")
        try:
            _validate_schema(connection, *_schema_contract(SCHEMA_VERSION))
        except StorageSchemaError as exc:
            raise _RecoveryFailure("SCHEMA_INCOMPATIBLE", source_state="incompatible") from exc
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        logical_bytes = page_size * page_count
        if page_size not in _PAGE_SIZES or page_count < 1:
            raise _RecoveryFailure(corrupt_reason, source_state="corrupt")
        if logical_bytes > MAX_ARTIFACT_BYTES or page_count > 8_388_608:
            raise _RecoveryFailure("ARTIFACT_LIMIT_EXCEEDED", source_state="admitted")
        integrity = connection.execute("PRAGMA integrity_check")
        saw_row = False
        for row in integrity:
            saw_row = True
            if len(row) != 1 or str(row[0]) != "ok":
                raise _RecoveryFailure(corrupt_reason, source_state="corrupt")
        if not saw_row:
            raise _RecoveryFailure(corrupt_reason, source_state="corrupt")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise _RecoveryFailure("FOREIGN_KEY_VIOLATION", source_state="corrupt")
        return {
            "identity": _identity(database.descriptor),
            "schema_user_version": version,
            "sqlite_version": sqlite3.sqlite_version,
            "page_size": page_size,
            "page_count": page_count,
            "logical_bytes": logical_bytes,
            "integrity_check": "ok",
            "foreign_key_check": "ok",
        }

    try:
        return _run_bounded_query(operation, connection, inspect)
    except _RecoveryFailure:
        raise
    except (sqlite3.DatabaseError, TypeError, ValueError) as exc:
        raise _RecoveryFailure(corrupt_reason, source_state="corrupt") from exc
    except sqlite3.Error as exc:
        raise _RecoveryFailure("IO_ERROR", source_state="admitted") from exc


def _copy_online(operation: _Operation, source: _Database, destination: _Database) -> None:
    if source.connection is None or destination.connection is None:
        raise _RecoveryFailure(
            "COMPLETION_UNCERTAIN",
            source_state="admitted",
            completion_uncertain=True,
        )

    def progress(status: int, _remaining: int, _total: int) -> None:
        operation.check_deadline()
        if status in (_SQLITE_BUSY, _SQLITE_LOCKED):
            operation.record_busy()
        elif status not in (sqlite3.SQLITE_OK, sqlite3.SQLITE_DONE):
            raise sqlite3.OperationalError(f"backup status {status}")

    try:
        source.connection.backup(
            destination.connection,
            pages=PAGES_PER_STEP,
            progress=progress,
            sleep=BUSY_SLEEP_SECONDS,
        )
    except _RecoveryFailure:
        raise
    except sqlite3.Error as exc:
        message = str(exc).lower()
        if "locked" in message or "busy" in message:
            operation.record_busy()
            raise _RecoveryFailure("LOCK_TIMEOUT", source_state="admitted") from exc
        raise _RecoveryFailure("IO_ERROR", source_state="admitted") from exc


def _check_space(directory_descriptor: int | None, path: Path, planned_bytes: int) -> None:
    try:
        info = (
            os.fstatvfs(directory_descriptor)
            if directory_descriptor is not None
            else os.statvfs(path.parent)
        )
        available = int(info.f_bavail) * int(info.f_frsize)
    except OSError as exc:
        raise _RecoveryFailure("IO_ERROR", source_state="admitted") from exc
    if available < planned_bytes + MIN_FREE_RESERVE_BYTES:
        raise _RecoveryFailure("DISK_RESERVE_INSUFFICIENT", source_state="admitted")


def _check_remaining_reserve(directory_descriptor: int | None, path: Path) -> None:
    _check_space(directory_descriptor, path, 0)


def _hash_descriptor(operation: _Operation, descriptor: int, maximum: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        operation.check_deadline()
        try:
            chunk = os.pread(descriptor, 1024 * 1024, offset)
        except OSError as exc:
            raise _RecoveryFailure("IO_ERROR", source_state="admitted") from exc
        if not chunk:
            break
        offset += len(chunk)
        if offset > maximum:
            raise _RecoveryFailure("ARTIFACT_LIMIT_EXCEEDED", source_state="admitted")
        digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _manifest_document(operation: _Operation, snapshot: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": MANIFEST_SCHEMA,
        "operation_id": operation.operation_id,
        "created_at": _timestamp(_wall_now()),
        "artifact_sha256": operation.artifact_sha256,
        "artifact": snapshot,
        "limits": dict(_LIMITS),
        "effects": dict(_EFFECTS),
    }


def _write_manifest(operation: _Operation, path: Path, document: dict[str, object]) -> str:
    payload = _canonical_json(document) + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise _RecoveryFailure("ARTIFACT_LIMIT_EXCEEDED", source_state="admitted")
    directory_descriptor = _open_destination_directory(path)
    descriptor: int | None = None
    try:
        _preflight_new_path(path, directory_descriptor)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        target: str | Path = path.name if directory_descriptor is not None else path
        kwargs = {"dir_fd": directory_descriptor} if directory_descriptor is not None else {}
        descriptor = os.open(target, flags, PRIVATE_DATABASE_MODE, **kwargs)
        if os.name == "posix":
            os.fchmod(descriptor, PRIVATE_DATABASE_MODE)
        _validate_private_file(descriptor, source=False)
        offset = 0
        while offset < len(payload):
            operation.check_deadline()
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short manifest write")
            offset += written
        os.fsync(descriptor)
        if not _path_matches_descriptor(path, descriptor):
            raise _RecoveryFailure(
                "COMPLETION_UNCERTAIN",
                source_state="admitted",
                completion_uncertain=True,
            )
        if directory_descriptor is not None:
            os.fsync(directory_descriptor)
        return _sha256_bytes(payload)
    except _RecoveryFailure:
        raise
    except FileExistsError as exc:
        # A collision discovered here raced the preflight and occurred after the
        # database artifact was created. Preserve both objects and avoid a
        # contradictory DESTINATION_EXISTS receipt, whose contract requires that
        # no destination was created.
        raise _RecoveryFailure("IO_ERROR", source_state="admitted") from exc
    except OSError as exc:
        raise _RecoveryFailure("IO_ERROR", source_state="admitted") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _closed_json_loads(payload: bytes) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    return json.loads(
        payload.decode("utf-8"),
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")),
    )


def _validate_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "operation_id",
        "created_at",
        "artifact_sha256",
        "artifact",
        "limits",
        "effects",
    }:
        raise _RecoveryFailure("INPUT_INVALID")
    if value["schema_version"] != MANIFEST_SCHEMA:
        raise _RecoveryFailure("INPUT_INVALID")
    if not isinstance(value["operation_id"], str) or not _OPERATION_ID.fullmatch(
        value["operation_id"]
    ):
        raise _RecoveryFailure("INPUT_INVALID")
    if not isinstance(value["artifact_sha256"], str) or not _DIGEST.fullmatch(
        value["artifact_sha256"]
    ):
        raise _RecoveryFailure("INPUT_INVALID")
    if not isinstance(value["created_at"], str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value["created_at"]
    ):
        raise _RecoveryFailure("INPUT_INVALID")
    if value["limits"] != _LIMITS or value["effects"] != _EFFECTS:
        raise _RecoveryFailure("INPUT_INVALID")
    artifact = value["artifact"]
    if not isinstance(artifact, dict) or set(artifact) != {
        "identity",
        "schema_user_version",
        "sqlite_version",
        "page_size",
        "page_count",
        "logical_bytes",
        "integrity_check",
        "foreign_key_check",
    }:
        raise _RecoveryFailure("INPUT_INVALID")
    identity = artifact["identity"]
    if not isinstance(identity, dict) or set(identity) != {
        "device", "inode", "uid", "mode", "link_count", "path_disclosed"
    }:
        raise _RecoveryFailure("INPUT_INVALID")
    if (
        any(
            isinstance(identity[key], bool) or not isinstance(identity[key], int)
            for key in ("device", "inode", "uid")
        )
        or identity["device"] < 0
        or identity["inode"] < 1
        or identity["uid"] < 0
        or identity["mode"] != "0600"
        or identity["link_count"] != 1
        or identity["path_disclosed"] is not False
    ):
        raise _RecoveryFailure("INPUT_INVALID")
    page_size = artifact["page_size"]
    page_count = artifact["page_count"]
    logical_bytes = artifact["logical_bytes"]
    if (
        artifact["schema_user_version"] != SCHEMA_VERSION
        or not isinstance(artifact["sqlite_version"], str)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", artifact["sqlite_version"])
        or isinstance(page_size, bool)
        or page_size not in _PAGE_SIZES
        or isinstance(page_count, bool)
        or not isinstance(page_count, int)
        or not 1 <= page_count <= 8_388_608
        or isinstance(logical_bytes, bool)
        or not isinstance(logical_bytes, int)
        or logical_bytes != page_size * page_count
        or logical_bytes > MAX_ARTIFACT_BYTES
        or artifact["integrity_check"] != "ok"
        or artifact["foreign_key_check"] != "ok"
    ):
        raise _RecoveryFailure("INPUT_INVALID")
    return value


def _read_manifest(operation: _Operation, path: Path) -> tuple[dict[str, object], str]:
    directory_descriptor, descriptor = _open_existing_file(path)
    try:
        info = os.fstat(descriptor)
        if info.st_size > MAX_MANIFEST_BYTES:
            raise _RecoveryFailure("INPUT_INVALID")
        payload = bytearray()
        offset = 0
        while True:
            operation.check_deadline()
            chunk = os.pread(descriptor, min(4096, MAX_MANIFEST_BYTES + 1 - offset), offset)
            if not chunk:
                break
            payload.extend(chunk)
            offset += len(chunk)
            if offset > MAX_MANIFEST_BYTES:
                raise _RecoveryFailure("INPUT_INVALID")
        if not _path_matches_descriptor(path, descriptor):
            raise _RecoveryFailure("SOURCE_IDENTITY_CHANGED", source_state="identity_changed")
        try:
            document = _validate_manifest(_closed_json_loads(bytes(payload)))
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise _RecoveryFailure("INPUT_INVALID") from exc
        return document, _sha256_bytes(bytes(payload))
    finally:
        os.close(descriptor)
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def _same_file(source: Path, destination: Path) -> bool:
    if os.path.normcase(os.fspath(source)) == os.path.normcase(os.fspath(destination)):
        return True
    try:
        return os.path.samefile(source, destination)
    except OSError:
        return False


def _terminal_manifest_digest(operation: _Operation, failure: _RecoveryFailure) -> str:
    return _sha256_bytes(
        _canonical_json(
            {
                "schema_version": "megalodon-sqlite-recovery-terminal-manifest-v1",
                "operation_id": operation.operation_id,
                "operation": operation.operation,
                "reason": failure.reason,
                "source_state": failure.source_state,
                "destination_created": operation.destination_created,
            }
        )
    )


def _failure_receipt(operation: _Operation, failure: _RecoveryFailure) -> dict[str, object]:
    finished = _wall_now()
    rollback = finished < operation.started_wall
    reason = "CLOCK_ROLLBACK" if rollback else failure.reason
    completion_uncertain = failure.completion_uncertain or reason == "COMPLETION_UNCERTAIN"
    elapsed = max(0, int((_monotonic() - operation.started_monotonic) * 1000))
    return {
        "schema_version": RECEIPT_SCHEMA,
        "operation_id": operation.operation_id,
        "operation": operation.operation,
        "status": "failed",
        "reason": reason,
        "started_at": _timestamp(operation.started_wall),
        "finished_at": _timestamp(finished),
        "clock_source": "operator_system_clock_untrusted",
        "monotonic_elapsed_ms": min(elapsed, MAX_ELAPSED_MS),
        "clock_rollback_observed": rollback,
        "completion_uncertain": completion_uncertain,
        "source_state": failure.source_state,
        "destination_state": (
            "unknown" if completion_uncertain and operation.destination_created else
            "incomplete_preserved" if operation.destination_created else "not_created"
        ),
        "destination_created": operation.destination_created,
        "destination_complete": False,
        "artifact_sha256": operation.artifact_sha256,
        "manifest_sha256": operation.manifest_sha256
        or _terminal_manifest_digest(operation, failure),
        "effects": dict(_EFFECTS),
    }


def _success_receipt(
    operation: _Operation,
    source: dict[str, object],
    destination: dict[str, object],
) -> dict[str, object]:
    source_identity = source.get("identity")
    destination_identity = destination.get("identity")
    if not isinstance(source_identity, dict) or not isinstance(destination_identity, dict):
        raise _RecoveryFailure("COMPLETION_UNCERTAIN", source_state="admitted", completion_uncertain=True)
    if (
        source_identity.get("device"),
        source_identity.get("inode"),
    ) == (
        destination_identity.get("device"),
        destination_identity.get("inode"),
    ):
        raise _RecoveryFailure("SAME_FILE_REFUSED", source_state="admitted")
    finished = _wall_now()
    if finished < operation.started_wall:
        raise _RecoveryFailure("CLOCK_ROLLBACK", source_state="admitted")
    elapsed = int((_monotonic() - operation.started_monotonic) * 1000)
    if elapsed > MAX_ELAPSED_MS:
        raise _RecoveryFailure("DEADLINE_EXCEEDED", source_state="admitted")
    return {
        "schema_version": RECEIPT_SCHEMA,
        "operation_id": operation.operation_id,
        "operation": operation.operation,
        "status": "completed",
        "reason": "COMPLETED",
        "started_at": _timestamp(operation.started_wall),
        "finished_at": _timestamp(finished),
        "clock_source": "operator_system_clock_untrusted",
        "monotonic_elapsed_ms": max(0, elapsed),
        "clock_rollback_observed": False,
        "completion_uncertain": False,
        "source": source,
        "destination": destination,
        "destination_created": True,
        "destination_complete": True,
        "destination_same_as_source": False,
        "artifact_sha256": operation.artifact_sha256,
        "manifest_sha256": operation.manifest_sha256,
        "effects": dict(_EFFECTS),
    }


def _new_operation(operation: str, operation_id: object) -> _Operation:
    return _Operation(operation, _safe_operation_id(operation_id), _wall_now(), _monotonic())


def backup_database(
    source: str | Path,
    destination: str | Path,
    manifest: str | Path,
    *,
    operation_id: str,
) -> dict[str, object]:
    """Back up one admitted schema-v3 store to a new artifact and manifest."""

    operation = _new_operation("backup", operation_id)
    source_database: _Database | None = None
    destination_database: _Database | None = None
    destination_directory: int | None = None
    try:
        if os.name != "posix":
            raise _RecoveryFailure("SOURCE_UNSAFE", source_state="unsafe")
        if operation.operation_id != operation_id:
            raise _RecoveryFailure("INPUT_INVALID")
        source_path = _absolute_path(source, destination=False)
        destination_path = _absolute_path(destination, destination=True)
        manifest_path = _absolute_path(manifest, destination=True)
        if _same_file(source_path, destination_path):
            raise _RecoveryFailure("SAME_FILE_REFUSED")
        if _same_file(source_path, manifest_path) or _same_file(destination_path, manifest_path):
            raise _RecoveryFailure("INPUT_INVALID")
        source_database = _open_source_database(source_path, immutable=False)
        source_snapshot = _inspect_database(
            operation, source_database, corrupt_reason="SOURCE_CORRUPT"
        )
        _assert_database_identity(source_database, source=True)
        destination_directory = _open_destination_directory(destination_path)
        _preflight_new_path(destination_path, destination_directory)
        manifest_directory = _open_destination_directory(manifest_path)
        try:
            _preflight_new_path(manifest_path, manifest_directory)
        finally:
            if manifest_directory is not None:
                os.close(manifest_directory)
        _check_space(destination_directory, destination_path, int(source_snapshot["logical_bytes"]))
        destination_database = _create_destination(
            operation, destination_path, destination_directory
        )
        destination_directory = None
        _copy_online(operation, source_database, destination_database)
        _assert_database_identity(source_database, source=True)
        _assert_database_identity(destination_database, source=False)
        destination_snapshot = _inspect_database(
            operation, destination_database, corrupt_reason="ARTIFACT_CORRUPT"
        )
        if destination_snapshot["logical_bytes"] > MAX_ARTIFACT_BYTES:
            raise _RecoveryFailure("ARTIFACT_LIMIT_EXCEEDED", source_state="admitted")
        if destination_database.connection is not None:
            destination_database.connection.close()
            destination_database.connection = None
        os.fsync(destination_database.descriptor)
        if destination_database.directory_descriptor is not None:
            os.fsync(destination_database.directory_descriptor)
        _check_remaining_reserve(
            destination_database.directory_descriptor, destination_path
        )
        operation.artifact_sha256 = _hash_descriptor(
            operation, destination_database.descriptor, MAX_ARTIFACT_BYTES
        )
        operation.manifest_sha256 = _write_manifest(
            operation,
            manifest_path,
            _manifest_document(operation, destination_snapshot),
        )
        _assert_database_identity(destination_database, source=False)
        return _success_receipt(operation, source_snapshot, destination_snapshot)
    except KeyboardInterrupt:
        failure = _RecoveryFailure(
            "INTERRUPTED_AFTER_CREATE"
            if operation.destination_created
            else "INTERRUPTED_BEFORE_CREATE",
            source_state=(
                "admitted" if source_database is not None else "not_admitted"
            ),
        )
        return _failure_receipt(
            operation,
            _classify_destination_binding(failure, destination_database),
        )
    except _RecoveryFailure as failure:
        return _failure_receipt(
            operation,
            _classify_destination_binding(failure, destination_database),
        )
    except Exception:
        failure = _RecoveryFailure(
            "IO_ERROR",
            source_state="admitted" if source_database else "not_admitted",
        )
        return _failure_receipt(
            operation,
            _classify_destination_binding(failure, destination_database),
        )
    finally:
        for database in (destination_database, source_database):
            if database is not None:
                try:
                    database.close()
                except BaseException:
                    pass
        if destination_directory is not None:
            try:
                os.close(destination_directory)
            except OSError:
                pass


def restore_database(
    source: str | Path,
    manifest: str | Path,
    destination: str | Path,
    *,
    artifact_sha256: str,
    operation_id: str,
) -> dict[str, object]:
    """Restore a verified backup artifact into one new, inactive database."""

    operation = _new_operation("restore", operation_id)
    source_database: _Database | None = None
    destination_database: _Database | None = None
    destination_directory: int | None = None
    try:
        if os.name != "posix":
            raise _RecoveryFailure("SOURCE_UNSAFE", source_state="unsafe")
        if (
            operation.operation_id != operation_id
            or not isinstance(artifact_sha256, str)
            or not _DIGEST.fullmatch(artifact_sha256)
        ):
            raise _RecoveryFailure("INPUT_INVALID")
        source_path = _absolute_path(source, destination=False)
        manifest_path = _absolute_path(manifest, destination=False)
        destination_path = _absolute_path(destination, destination=True)
        if _same_file(source_path, destination_path):
            raise _RecoveryFailure("SAME_FILE_REFUSED")
        if _same_file(manifest_path, destination_path) or _same_file(source_path, manifest_path):
            raise _RecoveryFailure("INPUT_INVALID")
        manifest_document, manifest_digest = _read_manifest(operation, manifest_path)
        operation.manifest_sha256 = manifest_digest
        if manifest_document["artifact_sha256"] != artifact_sha256:
            raise _RecoveryFailure("ARTIFACT_CORRUPT", source_state="corrupt")
        source_database = _open_source_database(source_path, immutable=True)
        generation = _file_generation(source_database.descriptor)
        operation.artifact_sha256 = _hash_descriptor(
            operation, source_database.descriptor, MAX_SOURCE_BYTES
        )
        if operation.artifact_sha256 != artifact_sha256:
            raise _RecoveryFailure("ARTIFACT_CORRUPT", source_state="corrupt")
        source_snapshot = _inspect_database(
            operation, source_database, corrupt_reason="ARTIFACT_CORRUPT"
        )
        recorded = manifest_document["artifact"]
        if not isinstance(recorded, dict) or any(
            source_snapshot[key] != recorded.get(key)
            for key in (
                "schema_user_version", "page_size", "page_count",
                "logical_bytes", "integrity_check", "foreign_key_check"
            )
        ):
            raise _RecoveryFailure("ARTIFACT_CORRUPT", source_state="corrupt")
        destination_directory = _open_destination_directory(destination_path)
        _preflight_new_path(destination_path, destination_directory)
        _check_space(destination_directory, destination_path, int(source_snapshot["logical_bytes"]))
        destination_database = _create_destination(
            operation, destination_path, destination_directory
        )
        destination_directory = None
        _copy_online(operation, source_database, destination_database)
        if _file_generation(source_database.descriptor) != generation:
            raise _RecoveryFailure("SOURCE_IDENTITY_CHANGED", source_state="identity_changed")
        if (
            _hash_descriptor(
                operation, source_database.descriptor, MAX_SOURCE_BYTES
            )
            != artifact_sha256
        ):
            raise _RecoveryFailure("SOURCE_IDENTITY_CHANGED", source_state="identity_changed")
        _assert_database_identity(source_database, source=True)
        _assert_database_identity(destination_database, source=False)
        destination_snapshot = _inspect_database(
            operation, destination_database, corrupt_reason="ARTIFACT_CORRUPT"
        )
        if destination_database.connection is not None:
            destination_database.connection.close()
            destination_database.connection = None
        os.fsync(destination_database.descriptor)
        if destination_database.directory_descriptor is not None:
            os.fsync(destination_database.directory_descriptor)
        _check_remaining_reserve(
            destination_database.directory_descriptor, destination_path
        )
        _assert_database_identity(destination_database, source=False)
        return _success_receipt(operation, source_snapshot, destination_snapshot)
    except KeyboardInterrupt:
        failure = _RecoveryFailure(
            "INTERRUPTED_AFTER_CREATE"
            if operation.destination_created
            else "INTERRUPTED_BEFORE_CREATE",
            source_state=(
                "admitted" if source_database is not None else "not_admitted"
            ),
        )
        return _failure_receipt(
            operation,
            _classify_destination_binding(failure, destination_database),
        )
    except _RecoveryFailure as failure:
        return _failure_receipt(
            operation,
            _classify_destination_binding(failure, destination_database),
        )
    except Exception:
        failure = _RecoveryFailure(
            "IO_ERROR",
            source_state="admitted" if source_database else "not_admitted",
        )
        return _failure_receipt(
            operation,
            _classify_destination_binding(failure, destination_database),
        )
    finally:
        for database in (destination_database, source_database):
            if database is not None:
                try:
                    database.close()
                except BaseException:
                    pass
        if destination_directory is not None:
            try:
                os.close(destination_directory)
            except OSError:
                pass
