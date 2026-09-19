"""Bounded SQLite backup and restore-to-new-destination engine (contract v1).

`docs/sqlite-recovery-contract.md` and `contracts/sqlite-recovery/v1` define a
normative vocabulary and terminal-receipt shape for backing up the schema-v3
local audit database and restoring a reviewed backup into a *new*
destination. Their own status line reads "Contract delivered... no runtime
command exists." This module is that runtime, and nothing more: it is not a
CLI, API, dashboard control, timer, watcher, service, or scheduler, and none
of it is wired into `storage.py`, the dashboard, or `python -m megalodon`.
Callers pass explicit paths; nothing here discovers, watches, or defaults to
any file.

Both operations use only SQLite's online-backup API (`sqlite3.Connection.
backup`), never an ordinary file copy, so committed WAL state is copied
coherently and a live writer is never disturbed. Every run ends in exactly
one closed terminal receipt: `status: "completed"` only after the destination
passes a full `PRAGMA integrity_check` and `PRAGMA foreign_key_check`, or
`status: "failed"` with one of the contract's 23 closed reason codes.
A destination that was created but not verified complete is always left in
place for operator review; this module never deletes it and never restores
in place. It performs no retention, migration, repair, network access, or
dashboard write, matching every `const: false` guarantee in the schema.

One documented gap: CPython's `sqlite3` module does not expose a per-step
busy-retry counter, so `MAX_BUSY_RETRIES` is kept as the contract's policy
constant but is not independently counted here. SQLite's own busy handler
retries within the backup call, bounded overall by the monotonic
`MAX_ELAPSED_MS` deadline enforced through the backup `progress` callback.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from time import monotonic
from types import MappingProxyType
from typing import Any

from .offline.common import require_unprivileged_linux

MAX_SOURCE_BYTES = 4 * 1024 ** 3
MAX_ARTIFACT_BYTES = 4 * 1024 ** 3
MIN_FREE_RESERVE_BYTES = 16 * 1024 ** 2
MAX_ELAPSED_MS = 300_000
MAX_BUSY_RETRIES = 60
PAGES_PER_STEP = 1024
REQUIRED_SCHEMA_USER_VERSION = 3
REQUIRED_MODE = 0o600

_OPERATION_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_ALLOWED_PAGE_SIZES = frozenset({512, 1024, 2048, 4096, 8192, 16384, 32768, 65536})
_SQLITE_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")

REASON_CODES = frozenset({
    "COMPLETED", "INPUT_INVALID", "SOURCE_UNAVAILABLE", "SOURCE_UNSAFE",
    "SOURCE_NOT_PRIVATE", "SOURCE_IDENTITY_CHANGED", "SCHEMA_INCOMPATIBLE",
    "SOURCE_CORRUPT", "DESTINATION_UNSAFE", "DESTINATION_EXISTS",
    "SAME_FILE_REFUSED", "LOCK_TIMEOUT", "DEADLINE_EXCEEDED",
    "DISK_RESERVE_INSUFFICIENT", "ARTIFACT_LIMIT_EXCEEDED", "ARTIFACT_CORRUPT",
    "FOREIGN_KEY_VIOLATION", "CLOCK_ROLLBACK", "INTERRUPTED_BEFORE_CREATE",
    "INTERRUPTED_AFTER_CREATE", "CLEANUP_FAILED", "COMPLETION_UNCERTAIN", "IO_ERROR",
})

_FIXED_EFFECTS = MappingProxyType({
    "source_mutated": False,
    "network_access_performed": False,
    "ordinary_copy_performed": False,
    "migration_performed": False,
    "repair_performed": False,
    "deletion_performed": False,
    "path_disclosed": False,
})


class SqliteRecoveryError(ValueError):
    """Raised only when no receipt can be constructed at all (bad call)."""

    def __init__(self, reason: str):
        if reason not in REASON_CODES:
            reason = "INPUT_INVALID"
        super().__init__(f"SQLITE_RECOVERY_V1:{reason}")
        self.reason = reason


class _Halt(Exception):
    """Carries a reason code and, when known, the source admission state.

    `source_state` is `None` for a halt raised after admission already
    succeeded (destination/copy/deadline failures): `_run` keeps whatever
    state it already recorded rather than letting this reset it back to
    `not_admitted`.
    """

    def __init__(self, reason: str, *, source_state: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.source_state = source_state


def _fmt(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_hex_prefixed(digest: str) -> str:
    return f"sha256:{digest}"


def _sha256_manifest(manifest: Mapping[str, Any]) -> str:
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_hex_prefixed(hashlib.sha256(encoded).hexdigest())


def _read_all(descriptor: int, ceiling: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = bytearray()
    while True:
        chunk = os.read(descriptor, 1_048_576)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > ceiling:
            raise _Halt("ARTIFACT_LIMIT_EXCEEDED", source_state="unsafe")
    return bytes(chunks)


def _identity(info: os.stat_result) -> Mapping[str, Any]:
    return MappingProxyType({
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "mode": format(stat.S_IMODE(info.st_mode), "04o"),
        "link_count": info.st_nlink,
        "path_disclosed": False,
    })


def _open_existing(path: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise _Halt("SOURCE_UNAVAILABLE", source_state="unavailable") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise _Halt("SOURCE_UNSAFE", source_state="unsafe")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != REQUIRED_MODE:
            raise _Halt("SOURCE_NOT_PRIVATE", source_state="unsafe")
        if info.st_size <= 0 or info.st_size > MAX_SOURCE_BYTES:
            raise _Halt("ARTIFACT_LIMIT_EXCEEDED", source_state="unsafe")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _descriptor_path(descriptor: int) -> str:
    for directory in ("/proc/self/fd", "/dev/fd"):
        candidate = f"{directory}/{descriptor}"
        if os.path.exists(candidate):
            return candidate
    raise _Halt("IO_ERROR")


def _verify_database(descriptor: int, *, read_only: bool) -> Mapping[str, Any]:
    uri = f"file:{_descriptor_path(descriptor)}?mode={'ro' if read_only else 'rw'}"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5)
    except sqlite3.Error:
        raise _Halt("SOURCE_CORRUPT") from None
    try:
        try:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        except sqlite3.Error:
            raise _Halt("SOURCE_CORRUPT") from None
        if version != REQUIRED_SCHEMA_USER_VERSION:
            raise _Halt("SCHEMA_INCOMPATIBLE")
        try:
            quick = connection.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.Error:
            raise _Halt("SOURCE_CORRUPT") from None
        if quick != "ok":
            raise _Halt("SOURCE_CORRUPT")
        try:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchone()
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            sqlite_version = str(connection.execute("select sqlite_version()").fetchone()[0])
        except sqlite3.Error:
            raise _Halt("SOURCE_CORRUPT") from None
        if integrity != "ok":
            raise _Halt("SOURCE_CORRUPT")
        if foreign_keys is not None:
            raise _Halt("FOREIGN_KEY_VIOLATION")
        if page_size not in _ALLOWED_PAGE_SIZES or page_count < 1:
            raise _Halt("SOURCE_CORRUPT")
        if not _SQLITE_VERSION.fullmatch(sqlite_version):
            sqlite_version = "0.0.0"
        info = os.fstat(descriptor)
        return MappingProxyType({
            "identity": _identity(info),
            "schema_user_version": version,
            "sqlite_version": sqlite_version,
            "page_size": page_size,
            "page_count": page_count,
            "logical_bytes": page_size * page_count,
            "integrity_check": "ok",
            "foreign_key_check": "ok",
        })
    finally:
        connection.close()


def _same_file(a: Path, b: Path) -> bool:
    return os.path.abspath(os.fspath(a)) == os.path.abspath(os.fspath(b))


def _open_parent_directory(path: Path) -> int:
    """Open the destination's parent by descriptor so the leaf create below
    is dir_fd-relative: a symlinked parent fails here (O_NOFOLLOW), and the
    leaf create can no longer be redirected by a parent swapped in later."""
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        return os.open(path.parent, flags)
    except OSError:
        raise _Halt("DESTINATION_UNSAFE") from None


def _free_bytes(directory_descriptor: int) -> int:
    try:
        usage = os.statvfs(directory_descriptor)
    except OSError:
        raise _Halt("DESTINATION_UNSAFE") from None
    return usage.f_bavail * usage.f_frsize


def _create_destination(destination: Path, estimated_bytes: int) -> int:
    name = destination.name
    if not name or name in {".", ".."}:
        raise _Halt("DESTINATION_UNSAFE")
    parent_descriptor = _open_parent_directory(destination)
    try:
        if _free_bytes(parent_descriptor) - estimated_bytes < MIN_FREE_RESERVE_BYTES:
            raise _Halt("DISK_RESERVE_INSUFFICIENT")
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, REQUIRED_MODE, dir_fd=parent_descriptor)
        except FileExistsError:
            raise _Halt("DESTINATION_EXISTS") from None
        except OSError:
            raise _Halt("INTERRUPTED_BEFORE_CREATE") from None
        return descriptor
    finally:
        os.close(parent_descriptor)


def _copy_via_backup_api(
    source_descriptor: int, destination_descriptor: int, deadline_monotonic: float,
) -> None:
    source_conn = sqlite3.connect(f"file:{_descriptor_path(source_descriptor)}?mode=ro", uri=True, timeout=5)
    destination_conn = sqlite3.connect(_descriptor_path(destination_descriptor), timeout=5)

    def progress(status: int, remaining: int, total: int) -> None:
        if monotonic() > deadline_monotonic:
            raise sqlite3.OperationalError("deadline exceeded")

    try:
        try:
            source_conn.backup(destination_conn, pages=PAGES_PER_STEP, progress=progress, sleep=0.05)
        except sqlite3.OperationalError as exc:
            if "lock" in str(exc).lower() or "busy" in str(exc).lower():
                raise _Halt("LOCK_TIMEOUT") from exc
            raise _Halt("DEADLINE_EXCEEDED") from exc
        except sqlite3.Error:
            raise _Halt("IO_ERROR") from None
        destination_conn.commit()
        # The source's journal mode carries into the copy; force a checkpoint
        # and drop WAL so the artifact is one self-contained file with no
        # separate -wal/-shm sidecar left for the later digest to miss.
        destination_conn.execute("PRAGMA journal_mode=DELETE")
    finally:
        destination_conn.close()
        source_conn.close()
    os.fsync(destination_descriptor)


def _manifest(
    operation: str, operation_id: str, reason: str,
    source: Mapping[str, Any] | None, destination: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    return {
        "schema_version": "megalodon-sqlite-recovery-manifest-v1",
        "operation": operation,
        "operation_id": operation_id,
        "reason": reason,
        "source_identity": dict(source["identity"]) if source else None,
        "destination_identity": dict(destination["identity"]) if destination else None,
        "source_page_count": source["page_count"] if source else None,
        "destination_page_count": destination["page_count"] if destination else None,
    }


def _validate_operation_id(operation_id: object) -> str:
    if type(operation_id) is not str or not _OPERATION_ID.fullmatch(operation_id):
        raise SqliteRecoveryError("INPUT_INVALID")
    return operation_id


def _run(
    operation: str, operation_id: str,
    admit_source,
    destination_path: Path,
) -> Mapping[str, Any]:
    started_monotonic = monotonic()
    started_wall = datetime.now(timezone.utc)
    deadline = started_monotonic + (MAX_ELAPSED_MS / 1000)

    destination_created = False
    destination_descriptor: int | None = None
    source_descriptor: int | None = None
    source_verified: Mapping[str, Any] | None = None
    destination_verified: Mapping[str, Any] | None = None
    artifact_digest: str | None = None
    reason = "COMPLETED"
    source_state = "not_admitted"
    completion_uncertain = False

    try:
        source_descriptor, source_verified, artifact_digest = admit_source()
        source_state = "admitted"

        destination_descriptor = _create_destination(
            destination_path, source_verified["logical_bytes"],
        )
        destination_created = True

        if monotonic() > deadline:
            raise _Halt("DEADLINE_EXCEEDED", source_state=source_state)

        _copy_via_backup_api(source_descriptor, destination_descriptor, deadline)
        destination_size = os.fstat(destination_descriptor).st_size
        if destination_size > MAX_ARTIFACT_BYTES:
            raise _Halt("ARTIFACT_LIMIT_EXCEEDED", source_state=source_state)

        destination_verified = _verify_database(destination_descriptor, read_only=False)
        if (
            source_verified["identity"]["device"],
            source_verified["identity"]["inode"],
        ) == (
            destination_verified["identity"]["device"],
            destination_verified["identity"]["inode"],
        ):
            raise _Halt("SAME_FILE_REFUSED", source_state=source_state)
        artifact_bytes = _read_all(destination_descriptor, MAX_ARTIFACT_BYTES)
        artifact_digest = artifact_digest or _sha256_hex_prefixed(
            hashlib.sha256(artifact_bytes).hexdigest()
        )
        # An untrusted wall-clock rollback can never be reported as success,
        # even though the copy itself verified cleanly: route it through the
        # same closed failure path below (destination stays preserved, not
        # deleted, for operator review) rather than build an inconsistent
        # receipt (successReceipt forbids clock_rollback_observed: true).
        if datetime.now(timezone.utc) < started_wall:
            raise _Halt("CLOCK_ROLLBACK", source_state=source_state)
        finished_wall = datetime.now(timezone.utc)
        manifest = _manifest(operation, operation_id, "COMPLETED", source_verified, destination_verified)
        receipt = {
            "schema_version": "megalodon-sqlite-recovery-receipt-v1",
            "operation_id": operation_id,
            "operation": operation,
            "status": "completed",
            "reason": "COMPLETED",
            "started_at": _fmt(started_wall),
            "finished_at": _fmt(finished_wall),
            "clock_source": "operator_system_clock_untrusted",
            "monotonic_elapsed_ms": min(int((monotonic() - started_monotonic) * 1000), MAX_ELAPSED_MS),
            "clock_rollback_observed": False,
            "completion_uncertain": False,
            "source": source_verified,
            "destination": destination_verified,
            "destination_created": True,
            "destination_complete": True,
            "destination_same_as_source": False,
            "artifact_sha256": artifact_digest,
            "manifest_sha256": _sha256_manifest(manifest),
            "effects": dict(_FIXED_EFFECTS),
        }
        return MappingProxyType(receipt)
    except _Halt as halt:
        reason = halt.reason
        if halt.source_state is not None:
            source_state = halt.source_state
    except BaseException:
        reason = "IO_ERROR"
        completion_uncertain = destination_created
    finally:
        for descriptor in (source_descriptor, destination_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    finished_wall = datetime.now(timezone.utc)
    clock_rollback = finished_wall < started_wall
    if clock_rollback:
        reason = "CLOCK_ROLLBACK"
    manifest = _manifest(operation, operation_id, reason, source_verified, destination_verified)
    receipt = {
        "schema_version": "megalodon-sqlite-recovery-receipt-v1",
        "operation_id": operation_id,
        "operation": operation,
        "status": "failed",
        "reason": reason,
        "started_at": _fmt(started_wall),
        "finished_at": _fmt(finished_wall),
        "clock_source": "operator_system_clock_untrusted",
        "monotonic_elapsed_ms": min(int((monotonic() - started_monotonic) * 1000), MAX_ELAPSED_MS),
        "clock_rollback_observed": clock_rollback,
        "completion_uncertain": completion_uncertain,
        "source_state": source_state,
        "destination_state": "incomplete_preserved" if destination_created else "not_created",
        "destination_created": destination_created,
        "destination_complete": False,
        "artifact_sha256": artifact_digest,
        "manifest_sha256": _sha256_manifest(manifest),
        "effects": dict(_FIXED_EFFECTS),
    }
    return MappingProxyType(receipt)


def backup_database(
    *, operation_id: str, source_path: str | os.PathLike[str], destination_path: str | os.PathLike[str],
) -> Mapping[str, Any]:
    """Back up one private schema-v3 SQLite store into a brand-new artifact.

    Returns one closed terminal receipt (`status` `"completed"` or
    `"failed"`); it never raises for an operational condition. It raises
    `SqliteRecoveryError("INPUT_INVALID")` only when `operation_id` itself is
    unusable, since a receipt cannot be built without one.
    """
    require_unprivileged_linux()
    operation_id = _validate_operation_id(operation_id)
    destination = Path(os.fspath(destination_path))

    def admit_source():
        source = Path(os.fspath(source_path))
        if _same_file(source, destination):
            raise _Halt("SAME_FILE_REFUSED")
        descriptor = _open_existing(source)
        try:
            verified = _verify_database(descriptor, read_only=True)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, verified, None

    return _run("backup", operation_id, admit_source, destination)


def restore_backup(
    *, operation_id: str, artifact_path: str | os.PathLike[str],
    expected_artifact_sha256: str, destination_path: str | os.PathLike[str],
) -> Mapping[str, Any]:
    """Restore one digest-verified backup artifact into a brand-new destination.

    `expected_artifact_sha256` is operator-supplied out-of-band identity, the
    same trust boundary `megalodon.threat_context` uses for its bundle
    digest: a match is not evidence the artifact is otherwise trustworthy,
    only that it is the exact bytes the operator selected. Restoring in place
    over an existing store is never supported; `destination_path` must not
    already exist.
    """
    require_unprivileged_linux()
    operation_id = _validate_operation_id(operation_id)
    if type(expected_artifact_sha256) is not str or not _DIGEST.fullmatch(expected_artifact_sha256):
        raise SqliteRecoveryError("INPUT_INVALID")
    destination = Path(os.fspath(destination_path))

    def admit_source():
        artifact = Path(os.fspath(artifact_path))
        if _same_file(artifact, destination):
            raise _Halt("SAME_FILE_REFUSED")
        descriptor = _open_existing(artifact)
        try:
            actual_bytes = _read_all(descriptor, MAX_ARTIFACT_BYTES)
            actual_digest = _sha256_hex_prefixed(hashlib.sha256(actual_bytes).hexdigest())
            if actual_digest != expected_artifact_sha256:
                raise _Halt("ARTIFACT_CORRUPT")
            verified = _verify_database(descriptor, read_only=True)
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor, verified, actual_digest

    return _run("restore", operation_id, admit_source, destination)
