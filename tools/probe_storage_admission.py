"""Bounded native storage-admission diagnostic for issue #345.

This probe does not relax admission. It creates one disposable owner-private
database, follows the production descriptor path strategy when admission permits
it, records only redacted classifications, invokes the production connection-path
validator unchanged, and removes the fixture.

Expected storage refusals are evidence, not probe crashes: they are serialized so
the native workflow can continue to the existing sample command and retain both
observations. Unexpected programming errors still fail the probe.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tempfile

from megalodon import storage


MAX_REPORT_BYTES = 4096


def _strategy(path: str) -> str:
    if path.startswith("/proc/self/fd/"):
        return "proc_self_fd"
    if path.startswith("/dev/fd/"):
        return "dev_fd"
    return "other"


def _same_stat(path: Path, fd: int) -> bool:
    try:
        return os.path.samestat(path.stat(follow_symlinks=False), os.fstat(fd))
    except OSError:
        return False


def _storage_code(exc: storage.StorageSchemaError) -> str:
    value = str(exc)
    if re.fullmatch(r"[A-Z_]+:[A-Z_]+", value):
        return value
    return "STORAGE_PATH:UNCLASSIFIED"


def _errno_code(exc: OSError) -> str:
    code = errno.errorcode.get(getattr(exc, "errno", None), "UNKNOWN")
    return f"error:{code}"


def _path_kind(path: Path) -> str:
    try:
        info = path.lstat()
    except OSError as exc:
        return _errno_code(exc)
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISREG(info.st_mode):
        return "regular"
    return "other"


def _open_status(path: Path, flags: int) -> str:
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        return "accepted"
    except OSError as exc:
        return _errno_code(exc)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _relative_open_status(parent: Path, child: str, flags: int) -> str:
    parent_descriptor = None
    child_descriptor = None
    try:
        parent_descriptor = os.open(parent, flags)
        try:
            child_descriptor = os.open(child, flags, dir_fd=parent_descriptor)
        except OSError as exc:
            return _errno_code(exc)
        return "accepted"
    except OSError as exc:
        return f"parent_{_errno_code(exc)}"
    finally:
        if child_descriptor is not None:
            os.close(child_descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def _darwin_alias_observation() -> dict[str, object]:
    """Inspect only fixed root-owned macOS alias locations without mutation."""

    if sys.platform != "darwin":
        return {"status": "not_applicable"}

    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return {
        "status": "observed",
        "var_kind": _path_kind(Path("/var")),
        "private_kind": _path_kind(Path("/private")),
        "private_var_kind": _path_kind(Path("/private/var")),
        "var_resolves_private_var": os.path.realpath("/var") == "/private/var",
        "private_var_direct_open": _open_status(Path("/private/var"), flags),
        "private_var_relative_open": _relative_open_status(
            Path("/private"), "var", flags
        ),
    }


def _temporary_path_class(path: Path) -> str:
    parts = path.parts
    if len(parts) >= 3 and parts[1] == "private" and parts[2] == "var":
        return "private_var"
    if len(parts) >= 2 and parts[1] == "var":
        return "var_alias"
    if len(parts) >= 2 and parts[1] == "Users":
        return "users"
    return "other"


def _sqlite_error_observation(exc: sqlite3.Error) -> dict[str, object]:
    code = getattr(exc, "sqlite_errorcode", None)
    name = getattr(exc, "sqlite_errorname", None)
    return {
        "cause_type": type(exc).__name__[:80],
        "sqlite_errorcode": int(code) if isinstance(code, int) else "unavailable",
        "sqlite_errorname": (
            str(name)
            if isinstance(name, str)
            and re.fullmatch(r"SQLITE_[A-Z0-9_]+", name)
            else "unavailable"
        ),
    }


def _darwin_transaction_stage_observation(use_descriptor_path: bool) -> dict[str, object]:
    """Identify the first SQLite stage that fails in a disposable fixture."""

    if sys.platform != "darwin":
        return {"status": "not_applicable"}

    with tempfile.TemporaryDirectory(prefix="megalodon-stage-probe-") as root:
        private = Path(root) / "private"
        private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
        path = private / "audit.db"
        directory_fd = None
        database_fd = None
        connection = None
        try:
            try:
                directory_fd = storage._open_private_directory(
                    private, create=False, prefix="STORAGE_PATH"
                )
                database_fd, _ = storage._open_private_database(
                    path,
                    directory_fd,
                    writable=True,
                    create=True,
                    prefix="STORAGE_PATH",
                )
            except storage.StorageSchemaError as exc:
                return {"status": _storage_code(exc)}

            anchored = storage._anchored_database_path(
                database_fd, path, "STORAGE_PATH"
            )
            sqlite_path = anchored if use_descriptor_path else path
            result: dict[str, object] = {
                "status": "running",
                "path_mode": "descriptor" if use_descriptor_path else "canonical",
                "database_identity_before": _same_stat(path, database_fd),
                "directory_identity_before": (
                    directory_fd is not None and _same_stat(private, directory_fd)
                ),
            }
            try:
                connection = sqlite3.connect(
                    f"{sqlite_path.as_uri()}?mode=rw&cache=private",
                    uri=True,
                    timeout=10,
                    check_same_thread=False,
                )
                storage._validate_connection_path(
                    connection,
                    storage._absolute_database_path(path),
                    "STORAGE_PATH",
                    anchor=anchored if use_descriptor_path else None,
                )
            except storage.StorageSchemaError as exc:
                result["status"] = _storage_code(exc)
                return result
            except sqlite3.Error as exc:
                result["status"] = "connect_failed"
                result.update(_sqlite_error_observation(exc))
                return result

            for stage, statement in (
                ("pragma_user_version", "PRAGMA user_version"),
                ("schema_read", "SELECT type, name, tbl_name FROM sqlite_schema"),
                ("begin_immediate", "BEGIN IMMEDIATE"),
            ):
                try:
                    connection.execute(statement).fetchall()
                except sqlite3.Error as exc:
                    result["status"] = f"{stage}_failed"
                    result.update(_sqlite_error_observation(exc))
                    return result
                result[stage] = "accepted"

            connection.rollback()
            result["status"] = "accepted"
            result["database_identity_after"] = _same_stat(path, database_fd)
            result["directory_identity_after"] = (
                directory_fd is not None and _same_stat(private, directory_fd)
            )
            result["journal_sidecar_after_rollback"] = (
                path.parent / f"{path.name}-journal"
            ).exists()
            return result
        finally:
            if connection is not None:
                connection.close()
            if database_fd is not None:
                os.close(database_fd)
            if directory_fd is not None:
                os.close(directory_fd)


def _darwin_directory_anchor_sqlite_observation() -> dict[str, object]:
    """Test a directory-fd SQLite path in a disposable Darwin-only fixture."""

    if sys.platform != "darwin":
        return {"status": "not_applicable"}

    with tempfile.TemporaryDirectory(prefix="megalodon-dirfd-probe-") as root:
        private = Path(root) / "private"
        private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
        path = private / "audit.db"
        directory_fd = None
        database_fd = None
        connection = None
        try:
            try:
                directory_fd = storage._open_private_directory(
                    private, create=False, prefix="STORAGE_PATH"
                )
                database_fd, _ = storage._open_private_database(
                    path,
                    directory_fd,
                    writable=True,
                    create=True,
                    prefix="STORAGE_PATH",
                )
            except storage.StorageSchemaError as exc:
                return {"status": _storage_code(exc)}

            if directory_fd is None:
                return {"status": "directory_descriptor_unavailable"}
            anchor_root = Path(
                storage._descriptor_database_path(directory_fd, private)
            )
            if str(anchor_root) == str(private):
                return {"status": "directory_descriptor_path_unavailable"}
            candidate = anchor_root / path.name
            try:
                same_identity = os.path.samestat(
                    candidate.stat(), os.fstat(database_fd)
                )
            except OSError as exc:
                return {
                    "status": "candidate_stat_failed",
                    "candidate_identity": False,
                    "candidate_stat": _errno_code(exc),
                }
            if not same_identity:
                return {
                    "status": "candidate_identity_mismatch",
                    "candidate_identity": False,
                }

            try:
                connection = sqlite3.connect(
                    f"{candidate.as_uri()}?mode=rw&cache=private",
                    uri=True,
                    timeout=10,
                    check_same_thread=False,
                )
                storage._validate_connection_path(
                    connection,
                    storage._absolute_database_path(path),
                    "STORAGE_PATH",
                    anchor=candidate,
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE megalodon_directory_anchor_probe(value INTEGER)"
                )
                connection.rollback()
            except storage.StorageSchemaError as exc:
                return {
                    "status": _storage_code(exc),
                    "candidate_identity": True,
                }
            except sqlite3.Error as exc:
                return {
                    "status": "sqlite_error",
                    "candidate_identity": True,
                    **_sqlite_error_observation(exc),
                }
            return {
                "status": "accepted",
                "candidate_identity": True,
                "descriptor_strategy": _strategy(str(anchor_root)),
            }
        finally:
            if connection is not None:
                connection.close()
            if database_fd is not None:
                os.close(database_fd)
            if directory_fd is not None:
                os.close(directory_fd)


def _production_store_observation() -> dict[str, object]:
    """Exercise the production Store constructor without exposing SQLite text."""

    result: dict[str, object] = {}
    store = None
    with tempfile.TemporaryDirectory(prefix="megalodon-store-probe-") as root:
        private = Path(root) / "private"
        private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
        path = private / "audit.db"
        try:
            store = storage.Store(path)
        except storage.StorageSchemaError as exc:
            result["status"] = _storage_code(exc)
            cause = exc.__cause__
            if isinstance(cause, sqlite3.Error):
                result.update(_sqlite_error_observation(cause))
            elif cause is None:
                result["cause_type"] = "none"
            else:
                result["cause_type"] = type(cause).__name__[:80]
        else:
            result["status"] = "accepted"
            result["cause_type"] = "none"
        finally:
            if store is not None:
                store.close()
    return result


def collect_report() -> dict[str, object]:
    report: dict[str, object] = {
        "platform": sys.platform,
        "python": ".".join(map(str, sys.version_info[:3])),
        "sqlite_version": sqlite3.sqlite_version,
        "darwin_alias": _darwin_alias_observation(),
        "darwin_directory_anchor_sqlite": _darwin_directory_anchor_sqlite_observation(),
        "darwin_descriptor_transaction": _darwin_transaction_stage_observation(True),
        "darwin_canonical_transaction": _darwin_transaction_stage_observation(False),
        "store_constructor": _production_store_observation(),
    }
    try:
        source_id = sqlite3.connect(":memory:").execute(
            "SELECT sqlite_source_id()"
        ).fetchone()[0]
        report["sqlite_source_id"] = str(source_id)[:160]
    except sqlite3.Error:
        report["sqlite_source_id"] = "unavailable"

    with tempfile.TemporaryDirectory(prefix="megalodon-storage-probe-") as root:
        private = Path(root) / "private"
        private.mkdir(mode=storage.PRIVATE_DIRECTORY_MODE)
        path = private / "audit.db"
        resolved = storage._resolve_top_level_system_alias(private)
        report["temporary_path_class"] = _temporary_path_class(private)
        report["system_alias_rewritten"] = resolved != private

        directory_fd = None
        database_fd = None
        connection = None
        try:
            try:
                directory_fd = storage._open_private_directory(
                    private, create=False, prefix="STORAGE_PATH"
                )
            except storage.StorageSchemaError as exc:
                report["production_directory_open"] = _storage_code(exc)
                report["diagnostic_status"] = "directory_open_refused"
                return report

            report["production_directory_open"] = "accepted"
            try:
                database_fd, _ = storage._open_private_database(
                    path,
                    directory_fd,
                    writable=True,
                    create=True,
                    prefix="STORAGE_PATH",
                )
            except storage.StorageSchemaError as exc:
                report["production_database_open"] = _storage_code(exc)
                report["diagnostic_status"] = "database_open_refused"
                return report

            report["production_database_open"] = "accepted"
            selected = storage._descriptor_database_path(database_fd, path)
            report["descriptor_strategy"] = _strategy(selected)
            report["database_identity_before"] = _same_stat(path, database_fd)
            report["directory_identity_before"] = (
                directory_fd is not None and _same_stat(private, directory_fd)
            )
            generation = storage._directory_generation(directory_fd)

            try:
                connection = sqlite3.connect(
                    f"{Path(selected).as_uri()}?mode=rw&cache=private",
                    uri=True,
                    timeout=10,
                    check_same_thread=False,
                )
            except sqlite3.Error:
                report["sqlite_connect"] = "error"
                report["diagnostic_status"] = "sqlite_connect_failed"
                return report

            report["sqlite_connect"] = "accepted"
            rows = connection.execute("PRAGMA database_list").fetchall()
            report["database_list_count"] = len(rows)
            if len(rows) == 1:
                seq, name, filename = rows[0][:3]
                report["database_list_shape"] = (
                    "main"
                    if int(seq) == 0 and str(name) == "main" and filename
                    else "unexpected"
                )
                if filename:
                    actual = storage._absolute_database_path(str(filename))
                    expected = storage._absolute_database_path(path)
                    selected_abs = storage._absolute_database_path(selected)
                    report["sqlite_filename_relation"] = (
                        "admitted_path"
                        if os.path.normcase(os.fspath(actual))
                        == os.path.normcase(os.fspath(expected))
                        else "descriptor_path"
                        if os.path.normcase(os.fspath(actual))
                        == os.path.normcase(os.fspath(selected_abs))
                        else "other"
                    )
                else:
                    report["sqlite_filename_relation"] = "empty"
            else:
                report["database_list_shape"] = "unexpected"
                report["sqlite_filename_relation"] = "unavailable"

            report["database_identity_after"] = _same_stat(path, database_fd)
            report["directory_identity_after"] = (
                directory_fd is not None and _same_stat(private, directory_fd)
            )
            report["directory_generation_changed"] = (
                storage._directory_generation(directory_fd) != generation
            )
            try:
                storage._validate_connection_path(
                    connection,
                    storage._absolute_database_path(path),
                    "STORAGE_PATH",
                    anchor=Path(selected),
                )
            except storage.StorageSchemaError as exc:
                report["production_validator"] = _storage_code(exc)
            else:
                report["production_validator"] = "accepted"
            report["diagnostic_status"] = "complete"
            return report
        finally:
            if connection is not None:
                connection.close()
            if database_fd is not None:
                os.close(database_fd)
            if directory_fd is not None:
                os.close(directory_fd)


def main() -> int:
    serialized = json.dumps(collect_report(), sort_keys=True)
    if len(serialized.encode("utf-8")) > MAX_REPORT_BYTES:
        raise SystemExit("STORAGE_DIAGNOSTIC:REPORT_TOO_LARGE")
    print(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
