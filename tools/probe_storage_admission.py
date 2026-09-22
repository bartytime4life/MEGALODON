"""Bounded native storage-admission diagnostic for issue #345.

This probe does not relax admission. It creates one disposable owner-private
database, follows the production descriptor path strategy, records only
redacted classifications, invokes the production connection-path validator,
and removes the fixture.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

from megalodon import storage


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


def main() -> int:
    report: dict[str, object] = {
        "platform": sys.platform,
        "python": ".".join(map(str, sys.version_info[:3])),
        "sqlite_version": sqlite3.sqlite_version,
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
        directory_fd = storage._open_private_directory(
            private, create=False, prefix="STORAGE_PATH"
        )
        database_fd = None
        connection = None
        try:
            database_fd, _ = storage._open_private_database(
                path, directory_fd, writable=True, create=True,
                prefix="STORAGE_PATH",
            )
            selected = storage._descriptor_database_path(database_fd, path)
            report["descriptor_strategy"] = _strategy(selected)
            report["database_identity_before"] = _same_stat(path, database_fd)
            report["directory_identity_before"] = (
                directory_fd is not None and _same_stat(private, directory_fd)
            )
            generation = storage._directory_generation(directory_fd)
            connection = sqlite3.connect(
                f"{Path(selected).as_uri()}?mode=rw&cache=private",
                uri=True, timeout=10, check_same_thread=False,
            )
            rows = connection.execute("PRAGMA database_list").fetchall()
            report["database_list_count"] = len(rows)
            if len(rows) == 1:
                seq, name, filename = rows[0][:3]
                report["database_list_shape"] = (
                    "main" if int(seq) == 0 and str(name) == "main" and filename
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
                    connection, storage._absolute_database_path(path), "STORAGE_PATH"
                )
            except storage.StorageSchemaError as exc:
                report["production_validator"] = str(exc)
            else:
                report["production_validator"] = "accepted"
        finally:
            if connection is not None:
                connection.close()
            if database_fd is not None:
                os.close(database_fd)
            if directory_fd is not None:
                os.close(directory_fd)

    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
