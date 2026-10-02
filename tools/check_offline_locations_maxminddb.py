"""Exercise the pinned maxminddb file-descriptor integration without pytest.

The native installer CI lane runs this against maxminddb 3.2.0, which is
otherwise absent from the general test environment.
"""
from __future__ import annotations

import errno
import importlib.metadata
import io
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import maxminddb  # noqa: E402
from megalodon import offline_locations  # noqa: E402
from megalodon.offline_locations import OfflineLocations  # noqa: E402


def require_closed(descriptor: int) -> None:
    try:
        os.fstat(descriptor)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
    else:
        raise AssertionError("offline-location descriptor remained open")


def main() -> None:
    version = importlib.metadata.version("maxminddb")
    if version != "3.2.0":
        raise AssertionError(f"expected pinned maxminddb 3.2.0, got {version}")

    with tempfile.TemporaryDirectory(prefix="megalodon-mmdb-") as raw_directory:
        directory = Path(raw_directory)
        directory.chmod(0o700)
        database = directory / "invalid.mmdb"
        database.write_bytes(b"not a database")
        database.chmod(0o600)

        real_os_open = os.open
        opened: list[int] = []

        def tracked_open(*args, **kwargs):
            descriptor = real_os_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        real_open_database = maxminddb.open_database
        observed_sources: list[tuple[object, int]] = []

        def inspected_open_database(source, mode):
            if not isinstance(source, io.BufferedReader) or source.mode != "rb":
                raise AssertionError("MODE_FD did not receive a binary file object")
            if mode != maxminddb.MODE_FD:
                raise AssertionError("MODE_FD was not selected")
            observed_sources.append((source, source.fileno()))
            return real_open_database(source, mode=mode)

        os.open = tracked_open
        maxminddb.open_database = inspected_open_database
        try:
            try:
                OfflineLocations.open(database)
            except ValueError as error:
                if not isinstance(error.__cause__, maxminddb.InvalidDatabaseError):
                    raise AssertionError(
                        "real maxminddb 3.2.0 did not validate the database"
                    ) from error
            else:
                raise AssertionError("invalid MMDB was accepted")

            if len(opened) != 1 or len(observed_sources) != 1:
                raise AssertionError("private MMDB path was not opened exactly once")
            source, descriptor = observed_sources[0]
            if not source.closed:
                raise AssertionError("binary file wrapper remained open")
            require_closed(descriptor)

            database.chmod(0o644)
            before = len(observed_sources)
            try:
                OfflineLocations.open(database)
            except ValueError as error:
                if "owner-private regular file" not in str(error):
                    raise
            else:
                raise AssertionError("readable-by-group MMDB was accepted")
            if len(observed_sources) != before:
                raise AssertionError("unsafe file reached maxminddb")
            if len(opened) != 2:
                raise AssertionError("unsafe MMDB was not closed after metadata check")
            require_closed(opened[-1])
        finally:
            maxminddb.open_database = real_open_database
            os.open = real_os_open

    print("OFFLINE_LOCATIONS_MAXMINDDB_3_2_0:PASS")


if __name__ == "__main__":
    main()
