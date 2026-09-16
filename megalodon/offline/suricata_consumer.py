"""No-write capacity preflight for one immutable Suricata publication."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Any, NamedTuple


STORE_PAGE_SIZE_BYTES = 4_096
STORE_MAX_PAGES = 131_072
STORE_MAX_BYTES = 536_870_912
MAX_RECORDS = 10_000
MAX_NORMALIZED_BATCH_BYTES = 16_777_216
CAPACITY_RESERVATION_MULTIPLIER = 4
CAPACITY_RESERVATION_OVERHEAD_BYTES = 8_388_608

ERROR_CODES = frozenset({
    "INPUT_CONTRACT", "SCHEMA_INCOMPATIBLE", "STORAGE_CAPACITY",
})


class ConsumerPreflightError(ValueError):
    """A fixed, path-free diagnostic for a refused consumer preflight."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "STORAGE_CAPACITY"
        self.code = code
        self.transaction_status = "not_started"
        self.action_status = "not_attempted"
        super().__init__(f"SURICATA_CONSUMER_V1:{code}")


class ConsumerPreflight(NamedTuple):
    """Immutable admission evidence; it conveys no transaction authority."""

    publication: tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]
    capacity: Mapping[str, int]
    transaction_status: str
    action_status: str


def _fail(code: str) -> None:
    raise ConsumerPreflightError(code) from None


def _fixed_integer(value: Any, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        _fail("INPUT_CONTRACT")
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _is_frozen(value: Any) -> bool:
    if isinstance(value, MappingProxyType):
        return all(type(key) is str and _is_frozen(item) for key, item in value.items())
    if isinstance(value, tuple):
        return all(_is_frozen(item) for item in value)
    return value is None or type(value) in {str, int, bool}


def _query_integer(connection: sqlite3.Connection, statement: str) -> int:
    try:
        row = connection.execute(statement).fetchone()
    except sqlite3.Error:
        _fail("STORAGE_CAPACITY")
    if row is None or len(row) != 1:
        _fail("STORAGE_CAPACITY")
    value = row[0]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail("STORAGE_CAPACITY")
    return value


def _validate_publication(
    publication: Any,
) -> tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any], int]:
    if (
        not isinstance(publication, tuple)
        or len(publication) != 2
        or not isinstance(publication[0], tuple)
        or not isinstance(publication[1], MappingProxyType)
        or not _is_frozen(publication)
    ):
        _fail("INPUT_CONTRACT")
    batch, receipt = publication
    if not batch or len(batch) > MAX_RECORDS or any(not isinstance(row, Mapping) for row in batch):
        _fail("INPUT_CONTRACT")
    if (
        receipt.get("schema_version") != "suricata-eve-reader-receipt-v1"
        or receipt.get("status") != "complete"
        or receipt.get("record_count") != len(batch)
        or receipt.get("normalized_alert_count") != len(batch)
        or receipt.get("action_status") != "not_attempted"
        or receipt.get("durable_write_status") != "not_attempted"
    ):
        _fail("INPUT_CONTRACT")
    try:
        normalized_bytes = sum(len(json.dumps(
            _plain(row), sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")) for row in batch)
    except (TypeError, ValueError, OverflowError, RecursionError):
        _fail("INPUT_CONTRACT")
    declared_bytes = _fixed_integer(
        receipt.get("normalized_batch_bytes"), maximum=MAX_NORMALIZED_BATCH_BYTES,
    )
    if normalized_bytes != declared_bytes or normalized_bytes > MAX_NORMALIZED_BATCH_BYTES:
        _fail("INPUT_CONTRACT")
    return batch, receipt, normalized_bytes


def preflight_publication(
    connection: sqlite3.Connection,
    publication: Any,
    *,
    database_path: str | os.PathLike[str],
) -> ConsumerPreflight:
    """Admit one reader publication without opening a transaction or writing rows.

    ``connection`` is the connection a later, separately authorized consumer would
    use. This function deliberately performs no schema creation, migration,
    retention, purge, or transaction operation.
    """
    batch, receipt, normalized_bytes = _validate_publication(publication)
    if connection.in_transaction:
        _fail("STORAGE_CAPACITY")

    try:
        rows = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [row[2] for row in rows if len(row) == 3 and row[1] == "main"]
        supplied_path = Path(database_path).resolve(strict=True)
        connected_path = Path(main_paths[0]).resolve(strict=True)
    except (sqlite3.Error, OSError, IndexError, TypeError, ValueError):
        _fail("STORAGE_CAPACITY")
    if len(main_paths) != 1 or supplied_path != connected_path:
        _fail("STORAGE_CAPACITY")

    page_size = _query_integer(connection, "PRAGMA page_size")
    if page_size != STORE_PAGE_SIZE_BYTES:
        _fail("SCHEMA_INCOMPATIBLE")
    bound_limit = _query_integer(
        connection, f"PRAGMA max_page_count={STORE_MAX_PAGES}",
    )
    if bound_limit != STORE_MAX_PAGES:
        _fail("STORAGE_CAPACITY")
    page_count = _query_integer(connection, "PRAGMA page_count")
    freelist_count = _query_integer(connection, "PRAGMA freelist_count")
    if page_count > STORE_MAX_PAGES or freelist_count > page_count:
        _fail("STORAGE_CAPACITY")

    reservation_bytes = (
        CAPACITY_RESERVATION_MULTIPLIER * normalized_bytes
        + CAPACITY_RESERVATION_OVERHEAD_BYTES
    )
    reservation_pages = (
        reservation_bytes + STORE_PAGE_SIZE_BYTES - 1
    ) // STORE_PAGE_SIZE_BYTES
    used_pages = page_count - freelist_count
    if STORE_MAX_PAGES - used_pages < reservation_pages:
        _fail("STORAGE_CAPACITY")

    try:
        filesystem = os.statvfs(connected_path.parent)
        available_bytes = filesystem.f_bavail * filesystem.f_frsize
    except (OSError, TypeError, ValueError):
        _fail("STORAGE_CAPACITY")
    if available_bytes < reservation_bytes:
        _fail("STORAGE_CAPACITY")

    capacity = MappingProxyType({
        "page_size_bytes": page_size,
        "max_pages": bound_limit,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "used_pages": used_pages,
        "reservation_bytes": reservation_bytes,
        "reservation_pages": reservation_pages,
        "filesystem_available_bytes": available_bytes,
    })
    return ConsumerPreflight(
        publication=(batch, receipt),
        capacity=capacity,
        transaction_status="not_started",
        action_status="not_attempted",
    )
