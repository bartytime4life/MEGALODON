"""Bounded transactional consumer for one immutable Suricata publication."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from types import MappingProxyType
from typing import Any, NamedTuple

from ..suricata_store import (
    SuricataStoreError,
    _STORE_MAX_BYTES as STORE_MAX_BYTES,
    _STORE_MAX_PAGES as STORE_MAX_PAGES,
    _STORE_PAGE_SIZE_BYTES as STORE_PAGE_SIZE_BYTES,
    _SuricataWriterHandle,
    _open_suricata_store_writer,
)


MAX_RECORDS = 10_000
MAX_NORMALIZED_BATCH_BYTES = 16_777_216
MAX_TRANSACTION_SECONDS = 30
CAPACITY_RESERVATION_MULTIPLIER = 4
CAPACITY_RESERVATION_OVERHEAD_BYTES = 8_388_608

ERROR_CODES = frozenset({
    "INPUT_CONTRACT", "COUNT_MISMATCH", "BATCH_BYTES", "REPLAY",
    "DATABASE_IDENTITY", "SCHEMA_INCOMPATIBLE", "STORAGE_CAPACITY",
    "TRANSACTION_TIMEOUT", "STORAGE_ERROR", "COMMIT_UNKNOWN",
    "RECONCILIATION_REQUIRED",
})

_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\."
    r"(?:0|[1-9][0-9]{0,2})\Z"
)
_UTC_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:"
    r"[0-9]{2}\.[0-9]{6}Z\Z"
)
_RUN_KEYS = (
    "engine", "adapter_profile", "declared_version", "version_basis",
    "sensor_id", "run_id", "ruleset_id", "ruleset_basis",
)
_ALERT_KEYS = frozenset({
    "schema_version", "source", "source_record_index", "observed_at",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "rule",
    "producer_reported_action", "evidence_kind", "count_unit",
    "action_status",
})
_RULE_KEYS = frozenset({"gid", "signature_id", "rev", "severity"})
_READER_RECEIPT_KEYS = frozenset({
    "schema_version", "reader_policy_version", "status", "run_identity",
    "record_count", "normalized_alert_count", "producer_blocked_count",
    "normalized_batch_bytes", "count_unit", "action_status",
    "durable_write_status", "source_snapshot_status", "replay_status",
})


class ConsumerError(ValueError):
    """A fixed, path-free diagnostic for a refused consumer operation."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "STORAGE_ERROR"
        self.code = code
        self.action_status = "not_attempted"
        super().__init__(f"SURICATA_CONSUMER_V1:{code}")


class ConsumerPreflightError(ConsumerError):
    """A pre-transaction refusal that wrote no consumer rows."""

    def __init__(self, code: str):
        super().__init__(code)
        self.transaction_status = "not_started"


class ConsumerPreflight(NamedTuple):
    """Immutable admission evidence; it conveys no transaction authority."""

    publication: tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]
    capacity: Mapping[str, int]
    transaction_status: str
    action_status: str


class _PublicationFacts(NamedTuple):
    publication: tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]
    identity: Mapping[str, Any]
    record_count: int
    blocked_count: int
    normalized_bytes: int
    record_json: tuple[str, ...]


class _TransactionTimeout(RuntimeError):
    pass


def _fail(code: str) -> None:
    raise ConsumerPreflightError(code) from None


def _fixed_integer(
    value: Any,
    *,
    minimum: int = 0,
    maximum: int,
    code: str = "INPUT_CONTRACT",
) -> int:
    if (
        type(value) is not int
        or not minimum <= value <= maximum
    ):
        _fail(code)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _exact_mapping(value: Any, keys: frozenset[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == keys


def _owned_mapping_snapshot(
    value: Any, keys: frozenset[str] | tuple[str, ...]
) -> dict[str, Any]:
    """Copy one closed mapping without retaining its caller-owned backing."""

    expected = frozenset(keys)
    if not isinstance(value, MappingProxyType):
        _fail("INPUT_CONTRACT")
    try:
        if len(value) != len(expected):
            _fail("INPUT_CONTRACT")
        actual_keys = tuple(value)
        if (
            any(type(key) is not str for key in actual_keys)
            or frozenset(actual_keys) != expected
        ):
            _fail("INPUT_CONTRACT")
        return {key: value[key] for key in sorted(expected)}
    except ConsumerPreflightError:
        raise
    except (KeyError, RuntimeError, TypeError, ValueError, RecursionError):
        _fail("INPUT_CONTRACT")


def _snapshot_publication(
    publication: Any,
) -> tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]:
    """Take a shape-bounded, deeply owned snapshot of a reader publication."""

    if (
        type(publication) is not tuple
        or len(publication) != 2
        or type(publication[0]) is not tuple
        or not isinstance(publication[1], MappingProxyType)
    ):
        _fail("INPUT_CONTRACT")
    batch, receipt = publication
    if not batch or len(batch) > MAX_RECORDS:
        _fail("INPUT_CONTRACT")

    owned_receipt = _owned_mapping_snapshot(receipt, _READER_RECEIPT_KEYS)
    owned_receipt["run_identity"] = _freeze(_owned_mapping_snapshot(
        owned_receipt["run_identity"], _RUN_KEYS,
    ))

    owned_batch: list[Mapping[str, Any]] = []
    for alert in batch:
        owned_alert = _owned_mapping_snapshot(alert, _ALERT_KEYS)
        owned_alert["source"] = _freeze(_owned_mapping_snapshot(
            owned_alert["source"], _RUN_KEYS,
        ))
        owned_alert["rule"] = _freeze(_owned_mapping_snapshot(
            owned_alert["rule"], _RULE_KEYS,
        ))
        owned_batch.append(_freeze(owned_alert))
    return tuple(owned_batch), _freeze(owned_receipt)


def _valid_identifier(value: Any) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_version(value: Any) -> bool:
    return type(value) is str and _VERSION.fullmatch(value) is not None


def _validate_identity(value: Any) -> None:
    if not _exact_mapping(value, frozenset(_RUN_KEYS)):
        _fail("INPUT_CONTRACT")
    if any(type(value[key]) is not str for key in _RUN_KEYS):
        _fail("INPUT_CONTRACT")
    if (
        value["engine"] != "suricata"
        or value["adapter_profile"] != "suricata-eve-alert-v1"
        or not _valid_version(value["declared_version"])
        or value["version_basis"] != "operator_declared"
        or not _valid_identifier(value["sensor_id"])
        or not _valid_identifier(value["run_id"])
        or not _valid_identifier(value["ruleset_id"])
        or value["ruleset_basis"] != "operator_declared"
    ):
        _fail("INPUT_CONTRACT")


def _validate_timestamp(value: Any) -> None:
    if type(value) is not str or _UTC_TIME.fullmatch(value) is None:
        _fail("INPUT_CONTRACT")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _fail("INPUT_CONTRACT")
    if parsed.year < 1970:
        _fail("INPUT_CONTRACT")


def _canonical_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if type(value) is not str or not 2 <= len(value) <= 39:
        _fail("INPUT_CONTRACT")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        _fail("INPUT_CONTRACT")
    if str(parsed) != value:
        _fail("INPUT_CONTRACT")
    return parsed


def _validate_alert(alert: Any, identity: Mapping[str, Any], index: int) -> None:
    if not _exact_mapping(alert, _ALERT_KEYS):
        _fail("INPUT_CONTRACT")
    string_fields = (
        "schema_version", "observed_at", "src_ip", "dst_ip", "protocol",
        "producer_reported_action", "evidence_kind", "count_unit",
        "action_status",
    )
    if any(type(alert[key]) is not str for key in string_fields):
        _fail("INPUT_CONTRACT")
    source_record_index = _fixed_integer(
        alert["source_record_index"], minimum=1, maximum=MAX_RECORDS,
    )
    _validate_identity(alert["source"])
    if (
        alert["schema_version"] != "external-alert-v1"
        or source_record_index != index
        or alert["source"] != identity
        or alert["protocol"] not in {"TCP", "UDP"}
        or alert["producer_reported_action"] not in {"allowed", "blocked"}
        or alert["evidence_kind"] != "signature_match"
        or alert["count_unit"] != "alert"
        or alert["action_status"] != "not_attempted"
    ):
        _fail("INPUT_CONTRACT")
    _validate_timestamp(alert["observed_at"])
    source = _canonical_ip(alert["src_ip"])
    destination = _canonical_ip(alert["dst_ip"])
    if source.version != destination.version:
        _fail("INPUT_CONTRACT")
    _fixed_integer(alert["src_port"], maximum=65_535)
    _fixed_integer(alert["dst_port"], maximum=65_535)
    rule = alert["rule"]
    if not _exact_mapping(rule, _RULE_KEYS):
        _fail("INPUT_CONTRACT")
    for key in ("gid", "signature_id", "rev"):
        _fixed_integer(rule[key], minimum=1, maximum=4_294_967_295)
    _fixed_integer(rule["severity"], minimum=1, maximum=255)


def _validate_reader_receipt(receipt: Any) -> None:
    if not _exact_mapping(receipt, _READER_RECEIPT_KEYS):
        _fail("INPUT_CONTRACT")
    string_fields = (
        "schema_version", "reader_policy_version", "status", "count_unit",
        "action_status", "durable_write_status", "source_snapshot_status",
        "replay_status",
    )
    if any(type(receipt[key]) is not str for key in string_fields):
        _fail("INPUT_CONTRACT")
    if (
        receipt["schema_version"] != "suricata-eve-reader-receipt-v1"
        or receipt["reader_policy_version"] != "suricata-eve-reader-policy-v1"
        or receipt["status"] != "complete"
        or receipt["count_unit"] != "alert"
        or receipt["action_status"] != "not_attempted"
        or receipt["durable_write_status"] != "not_attempted"
        or receipt["source_snapshot_status"] != "metadata_unchanged_not_atomic"
        or receipt["replay_status"] != "fresh"
    ):
        _fail("INPUT_CONTRACT")
    _validate_identity(receipt["run_identity"])


def _validate_publication(publication: Any) -> _PublicationFacts:
    batch, receipt = _snapshot_publication(publication)
    _validate_reader_receipt(receipt)
    identity = receipt["run_identity"]
    blocked_count = 0
    record_json: list[str] = []
    try:
        for index, alert in enumerate(batch, start=1):
            _validate_alert(alert, identity, index)
            blocked_count += alert["producer_reported_action"] == "blocked"
            record_json.append(json.dumps(
                _plain(alert), sort_keys=True, separators=(",", ":"),
            ))
    except ConsumerPreflightError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError):
        _fail("INPUT_CONTRACT")

    record_count = len(batch)
    declared_record_count = _fixed_integer(
        receipt["record_count"], minimum=1, maximum=MAX_RECORDS,
        code="COUNT_MISMATCH",
    )
    declared_alert_count = _fixed_integer(
        receipt["normalized_alert_count"], minimum=1, maximum=MAX_RECORDS,
        code="COUNT_MISMATCH",
    )
    declared_blocked_count = _fixed_integer(
        receipt["producer_blocked_count"], maximum=MAX_RECORDS,
        code="COUNT_MISMATCH",
    )
    if (
        declared_record_count != record_count
        or declared_alert_count != record_count
        or declared_blocked_count != blocked_count
    ):
        _fail("COUNT_MISMATCH")
    normalized_bytes = sum(len(item.encode("utf-8")) for item in record_json)
    declared_bytes = _fixed_integer(
        receipt["normalized_batch_bytes"], minimum=1,
        maximum=MAX_NORMALIZED_BATCH_BYTES, code="BATCH_BYTES",
    )
    if normalized_bytes != declared_bytes or normalized_bytes > MAX_NORMALIZED_BATCH_BYTES:
        _fail("BATCH_BYTES")
    return _PublicationFacts(
        publication=(batch, receipt), identity=identity,
        record_count=record_count, blocked_count=blocked_count,
        normalized_bytes=normalized_bytes, record_json=tuple(record_json),
    )


def _query_integer(connection: sqlite3.Connection, statement: str) -> int:
    try:
        row = connection.execute(statement).fetchone()
    except sqlite3.Error:
        _fail("STORAGE_CAPACITY")
    if row is None or len(row) != 1:
        _fail("STORAGE_CAPACITY")
    value = row[0]
    if type(value) is not int or value < 0:
        _fail("STORAGE_CAPACITY")
    return value


def _connected_regular_path(
    connection: sqlite3.Connection,
    database_path: str | os.PathLike[str],
) -> Path:
    try:
        rows = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [row[2] for row in rows if len(row) == 3 and row[1] == "main"]
        if len(main_paths) != 1 or not main_paths[0]:
            _fail("STORAGE_CAPACITY")
        supplied_raw = Path(database_path)
        connected_raw = Path(main_paths[0])
        supplied_info = supplied_raw.lstat()
        connected_info = connected_raw.lstat()
        if (
            supplied_raw.is_symlink()
            or connected_raw.is_symlink()
            or not stat.S_ISREG(supplied_info.st_mode)
            or not stat.S_ISREG(connected_info.st_mode)
            or supplied_info.st_nlink != 1
            or connected_info.st_nlink != 1
        ):
            _fail("STORAGE_CAPACITY")
        supplied_path = supplied_raw.resolve(strict=True)
        connected_path = connected_raw.resolve(strict=True)
    except ConsumerPreflightError:
        raise
    except (sqlite3.Error, OSError, IndexError, TypeError, ValueError):
        _fail("STORAGE_CAPACITY")
    if supplied_path != connected_path:
        _fail("STORAGE_CAPACITY")
    return connected_path


def preflight_publication(
    connection: sqlite3.Connection,
    publication: Any,
    *,
    database_path: str | os.PathLike[str],
) -> ConsumerPreflight:
    """Validate one publication and fixed capacity before any transaction."""

    facts = _validate_publication(publication)
    if connection.in_transaction:
        _fail("STORAGE_CAPACITY")
    connected_path = _connected_regular_path(connection, database_path)
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
        CAPACITY_RESERVATION_MULTIPLIER * facts.normalized_bytes
        + CAPACITY_RESERVATION_OVERHEAD_BYTES
    )
    reservation_pages = (
        reservation_bytes + STORE_PAGE_SIZE_BYTES - 1
    ) // STORE_PAGE_SIZE_BYTES
    # Owner policy: observe reusable pages but never credit them to headroom.
    used_pages = page_count
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
        "credited_freelist_pages": 0,
        "used_pages": used_pages,
        "reservation_bytes": reservation_bytes,
        "reservation_pages": reservation_pages,
        "filesystem_available_bytes": available_bytes,
    })
    return ConsumerPreflight(
        publication=facts.publication, capacity=capacity,
        transaction_status="not_started", action_status="not_attempted",
    )


def _run_key(identity: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(identity[key] for key in _RUN_KEYS)


def _validate_attempt_id(value: Any) -> str:
    if not _valid_identifier(value):
        _fail("INPUT_CONTRACT")
    return value


def _receipt(
    facts: _PublicationFacts,
    attempt_id: str,
    outcome: str,
    failure_code: str | None = None,
) -> Mapping[str, Any]:
    states = {
        "committed": (
            "committed", "committed", "recorded", "committed",
            "not_required", None,
        ),
        "rejected": (
            "rejected", "not_attempted", "duplicate", "not_started",
            "not_required", "REPLAY",
        ),
        "rejected_rolled_back": (
            "rejected", "rolled_back", "duplicate", "rolled_back",
            "not_required", "REPLAY",
        ),
        "preflight_failed": (
            "failed", "not_attempted", "not_recorded", "not_started",
            "not_required", failure_code,
        ),
        "rolled_back": (
            "failed", "rolled_back", "not_recorded", "rolled_back",
            "not_required", failure_code,
        ),
        "unknown": (
            "reconciliation_required", "unknown", "unknown", "unknown",
            "required", "COMMIT_UNKNOWN",
        ),
    }
    status, durable, replay, transaction, reconciliation, failure = states[outcome]
    value = {
        "schema_version": "suricata-eve-consumer-receipt-v1",
        "consumer_policy_version": "suricata-eve-consumer-policy-v1",
        "reader_receipt_version": "suricata-eve-reader-receipt-v1",
        "consumer_attempt_id": attempt_id,
        "status": status,
        "run_identity": _plain(facts.identity),
        "record_count": facts.record_count,
        "normalized_alert_count": facts.record_count,
        "producer_blocked_count": facts.blocked_count,
        "normalized_batch_bytes": facts.normalized_bytes,
        "count_unit": "alert",
        "action_status": "not_attempted",
        "durable_write_status": durable,
        "replay_status": replay,
        "transaction_status": transaction,
        "reconciliation_status": reconciliation,
        "failure_code": failure,
    }
    return _freeze(value)


def _find_run(
    connection: sqlite3.Connection, identity: Mapping[str, Any]
) -> tuple[int, str] | None:
    row = connection.execute(
        """SELECT id, consumer_attempt_id FROM consumer_runs
           WHERE engine=? AND adapter_profile=? AND declared_version=?
             AND version_basis=? AND sensor_id=? AND run_id=?
             AND ruleset_id=? AND ruleset_basis=?""",
        _run_key(identity),
    ).fetchone()
    if row is None:
        return None
    return int(row[0]), str(row[1])


def _find_attempt(
    connection: sqlite3.Connection, attempt_id: str
) -> tuple[int] | None:
    row = connection.execute(
        "SELECT id FROM consumer_runs WHERE consumer_attempt_id=?", (attempt_id,)
    ).fetchone()
    if row is None:
        return None
    return (int(row[0]),)


def _remaining_milliseconds(started: float) -> int:
    try:
        remaining = MAX_TRANSACTION_SECONDS - (time.monotonic() - started)
        if not math.isfinite(remaining) or remaining <= 0:
            raise _TransactionTimeout
        return max(1, min(30_000, int(remaining * 1_000)))
    except _TransactionTimeout:
        raise
    except Exception as exc:
        raise _TransactionTimeout from exc


def _deadline_progress(started: float) -> int:
    try:
        _remaining_milliseconds(started)
    except _TransactionTimeout:
        return 1
    return 0


def _deadline_failure_code(started: float, default: str) -> str:
    try:
        _remaining_milliseconds(started)
    except _TransactionTimeout:
        return "TRANSACTION_TIMEOUT"
    return default


def _rollback(connection: sqlite3.Connection) -> bool:
    try:
        connection.rollback()
        return not connection.in_transaction
    except sqlite3.Error:
        return False


def _commit(connection: sqlite3.Connection) -> None:
    connection.commit()


def _readback_matches(
    connection: sqlite3.Connection,
    facts: _PublicationFacts,
    attempt_id: str,
    receipt_json: str,
) -> bool:
    run = connection.execute(
        """SELECT id, engine, adapter_profile, declared_version, version_basis,
                  sensor_id, run_id, ruleset_id, ruleset_basis,
                  consumer_attempt_id
           FROM consumer_runs
           WHERE engine=? AND adapter_profile=? AND declared_version=?
             AND version_basis=? AND sensor_id=? AND run_id=?
             AND ruleset_id=? AND ruleset_basis=?""",
        _run_key(facts.identity),
    ).fetchone()
    if run is None:
        return False
    expected_run = (int(run[0]), *_run_key(facts.identity), attempt_id)
    if tuple(run) != expected_run:
        return False
    stored_receipt = connection.execute(
        """SELECT consumer_attempt_id, receipt_json FROM consumer_receipts
           WHERE run_row_id=?""",
        (int(run[0]),),
    ).fetchone()
    if stored_receipt != (attempt_id, receipt_json):
        return False
    alerts = connection.execute(
        """SELECT source_record_index, record_json FROM consumer_alerts
           WHERE run_row_id=? ORDER BY source_record_index""",
        (int(run[0]),),
    ).fetchall()
    expected_alerts = tuple(enumerate(facts.record_json, start=1))
    return tuple((int(row[0]), str(row[1])) for row in alerts) == expected_alerts


def _store_failure_code(error: SuricataStoreError) -> str:
    diagnostic = str(error)
    if "INCOMPATIBLE" in diagnostic:
        return "SCHEMA_INCOMPATIBLE"
    if "CAPACITY" in diagnostic:
        return "STORAGE_CAPACITY"
    if any(token in diagnostic for token in (
        "DATABASE", "DIRECTORY", "SIDECAR", "PATH", "CREATION", "RECOVERY",
    )):
        return "DATABASE_IDENTITY"
    return "STORAGE_ERROR"


def _consume_open_store(
    writer: _SuricataWriterHandle,
    facts: _PublicationFacts,
    attempt_id: str,
    started: float,
) -> Mapping[str, Any]:
    connection = writer.connection
    try:
        preflight_publication(
            connection, facts.publication, database_path=writer.path,
        )
    except ConsumerPreflightError as error:
        return _receipt(
            facts,
            attempt_id,
            "preflight_failed",
            _deadline_failure_code(started, error.code),
        )

    try:
        _remaining_milliseconds(started)
        writer.verify_identity()
        if _find_run(connection, facts.identity) is not None:
            return _receipt(facts, attempt_id, "rejected")
        if _find_attempt(connection, attempt_id) is not None:
            return _receipt(
                facts, attempt_id, "preflight_failed", "DATABASE_IDENTITY"
            )
        busy_ms = _remaining_milliseconds(started)
        connection.execute(f"PRAGMA busy_timeout={busy_ms}")
        connection.execute("BEGIN IMMEDIATE")
    except _TransactionTimeout:
        return _receipt(
            facts, attempt_id, "preflight_failed", "TRANSACTION_TIMEOUT"
        )
    except SuricataStoreError:
        return _receipt(
            facts, attempt_id, "preflight_failed", "DATABASE_IDENTITY"
        )
    except sqlite3.Error:
        return _receipt(
            facts,
            attempt_id,
            "preflight_failed",
            _deadline_failure_code(started, "STORAGE_ERROR"),
        )

    try:
        _remaining_milliseconds(started)
        writer.verify_identity()
        if _find_run(connection, facts.identity) is not None:
            if not _rollback(connection):
                return _receipt(facts, attempt_id, "unknown")
            return _receipt(facts, attempt_id, "rejected_rolled_back")
        if _find_attempt(connection, attempt_id) is not None:
            if not _rollback(connection):
                return _receipt(facts, attempt_id, "unknown")
            return _receipt(
                facts, attempt_id, "rolled_back", "DATABASE_IDENTITY"
            )

        committed = _receipt(facts, attempt_id, "committed")
        committed_json = json.dumps(
            _plain(committed), sort_keys=True, separators=(",", ":"),
        )
        cursor = connection.execute(
            """INSERT INTO consumer_runs (
                   engine, adapter_profile, declared_version, version_basis,
                   sensor_id, run_id, ruleset_id, ruleset_basis,
                   consumer_attempt_id
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (*_run_key(facts.identity), attempt_id),
        )
        run_row_id = cursor.lastrowid
        if (
            isinstance(run_row_id, bool)
            or not isinstance(run_row_id, int)
            or run_row_id < 1
        ):
            raise sqlite3.DatabaseError
        for index, record_json in enumerate(facts.record_json, start=1):
            if index == 1 or index % 64 == 0:
                _remaining_milliseconds(started)
            connection.execute(
                """INSERT INTO consumer_alerts (
                       run_row_id, source_record_index, record_json
                   ) VALUES (?, ?, ?)""",
                (run_row_id, index, record_json),
            )
        connection.execute(
            """INSERT INTO consumer_receipts (
                   run_row_id, consumer_attempt_id, receipt_json
               ) VALUES (?, ?, ?)""",
            (run_row_id, attempt_id, committed_json),
        )
        _remaining_milliseconds(started)
        writer.verify_identity()
    except _TransactionTimeout:
        if not _rollback(connection):
            return _receipt(facts, attempt_id, "unknown")
        return _receipt(
            facts, attempt_id, "rolled_back", "TRANSACTION_TIMEOUT"
        )
    except (SuricataStoreError, sqlite3.IntegrityError):
        if not _rollback(connection):
            return _receipt(facts, attempt_id, "unknown")
        return _receipt(facts, attempt_id, "rolled_back", "DATABASE_IDENTITY")
    except (sqlite3.Error, OSError, TypeError, ValueError, OverflowError):
        if not _rollback(connection):
            return _receipt(facts, attempt_id, "unknown")
        return _receipt(
            facts,
            attempt_id,
            "rolled_back",
            _deadline_failure_code(started, "STORAGE_ERROR"),
        )

    try:
        _commit(connection)
    except (sqlite3.Error, OSError):
        return _receipt(facts, attempt_id, "unknown")
    try:
        _remaining_milliseconds(started)
        writer.verify_identity()
        if not _readback_matches(
            connection, facts, attempt_id, committed_json,
        ):
            return _receipt(facts, attempt_id, "unknown")
        _remaining_milliseconds(started)
    except (
        _TransactionTimeout, SuricataStoreError, sqlite3.Error, OSError,
        TypeError, ValueError, OverflowError,
    ):
        return _receipt(facts, attempt_id, "unknown")
    return committed


def consume_publication(
    database_path: str | os.PathLike[str],
    publication: Any,
    *,
    consumer_attempt_id: str,
) -> Mapping[str, Any]:
    """Atomically persist one exact reader publication in an existing store.

    This performs one local durable write. It does not create or migrate a
    store, reopen source data, run a sensor, access a network, launch a process,
    invoke a model, update a dashboard, purge evidence, or execute an action. A
    ``reconciliation_required`` result must not be blindly retried.
    """

    facts = _validate_publication(publication)
    attempt_id = _validate_attempt_id(consumer_attempt_id)
    try:
        started = time.monotonic()
    except Exception:
        return _receipt(
            facts, attempt_id, "preflight_failed", "TRANSACTION_TIMEOUT"
        )
    try:
        with _open_suricata_store_writer(
            database_path,
            progress_handler=lambda: _deadline_progress(started),
        ) as writer:
            return _consume_open_store(writer, facts, attempt_id, started)
    except SuricataStoreError as error:
        return _receipt(
            facts,
            attempt_id,
            "preflight_failed",
            _deadline_failure_code(started, _store_failure_code(error)),
        )


__all__ = [
    "ConsumerError", "ConsumerPreflight", "ConsumerPreflightError",
    "consume_publication", "preflight_publication",
]
