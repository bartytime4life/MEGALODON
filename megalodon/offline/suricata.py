"""Bounded, file-only Suricata envelope reader with no producer or side effects."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime, timezone
import errno
import ipaddress
import json
import os
import re
import stat
import time
from types import MappingProxyType
from typing import AbstractSet, Any, Iterator, TypeAlias

from ..capture import CaptureError
from .common import OfflineError, _parts, require_unprivileged_linux


MAX_TOTAL_BYTES = 67_108_864
MAX_RECORDS = 10_000
MAX_RECORD_BYTES = 65_536
MAX_DEPTH = 4
MAX_INTEGER_DIGITS = 10
MAX_OUTPUT_BYTES = 16_777_216
MAX_ELAPSED_SECONDS = 30

ERROR_CODES = frozenset({
    "SOURCE_PATH", "SOURCE_SYMLINK", "SOURCE_TYPE", "SOURCE_OWNER",
    "SOURCE_MODE", "SOURCE_CHANGED", "TOTAL_BYTES", "RECORD_LIMIT",
    "RECORD_BYTES", "EMPTY_INPUT", "EMPTY_RECORD", "FRAMING", "UTF8",
    "DUPLICATE_KEY", "DEPTH", "JSON_NUMBER", "JSON", "SCHEMA",
    "SEMANTIC", "RUN_IDENTITY", "RECORD_SEQUENCE", "REPLAY",
    "COUNT_MISMATCH", "OUTPUT_LIMIT", "TIME_LIMIT",
})

RunKey: TypeAlias = tuple[str, str, str, str, str, str, str, str]
Publication: TypeAlias = tuple[
    tuple[Mapping[str, Any], ...],
    Mapping[str, Any],
]

_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_VERSION = re.compile(
    r"(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})\."
    r"(?:0|[1-9][0-9]{0,2})\Z"
)
_EVE_TIME = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:?[0-9]{2})\Z"
)
_IP_LITERAL = re.compile(r"[0-9A-Fa-f:.]+\Z")
_SOURCE_KEYS = frozenset({
    "engine", "adapter_profile", "declared_version", "version_basis",
    "sensor_id", "run_id", "ruleset_id", "ruleset_basis",
})
_EVENT_KEYS = frozenset({
    "timestamp", "event_type", "src_ip", "src_port", "dest_ip",
    "dest_port", "proto", "alert",
})
_ALERT_REQUIRED = frozenset({"gid", "signature_id", "rev", "severity", "action"})
_ALERT_OPTIONAL = frozenset({"signature", "category"})
_RUN_KEY_FIELDS = (
    "engine", "adapter_profile", "declared_version", "version_basis",
    "sensor_id", "run_id", "ruleset_id", "ruleset_basis",
)


class ReaderError(ValueError):
    """A fixed diagnostic that never includes source data or filesystem details."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "SOURCE_CHANGED"
        super().__init__(f"SURICATA_READER_V1:{code}")


def _fail(code: str) -> None:
    raise ReaderError(code) from None


def _deadline(started: float, clock: Any) -> None:
    try:
        expired = clock() - started > MAX_ELAPSED_SECONDS
    except Exception:
        _fail("TIME_LIMIT")
    if expired:
        _fail("TIME_LIMIT")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def _close_all(descriptors: list[int], primary: BaseException | None) -> None:
    failed = False
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            failed = True
    if failed and primary is None:
        _fail("SOURCE_CHANGED")


def _open_source(path: str) -> tuple[int, list[int], list[tuple[int, ...]]]:
    try:
        parts = _parts(path, absolute=True)
    except OfflineError:
        _fail("SOURCE_PATH")
    if not parts:
        _fail("SOURCE_PATH")

    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        descriptors.append(directory)
        identities.append(_identity(os.fstat(directory)))
        for part in parts[:-1]:
            try:
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    _fail("SOURCE_SYMLINK")
                if exc.errno == errno.ENOTDIR:
                    try:
                        info = os.stat(part, dir_fd=directory, follow_symlinks=False)
                    except OSError:
                        _fail("SOURCE_PATH")
                    _fail("SOURCE_SYMLINK" if stat.S_ISLNK(info.st_mode) else "SOURCE_TYPE")
                _fail("SOURCE_PATH")
            directory = child
            descriptors.append(directory)
            identities.append(_identity(os.fstat(directory)))

        try:
            source = os.open(
                parts[-1],
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=directory,
            )
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                _fail("SOURCE_SYMLINK")
            try:
                failed_info = os.stat(
                    parts[-1], dir_fd=directory, follow_symlinks=False
                )
            except OSError:
                _fail("SOURCE_PATH")
            if stat.S_ISLNK(failed_info.st_mode):
                _fail("SOURCE_SYMLINK")
            if not stat.S_ISREG(failed_info.st_mode):
                _fail("SOURCE_TYPE")
            _fail("SOURCE_PATH")
        descriptors.append(source)
        info = os.fstat(source)
        identities.append(_identity(info))
        if not stat.S_ISREG(info.st_mode):
            _fail("SOURCE_TYPE")
        if info.st_uid != os.geteuid():
            _fail("SOURCE_OWNER")
        if stat.S_IMODE(info.st_mode) not in {0o400, 0o600}:
            _fail("SOURCE_MODE")
        if info.st_size > MAX_TOTAL_BYTES:
            _fail("TOTAL_BYTES")
        return source, descriptors, identities
    except BaseException as exc:
        _close_all(descriptors, exc)
        raise


def _verify_identities(descriptors: list[int], expected: list[tuple[int, ...]]) -> None:
    try:
        actual = [_identity(os.fstat(descriptor)) for descriptor in descriptors]
    except OSError:
        _fail("SOURCE_CHANGED")
    if actual != expected:
        _fail("SOURCE_CHANGED")


def _decode(raw: bytes) -> Any:
    if len(raw) > MAX_RECORD_BYTES:
        _fail("RECORD_BYTES")
    raw = raw[:-2] if raw.endswith(b"\r\n") else raw[:-1] if raw.endswith(b"\n") else raw
    if not raw:
        _fail("EMPTY_RECORD")
    if b"\n" in raw or b"\r" in raw:
        _fail("FRAMING")
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("UTF8")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _fail("UTF8")

    depth = 0
    quoted = False
    escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                _fail("DEPTH")
        elif char in "]}":
            depth -= 1

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("DUPLICATE_KEY")
            result[key] = value
        return result

    def integer(token: str) -> int:
        if len(token.lstrip("-")) > MAX_INTEGER_DIGITS:
            _fail("JSON_NUMBER")
        return int(token)

    def reject_number(token: str) -> None:
        _fail("JSON_NUMBER")

    try:
        return json.loads(
            text,
            object_pairs_hook=pairs,
            parse_int=integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except ReaderError:
        raise
    except (json.JSONDecodeError, RecursionError):
        _fail("JSON")


def _exact_object(value: Any, required: frozenset[str], optional: frozenset[str] = frozenset()) -> bool:
    return isinstance(value, dict) and required <= value.keys() and set(value) <= required | optional


def _bounded_int(value: Any, minimum: int, maximum: int) -> bool:
    return type(value) is int and minimum <= value <= maximum


def _printable_label(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 160
        and all(0x20 <= ord(char) <= 0x7E for char in value)
    )


def _validate_input(value: Any) -> None:
    if not _exact_object(
        value,
        frozenset({"schema_version", "source", "source_record_index", "event"}),
    ):
        _fail("SCHEMA")
    if value["schema_version"] != "suricata-eve-alert-input-v1":
        _fail("SCHEMA")
    if not _bounded_int(value["source_record_index"], 1, MAX_RECORDS):
        _fail("SCHEMA")

    source = value["source"]
    if not _exact_object(source, _SOURCE_KEYS):
        _fail("SCHEMA")
    if (
        source["engine"] != "suricata"
        or source["adapter_profile"] != "suricata-eve-alert-v1"
        or source["version_basis"] != "operator_declared"
        or source["ruleset_basis"] != "operator_declared"
        or not isinstance(source["declared_version"], str)
        or not _VERSION.fullmatch(source["declared_version"])
        or any(
            not isinstance(source[key], str) or not _IDENTIFIER.fullmatch(source[key])
            for key in ("sensor_id", "run_id", "ruleset_id")
        )
    ):
        _fail("SCHEMA")

    event = value["event"]
    if not _exact_object(event, _EVENT_KEYS):
        _fail("SCHEMA")
    if (
        event["event_type"] != "alert"
        or not isinstance(event["proto"], str)
        or event["proto"] not in {"TCP", "UDP"}
        or not _bounded_int(event["src_port"], 0, 65535)
        or not _bounded_int(event["dest_port"], 0, 65535)
        or not isinstance(event["timestamp"], str)
        or not 20 <= len(event["timestamp"]) <= 32
        or not _EVE_TIME.fullmatch(event["timestamp"])
    ):
        _fail("SCHEMA")
    for key in ("src_ip", "dest_ip"):
        address = event[key]
        if (
            not isinstance(address, str)
            or not 2 <= len(address) <= 45
            or not _IP_LITERAL.fullmatch(address)
        ):
            _fail("SCHEMA")

    alert = event["alert"]
    if not _exact_object(alert, _ALERT_REQUIRED, _ALERT_OPTIONAL):
        _fail("SCHEMA")
    if (
        any(not _bounded_int(alert[key], 1, 4_294_967_295) for key in ("gid", "signature_id", "rev"))
        or not _bounded_int(alert["severity"], 1, 255)
        or not isinstance(alert["action"], str)
        or alert["action"] not in {"allowed", "blocked"}
        or any(not _printable_label(alert[key]) for key in _ALERT_OPTIONAL if key in alert)
    ):
        _fail("SCHEMA")

    try:
        source_address = ipaddress.ip_address(event["src_ip"])
        destination_address = ipaddress.ip_address(event["dest_ip"])
    except ValueError:
        _fail("SEMANTIC")
    if source_address.version != destination_address.version:
        _fail("SEMANTIC")
    _utc(event["timestamp"])


def _utc(value: str) -> str:
    try:
        if value.endswith(("-0000", "-00:00")):
            raise ValueError
        match = re.search(r"([+-])([0-9]{2}):?([0-9]{2})$", value)
        if match:
            hours, minutes = int(match[2]), int(match[3])
            if minutes > 59 or hours > 14 or (hours == 14 and minutes):
                raise ValueError
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            raise ValueError
        stamp = stamp.astimezone(timezone.utc)
        if stamp.year < 1970:
            raise ValueError
        return stamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        _fail("SEMANTIC")


def _normalize(value: dict[str, Any]) -> dict[str, Any]:
    event = value["event"]
    return {
        "schema_version": "external-alert-v1",
        "source": deepcopy(value["source"]),
        "source_record_index": value["source_record_index"],
        "observed_at": _utc(event["timestamp"]),
        "src_ip": str(ipaddress.ip_address(event["src_ip"])),
        "src_port": event["src_port"],
        "dst_ip": str(ipaddress.ip_address(event["dest_ip"])),
        "dst_port": event["dest_port"],
        "protocol": event["proto"],
        "rule": {key: event["alert"][key] for key in ("gid", "signature_id", "rev", "severity")},
        "producer_reported_action": event["alert"]["action"],
        "evidence_kind": "signature_match",
        "count_unit": "alert",
        "action_status": "not_attempted",
    }


def _run_key(identity: Mapping[str, str]) -> RunKey:
    return tuple(identity[key] for key in _RUN_KEY_FIELDS)  # type: ignore[return-value]


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _records(source: int, started: float, clock: Any) -> Iterator[bytes]:
    current = bytearray()
    total = 0
    count = 0
    quoted = False
    escaped = False
    while True:
        _deadline(started, clock)
        try:
            chunk = os.read(source, 8192)
        except OSError:
            _fail("SOURCE_CHANGED")
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_TOTAL_BYTES:
            _fail("TOTAL_BYTES")
        for byte in chunk:
            if byte == 10:
                if quoted:
                    _fail("FRAMING")
                current.append(byte)
                if len(current) > MAX_RECORD_BYTES:
                    _fail("RECORD_BYTES")
                count += 1
                if count > MAX_RECORDS:
                    _fail("RECORD_LIMIT")
                yield bytes(current)
                current.clear()
                escaped = False
                continue
            current.append(byte)
            if len(current) > MAX_RECORD_BYTES:
                _fail("RECORD_BYTES")
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
    if current:
        count += 1
        if count > MAX_RECORDS:
            _fail("RECORD_LIMIT")
        yield bytes(current)
    if not count:
        _fail("EMPTY_INPUT")


def _read_publication(
    path: str,
    replay_view: frozenset[RunKey],
    started: float,
    clock: Any,
) -> Publication:
    source: int | None = None
    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    primary: BaseException | None = None
    try:
        source, descriptors, identities = _open_source(path)
        _deadline(started, clock)
        _verify_identities(descriptors, identities)

        normalized: list[dict[str, Any]] = []
        identity: dict[str, str] | None = None
        blocked = 0
        output_bytes = 0
        for expected_index, raw in enumerate(_records(source, started, clock), start=1):
            _deadline(started, clock)
            value = _decode(raw)
            _validate_input(value)
            if value["source_record_index"] != expected_index:
                _fail("RECORD_SEQUENCE")
            if identity is None:
                identity = deepcopy(value["source"])
            elif value["source"] != identity:
                _fail("RUN_IDENTITY")
            item = _normalize(value)
            if item["producer_reported_action"] == "blocked":
                blocked += 1
            output_bytes += len(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            if output_bytes > MAX_OUTPUT_BYTES:
                _fail("OUTPUT_LIMIT")
            normalized.append(item)

        if identity is None:
            _fail("EMPTY_INPUT")
        try:
            replayed = _run_key(identity) in replay_view
        except Exception:
            _fail("REPLAY")
        if replayed:
            _fail("REPLAY")
        if blocked > len(normalized):
            _fail("COUNT_MISMATCH")

        receipt = {
            "schema_version": "suricata-eve-reader-receipt-v1",
            "reader_policy_version": "suricata-eve-reader-policy-v1",
            "status": "complete",
            "run_identity": identity,
            "record_count": len(normalized),
            "normalized_alert_count": len(normalized),
            "producer_blocked_count": blocked,
            "normalized_batch_bytes": output_bytes,
            "count_unit": "alert",
            "action_status": "not_attempted",
            "durable_write_status": "not_attempted",
            "source_snapshot_status": "metadata_unchanged_not_atomic",
            "replay_status": "fresh",
        }
        _deadline(started, clock)
        _verify_identities(descriptors, identities)
        _deadline(started, clock)
        publication: Publication = (
            tuple(_freeze(item) for item in normalized),
            _freeze(receipt),
        )
        return publication
    except CaptureError as exc:
        primary = exc
        raise
    except ReaderError as exc:
        primary = exc
        raise
    except OSError:
        primary = ReaderError("SOURCE_CHANGED")
        raise primary from None
    except Exception:
        primary = ReaderError("SOURCE_CHANGED")
        raise primary from None
    finally:
        if descriptors:
            _close_all(descriptors, primary)


def read_completed_file(
    path: str,
    *,
    completed_run_keys: AbstractSet[RunKey] = frozenset(),
) -> Publication:
    """Validate one private completed file and return one immutable publication.

    Call from the main thread of a single-threaded Linux process with SIGALRM
    unblocked and not pending, and with no active ITIMER_REAL timer. The function
    performs no persistence, network access, process launch, sensor control,
    logging, callback, dashboard update, or response action.
    """
    clock = time.monotonic
    try:
        started = clock()
    except Exception:
        _fail("TIME_LIMIT")
    _deadline(started, clock)
    try:
        require_unprivileged_linux()
    except OfflineError:
        _fail("SOURCE_PATH")
    if type(completed_run_keys) not in {set, frozenset}:
        _fail("REPLAY")
    try:
        replay_view = frozenset(completed_run_keys)
    except Exception:
        _fail("REPLAY")
    if any(
        type(key) is not tuple
        or len(key) != len(_RUN_KEY_FIELDS)
        or any(type(part) is not str for part in key)
        for key in replay_view
    ):
        _fail("REPLAY")
    try:
        remaining = MAX_ELAPSED_SECONDS - (clock() - started)
    except Exception:
        _fail("TIME_LIMIT")
    if remaining <= 0:
        _fail("TIME_LIMIT")

    try:
        from ..cli import _scoped_run_deadline

        with _scoped_run_deadline(remaining):
            return _read_publication(path, replay_view, started, clock)
    except ReaderError:
        raise
    except (CaptureError, OSError, ValueError):
        _fail("TIME_LIMIT")
    except Exception:
        _fail("TIME_LIMIT")
