"""Privacy-minimal reader for one completed Suricata 8.0.7 EVE alert file.

The existing :mod:`megalodon.offline.suricata` reader accepts MEGALODON's
closed envelope.  This module is the deliberately smaller producer boundary in
front of it: one operator-selected, checksum-bound, alert-only EVE JSONL file is
projected into the exact immutable publication already accepted by the durable
consumer.

It does not start or configure Suricata, watch a directory, retain raw records,
write a database, update a dashboard, contact a network service, or act on a
producer-reported ``blocked`` value.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json
import os
import re
import time
from typing import AbstractSet, Any, Iterator

from ..capture import CaptureError
from . import suricata
from .common import OfflineError, require_unprivileged_linux


PINNED_SURICATA_VERSION = "8.0.7"
PRODUCER_PROFILE = "suricata-8.0.7-alert-json-v1"
MAX_INTEGER_DIGITS = 20

ERROR_CODES = frozenset(set(suricata.ERROR_CODES) | {
    "SOURCE_LINK", "PROFILE", "DIGEST", "MIXED_EVENT_TYPE", "FORBIDDEN_FIELD",
})

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_RAW_REQUIRED = frozenset({
    "timestamp", "event_type", "src_ip", "src_port", "dest_ip", "dest_port",
    "proto", "alert",
})
_RAW_OPTIONAL = frozenset({
    "flow_id", "pcap_cnt", "tx_id", "app_proto", "direction", "pkt_src",
    "community_id",
})
_FORBIDDEN_TOP_LEVEL = frozenset({
    "payload", "payload_printable", "packet", "packet_info", "capture_file",
    "metadata", "ether", "flow", "http", "dns", "tls", "files", "fileinfo",
    "verdict",
})
_ALERT_REQUIRED = frozenset({"action", "gid", "signature_id", "rev", "severity"})
_ALERT_OPTIONAL = frozenset({"signature", "category"})
_FORBIDDEN_ALERT = frozenset({"metadata", "source", "target", "engine", "verdict"})
_OPTIONAL_INTEGER_MAXIMUMS = {
    "flow_id": 18_446_744_073_709_551_615,
    "pcap_cnt": 18_446_744_073_709_551_615,
    "tx_id": 4_294_967_295,
}


class RawEveError(ValueError):
    """A fixed, path-free diagnostic for the raw-EVE producer boundary."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "SOURCE_CHANGED"
        self.code = code
        super().__init__(f"SURICATA_RAW_EVE_V1:{code}")


def _fail(code: str) -> None:
    raise RawEveError(code) from None


def _deadline(started: float, clock: Any) -> None:
    try:
        expired = clock() - started > suricata.MAX_ELAPSED_SECONDS
    except Exception:
        _fail("TIME_LIMIT")
    if expired:
        _fail("TIME_LIMIT")


def _reader_code(error: suricata.ReaderError) -> str:
    code = str(error).rsplit(":", 1)[-1]
    return code if code in ERROR_CODES else "SOURCE_CHANGED"


def _decode(raw: bytes) -> Any:
    if len(raw) > suricata.MAX_RECORD_BYTES:
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
            if depth > suricata.MAX_DEPTH:
                _fail("DEPTH")
        elif char in "]}":
            depth -= 1
    if quoted or depth != 0:
        _fail("JSON")

    def unique(items: list[tuple[str, Any]]) -> dict[str, Any]:
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

    def reject_number(_token: str) -> None:
        _fail("JSON_NUMBER")

    try:
        return json.loads(
            text,
            object_pairs_hook=unique,
            parse_int=integer,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except RawEveError:
        raise
    except (json.JSONDecodeError, RecursionError):
        _fail("JSON")


def _records(
    source: int,
    started: float,
    clock: Any,
    digest: Any,
) -> Iterator[bytes]:
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
        digest.update(chunk)
        total += len(chunk)
        if total > suricata.MAX_TOTAL_BYTES:
            _fail("TOTAL_BYTES")
        for byte in chunk:
            if byte == 10:
                if quoted:
                    _fail("FRAMING")
                current.append(byte)
                if len(current) > suricata.MAX_RECORD_BYTES:
                    _fail("RECORD_BYTES")
                count += 1
                if count > suricata.MAX_RECORDS:
                    _fail("RECORD_LIMIT")
                yield bytes(current)
                current.clear()
                escaped = False
                continue
            current.append(byte)
            if len(current) > suricata.MAX_RECORD_BYTES:
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
    if quoted:
        _fail("FRAMING")
    if current:
        count += 1
        if count > suricata.MAX_RECORDS:
            _fail("RECORD_LIMIT")
        yield bytes(current)
    if not count:
        _fail("EMPTY_INPUT")


def _printable(value: Any, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and all(0x20 <= ord(char) <= 0x7E for char in value)
    )


def _validate_ignored_fields(value: Mapping[str, Any]) -> None:
    for key, maximum in _OPTIONAL_INTEGER_MAXIMUMS.items():
        if key in value and (type(value[key]) is not int or not 0 <= value[key] <= maximum):
            _fail("SCHEMA")
    for key in ("app_proto", "pkt_src"):
        if key in value and not _printable(value[key], 64):
            _fail("SCHEMA")
    if "community_id" in value and not _printable(value["community_id"], 128):
        _fail("SCHEMA")
    if "direction" in value and value["direction"] not in {"to_server", "to_client"}:
        _fail("SCHEMA")


def _normalize_raw(
    value: Any,
    *,
    source_identity: dict[str, str],
    source_record_index: int,
) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("SCHEMA")
    if value.get("event_type") != "alert":
        _fail("MIXED_EVENT_TYPE")
    if set(value) & _FORBIDDEN_TOP_LEVEL:
        _fail("FORBIDDEN_FIELD")
    if not _RAW_REQUIRED <= value.keys() or set(value) - (_RAW_REQUIRED | _RAW_OPTIONAL):
        _fail("SCHEMA")
    _validate_ignored_fields(value)

    alert = value.get("alert")
    if type(alert) is not dict:
        _fail("SCHEMA")
    if set(alert) & _FORBIDDEN_ALERT:
        _fail("FORBIDDEN_FIELD")
    if not _ALERT_REQUIRED <= alert.keys() or set(alert) - (_ALERT_REQUIRED | _ALERT_OPTIONAL):
        _fail("SCHEMA")

    envelope = {
        "schema_version": "suricata-eve-alert-input-v1",
        "source": deepcopy(source_identity),
        "source_record_index": source_record_index,
        "event": {key: deepcopy(value[key]) for key in _RAW_REQUIRED},
    }
    try:
        suricata._validate_input(envelope)
        return suricata._normalize(envelope)
    except suricata.ReaderError as error:
        _fail(_reader_code(error))


def _validate_request(
    expected_digest: Any,
    declared_version: Any,
    sensor_id: Any,
    run_id: Any,
    ruleset_id: Any,
    completed_run_keys: Any,
) -> tuple[dict[str, str], frozenset[suricata.RunKey]]:
    if type(expected_digest) is not str or not _DIGEST.fullmatch(expected_digest):
        _fail("DIGEST")
    if declared_version != PINNED_SURICATA_VERSION:
        _fail("PROFILE")
    if any(type(value) is not str or not _IDENTIFIER.fullmatch(value) for value in (sensor_id, run_id, ruleset_id)):
        _fail("SCHEMA")
    if type(completed_run_keys) not in {set, frozenset}:
        _fail("REPLAY")
    try:
        replay_view = frozenset(completed_run_keys)
    except Exception:
        _fail("REPLAY")
    if any(
        type(key) is not tuple
        or len(key) != len(suricata._RUN_KEY_FIELDS)
        or any(type(part) is not str for part in key)
        for key in replay_view
    ):
        _fail("REPLAY")
    identity = {
        "engine": "suricata",
        "adapter_profile": "suricata-eve-alert-v1",
        "declared_version": declared_version,
        "version_basis": "operator_declared",
        "sensor_id": sensor_id,
        "run_id": run_id,
        "ruleset_id": ruleset_id,
        "ruleset_basis": "operator_declared",
    }
    if suricata._run_key(identity) in replay_view:
        _fail("REPLAY")
    return identity, replay_view


def _close(descriptors: list[int], primary: BaseException | None) -> None:
    failed = False
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except OSError:
            failed = True
    if failed and primary is None:
        _fail("SOURCE_CHANGED")


def _read(
    path: str,
    *,
    expected_digest: str,
    source_identity: dict[str, str],
    started: float,
    clock: Any,
) -> suricata.Publication:
    descriptors: list[int] = []
    identities: list[tuple[int, ...]] = []
    primary: BaseException | None = None
    try:
        try:
            source, descriptors, identities = suricata._open_source(path)
        except suricata.ReaderError as error:
            _fail(_reader_code(error))
        try:
            if os.fstat(source).st_nlink != 1:
                _fail("SOURCE_LINK")
        except OSError:
            _fail("SOURCE_CHANGED")
        _deadline(started, clock)
        try:
            suricata._verify_identities(descriptors, identities)
        except suricata.ReaderError as error:
            _fail(_reader_code(error))

        digest = hashlib.sha256()
        normalized: list[dict[str, Any]] = []
        blocked = 0
        output_bytes = 0
        for index, raw in enumerate(_records(source, started, clock, digest), start=1):
            _deadline(started, clock)
            item = _normalize_raw(
                _decode(raw), source_identity=source_identity, source_record_index=index,
            )
            if item["producer_reported_action"] == "blocked":
                blocked += 1
            output_bytes += len(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            if output_bytes > suricata.MAX_OUTPUT_BYTES:
                _fail("OUTPUT_LIMIT")
            normalized.append(item)

        actual_digest = f"sha256:{digest.hexdigest()}"
        if actual_digest != expected_digest:
            _fail("DIGEST")
        try:
            suricata._verify_identities(descriptors, identities)
        except suricata.ReaderError as error:
            _fail(_reader_code(error))
        _deadline(started, clock)

        receipt = {
            "schema_version": "suricata-eve-reader-receipt-v1",
            "reader_policy_version": "suricata-eve-reader-policy-v1",
            "status": "complete",
            "run_identity": deepcopy(source_identity),
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
        return (
            tuple(suricata._freeze(item) for item in normalized),
            suricata._freeze(receipt),
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        if descriptors:
            _close(descriptors, primary)


def read_completed_raw_eve(
    path: str,
    *,
    expected_digest: str,
    sensor_id: str,
    run_id: str,
    ruleset_id: str,
    declared_version: str = PINNED_SURICATA_VERSION,
    completed_run_keys: AbstractSet[suricata.RunKey] = frozenset(),
) -> suricata.Publication:
    """Return one consumer-compatible publication from an alert-only EVE file.

    The caller must supply the exact SHA-256 digest and closed run identity.
    Call from the main thread of a single-threaded, unprivileged Linux process
    with the same ``SIGALRM`` conditions required by ``read_completed_file``.
    """

    source_identity, _replay_view = _validate_request(
        expected_digest,
        declared_version,
        sensor_id,
        run_id,
        ruleset_id,
        completed_run_keys,
    )
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
    try:
        remaining = suricata.MAX_ELAPSED_SECONDS - (clock() - started)
    except Exception:
        _fail("TIME_LIMIT")
    if remaining <= 0:
        _fail("TIME_LIMIT")

    try:
        from ..cli import _scoped_run_deadline

        with _scoped_run_deadline(remaining):
            return _read(
                path,
                expected_digest=expected_digest,
                source_identity=source_identity,
                started=started,
                clock=clock,
            )
    except RawEveError:
        raise
    except (CaptureError, OSError, ValueError):
        _fail("TIME_LIMIT")
    except Exception:
        _fail("TIME_LIMIT")
