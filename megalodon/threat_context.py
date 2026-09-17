"""Bounded offline STIX 2.1 context reader with no fetch or action path.

The reader accepts one explicitly selected, owner-private completed bundle and
returns an immutable, privacy-bounded context projection plus a receipt.  STIX
patterns and references remain untrusted text: this module does not evaluate a
pattern, enrich a detection, infer attribution, persist data, or contact a feed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
import re
import stat
import time
from types import MappingProxyType
from typing import Any
from uuid import UUID

from .offline.common import OfflineError, _parts, require_unprivileged_linux


MAX_BUNDLE_BYTES = 16_777_216
MAX_OBJECTS = 4_096
MAX_NESTING_DEPTH = 32
MAX_NORMALIZED_BYTES = 16_777_216
MAX_PATTERN_CHARS = 8_192
MAX_LABELS = 32
MAX_MARKING_REFS = 64
MAX_EXTERNAL_REFERENCES = 32
MAX_ELAPSED_SECONDS = 15

ERROR_CODES = frozenset({
    "SOURCE_PATH", "SOURCE_SYMLINK", "SOURCE_TYPE", "SOURCE_OWNER",
    "SOURCE_MODE", "SOURCE_LINK", "SOURCE_CHANGED", "BUNDLE_BYTES",
    "EMPTY_INPUT", "UTF8", "DEPTH", "JSON", "DUPLICATE_KEY",
    "JSON_NUMBER", "DIGEST", "SCHEMA", "OBJECT_LIMIT",
    "DUPLICATE_OBJECT", "MARKING", "TEXT", "OUTPUT_LIMIT", "TIME_LIMIT",
})

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TYPE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z\Z"
)
_HASH_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HASH_VALUE = re.compile(r"[A-Fa-f0-9]{2,256}\Z")


class ThreatContextError(ValueError):
    """A fixed path-free diagnostic for the offline context boundary."""

    def __init__(self, code: str):
        if code not in ERROR_CODES:
            code = "SOURCE_CHANGED"
        super().__init__(f"THREAT_CONTEXT_READER_V1:{code}")


def _fail(code: str) -> None:
    raise ThreatContextError(code) from None


def _deadline(started: float) -> None:
    try:
        expired = time.monotonic() - started > MAX_ELAPSED_SECONDS
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
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
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
                info = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            except OSError:
                _fail("SOURCE_PATH")
            if stat.S_ISLNK(info.st_mode):
                _fail("SOURCE_SYMLINK")
            if not stat.S_ISREG(info.st_mode):
                _fail("SOURCE_TYPE")
            _fail("SOURCE_PATH")
        descriptors.append(source)
        info = os.fstat(source)
        identities.append(_identity(info))
        if not stat.S_ISREG(info.st_mode):
            _fail("SOURCE_TYPE")
        if info.st_nlink != 1:
            _fail("SOURCE_LINK")
        if info.st_uid != os.geteuid():
            _fail("SOURCE_OWNER")
        if stat.S_IMODE(info.st_mode) not in {0o400, 0o600}:
            _fail("SOURCE_MODE")
        if not 0 < info.st_size <= MAX_BUNDLE_BYTES:
            _fail("EMPTY_INPUT" if info.st_size == 0 else "BUNDLE_BYTES")
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


def _read_source(path: str, started: float) -> bytes:
    source, descriptors, identities = _open_source(path)
    primary: BaseException | None = None
    try:
        data = bytearray()
        while True:
            _deadline(started)
            try:
                chunk = os.read(source, min(65_536, MAX_BUNDLE_BYTES - len(data) + 1))
            except OSError:
                _fail("SOURCE_CHANGED")
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_BUNDLE_BYTES:
                _fail("BUNDLE_BYTES")
        _verify_identities(descriptors, identities)
        return bytes(data)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        _close_all(descriptors, primary)


def _scan_depth(text: str) -> None:
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
            if depth > MAX_NESTING_DEPTH:
                _fail("DEPTH")
        elif char in "]}":
            depth -= 1
    if quoted or depth != 0:
        _fail("JSON")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("DUPLICATE_KEY")
        result[key] = value
    return result


def _integer(value: str) -> int:
    if not re.fullmatch(r"-?(?:0|[1-9][0-9]{0,19})", value):
        _fail("JSON_NUMBER")
    return int(value)


def _reject_number(_value: str) -> None:
    _fail("JSON_NUMBER")


def _decode(raw: bytes) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf"):
        _fail("UTF8")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        _fail("UTF8")
    _scan_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except ThreatContextError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError):
        _fail("JSON")
    if type(value) is not dict:
        _fail("SCHEMA")
    return value


def _text(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        _fail("TEXT")
    return value


def _stix_id(value: object, expected_type: str | None = None) -> str:
    text = _text(value, 128)
    if "--" not in text:
        _fail("SCHEMA")
    object_type, raw_uuid = text.split("--", 1)
    if not _TYPE.fullmatch(object_type) or (expected_type is not None and object_type != expected_type):
        _fail("SCHEMA")
    try:
        parsed = UUID(raw_uuid)
    except ValueError:
        _fail("SCHEMA")
    if str(parsed) != raw_uuid or parsed.version not in {4, 5}:
        _fail("SCHEMA")
    return text


def _timestamp(value: object) -> str:
    text = _text(value, 40)
    if not _TIMESTAMP.fullmatch(text):
        _fail("SCHEMA")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError:
        _fail("SCHEMA")
    if parsed.tzinfo != timezone.utc:
        _fail("SCHEMA")
    return text


def _string_list(value: object, maximum_items: int, maximum_chars: int) -> list[str]:
    if type(value) is not list or len(value) > maximum_items:
        _fail("SCHEMA")
    result = [_text(item, maximum_chars) for item in value]
    if len(result) != len(set(result)):
        _fail("SCHEMA")
    return result


def _external_references(value: object) -> list[dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_EXTERNAL_REFERENCES:
        _fail("SCHEMA")
    result = []
    for reference in value:
        if type(reference) is not dict or not set(reference) <= {
            "source_name", "description", "url", "hashes", "external_id",
        } or "source_name" not in reference:
            _fail("SCHEMA")
        item: dict[str, Any] = {"source_name": _text(reference["source_name"], 128)}
        for key, maximum in (("description", 1_024), ("url", 2_048), ("external_id", 256)):
            if key in reference:
                item[key] = _text(reference[key], maximum)
        if "hashes" in reference:
            hashes = reference["hashes"]
            if type(hashes) is not dict or not 1 <= len(hashes) <= 16:
                _fail("SCHEMA")
            normalized_hashes = {}
            for name, digest in hashes.items():
                if type(name) is not str or not _HASH_NAME.fullmatch(name):
                    _fail("SCHEMA")
                digest_text = _text(digest, 256)
                if not _HASH_VALUE.fullmatch(digest_text):
                    _fail("SCHEMA")
                normalized_hashes[name] = digest_text
            item["hashes"] = normalized_hashes
        result.append(item)
    return result


def _marking_definition(value: dict[str, Any], item: dict[str, Any]) -> None:
    definition_type = value.get("definition_type")
    definition = value.get("definition")
    if definition_type == "tlp":
        if type(definition) is not dict or set(definition) != {"tlp"}:
            _fail("MARKING")
        tlp = _text(definition["tlp"], 16).lower()
        if tlp not in {"white", "green", "amber", "red", "clear", "amber+strict"}:
            _fail("MARKING")
        item["definition_type"] = "tlp"
        item["definition"] = {"tlp": tlp}
    elif definition_type == "statement":
        if type(definition) is not dict or set(definition) != {"statement"}:
            _fail("MARKING")
        item["definition_type"] = "statement"
        item["definition"] = {"statement": _text(definition["statement"], 2_048)}
    else:
        _fail("MARKING")


def _normalize_object(value: object) -> dict[str, Any]:
    if type(value) is not dict:
        _fail("SCHEMA")
    object_type = value.get("type")
    if type(object_type) is not str or not _TYPE.fullmatch(object_type) or object_type == "bundle":
        _fail("SCHEMA")
    if value.get("spec_version") != "2.1" or "id" not in value:
        _fail("SCHEMA")
    item: dict[str, Any] = {
        "type": object_type,
        "spec_version": "2.1",
        "id": _stix_id(value["id"], object_type),
    }
    if "granular_markings" in value:
        _fail("MARKING")
    if "created_by_ref" in value:
        item["created_by_ref"] = _stix_id(value["created_by_ref"], "identity")
    for key in ("created", "modified"):
        if key in value:
            item[key] = _timestamp(value[key])
    if "revoked" in value:
        if type(value["revoked"]) is not bool:
            _fail("SCHEMA")
        item["revoked"] = value["revoked"]
    if "confidence" in value:
        if type(value["confidence"]) is not int or not 0 <= value["confidence"] <= 100:
            _fail("SCHEMA")
        item["confidence"] = value["confidence"]
    if "name" in value:
        item["name"] = _text(value["name"], 256)
    if "labels" in value:
        item["labels"] = _string_list(value["labels"], MAX_LABELS, 256)
    if "object_marking_refs" in value:
        refs = _string_list(value["object_marking_refs"], MAX_MARKING_REFS, 128)
        item["object_marking_refs"] = [_stix_id(ref, "marking-definition") for ref in refs]
    if "external_references" in value:
        item["external_references"] = _external_references(value["external_references"])

    if object_type == "indicator":
        if not {"pattern", "pattern_type", "valid_from"} <= set(value):
            _fail("SCHEMA")
        item["pattern"] = _text(value["pattern"], MAX_PATTERN_CHARS)
        item["pattern_type"] = _text(value["pattern_type"], 64)
        item["valid_from"] = _timestamp(value["valid_from"])
        if "pattern_version" in value:
            item["pattern_version"] = _text(value["pattern_version"], 32)
        if "valid_until" in value:
            item["valid_until"] = _timestamp(value["valid_until"])
            if datetime.fromisoformat(item["valid_until"].removesuffix("Z") + "+00:00") < datetime.fromisoformat(item["valid_from"].removesuffix("Z") + "+00:00"):
                _fail("SCHEMA")
    elif "pattern" in value or "pattern_type" in value or "pattern_version" in value:
        _fail("SCHEMA")

    if object_type == "marking-definition":
        _marking_definition(value, item)
    return item


def _freeze(value: Any) -> Any:
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def read_completed_bundle(
    path: str | os.PathLike[str], expected_digest: str,
) -> tuple[tuple[Mapping[str, Any], ...], Mapping[str, Any]]:
    """Read one private completed STIX bundle and return inert context.

    The expected digest is operator-supplied out-of-band identity, not evidence
    that the bundle is trustworthy.  Successful parsing grants no detection,
    attribution, persistence, network, model, or response authority.
    """
    require_unprivileged_linux()
    if type(expected_digest) is not str or not _DIGEST.fullmatch(expected_digest):
        _fail("DIGEST")
    try:
        selected_path = os.fspath(path)
    except TypeError:
        _fail("SOURCE_PATH")
    if type(selected_path) is not str:
        _fail("SOURCE_PATH")
    started = time.monotonic()
    raw = _read_source(selected_path, started)
    artifact_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if artifact_digest != expected_digest:
        _fail("DIGEST")
    bundle = _decode(raw)
    if set(bundle) != {"type", "id", "objects"} or bundle.get("type") != "bundle":
        _fail("SCHEMA")
    bundle_id = _stix_id(bundle.get("id"), "bundle")
    objects = bundle.get("objects")
    if type(objects) is not list or not 1 <= len(objects) <= MAX_OBJECTS:
        _fail("OBJECT_LIMIT")

    normalized = []
    seen_ids: set[str] = set()
    object_types: Counter[str] = Counter()
    normalized_bytes = 0
    for value in objects:
        _deadline(started)
        item = _normalize_object(value)
        if item["id"] in seen_ids:
            _fail("DUPLICATE_OBJECT")
        seen_ids.add(item["id"])
        object_types[item["type"]] += 1
        normalized_bytes += len(json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if normalized_bytes > MAX_NORMALIZED_BYTES:
            _fail("OUTPUT_LIMIT")
        normalized.append(item)

    marking_ids = {item["id"] for item in normalized if item["type"] == "marking-definition"}
    for item in normalized:
        if any(reference not in marking_ids for reference in item.get("object_marking_refs", ())):
            _fail("MARKING")

    _deadline(started)
    receipt = {
        "schema_version": "megalodon-threat-context-reader-v1",
        "status": "complete",
        "bundle_id": bundle_id,
        "artifact_digest": artifact_digest,
        "object_count": len(normalized),
        "object_types": dict(sorted(object_types.items())),
        "marking_definition_count": len(marking_ids),
        "indicator_pattern_count": object_types.get("indicator", 0),
        "normalized_context_bytes": normalized_bytes,
        "source_snapshot_status": "metadata_unchanged_not_atomic",
        "pattern_handling": "untrusted_text_never_execute",
        "runtime_fetch": False,
        "taxii": False,
        "attribution_authority": False,
        "detection_authority": False,
        "action_authority": "none",
        "persistence_status": "not_attempted",
    }
    return tuple(_freeze(item) for item in normalized), _freeze(receipt)
