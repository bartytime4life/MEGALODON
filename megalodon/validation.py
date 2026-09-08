"""Input validation and normalization for untrusted network metadata."""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import math
import re
from typing import Any


class ValidationError(ValueError):
    """Raised when an event or policy value is not safe to use."""


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_INTEGER_TEXT = re.compile(r"[0-9]+")


def parse_ip(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("IP address must be a non-empty string")
    candidate = value.strip()
    if "%" in candidate:
        raise ValidationError("IPv6 zone identifiers are not accepted")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError as exc:
        raise ValidationError(f"invalid IP address: {value!r}") from exc


def parse_network(value: str) -> ipaddress._BaseNetwork:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"invalid network: {value!r}") from exc


def _parse_integer(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{field_name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        candidate = value.strip()
        if _INTEGER_TEXT.fullmatch(candidate):
            return int(candidate)
    raise ValidationError(f"{field_name} must be an integer")


def parse_port(value: Any, *, allow_none: bool = True) -> int | None:
    if value is None and allow_none:
        return None
    port = _parse_integer(value, "port")
    if not 0 <= port <= 65535:
        raise ValidationError(f"port outside 0..65535: {port}")
    return port


def parse_nonnegative_int(value: Any, field_name: str) -> int:
    parsed = _parse_integer(value, field_name)
    if parsed < 0:
        raise ValidationError(f"{field_name} must be non-negative")
    return parsed


def parse_timestamp(value: Any) -> datetime:
    if value is None or value == "":
        raise ValidationError("timestamp must be present and timezone-aware")
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        candidate = value.strip().replace("Z", "+00:00")
        try:
            result = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValidationError(f"invalid ISO timestamp: {value!r}") from exc
    else:
        raise ValidationError("timestamp must be an ISO string")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValidationError("timestamp must include an explicit UTC offset")
    try:
        return result.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise ValidationError("timestamp is outside the supported UTC range") from exc


def parse_flags(value: Any) -> frozenset[str]:
    if value is None or value == "":
        return frozenset()
    if isinstance(value, str):
        raw = value.replace("|", ",").replace(" ", ",").split(",")
    elif isinstance(value, (list, tuple, set, frozenset)):
        raw = value
    else:
        raise ValidationError("tcp_flags must be a string or sequence")
    flags = {str(item).strip().upper() for item in raw if str(item).strip()}
    allowed = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"}
    unknown = flags - allowed
    if unknown:
        raise ValidationError(f"unknown TCP flags: {sorted(unknown)}")
    return frozenset(flags)


def safe_text(value: Any, field_name: str, max_length: int = 512) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be text")
    if _CONTROL_CHARS.search(value):
        raise ValidationError(f"{field_name} contains control characters")
    if len(value) > max_length:
        raise ValidationError(f"{field_name} exceeds {max_length} characters")
    return value


def validate_metadata(
    value: Any,
    *,
    max_depth: int = 4,
    max_items: int = 64,
    max_text: int = 256,
    max_bytes: int = 8192,
) -> dict[str, Any]:
    """Validate bounded, JSON-safe metadata without retaining packet payloads."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError("metadata must be an object")

    visited = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal visited
        visited += 1
        if visited > max_items:
            raise ValidationError(f"metadata exceeds {max_items} items")
        if depth > max_depth:
            raise ValidationError(f"metadata exceeds depth {max_depth}")
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValidationError("metadata keys must be text")
                safe_text(key, "metadata key", max_text)
                walk(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                walk(nested, depth + 1)
        elif isinstance(item, str):
            safe_text(item, "metadata value", max_text)
        elif isinstance(item, (bool, int)) or item is None:
            return
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValidationError("metadata numbers must be finite")
        else:
            raise ValidationError("metadata contains a non-JSON value")

    walk(value, 0)
    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError("metadata must be JSON serializable") from exc
    if len(serialized.encode("utf-8")) > max_bytes:
        raise ValidationError(f"metadata exceeds {max_bytes} bytes")
    return value


def is_global_unicast(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_global and not address.is_multicast
