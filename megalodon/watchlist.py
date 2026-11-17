"""Operator-supplied local IP/CIDR indicator watchlist. No fetch, no feed, no verdict.

Format (UTF-8 text, one indicator per line)::

    # comment lines and blank lines are ignored
    198.51.100.7            # optional label shown with the finding
    203.0.113.0/24          # known scanner range
    2001:db8:dead::/48

The file must be an owner-private regular file (no symlink, not group- or
world-writable) because a watchlist decides which addresses are flagged.
Networks broader than IPv4 /8 or IPv6 /16 are refused so that a mistaken
``0.0.0.0/0`` cannot flag every event. Matching is longest-prefix first.

``stix_indicators`` converts only whole-pattern IP equality comparisons from a
digest-pinned STIX 2.1 bundle (read by :mod:`megalodon.threat_context`); every
other pattern is counted as skipped and is never evaluated.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import os
import re
import stat
import tempfile
import unicodedata
from typing import Iterable

from .validation import ValidationError

MAX_WATCHLIST_BYTES = 8 * 1024 * 1024
MAX_INDICATORS = 200_000
MAX_LABEL_CHARS = 64
MIN_PREFIX = {4: 8, 6: 16}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_LABEL_SAFE = re.compile(r"[^\w .,:;/@()+\-\[\]#]")
_COMPARISON = r"(ipv4-addr|ipv6-addr):value\s*=\s*'([0-9A-Fa-f:./]{2,49})'"
_STIX_PATTERN = re.compile(
    r"\[\s*" + _COMPARISON + r"(?:\s+OR\s+" + _COMPARISON + r")*\s*\]"
)
_STIX_PART = re.compile(_COMPARISON)


def _label(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).strip()
    text = "".join(ch for ch in text if ch.isprintable())
    return _LABEL_SAFE.sub("", text)[:MAX_LABEL_CHARS].strip()


def parse_indicator(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """One IP or CIDR; IPv4-mapped IPv6 is folded to IPv4; broad networks refused."""
    if "%" in text:
        raise ValidationError("zone identifiers are not accepted")
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValidationError("invalid indicator") from None
    if network.version == 6 and network.prefixlen >= 96:
        mapped = network.network_address.ipv4_mapped
        if mapped is not None:
            network = ipaddress.ip_network((mapped, network.prefixlen - 96))
    if network.prefixlen < MIN_PREFIX[network.version]:
        raise ValidationError(
            f"indicator broader than /{MIN_PREFIX[network.version]} is refused"
        )
    return network


class Watchlist:
    """Immutable after construction; lookups are O(distinct prefix lengths)."""

    def __init__(
        self,
        entries: Iterable[tuple[ipaddress._BaseNetwork, str]] = (),
        *,
        severity: str = "HIGH",
        source: str = "memory",
    ) -> None:
        if severity not in SEVERITIES:
            raise ValidationError("watchlist severity must be LOW, MEDIUM, HIGH or CRITICAL")
        self.severity = severity
        self.source = source
        self._tables: dict[tuple[int, int], dict[int, tuple[str, str]]] = {}
        count = 0
        for network, label in entries:
            table = self._tables.setdefault((network.version, network.prefixlen), {})
            key = int(network.network_address)
            if key not in table:
                count += 1
                if count > MAX_INDICATORS:
                    raise ValidationError(f"watchlist exceeds {MAX_INDICATORS} indicators")
            table[key] = (network.with_prefixlen if network.num_addresses > 1
                          else str(network.network_address), label)
        self._count = count
        # Longest prefix first so the most specific label wins.
        self._order = sorted(self._tables, key=lambda item: (item[0], -item[1]))

    def __len__(self) -> int:
        return self._count

    def match(self, address: str) -> tuple[str, str] | None:
        parsed = ipaddress.ip_address(address)
        if parsed.version == 6 and parsed.ipv4_mapped is not None:
            parsed = parsed.ipv4_mapped
        value = int(parsed)
        width = 32 if parsed.version == 4 else 128
        for version, prefix in self._order:
            if version != parsed.version:
                continue
            masked = value >> (width - prefix) << (width - prefix)
            hit = self._tables[(version, prefix)].get(masked)
            if hit is not None:
                return hit
        return None

    def summary(self) -> dict[str, object]:
        by_version = {4: 0, 6: 0}
        for (version, _), table in self._tables.items():
            by_version[version] += len(table)
        return {
            "schema": "megalodon-watchlist-summary-v1",
            "indicators": self._count,
            "ipv4": by_version[4],
            "ipv6": by_version[6],
            "prefix_lengths": len(self._tables),
            "severity": self.severity,
            "network_access_performed": False,
        }


def parse_lines(lines: Iterable[str]) -> list[tuple[ipaddress._BaseNetwork, str]]:
    entries = []
    for number, raw in enumerate(lines, start=1):
        text, _, comment = raw.partition("#")
        text = text.strip()
        if not text:
            continue
        if len(text.split()) != 1:
            raise ValidationError(f"watchlist line {number}: one indicator per line")
        try:
            entries.append((parse_indicator(text), _label(comment)))
        except ValidationError as exc:
            raise ValidationError(f"watchlist line {number}: {exc}") from None
    return entries


def _read_private(path: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValidationError(f"watchlist cannot be opened: {exc.strerror}") from None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValidationError("watchlist must be a regular file")
        if info.st_uid != os.geteuid():
            raise ValidationError("watchlist must be owned by the current user")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValidationError("watchlist must not be group- or world-writable")
        if info.st_size > MAX_WATCHLIST_BYTES:
            raise ValidationError("watchlist exceeds the 8 MiB limit")
        chunks, total = [], 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_WATCHLIST_BYTES:
                raise ValidationError("watchlist exceeds the 8 MiB limit")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_watchlist(path: str | os.PathLike[str], *, severity: str = "HIGH") -> Watchlist:
    raw = _read_private(os.fspath(path))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValidationError("watchlist must be UTF-8 text") from None
    return Watchlist(parse_lines(text.splitlines()), severity=severity, source="file")


def stix_indicators(
    objects: Iterable[object], *, now: datetime | None = None,
) -> tuple[list[tuple[ipaddress._BaseNetwork, str]], dict[str, int]]:
    """Convert inert STIX indicator objects; nothing outside IP equality is evaluated."""
    now = now or datetime.now(timezone.utc)
    entries: list[tuple[ipaddress._BaseNetwork, str]] = []
    counts = {"converted": 0, "skipped_pattern": 0, "skipped_revoked": 0,
              "skipped_expired": 0, "skipped_invalid": 0}
    for item in objects:
        if not hasattr(item, "get") or item.get("type") != "indicator":
            continue
        if item.get("revoked") is True:
            counts["skipped_revoked"] += 1
            continue
        until = item.get("valid_until")
        if isinstance(until, str):
            try:
                if datetime.fromisoformat(until.replace("Z", "+00:00")) <= now:
                    counts["skipped_expired"] += 1
                    continue
            except ValueError:
                counts["skipped_invalid"] += 1
                continue
        pattern = item.get("pattern")
        if item.get("pattern_type") != "stix" or not isinstance(pattern, str) \
                or _STIX_PATTERN.fullmatch(pattern.strip()) is None:
            counts["skipped_pattern"] += 1
            continue
        label = _label(str(item.get("name") or item.get("id") or "stix indicator"))
        parts = []
        try:
            for kind, value in _STIX_PART.findall(pattern):
                network = parse_indicator(value)
                if network.version != (4 if kind == "ipv4-addr" else 6):
                    raise ValidationError("address family mismatch")
                parts.append(network)
        except ValidationError:
            counts["skipped_invalid"] += 1
            continue
        entries.extend((network, label) for network in parts)
        counts["converted"] += 1
    return entries, counts


def render(entries: Iterable[tuple[ipaddress._BaseNetwork, str]], header: str) -> str:
    lines = [f"# {_label(header)}"]
    seen: set[str] = set()
    for network, label in entries:
        text = network.with_prefixlen if network.num_addresses > 1 else str(network.network_address)
        if text in seen:
            continue
        seen.add(text)
        lines.append(f"{text}  # {label}" if label else text)
    return "\n".join(lines) + "\n"


def write_private(path: str | os.PathLike[str], text: str, *, replace: bool = False) -> None:
    """Atomic owner-private (0600) write; refuses to overwrite unless asked."""
    target = os.fspath(path)
    if os.path.lexists(target) and not replace:
        raise ValidationError("watchlist output exists; pass --replace to overwrite")
    directory = os.path.dirname(os.path.abspath(target))
    handle, temporary = tempfile.mkstemp(prefix=".watchlist-", dir=directory)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
