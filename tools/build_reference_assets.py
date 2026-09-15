#!/usr/bin/env python3
"""Build MEGALODON's pinned public reference data and synthetic corpus.

This maintainer-only tool performs no network access.  It accepts the two exact
IANA CSV snapshots named below, verifies their pinned bytes, projects only the
fields used for offline context, and emits deterministic package resources.
The scenario generator is intentionally independent of the detector.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import Iterable


SERVICE_SOURCE = {
    "id": "iana-service-names-port-numbers",
    "file": "service-names-port-numbers.csv",
    "canonical_url": (
        "https://www.iana.org/assignments/service-names-port-numbers/"
        "service-names-port-numbers.csv"
    ),
    "registry_url": "https://www.iana.org/assignments/service-names-port-numbers",
    "registry_last_updated": "2026-09-07",
    "retrieved_at": "2026-09-10T19:10:11.051Z",
    "retrieved_at_basis": "connector_receipt_utc_not_filesystem_metadata",
    "content_type": "text/csv; charset=UTF-8; header=present",
    "last_modified": "Mon, 07 Sep 2026 18:41:30 GMT",
    "raw_bytes": 1_157_044,
    "raw_sha256": "9777be6d2451ab61ac3c64443b0cfb968bbdeddea3cc5e640eb81f3ec045b7a4",
    "expected_header": [
        "Service Name",
        "Port Number",
        "Transport Protocol",
        "Description",
        "Assignee",
        "Contact",
        "Registration Date",
        "Modification Date",
        "Reference",
        "Service Code",
        "Unauthorized Use Reported",
        "Assignment Notes",
    ],
    "retained_fields": [
        "Service Name",
        "Port Number",
        "Transport Protocol",
        "Description",
        "Registration Date",
        "Modification Date",
    ],
    "omitted_fields": [
        "Assignee",
        "Contact",
        "Reference",
        "Service Code",
        "Unauthorized Use Reported",
        "Assignment Notes",
    ],
}

PROTOCOL_SOURCE = {
    "id": "iana-protocol-numbers",
    "file": "protocol-numbers-1.csv",
    "canonical_url": (
        "https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv"
    ),
    "registry_url": "https://www.iana.org/assignments/protocol-numbers",
    "registry_last_updated": "2026-03-09",
    "retrieved_at": "2026-09-10T19:13:32.727Z",
    "retrieved_at_basis": "connector_receipt_utc_not_filesystem_metadata",
    "content_type": "text/csv; charset=UTF-8; header=present",
    "last_modified": "Tue, 10 Mar 2026 03:31:19 GMT",
    "raw_bytes": 9_230,
    "raw_sha256": "e704ee14e69347681b3a6271af02195a9741236074fc311449ebb032101bdf2c",
    "expected_header": [
        "Decimal",
        "Keyword",
        "Protocol",
        "IPv6 Extension Header",
        "Reference",
    ],
    "retained_fields": [
        "Decimal",
        "Keyword",
        "Protocol",
        "IPv6 Extension Header",
    ],
    "omitted_fields": ["Reference"],
}

SERVICE_TRANSPORTS = {"tcp", "udp", "sctp", "dccp"}
DATE = re.compile(r"[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?")
PORT = re.compile(r"([0-9]{1,5})(?:-([0-9]{1,5}))?")
DECIMAL = re.compile(r"([0-9]{1,3})(?:-([0-9]{1,3}))?")
BASE = datetime(2020, 1, 1, tzinfo=timezone.utc)
RULES = ("DNS_TUNNELING", "PORT_SCAN", "SYN_FLOOD")
MAX_SHARD_BYTES = 76 * 1024


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _text(value: str) -> str | None:
    normalized = " ".join(value.split())
    return normalized or None


def _date(value: str) -> str | None:
    normalized = _text(value)
    if normalized is not None and not DATE.fullmatch(normalized):
        raise ValueError("unexpected IANA date")
    return normalized


def _range(value: str, pattern: re.Pattern[str], maximum: int) -> tuple[int, int]:
    match = pattern.fullmatch(value)
    if not match:
        raise ValueError("unexpected IANA numeric range")
    start = int(match.group(1))
    end = int(match.group(2) or match.group(1))
    if not 0 <= start <= end <= maximum:
        raise ValueError("IANA numeric range outside contract")
    return start, end


def _source(path: Path, contract: dict[str, object]) -> tuple[bytes, list[dict[str, str]]]:
    expected_bytes = int(contract["raw_bytes"])
    remaining = expected_bytes + 1
    chunks: list[bytes] = []
    with path.open("rb") as source:
        while remaining:
            chunk = source.read(min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    data = b"".join(chunks)
    if len(data) != expected_bytes or _digest(data) != contract["raw_sha256"]:
        raise ValueError("IANA source does not match the pinned snapshot")
    text = data.decode("utf-8-sig")
    csv.field_size_limit(16 * 1024)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if reader.fieldnames != contract["expected_header"]:
        raise ValueError("unexpected IANA CSV header")
    rows = list(reader)
    if any(None in row for row in rows):
        raise ValueError("unexpected IANA CSV row width")
    return data, rows


def _service_records(rows: Iterable[dict[str, str]]) -> tuple[list[dict[str, object]], int]:
    records: list[dict[str, object]] = []
    excluded = 0
    for source_row, row in enumerate(rows, start=1):
        transport = row["Transport Protocol"]
        port_text = row["Port Number"]
        if transport not in SERVICE_TRANSPORTS or not port_text:
            excluded += 1
            continue
        start, end = _range(port_text, PORT, 65_535)
        service = _text(row["Service Name"])
        description = _text(row["Description"])
        if service is None:
            record_kind = (
                "reserved"
                if (description or "").casefold().startswith("reserved")
                else "unassigned"
                if (description or "").casefold().startswith("unassigned")
                else "unnamed"
            )
        else:
            record_kind = "named"
        records.append(
            {
                "description": description,
                "modification_date": _date(row["Modification Date"]),
                "port_end": end,
                "port_start": start,
                "record_kind": record_kind,
                "registration_date": _date(row["Registration Date"]),
                "service_name": service,
                "source_row": source_row,
                "transport": transport,
            }
        )
    records.sort(
        key=lambda item: (
            item["port_start"],
            item["port_end"],
            item["transport"],
            item["service_name"] or "",
            item["description"] or "",
            item["registration_date"] or "",
            item["modification_date"] or "",
            item["source_row"],
        )
    )
    if len({record["source_row"] for record in records}) != len(records):
        raise ValueError("duplicate IANA service source row")
    return records, excluded


def _protocol_records(rows: Iterable[dict[str, str]]) -> list[dict[str, object]]:
    records = []
    for source_row, row in enumerate(rows, start=1):
        start, end = _range(row["Decimal"], DECIMAL, 255)
        marker = row["IPv6 Extension Header"]
        if marker not in {"", "N", "Y"}:
            raise ValueError("unexpected IPv6 extension-header marker")
        keyword = _text(row["Keyword"])
        name = _text(row["Protocol"])
        combined = " ".join(value for value in (keyword, name) if value).casefold()
        if "experimentation" in combined or "experimental" in combined:
            record_kind = "experimental"
        elif "unassigned" in combined:
            record_kind = "unassigned"
        elif "reserved" in combined:
            record_kind = "reserved"
        elif keyword is not None or name is not None:
            record_kind = "named"
        else:
            record_kind = "unnamed"
        records.append(
            {
                "decimal_end": end,
                "decimal_start": start,
                "ipv6_extension_header": (
                    "yes" if marker == "Y" else "no" if marker == "N" else "unspecified"
                ),
                "keyword": keyword,
                "protocol_name": name,
                "record_kind": record_kind,
                "source_row": source_row,
            }
        )
    records.sort(
        key=lambda item: (
            item["decimal_start"],
            item["decimal_end"],
            item["keyword"] or "",
            item["protocol_name"] or "",
            item["source_row"],
        )
    )
    if len({record["source_row"] for record in records}) != len(records):
        raise ValueError("duplicate IANA protocol source row")
    return records


def _event(
    seconds: float,
    src: str,
    dst: str,
    protocol: str,
    *,
    src_port: int | None,
    dst_port: int | None,
    flags: tuple[str, ...] = (),
    dns_length: int | None = None,
    byte_count: int = 60,
) -> dict[str, object]:
    stamp = BASE + timedelta(seconds=seconds)
    return {
        "byte_count": byte_count,
        "dns_query_length": dns_length,
        "dst_ip": dst,
        "dst_port": dst_port,
        "interface": "synthetic-corpus-v1",
        "metadata": {},
        "observed_at": stamp.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "protocol": protocol,
        "src_ip": src,
        "src_port": src_port,
        "tcp_flags": list(flags),
    }


def _routine() -> list[dict[str, object]]:
    rows = []
    for index in range(240):
        src = f"192.0.2.{10 + index % 16}"
        dst = f"198.51.100.{20 + index % 8}"
        if index % 5 == 0:
            rows.append(_event(index * 2, src, dst, "DNS", src_port=53000 + index % 1000,
                               dst_port=53, dns_length=24 + index % 20, byte_count=140))
        else:
            rows.append(_event(index * 2, src, dst, "TCP", src_port=40000 + index,
                               dst_port=443 if index % 2 else 80, flags=("ACK",), byte_count=512))
    for index in range(240):
        src = f"2001:db8::{10 + index % 16:x}"
        dst = f"2001:db8:1::{20 + index % 8:x}"
        if index % 5 == 0:
            rows.append(_event(600 + index * 2, src, dst, "UDP", src_port=54000 + index % 1000,
                               dst_port=53, dns_length=20 + index % 25, byte_count=160))
        else:
            rows.append(_event(600 + index * 2, src, dst, "TCP", src_port=41000 + index,
                               dst_port=443 if index % 2 else 80, flags=("ACK",), byte_count=768))
    return rows


def _threshold_matrix() -> list[dict[str, object]]:
    rows = []
    syn_cases = (("192.0.2.30", 99), ("192.0.2.31", 100), ("2001:db8::32", 101))
    for case, (src, amount) in enumerate(syn_cases):
        dst = "2001:db8:1::20" if ":" in src else "198.51.100.20"
        for index in range(amount):
            rows.append(_event(case * 20 + index / 1000, src, dst, "TCP",
                               src_port=42000 + index, dst_port=443, flags=("SYN",)))
    port_cases = (("192.0.2.40", 19), ("192.0.2.41", 20), ("2001:db8::42", 21))
    for case, (src, amount) in enumerate(port_cases):
        dst = "2001:db8:2::20" if ":" in src else "203.0.113.20"
        for index in range(amount):
            rows.append(_event(100 + case * 20 + index / 1000, src, dst, "TCP",
                               src_port=43000, dst_port=1000 + index, flags=("ACK",)))
    dns_cases = (("192.0.2.50", 49), ("192.0.2.51", 50), ("2001:db8::52", 51))
    for case, (src, length) in enumerate(dns_cases):
        dst = "2001:db8:3::53" if ":" in src else "198.51.100.53"
        rows.append(_event(200 + case, src, dst, "DNS", src_port=53000 + case,
                           dst_port=53, dns_length=length, byte_count=180))
    return rows


def _cooldown() -> list[dict[str, object]]:
    rows = []
    for burst in (0, 30):
        for index in range(100):
            rows.append(_event(burst + index / 100, "192.0.2.60", "198.51.100.60", "TCP",
                               src_port=44000 + index, dst_port=443, flags=("SYN",)))
    for burst in (100, 130):
        for index in range(20):
            rows.append(_event(burst + index / 100, "192.0.2.61", "203.0.113.61", "TCP",
                               src_port=45000, dst_port=2000 + index, flags=("ACK",)))
    for seconds in (200, 229.999999, 230):
        rows.append(_event(seconds, "2001:db8::62", "2001:db8:4::53", "DNS",
                           src_port=55000, dst_port=53, dns_length=60, byte_count=200))
    return rows


def _mixed() -> list[dict[str, object]]:
    rows = []
    for index in range(360):
        src = f"192.0.2.{70 + index % 6}"
        dst = f"198.51.100.{70 + index % 4}"
        rows.append(_event(index * 10, src, dst, "TCP", src_port=46000 + index % 1000,
                           dst_port=443 if index % 3 else 80, flags=("ACK",), byte_count=900))
    for base, src in ((4000, "192.0.2.80"), (5000, "2001:db8::80")):
        dst = "2001:db8:5::80" if ":" in src else "198.51.100.80"
        for index in range(100):
            rows.append(_event(base + index / 100, src, dst, "TCP", src_port=47000 + index,
                               dst_port=443, flags=("SYN",)))
    for case, src in enumerate(("192.0.2.81", "192.0.2.82", "2001:db8::83")):
        dst = "2001:db8:6::83" if ":" in src else "203.0.113.81"
        for index in range(20):
            rows.append(_event(6000 + case * 1000 + index / 100, src, dst, "TCP",
                               src_port=48000, dst_port=3000 + index, flags=("ACK",)))
    for case, src in enumerate(("192.0.2.84", "192.0.2.85", "2001:db8::86", "2001:db8::87")):
        dst = "2001:db8:7::53" if ":" in src else "198.51.100.53"
        rows.append(_event(9000 + case * 40, src, dst, "DNS", src_port=56000 + case,
                           dst_port=53, dns_length=70 + case, byte_count=220))
    return rows


def _lookalikes() -> list[dict[str, object]]:
    rows = []
    for index in range(100):
        rows.append(_event(index / 100, "192.0.2.90", "198.51.100.90", "TCP",
                           src_port=49000 + index, dst_port=8443, flags=("SYN",)))
    for index in range(20):
        rows.append(_event(100 + index / 100, "192.0.2.91", "203.0.113.91", "TCP",
                           src_port=50000, dst_port=4000 + index, flags=("ACK",)))
    rows.append(_event(200, "192.0.2.92", "198.51.100.53", "DNS",
                       src_port=57000, dst_port=53, dns_length=72, byte_count=240))
    return rows


def _ipv6() -> list[dict[str, object]]:
    rows = []
    for index in range(100):
        rows.append(_event(index / 100, "2001:db8::100", "2001:db8:8::100", "TCP",
                           src_port=51000 + index, dst_port=443, flags=("SYN",)))
    for index in range(20):
        rows.append(_event(100 + index / 100, "2001:db8::101", "2001:db8:8::101", "TCP",
                           src_port=52000, dst_port=5000 + index, flags=("ACK",)))
    rows.append(_event(200, "2001:db8::102", "2001:db8:8::53", "UDP",
                       src_port=58000, dst_port=53, dns_length=64, byte_count=260))
    return rows


def _syn_cutoff(*, outside: bool) -> list[dict[str, object]]:
    rows = [
        _event(0, "192.0.2.110", "198.51.100.110", "TCP",
               src_port=59000, dst_port=443, flags=("SYN",))
    ]
    final_time = 10.001 if outside else 10
    for index in range(1, 100):
        rows.append(_event(final_time, "192.0.2.110", "198.51.100.110", "TCP",
                           src_port=59000 + index, dst_port=443, flags=("SYN",)))
    return rows


def _port_distinctness(*, repeated: bool) -> list[dict[str, object]]:
    return [
        _event(index / 4, "2001:db8:a::1", "2001:db8:a::2", "TCP",
               src_port=60000 + index, dst_port=10000 if repeated else 10000 + index,
               flags=("ACK",))
        for index in range(20)
    ]


def _dns_protocol_gates() -> list[dict[str, object]]:
    return [
        _event(0, "192.0.2.120", "198.51.100.120", "DNS",
               src_port=53000, dst_port=53, dns_length=49, byte_count=128),
        _event(1, "2001:db8:b::1", "2001:db8:b::53", "DNS",
               src_port=53001, dst_port=53, dns_length=50, byte_count=129),
        _event(2, "203.0.113.121", "198.51.100.121", "UDP",
               src_port=53002, dst_port=53, dns_length=50, byte_count=129),
        _event(3, "2001:db8:b::2", "2001:db8:b::53", "TCP",
               src_port=53003, dst_port=53, flags=("ACK",), dns_length=80,
               byte_count=160),
    ]


def _source_pressure() -> list[dict[str, object]]:
    rows = [
        _event(index / 1000, "2001:db8:9::1", "2001:db8:9::2", "TCP",
               src_port=40000 + index, dst_port=443, flags=("SYN",))
        for index in range(100)
    ]
    rows.extend(
        _event(1 + (index - 1) / 1000, f"2001:db8:ffff::{index:x}",
               "2001:db8:ffff::ffff", "UDP",
               src_port=30000 + ((index - 1) % 10000), dst_port=33434,
               byte_count=72)
        for index in range(1, 4097)
    )
    rows.extend(
        _event(6 + index / 1000, "2001:db8:9::1", "2001:db8:9::2", "TCP",
               src_port=40100 + index, dst_port=443, flags=("SYN",))
        for index in range(100)
    )
    return rows


def _scenario_definitions() -> tuple[dict[str, object], ...]:
    return (
        {
            "id": "routine-dual-stack-v1",
            "description": "Mixed IPv4/IPv6 web and short DNS-shaped metadata below every fixed threshold.",
            "interpretation": "synthetic routine-shaped background",
            "expected": {rule: 0 for rule in RULES},
            "records": _routine(),
        },
        {
            "id": "threshold-matrix-v1",
            "description": "Below, exact, and above quantities for all three fixed detectors.",
            "interpretation": "synthetic boundary behavior; intent unknown",
            "expected": {"DNS_TUNNELING": 2, "PORT_SCAN": 2, "SYN_FLOOD": 2},
            "records": _threshold_matrix(),
        },
        {
            "id": "cooldown-boundaries-v1",
            "description": "Repeated qualifying patterns around the exact 30-second cooldown boundary.",
            "interpretation": "synthetic temporal boundary behavior; intent unknown",
            "expected": {"DNS_TUNNELING": 2, "PORT_SCAN": 2, "SYN_FLOOD": 2},
            "records": _cooldown(),
        },
        {
            "id": "mixed-triage-v1",
            "description": "Routine-shaped metadata plus multiple rule findings spread across a long timeline.",
            "interpretation": "synthetic dashboard and analyst workflow exercise",
            "expected": {"DNS_TUNNELING": 4, "PORT_SCAN": 3, "SYN_FLOOD": 2},
            "records": _mixed(),
        },
        {
            "id": "authorized-lookalikes-v1",
            "description": "Load-test, inventory-sweep, and long-name lookalikes that still meet rule thresholds.",
            "interpretation": "synthetic authorized-benign alternative; labels are scenario context only",
            "expected": {"DNS_TUNNELING": 1, "PORT_SCAN": 1, "SYN_FLOOD": 1},
            "records": _lookalikes(),
        },
        {
            "id": "ipv6-parity-v1",
            "description": "IPv6 documentation-range equivalents for each fixed detector.",
            "interpretation": "synthetic address-family parity exercise; intent unknown",
            "expected": {"DNS_TUNNELING": 1, "PORT_SCAN": 1, "SYN_FLOOD": 1},
            "records": _ipv6(),
        },
        {
            "id": "syn-window-cutoff-v1",
            "description": "One SYN at the window start and 99 at the inclusive ten-second cutoff.",
            "interpretation": "synthetic inclusive-window boundary; intent unknown",
            "expected": {"DNS_TUNNELING": 0, "PORT_SCAN": 0, "SYN_FLOOD": 1},
            "records": _syn_cutoff(outside=False),
        },
        {
            "id": "syn-window-outside-v1",
            "description": "One SYN at the window start and 99 just beyond the ten-second cutoff.",
            "interpretation": "synthetic expired-window negative control; intent unknown",
            "expected": {rule: 0 for rule in RULES},
            "records": _syn_cutoff(outside=True),
        },
        {
            "id": "port-distinct-ipv6-v1",
            "description": "Twenty IPv6 TCP observations targeting twenty distinct destination ports.",
            "interpretation": "synthetic exact distinct-port boundary; intent unknown",
            "expected": {"DNS_TUNNELING": 0, "PORT_SCAN": 1, "SYN_FLOOD": 0},
            "records": _port_distinctness(repeated=False),
        },
        {
            "id": "port-repeated-ipv6-v1",
            "description": "Twenty IPv6 TCP observations repeatedly targeting one destination port.",
            "interpretation": "synthetic distinctness negative control; intent unknown",
            "expected": {rule: 0 for rule in RULES},
            "records": _port_distinctness(repeated=True),
        },
        {
            "id": "dns-protocol-gates-v1",
            "description": "Below-threshold DNS plus exact-threshold DNS/UDP and an ineligible TCP lookalike.",
            "interpretation": "synthetic length and protocol boundary; intent unknown",
            "expected": {"DNS_TUNNELING": 2, "PORT_SCAN": 0, "SYN_FLOOD": 0},
            "records": _dns_protocol_gates(),
        },
        {
            "id": "source-cap-pressure-v1",
            "description": "Two SYN bursts separated by 4,096 unique IPv6 sources inside cooldown.",
            "interpretation": "synthetic source-eviction and cooldown-reset boundary; intent unknown",
            "expected": {"DNS_TUNNELING": 0, "PORT_SCAN": 0, "SYN_FLOOD": 2},
            "records": _source_pressure(),
        },
    )


def _artifact(path: Path, schema: str, rows: int) -> dict[str, object]:
    data = path.read_bytes()
    return {
        "bytes": len(data),
        "path": path.name,
        "rows": rows,
        "schema": schema,
        "sha256": _digest(data),
    }


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject existing symlinks from the filesystem root through ``path``."""

    absolute = Path(os.path.abspath(path))
    for component in (*reversed(absolute.parents), absolute):
        try:
            mode = component.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError(f"{label} must not contain symlink components")


def _new_output_directory(output_root: Path) -> None:
    _reject_symlink_components(output_root, "generated output path")
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("generated output directory must not already exist")
    if not output_root.parent.is_dir() or output_root.parent.is_symlink():
        raise ValueError("generated output parent must be a real directory")
    output_root.mkdir(mode=0o700)


def _declared_bundle_names(bundle: Path) -> set[str]:
    try:
        manifest = json.loads((bundle / "manifest.json").read_bytes())
        if bundle.name == "iana-v1":
            names = [item["path"] for item in manifest["artifacts"]]
        elif bundle.name == "corpus-v1":
            names = [
                shard["path"]
                for scenario in manifest["scenarios"]
                for shard in scenario["shards"]
            ]
        else:
            raise ValueError("unexpected bundle name")
    except (KeyError, TypeError, json.JSONDecodeError, OSError) as exc:
        raise ValueError("bundle manifest cannot identify owned files") from exc
    if (
        not names
        or any(
            not isinstance(name, str)
            or not name
            or "/" in name
            or "\\" in name
            for name in names
        )
        or len(names) != len(set(names))
    ):
        raise ValueError("bundle manifest contains unsafe artifact names")
    return {"manifest.json", *names}


def _publish_bundle(staged: Path, target: Path) -> None:
    """Replace one generated bundle without following destination symlinks."""

    _reject_symlink_components(staged, "staged bundle path")
    _reject_symlink_components(target, "bundle destination path")
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("bundle destination must be a real directory")
    staged_entries = tuple(staged.iterdir())
    if (
        any(child.is_symlink() or not child.is_file() for child in staged_entries)
        or {child.name for child in staged_entries} != _declared_bundle_names(staged)
    ):
        raise ValueError("staged bundle contains an unexpected entry")
    backup = target.parent / f".{target.name}.previous"
    if backup.exists() or backup.is_symlink():
        raise ValueError("bundle backup path already exists")
    moved_old = False
    if target.exists():
        target_entries = tuple(target.iterdir())
        if (
            any(child.is_symlink() or not child.is_file() for child in target_entries)
            or {child.name for child in target_entries} != _declared_bundle_names(target)
        ):
            raise ValueError("existing bundle contains an unexpected entry")
        os.replace(target, backup)
        moved_old = True
    try:
        os.replace(staged, target)
    except BaseException as publish_error:
        if moved_old:
            try:
                # A signal may be delivered after the rename completed but
                # before os.replace() returned. Move that new directory back
                # to staging before restoring the previous closed bundle.
                if target.exists() or target.is_symlink():
                    if staged.exists() or staged.is_symlink():
                        raise RuntimeError(
                            "cannot restore the previous bundle while both "
                            "staged and destination paths exist"
                        )
                    os.replace(target, staged)
                os.replace(backup, target)
            except BaseException as restore_error:
                publish_error.add_note(
                    "restoring the previous bundle failed; inspect the "
                    f"destination and {backup.name}: {restore_error!r}"
                )
        raise
    if moved_old:
        shutil.rmtree(backup)


def _chunks(lines: Iterable[bytes]) -> list[tuple[bytes, int]]:
    chunks: list[tuple[bytes, int]] = []
    pending: list[bytes] = []
    pending_bytes = 0
    for line in lines:
        if len(line) > MAX_SHARD_BYTES:
            raise ValueError("normalized line exceeds shard boundary")
        if pending and pending_bytes + len(line) > MAX_SHARD_BYTES:
            chunks.append((b"".join(pending), len(pending)))
            pending = []
            pending_bytes = 0
        pending.append(line)
        pending_bytes += len(line)
    if pending:
        chunks.append((b"".join(pending), len(pending)))
    return chunks


def _write_shards(
    output_root: Path,
    prefix: str,
    schema: str,
    lines: Iterable[bytes],
) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    for part, (data, rows) in enumerate(_chunks(lines), start=1):
        path = output_root / f"{prefix}.part-{part:03d}.jsonl"
        path.write_bytes(data)
        artifacts.append(_artifact(path, schema, rows))
    if not artifacts:
        raise ValueError("empty artifact group")
    return artifacts


def build_iana(source_root: Path, output_root: Path) -> None:
    service_data, service_rows = _source(source_root / SERVICE_SOURCE["file"], SERVICE_SOURCE)
    protocol_data, protocol_rows = _source(source_root / PROTOCOL_SOURCE["file"], PROTOCOL_SOURCE)
    services, excluded_services = _service_records(service_rows)
    protocols = _protocol_records(protocol_rows)
    _new_output_directory(output_root)
    artifacts: list[dict[str, object]] = []
    for band in range(64):
        band_rows = [row for row in services if row["port_start"] // 1024 == band]
        if not band_rows:
            continue
        artifacts.extend(
            _write_shards(
                output_root,
                f"service-ports-{band * 1024:05d}-{min(65_535, band * 1024 + 1023):05d}",
                "iana-service-port-record-v1",
                (_json_bytes(row) for row in band_rows),
            )
        )
    artifacts.extend(
        _write_shards(
            output_root,
            "protocol-numbers",
            "iana-protocol-number-record-v1",
            (_json_bytes(row) for row in protocols),
        )
    )

    def source_receipt(contract: dict[str, object], raw_rows: int) -> dict[str, object]:
        return {
            key: contract[key]
            for key in (
                "id",
                "canonical_url",
                "content_type",
                "last_modified",
                "registry_url",
                "registry_last_updated",
                "retrieved_at",
                "retrieved_at_basis",
                "raw_bytes",
                "raw_sha256",
                "retained_fields",
                "omitted_fields",
            )
        } | {"raw_data_rows": raw_rows, "raw_header": contract["expected_header"]}

    manifest = {
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "bundle_id": "iana-network-reference-20260910",
        "created_from_retrievals_at": "2026-09-10T19:13:32.727Z",
        "license": {
            "id": "CC0-1.0",
            "scope": (
                "IANA service-name/port and protocol-number registry data only; "
                "linked RFC and third-party material excluded"
            ),
            "url": "https://www.iana.org/help/licensing-terms",
        },
        "limits": {
            "max_artifacts": 128,
            "max_line_bytes": 4096,
            "max_protocol_rows": 512,
            "max_shard_bytes": MAX_SHARD_BYTES,
            "max_service_rows": 20_000,
            "max_total_bytes": 4_456_448,
        },
        "normalizer": "iana-network-reference-normalizer-v1",
        "privacy_projection": {
            "service_rows_excluded_without_usable_port_and_transport": excluded_services,
            "source_contact_and_freeform_notes_retained": False,
            "source_row_retained_as_one_based_data_row_ordinal": True,
        },
        "runtime_network_access": False,
        "schema": "iana-network-reference-manifest-v1",
        "sources": [
            source_receipt(SERVICE_SOURCE, len(service_rows)),
            source_receipt(PROTOCOL_SOURCE, len(protocol_rows)),
        ],
        "verification_scope": (
            "Raw-source and derived-artifact digest integrity is pinned; publisher authenticity "
            "was not cryptographically verified."
        ),
        "warning": (
            "Registry assignments are analyst context hints, never proof of an observed service, "
            "traffic safety, malicious intent, or a security verdict."
        ),
        "total_artifact_bytes": sum(item["bytes"] for item in artifacts),
    }
    (output_root / "manifest.json").write_bytes(_json_bytes(manifest))
    assert len(service_data) == SERVICE_SOURCE["raw_bytes"]
    assert len(protocol_data) == PROTOCOL_SOURCE["raw_bytes"]


def build_corpus(output_root: Path) -> None:
    _new_output_directory(output_root)
    scenarios = []
    total_records = 0
    total_bytes = 0
    total_shards = 0
    for definition in _scenario_definitions():
        records = definition["records"]
        data = b"".join(_json_bytes(row) for row in records)
        shard_artifacts = _write_shards(
            output_root,
            str(definition["id"]),
            "synthetic-packet-event-v1",
            (_json_bytes(row) for row in records),
        )
        shards = [
            {
                "bytes": item["bytes"],
                "path": item["path"],
                "records": item["rows"],
                "sha256": item["sha256"],
            }
            for item in shard_artifacts
        ]
        scenarios.append(
            {
                **{key: value for key, value in definition.items() if key != "records"},
                "action_status": "not_attempted",
                "bytes": len(data),
                "count_unit": "event_metadata",
                "quality_label": "synthetic-only",
                "records": len(records),
                "sha256": _digest(data),
                "shards": shards,
            }
        )
        total_records += len(records)
        total_bytes += len(data)
        total_shards += len(shards)
    manifest = {
        "address_sources": [
            {
                "cidrs": ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
                "reference": "RFC 5737",
            },
            {"cidrs": ["2001:db8::/32"], "reference": "RFC 3849"},
        ],
        "calibration": "uncalibrated",
        "corpus_id": "synthetic-scenario-corpus-v1",
        "detector_clock": "2030-01-01T00:00:00.000000Z",
        "detector_profile": {
            "alert_cooldown_seconds": 30,
            "dns_query_length": 50,
            "max_events_per_source_window": 4096,
            "max_tracked_sources": 4096,
            "port_scan_distinct_ports": 20,
            "port_scan_window_seconds": 5,
            "syn_flood_threshold": 100,
            "syn_flood_window_seconds": 10,
        },
        "generated_by": "detector-independent-scenario-generator-v1",
        "limits": {
            "max_line_bytes": 2048,
            "max_scenario_bytes": 2_097_152,
            "max_scenario_records": 5000,
            "max_scenarios": 16,
            "max_shard_bytes": MAX_SHARD_BYTES,
            "max_shards": 64,
            "max_total_bytes": 4_194_304,
            "max_total_records": 10_000,
        },
        "limitations": [
            "Synthetic scenarios do not establish real-world accuracy, prevalence, false-positive rates, or coverage.",
            "Scenario interpretation labels are test context, not evidence available to the detector.",
            "A rule match is a fixed-heuristic finding, not malware attribution or response authorization.",
            "No packet payload, DNS name, real operator telemetry, external alert, flow, or threat indicator is present.",
        ],
        "quality_label": "synthetic-only",
        "runtime_network_access": False,
        "scenarios": scenarios,
        "schema": "synthetic-scenario-corpus-manifest-v1",
        "total_bytes": total_bytes,
        "total_records": total_records,
        "total_shards": total_shards,
    }
    (output_root / "manifest.json").write_bytes(_json_bytes(manifest))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iana-source-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    output_root = args.output_root
    _reject_symlink_components(output_root, "generated output root")
    if output_root.is_symlink() or (output_root.exists() and not output_root.is_dir()):
        raise ValueError("output root must be a real directory")
    output_root.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(output_root, "generated output root")
    with tempfile.TemporaryDirectory(prefix=".reference-build-", dir=output_root) as staging:
        staging_root = Path(staging)
        build_iana(args.iana_source_root, staging_root / "iana-v1")
        build_corpus(staging_root / "corpus-v1")
        _publish_bundle(staging_root / "iana-v1", output_root / "iana-v1")
        _publish_bundle(staging_root / "corpus-v1", output_root / "corpus-v1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
