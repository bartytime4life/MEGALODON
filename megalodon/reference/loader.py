"""Strict, bounded loaders for repository-pinned offline reference assets."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
import hashlib
import ipaddress
from importlib import resources
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

from ..config import DetectionSettings
from ..detector import Detector
from ..models import PacketEvent
from ..validation import safe_text, ValidationError


IANA_MANIFEST_SHA256 = "cb3254221886266c2fc6efe7f458c12cd35b97a1e5fc6cb284bf7b4c9972e6ff"
CORPUS_MANIFEST_SHA256 = "04870e2d602ed4dd8bc4ef36adc61b62f3ed904ba92afea1267620b07c6438be"
IANA_LIMITS = {
    "max_artifacts": 128,
    "max_line_bytes": 4096,
    "max_protocol_rows": 512,
    "max_shard_bytes": 76 * 1024,
    "max_service_rows": 20_000,
    "max_total_bytes": 4_456_448,
}
CORPUS_LIMITS = {
    "max_line_bytes": 2048,
    "max_scenario_bytes": 2_097_152,
    "max_scenario_records": 5000,
    "max_scenarios": 16,
    "max_shard_bytes": 76 * 1024,
    "max_shards": 64,
    "max_total_bytes": 4_194_304,
    "max_total_records": 10_000,
}
RULES = ("DNS_TUNNELING", "PORT_SCAN", "SYN_FLOOD")
TRANSPORTS = frozenset({"tcp", "udp", "sctp", "dccp"})
DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)
_HASH = re.compile(r"[0-9a-f]{64}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?")
_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z"
)
_SCENARIO_ID = re.compile(r"[a-z][a-z0-9-]{0,62}-v[0-9]")
_SERVICE_SHARD = re.compile(
    r"service-ports-([0-9]{5})-([0-9]{5})\.part-([0-9]{3})\.jsonl"
)
_EVENT_FIELDS = {
    "byte_count",
    "dns_query_length",
    "dst_ip",
    "dst_port",
    "interface",
    "metadata",
    "observed_at",
    "protocol",
    "src_ip",
    "src_port",
    "tcp_flags",
}


class ReferenceDataError(ValueError):
    """A fixed diagnostic that never includes reference data or local paths."""


def _fail(code: str) -> None:
    raise ReferenceDataError(f"REFERENCE_DATA:{code}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_resource(parts: tuple[str, ...], maximum: int) -> bytes:
    node = resources.files("megalodon.reference")
    for part in parts:
        if not isinstance(part, str) or not part or "/" in part or "\\" in part:
            _fail("RESOURCE_NAME")
        node = node.joinpath(part)
    try:
        with node.open("rb") as stream:
            data = stream.read(maximum + 1)
    except (FileNotFoundError, IsADirectoryError, OSError):
        _fail("RESOURCE_IO")
    if len(data) > maximum:
        _fail("RESOURCE_LIMIT")
    return data


def _resource_names(directory: str) -> set[str]:
    node = resources.files("megalodon.reference").joinpath(directory)
    try:
        return {child.name for child in node.iterdir() if child.is_file()}
    except (FileNotFoundError, NotADirectoryError, OSError):
        _fail("RESOURCE_IO")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("DUPLICATE_KEY")
        result[key] = value
    return result


def _integer(value: str) -> int:
    if len(value.lstrip("-")) > 20:
        _fail("JSON_NUMBER")
    return int(value)


def _reject_number(_: str) -> None:
    _fail("JSON_NUMBER")


def _json(data: bytes, *, line: bool = False) -> object:
    if line and (not data or b"\n" in data or b"\r" in data):
        _fail("FRAMING")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        _fail("ENCODING")
    try:
        return json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except ReferenceDataError:
        raise
    except (json.JSONDecodeError, RecursionError):
        _fail("JSON")


def _mapping(value: object, fields: set[str], code: str = "SCHEMA") -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(code)
    return value


def _list(value: object, maximum: int, code: str = "SCHEMA") -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        _fail(code)
    return value


def _uint(value: object, maximum: int, code: str = "SCHEMA") -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        _fail(code)
    return value


def _string(value: object, maximum: int, code: str = "SCHEMA") -> str:
    try:
        result = safe_text(value, "reference field", maximum)
    except ValidationError:
        _fail(code)
    if not result:
        _fail(code)
    return result


def _optional_string(value: object, maximum: int, code: str = "SCHEMA") -> str | None:
    if value is None:
        return None
    return _string(value, maximum, code)


def _date_value(value: object) -> str | None:
    result = _optional_string(value, 10)
    if result is None:
        return None
    if not _DATE.fullmatch(result):
        _fail("IANA_RECORD")
    try:
        date.fromisoformat(result if len(result) == 10 else result + "-01")
    except ValueError:
        _fail("IANA_RECORD")
    return result


def _lines(data: bytes, maximum: int) -> list[bytes]:
    if data and not data.endswith(b"\n"):
        _fail("FRAMING")
    result = data.splitlines()
    if any(not line or len(line) > maximum for line in result):
        _fail("FRAMING")
    return result


@dataclass(frozen=True)
class ServicePortRecord:
    description: str | None
    modification_date: str | None
    port_end: int
    port_start: int
    record_kind: str
    registration_date: str | None
    service_name: str | None
    source_row: int
    transport: str

    def public(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ProtocolNumberRecord:
    decimal_end: int
    decimal_start: int
    ipv6_extension_header: str
    keyword: str | None
    protocol_name: str | None
    record_kind: str
    source_row: int

    def public(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IanaBundle:
    bundle_id: str
    manifest_sha256: str
    artifact_count: int
    total_artifact_bytes: int
    license_id: str
    services_last_updated: str
    protocols_last_updated: str
    warning: str
    verification_scope: str
    services: tuple[ServicePortRecord, ...]
    protocols: tuple[ProtocolNumberRecord, ...]

    def summary(self) -> dict[str, object]:
        return {
            "schema": "iana-network-reference-summary-v1",
            "bundle_id": self.bundle_id,
            "manifest_sha256": self.manifest_sha256,
            "artifact_count": self.artifact_count,
            "artifact_bytes": self.total_artifact_bytes,
            "license": self.license_id,
            "runtime_network_access": False,
            "service_records": len(self.services),
            "protocol_records": len(self.protocols),
            "services_last_updated": self.services_last_updated,
            "protocols_last_updated": self.protocols_last_updated,
            "verification_scope": self.verification_scope,
            "warning": self.warning,
            "network_access_performed": False,
            "persistence_status": "not_attempted",
            "action_status": "not_attempted",
        }


def _iana_manifest(data: bytes) -> dict[str, Any]:
    if _sha256(data) != IANA_MANIFEST_SHA256:
        _fail("MANIFEST_INTEGRITY")
    value = _mapping(
        _json(data),
        {
            "artifact_count",
            "artifacts",
            "bundle_id",
            "created_from_retrievals_at",
            "license",
            "limits",
            "normalizer",
            "privacy_projection",
            "runtime_network_access",
            "schema",
            "sources",
            "total_artifact_bytes",
            "verification_scope",
            "warning",
        },
        "IANA_MANIFEST",
    )
    if (
        value["schema"] != "iana-network-reference-manifest-v1"
        or value["bundle_id"] != "iana-network-reference-20260910"
        or value["normalizer"] != "iana-network-reference-normalizer-v1"
        or value["runtime_network_access"] is not False
        or value["limits"] != IANA_LIMITS
    ):
        _fail("IANA_MANIFEST")
    license_value = _mapping(value["license"], {"id", "scope", "url"}, "IANA_MANIFEST")
    if (
        license_value["id"] != "CC0-1.0"
        or license_value["url"] != "https://www.iana.org/help/licensing-terms"
    ):
        _fail("IANA_MANIFEST")
    privacy = _mapping(
        value["privacy_projection"],
        {
            "service_rows_excluded_without_usable_port_and_transport",
            "source_contact_and_freeform_notes_retained",
            "source_row_retained_as_one_based_data_row_ordinal",
        },
        "IANA_MANIFEST",
    )
    _uint(privacy["service_rows_excluded_without_usable_port_and_transport"], 20_000)
    if (
        privacy["source_contact_and_freeform_notes_retained"] is not False
        or privacy["source_row_retained_as_one_based_data_row_ordinal"] is not True
    ):
        _fail("IANA_MANIFEST")
    artifacts = _list(value["artifacts"], IANA_LIMITS["max_artifacts"], "IANA_MANIFEST")
    artifact_count = _uint(value["artifact_count"], IANA_LIMITS["max_artifacts"], "IANA_MANIFEST")
    if not artifacts or artifact_count != len(artifacts):
        _fail("IANA_MANIFEST")
    names: set[str] = set()
    service_paths: list[str] = []
    service_parts: dict[tuple[int, int], list[int]] = {}
    protocol_artifacts = 0
    total_artifact_bytes = 0
    total_service_rows = 0
    total_protocol_rows = 0
    declared_total_bytes = _uint(
        value["total_artifact_bytes"], IANA_LIMITS["max_total_bytes"], "IANA_MANIFEST"
    )
    for artifact in artifacts:
        item = _mapping(artifact, {"bytes", "path", "rows", "schema", "sha256"}, "IANA_MANIFEST")
        path = _string(item["path"], 96, "IANA_MANIFEST")
        if path in names:
            _fail("IANA_MANIFEST")
        names.add(path)
        size = _uint(item["bytes"], IANA_LIMITS["max_shard_bytes"], "IANA_MANIFEST")
        rows = _uint(item["rows"], IANA_LIMITS["max_service_rows"], "IANA_MANIFEST")
        if not size or not rows:
            _fail("IANA_MANIFEST")
        total_artifact_bytes += size
        if not isinstance(item["sha256"], str) or not _HASH.fullmatch(item["sha256"]):
            _fail("IANA_MANIFEST")
        match = _SERVICE_SHARD.fullmatch(path)
        if item["schema"] == "iana-service-port-record-v1" and match is not None:
            start, end, part = (int(group) for group in match.groups())
            if start % 1024 or end != min(65_535, start + 1023) or start > end:
                _fail("IANA_MANIFEST")
            service_paths.append(path)
            service_parts.setdefault((start, end), []).append(part)
            total_service_rows += rows
        elif (
            item["schema"] == "iana-protocol-number-record-v1"
            and path == "protocol-numbers.part-001.jsonl"
        ):
            protocol_artifacts += 1
            total_protocol_rows += rows
        else:
            _fail("IANA_MANIFEST")
    if (
        protocol_artifacts != 1
        or not service_paths
        or service_paths != sorted(service_paths)
        or any(parts != list(range(1, len(parts) + 1)) for parts in service_parts.values())
        or total_service_rows > IANA_LIMITS["max_service_rows"]
        or total_protocol_rows > IANA_LIMITS["max_protocol_rows"]
        or total_artifact_bytes != declared_total_bytes
        or total_artifact_bytes > IANA_LIMITS["max_total_bytes"]
    ):
        _fail("IANA_MANIFEST")
    sources = _list(value["sources"], 2, "IANA_MANIFEST")
    if len(sources) != 2:
        _fail("IANA_MANIFEST")
    expected_sources = {
        "iana-service-names-port-numbers": (
            "9777be6d2451ab61ac3c64443b0cfb968bbdeddea3cc5e640eb81f3ec045b7a4",
            "2026-09-07",
            1_157_044,
            14_535,
        ),
        "iana-protocol-numbers": (
            "e704ee14e69347681b3a6271af02195a9741236074fc311449ebb032101bdf2c",
            "2026-03-09",
            9_230,
            152,
        ),
    }
    source_ids: set[str] = set()
    for source in sources:
        item = _mapping(
            source,
            {
                "canonical_url",
                "content_type",
                "id",
                "last_modified",
                "omitted_fields",
                "raw_bytes",
                "raw_data_rows",
                "raw_header",
                "raw_sha256",
                "registry_last_updated",
                "registry_url",
                "retained_fields",
                "retrieved_at",
                "retrieved_at_basis",
            },
            "IANA_MANIFEST",
        )
        source_id = _string(item["id"], 64, "IANA_MANIFEST")
        if source_id in source_ids:
            _fail("IANA_MANIFEST")
        source_ids.add(source_id)
        if expected_sources.get(source_id) != (
            item["raw_sha256"],
            item["registry_last_updated"],
            item["raw_bytes"],
            item["raw_data_rows"],
        ):
            _fail("IANA_MANIFEST")
        _uint(item["raw_bytes"], 2_000_000, "IANA_MANIFEST")
        _uint(item["raw_data_rows"], 20_000, "IANA_MANIFEST")
        for field in ("raw_header", "retained_fields", "omitted_fields"):
            entries = _list(item[field], 12, "IANA_MANIFEST")
            if not entries or any(not isinstance(entry, str) or not entry for entry in entries):
                _fail("IANA_MANIFEST")
        if (
            item["content_type"] != "text/csv; charset=UTF-8; header=present"
            or item["retrieved_at_basis"]
            != "connector_receipt_utc_not_filesystem_metadata"
        ):
            _fail("IANA_MANIFEST")
        for field in (
            "canonical_url",
            "last_modified",
            "registry_url",
            "retrieved_at",
            "retrieved_at_basis",
        ):
            _string(item[field], 256, "IANA_MANIFEST")
    if source_ids != set(expected_sources):
        _fail("IANA_MANIFEST")
    _string(value["warning"], 512, "IANA_MANIFEST")
    _string(value["verification_scope"], 512, "IANA_MANIFEST")
    return value


def _service_record(value: object) -> ServicePortRecord:
    item = _mapping(
        value,
        {
            "description",
            "modification_date",
            "port_end",
            "port_start",
            "record_kind",
            "registration_date",
            "service_name",
            "source_row",
            "transport",
        },
        "IANA_RECORD",
    )
    record_kind = item["record_kind"]
    transport = item["transport"]
    if (
        not isinstance(record_kind, str)
        or record_kind not in {"named", "reserved", "unassigned", "unnamed"}
        or not isinstance(transport, str)
        or transport not in TRANSPORTS
    ):
        _fail("IANA_RECORD")
    start = _uint(item["port_start"], 65_535, "IANA_RECORD")
    end = _uint(item["port_end"], 65_535, "IANA_RECORD")
    if start > end:
        _fail("IANA_RECORD")
    service = _optional_string(item["service_name"], 64, "IANA_RECORD")
    description = _optional_string(item["description"], 512, "IANA_RECORD")
    source_row = _uint(item["source_row"], 14_535, "IANA_RECORD")
    if (record_kind == "named") != (service is not None):
        _fail("IANA_RECORD")
    if source_row == 0 or (record_kind != "named" and description is None):
        _fail("IANA_RECORD")
    return ServicePortRecord(
        description=description,
        modification_date=_date_value(item["modification_date"]),
        port_end=end,
        port_start=start,
        record_kind=record_kind,
        registration_date=_date_value(item["registration_date"]),
        service_name=service,
        source_row=source_row,
        transport=transport,
    )


def _protocol_record(value: object) -> ProtocolNumberRecord:
    item = _mapping(
        value,
        {
            "decimal_end",
            "decimal_start",
            "ipv6_extension_header",
            "keyword",
            "protocol_name",
            "record_kind",
            "source_row",
        },
        "IANA_RECORD",
    )
    record_kind = item["record_kind"]
    marker = item["ipv6_extension_header"]
    if (
        not isinstance(record_kind, str)
        or record_kind
        not in {"named", "reserved", "unassigned", "unnamed", "experimental"}
        or not isinstance(marker, str)
        or marker not in {"yes", "no", "unspecified"}
    ):
        _fail("IANA_RECORD")
    start = _uint(item["decimal_start"], 255, "IANA_RECORD")
    end = _uint(item["decimal_end"], 255, "IANA_RECORD")
    keyword = _optional_string(item["keyword"], 64, "IANA_RECORD")
    protocol_name = _optional_string(item["protocol_name"], 128, "IANA_RECORD")
    source_row = _uint(item["source_row"], 152, "IANA_RECORD")
    if (
        start > end
        or source_row == 0
        or (record_kind == "unnamed") != (keyword is None and protocol_name is None)
    ):
        _fail("IANA_RECORD")
    return ProtocolNumberRecord(
        decimal_end=end,
        decimal_start=start,
        ipv6_extension_header=marker,
        keyword=keyword,
        protocol_name=protocol_name,
        record_kind=record_kind,
        source_row=source_row,
    )


def _iana_artifact(metadata: dict[str, Any]) -> bytes:
    data = _read_resource(
        ("iana-v1", metadata["path"]), IANA_LIMITS["max_shard_bytes"]
    )
    if len(data) != metadata["bytes"] or _sha256(data) != metadata["sha256"]:
        _fail("ARTIFACT_INTEGRITY")
    return data


def load_iana() -> IanaBundle:
    manifest_data = _read_resource(("iana-v1", "manifest.json"), 32 * 1024)
    manifest = _iana_manifest(manifest_data)
    expected_files = {"manifest.json", *(item["path"] for item in manifest["artifacts"])}
    if _resource_names("iana-v1") != expected_files:
        _fail("RESOURCE_SET")
    verified_artifacts = [(item, _iana_artifact(item)) for item in manifest["artifacts"]]
    service_records: list[ServicePortRecord] = []
    protocol_records: list[ProtocolNumberRecord] = []
    for metadata, data in verified_artifacts:
        lines = _lines(data, IANA_LIMITS["max_line_bytes"])
        if len(lines) != metadata["rows"]:
            _fail("ROW_COUNT")
        if metadata["schema"] == "iana-service-port-record-v1":
            match = _SERVICE_SHARD.fullmatch(metadata["path"])
            if match is None:
                _fail("IANA_MANIFEST")
            band_start, band_end = (int(group) for group in match.groups()[:2])
            for line in lines:
                record = _service_record(_json(line, line=True))
                if not band_start <= record.port_start <= band_end:
                    _fail("IANA_RECORD")
                service_records.append(record)
        else:
            protocol_records.extend(
                _protocol_record(_json(line, line=True)) for line in lines
            )
    services = tuple(service_records)
    protocols = tuple(protocol_records)
    service_rows = sum(
        item["rows"]
        for item in manifest["artifacts"]
        if item["schema"] == "iana-service-port-record-v1"
    )
    protocol_rows = sum(
        item["rows"]
        for item in manifest["artifacts"]
        if item["schema"] == "iana-protocol-number-record-v1"
    )
    if len(services) != service_rows or len(protocols) != protocol_rows:
        _fail("ROW_COUNT")
    service_keys = [
        (
            item.port_start,
            item.port_end,
            item.transport,
            item.service_name or "",
            item.description or "",
            item.registration_date or "",
            item.modification_date or "",
            item.source_row,
        )
        for item in services
    ]
    protocol_keys = [
        (
            item.decimal_start,
            item.decimal_end,
            item.keyword or "",
            item.protocol_name or "",
            item.source_row,
        )
        for item in protocols
    ]
    if service_keys != sorted(service_keys) or len({item.source_row for item in services}) != len(
        services
    ):
        _fail("ORDER_OR_DUPLICATE")
    if protocol_keys != sorted(protocol_keys) or len(
        {item.source_row for item in protocols}
    ) != len(protocols):
        _fail("ORDER_OR_DUPLICATE")
    sources = {item["id"]: item for item in manifest["sources"]}
    return IanaBundle(
        bundle_id=manifest["bundle_id"],
        manifest_sha256=IANA_MANIFEST_SHA256,
        artifact_count=manifest["artifact_count"],
        total_artifact_bytes=manifest["total_artifact_bytes"],
        license_id=manifest["license"]["id"],
        services_last_updated=sources["iana-service-names-port-numbers"]["registry_last_updated"],
        protocols_last_updated=sources["iana-protocol-numbers"]["registry_last_updated"],
        warning=manifest["warning"],
        verification_scope=manifest["verification_scope"],
        services=services,
        protocols=protocols,
    )


def lookup_port(transport: str, port: int) -> dict[str, object]:
    if not isinstance(transport, str) or transport.lower() not in TRANSPORTS:
        _fail("LOOKUP_ARGUMENT")
    if type(port) is not int or not 0 <= port <= 65_535:
        _fail("LOOKUP_ARGUMENT")
    bundle = load_iana()
    normalized = transport.lower()
    all_matches = [
        item
        for item in bundle.services
        if item.transport == normalized and item.port_start <= port <= item.port_end
    ]
    matches = all_matches[:8]
    return {
        "schema": "iana-service-port-hint-v1",
        "bundle_id": bundle.bundle_id,
        "transport": normalized,
        "port": port,
        "match_count": len(all_matches),
        "matches": [item.public() for item in matches],
        "truncated": len(all_matches) > len(matches),
        "action_status": "not_attempted",
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "warning": bundle.warning,
    }


def lookup_protocol(number: int) -> dict[str, object]:
    if type(number) is not int or not 0 <= number <= 255:
        _fail("LOOKUP_ARGUMENT")
    bundle = load_iana()
    all_matches = [
        item
        for item in bundle.protocols
        if item.decimal_start <= number <= item.decimal_end
    ]
    matches = all_matches[:4]
    return {
        "schema": "iana-protocol-number-hint-v1",
        "bundle_id": bundle.bundle_id,
        "number": number,
        "match_count": len(all_matches),
        "matches": [item.public() for item in matches],
        "truncated": len(all_matches) > len(matches),
        "action_status": "not_attempted",
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "warning": bundle.warning,
    }


@dataclass(frozen=True)
class CorpusScenario:
    scenario_id: str
    description: str
    interpretation: str
    records: tuple[PacketEvent, ...]
    expected: Mapping[str, int]
    artifact_sha256: str
    artifact_bytes: int


@dataclass(frozen=True)
class CorpusBundle:
    corpus_id: str
    manifest_sha256: str
    detector_clock: datetime
    detector_profile: DetectionSettings
    quality_label: str
    calibration: str
    scenarios: tuple[CorpusScenario, ...]
    limitations: tuple[str, ...]
    total_records: int
    total_bytes: int
    total_shards: int


def _corpus_manifest(data: bytes) -> dict[str, Any]:
    if _sha256(data) != CORPUS_MANIFEST_SHA256:
        _fail("MANIFEST_INTEGRITY")
    value = _mapping(
        _json(data),
        {
            "address_sources",
            "calibration",
            "corpus_id",
            "detector_clock",
            "detector_profile",
            "generated_by",
            "limitations",
            "limits",
            "quality_label",
            "runtime_network_access",
            "scenarios",
            "schema",
            "total_bytes",
            "total_records",
            "total_shards",
        },
        "CORPUS_MANIFEST",
    )
    if (
        value["schema"] != "synthetic-scenario-corpus-manifest-v1"
        or value["corpus_id"] != "synthetic-scenario-corpus-v1"
        or value["generated_by"] != "detector-independent-scenario-generator-v1"
        or value["quality_label"] != "synthetic-only"
        or value["calibration"] != "uncalibrated"
        or value["runtime_network_access"] is not False
        or value["limits"] != CORPUS_LIMITS
        or value["detector_profile"] != asdict(DetectionSettings())
    ):
        _fail("CORPUS_MANIFEST")
    if value["address_sources"] != [
        {
            "cidrs": ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
            "reference": "RFC 5737",
        },
        {"cidrs": ["2001:db8::/32"], "reference": "RFC 3849"},
    ]:
        _fail("CORPUS_MANIFEST")
    stamp = value["detector_clock"]
    if not isinstance(stamp, str) or not _STAMP.fullmatch(stamp):
        _fail("CORPUS_MANIFEST")
    try:
        clock = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        _fail("CORPUS_MANIFEST")
    if clock.tzinfo != timezone.utc:
        _fail("CORPUS_MANIFEST")
    _uint(value["total_bytes"], CORPUS_LIMITS["max_total_bytes"], "CORPUS_MANIFEST")
    _uint(value["total_records"], CORPUS_LIMITS["max_total_records"], "CORPUS_MANIFEST")
    _uint(value["total_shards"], CORPUS_LIMITS["max_shards"], "CORPUS_MANIFEST")
    limitations = _list(value["limitations"], 8, "CORPUS_MANIFEST")
    if not limitations or any(not isinstance(item, str) or not 1 <= len(item) <= 512 for item in limitations):
        _fail("CORPUS_MANIFEST")
    scenarios = _list(value["scenarios"], CORPUS_LIMITS["max_scenarios"], "CORPUS_MANIFEST")
    if not scenarios:
        _fail("CORPUS_MANIFEST")
    return value


def _documentation_address(value: str) -> ipaddress._BaseAddress:
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        _fail("CORPUS_EVENT")
    if str(address) != value or not any(address in network for network in DOCUMENTATION_NETWORKS):
        _fail("CORPUS_ADDRESS")
    return address


def _corpus_event(value: object) -> PacketEvent:
    item = _mapping(value, _EVENT_FIELDS, "CORPUS_EVENT")
    flags = item["tcp_flags"]
    if (
        item["interface"] != "synthetic-corpus-v1"
        or item["metadata"] != {}
        or not isinstance(item["protocol"], str)
        or item["protocol"] not in {"TCP", "UDP", "DNS"}
        or not isinstance(flags, list)
        or len(flags) > 8
        or any(not isinstance(flag, str) for flag in flags)
        or flags != sorted(set(flags))
        or not isinstance(item["observed_at"], str)
        or not _STAMP.fullmatch(item["observed_at"])
    ):
        _fail("CORPUS_EVENT")
    source = _documentation_address(item["src_ip"])
    destination = _documentation_address(item["dst_ip"])
    if source.version != destination.version:
        _fail("CORPUS_ADDRESS")
    try:
        event = PacketEvent.from_mapping(item)
    except (KeyError, TypeError, ValueError):
        _fail("CORPUS_EVENT")
    if event.byte_count <= 0 or event.observed_at.tzinfo != timezone.utc:
        _fail("CORPUS_EVENT")
    return event


def load_corpus() -> CorpusBundle:
    manifest_data = _read_resource(("corpus-v1", "manifest.json"), 64 * 1024)
    manifest = _corpus_manifest(manifest_data)
    declared_names = {"manifest.json"}
    scenario_ids: set[str] = set()
    scenarios: list[CorpusScenario] = []
    total_records = 0
    total_bytes = 0
    total_shards = 0
    for raw in manifest["scenarios"]:
        item = _mapping(
            raw,
            {
                "action_status",
                "bytes",
                "count_unit",
                "description",
                "expected",
                "id",
                "interpretation",
                "quality_label",
                "records",
                "sha256",
                "shards",
            },
            "CORPUS_MANIFEST",
        )
        scenario_id = item["id"]
        if (
            not isinstance(scenario_id, str)
            or not _SCENARIO_ID.fullmatch(scenario_id)
            or scenario_id in scenario_ids
            or item["quality_label"] != "synthetic-only"
            or item["count_unit"] != "event_metadata"
            or item["action_status"] != "not_attempted"
            or not isinstance(item["sha256"], str)
            or not _HASH.fullmatch(item["sha256"])
        ):
            _fail("CORPUS_MANIFEST")
        expected = _mapping(item["expected"], set(RULES), "CORPUS_MANIFEST")
        expected_counts = {
            rule: _uint(expected[rule], CORPUS_LIMITS["max_scenario_records"], "CORPUS_MANIFEST")
            for rule in RULES
        }
        declared_records = _uint(
            item["records"], CORPUS_LIMITS["max_scenario_records"], "CORPUS_MANIFEST"
        )
        declared_bytes = _uint(
            item["bytes"], CORPUS_LIMITS["max_scenario_bytes"], "CORPUS_MANIFEST"
        )
        if declared_records == 0 or declared_bytes == 0 or sum(expected_counts.values()) > declared_records:
            _fail("CORPUS_MANIFEST")
        description = _string(item["description"], 512, "CORPUS_MANIFEST")
        interpretation = _string(item["interpretation"], 512, "CORPUS_MANIFEST")
        raw_shards = _list(item["shards"], CORPUS_LIMITS["max_shards"], "CORPUS_MANIFEST")
        if not raw_shards or total_shards + len(raw_shards) > CORPUS_LIMITS["max_shards"]:
            _fail("CORPUS_MANIFEST")
        verified_parts: list[bytes] = []
        shard_records = 0
        shard_bytes = 0
        for index, raw_shard in enumerate(raw_shards, start=1):
            shard = _mapping(
                raw_shard, {"bytes", "path", "records", "sha256"}, "CORPUS_MANIFEST"
            )
            filename = _string(shard["path"], 96, "CORPUS_MANIFEST")
            if filename != f"{scenario_id}.part-{index:03d}.jsonl":
                _fail("CORPUS_MANIFEST")
            size = _uint(
                shard["bytes"], CORPUS_LIMITS["max_shard_bytes"], "CORPUS_MANIFEST"
            )
            count = _uint(
                shard["records"], CORPUS_LIMITS["max_scenario_records"], "CORPUS_MANIFEST"
            )
            if (
                not size
                or not count
                or not isinstance(shard["sha256"], str)
                or not _HASH.fullmatch(shard["sha256"])
                or filename in declared_names
            ):
                _fail("CORPUS_MANIFEST")
            part = _read_resource(
                ("corpus-v1", filename), CORPUS_LIMITS["max_shard_bytes"]
            )
            if len(part) != size or _sha256(part) != shard["sha256"]:
                _fail("ARTIFACT_INTEGRITY")
            if len(_lines(part, CORPUS_LIMITS["max_line_bytes"])) != count:
                _fail("ROW_COUNT")
            declared_names.add(filename)
            verified_parts.append(part)
            shard_bytes += size
            shard_records += count
        data = b"".join(verified_parts)
        if (
            shard_bytes != declared_bytes
            or shard_records != declared_records
            or len(data) != declared_bytes
            or _sha256(data) != item["sha256"]
        ):
            _fail("ARTIFACT_INTEGRITY")
        lines = _lines(data, CORPUS_LIMITS["max_line_bytes"])
        if len(lines) != declared_records:
            _fail("ROW_COUNT")
        records = tuple(_corpus_event(_json(line, line=True)) for line in lines)
        previous: datetime | None = None
        source_times: dict[str, datetime] = {}
        for event in records:
            if previous is not None and event.observed_at < previous:
                _fail("CORPUS_ORDER")
            if event.observed_at < source_times.get(event.src_ip, event.observed_at):
                _fail("CORPUS_ORDER")
            previous = event.observed_at
            source_times[event.src_ip] = event.observed_at
        scenario_ids.add(scenario_id)
        scenarios.append(
            CorpusScenario(
                scenario_id=scenario_id,
                description=description,
                interpretation=interpretation,
                records=records,
                expected=MappingProxyType(expected_counts),
                artifact_sha256=item["sha256"],
                artifact_bytes=declared_bytes,
            )
        )
        total_records += declared_records
        total_bytes += declared_bytes
        total_shards += len(raw_shards)
    if (
        total_records != manifest["total_records"]
        or total_bytes != manifest["total_bytes"]
        or total_shards != manifest["total_shards"]
        or _resource_names("corpus-v1") != declared_names
    ):
        _fail("CORPUS_TOTAL")
    detector_profile = DetectionSettings(**manifest["detector_profile"])
    return CorpusBundle(
        corpus_id=manifest["corpus_id"],
        manifest_sha256=CORPUS_MANIFEST_SHA256,
        detector_clock=datetime.fromisoformat(manifest["detector_clock"].replace("Z", "+00:00")),
        detector_profile=detector_profile,
        quality_label=manifest["quality_label"],
        calibration=manifest["calibration"],
        scenarios=tuple(scenarios),
        limitations=tuple(manifest["limitations"]),
        total_records=total_records,
        total_bytes=total_bytes,
        total_shards=total_shards,
    )


def evaluate_corpus(scenario_id: str | None = None) -> dict[str, object]:
    """Validate every corpus byte before running the detector in memory."""
    bundle = load_corpus()
    selected = bundle.scenarios
    if scenario_id is not None:
        selected = tuple(item for item in selected if item.scenario_id == scenario_id)
        if len(selected) != 1:
            _fail("UNKNOWN_SCENARIO")
    outcomes = []
    all_match = True
    for scenario in selected:
        detector = Detector(bundle.detector_profile, clock=lambda: bundle.detector_clock)
        observed_counter: Counter[str] = Counter()
        for event in scenario.records:
            for detection in detector.analyze(event):
                observed_counter[detection.rule_id] += 1
        observed = {rule: observed_counter[rule] for rule in RULES}
        expected = dict(scenario.expected)
        matches = observed == expected
        all_match = all_match and matches
        outcomes.append(
            {
                "scenario_id": scenario.scenario_id,
                "records": len(scenario.records),
                "artifact_sha256": scenario.artifact_sha256,
                "description": scenario.description,
                "interpretation": scenario.interpretation,
                "expected": expected,
                "observed": observed,
                "matches_expected": matches,
                "quality_label": "synthetic-only",
                "calibration": "uncalibrated",
                "action_status": "not_attempted",
            }
        )
    return {
        "schema": "synthetic-corpus-evaluation-v1",
        "corpus_id": bundle.corpus_id,
        "manifest_sha256": bundle.manifest_sha256,
        "quality_label": bundle.quality_label,
        "calibration": bundle.calibration,
        "validated_total_records": bundle.total_records,
        "validated_total_bytes": bundle.total_bytes,
        "validated_total_shards": bundle.total_shards,
        "evaluated_scenarios": len(outcomes),
        "all_match": all_match,
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
        "scenarios": outcomes,
        "limitations": list(bundle.limitations),
    }
