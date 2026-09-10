"""Pinned reference data stays closed, deterministic, bounded, and read-only."""

from __future__ import annotations

import ast
from collections import defaultdict
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest

from megalodon import firewall, models, service, storage
from megalodon import evaluation
from megalodon.reference import (
    ReferenceDataError,
    ServicePortRecord,
    evaluate_corpus,
    load_corpus,
    load_iana,
    lookup_port,
    lookup_protocol,
)
from megalodon.reference import loader


REFERENCE_ROOT = Path(loader.__file__).resolve().parent
GENERATOR = REFERENCE_ROOT.parents[1] / "tools" / "build_reference_assets.py"
MAX_GENERATED_TEXT_BYTES = 80 * 1024


@pytest.fixture(scope="module")
def iana_bundle():
    return load_iana()


@pytest.fixture(scope="module")
def corpus_bundle():
    return load_corpus()


def _manifest(directory: str) -> dict[str, object]:
    return json.loads((REFERENCE_ROOT / directory / "manifest.json").read_bytes())


def _canonical_json(value: object) -> bytes:
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


def _mutated(data: bytes) -> bytes:
    assert data
    replacement = b"[" if data[:1] != b"[" else b"{"
    return replacement + data[1:]


def _valid_event() -> dict[str, object]:
    return {
        "byte_count": 60,
        "dns_query_length": None,
        "dst_ip": "198.51.100.2",
        "dst_port": 443,
        "interface": "synthetic-corpus-v1",
        "metadata": {},
        "observed_at": "2020-01-01T00:00:00.000000Z",
        "protocol": "TCP",
        "src_ip": "192.0.2.1",
        "src_port": 40000,
        "tcp_flags": ["SYN"],
    }


def _load_generator():
    specification = importlib.util.spec_from_file_location(
        "megalodon_build_reference_assets_test", GENERATOR
    )
    assert specification is not None and specification.loader is not None
    generator = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(generator)
    return generator


def test_iana_exact_counts_source_receipts_and_source_rows(iana_bundle):
    summary = iana_bundle.summary()
    assert summary["schema"] == "iana-network-reference-summary-v1"
    assert summary["service_records"] == len(iana_bundle.services) == 12_577
    assert summary["protocol_records"] == len(iana_bundle.protocols) == 152
    assert summary["runtime_network_access"] is False
    assert summary["network_access_performed"] is False
    assert summary["persistence_status"] == "not_attempted"
    assert summary["action_status"] == "not_attempted"
    assert iana_bundle.license_id == "CC0-1.0"
    assert iana_bundle.services_last_updated == "2026-09-07"
    assert iana_bundle.protocols_last_updated == "2026-03-09"
    assert len({record.source_row for record in iana_bundle.services}) == 12_577
    assert len({record.source_row for record in iana_bundle.protocols}) == 152

    manifest = _manifest("iana-v1")
    sources = {source["id"]: source for source in manifest["sources"]}
    assert (
        sources["iana-service-names-port-numbers"]["raw_data_rows"],
        sources["iana-service-names-port-numbers"]["raw_bytes"],
        sources["iana-service-names-port-numbers"]["raw_sha256"],
    ) == (
        14_535,
        1_157_044,
        "9777be6d2451ab61ac3c64443b0cfb968bbdeddea3cc5e640eb81f3ec045b7a4",
    )
    assert (
        sources["iana-protocol-numbers"]["raw_data_rows"],
        sources["iana-protocol-numbers"]["raw_bytes"],
        sources["iana-protocol-numbers"]["raw_sha256"],
    ) == (
        152,
        9_230,
        "e704ee14e69347681b3a6271af02195a9741236074fc311449ebb032101bdf2c",
    )
    assert all(
        source["retrieved_at_basis"]
        == "connector_receipt_utc_not_filesystem_metadata"
        for source in sources.values()
    )


def test_known_iana_port_and_protocol_semantics_preserve_source_rows():
    https = lookup_port("TCP", 443)
    assert https["match_count"] == 1
    assert https["truncated"] is False
    assert https["action_status"] == "not_attempted"
    assert https["persistence_status"] == "not_attempted"
    assert https["network_access_performed"] is False
    assert https["matches"] == [
        {
            "description": "http protocol over TLS/SSL",
            "modification_date": "2021-10-01",
            "port_end": 443,
            "port_start": 443,
            "record_kind": "named",
            "registration_date": None,
            "service_name": "https",
            "source_row": 790,
            "transport": "tcp",
        }
    ]

    tcp = lookup_protocol(6)
    assert tcp["matches"] == [
        {
            "decimal_end": 6,
            "decimal_start": 6,
            "ipv6_extension_header": "unspecified",
            "keyword": "TCP",
            "protocol_name": "Transmission Control",
            "record_kind": "named",
            "source_row": 7,
        }
    ]
    experimental = lookup_protocol(253)
    assert experimental["match_count"] == 1
    assert experimental["matches"][0] == {
        "decimal_end": 253,
        "decimal_start": 253,
        "ipv6_extension_header": "yes",
        "keyword": None,
        "protocol_name": "Use for experimentation and testing",
        "record_kind": "experimental",
        "source_row": 150,
    }
    assert experimental["matches"][0]["record_kind"] != "unassigned"


def test_duplicate_port_transport_hints_are_not_collapsed(iana_bundle):
    matches = [
        record
        for record in iana_bundle.services
        if record.port_start == record.port_end == 80 and record.transport == "tcp"
    ]
    assert [(record.service_name, record.source_row) for record in matches] == [
        ("http", 171),
        ("www", 173),
        ("www-http", 175),
    ]
    result = lookup_port("tcp", 80)
    assert result["match_count"] == 3
    assert [match["source_row"] for match in result["matches"]] == [171, 173, 175]

    grouped: dict[tuple[int, int, str], list[int]] = defaultdict(list)
    for record in iana_bundle.services:
        grouped[(record.port_start, record.port_end, record.transport)].append(
            record.source_row
        )
    assert sum(len(rows) > 1 for rows in grouped.values()) == 226


def test_lookup_result_is_bounded_without_collapsing_total(monkeypatch):
    records = tuple(
        ServicePortRecord(
            description=f"synthetic hint {index}",
            modification_date=None,
            port_end=443,
            port_start=443,
            record_kind="named",
            registration_date=None,
            service_name=f"hint-{index}",
            source_row=index + 1,
            transport="tcp",
        )
        for index in range(10)
    )
    monkeypatch.setattr(
        loader,
        "load_iana",
        lambda: SimpleNamespace(
            bundle_id="bounded-test",
            services=records,
            warning="context only",
        ),
    )
    result = loader.lookup_port("tcp", 443)
    assert result["match_count"] == 10
    assert len(result["matches"]) == 8
    assert result["truncated"] is True
    assert [match["source_row"] for match in result["matches"]] == list(range(1, 9))


def test_generated_data_is_closed_pinned_and_under_80_kib():
    iana = _manifest("iana-v1")
    corpus = _manifest("corpus-v1")
    assert iana["artifact_count"] == len(iana["artifacts"]) == 74
    assert corpus["total_shards"] == sum(
        len(scenario["shards"]) for scenario in corpus["scenarios"]
    ) == 30

    declared = {
        "iana-v1": {"manifest.json", *(item["path"] for item in iana["artifacts"])},
        "corpus-v1": {
            "manifest.json",
            *(
                shard["path"]
                for scenario in corpus["scenarios"]
                for shard in scenario["shards"]
            ),
        },
    }
    for directory, expected_names in declared.items():
        root = REFERENCE_ROOT / directory
        files = {path.name: path for path in root.iterdir() if path.is_file()}
        assert set(files) == expected_names
        assert all(path.suffix in {".json", ".jsonl"} for path in files.values())
        assert all(
            0 < path.stat().st_size <= MAX_GENERATED_TEXT_BYTES
            for path in files.values()
        )

    for artifact in iana["artifacts"]:
        data = (REFERENCE_ROOT / "iana-v1" / artifact["path"]).read_bytes()
        assert len(data) == artifact["bytes"]
        assert hashlib.sha256(data).hexdigest() == artifact["sha256"]
        assert len(data.splitlines()) == artifact["rows"]

    for scenario in corpus["scenarios"]:
        parts = []
        for index, shard in enumerate(scenario["shards"], start=1):
            assert shard["path"] == f"{scenario['id']}.part-{index:03d}.jsonl"
            data = (REFERENCE_ROOT / "corpus-v1" / shard["path"]).read_bytes()
            assert len(data) == shard["bytes"]
            assert hashlib.sha256(data).hexdigest() == shard["sha256"]
            assert len(data.splitlines()) == shard["records"]
            parts.append(data)
        combined = b"".join(parts)
        assert len(combined) == scenario["bytes"]
        assert hashlib.sha256(combined).hexdigest() == scenario["sha256"]
        assert len(combined.splitlines()) == scenario["records"]


def test_all_synthetic_scenarios_match_exact_expectations(corpus_bundle):
    assert corpus_bundle.total_records == 6_492
    assert len(corpus_bundle.scenarios) == 12
    assert corpus_bundle.quality_label == "synthetic-only"
    assert corpus_bundle.calibration == "uncalibrated"
    assert sum(len(scenario.records) for scenario in corpus_bundle.scenarios) == 6_492

    result = evaluate_corpus()
    assert result["validated_total_records"] == 6_492
    assert result["evaluated_scenarios"] == 12
    assert result["all_match"] is True
    assert result["quality_label"] == "synthetic-only"
    assert result["calibration"] == "uncalibrated"
    assert result["network_access_performed"] is False
    assert result["persistence_status"] == "not_attempted"
    assert result["action_status"] == "not_attempted"
    assert sum(scenario["records"] for scenario in result["scenarios"]) == 6_492
    assert all(
        scenario["expected"] == scenario["observed"]
        and scenario["matches_expected"] is True
        and scenario["quality_label"] == "synthetic-only"
        and scenario["calibration"] == "uncalibrated"
        and scenario["action_status"] == "not_attempted"
        for scenario in result["scenarios"]
    )


def test_strict_json_rejects_duplicate_keys():
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:DUPLICATE_KEY$"):
        loader._json(b'{"field":1,"field":2}', line=True)


@pytest.mark.parametrize("field", ("unknown", "payload"))
def test_corpus_event_rejects_unknown_and_payload_keys(field):
    event = _valid_event()
    event[field] = "must not be present"
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:CORPUS_EVENT$"):
        loader._corpus_event(event)


def test_corpus_event_rejects_real_world_address():
    event = _valid_event()
    event["src_ip"] = "8.8.8.8"
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:CORPUS_ADDRESS$"):
        loader._corpus_event(event)


def test_unrelated_iana_shard_digest_failure_blocks_lookup(monkeypatch):
    manifest = _manifest("iana-v1")
    target = manifest["artifacts"][-2]["path"]
    original = loader._read_resource

    def tampered(parts, maximum):
        data = original(parts, maximum)
        return _mutated(data) if parts == ("iana-v1", target) else data

    monkeypatch.setattr(loader, "_read_resource", tampered)
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:ARTIFACT_INTEGRITY$"):
        lookup_port("tcp", 443)


def test_unselected_corpus_shard_digest_failure_blocks_evaluation(monkeypatch):
    manifest = _manifest("corpus-v1")
    target_scenario = next(
        item for item in manifest["scenarios"] if item["id"] == "source-cap-pressure-v1"
    )
    target = target_scenario["shards"][-1]["path"]
    original = loader._read_resource

    def tampered(parts, maximum):
        data = original(parts, maximum)
        return _mutated(data) if parts == ("corpus-v1", target) else data

    monkeypatch.setattr(loader, "_read_resource", tampered)
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:ARTIFACT_INTEGRITY$"):
        evaluate_corpus("dns-protocol-gates-v1")


def test_corpus_shard_row_count_mismatch_is_rejected(monkeypatch):
    manifest = _manifest("corpus-v1")
    manifest["scenarios"][0]["shards"][0]["records"] += 1
    changed_manifest = _canonical_json(manifest)
    original = loader._read_resource

    def changed(parts, maximum):
        if parts == ("corpus-v1", "manifest.json"):
            return changed_manifest
        return original(parts, maximum)

    monkeypatch.setattr(
        loader,
        "CORPUS_MANIFEST_SHA256",
        hashlib.sha256(changed_manifest).hexdigest(),
    )
    monkeypatch.setattr(loader, "_read_resource", changed)
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:ROW_COUNT$"):
        load_corpus()


def test_resource_reader_rejects_overflow():
    with pytest.raises(ReferenceDataError, match=r"^REFERENCE_DATA:RESOURCE_LIMIT$"):
        loader._read_resource(("iana-v1", "manifest.json"), 8)


def test_iana_normalizer_preserves_ranges_duplicates_and_blank_keyword_semantics():
    generator = _load_generator()
    services, excluded = generator._service_records(
        [
            {
                "Transport Protocol": "udp",
                "Port Number": "14001",
                "Service Name": "sua",
                "Description": "De-Registered",
                "Modification Date": "",
                "Registration Date": "2005-09",
            },
            {
                "Transport Protocol": "tcp",
                "Port Number": "100-102",
                "Service Name": "",
                "Description": "Reserved",
                "Modification Date": "",
                "Registration Date": "",
            },
            {
                "Transport Protocol": "tcp",
                "Port Number": "",
                "Service Name": "portless",
                "Description": "excluded",
                "Modification Date": "",
                "Registration Date": "",
            },
            {
                "Transport Protocol": "udp",
                "Port Number": "14001",
                "Service Name": "alias",
                "Description": "Second name for the same key",
                "Modification Date": "",
                "Registration Date": "",
            },
        ]
    )
    assert excluded == 1
    assert [(row["port_start"], row["port_end"]) for row in services] == [
        (100, 102),
        (14_001, 14_001),
        (14_001, 14_001),
    ]
    assert [row["source_row"] for row in services] == [2, 4, 1]
    assert [row["record_kind"] for row in services] == ["reserved", "named", "named"]

    protocols = generator._protocol_records(
        [
            {
                "Decimal": "61",
                "Keyword": "",
                "Protocol": "any host internal protocol",
                "IPv6 Extension Header": "",
            },
            {
                "Decimal": "148-252",
                "Keyword": "",
                "Protocol": "Unassigned",
                "IPv6 Extension Header": "",
            },
            {
                "Decimal": "253",
                "Keyword": "",
                "Protocol": "Use for experimentation and testing",
                "IPv6 Extension Header": "Y",
            },
        ]
    )
    assert [(row["decimal_start"], row["decimal_end"]) for row in protocols] == [
        (61, 61),
        (148, 252),
        (253, 253),
    ]
    assert [row["record_kind"] for row in protocols] == [
        "named",
        "unassigned",
        "experimental",
    ]


def test_iana_source_digest_refusal_precedes_parsing(tmp_path):
    generator = _load_generator()
    source = tmp_path / generator.SERVICE_SOURCE["file"]
    source.write_bytes(b"not the pinned IANA snapshot")
    with pytest.raises(ValueError, match="does not match the pinned snapshot"):
        generator._source(source, generator.SERVICE_SOURCE)


def test_iana_source_refuses_oversized_sparse_input(tmp_path):
    generator = _load_generator()
    source = tmp_path / generator.SERVICE_SOURCE["file"]
    with source.open("wb") as stream:
        stream.seek(generator.SERVICE_SOURCE["raw_bytes"] + 128 * 1024 * 1024)
        stream.write(b"x")

    with pytest.raises(ValueError, match="does not match the pinned snapshot"):
        generator._source(source, generator.SERVICE_SOURCE)


def test_generator_rejects_existing_or_symlink_output(tmp_path):
    generator = _load_generator()
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ValueError, match="must not already exist"):
        generator.build_corpus(existing)

    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink components"):
        generator.build_corpus(linked)
    assert list(outside.iterdir()) == []

    real_parent = tmp_path / "real-parent"
    nested_parent = real_parent / "nested"
    nested_parent.mkdir(parents=True)
    alias_parent = tmp_path / "alias-parent"
    alias_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink components"):
        generator.build_corpus(alias_parent / "nested" / "corpus-v1")


def test_bundle_publish_uses_closed_directory_renames_and_is_symlink_safe(tmp_path):
    generator = _load_generator()

    def bundle(parent: Path, content: bytes) -> Path:
        root = parent / "corpus-v1"
        root.mkdir(parents=True)
        artifact = "example-v1.part-001.jsonl"
        (root / artifact).write_bytes(content)
        (root / "manifest.json").write_text(
            json.dumps({"scenarios": [{"shards": [{"path": artifact}]}]}),
            encoding="ascii",
        )
        return root

    target = bundle(tmp_path / "destination", b"old\n")
    staged = bundle(tmp_path / "staging", b"new\n")
    generator._publish_bundle(staged, target)
    assert (target / "example-v1.part-001.jsonl").read_bytes() == b"new\n"
    assert not (target.parent / ".corpus-v1.previous").exists()

    staged_extra = bundle(tmp_path / "staging-extra", b"next\n")
    (target / "operator-note.txt").write_text("preserve", encoding="ascii")
    with pytest.raises(ValueError, match="existing bundle contains"):
        generator._publish_bundle(staged_extra, target)
    assert (target / "operator-note.txt").read_text(encoding="ascii") == "preserve"

    outside = bundle(tmp_path / "outside-parent", b"outside\n")
    link_parent = tmp_path / "link-parent"
    link_parent.mkdir()
    link = link_parent / "corpus-v1"
    link.symlink_to(outside, target_is_directory=True)
    staged_link = bundle(tmp_path / "staging-link", b"blocked\n")
    with pytest.raises(ValueError, match="symlink components"):
        generator._publish_bundle(staged_link, link)
    assert (outside / "example-v1.part-001.jsonl").read_bytes() == b"outside\n"

    real_alias_parent = tmp_path / "publish-real-parent"
    nested_alias_parent = real_alias_parent / "nested"
    aliased_target = bundle(nested_alias_parent, b"aliased-old\n")
    alias_parent = tmp_path / "publish-alias-parent"
    alias_parent.symlink_to(real_alias_parent, target_is_directory=True)
    staged_alias = bundle(tmp_path / "staging-alias", b"blocked\n")
    with pytest.raises(ValueError, match="symlink components"):
        generator._publish_bundle(
            staged_alias, alias_parent / "nested" / aliased_target.name
        )
    assert (aliased_target / "example-v1.part-001.jsonl").read_bytes() == b"aliased-old\n"


@pytest.mark.parametrize("interrupt_after_rename", [False, True])
def test_bundle_publish_restores_previous_target_on_keyboard_interrupt(
    tmp_path, monkeypatch, interrupt_after_rename
):
    generator = _load_generator()

    def bundle(parent: Path, content: bytes) -> Path:
        root = parent / "corpus-v1"
        root.mkdir(parents=True)
        artifact = "example-v1.part-001.jsonl"
        (root / artifact).write_bytes(content)
        (root / "manifest.json").write_text(
            json.dumps({"scenarios": [{"shards": [{"path": artifact}]}]}),
            encoding="ascii",
        )
        return root

    target = bundle(tmp_path / "destination", b"old\n")
    staged = bundle(tmp_path / "staging", b"new\n")
    real_replace = generator.os.replace

    def interrupt_staged_publish(source, destination):
        if Path(source) == staged and Path(destination) == target:
            if interrupt_after_rename:
                real_replace(source, destination)
            raise KeyboardInterrupt
        return real_replace(source, destination)

    monkeypatch.setattr(generator.os, "replace", interrupt_staged_publish)
    with pytest.raises(KeyboardInterrupt):
        generator._publish_bundle(staged, target)

    assert (target / "example-v1.part-001.jsonl").read_bytes() == b"old\n"
    assert (staged / "example-v1.part-001.jsonl").read_bytes() == b"new\n"
    assert not (target.parent / ".corpus-v1.previous").exists()


def test_evaluator_sources_have_no_effectful_imports_or_constructors():
    forbidden_modules = {"firewall", "service", "socket", "sqlite3", "storage", "subprocess"}
    forbidden_names = {"ActionRecord", "MegalodonService", "NftablesFirewall", "Store"}
    for path in (Path(loader.__file__), Path(evaluation.__file__)):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not any(
                    alias.name.split(".")[0] in forbidden_modules for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[-1] not in forbidden_modules
                assert not any(alias.name in forbidden_names for alias in node.names)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in forbidden_names


def test_evaluation_performs_no_network_process_store_service_or_action(
    monkeypatch, capsys
):
    def denied(*args, **kwargs):
        raise AssertionError("offline evaluation crossed an effect boundary")

    for owner, name in (
        (socket, "socket"),
        (socket, "create_connection"),
        (sqlite3, "connect"),
        (subprocess, "Popen"),
        (subprocess, "run"),
        (subprocess, "call"),
        (subprocess, "check_call"),
        (subprocess, "check_output"),
        (storage, "Store"),
        (storage, "DashboardStore"),
        (service, "MegalodonService"),
        (firewall, "NftablesFirewall"),
        (models, "ActionRecord"),
    ):
        monkeypatch.setattr(owner, name, denied)

    assert evaluation.main(["corpus", "--scenario", "dns-protocol-gates-v1"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["evaluated_scenarios"] == 1
    assert result["validated_total_records"] == 6_492
    assert result["network_access_performed"] is False
    assert result["persistence_status"] == "not_attempted"
    assert result["action_status"] == "not_attempted"


def test_cli_reference_and_corpus_success(capsys):
    assert evaluation.main(["reference", "verify"]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["service_records"] == 12_577
    assert verified["protocol_records"] == 152

    assert evaluation.main(["reference", "port", "tcp", "443"]) == 0
    port = json.loads(capsys.readouterr().out)
    assert port["matches"][0]["service_name"] == "https"
    assert port["action_status"] == "not_attempted"

    assert evaluation.main(["corpus", "--scenario", "dns-protocol-gates-v1"]) == 0
    corpus = json.loads(capsys.readouterr().out)
    assert corpus["evaluated_scenarios"] == 1
    assert corpus["validated_total_records"] == 6_492
    assert corpus["scenarios"][0]["matches_expected"] is True


def test_cli_reports_bounded_operation_and_argument_errors(capsys):
    assert evaluation.main(["corpus", "--scenario", "not-present-v1"]) == 2
    failure = json.loads(capsys.readouterr().out)
    assert failure == {
        "schema": "reference-operation-error-v1",
        "status": "failed",
        "error": "REFERENCE_DATA:UNKNOWN_SCENARIO",
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }

    with pytest.raises(SystemExit) as caught:
        evaluation.main(["reference", "port", "tcp", "65536"])
    assert caught.value.code == 2
    argument_failure = json.loads(capsys.readouterr().err)
    assert argument_failure == {
        "schema": "reference-operation-error-v1",
        "status": "failed",
        "error": "INVALID_ARGUMENTS",
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }


def test_corpus_generator_is_byte_reproducible(tmp_path):
    generator = _load_generator()

    generated = tmp_path / "corpus-v1"
    generator.build_corpus(generated)
    expected = REFERENCE_ROOT / "corpus-v1"
    expected_files = {path.name: path for path in expected.iterdir() if path.is_file()}
    generated_files = {path.name: path for path in generated.iterdir() if path.is_file()}
    assert set(generated_files) == set(expected_files)
    for name, path in generated_files.items():
        assert path.read_bytes() == expected_files[name].read_bytes(), name
        assert path.stat().st_size <= MAX_GENERATED_TEXT_BYTES
