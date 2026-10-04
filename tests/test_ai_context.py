"""Synthetic contract acceptance only; no model benefit or host qualification."""

import ast
import builtins
from copy import deepcopy
from hashlib import sha256
from importlib.resources import files
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading

import pytest

from megalodon.ai_context import (
    CONTEXT_SCHEMA, INPUT_SCHEMA, MAX_CONTEXT_BYTES, MAX_COUNT, MAX_RECORDS,
    ContextError, build_context,
)


START = 1790985600  # 2026-10-03T00:00:00Z; fixed synthetic complete hour.
PACKETS, FLOWS, BASELINES = "a" * 32, "b" * 32, "c" * 32
SCOPE = "d" * 32
SUBJECT = "192.0.2.10"


def source(identifier=PACKETS, kind="packets"):
    return {"id": identifier, "kind": kind, "expires_at": START + 86400}


def record(number=1, *, kind="packets", sensor="accepted packet metadata", segment=PACKETS):
    row = {"ref": f"{segment}:{number}", "source": sensor, "scope_id": SCOPE, "kind": kind,
           "observed_at": START + number, "src_ip": SUBJECT, "dst_ip": "198.51.100.20",
           "protocol": "TCP", "src_port": 50000, "dst_port": 443,
           "tcp_flags": ["SYN"], "missing": {}}
    if kind == "packets":
        row["findings"] = []
    else:
        row["missing"]["findings"] = "not_qualified"
    return row


def request():
    return {"schema": INPUT_SCHEMA, "subject": SUBJECT,
            "window": {"start": START, "end": START + 3600}, "as_of": START + 3600,
            "sources": [source()], "records": [record()],
            "coverage": {"truncated": False, "missing": []},
            "comparison": {"state": "unavailable", "reason": "no_baseline"},
            "references": [{"source": "attack", "edition": "2026-08-05", "id": "T1046"}]}


def with_comparison(value):
    value["sources"].append(source(BASELINES, "baselines"))
    def hour(number, start, count):
        return {"ref": f"{BASELINES}:{number}", "subject": SUBJECT,
                "source": "accepted packet metadata", "scope_id": SCOPE, "kind": "packets",
                "start": start, "end": start + 3600, "count": count, "basis": "retained_record_count", "eligible": True}
    value["comparison"] = {"state": "available", "current": [hour(2, START, 10)],
                           "previous": [hour(1, START - 3600, 7)]}
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def starter_references():
    root = files("megalodon.reference").joinpath("security-v1")
    raw = root.joinpath("starter.json").read_bytes()
    assert sha256(raw).hexdigest() == root.joinpath("starter.sha256").read_text().strip()
    return json.loads(raw)["entries"]


@pytest.mark.parametrize("reference", starter_references(), ids=lambda row: row["id"])
def test_bundled_reference_identity_is_preserved_exactly(reference):
    value = request()
    value["references"] = [{"source": reference["source"], "edition": reference["edition"],
                            "id": reference["identifier"]}]
    assert build_context(value)["reference_ids"] == [reference["id"]]


@pytest.mark.parametrize("source,edition,identifier", [
    ("attack", "2026.08.05", "T1046"),
    ("atlas", "2026-09-01", "AML.T0051"),
    ("d3fend", "2026.09", "NetworkTrafficAnalysis"),
    ("owasp", "2026.09", "LLM01"),
    ("kev", "2026-10-01", "CVE-2004-1464"),
    ("attack", "2026-08-05", "LLM01"),
    ("atlas", "2026.09", "T1046"),
    ("d3fend", "1.6.0", "../../NetworkTrafficAnalysis"),
    ("owasp", "2026", "CVE-2004-1464"),
    ("kev", "2026.10.01", "AML.T0051"),
])
def test_source_specific_reference_grammar_stays_closed(source, edition, identifier):
    value = request()
    value["references"] = [{"source": source, "edition": edition, "id": identifier}]
    with pytest.raises(ContextError, match="^INVALID_IDENTIFIER$"):
        build_context(value)


def test_kev_source_identity_is_not_rewritten_to_an_invented_alias():
    value = request()
    value["references"] = [{"source": "cisa-kev", "edition": "2026.10.01", "id": "CVE-2004-1464"}]
    with pytest.raises(ContextError, match="^UNSUPPORTED_VALUE$"):
        build_context(value)


@pytest.mark.parametrize("sensor", ["suricata-eve", "zeek-conn", "zeek-sample"])
@pytest.mark.parametrize("findings", [[], [{"id": 17, "rule": "SYN_FLOOD"}]])
def test_flow_findings_field_is_refused_even_when_empty(sensor, findings):
    value = request()
    value["references"] = []
    value["sources"] = [source(FLOWS, "flows")]
    row = record(kind="flows", sensor=sensor, segment=FLOWS)
    del row["missing"]["findings"]
    row["findings"] = findings
    value["records"] = [row]
    with pytest.raises(ContextError, match="^UNSUPPORTED_FINDING$"):
        build_context(value)


@pytest.mark.parametrize("sensor", ["suricata-eve", "zeek-conn", "zeek-sample"])
def test_flow_findings_stay_unqualified_while_packet_absence_can_be_qualified(sensor):
    value = request()
    packet_group, = build_context(value)["groups"]
    value["sources"] = [source(FLOWS, "flows")]
    value["records"] = [record(kind="flows", sensor=sensor, segment=FLOWS)]
    flow_group, = build_context(value)["groups"]
    assert packet_group["findings"] == flow_group["findings"] == []
    assert "findings" not in packet_group["missing"]
    assert flow_group["missing"]["findings"] == ["not_qualified"]


def test_deterministic_owned_packet_has_inspectable_measurements_and_stable_digest():
    value = request()
    value["records"].append(record(2))
    before = deepcopy(value)
    packet = build_context(value)
    assert value == before
    assert packet["schema"] == CONTEXT_SCHEMA
    assert packet["subject"] == SUBJECT
    group, = packet["groups"]
    assert group == {
        "source": "accepted packet metadata", "scope_id": SCOPE, "measurement": "packet_records", "record_count": 2,
        "evidence_refs": [f"{PACKETS}:1", f"{PACKETS}:2"],
        "first_observed_at": START + 1, "last_observed_at": START + 2,
        "protocol_counts": {"TCP": 2}, "src_port_counts": [{"protocol": "TCP", "port": 50000, "count": 2}],
        "dst_port_counts": [{"protocol": "TCP", "port": 443, "count": 2}],
        "tcp_flag_counts": {"SYN": 2}, "findings": [], "missing": {},
    }
    assert packet["reference_ids"] == ["attack@2026-08-05:T1046"]
    assert packet["snapshot_sha256"] == sha256(canonical({k: v for k, v in packet.items() if k != "snapshot_sha256"})).hexdigest()
    assert len(canonical(packet)) <= MAX_CONTEXT_BYTES
    value["records"].reverse()
    assert build_context(value) == packet
    packet["dependencies"][0]["expires_at"] = 1
    packet["window"]["start"] = 0
    packet["groups"][0]["missing"]["protocol"] = ["not_collected"]
    assert value["sources"] == before["sources"] and value["window"] == before["window"]
    assert value["records"][0]["missing"] == {}


def test_packet_and_flow_records_and_sensors_are_never_combined():
    value = request()
    value["sources"].append(source(FLOWS, "flows"))
    value["records"] += [record(2, kind="flows", sensor="suricata-eve", segment=FLOWS),
                         record(3, kind="flows", sensor="zeek-conn", segment=FLOWS)]
    packet = build_context(value)
    assert [(g["source"], g["measurement"], g["record_count"]) for g in packet["groups"]] == [
        ("accepted packet metadata", "packet_records", 1), ("suricata-eve", "flow_records", 1), ("zeek-conn", "flow_records", 1)]
    assert "total_packets" not in packet and "connections" not in canonical(packet).decode()
    value["sources"].reverse()
    value["records"].reverse()
    assert build_context(value) == packet


def test_distinct_collection_scopes_stay_separate_even_for_the_same_sensor():
    value = request()
    other = record(2)
    other["scope_id"] = "e" * 32
    value["records"].append(other)
    groups = build_context(value)["groups"]
    assert len(groups) == 2 and all(group["record_count"] == 1 for group in groups)


def test_ipv6_selection_is_canonical_and_matches_either_endpoint():
    value = request()
    value["subject"] = "2001:0db8:0000:0000:0000:0000:0000:0002"
    value["records"][0]["dst_ip"] = "2001:db8::2"
    packet = build_context(value)
    assert packet["subject"] == "2001:db8::2"
    # Other endpoint addresses are input qualification, not added model context.
    assert SUBJECT not in canonical(packet).decode()


def test_missing_measurement_is_not_a_zero_or_partial_histogram():
    value = request()
    other = record(2)
    del other["dst_port"]
    other["missing"]["dst_port"] = "not_collected"
    value["records"].append(other)
    group, = build_context(value)["groups"]
    assert group["missing"]["dst_port"] == ["not_collected"]
    assert "dst_port_counts" not in group
    del value["records"][1]
    value["records"][0]["dst_port"] = 0
    group, = build_context(value)["groups"]
    assert group["dst_port_counts"] == [{"protocol": "TCP", "port": 0, "count": 1}]
    assert "dst_port" not in group["missing"]


def test_empty_selection_and_missing_comparison_do_not_claim_unchanged_or_safe():
    value = request()
    value.update(records=[], sources=[])
    value["coverage"]["missing"] = ["no_qualified_records"]
    packet = build_context(value)
    assert packet["groups"] == []
    assert packet["comparison"] == {"state": "unavailable", "reason": "no_baseline"}
    assert packet["coverage"]["missing"] == ["no_qualified_records"]
    assert "no_capture_or_identity_guarantee" in packet["scope"]


def test_only_supplied_actual_deterministic_finding_ids_are_retained():
    value = request()
    value["records"][0]["findings"] = [{"id": 17, "rule": "SYN_FLOOD"}]
    partial = record(2)
    del partial["findings"]
    partial["missing"]["findings"] = "not_qualified"
    value["records"].append(partial)
    group, = build_context(value)["groups"]
    assert group["findings"] == [{"ref": f"{PACKETS}:finding:17", "rule": "SYN_FLOOD"}]
    assert group["missing"]["findings"] == ["not_qualified"]
    assert "severity" not in group and "proposal" not in group


def test_adjacent_eligible_hour_comparison_is_computed_not_model_arithmetic():
    value = with_comparison(request())
    result = build_context(value)["comparison"]
    assert result["previous_window"] == {"start": START - 3600, "end": START}
    group, = result["groups"]
    assert (group["current_count"], group["previous_count"], group["delta"], group["eligible_hours"]) == (10, 7, 3, 2)
    value["comparison"]["current"][0]["count"] = 0
    value["records"] = []
    value["sources"] = [source(BASELINES, "baselines")]
    value["coverage"]["missing"] = ["no_qualified_records"]
    group, = build_context(value)["comparison"]["groups"]
    assert group["current_count"] == 0 and group["delta"] == -7


@pytest.mark.parametrize("path,replacement,code", [
    (("schema",), "future-v2", "UNSUPPORTED_SCHEMA"),
    (("subject",), "attacker.example", "INVALID_SUBJECT"),
    (("subject",), "fe80::1%eth0", "INVALID_SUBJECT"),
    (("subject",), "192.0.2.11", "SUBJECT_MISMATCH"),
    (("as_of",), START, "FUTURE_WINDOW"),
    (("window", "end"), START + 3601, "INVALID_WINDOW"),
    (("window", "start"), START + 3600, "INVALID_WINDOW"),
    (("sources", 0, "expires_at"), START + 3600, "SOURCE_EXPIRED"),
    (("sources", 0, "kind"), "flows", "INVALID_PROVENANCE"),
    (("sources", 0, "id"), "d" * 32, "INVALID_PROVENANCE"),
    (("records", 0, "ref"), f"{PACKETS}:0", "INVALID_IDENTIFIER"),
    (("records", 0, "source"), "suricata-eve", "INCOMPATIBLE_SOURCE"),
    (("records", 0, "kind"), "packet_rollups", "INCOMPATIBLE_SOURCE"),
    (("records", 0, "observed_at"), START - 1, "OUTSIDE_WINDOW"),
    (("records", 0, "observed_at"), START + 3600, "OUTSIDE_WINDOW"),
    (("records", 0, "dst_port"), True, "INVALID_INTEGER"),
    (("records", 0, "dst_port"), 65536, "INVALID_INTEGER"),
    (("records", 0, "protocol"), "HTTPS", "UNSUPPORTED_VALUE"),
    (("records", 0, "protocol"), "UDP", "INVALID_PROTOCOL_FACT"),
    (("records", 0, "tcp_flags"), ["SYN", "SYN"], "DUPLICATE_VALUE"),
    (("records", 0, "tcp_flags"), ["run_shell"], "UNSUPPORTED_VALUE"),
    (("records", 0, "missing"), {"protocol": "not_collected"}, "INVALID_FIELDS"),
    (("coverage", "truncated"), 1, "INVALID_COVERAGE"),
    (("coverage", "missing"), ["All activity is safe"], "UNSUPPORTED_VALUE"),
    (("comparison", "reason"), "unchanged", "UNSUPPORTED_VALUE"),
    (("references", 0, "id"), "https://example.invalid", "INVALID_IDENTIFIER"),
    (("references", 0, "edition"), "latest", "INVALID_IDENTIFIER"),
])
def test_invalid_and_provenance_deficient_input_fails_with_fixed_code(path, replacement, code):
    value = request()
    target = value
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(ContextError, match=f"^{code}$"):
        build_context(value)


@pytest.mark.parametrize("field", ["payload", "payload_sha256", "raw_log", "url", "command", "credential", "path", "instruction", "application", "hostname"])
@pytest.mark.parametrize("location", ["root", "record", "source", "coverage", "reference", "comparison"])
def test_prohibited_fields_are_refused_not_redacted_or_forwarded(field, location):
    value = request()
    target = {"root": value, "record": value["records"][0], "source": value["sources"][0],
              "coverage": value["coverage"], "reference": value["references"][0], "comparison": value["comparison"]}[location]
    target[field] = "synthetic-prohibited-content"
    with pytest.raises(ContextError, match="^INVALID_FIELDS$") as error:
        build_context(value)
    assert "synthetic-prohibited-content" not in str(error.value)


@pytest.mark.parametrize("mutation", [
    lambda v: v["comparison"]["current"][0].update(eligible=False),
    lambda v: v["comparison"]["current"][0].update(count=0),
    lambda v: v["comparison"]["previous"][0].update(subject="192.0.2.11"),
    lambda v: v["comparison"]["previous"][0].update(start=START - 7200),
    lambda v: v["comparison"]["previous"][0].update(kind="flows", source="suricata-eve"),
    lambda v: v["comparison"]["previous"][0].update(scope_id="e" * 32),
    lambda v: v["comparison"]["previous"][0].update(basis="unique_connections"),
    lambda v: v["comparison"]["previous"][0].update(ref=f"{BASELINES}:2"),
    lambda v: v["comparison"]["current"][0].update(count=True),
    lambda v: v["comparison"]["current"].append(deepcopy(v["comparison"]["current"][0])),
    lambda v: v["coverage"].update(truncated=True),
    lambda v: v["coverage"].update(missing=["sensor_disagreement"]),
    lambda v: v["sources"][-1].update(expires_at=START),
])
def test_incomplete_incompatible_or_expired_comparisons_cannot_claim_a_delta(mutation):
    value = with_comparison(request())
    mutation(value)
    with pytest.raises(ContextError):
        build_context(value)


@pytest.mark.parametrize("field", ["protocol", "src_port", "dst_port", "tcp_flags", "findings"])
def test_omitted_fields_require_explicit_closed_missing_reason(field):
    value = request()
    del value["records"][0][field]
    with pytest.raises(ContextError, match="^INVALID_FIELDS$"):
        build_context(value)
    value["records"][0]["missing"][field] = "not_collected"
    if field == "protocol":
        for dependent in ("src_port", "dst_port", "tcp_flags"):
            del value["records"][0][dependent]
            value["records"][0]["missing"][dependent] = "not_qualified"
    assert field in build_context(value)["groups"][0]["missing"]


@pytest.mark.parametrize("protocol", ["UNKNOWN", "OTHER", "DNS"])
def test_unknown_transport_cannot_claim_flags_or_ports_are_not_applicable(protocol):
    value = request()
    row = value["records"][0]
    row["protocol"] = protocol
    for field in ("src_port", "dst_port", "tcp_flags"):
        del row[field]
        row["missing"][field] = "not_applicable"
    with pytest.raises(ContextError, match="^INVALID_MISSINGNESS$"):
        build_context(value)
    row["protocol"] = "ICMP"
    assert build_context(value)["groups"][0]["missing"]["tcp_flags"] == ["not_applicable"]


def test_counter_boundaries_do_not_round_and_expiry_is_rechecked_at_supplied_time():
    value = with_comparison(request())
    value["comparison"]["current"][0]["count"] = MAX_COUNT
    value["comparison"]["previous"][0]["count"] = 0
    assert build_context(value)["comparison"]["groups"][0]["delta"] == MAX_COUNT
    value["comparison"]["current"][0]["count"] += 1
    with pytest.raises(ContextError, match="^INVALID_INTEGER$"):
        build_context(value)
    value = request()
    value["as_of"] = value["sources"][0]["expires_at"]
    with pytest.raises(ContextError, match="^SOURCE_EXPIRED$"):
        build_context(value)


@pytest.mark.parametrize("rule", ["invented", "OBSERVED_ACTIVITY", "SURICATA_ALERT"])
def test_patterns_and_external_alerts_cannot_be_recast_as_deterministic_findings(rule):
    value = request()
    value["records"][0]["findings"] = [{"id": 1, "rule": rule}]
    with pytest.raises(ContextError, match="^UNSUPPORTED_VALUE$"):
        build_context(value)


def test_finding_unknown_fields_duplicates_and_unused_dependencies_are_refused():
    value = request()
    value["records"][0]["findings"] = [{"id": 1, "rule": "SYN_FLOOD", "command": "synthetic"}]
    with pytest.raises(ContextError, match="^INVALID_FIELDS$"):
        build_context(value)
    del value["records"][0]["findings"][0]["command"]
    value["records"].append(record(2))
    value["records"][1]["findings"] = deepcopy(value["records"][0]["findings"])
    with pytest.raises(ContextError, match="^DUPLICATE_REFERENCE$"):
        build_context(value)
    value = request()
    value["sources"].append(source(FLOWS, "flows"))
    with pytest.raises(ContextError, match="^UNUSED_SOURCE$"):
        build_context(value)


@pytest.mark.parametrize("where", ["records", "sources", "references"])
def test_duplicates_fail_instead_of_double_counting(where):
    value = request()
    value[where].append(deepcopy(value[where][0]))
    with pytest.raises(ContextError, match="^DUPLICATE_"):
        build_context(value)


def test_maximum_selection_is_bounded_without_silent_truncation():
    value = request()
    value["records"] = [record(i + 1) for i in range(MAX_RECORDS)]
    assert build_context(value)["groups"][0]["record_count"] == MAX_RECORDS
    value["records"].append(record(25))
    with pytest.raises(ContextError, match="^INVALID_LIST$"):
        build_context(value)
    value["records"].pop()
    # Different ports grow the canonical projection; no fields disappear to fit.
    for i, row in enumerate(value["records"]):
        row.update(src_port=i, dst_port=i + 1)
    with pytest.raises(ContextError, match="^CONTEXT_TOO_LARGE$"):
        build_context(value)


@pytest.mark.parametrize("bad", [None, float("nan"), 1.0, -1, 2**60, b"bytes", "\u202eunsafe", "x" * 100000])
def test_malformed_values_are_rejected_before_serialization(bad):
    value = request()
    value["records"][0]["dst_port"] = bad
    with pytest.raises(ContextError):
        build_context(value)


def test_cycles_and_custom_types_cannot_run_hooks_or_exhaust_recursion():
    value = request()
    value["records"] = [value]
    with pytest.raises(ContextError, match="^INPUT_TOO_LARGE$"):
        build_context(value)
    class Hostile(dict):
        def items(self):
            raise AssertionError("must not run custom hooks")
    with pytest.raises(ContextError, match="^INVALID_TYPE$"):
        build_context(Hostile(request()))


def test_snapshot_changes_with_selection_measurements_and_dependency_lifetime():
    value = request()
    original = build_context(value)["snapshot_sha256"]
    for changed in ("subject", "port", "expiry", "as_of"):
        other = deepcopy(value)
        if changed == "subject":
            other["subject"] = other["records"][0]["dst_ip"]
        elif changed == "port":
            other["records"][0]["dst_port"] = 8443
        elif changed == "expiry":
            other["sources"][0]["expires_at"] += 1
        else:
            other["as_of"] += 1
        assert build_context(other)["snapshot_sha256"] != original
    assert build_context(value)["snapshot_sha256"] == original
    # A-to-B-to-A returns the same content hash; a future UI needs a separate
    # request-generation token. This helper cannot claim race protection.


def test_builder_has_no_io_or_runtime_imports(monkeypatch):
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / "megalodon/ai_context.py").read_text())
    imports = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imports |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert imports <= {"__future__", "collections", "hashlib", "ipaddress", "json", "re"}
    for path in (root / "megalodon").rglob("*.py"):
        # Only the two retained-evidence admission adapters consume the builder.
        if path.name not in {"ai_context.py", "endpoint_context.py", "endpoint_hour_counts.py"}:
            assert "ai_context" not in path.read_text(), f"Unexpected runtime wiring: {path}"
    value = with_comparison(request())
    def forbidden(*args, **kwargs):
        raise AssertionError("context construction attempted a side effect")
    with monkeypatch.context() as patch:
        for module, name in ((builtins, "open"), (os, "open"), (os, "write"), (os, "system"),
                             (socket, "socket"), (socket, "getaddrinfo"), (sqlite3, "connect"),
                             (subprocess, "Popen"), (threading.Thread, "start")):
            patch.setattr(module, name, forbidden)
        packet = build_context(value)
        value["records"][0]["command"] = "synthetic"
        with pytest.raises(ContextError, match="^INVALID_FIELDS$"):
            build_context(value)
    assert packet["comparison"]["groups"][0]["delta"] == 3
